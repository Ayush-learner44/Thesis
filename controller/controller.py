"""
DDoS Detection Controller — Asymmetric Diamond Topology
(2 splitters: s1, s2  ×  3 detectors: A, B, C  ×  60 hosts)

Switch roles:
  s1, s2     (traffic_splitter.p4)  — table-driven splitters.
                                       Controller fills syn_split + ack_split
                                       tables with entries that realise the
                                       chosen scenario's routing pattern.
  A, B, C    (ddos_detector.p4)     — identical CMS detectors.
                                       All three run the same P4. Their
                                       behaviour differs only because of
                                       which traffic the splitters send.

The active scenario is chosen at startup via an interactive prompt
(same pattern as verify.py). The chosen scenario determines which
entries the controller installs into the syn_split and ack_split
tables on s1 and s2. Detection logic, ML ensemble, FlowTable, digest
handlers — all UNCHANGED from the 2-detector version.
"""

import os, sys, time, pickle, threading, logging, ipaddress
import numpy as np

sys.path.insert(0, '/home/ayush/p4-tools/p4-utils')
from p4utils.utils.sswitch_p4runtime_API import SimpleSwitchP4RuntimeAPI
from p4utils.utils.helper import load_topo

logging.basicConfig(level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s', datefmt='%H:%M:%S')
log = logging.getLogger('DDoS')
log.setLevel(logging.INFO)
log.propagate = False
_handler = logging.StreamHandler()
_handler.setLevel(logging.INFO)
_handler.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s', datefmt='%H:%M:%S'))
log.addHandler(_handler)

_PROJECT_ROOT = os.path.join(os.path.dirname(__file__), '..')
MODELS_DIR    = os.path.join(_PROJECT_ROOT, 'ml', 'models')
TOPO_PATH     = os.path.join(_PROJECT_ROOT, 'topology.json')

SPLITTER_P4RT = os.path.join(_PROJECT_ROOT, 'p4src', 'traffic_splitter_p4rt.txt')
SPLITTER_JSON = os.path.join(_PROJECT_ROOT, 'p4src', 'traffic_splitter.json')
DETECTOR_P4RT = os.path.join(_PROJECT_ROOT, 'p4src', 'ddos_detector_p4rt.txt')
DETECTOR_JSON = os.path.join(_PROJECT_ROOT, 'p4src', 'ddos_detector.json')

# Switches running the splitter P4 — no digests, no block rules pushed here.
SPLITTER_SWITCHES = {'s1', 's2'}

# Host MACs — h0 + 60 clients
HOST_MACS = {'h0': 'aa:00:00:00:00:00'}
for _i in range(1, 61):
    HOST_MACS[f'h{_i}'] = f'aa:00:00:00:00:{_i:02x}'

# ================================================================
# PORT MAPS — must match port1= values in network.py addLink calls
# ================================================================

# Splitters carry only their own clients' MACs in l2_forward.
# s1: hosts h1..h30 on ports 1..30
S1_PORT_MAP = {f'h{i}': i for i in range(1, 31)}
# s2: hosts h31..h60 on ports 1..30 (h31→1, h60→30)
S2_PORT_MAP = {f'h{i}': i - 30 for i in range(31, 61)}

# Detector switches: s1=port 1, s2=port 2, h0=port 3.
# L2 forwarding decides which splitter port to send return traffic
# toward, based on which side the destination client lives on.
_DETECTOR_PORT_MAP = {f'h{i}': 1 for i in range(1, 31)}
_DETECTOR_PORT_MAP.update({f'h{i}': 2 for i in range(31, 61)})
_DETECTOR_PORT_MAP['h0'] = 3

A_PORT_MAP = dict(_DETECTOR_PORT_MAP)
B_PORT_MAP = dict(_DETECTOR_PORT_MAP)
C_PORT_MAP = dict(_DETECTOR_PORT_MAP)

PORT_MAPS = {
    's1': S1_PORT_MAP, 's2': S2_PORT_MAP,
    'A':  A_PORT_MAP,  'B':  B_PORT_MAP,  'C':  C_PORT_MAP,
}

MAX_FLOW_TABLE_SIZE = 100_000

# ================================================================
# SCENARIOS — split percentages for SYN and ACK tables
#
# Each entry: (name, syn_ranges, ack_ranges)
# Range item:   (bucket_lo, bucket_hi, destination_letter)
# Buckets cover [0..99]; destination_letter in {'A','B','C'}.
# ================================================================

SCENARIOS = {
    1:  ('Baseline — single SYN path, single ACK path',
         [(0, 99, 'A')],
         [(0, 99, 'B')]),
    2:  ('SYN split across 2 detectors (A+C), all ACKs on B',
         [(0, 49, 'A'), (50, 99, 'C')],
         [(0, 99, 'B')]),
    3:  ('SYN split across all 3 detectors, all ACKs on B',
         [(0, 32, 'A'), (33, 65, 'B'), (66, 99, 'C')],
         [(0, 99, 'B')]),
    4:  ('All SYNs on A, ACK split across 2 detectors (B+C)',
         [(0, 99, 'A')],
         [(0, 49, 'B'), (50, 99, 'C')]),
    5:  ('All SYNs on A, ACK split across all 3 detectors',
         [(0, 99, 'A')],
         [(0, 32, 'A'), (33, 65, 'B'), (66, 99, 'C')]),
    6:  ('ECMP-style noise — mild spread on both SYN and ACK',
         [(0, 79, 'A'), (80, 89, 'B'), (90, 99, 'C')],
         [(0,  9, 'A'), (10, 89, 'B'), (90, 99, 'C')]),
    7:  ('Cross-contamination — A and B BOTH see SYN and ACK',
         [(0, 69, 'A'), (70, 99, 'B')],
         [(0, 29, 'A'), (30, 99, 'B')]),
    8:  ('Max contamination — all 3 detectors see SYN and ACK',
         [(0, 49, 'A'), (50, 74, 'B'), (75, 99, 'C')],
         [(0, 24, 'A'), (25, 74, 'B'), (75, 99, 'C')]),
    9:  ('Mirror symmetry — same split for SYN and ACK (neg control)',
         [(0, 49, 'A'), (50, 99, 'B')],
         [(0, 49, 'A'), (50, 99, 'B')]),
    10: ('Mid-experiment shift — SYN path changes at t=30s',
         [(0, 99, 'A')],
         [(0, 99, 'B')]),
}


def _ranges_to_pct_str(ranges):
    """Turn [(0,49,'A'),(50,99,'C')] into '50% -> A,  50% -> C' (buckets 0..99 = %)."""
    parts = []
    for lo, hi, dest in ranges:
        pct = hi - lo + 1
        parts.append(f'{pct:3d}% -> {dest}')
    return ',  '.join(parts)


def pick_scenario():
    print()
    print('=' * 78)
    print('  DDoS Controller — Pick split scenario')
    print('  (each scenario installs entries on s1 and s2 split tables)')
    print('=' * 78)
    print()
    for k, (name, syn_ranges, ack_ranges) in SCENARIOS.items():
        print(f'  {k:2d}. {name}')
        if k == 10:
            # Special-case: scenario 10 shifts SYN at t=30s
            print(f'        SYN: {_ranges_to_pct_str(syn_ranges)}'
                  f'   ──► 50% -> A,  50% -> C  @ t=30s')
        else:
            print(f'        SYN: {_ranges_to_pct_str(syn_ranges)}')
        print(f'        ACK: {_ranges_to_pct_str(ack_ranges)}')
        print()
    print('  Legend: "70% -> A" means 70 of every 100 packets of that type go to detector A.')
    print('          A, B, C are the three detector switches running ddos_detector.p4.')
    print()
    while True:
        try:
            choice = int(input('Enter scenario [1-10]: ').strip())
            if choice in SCENARIOS:
                return choice
        except (ValueError, KeyboardInterrupt, EOFError):
            print()
            sys.exit(1)
        print('Invalid choice, try again.')


def _bytes_to_ipv6(raw):
    return str(ipaddress.ip_address(bytes(raw)))


# ================================================================
# ML ENSEMBLE  (unchanged from 2-detector version)
# ================================================================

class EnsembleClassifier:
    def __init__(self, models_dir):
        self.models = {}
        self.scaler = None
        log.info(f"Loading ML models from {models_dir}/")
        for name, fname in [('knn', 'knn_model.pkl'), ('rf',  'rf_model.pkl'),
                             ('dt',  'dt_model.pkl'),  ('xgb', 'xgb_model.pkl'),
                             ('svm', 'svm_model.pkl')]:
            path = os.path.join(models_dir, fname)
            if os.path.exists(path):
                with open(path, 'rb') as f:
                    self.models[name] = pickle.load(f)
                log.info(f"  Loaded: {name}")
            else:
                log.warning(f"  Missing: {path}")
        scaler_path = os.path.join(models_dir, 'scaler.pkl')
        if os.path.exists(scaler_path):
            with open(scaler_path, 'rb') as f:
                self.scaler = pickle.load(f)
        log.info(f"Ensemble ready: {len(self.models)} models loaded")

    def predict(self, pps):
        pps_scaled = pps * 5000.0
        features = np.array([[pps_scaled]])
        if self.scaler:
            features = self.scaler.transform(features)
        votes = sum(1 for m in self.models.values() if m.predict(features)[0] == 1)
        total = len(self.models)
        return votes > (total / 2), votes, total


# ================================================================
# FLOW TABLE  (unchanged)
# ================================================================

class FlowTable:
    def __init__(self, max_size=MAX_FLOW_TABLE_SIZE):
        self._table = {}
        self._lock  = threading.Lock()
        self._max   = max_size

    def record(self, flow_key, timestamp_us):
        with self._lock:
            if flow_key in self._table:
                return False
            if len(self._table) >= self._max:
                del self._table[next(iter(self._table))]
            self._table[flow_key] = [timestamp_us, 0]
            return True

    def get_start(self, flow_key):
        with self._lock:
            e = self._table.get(flow_key)
            return e[0] if e else None

    def increment_ack(self, flow_key):
        with self._lock:
            if flow_key in self._table:
                self._table[flow_key][1] += 1

    def get_ack(self, flow_key):
        with self._lock:
            e = self._table.get(flow_key)
            return e[1] if e else 0


# ================================================================
# CONTROLLER
# ================================================================

class DDoSController:
    def __init__(self, scenario_id):
        self.scenario_id = scenario_id
        name, self.syn_ranges, self.ack_ranges = SCENARIOS[scenario_id]
        self.scenario_name = name

        self.ensemble    = EnsembleClassifier(MODELS_DIR)
        self.flow_table  = FlowTable()
        self.switches    = {}
        self.blocked_ips = set()
        self.stats       = {'first_seen': 0, 'threshold': 0,
                            'evidence':   0, 'attacks':   0, 'benign': 0}
        self._lock       = threading.Lock()

        self.topo = load_topo(TOPO_PATH)
        self._connect_switches()
        self._install_forwarding_rules()
        self._install_split_rules()
        self._enable_digests()

        if scenario_id == 10:
            threading.Timer(30.0, self._scenario_10_shift).start()
            log.info("Scenario 10: SYN split will shift to 50%A / 50%C at t=30s")

    # ------------------------------------------------------------------
    # SETUP
    # ------------------------------------------------------------------

    def _connect_switches(self):
        log.info("Connecting to switches via P4Runtime/gRPC...")
        p4_files = {sw: (SPLITTER_P4RT, SPLITTER_JSON)
                    if sw in SPLITTER_SWITCHES
                    else (DETECTOR_P4RT, DETECTOR_JSON)
                    for sw in self.topo.get_p4switches()}

        for sw in self.topo.get_p4switches():
            device_id = self.topo.get_p4switch_id(sw)
            grpc_port = self.topo.get_grpc_port(sw)
            p4rt, jsn = p4_files[sw]
            try:
                self.switches[sw] = SimpleSwitchP4RuntimeAPI(
                    device_id = device_id,
                    grpc_port = grpc_port,
                    p4rt_path = p4rt,
                    json_path  = jsn,
                )
                role = 'splitter' if sw in SPLITTER_SWITCHES else 'detector'
                log.info(f"  Connected: {sw} [{role}] (device_id={device_id} grpc={grpc_port})")
            except Exception as e:
                log.error(f"  Failed to connect {sw}: {e}")

    def _install_forwarding_rules(self):
        for sw, port_map in PORT_MAPS.items():
            api = self.switches.get(sw)
            if not api:
                log.warning(f"  {sw} not connected — skipping L2 rules")
                continue
            log.info(f"Installing L2 rules on {sw}...")
            for host, port in port_map.items():
                mac = HOST_MACS.get(host)
                if not mac:
                    continue
                try:
                    api.table_add('MyIngress.l2_forward', 'MyIngress.forward',
                                  [mac], [str(port)])
                except Exception as e:
                    if 'already exists' not in str(e).lower():
                        log.warning(f"  {sw} L2 rule failed ({host}): {e}")

    def _install_split_rules(self):
        """Install syn_split + ack_split entries on s1 and s2 per scenario."""
        for sw_name in SPLITTER_SWITCHES:
            api = self.switches.get(sw_name)
            if not api:
                log.warning(f"  {sw_name} not connected — skipping split rules")
                continue
            log.info(f"Installing split rules on {sw_name} (scenario {self.scenario_id})...")

            # SYN split table
            for lo, hi, dest in self.syn_ranges:
                for b in range(lo, hi + 1):
                    try:
                        api.table_add('MyIngress.syn_split',
                                      f'MyIngress.send_to_{dest}', [str(b)])
                    except Exception as e:
                        if 'already exists' not in str(e).lower():
                            log.warning(f"  syn_split[{b}] on {sw_name}: {e}")

            # ACK split table
            for lo, hi, dest in self.ack_ranges:
                for b in range(lo, hi + 1):
                    try:
                        api.table_add('MyIngress.ack_split',
                                      f'MyIngress.send_to_{dest}', [str(b)])
                    except Exception as e:
                        if 'already exists' not in str(e).lower():
                            log.warning(f"  ack_split[{b}] on {sw_name}: {e}")

            syn_count = sum(hi - lo + 1 for lo, hi, _ in self.syn_ranges)
            ack_count = sum(hi - lo + 1 for lo, hi, _ in self.ack_ranges)
            log.info(f"  {sw_name}: installed {syn_count} syn_split + {ack_count} ack_split entries")

    def _scenario_10_shift(self):
        """At t=30s, shift SYN split from 100%A to 50%A / 50%C.
        Clears current syn_split entries and reinstalls.
        """
        new_syn_ranges = [(0, 49, 'A'), (50, 99, 'C')]
        log.warning("=" * 48)
        log.warning("SCENARIO 10 SHIFT — SYN split now 50%A / 50%C")
        log.warning("=" * 48)
        for sw_name in SPLITTER_SWITCHES:
            api = self.switches.get(sw_name)
            if not api:
                continue
            # Try table_clear; fall back to per-entry delete
            try:
                api.table_clear('MyIngress.syn_split')
            except AttributeError:
                for b in range(100):
                    try:
                        api.table_delete_match('MyIngress.syn_split', [str(b)])
                    except Exception:
                        pass
            except Exception as e:
                log.warning(f"  {sw_name} table_clear: {e}")
            # Reinstall new ranges
            for lo, hi, dest in new_syn_ranges:
                for b in range(lo, hi + 1):
                    try:
                        api.table_add('MyIngress.syn_split',
                                      f'MyIngress.send_to_{dest}', [str(b)])
                    except Exception as e:
                        if 'already exists' not in str(e).lower():
                            log.warning(f"  syn_split[{b}] shift on {sw_name}: {e}")
            log.info(f"  {sw_name}: syn_split reconfigured")

    def _enable_digests(self):
        """Enable all three digest types on every detector switch.
        Splitter switches (s1, s2) do not run detector P4 — skipped."""
        for sw, api in self.switches.items():
            if sw in SPLITTER_SWITCHES:
                continue
            log.info(f"Enabling digests on {sw}...")
            for name in ('first_seen_digest_t', 'threshold_digest_t', 'evidence_digest_t'):
                try:
                    api.digest_enable(name, max_timeout_ns=0,
                                      max_list_size=1, ack_timeout_ns=0)
                    log.info(f"  {sw}: enabled {name}")
                except Exception as e:
                    log.warning(f"  {sw} digest_enable({name}): {e}")

    # ------------------------------------------------------------------
    # BLOCKING — pushed to ALL detector switches
    # ------------------------------------------------------------------

    def _push_block_rule(self, src_ip_str):
        for sw, api in self.switches.items():
            if sw in SPLITTER_SWITCHES:
                continue
            try:
                api.table_add('MyIngress.dangerous_table', 'MyIngress.drop',
                              [src_ip_str])
                log.info(f"  Block rule installed on {sw}: {src_ip_str}")
            except Exception as e:
                if 'already exists' not in str(e).lower():
                    log.warning(f"  Block rule failed on {sw}: {e}")

    # ------------------------------------------------------------------
    # DIGEST HANDLERS  (unchanged from 2-detector version)
    # ------------------------------------------------------------------

    def _handle_first_seen(self, members, sw_name):
        src_ip    = _bytes_to_ipv6(members[0].bitstring)
        dst_ip    = _bytes_to_ipv6(members[1].bitstring)
        dst_port  = int.from_bytes(members[2].bitstring, 'big')
        protocol  = int.from_bytes(members[3].bitstring, 'big')
        timestamp = int.from_bytes(members[4].bitstring, 'big')

        flow_key = (src_ip, dst_ip, dst_port, protocol)
        is_new = self.flow_table.record(flow_key, timestamp)

        with self._lock:
            self.stats['first_seen'] += 1

        if is_new:
            log.info(f"FIRST_SEEN  [{sw_name}]  {src_ip} -> {dst_ip}:{dst_port} "
                     f"proto={protocol}  ts={timestamp}us")

    def _handle_threshold(self, members, sw_name):
        src_ip    = _bytes_to_ipv6(members[0].bitstring)
        dst_ip    = _bytes_to_ipv6(members[1].bitstring)
        dst_port  = int.from_bytes(members[2].bitstring, 'big')
        protocol  = int.from_bytes(members[3].bitstring, 'big')
        cms_min   = int.from_bytes(members[4].bitstring, 'big')
        timestamp = int.from_bytes(members[5].bitstring, 'big')

        flow_key = (src_ip, dst_ip, dst_port, protocol)

        with self._lock:
            self.stats['threshold'] += 1
            already_blocked = src_ip in self.blocked_ips

        if already_blocked:
            return

        start_time = self.flow_table.get_start(flow_key)
        if start_time is None:
            start_time = timestamp - 1_000_000

        ack_count     = self.flow_table.get_ack(flow_key)
        adjusted      = max(0, cms_min - ack_count)
        elapsed       = max(0.001, (timestamp - start_time) / 1_000_000.0)
        pps           = adjusted / elapsed

        is_attack, votes, total = self.ensemble.predict(pps)

        log.info(f"THRESHOLD   [{sw_name}]  {src_ip} -> :{dst_port}  "
                 f"cms_min={cms_min}  ack_count={ack_count}  adjusted={adjusted}  "
                 f"elapsed={elapsed:.3f}s  pps={pps:.1f}  pps_scaled={pps*5000:.0f}  vote={votes}/{total}")

        if is_attack:
            log.warning(
                f"\n{'─'*48}\n"
                f"  ATTACK DETECTED\n"
                f"  src        : {src_ip}  (via {sw_name})\n"
                f"  cms_min    : {cms_min}   ack_count  : {ack_count}   adjusted : {adjusted}\n"
                f"  pps        : {pps:.1f}   pps_scaled : {pps*5000:.0f}   vote : {votes}/{total}\n"
                f"  action     : drop rule installed on ALL detector switches\n"
                f"{'─'*48}"
            )
            with self._lock:
                self.blocked_ips.add(src_ip)
                self.stats['attacks'] += 1
            self._push_block_rule(src_ip)
        else:
            log.info(
                f"\n{'─'*48}\n"
                f"  BENIGN\n"
                f"  src        : {src_ip}  (via {sw_name})\n"
                f"  cms_min    : {cms_min}   ack_count  : {ack_count}   adjusted : {adjusted}\n"
                f"  pps        : {pps:.1f}   pps_scaled : {pps*5000:.0f}   vote : {votes}/{total}\n"
                f"{'─'*48}"
            )
            with self._lock:
                self.stats['benign'] += 1

    def _handle_evidence(self, members, sw_name):
        src_ip   = _bytes_to_ipv6(members[0].bitstring)
        dst_ip   = _bytes_to_ipv6(members[1].bitstring)
        dst_port = int.from_bytes(members[2].bitstring, 'big')
        protocol = int.from_bytes(members[3].bitstring, 'big')

        flow_key = (src_ip, dst_ip, dst_port, protocol)
        self.flow_table.increment_ack(flow_key)

        with self._lock:
            self.stats['evidence'] += 1

        log.debug(f"EVIDENCE    [{sw_name}]  {src_ip} -> :{dst_port}")

    # ------------------------------------------------------------------
    # DIGEST RECEIVER  (unchanged)
    # ------------------------------------------------------------------

    def _recv_digest(self, sw_name):
        api = self.switches.get(sw_name)
        if not api:
            log.error(f"Digest receiver: no API for {sw_name}")
            return

        log.info(f"Digest receiver ready on {sw_name}")
        while True:
            try:
                digest_list = api.get_digest_list(timeout=1)
                if digest_list is None:
                    continue

                for digest_entry in digest_list.data:
                    members = digest_entry.struct.members
                    n = len(members)

                    if n == 4:
                        self._handle_evidence(members, sw_name)
                    elif n == 5:
                        self._handle_first_seen(members, sw_name)
                    elif n == 6:
                        self._handle_threshold(members, sw_name)
                    else:
                        log.warning(f"Unexpected digest on {sw_name}: {n} members")

            except Exception as e:
                if 'timeout' not in str(e).lower():
                    log.error(f"Digest stream error on {sw_name}: {e}")

    # ------------------------------------------------------------------
    # MAIN LOOP
    # ------------------------------------------------------------------

    def start(self):
        detector_switches = [sw for sw in self.switches if sw not in SPLITTER_SWITCHES]
        for sw in detector_switches:
            t = threading.Thread(target=self._recv_digest, args=(sw,), daemon=True)
            t.start()

        log.info("")
        log.info("=" * 60)
        log.info(f"DDoS Detection Controller RUNNING — scenario {self.scenario_id}")
        log.info(f"  Scenario          : {self.scenario_name}")
        log.info(f"  Splitter switches : {sorted(SPLITTER_SWITCHES)}")
        log.info(f"  Detector switches : {sorted(detector_switches)}")
        log.info(f"  SYN ranges        : {self.syn_ranges}")
        log.info(f"  ACK ranges        : {self.ack_ranges}")
        log.info("  Digests : first_seen | threshold | evidence (all 3 on each detector)")
        log.info("  Blocking: dangerous_table pushed to ALL detector switches")
        log.info("  pps formula: max(0, cms_min - ack_count) / elapsed_total")
        log.info("=" * 60)

        try:
            while True:
                time.sleep(10)
                with self._lock:
                    s = self.stats.copy()
                    n_blocked = len(self.blocked_ips)
                log.info(f"STATS | FirstSeen:{s['first_seen']}  "
                         f"Threshold:{s['threshold']}  Evidence:{s['evidence']}  "
                         f"Attacks:{s['attacks']}  Benign:{s['benign']}  "
                         f"Blocked:{n_blocked}")
        except KeyboardInterrupt:
            with self._lock:
                s = self.stats.copy()
                n_blocked = len(self.blocked_ips)
            print("\n" + "=" * 60)
            print(f"FINAL STATS — scenario {self.scenario_id} ({self.scenario_name})")
            print(f"  FIRST_SEEN digests  : {s['first_seen']}")
            print(f"  THRESHOLD digests   : {s['threshold']}")
            print(f"  EVIDENCE digests    : {s['evidence']}")
            print(f"  Attacks detected    : {s['attacks']}")
            print(f"  Benign flows        : {s['benign']}")
            print(f"  IPs blocked         : {n_blocked}")
            print("=" * 60)


if __name__ == '__main__':
    scenario = pick_scenario()
    ctrl = DDoSController(scenario)
    ctrl.start()
