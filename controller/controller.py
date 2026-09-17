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

The active scenario is chosen at startup via an interactive prompt.
The chosen scenario determines which
entries the controller installs into the syn_split and ack_split
tables on s1 and s2.

Detection: at each THRESHOLD digest the controller computes six host-level
features (syn_count, ack_count, unacked, completion_ratio, syn_rate_pps,
duration_s) and feeds them to a single trained model (lean_model.pkl). The
ack_count comes from EVIDENCE digests, so an ACK that took a different path is
still counted (asymmetric-routing reconstruction). On an ATTACK verdict the
drop rule is installed on all detector switches.
"""

import os, sys, time, pickle, threading, logging, ipaddress, subprocess
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
# REPUTATION / HYSTERESIS  — don't block on ONE bad window.
#   each flow carries a score: +REWARD on a benign window (capped at
#   SCORE_CAP), -PENALTY on an attack window; BLOCK only when the score
#   reaches BLOCK_SCORE (sustained attack over several windows).
#   RTT-lagged benign flow: one bad window -> score -1, then recovers ->
#   never reaches BLOCK_SCORE -> not blocked. Real attacker: bad every
#   window -> crosses BLOCK_SCORE in |BLOCK_SCORE| windows -> blocked.
# ================================================================
SCORE_REWARD =  1     # benign window
SCORE_PENALTY = 1     # attack window
SCORE_CAP     = 3     # max positive credit a flow can bank
BLOCK_SCORE   = -2    # block when score <= this

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
# LEAN MODEL  (single model, 6 host-level features)
# ================================================================

class LeanModel:
    """Loads the lean model + its feature order. Predicts on the 6 windowed
    features the controller computes at each THRESHOLD (no rate-scaling hack)."""

    def __init__(self, models_dir):
        with open(os.path.join(models_dir, 'lean_model.pkl'), 'rb') as f:
            self.model = pickle.load(f)
        with open(os.path.join(models_dir, 'lean_feature_order.pkl'), 'rb') as f:
            self.feature_order = pickle.load(f)
        log.info(f"Lean model loaded; features (in order): {self.feature_order}")

    def predict(self, feats):
        """feats: dict of feature_name -> value. Returns True if ATTACK."""
        x = np.array([[float(feats[f]) for f in self.feature_order]])
        return int(self.model.predict(x)[0]) == 1


# ================================================================
# FLOW TABLE  (windowed: counts reset every THRESHOLD evaluation)
#
# entry layout: [first_seen_us, ack_count, last_eval_us, last_cms_syn, score]
#   first_seen_us : true flow age reference — IMMUTABLE, never overwritten
#   ack_count     : EVIDENCE-reconstructed remote ACKs since the last eval
#                   (windowed — reset to 0 at each THRESHOLD eval)
#   last_eval_us  : window start — reset to the eval timestamp each eval
#   last_cms_syn  : CMS snapshot at the last eval (to compute syn_delta)
#   score         : reputation score (hysteresis) — cross-window memory that
#                   SURVIVES the count resets; block only when it drops to
#                   BLOCK_SCORE. See REPUTATION constants above.
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
            self._table[flow_key] = [timestamp_us, 0, timestamp_us, 0, 0]
            return True

    def bump_score(self, flow_key, delta, cap):
        """Add delta to this flow's reputation score (capped at +cap on the
        high side) and return the new score. Runs under the table lock."""
        with self._lock:
            e = self._table.get(flow_key)
            if e is None:
                e = [0, 0, 0, 0, 0]
                self._table[flow_key] = e
            e[4] = min(cap, e[4] + delta)
            return e[4]

    def increment_ack(self, flow_key):
        with self._lock:
            if flow_key in self._table:
                self._table[flow_key][1] += 1

    def get_ack(self, flow_key):
        with self._lock:
            e = self._table.get(flow_key)
            return e[1] if e else 0

    def snapshot_and_reset(self, flow_key, cms_min, timestamp_us):
        """Atomically READ this flow's window (ACKs since last eval, previous
        CMS snapshot, window-start time) AND reset the window — in ONE locked
        step. ACKs arriving after this call land in the fresh window and are
        NOT lost (they count toward the next window). first_seen is never
        modified.  Returns (first_seen_us, last_cms_syn, ack_window, window_start_us)."""
        with self._lock:
            e = self._table.get(flow_key)
            if e is None:
                # THRESHOLD without a prior FIRST_SEEN (lost digest) — synthesise
                e = [timestamp_us, 0, timestamp_us, 0, 0]
                self._table[flow_key] = e
            first_seen   = e[0]
            ack_window   = e[1]
            window_start = e[2]
            last_cms     = e[3]
            # reset the window (first_seen at e[0] is left untouched)
            e[1] = 0
            e[2] = timestamp_us
            e[3] = cms_min
            return first_seen, last_cms, ack_window, window_start


# ================================================================
# CONTROLLER
# ================================================================

class DDoSController:
    def __init__(self, scenario_id):
        self.scenario_id = scenario_id
        name, self.syn_ranges, self.ack_ranges = SCENARIOS[scenario_id]
        self.scenario_name = name

        self.model       = LeanModel(MODELS_DIR)
        self.flow_table  = FlowTable()
        self.switches    = {}
        self.blocked_ips = set()
        self.stats       = {'first_seen': 0, 'threshold': 0, 'evidence':   0,
                            'attacks':   0, 'benign': 0, 'suspicious': 0}
        self._lock       = threading.Lock()

        # per-eval feature dump for diagnostics (analyze_evals.py reads this).
        # In a benign run, any row with verdict=ATTACK is a FALSE POSITIVE.
        self._csv_lock = threading.Lock()
        try:
            self._eval_csv = open('/tmp/threshold_evals.csv', 'w')
            self._eval_csv.write('time_us,sw,src_ip,dst_port,syn_d,ack_d,unacked,'
                                 'completion_ratio,syn_rate_pps,duration_s,verdict,'
                                 'score,blocked\n')
            self._eval_csv.flush()
        except Exception as e:
            log.warning(f"eval CSV disabled: {e}")
            self._eval_csv = None

        self.topo = load_topo(TOPO_PATH)
        self._connect_switches()
        self._reset_switch_state()          # wipe old CMS counts + block rules
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

    # detector thrift ports (simple_switch_grpc also runs a thrift server here)
    _THRIFT_FALLBACK = {'A': 9092, 'B': 9093, 'C': 9094}

    def _reset_switch_state(self):
        """Make every controller (re)start a CLEAN slate WITHOUT restarting
        mininet or the switches:
          * clear the block table (dangerous_table) via P4Runtime, and
          * zero the CMS registers (cms_row0/1) via the switch's thrift CLI.
        Run once at startup, on the 3 detectors only (splitters have neither)."""
        for sw, api in self.switches.items():
            if sw in SPLITTER_SWITCHES:
                continue
            # 1) drop all previously-installed block rules
            try:
                api.table_clear('MyIngress.dangerous_table')
            except Exception as e:
                if 'no entries' not in str(e).lower():
                    log.warning(f"  {sw} dangerous_table clear: {e}")
            # 2) zero the CMS counters over thrift
            try:
                tport = self.topo.get_thrift_port(sw)
            except Exception:
                tport = self._THRIFT_FALLBACK.get(sw)
            if not tport:
                log.warning(f"  {sw}: no thrift port, CMS not reset")
                continue
            cmds = "register_reset MyIngress.cms_row0\nregister_reset MyIngress.cms_row1\n"
            try:
                subprocess.run(['simple_switch_CLI', '--thrift-port', str(tport)],
                               input=cmds, capture_output=True, text=True, timeout=15)
                log.info(f"  {sw}: CMS registers reset + block rules cleared (thrift {tport})")
            except FileNotFoundError:
                log.warning("  simple_switch_CLI not on PATH — CMS not reset "
                            "(restart mininet for a clean CMS)")
            except Exception as e:
                log.warning(f"  {sw} CMS reset: {e}")

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

        # ---- WINDOWED features: each THRESHOLD eval measures ONLY the window
        # since the previous eval, via an atomic snapshot-and-reset (see TODO.md).
        #   syn_count = new SYNs this window = CMS snapshot delta (~32 in the
        #               asymmetric case, where cms_min is monotonic-up because
        #               ACKs take the other path). cms_min is already net of any
        #               LOCAL ACK decrement done in the dataplane.
        #   ack_count = EVIDENCE-reconstructed remote ACKs THIS window (then reset)
        # first_seen (immutable) is returned for logging but not used as the clock.
        first_seen, last_cms, ack_window, window_start = \
            self.flow_table.snapshot_and_reset(flow_key, cms_min, timestamp)

        syn_count = cms_min - last_cms
        if syn_count <= 0:
            # non-monotonic CMS (contamination, or a local-ACK decrement dipped
            # cms_min below the last snapshot) — fall back to the raw count.
            syn_count = cms_min
        ack_count        = ack_window
        unacked          = max(0, syn_count - ack_count)
        completion_ratio = (ack_count / syn_count) if syn_count > 0 else 0.0
        elapsed          = max(0.001, (timestamp - window_start) / 1_000_000.0)
        syn_rate_pps     = syn_count / elapsed
        duration_s       = elapsed

        feats = {
            'syn_count':        syn_count,
            'ack_count':        ack_count,
            'unacked':          unacked,
            'completion_ratio': completion_ratio,
            'syn_rate_pps':     syn_rate_pps,
            'duration_s':       duration_s,
        }
        is_attack = self.model.predict(feats)   # per-WINDOW verdict (may be noisy)

        # Reputation / hysteresis: a single bad window must NOT block. Move the
        # flow's score (+REWARD benign, -PENALTY attack) and block only once it
        # has behaved like an attack across enough windows to reach BLOCK_SCORE.
        delta = -SCORE_PENALTY if is_attack else SCORE_REWARD
        score = self.flow_table.bump_score(flow_key, delta, SCORE_CAP)
        should_block = score <= BLOCK_SCORE

        log.info(f"THRESHOLD   [{sw_name}]  {src_ip} -> :{dst_port}  [window] "
                 f"synΔ={syn_count} ackΔ={ack_count} unacked={unacked} "
                 f"compl={completion_ratio:.2f} pps={syn_rate_pps:.1f} win={duration_s:.3f}s "
                 f"score={score} -> {'ATTACK' if is_attack else 'BENIGN'}"
                 f"{'  [BLOCK]' if should_block else ''}")

        if self._eval_csv is not None:
            with self._csv_lock:
                self._eval_csv.write(
                    f"{timestamp},{sw_name},{src_ip},{dst_port},{syn_count},{ack_count},"
                    f"{unacked},{completion_ratio:.4f},{syn_rate_pps:.2f},{duration_s:.4f},"
                    f"{'ATTACK' if is_attack else 'BENIGN'},{score},"
                    f"{'BLOCK' if should_block else ''}\n")
                self._eval_csv.flush()

        if should_block:
            # atomic check-and-reserve: if two detectors flag the same attacker
            # at once, only the FIRST thread past this lock pushes the rule.
            with self._lock:
                if src_ip in self.blocked_ips:
                    return                       # already handled by another thread
                self.blocked_ips.add(src_ip)     # reserve now, inside the lock
                self.stats['attacks'] += 1
            log.warning(
                f"\n{'─'*48}\n"
                f"  ATTACK DETECTED  (score {score} <= {BLOCK_SCORE})\n"
                f"  src     : {src_ip}  (via {sw_name})\n"
                f"  syn={syn_count} ack={ack_count} unacked={unacked} "
                f"completion_ratio={completion_ratio:.2f}\n"
                f"  action  : drop rule installed on ALL detector switches\n"
                f"{'─'*48}"
            )
            self._push_block_rule(src_ip)
        else:
            with self._lock:
                if is_attack:
                    self.stats['suspicious'] += 1   # bad window, not yet blocked
                else:
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
        log.info(f"  Model   : lean_model.pkl  features={self.model.feature_order}")
        log.info("=" * 60)

        try:
            while True:
                time.sleep(10)
                with self._lock:
                    s = self.stats.copy()
                    n_blocked = len(self.blocked_ips)
                log.info(f"STATS | FirstSeen:{s['first_seen']}  "
                         f"Threshold:{s['threshold']}  Evidence:{s['evidence']}  "
                         f"Benign:{s['benign']}  Suspicious:{s['suspicious']}  "
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
            print(f"  Benign windows      : {s['benign']}")
            print(f"  Suspicious windows  : {s['suspicious']}   (bad window, score not yet at block)")
            print(f"  Block events        : {s['attacks']}")
            print(f"  IPs blocked         : {n_blocked}")
            print("=" * 60)


if __name__ == '__main__':
    scenario = pick_scenario()
    ctrl = DDoSController(scenario)
    ctrl.start()
