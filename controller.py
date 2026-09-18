"""P4Runtime controller for the Clos fat-tree.

Installs l2_forward on all 20 switches; runs detection on the 8 aggregation
switches. Per THRESHOLD it computes windowed features, scores the flow with the
lean model, and blocks a source (on every detector) once its reputation score
hits BLOCK_SCORE. Self-contained: the detection classes are here, not imported.
Run:  python3 controller.py
"""
import os, sys, time, pickle, threading, logging, ipaddress, subprocess
import numpy as np
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, 'lib'))
sys.path.insert(0, '/home/ayush/p4-tools/p4-utils')
import fattree as ft
from p4utils.utils.sswitch_p4runtime_API import SimpleSwitchP4RuntimeAPI
from p4utils.utils.helper import load_topo

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(message)s', datefmt='%H:%M:%S')
log = logging.getLogger('clos')

MODELS_DIR = os.path.join(HERE, 'models')
TOPO_PATH  = os.path.join(HERE, 'topology.json')
os.makedirs(os.path.join(HERE, 'tmp'), exist_ok=True)          # run artifacts (gitignored)
EVAL_CSV   = os.path.join(HERE, 'tmp', 'threshold_evals.csv')
P4FILES = {'core': ('p4src/ft_core_p4rt.txt', 'p4src/ft_core.json'),
           'agg':  ('p4src/ddos_detector_p4rt.txt', 'p4src/ddos_detector.json'),
           'edge': ('p4src/ft_edge_p4rt.txt', 'p4src/ft_edge.json')}
THRIFT = {sw: 9090 + i for i, sw in enumerate(ft.CORES + ft.AGGS + ft.EDGES)}

# reputation: never block on one window (+1 benign, -1 attack, block at <= -2)
REWARD, PENALTY, CAP, BLOCK_SCORE = 1, 1, 3, -2

def role(sw): return 'core' if sw in ft.CORES else ('agg' if sw in ft.AGGS else 'edge')
def _ip6(raw): return str(ipaddress.ip_address(bytes(raw)))


class LeanModel:
    """Trained classifier over 6 windowed features."""
    def __init__(self, d):
        self.model = pickle.load(open(os.path.join(d, 'lean_model.pkl'), 'rb'))
        self.order = pickle.load(open(os.path.join(d, 'lean_feature_order.pkl'), 'rb'))
    def predict(self, f):                                       # True = attack
        return int(self.model.predict(np.array([[float(f[k]) for k in self.order]]))[0]) == 1


class FlowTable:
    """Per-flow state: [first_seen, ack_count, last_eval, last_cms_syn, score]."""
    def __init__(self, cap=100_000):
        self.t, self.lock, self.cap = {}, threading.Lock(), cap
    def record(self, fk, ts):                                   # note a new flow once
        with self.lock:
            if fk in self.t: return
            if len(self.t) >= self.cap: del self.t[next(iter(self.t))]
            self.t[fk] = [ts, 0, ts, 0, 0]
    def add_ack(self, fk):                                      # EVIDENCE -> +1 windowed ack
        with self.lock:
            if fk in self.t: self.t[fk][1] += 1
    def bump(self, fk, d):                                      # move reputation score (capped)
        with self.lock:
            e = self.t.setdefault(fk, [0, 0, 0, 0, 0])
            e[4] = min(CAP, e[4] + d); return e[4]
    def snap(self, fk, cms, ts):                               # read window + reset, atomically
        with self.lock:
            e = self.t.setdefault(fk, [ts, 0, ts, 0, 0])
            fs, ack, start, last = e[0], e[1], e[2], e[3]
            e[1], e[2], e[3] = 0, ts, cms
            return fs, last, ack, start


class Controller:
    def __init__(self):
        self.model = LeanModel(MODELS_DIR)
        self.flows = FlowTable()
        self.sw = {}
        self.blocked = set()
        self.stats = dict(first_seen=0, threshold=0, evidence=0, benign=0, suspicious=0, blocked=0)
        self.lock = threading.Lock()
        self.csv = open(EVAL_CSV, 'w')
        self.csv.write('time_us,sw,src_ip,dst_port,syn_d,ack_d,unacked,'
                       'completion_ratio,syn_rate_pps,duration_s,verdict,score,blocked\n')
        self.topo = load_topo(TOPO_PATH)
        self._connect(); self._reset(); self._forward(); self._digests()

    # ---- setup ----
    def _connect(self):
        for s in self.topo.get_p4switches():
            p4rt, jsn = P4FILES[role(s)]
            try:
                self.sw[s] = SimpleSwitchP4RuntimeAPI(self.topo.get_p4switch_id(s),
                              self.topo.get_grpc_port(s), p4rt_path=p4rt, json_path=jsn)
            except Exception as e:
                log.error(f"connect {s}: {e}")
        log.info(f"connected {len(self.sw)}/20 switches")

    def _reset(self):                                          # clean slate on each start
        for s in ft.AGGS:
            api = self.sw.get(s)
            if not api: continue
            try: api.table_clear('MyIngress.dangerous_table')
            except Exception: pass
            subprocess.run(['simple_switch_CLI', '--thrift-port', str(THRIFT[s])],
                           input='register_reset MyIngress.cms_row0\nregister_reset MyIngress.cms_row1\n',
                           capture_output=True, text=True, timeout=15)

    def _forward(self):                                        # l2_forward on all switches
        for s, rules in ft.ROUTES.items():
            api = self.sw.get(s)
            if not api: continue
            for mac, port in rules:
                try: api.table_add('MyIngress.l2_forward', 'MyIngress.forward', [mac], [str(port)])
                except Exception as e:
                    if 'exist' not in str(e).lower(): log.warning(f"{s} l2: {e}")
        log.info("forwarding installed on all 20 switches")

    def _digests(self):                                       # enable digests on detectors
        for s in ft.AGGS:
            api = self.sw.get(s)
            if not api: continue
            for d in ('first_seen_digest_t', 'threshold_digest_t', 'evidence_digest_t'):
                try: api.digest_enable(d, max_timeout_ns=0, max_list_size=1, ack_timeout_ns=0)
                except Exception as e: log.warning(f"{s} digest {d}: {e}")
        log.info(f"digests enabled on {len(ft.AGGS)} detectors")

    def _block(self, ip):                                     # drop rule on every detector
        for s in ft.AGGS:
            api = self.sw.get(s)
            if not api: continue
            try: api.table_add('MyIngress.dangerous_table', 'MyIngress.drop', [ip])
            except Exception as e:
                if 'exist' not in str(e).lower(): log.warning(f"block {ip} {s}: {e}")

    # ---- digest handlers ----
    def _first_seen(self, m, s):
        self.flows.record((_ip6(m[0].bitstring), _ip6(m[1].bitstring),
                           int.from_bytes(m[2].bitstring, 'big'), int.from_bytes(m[3].bitstring, 'big')),
                          int.from_bytes(m[4].bitstring, 'big'))
        with self.lock: self.stats['first_seen'] += 1

    def _evidence(self, m, s):
        self.flows.add_ack((_ip6(m[0].bitstring), _ip6(m[1].bitstring),
                            int.from_bytes(m[2].bitstring, 'big'), int.from_bytes(m[3].bitstring, 'big')))
        with self.lock: self.stats['evidence'] += 1

    def _threshold(self, m, s):
        src, dst = _ip6(m[0].bitstring), _ip6(m[1].bitstring)
        port, proto = int.from_bytes(m[2].bitstring, 'big'), int.from_bytes(m[3].bitstring, 'big')
        cms, ts = int.from_bytes(m[4].bitstring, 'big'), int.from_bytes(m[5].bitstring, 'big')
        fk = (src, dst, port, proto)
        with self.lock:
            self.stats['threshold'] += 1
            if src in self.blocked: return
        _, last, ack, start = self.flows.snap(fk, cms, ts)
        syn = cms - last if cms - last > 0 else cms                 # windowed SYNs (~32)
        unacked = max(0, syn - ack)
        compl = ack / syn if syn else 0.0
        elapsed = max(0.001, (ts - start) / 1e6)
        feats = dict(syn_count=syn, ack_count=ack, unacked=unacked, completion_ratio=compl,
                     syn_rate_pps=syn / elapsed, duration_s=elapsed)
        attack = self.model.predict(feats)
        score = self.flows.bump(fk, -PENALTY if attack else REWARD)
        do_block = score <= BLOCK_SCORE
        self.csv.write(f"{ts},{s},{src},{port},{syn},{ack},{unacked},{compl:.4f},"
                       f"{syn/elapsed:.2f},{elapsed:.4f},{'ATTACK' if attack else 'BENIGN'},"
                       f"{score},{'BLOCK' if do_block else ''}\n"); self.csv.flush()
        if do_block:
            with self.lock:
                if src in self.blocked: return
                self.blocked.add(src); self.stats['blocked'] += 1
            log.info(f"BLOCK {src} (score {score}) via {s}")
            self._block(src)
        else:
            with self.lock:
                self.stats['suspicious' if attack else 'benign'] += 1

    def _recv(self, s):
        api = self.sw.get(s)
        if not api: return
        while True:
            try:
                dl = api.get_digest_list(timeout=1)
                if dl is None: continue
                for d in dl.data:
                    m = d.struct.members
                    (self._evidence if len(m) == 4 else self._first_seen if len(m) == 5
                     else self._threshold)(m, s)
            except Exception as e:
                if 'timeout' not in str(e).lower(): log.error(f"digest {s}: {e}")

    def start(self):
        for s in ft.AGGS:
            threading.Thread(target=self._recv, args=(s,), daemon=True).start()
        log.info(f"CLOS controller RUNNING  detectors={ft.AGGS}")
        try:
            while True:
                time.sleep(10)
                with self.lock: s = dict(self.stats)
                log.info(f"STATS | FirstSeen:{s['first_seen']} Threshold:{s['threshold']} "
                         f"Evidence:{s['evidence']} Benign:{s['benign']} "
                         f"Suspicious:{s['suspicious']} Blocked:{s['blocked']}")
        except KeyboardInterrupt:
            with self.lock: s = dict(self.stats)
            print(f"\nFINAL | Threshold:{s['threshold']} Benign:{s['benign']} "
                  f"Suspicious:{s['suspicious']} Blocked:{s['blocked']}")


if __name__ == '__main__':
    Controller().start()
