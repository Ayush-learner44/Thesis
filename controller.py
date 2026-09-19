"""P4Runtime controller for the Clos fat-tree.

Installs l2_forward on all 20 switches; runs detection on the 8 aggregation
switches. Per THRESHOLD it computes windowed features, scores the flow with the
lean model, and blocks a source (on every detector) once its reputation score
hits BLOCK_SCORE. Self-contained: the detection classes are here, not imported.
Run:  python3 controller.py
"""
import os, sys, time, math, pickle, threading, logging, ipaddress, subprocess, collections
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
IP2NAME = {h['ipv6']: h['name'] for h in ft.HOSTS}          # readable spoof-victim names


class LeanModel:
    """Trained classifier over 6 windowed features."""
    def __init__(self, d):
        self.model = pickle.load(open(os.path.join(d, 'lean_model.pkl'), 'rb'))
        self.order = pickle.load(open(os.path.join(d, 'lean_feature_order.pkl'), 'rb'))
    def predict(self, f):                                       # True = attack
        return int(self.model.predict(np.array([[float(f[k]) for k in self.order]]))[0]) == 1


class Reporter:
    """Single home for real-time console output (timestamped, coloured, aligned).
    Detection logic only calls seen()/vote()/block()/mark(); formatting lives here."""
    _C = dict(t='\033[2m', SEEN='\033[36m', BENIGN='\033[32m', ATTACK='\033[33m',
              BLOCK='\033[1;31m', mark='\033[1;35m', z='\033[0m')
    def _stamp(self): return f"{self._C['t']}{time.strftime('%H:%M:%S')}{self._C['z']}"
    def seen(self, ip, port):
        print(f"{self._stamp()} {self._C['SEEN']}SEEN {self._C['z']} {ip:<22} :{port}  new flow", flush=True)
    def vote(self, ip, verdict, score, compl, syn, ack):
        c = self._C[verdict]
        print(f"{self._stamp()} {c}VOTE {verdict:<6}{self._C['z']} {ip:<22} "
              f"score={score:+d} compl={compl:.2f} syn={syn} ack={ack}", flush=True)
    def block(self, ip, score):
        print(f"{self._stamp()} {self._C['BLOCK']}BLOCK{self._C['z']} {ip:<22} "
              f"score={score} -> dropped on all detectors", flush=True)
    def mark(self, text):
        print(f"{self._stamp()} {self._C['mark']}── {text} ──{self._C['z']}", flush=True)
    def entropy(self, H, victim, vsyn, total, vsrc, suspect=False):
        share = vsyn / total if total else 0.0
        tag = f"  {self._C['BLOCK']}<< SPOOF SUSPECTED >>{self._C['z']}" if suspect else ""
        print(f"{self._stamp()} {self._C['mark']}ENTROPY H={H:.2f}  top={victim} "
              f"({vsyn}/{total} uncompleted, {share:.0%})  distinct_srcs={vsrc}{self._C['z']}{tag}", flush=True)


class EntropyMonitor:
    """Completion-gated traffic-entropy over destinations (report-only for now).
    LIVE set { dst : uncompleted source IPs }: a source is ADDED on FIRST_SEEN and
    REMOVED on EVIDENCE (its flow completed, sym or asym path). Every `window` s it
    snapshots (does NOT clear) and computes Tsallis entropy over the per-dst
    uncompleted-source counts. Entropy DROPS when uncompleted flows pile onto one
    victim = the spoofing signature: spoofed sources never complete so they persist,
    while benign sources are removed within ~1 RTT. Not wired into blocking yet."""
    def __init__(self, reporter, tmp=None, window=2.0, q=2.0, card_thresh=50):
        self.rep, self.win, self.q, self.tmp = reporter, window, q, tmp
        self.card_thresh = card_thresh                         # min uncompleted srcs to call it spoofing
        self.lock = threading.Lock()
        self.srcs = collections.defaultdict(set)               # dst -> {uncompleted src}
        self.suspects = {}                                     # victim_ip -> peak uncompleted-src count
        self._last = None                                      # last reported snapshot (dedup)
        self.min_H, self.max_H = float('inf'), 0.0             # entropy range over the run
    def arrived(self, src, dst):                               # FIRST_SEEN: new flow
        with self.lock: self.srcs[dst].add(src)
    def completed(self, src, dst):                             # EVIDENCE: flow finished -> drop
        with self.lock:
            s = self.srcs.get(dst)
            if s is not None: s.discard(src)
    def _tsallis(self, counts):
        tot = sum(counts)
        if tot <= 0: return 0.0
        ps = [c / tot for c in counts]
        if self.q == 1.0:                                      # Shannon limit
            return -sum(p * math.log2(p) for p in ps if p > 0)
        return (1.0 - sum(p ** self.q for p in ps)) / (self.q - 1.0)
    def _flush(self):
        with self.lock:
            counts = {d: len(v) for d, v in self.srcs.items() if v}   # snapshot, DON'T clear
        if not counts: return
        sig = tuple(sorted(counts.items()))
        if sig == self._last: return                           # unchanged since last window -> don't repeat
        self._last = sig
        H = self._tsallis(list(counts.values()))
        self.min_H = min(self.min_H, H); self.max_H = max(self.max_H, H)
        victim = max(counts, key=counts.get)
        top = counts[victim]
        flagged = False
        for d, n in counts.items():                            # flag EVERY dest over threshold
            if n >= self.card_thresh:
                self.suspects[d] = max(self.suspects.get(d, 0), n); flagged = True
        self.rep.entropy(H, victim, top, sum(counts.values()), top, flagged)
        if self.tmp: self.dump(self.tmp)                       # keep verify.py's files fresh (every change)
    def run(self):                                             # daemon loop
        while True:
            time.sleep(self.win)
            self._flush()
    def dump(self, tmp):                                       # write detection + entropy for verify.py
        with self.lock:
            sus = dict(self.suspects); mn, mx = self.min_H, self.max_H
        with open(os.path.join(tmp, 'spoof_detected.csv'), 'w') as f:
            f.write('server_ip,peak_uncompleted\n')
            for ip, c in sorted(sus.items(), key=lambda kv: -kv[1]):
                f.write(f'{ip},{c}\n')
        with open(os.path.join(tmp, 'spoof_summary.txt'), 'w') as f:
            f.write((f'{mn:.4f} {mx:.4f}\n') if mn != float('inf') else 'nan nan\n')
    def reset(self):                                          # clear per-run spoof state on new traffic
        with self.lock:
            self.srcs.clear(); self.suspects.clear()
            self.min_H, self.max_H, self._last = float('inf'), 0.0, None
        if self.tmp: self.dump(self.tmp)


class FlowTable:
    """Per-flow state: [first_seen, ack_count, last_eval, score].
    SYN counting is windowed IN THE DATA PLANE now (each THRESHOLD digest = one
    32-SYN window, counter resets at 32), so the controller no longer tracks a
    cms delta."""
    def __init__(self, cap=100_000):
        self.t, self.lock, self.cap = {}, threading.Lock(), cap
    def record(self, fk, ts):                                   # note a new flow once; True if new
        with self.lock:
            if fk in self.t: return False
            if len(self.t) >= self.cap: del self.t[next(iter(self.t))]
            self.t[fk] = [ts, 0, ts, 0]
            return True
    def add_ack(self, fk):                                      # EVIDENCE -> +1 windowed ack
        with self.lock:
            if fk in self.t: self.t[fk][1] += 1
    def bump(self, fk, d):                                      # move reputation score (capped)
        with self.lock:
            e = self.t.setdefault(fk, [0, 0, 0, 0])
            e[3] = min(CAP, e[3] + d); return e[3]
    def snap(self, fk, ts):                                     # read ACK window + reset, atomically
        with self.lock:
            e = self.t.setdefault(fk, [ts, 0, ts, 0])
            fs, ack, start = e[0], e[1], e[2]
            e[1], e[2] = 0, ts
            return fs, ack, start


class Controller:
    def __init__(self):
        self.model = LeanModel(MODELS_DIR)
        self.flows = FlowTable()
        self.report = Reporter()
        self.entropy = EntropyMonitor(self.report, tmp=os.path.join(HERE, 'tmp'))  # 2s spoof entropy
        self._last_evt = 0.0                                    # ts of last digest (activity monitor)
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
        fk = (_ip6(m[0].bitstring), _ip6(m[1].bitstring),
              int.from_bytes(m[2].bitstring, 'big'), int.from_bytes(m[3].bitstring, 'big'))
        if self.flows.record(fk, int.from_bytes(m[4].bitstring, 'big')):   # genuinely NEW flow only
            self.report.seen(fk[0], fk[2])                      # print once
            self.entropy.arrived(fk[0], fk[1])                 # add src to the dst's uncompleted set
            with self.lock: self.stats['first_seen'] += 1
        # a re-fired FIRST_SEEN for an already-known flow (post-reset) does nothing:
        # no print, no stat, no entropy double-count.

    def _evidence(self, m, s):
        src, dst = _ip6(m[0].bitstring), _ip6(m[1].bitstring)
        fk = (src, dst, int.from_bytes(m[2].bitstring, 'big'), int.from_bytes(m[3].bitstring, 'big'))
        self.flows.add_ack(fk)
        self.entropy.completed(src, dst)                       # flow completed -> drop from spoof set
        with self.lock: self.stats['evidence'] += 1

    def _threshold(self, m, s):
        src, dst = _ip6(m[0].bitstring), _ip6(m[1].bitstring)
        port, proto = int.from_bytes(m[2].bitstring, 'big'), int.from_bytes(m[3].bitstring, 'big')
        cms, ts = int.from_bytes(m[4].bitstring, 'big'), int.from_bytes(m[5].bitstring, 'big')
        fk = (src, dst, port, proto)
        with self.lock:
            self.stats['threshold'] += 1
            if src in self.blocked: return
        _, ack, start = self.flows.snap(fk, ts)
        syn = cms if cms > 0 else 32                                # data plane windows SYNs: 1 digest = 32
        unacked = max(0, syn - ack)
        compl = ack / syn if syn else 0.0
        elapsed = max(0.001, (ts - start) / 1e6)
        feats = dict(syn_count=syn, ack_count=ack, unacked=unacked, completion_ratio=compl,
                     syn_rate_pps=syn / elapsed, duration_s=elapsed)
        attack = self.model.predict(feats)
        score = self.flows.bump(fk, -PENALTY if attack else REWARD)
        do_block = score <= BLOCK_SCORE
        self.report.vote(src, 'ATTACK' if attack else 'BENIGN', score, compl, syn, ack)
        self.csv.write(f"{ts},{s},{src},{port},{syn},{ack},{unacked},{compl:.4f},"
                       f"{syn/elapsed:.2f},{elapsed:.4f},{'ATTACK' if attack else 'BENIGN'},"
                       f"{score},{'BLOCK' if do_block else ''}\n"); self.csv.flush()
        if do_block:
            with self.lock:
                if src in self.blocked: return
                self.blocked.add(src); self.stats['blocked'] += 1
            self.report.block(src, score)
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
                self._last_evt = time.time()                    # feed the activity monitor
                for d in dl.data:
                    m = d.struct.members
                    (self._evidence if len(m) == 4 else self._first_seen if len(m) == 5
                     else self._threshold)(m, s)
            except Exception as e:
                if 'timeout' not in str(e).lower(): log.error(f"digest {s}: {e}")

    def _monitor(self):                                        # print traffic START/IDLE transitions
        active = False
        while True:
            time.sleep(1)
            idle = time.time() - self._last_evt
            if not active and idle < 1.5:
                active = True; self.report.mark('traffic START (digests arriving)')
            elif active and idle >= 6:                         # 6s so bursty traffic doesn't flap
                active = False; self.report.mark('traffic IDLE — launch stopped')

    def start(self):
        for s in ft.AGGS:
            threading.Thread(target=self._recv, args=(s,), daemon=True).start()
        threading.Thread(target=self._monitor, daemon=True).start()
        threading.Thread(target=self.entropy.run, daemon=True).start()   # 2s entropy report
        log.info(f"CLOS controller RUNNING  detectors={ft.AGGS}")
        self.report.mark('controller RUNNING — waiting for traffic')
        def _spoof():                                          # readable spoof-suspect summary (most-hit first)
            sp = sorted(self.entropy.suspects.items(), key=lambda kv: -kv[1])
            return (', '.join(f"{IP2NAME.get(ip, ip)}({c})" for ip, c in sp) if sp else 'none')
        try:
            while True:
                time.sleep(10)
                with self.lock: s = dict(self.stats)
                log.info(f"STATS | FirstSeen:{s['first_seen']} Threshold:{s['threshold']} "
                         f"Evidence:{s['evidence']} Benign:{s['benign']} "
                         f"Suspicious:{s['suspicious']} Blocked:{s['blocked']} "
                         f"| Spoof-suspect: {_spoof()}")
        except KeyboardInterrupt:
            with self.lock: s = dict(self.stats)
            self.entropy.dump(os.path.join(HERE, 'tmp'))
            print(f"\nFINAL | Threshold:{s['threshold']} Benign:{s['benign']} "
                  f"Suspicious:{s['suspicious']} Blocked:{s['blocked']} "
                  f"| Spoof-suspect: {_spoof()}")


if __name__ == '__main__':
    Controller().start()
