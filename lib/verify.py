"""Server-side verification for a Clos run.
Reads all server pcaps (/tmp/cap_*.pcap), the controller's blocks
(/tmp/threshold_evals.csv), and the run's ground-truth roles (/tmp/run_roles.csv),
then scores: attackers blocked, benign served, false positives/negatives.
  python3 lib/verify.py
"""
import csv, glob, os, sys
from scapy.all import PcapReader, IPv6, TCP
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fattree as ft

TMP = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'tmp')
G, R, C, B, DIM, Z = '\033[32m', '\033[31m', '\033[36m', '\033[1m', '\033[2m', '\033[0m'
IP2NAME = {h['ipv6']: h['name'] for h in ft.HOSTS}
SERVERS = {h['ipv6'] for h in ft.HOSTS if h['role'] == 'server'}

roles = {r['src_ip']: r['role'] for r in csv.DictReader(open(f'{TMP}/run_roles.csv'))}
blocked = {r['src_ip'] for r in csv.DictReader(open(f'{TMP}/threshold_evals.csv'))
           if r.get('blocked') == 'BLOCK'} if glob.glob(f'{TMP}/threshold_evals.csv') else set()

syn, comp = {}, {}                                  # SYNs / completed handshakes that reached a server
for pcap in glob.glob(f'{TMP}/cap_*.pcap'):
    try:
        for p in PcapReader(pcap):
            if IPv6 in p and TCP in p:
                fl, s = int(p[TCP].flags), p[IPv6].src
                if fl & 0x02 and not fl & 0x10: syn[s] = syn.get(s, 0) + 1
                elif fl & 0x10 and not fl & 0x02: comp[s] = comp.get(s, 0) + 1
    except Exception as e:
        print(f"(skip {pcap}: {e})")

atk = [ip for ip, r in roles.items() if r == 'attacker']
ben = [ip for ip, r in roles.items() if r == 'benign']

print("=" * 68)
print(f"CLOS VERIFICATION  ({len(atk)} attackers, {len(ben)} benign this run)")
print("=" * 68)
print(f"  {'src_ip':<16} {'role':<9} {'SYN_reached':>11} {'completed':>10}  blocked?")
for ip in sorted(roles, key=lambda x: (roles[x], x)):
    bl = f"{R}YES{Z}" if ip in blocked else f"{G}no{Z}"
    print(f"  {ip:<16} {roles[ip]:<9} {syn.get(ip,0):>11} {comp.get(ip,0):>10}  {bl}")

rate = lambda n, d: (n / d) if d else None
fmt  = lambda x: f"{x*100:5.1f}%" if x is not None else "  n/a"

# ==== CONFUSION MATRIX (ALWAYS): blocking of real-source attackers ====
TP = sum(ip in blocked for ip in atk)              # attacker, blocked  (correct)
FN = len(atk) - TP                                 # attacker, missed   (bad)
FP = sum(ip in blocked for ip in ben)              # benign, blocked    (bad)
TN = len(ben) - FP                                 # benign, allowed    (correct)
prec, rec = rate(TP, TP + FP), rate(TP, TP + FN)
acc,  fpr = rate(TP + TN, TP + FN + FP + TN), rate(FP, FP + TN)
f1 = (2 * prec * rec / (prec + rec)) if (prec and rec) else None
print("\n" + "=" * 68)
print("  CONFUSION MATRIX   (predicted 'attack' = blocked)")
print(f"                          {B}predicted{Z}")
print(f"                     {'BLOCK':>9} {'allow':>9}")
print(f"   actual attack   {G}{TP:>9}{Z} {R}{FN:>9}{Z}   {DIM}TP / FN{Z}")
print(f"   actual benign   {R}{FP:>9}{Z} {G}{TN:>9}{Z}   {DIM}FP / TN{Z}")
print("-" * 68)
print(f"   {C}Recall   {Z} {fmt(rec)}   {DIM}attackers caught       TP/(TP+FN){Z}")
print(f"   {C}Precision{Z} {fmt(prec)}   {DIM}blocks that were real  TP/(TP+FP){Z}")
print(f"   {C}Accuracy {Z} {fmt(acc)}   {DIM}(TP+TN)/all{Z}")
print(f"   {C}F1-score {Z} {fmt(f1)}")
print(f"   {C}FPR      {Z} {fmt(fpr)}   {DIM}benign wrongly blocked FP/(FP+TN){Z}")
print(f"   {DIM}attack SYNs leaked pre-block: {sum(syn.get(ip,0) for ip in atk)}{Z}")
print("=" * 68)

# ==== SPOOFING DETECTION (SEPARATE, below): server-level; only for a spoof run ====
print("  SPOOFING DETECTION   (server-level, entropy/cardinality)")
if os.path.exists(f'{TMP}/spoof_targets.csv'):
    truth = {r['server_ip'] for r in csv.DictReader(open(f'{TMP}/spoof_targets.csv'))}
    detected, peak = set(), {}
    if os.path.exists(f'{TMP}/spoof_detected.csv'):
        for r in csv.DictReader(open(f'{TMP}/spoof_detected.csv')):
            detected.add(r['server_ip']); peak[r['server_ip']] = int(r['peak_uncompleted'])
    minH = maxH = None
    if os.path.exists(f'{TMP}/spoof_summary.txt'):
        try: minH, maxH = map(float, open(f'{TMP}/spoof_summary.txt').read().split())
        except Exception: pass
    benign_srv = SERVERS - truth
    sTP, sFN = len(truth & detected), len(truth - detected)
    sFP, sTN = len(detected & benign_srv), len(benign_srv - detected)
    srec, sprec, sacc = rate(sTP, sTP + sFN), rate(sTP, sTP + sFP), rate(sTP + sTN, len(SERVERS))
    nm = lambda s: ', '.join(sorted(IP2NAME.get(x, x) for x in s)) or '-'
    print(f"   spoofed servers (truth): {C}{nm(truth)}{Z}   [K={len(truth)}]")
    print(f"   flagged by controller  : {C}{nm(detected)}{Z}")
    print(f"   {G}caught(TP):{sTP}/{len(truth)}{Z}  {R}missed(FN):{sFN}{Z}  "
          f"{R}false-alarm(FP):{sFP}{Z}  {G}clean(TN):{sTN}{Z}")
    print(f"   {C}Detection recall{Z} {fmt(srec)}   {C}Precision{Z} {fmt(sprec)}   {C}Accuracy(8){Z} {fmt(sacc)}")
    if minH is not None and minH == minH:          # skip if nan
        print(f"   {C}Entropy over run{Z}  min H={minH:.2f}  max H={maxH:.2f}   {DIM}(lower=more concentrated){Z}")
    for ip, c in sorted(peak.items(), key=lambda kv: -kv[1]):
        tag = f"{G}(victim){Z}" if ip in truth else f"{R}(FALSE ALARM - benign!){Z}"
        print(f"      {IP2NAME.get(ip, ip):<5} {c:>7} uncompleted  {tag}")
elif os.path.exists(f'{TMP}/spoof_sweep.csv'):
    # spoof-sweep: sources sent per server vs whether it got flagged -> shows the floor
    sweep = {r['server_ip']: int(r['sources']) for r in csv.DictReader(open(f'{TMP}/spoof_sweep.csv'))}
    detected = set()
    if os.path.exists(f'{TMP}/spoof_detected.csv'):
        detected = {r['server_ip'] for r in csv.DictReader(open(f'{TMP}/spoof_detected.csv'))}
    print(f"   {DIM}SWEEP: distinct spoofed sources sent per server vs flagged{Z}")
    floor = None
    for ip, n in sorted(sweep.items(), key=lambda kv: kv[1]):
        hit = ip in detected
        if hit and floor is None: floor = n
        tag = f"{G}FLAGGED{Z}" if hit else f"{DIM}below floor{Z}"
        print(f"      {IP2NAME.get(ip, ip):<5} {n:>4} sources  {tag}")
    print(f"   {C}Detection floor{Z} = {floor if floor is not None else 'n/a'} distinct sources "
          f"{DIM}(lowest source-count that flagged = card_thresh){Z}")
else:
    print(f"   {DIM}n/a - not a spoof run{Z}")
print("=" * 68)
