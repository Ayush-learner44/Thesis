"""Server-side verification for a Clos run.
Reads all server pcaps (/tmp/cap_*.pcap), the controller's blocks
(/tmp/threshold_evals.csv), and the run's ground-truth roles (/tmp/run_roles.csv),
then scores: attackers blocked, benign served, false positives/negatives.
  python3 lib/verify.py
"""
import csv, glob, os
from scapy.all import PcapReader, IPv6, TCP

TMP = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'tmp')

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
    print(f"  {ip:<16} {roles[ip]:<9} {syn.get(ip,0):>11} {comp.get(ip,0):>10}  "
          f"{'YES' if ip in blocked else 'no'}")

atk_blocked = sum(ip in blocked for ip in atk)
ben_served  = sum(comp.get(ip, 0) > 0 for ip in ben)
ben_fp      = sum(ip in blocked for ip in ben)
print("\n" + "=" * 68)
print(f"  attackers blocked (recall) : {atk_blocked}/{len(atk)}")
print(f"  attack SYNs leaked pre-block: {sum(syn.get(ip,0) for ip in atk)}")
print(f"  benign served              : {ben_served}/{len(ben)}")
print(f"  benign wrongly blocked (FP): {ben_fp}")
print("=" * 68)
