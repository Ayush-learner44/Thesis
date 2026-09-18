"""Traffic launcher. Run from the mininet prompt (cwd = my2):
      py exec(open('launch.py').read())
All 24 CLIENTS generate traffic to their cross-edge target server. Set MODE below.
Writes tmp/run_roles.csv (src_ip,role) for verify.py.
(No net-referencing functions here, so the short `py exec(...)` form works.)
"""
import sys
sys.path.insert(0, '/home/ayush/my2/lib')
import fattree as ft

# ---- choose scenario ----
MODE = 'benign'          # benign | flash | attack | mixed | lrddos
DUR  = 3                 # attack flood seconds
# -------------------------

ATK = '/home/ayush/my2/lib/attack.py'
TMP = '/home/ayush/my2/tmp'                       # run artifacts (gitignored)
import os; os.makedirs(TMP, exist_ok=True)
LR_RATES = [1, 2, 5, 10, 25, 50, 75, 100]        # lrddos pps ladder, cycled over clients
roles = {}
print('=' * 60, f"\n[launch] MODE={MODE}  clients={len(ft.CLIENTS)}  servers={len(ft.SERVERS)}")

for i, h in enumerate(ft.CLIENTS):
    tgt = ft.TARGET[h]
    if MODE == 'benign':
        net.get(h).cmd(f'ab -r -n 100 -c 5 http://[{tgt}]:80/ >{TMP}/ab_{h}.log 2>&1 &'); roles[h] = 'benign'
    elif MODE == 'flash':
        net.get(h).cmd(f'ab -r -n 150 -c 40 http://[{tgt}]:80/ >{TMP}/ab_{h}.log 2>&1 &'); roles[h] = 'benign'
    elif MODE == 'attack':
        net.get(h).cmd(f'python3 {ATK} {tgt} {DUR} >{TMP}/atk_{h}.log 2>&1 &'); roles[h] = 'attacker'
    elif MODE == 'mixed':
        if i < len(ft.CLIENTS) // 2:
            net.get(h).cmd(f'python3 {ATK} {tgt} {DUR} >{TMP}/atk_{h}.log 2>&1 &'); roles[h] = 'attacker'
        else:
            net.get(h).cmd(f'ab -r -n 100 -c 5 http://[{tgt}]:80/ >{TMP}/ab_{h}.log 2>&1 &'); roles[h] = 'benign'
    elif MODE == 'lrddos':
        r = LR_RATES[i % len(LR_RATES)]
        net.get(h).cmd(f'python3 {ATK} {tgt} 200 --rate {r} --count 100 >{TMP}/atk_{h}.log 2>&1 &')
        roles[h] = 'attacker'

with open(f'{TMP}/run_roles.csv', 'w') as f:        # ground truth for verify.py
    f.write('src_ip,role\n')
    for h in roles:
        f.write(f"{ft.HOST_BY_NAME[h]['ipv6']},{roles[h]}\n")
if MODE == 'lrddos':
    print('  lrddos pps cycled over clients:', LR_RATES)
print('[launch] launched. Watch controller; then: python3 lib/verify.py\n' + '=' * 60)
