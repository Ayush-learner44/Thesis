"""Traffic launcher. Run from the mininet prompt (cwd = my2):
      py exec(open('launch.py').read())
All 24 CLIENTS generate traffic to their round-robin (cross-pod) server. Set MODE below.
Writes tmp/run_roles.csv (src_ip,role) for verify.py.
(No net-referencing functions here, so the short `py exec(...)` form works.)
"""
import sys
sys.path.insert(0, '/home/ayush/my2/lib')
import fattree as ft

# ---- choose scenario ----
MODE = 'spoof-sweep'          # benign | flash | attack | mixed | lrddos | spoof | spoof-sweep
DUR  = 3                 # attack flood seconds
# -------------------------

ATK = '/home/ayush/my2/lib/attack.py'
TMP = '/home/ayush/my2/tmp'                       # run artifacts (gitignored)
import os; os.makedirs(TMP, exist_ok=True)
try: os.remove(TMP + '/spoof_targets.csv')       # clear stale truth; only a spoof run recreates it
except OSError: pass
try: os.remove(TMP + '/spoof_sweep.csv')         # clear stale sweep; only spoof-sweep recreates it
except OSError: pass
LR_RATES = [1, 2, 5, 10, 25, 50, 75, 100]        # lrddos pps ladder, cycled over clients
import random
SPOOF_HEAVY = SPOOF_LIGHT = None
if MODE == 'spoof':
    _K = random.randint(3, len(ft.SERVERS))                 # RANDOM number of victims: 3..8
    _vics = random.sample(ft.SERVERS, _K)
    SPOOF_HEAVY = []; SPOOF_LIGHT = []                      # plain loops (exec-safe)
    for _s in ft.SERVERS:
        if _s in _vics: SPOOF_HEAVY.append(ft.HOST_BY_NAME[_s]['ipv6'])
        else:           SPOOF_LIGHT.append(ft.HOST_BY_NAME[_s]['ipv6'])
    try:                                                   # GROUND TRUTH for verify.py
        with open(TMP + '/spoof_targets.csv', 'w') as _f:
            _f.write('server_ip\n')
            for _ip in SPOOF_HEAVY: _f.write(_ip + '\n')
    except Exception as _e:
        print("[launch] warn: could not write spoof_targets.csv:", _e)
    print("[launch] SPOOF: " + str(_K) + " random victims " + str(_vics)
          + " spoofed 10s; other " + str(len(SPOOF_LIGHT)) + " servers get benign load")
SWEEP_COUNTS = [10, 20, 30, 40, 50, 75, 150, 400]           # distinct spoofed srcs per server (floor sweep)
if MODE == 'spoof-sweep':
    print("[launch] SPOOF-SWEEP: one spoofer per server, laddered distinct-source counts:")
    for _i in range(len(ft.SERVERS)):
        print("   " + ft.SERVERS[_i] + " <- " + str(SWEEP_COUNTS[_i % len(SWEEP_COUNTS)]) + " sources")
    print("   -> whichever servers appear in the controller's Spoof-suspect line = above the floor")
    try:                                                    # ground truth for verify.py sweep table
        with open(TMP + '/spoof_sweep.csv', 'w') as _f:
            _f.write('server_ip,sources\n')
            for _i in range(len(ft.SERVERS)):
                _f.write(ft.HOST_BY_NAME[ft.SERVERS[_i]]['ipv6'] + ',' + str(SWEEP_COUNTS[_i % len(SWEEP_COUNTS)]) + '\n')
    except Exception as _e:
        print("[launch] warn: could not write spoof_sweep.csv:", _e)
roles = {}
_sp = ("  SPOOFED=" + str(len(_vics)) + " " + str(_vics)) if MODE == 'spoof' else ""
print('=' * 60, "\n[launch] MODE=" + MODE + "  clients=" + str(len(ft.CLIENTS))
      + "  servers=" + str(len(ft.SERVERS)) + _sp)

for i, h in enumerate(ft.CLIENTS):
    tgt = ft.TARGET[h]
    if MODE == 'benign':
        net.get(h).cmd(f'ab -r -n 100 -c 5 http://[{tgt}]:80/ >{TMP}/ab_{h}.log 2>&1 &'); roles[h] = 'benign'
    elif MODE == 'flash':
        net.get(h).cmd(f'ab -r -n 200 -c 40 http://[{tgt}]:80/ >{TMP}/ab_{h}.log 2>&1 &'); roles[h] = 'benign'
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
    elif MODE == 'spoof':
        # one benign client per NON-victim server (~20 in-flight, stays under the 50
        # threshold so it won't false-flag); every other client spoofs the victims
        _nl = len(SPOOF_LIGHT)
        if i < _nl:
            tgt2 = SPOOF_LIGHT[i]
            net.get(h).cmd(f'ab -r -n 200 -c 20 http://[{tgt2}]:80/ >{TMP}/ab_{h}.log 2>&1 &')
            roles[h] = 'benign'
        else:
            tgt2 = SPOOF_HEAVY[(i - _nl) % len(SPOOF_HEAVY)]
            net.get(h).cmd(f'python3 {ATK} {tgt2} 10 --spoof >{TMP}/atk_{h}.log 2>&1 &')
            roles[h] = 'attacker'
    elif MODE == 'spoof-sweep':
        # one spoofer per server, each sending a laddered #distinct spoofed sources
        if i < len(ft.SERVERS):
            _cnt = SWEEP_COUNTS[i % len(SWEEP_COUNTS)]
            tgt2 = ft.HOST_BY_NAME[ft.SERVERS[i]]['ipv6']
            net.get(h).cmd(f'python3 {ATK} {tgt2} 20 --spoof --count {_cnt} >{TMP}/atk_{h}.log 2>&1 &')
            roles[h] = 'attacker'
        # clients beyond the 8 servers stay idle in this mode

with open(f'{TMP}/run_roles.csv', 'w') as f:        # ground truth for verify.py
    f.write('src_ip,role\n')
    for h in roles:
        f.write(f"{ft.HOST_BY_NAME[h]['ipv6']},{roles[h]}\n")
if MODE == 'lrddos':
    print('  lrddos pps cycled over clients:', LR_RATES)
print('[launch] launched. Watch controller; then: python3 lib/verify.py\n' + '=' * 60)
