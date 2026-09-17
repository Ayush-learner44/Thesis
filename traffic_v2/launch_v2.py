"""
launch_v2.py  --  Live-testbed traffic using the "real" tools.

  benign  : ApacheBench (ab) steady real HTTP on all 60 hosts
  flash   : ApacheBench high-concurrency surge on all 60 hosts
  attack  : short (<5s) scapy IPv6 SYN flood on the attacker set
  spoof   : same but with spoofed source IPv6 (will EVADE per-source CMS)
  mixed   : attackers flood + everyone else runs ab benign

Run from the mininet> prompt:
    py exec(open('/home/ayush/my2/traffic_v2/launch_v2.py').read(), {'net': net, '__builtins__': __builtins__})

Requires on the hosts: apache2-utils (ab), scapy. See RUNBOOK.md.
"""

# ============================================================
# >>> SET MODE HERE <<<  (benign | flash | attack | spoof | mixed)
MODE = 'flash'
ATTACK_SECONDS = 3
# ============================================================

VIP  = '2001:1:1::100'
VMAC = 'aa:00:00:00:00:00'
ATK  = '/home/ayush/my2/traffic_v2/attack_short.py'

ALL       = [f'h{i}' for i in range(1, 61)]
ATTACKERS = [f'h{i}' for i in range(1, 11)] + [f'h{i}' for i in range(31, 41)]  # h1-10, h31-40
LEGIT     = [h for h in ALL if h not in ATTACKERS]


def prep(h):
    """enable IPv6, self-assign this host's own /64 addr (gives it a connected
    route to the server — without this ab gets 'Network is unreachable'),
    then install the static NDP entry for the server."""
    node = net.get(h)
    idx = int(h[1:])                        # 'h7' -> 7  -> 2001:1:1::7
    node.cmd('sysctl -w net.ipv6.conf.all.disable_ipv6=0 >/dev/null 2>&1')
    node.cmd(f'ip -6 addr add nodad 2001:1:1::{idx:x}/64 dev {h}-eth0 2>/dev/null')
    node.cmd(f'ip -6 neigh replace {VIP} lladdr {VMAC} dev {h}-eth0 nud permanent')


def ab(h, n, c):
    net.get(h).cmd(f'ab -r -n {n} -c {c} http://[{VIP}]:80/ >/tmp/ab_{h}.log 2>&1 &')


def flood(h, spoof=False):
    arg = f'{ATTACK_SECONDS} spoof' if spoof else f'{ATTACK_SECONDS}'
    net.get(h).cmd(f'python3 {ATK} {arg} >/tmp/atk_{h}.log 2>&1 &')


print('=' * 60)
print(f'[launch_v2] MODE = {MODE}')
print('=' * 60)

if MODE == 'benign':
    for h in ALL:
        prep(h); ab(h, 200, 5)
    print(f'[launch_v2] ab benign (200 conns, c=5) on all {len(ALL)} hosts')

elif MODE == 'flash':
    for h in ALL:
        prep(h); ab(h, 300, 20)
    print(f'[launch_v2] ab FLASH CROWD (300 conns, c=20) on all {len(ALL)} hosts')

elif MODE in ('attack', 'spoof'):
    for h in ATTACKERS:
        flood(h, spoof=(MODE == 'spoof'))
    print(f'[launch_v2] {MODE} SYN flood ({ATTACK_SECONDS}s) from {len(ATTACKERS)} attackers')

elif MODE == 'mixed':
    for h in LEGIT:
        prep(h); ab(h, 200, 5)
    for h in ATTACKERS:
        flood(h)
    print(f'[launch_v2] MIXED: {len(ATTACKERS)} attackers flood + {len(LEGIT)} legit ab')

else:
    print(f'[launch_v2] unknown MODE {MODE}')

print('=' * 60)
print('[launch_v2] launched. attackers stop after %ds; ab finishes on its own.' % ATTACK_SECONDS)
print('=' * 60)
