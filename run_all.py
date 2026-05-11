"""
run_all.py — Fire all traffic simultaneously from mininet CLI
h1, h2       → attack.py  (SYN flood)
h3, h4, h5   → traffic.py (legit traffic)

Run from mininet CLI:
    mininet> py exec(open('/home/ayush/my/run_all.py').read())

Check logs after:
    mininet> py net.get('h1').cmd('cat /tmp/my_h1.log')
"""

import time

BASE = '/home/ayush/my2'

# 20 attackers + 40 legit, spread across BOTH splitters:
#   s1 side:  h1..h10 attack     |  h11..h30 legit  (10 atk + 20 legit)
#   s2 side:  h31..h40 attack    |  h41..h60 legit  (10 atk + 20 legit)
hosts_scripts = (
    [(f'h{i}', 'attack.py')  for i in range(1, 11)]   +  # h1..h10  attack on s1
    [(f'h{i}', 'attack.py')  for i in range(31, 41)]  +  # h31..h40 attack on s2
    [(f'h{i}', 'traffic.py') for i in range(11, 31)]  +  # h11..h30 legit on s1
    [(f'h{i}', 'traffic.py') for i in range(41, 61)]     # h41..h60 legit on s2
)

for host, script in hosts_scripts:
    net.get(host).cmd(f'cd {BASE} && python3 {script} > /tmp/my_{host}.log 2>&1 &')
    print(f'[run_all] {host} -> {script}')

print('[run_all] All launched simultaneously.')
print('[run_all] Check logs with:')
for host, _ in hosts_scripts:
    print(f'  mininet> py net.get("{host}").cmd("cat /tmp/my_{host}.log")')
