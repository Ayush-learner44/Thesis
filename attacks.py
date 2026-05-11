"""
attacks.py — Simultaneous SYN flood from ALL client hosts (h1–h5).

Run from the Mininet CLI:
    mininet> py exec(open('/home/ayush/my/attacks.py').read(), {'net': net, '__builtins__': __builtins__})

Each host fires attack.py (200 raw SYNs at 100 pps) simultaneously.
Controller should detect each host independently and block all of them.
"""

SCRIPT = '/home/ayush/my2/attack.py'
# All 60 hosts — h1..h30 on s1, h31..h60 on s2
HOSTS  = [f'h{i}' for i in range(1, 61)]

print(f"[attacks] Launching attack.py on {HOSTS} simultaneously...")

procs = {h: net.get(h).popen(['python3', SCRIPT]) for h in HOSTS}

for h, p in procs.items():
    out, _ = p.communicate()
    for line in out.decode().strip().splitlines():
        print(f"[attacks] {h}: {line}")

print("[attacks] All hosts done")
