"""
legit-traffic.py — Simultaneous legitimate traffic from ALL client hosts (h1–h5).

Run from the Mininet CLI:
    mininet> py exec(open('/home/ayush/my/legit-traffic.py').read(), {'net': net, '__builtins__': __builtins__})

Each host fires traffic.py (real TCP connections) simultaneously.
Expected result: all connections succeed, nobody gets blocked.
"""

SCRIPT = '/home/ayush/my2/traffic.py'
# All 60 hosts — h1..h30 on s1, h31..h60 on s2
HOSTS  = [f'h{i}' for i in range(1, 61)]

print(f"[legit-traffic] Launching traffic.py on {HOSTS} simultaneously...")

procs = {h: net.get(h).popen(['python3', SCRIPT]) for h in HOSTS}

for h, p in procs.items():
    out, _ = p.communicate()
    for line in out.decode().strip().splitlines():
        print(f"[legit-traffic] {h}: {line}")

print("[legit-traffic] All hosts done")
