"""
flood.py — Realistic flash crowd simulation with mixed traffic pattern.
Self-assigns IPv6 if p4-utils didn't.

Traffic pattern (200 total connections):
  Phase 1 —  70 fast sequential @ 100/sec  (viral link / event spike)
  Phase 2 —  70 sequential @ 10/sec        (sustained high-interest traffic)
  Phase 3 —  30 fast sequential @ 100/sec  (second spike / retweet wave)
  Phase 4 —  30 sequential @ random        (traffic settling back down)

All phases use real TCP connections — full 3-way handshake completes.
At 100/sec each connection's ACK reaches path_b_sw before the next 64
SYNs accumulate, so the CMS-based detector sees acks and scores low pps.

Run from any legit host xterm:
    python3 /home/ayush/my/flood.py
"""

import socket, re, subprocess, time, random

subprocess.run(['sysctl', '-w', 'net.ipv6.conf.all.disable_ipv6=0'], capture_output=True)
subprocess.run(['sysctl', '-w', 'net.ipv6.conf.default.disable_ipv6=0'], capture_output=True)

VICTIM_IP  = "2001:1:1::100"
VICTIM_MAC = "aa:00:00:00:00:00"
DST_PORT   = 80

# h0 + 60 client hosts. Used as fallback when p4-utils' setIntfIp didn't
# successfully land an IPv6 on the interface — common in WSL2 because
# new netns inherit net.ipv6.conf.default.disable_ipv6=1.
IPV6_MAP = {'h0': '2001:1:1::100'}
IPV6_MAP.update({f'h{i}': f'2001:1:1::{i:x}' for i in range(1, 61)})

def get_iface_info():
    result = subprocess.run(['ip', 'link'], capture_output=True, text=True)
    iface = None
    for line in result.stdout.split('\n'):
        m = re.search(r'\d+:\s+([\w-]+eth\d+)', line)
        if m:
            iface = m.group(1)
            break
    if not iface:
        return None, "unknown"

    result = subprocess.run(['ip', '-6', 'addr', 'show', iface], capture_output=True, text=True)
    ip6_m = re.search(r'inet6 (2001[0-9a-f:]+)/\d+', result.stdout)
    if ip6_m:
        ipv6 = ip6_m.group(1)
    else:
        hostname = iface.split('-eth')[0]
        ipv6 = IPV6_MAP.get(hostname, "unknown")
        if ipv6 != "unknown":
            subprocess.run(['ip', '-6', 'addr', 'add', 'nodad', ipv6 + '/64', 'dev', iface],
                           capture_output=True)
            print(f"[flood] Assigned {ipv6}/64 to {iface} (nodad)")

    return iface, ipv6

iface, my_ipv6 = get_iface_info()

if iface:
    subprocess.run(['ip', '-6', 'neigh', 'replace', VICTIM_IP,
                    'lladdr', VICTIM_MAC, 'dev', iface, 'nud', 'permanent'],
                   capture_output=True)

def single_connection():
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((VICTIM_IP, DST_PORT, 0, 0))
        s.send(b"GET / HTTP/1.0\r\nHost: server\r\n\r\n")
        s.recv(1024)
        s.close()
    except Exception:
        pass

print(f"[flood] Host  : {my_ipv6}")
print(f"[flood] Target: {VICTIM_IP}:{DST_PORT}")
print(f"[flood] Pattern: 70 @ 100/sec → 70 @ 10/sec → 30 @ 100/sec → 30 @ random")

# Phase 1: 70 fast sequential at 100/sec — spike arrival, staggered not simultaneous
print(f"[flood] Phase-1: 70 connections at 100/sec...")
for i in range(70):
    single_connection()
    time.sleep(0.01)
print(f"[flood] Phase-1: done")

# Phase 2: 70 sequential at 10/sec
print(f"[flood] Phase-2: 70 connections at 10/sec...")
for i in range(70):
    single_connection()
    time.sleep(0.1)
print(f"[flood] Phase-2: done")

# Phase 3: 30 fast sequential at 100/sec — second spike
print(f"[flood] Phase-3: 30 connections at 100/sec...")
for i in range(30):
    single_connection()
    time.sleep(0.01)
print(f"[flood] Phase-3: done")

# Phase 4: 30 at random speed between 5–15/sec
print(f"[flood] Phase-4: 30 connections at random speed (5–15/sec)...")
for i in range(30):
    single_connection()
    time.sleep(random.uniform(0.067, 0.2))
print(f"[flood] Phase-4: done")

print(f"[flood] Done — 200 connections total from {my_ipv6}")
