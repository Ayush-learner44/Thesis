"""
traffic.py — Legitimate traffic script
Uses real kernel TCP sockets → full 3-way handshake completes.
Self-assigns IPv6 if p4-utils didn't. Run from any legit host xterm:
    python3 /home/ayush/my/traffic.py
"""

import socket, time, re, subprocess, sys

# Enable IPv6 in this namespace (WSL2 disables it on new veth interfaces)
subprocess.run(['sysctl', '-w', 'net.ipv6.conf.all.disable_ipv6=0'], capture_output=True)
subprocess.run(['sysctl', '-w', 'net.ipv6.conf.default.disable_ipv6=0'], capture_output=True)

VICTIM_IP  = "2001:1:1::100"     # h0 IPv6 — matches network.py
VICTIM_MAC = "aa:00:00:00:00:00" # h0 MAC  — matches network.py
DST_PORT   = 80
NUM_CONNS  = 80
INTER      = 0.333  # 3 connections per second

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

    # IPv6 — detect or self-assign
    result = subprocess.run(['ip', '-6', 'addr', 'show', iface], capture_output=True, text=True)
    ip6_m = re.search(r'inet6 (2001[0-9a-f:]+)/\d+', result.stdout)
    if ip6_m:
        ipv6 = ip6_m.group(1)
    else:
        hostname = iface.split('-eth')[0]
        ipv6 = IPV6_MAP.get(hostname, "unknown")
        if ipv6 != "unknown":
            r = subprocess.run(['ip', '-6', 'addr', 'add', 'nodad', ipv6 + '/64', 'dev', iface],
                               capture_output=True)
            if r.returncode == 0:
                print(f"[traffic] Assigned {ipv6}/64 to {iface} (nodad)")
                time.sleep(0.2)   # let the route settle
            else:
                print(f"[traffic] ip addr add failed: {r.stderr.decode().strip()}")

    return iface, ipv6

iface, my_ipv6 = get_iface_info()

# Static neighbor entry for h0 — bypasses NDP (P4 l2_forward is unicast-only)
if iface:
    subprocess.run(['ip', '-6', 'neigh', 'replace', VICTIM_IP,
                    'lladdr', VICTIM_MAC, 'dev', iface, 'nud', 'permanent'],
                   capture_output=True)

def legit_connection(idx):
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((VICTIM_IP, DST_PORT, 0, 0))
        s.send(b"GET / HTTP/1.0\r\nHost: server\r\n\r\n")
        s.recv(1024)
        s.close()
        return True
    except Exception as e:
        print(f"[traffic] conn {idx} FAILED: {e}")
        return False

print(f"[traffic] Host  : {my_ipv6}")
print(f"[traffic] Target: {VICTIM_IP}:{DST_PORT}")
print(f"[traffic] Sending {NUM_CONNS} legitimate connections (~3/sec)...")

for i in range(NUM_CONNS):
    legit_connection(i)
    time.sleep(INTER)

print(f"[traffic] Done — {NUM_CONNS} connections from {my_ipv6}")
