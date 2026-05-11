"""
legit.py — Demonstrates BENIGN ML classification.

Shows your guide that a host sending SYNs at LOW rate:
  - Accumulates in the CMS (fixed source port, same bucket every time)
  - Triggers THRESHOLD at 64 SYNs
  - ML votes BENIGN (low pps)
  - Host is NOT blocked — keeps running freely

Run from ANY host xterm:
    python3 /home/ayush/my/legit.py

How it works:
  - Uses Scapy raw SYN injection (fixed src_port=20000)
  - All 80 packets hit the SAME two CMS buckets → counter accumulates
  - Rate = 8 pps → at packet 64: elapsed = 8s → pps = 8 → ML votes BENIGN
  - Blocks outgoing RSTs so h0's SYN-ACK doesn't undo the counter
  - After 64 packets: controller logs BENIGN, no drop rule installed
  - Packets 65-80: controller sees more THRESHOLDs, keeps voting BENIGN

Contrast with attack.py:
  - attack.py sends at 100 pps → ML votes ATTACK → host blocked
  - legit.py  sends at   8 pps → ML votes BENIGN → host NOT blocked
"""

import re, sys, time, subprocess
from scapy.all import Ether, IPv6, TCP, sendp

# ── Enable IPv6 in this namespace ──────────────────────────────────────────
subprocess.run(['sysctl', '-w', 'net.ipv6.conf.all.disable_ipv6=0'],     capture_output=True)
subprocess.run(['sysctl', '-w', 'net.ipv6.conf.default.disable_ipv6=0'], capture_output=True)

# ── Block outgoing RSTs ────────────────────────────────────────────────────
# h0 replies to each SYN with SYN-ACK. Our kernel (having not sent the SYN)
# would send RST-ACK back, which P4 treats as ACK and DECREMENTS the CMS
# counter — preventing accumulation to 64. Dropping RSTs fixes this.
subprocess.run(['ip6tables', '-F', 'OUTPUT'], capture_output=True)
subprocess.run(['ip6tables', '-A', 'OUTPUT', '-p', 'tcp',
                '--tcp-flags', 'RST', 'RST', '-j', 'DROP'], capture_output=True)

# ── Config ─────────────────────────────────────────────────────────────────
VICTIM_IP   = "2001:1:1::100"
VICTIM_MAC  = "aa:00:00:00:00:00"
DST_PORT    = 80
SRC_PORT    = 20000    # FIXED — all packets hit the same CMS bucket
NUM_PACKETS = 80       # 64 triggers THRESHOLD; 80 gives second trigger at 128
RATE_PPS    = 8        # 8 pps → at 64 pkts: elapsed≈8s, pps≈8 → ML = BENIGN

# h0 + 60 client hosts. Used as fallback when p4-utils' setIntfIp didn't
# successfully land an IPv6 on the interface — common in WSL2 because
# new netns inherit net.ipv6.conf.default.disable_ipv6=1.
IPV6_MAP = {'h0': '2001:1:1::100'}
IPV6_MAP.update({f'h{i}': f'2001:1:1::{i:x}' for i in range(1, 61)})

# ── Interface / IP detection ───────────────────────────────────────────────
def get_iface_info():
    result = subprocess.run(['ip', 'link'], capture_output=True, text=True)
    iface = None
    for line in result.stdout.split('\n'):
        m = re.search(r'\d+:\s+([\w-]+eth\d+)', line)
        if m:
            iface = m.group(1)
            break
    if not iface:
        print("[legit] ERROR: could not detect network interface")
        sys.exit(1)

    result = subprocess.run(['ip', 'link', 'show', iface], capture_output=True, text=True)
    mac_m = re.search(r'link/ether ([0-9a-f:]+)', result.stdout)
    src_mac = mac_m.group(1) if mac_m else None
    if not src_mac:
        print(f"[legit] ERROR: could not read MAC on {iface}")
        sys.exit(1)

    result = subprocess.run(['ip', '-6', 'addr', 'show', iface], capture_output=True, text=True)
    ip6_m = re.search(r'inet6 (2001[0-9a-f:]+)/\d+', result.stdout)
    if ip6_m:
        src_ipv6 = ip6_m.group(1)
    else:
        hostname = iface.split('-eth')[0]
        src_ipv6 = IPV6_MAP.get(hostname)
        if not src_ipv6:
            print(f"[legit] ERROR: unknown host '{hostname}', add to IPV6_MAP")
            sys.exit(1)
        r = subprocess.run(['ip', '-6', 'addr', 'add', 'nodad',
                            src_ipv6 + '/64', 'dev', iface], capture_output=True)
        if r.returncode == 0:
            print(f"[legit] Assigned {src_ipv6}/64 to {iface} (nodad)")
            time.sleep(0.2)

    return iface, src_mac, src_ipv6

iface, src_mac, src_ipv6 = get_iface_info()

# ── Print what's about to happen ───────────────────────────────────────────
elapsed_at_threshold = 64 / RATE_PPS
print()
print("=" * 58)
print("  legit.py — BENIGN classification demo")
print("=" * 58)
print(f"  Host     : {src_ipv6} on {iface}")
print(f"  Target   : {VICTIM_IP}:{DST_PORT}")
print(f"  Rate     : {RATE_PPS} pps  (attack.py uses 100 pps)")
print(f"  Src port : {SRC_PORT} (fixed — same CMS bucket every packet)")
print(f"  Packets  : {NUM_PACKETS}")
print(f"  Expected : THRESHOLD at packet 64 (~{elapsed_at_threshold:.0f}s)")
print(f"             elapsed={elapsed_at_threshold:.1f}s, pps={RATE_PPS}")
print(f"             ML votes BENIGN → host NOT blocked")
print("=" * 58)
print()

# ── Send packets ───────────────────────────────────────────────────────────
inter = 1.0 / RATE_PPS
start = time.time()

for i in range(NUM_PACKETS):
    pkt = (Ether(src=src_mac, dst=VICTIM_MAC) /
           IPv6(src=src_ipv6, dst=VICTIM_IP) /
           TCP(sport=SRC_PORT, dport=DST_PORT, flags="S", seq=1000 + i))
    sendp(pkt, iface=iface, verbose=0)

    elapsed = time.time() - start
    if (i + 1) == 64:
        print(f"[legit] Packet 64 sent at {elapsed:.1f}s → "
              f"THRESHOLD fires in controller now")
    elif (i + 1) % 16 == 0:
        print(f"[legit] Sent {i+1}/{NUM_PACKETS} packets  ({elapsed:.1f}s elapsed)")

    time.sleep(inter)

total = time.time() - start
print()
print(f"[legit] Done — {NUM_PACKETS} packets in {total:.1f}s")
print(f"[legit] Check controller: should show BENIGN, {src_ipv6} NOT blocked")
print()
