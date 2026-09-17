"""
lrddos_sweep.py  --  Low-Rate DDoS sweep: find the MINIMUM pps your
detector flags as an attack.

Idea: your discriminator is NOT "high pps" -- it's "SYNs that never
complete" (completion_ratio / unacked). So in theory an LR-DDoS at 1 pps
should be caught as readily as a 10k pps flood, as long as it reaches the
32-SYN THRESHOLD so the controller evaluates it. This sweep TESTS that
empirically: each attacker floods at a different fixed rate; whichever
source IPs the controller blocks tells you the real minimum detected rate.

Run from the mininet> prompt (network + controller + server already up):
    py exec(open('/home/ayush/my2/traffic_v2/lrddos_sweep.py').read(), {'net': net, '__builtins__': __builtins__})

Then read the controller log: the LOWEST pps whose source IP is Blocked
is your minimum detected attack rate. Anything below that EVADES -> that's
your honest lower bound / limitation to report.

Each attacker sends COUNT half-open SYNs (never ACKed). COUNT=40 crosses
the 32-SYN threshold once. NOTE: at 1 pps that host runs ~40s -- the slow
rates dominate runtime. Trim RATES if you want it faster.
"""

ATK    = '/home/ayush/my2/traffic_v2/attack_rate.py'
COUNT  = 40                                  # > 32-SYN threshold, one eval
RATES  = [1, 2, 5, 10, 25, 50, 100, 250]     # pps ladder -> h1..h8

print('=' * 62)
print('[lrddos_sweep] LR-DDoS rate sweep  (COUNT=%d half-open SYNs each)' % COUNT)
print('=' * 62)
print('  host   source IPv6        rate      ~runtime')
print('  ----   ----------------   -------   --------')
for i, rate in enumerate(RATES, start=1):
    h   = f'h{i}'
    ip6 = f'2001:1:1::{i:x}'
    net.get(h).cmd(f'python3 {ATK} --rate {rate} --count {COUNT} '
                   f'>/tmp/lr_{h}.log 2>&1 &')
    print('  %-5s  %-16s   %4d pps   %4.0fs' % (h, ip6, rate, COUNT / rate))
print('=' * 62)
print('[lrddos_sweep] launched. Watch the controller for BLOCKED source IPs.')
print('[lrddos_sweep] Lowest-rate IP blocked = your MINIMUM detected pps.')
print('[lrddos_sweep] Any rate NOT blocked = evades (honest lower bound).')
print('=' * 62)
