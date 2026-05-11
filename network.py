from p4utils.mininetlib.network_API import NetworkAPI

net = NetworkAPI()
net.setLogLevel('info')

# ================================================================
# FULL DIAMOND TOPOLOGY  (2 splitters × 3 detectors × 60 hosts)
#
#   h1..h30 ──── s1 ──┐ ┌── A ──┐
#                     ├─┤── B ──┤── h0 (3 NICs, same MAC)
#   h31..h60 ─── s2 ──┘ └── C ──┘
#
# s1 ports:  1..30 = h1..h30           31=A, 32=B, 33=C
# s2 ports:  1..30 = h31..h60          31=A, 32=B, 33=C
# A  ports:  1=s1, 2=s2, 3=h0-eth0
# B  ports:  1=s1, 2=s2, 3=h0-eth1
# C  ports:  1=s1, 2=s2, 3=h0-eth2
#
# No s1↔s2 link — each detector is equidistant from each splitter.
# h0 has the SAME MAC on all 3 interfaces; IPv6 is assigned only
# on eth0 (the A path). Linux weak-host model accepts packets on
# eth1 and eth2 as well.
# ================================================================

# ── Switches ────────────────────────────────────────────────────
net.addP4RuntimeSwitch('s1')
net.addP4RuntimeSwitch('s2')
net.addP4RuntimeSwitch('A')
net.addP4RuntimeSwitch('B')
net.addP4RuntimeSwitch('C')

net.setP4Source('s1', 'p4src/traffic_splitter.p4')
net.setP4Source('s2', 'p4src/traffic_splitter.p4')
net.setP4Source('A',  'p4src/ddos_detector.p4')
net.setP4Source('B',  'p4src/ddos_detector.p4')
net.setP4Source('C',  'p4src/ddos_detector.p4')
net.setCompiler(p4rt=True)

# ── Hosts ───────────────────────────────────────────────────────
net.addHost('h0')
for i in range(1, 61):
    net.addHost(f'h{i}')

# ── Links — hosts to splitters ──────────────────────────────────
for i in range(1, 31):
    net.addLink('s1', f'h{i}', port1=i, port2=0)
for i in range(31, 61):
    net.addLink('s2', f'h{i}', port1=i - 30, port2=0)

# ── Links — splitters to detectors (full diamond) ───────────────
net.addLink('s1', 'A', port1=31, port2=1)
net.addLink('s1', 'B', port1=32, port2=1)
net.addLink('s1', 'C', port1=33, port2=1)
net.addLink('s2', 'A', port1=31, port2=2)
net.addLink('s2', 'B', port1=32, port2=2)
net.addLink('s2', 'C', port1=33, port2=2)

# ── Links — detectors to h0 (3 NICs) ────────────────────────────
net.addLink('A', 'h0', port1=3, port2=0)
net.addLink('B', 'h0', port1=3, port2=1)
net.addLink('C', 'h0', port1=3, port2=2)

# ── Client MACs (h1..h60) ───────────────────────────────────────
for i in range(1, 61):
    mac = f'aa:00:00:00:00:{i:02x}'
    sw  = 's1' if i <= 30 else 's2'
    net.setIntfMac(f'h{i}', sw, mac)

# ── h0 MAC — same on all 3 interfaces (weak host model) ─────────
net.setIntfMac('h0', 'A', 'aa:00:00:00:00:00')
net.setIntfMac('h0', 'B', 'aa:00:00:00:00:00')
net.setIntfMac('h0', 'C', 'aa:00:00:00:00:00')

# ── Client IPv6 addresses ───────────────────────────────────────
for i in range(1, 61):
    ipv6 = f'2001:1:1::{i:x}/64'
    sw   = 's1' if i <= 30 else 's2'
    net.setIntfIp(f'h{i}', sw, ipv6)

# ── h0 IPv6 — only on the A interface ───────────────────────────
# h0 uses ::100 (NOT ::10) to avoid collision with h16's natural address
# (0x10 = 16 = h16). Clients h1..h60 use ::1..::3c.
net.setIntfIp('h0', 'A', '2001:1:1::100/64')

# ── No ARP / NDP — static neighbor entries handled by scripts ───
net.disableArpTables()
net.disableGwArp()

# ── gRPC + Thrift ports per switch ──────────────────────────────
net.setThriftPort('s1', 9090); net.setGrpcPort('s1', 9559)
net.setThriftPort('s2', 9091); net.setGrpcPort('s2', 9560)
net.setThriftPort('A',  9092); net.setGrpcPort('A',  9561)
net.setThriftPort('B',  9093); net.setGrpcPort('B',  9562)
net.setThriftPort('C',  9094); net.setGrpcPort('C',  9563)

net.enableCli()

print("""
\033[1;36m
================================================================
  EXPERIMENT QUICK REFERENCE  (scroll up if buried)
================================================================

  STEP 1 — MININET is up (this terminal)

  STEP 2 — CONTROLLER  (separate Linux terminal):
    cd /home/ayush/my2/controller
    python3 controller.py
    → Pick scenario [1-10] at the prompt

  STEP 3 — SERVER  (open h0 xterm, run before traffic):
    xterm h0
    python3 /home/ayush/my2/server.py

  STEP 4 — TRAFFIC  (paste into mininet CLI below):

    run_all.py    h1+h2 attack | h3+h4+h5 legit  (other hosts idle)
      py exec(open('/home/ayush/my2/run_all.py').read(), {'net': net, '__builtins__': __builtins__})

    attacks.py    h1..h5 all attack
      py exec(open('/home/ayush/my2/attacks.py').read(), {'net': net, '__builtins__': __builtins__})

    flooding.py   h1..h5 flash crowd
      py exec(open('/home/ayush/my2/flooding.py').read(), {'net': net, '__builtins__': __builtins__})

    legit-traffic.py   h1..h5 slow legit traffic
      py exec(open('/home/ayush/my2/legit-traffic.py').read(), {'net': net, '__builtins__': __builtins__})

  STEP 5 — VERIFY  (Ctrl+C server.py first, then):
    python3 /home/ayush/my2/verify.py

================================================================\033[0m
""")

net.startNetwork()
