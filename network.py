"""Boot the k=4 fat-tree (20 switches, 32 hosts, 8 servers) and auto-configure it.
Run:  sudo python3 network.py     then in another terminal:  python3 controller.py
"""
import os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, 'lib'))
import fattree as ft
from p4utils.mininetlib.network_API import NetworkAPI
from mininet.cli import CLI

net = NetworkAPI(); net.setLogLevel('info')
P4 = {'core': 'p4src/ft_core.p4', 'agg': 'p4src/ddos_detector.p4', 'edge': 'p4src/ft_edge.p4'}
role = lambda sw: 'core' if sw in ft.CORES else ('agg' if sw in ft.AGGS else 'edge')

switches = ft.CORES + ft.AGGS + ft.EDGES
for sw in switches:                                    # add + program every switch
    net.addP4RuntimeSwitch(sw); net.setP4Source(sw, P4[role(sw)])
net.setCompiler(p4rt=True)

for h in ft.HOSTS:                                     # hosts
    net.addHost(h['name'])
for (s1, p1, s2, p2) in ft.LINKS:                      # links
    net.addLink(s1, s2, port1=p1, port2=p2)
for h in ft.HOSTS:                                     # MAC + IPv6 per host
    net.setIntfMac(h['name'], h['edge_sw'], h['mac'])
    net.setIntfIp(h['name'], h['edge_sw'], h['ipv6'] + '/64')

net.disableArpTables(); net.disableGwArp()
for i, sw in enumerate(switches):                      # gRPC + thrift ports
    net.setThriftPort(sw, 9090 + i); net.setGrpcPort(sw, 9560 + i)

net.disableCli()                                       # start CLI ourselves, after host config
net.startNetwork()
mn = net.net

for h in ft.HOSTS:                                     # enable IPv6 + assign own address
    n, ifc = mn.get(h['name']), f"{h['name']}-eth0"
    n.cmd('sysctl -w net.ipv6.conf.all.disable_ipv6=0 >/dev/null 2>&1')
    n.cmd(f'ip -6 addr add nodad {h["ipv6"]}/64 dev {ifc} 2>/dev/null')
for h in ft.HOSTS:                                     # static NDP for every other host
    n, ifc = mn.get(h['name']), f"{h['name']}-eth0"
    for o in ft.HOSTS:
        if o['name'] != h['name']:
            n.cmd(f'ip -6 neigh replace {o["ipv6"]} lladdr {o["mac"]} dev {ifc} nud permanent')

TMP = os.path.join(HERE, 'tmp'); os.makedirs(TMP, exist_ok=True)   # run artifacts (gitignored)
for srv in ft.SERVERS:                                 # auto-start nginx+pcap on every server
    mn.get(srv).cmd(f'python3 {HERE}/server.py > {TMP}/srv_{srv}.log 2>&1 &')
print(f"[net] {len(ft.HOSTS)} hosts configured; servers running: {ft.SERVERS}")

print("\n\033[1;36m CLOS fat-tree up (20 switches, 32 hosts, 8 servers h4..h32)."
      "\n  controller : python3 controller.py"
      "\n  traffic    : py exec(open('launch.py').read())"
      "\n  watch a srv: xterm h8  ->  tail -f tmp/srv_h8.log\033[0m\n")
CLI(mn); net.stopNetwork()
