"""k=4 fat-tree topology + routing. Single source of truth.

20 switches (4 core, 8 aggregation=detectors, 8 edge), 8 edges x 4 hosts = 32
hosts. All hosts of one pod (SERVER_POD, default pod 2 = h17..h24) are SERVERS; every
other host is a client, so every client->server flow is cross-pod (always sprayed).
Up-path is sprayed at the edge; down-path is fixed by destination.
"""

K, HALF, HOSTS_PER_EDGE = 4, 2, 4          # arity, k/2, hosts per edge
SERVER_POD = 2                             # this whole pod is the server farm; rest = clients

def core(i, j): return f'c{i}{j}'
def agg(p, a):  return f'a{p}{a}'
def edge(p, e): return f'e{p}{e}'

CORES = [core(i, j) for i in range(HALF) for j in range(HALF)]   # c00 c01 c10 c11
AGGS  = [agg(p, a)  for p in range(K) for a in range(HALF)]      # a00..a31 (detectors)
EDGES = [edge(p, e) for p in range(K) for e in range(HALF)]      # e00..e31
DETECTORS  = list(AGGS)
FORWARDERS = list(EDGES) + list(CORES)

# ---- hosts: 4 per edge, last one = server -----------------------------------
HOSTS = []
for eidx, esw in enumerate(EDGES):
    for pos in range(HOSTS_PER_EDGE):
        hid = eidx * HOSTS_PER_EDGE + pos + 1                    # global 1-based id
        HOSTS.append(dict(
            name=f'h{hid}', id=hid,
            mac=f'aa:00:00:00:00:{hid:02x}',
            ipv6=f'2001:1:1::{hid:x}',
            pod=eidx // HALF, edge_sw=esw, edge_idx=eidx % HALF,
            role='server' if eidx // HALF == SERVER_POD else 'client',
            down_port=1 + pos,                                   # edge host ports 1..4
        ))

SERVERS = [h['name'] for h in HOSTS if h['role'] == 'server']    # pod 2: h17..h24
CLIENTS = [h['name'] for h in HOSTS if h['role'] == 'client']
HOST_BY_NAME = {h['name']: h for h in HOSTS}

# client -> target server IP: round-robin across the server pod, shared evenly over
# all 8 servers. every client lives in another pod, so every flow is cross-pod (up to
# a core and back down) -> always climbs an aggregation detector and gets sprayed.
TARGET = {name: HOST_BY_NAME[SERVERS[i % len(SERVERS)]]['ipv6']
          for i, name in enumerate(CLIENTS)}

# ---- links: (sw1, port1, sw2, port2) ----------------------------------------
# edge ports: 1..4 hosts (down), 5..6 aggs (up) | agg: 1..2 edges, 3..4 cores | core: 1..4 pods
EDGE_UP0 = HOSTS_PER_EDGE + 1                                    # first edge uplink = 5
EDGE_SPRAY_PORTS = list(range(EDGE_UP0, EDGE_UP0 + HALF))        # [5, 6]
LINKS = []
for h in HOSTS:                                                  # edge <-> host
    LINKS.append((h['edge_sw'], h['down_port'], h['name'], 0))
for p in range(K):                                              # edge <-> agg
    for e in range(HALF):
        for a in range(HALF):
            LINKS.append((edge(p, e), EDGE_UP0 + a, agg(p, a), 1 + e))
for p in range(K):                                              # agg <-> core
    for a in range(HALF):
        for j in range(HALF):
            LINKS.append((agg(p, a), HALF + 1 + j, core(a, j), p + 1))

# ---- routing: {switch: [(dst_mac, egress_port), ...]} for l2_forward ---------
def routes():
    R = {sw: [] for sw in CORES + AGGS + EDGES}
    for d in HOSTS:
        for c in CORES:                                         # core: down to dst pod
            R[c].append((d['mac'], d['pod'] + 1))
        for p in range(K):                                     # agg: down if local pod else up
            for a in range(HALF):
                R[agg(p, a)].append((d['mac'], 1 + d['edge_idx'] if p == d['pod'] else HALF + 1))
        R[d['edge_sw']].append((d['mac'], d['down_port']))     # edge: local hosts only (else spray)
    return R

ROUTES = routes()

if __name__ == '__main__':
    print(f"k={K}: {len(CORES)} core, {len(AGGS)} agg, {len(EDGES)} edge, "
          f"{len(HOSTS)} hosts ({len(SERVERS)} servers, {len(CLIENTS)} clients), {len(LINKS)} links")
    print("servers:", SERVERS)
    print("spray ports:", EDGE_SPRAY_PORTS)
