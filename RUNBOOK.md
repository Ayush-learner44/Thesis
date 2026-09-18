# CLOS (k=4 fat-tree) testbed — RUNBOOK

Distributed SYN-flood detection on a real datacenter fabric. SYN and ACK take
different upward paths (edge per-packet spray) but reach the same server
(down-routing is fixed), so no single aggregation detector sees a whole flow —
the controller reconstructs. Hosts and servers auto-configure at boot.

**20 switches** (4 core, 8 aggregation = detectors, 8 edge = spray) · **32 hosts**
(4 per edge) · **8 servers** = the last host of each edge: `h4 h8 h12 h16 h20 h24 h28 h32`
(IPs `::4 ::8 …`). The other 24 hosts are clients. `hN = 2001:1:1::N` (hex).

## Files
| File | Role |
|---|---|
| `network.py` | boots the fabric, auto-configs hosts (IPv6+NDP), auto-starts the 8 servers |
| `controller.py` | installs forwarding on all 20; detection on the 8 aggregations |
| `server.py` | nginx + pcap per server (auto-started by `network.py`) |
| `launch.py` | traffic from **all clients**: benign / flash / attack / mixed / lrddos |
| `lib/fattree.py` | topology + routing (single source of truth) |
| `lib/attack.py` | scapy SYN flooder (invoked by `launch.py`) |
| `lib/verify.py` | server-side scorecard (reads pcaps + controller blocks + roles) |
| `lib/nginx_ft.conf` | nginx config (IPv6, access log → stdout) |
| `fattree_topology.svg` | diagram |

## One-time install
```bash
sudo apt install -y nginx apache2-utils
```

## Run
**1) Network** (terminal A) — configures hosts and starts all 8 servers:
```bash
cd /home/ayush/my2 && sudo python3 network.py
```
Wait for `[net] 32 hosts configured; servers running: [...]` and the mininet prompt.

**2) Controller** (terminal B):
```bash
cd /home/ayush/my2 && python3 controller.py
```
→ 20 switches connected, forwarding installed, digests enabled, `RUNNING`.

**3) Verify forwarding:**
```
mininet> h1 ping6 -c2 2001:1:1::8      # 0% loss (h1 -> a server, cross-edge)
```

**4) Traffic** — set `MODE` in `launch.py`, then (short form — run from the
`my2` dir where you launched mininet):
```
mininet> py exec(open('launch.py').read())
```
| MODE | all clients … | expect |
|------|---------------|--------|
| `benign` | steady ab to their server | 0 blocked |
| `flash`  | heavy ab burst | 0 blocked (score absorbs spray lag) |
| `attack` | scapy SYN flood | all blocked |
| `mixed`  | half flood + half ab | attackers blocked, benign served |
| `lrddos` | vary pps (1…100) | lowest blocked source = min detected rate |

**5) Verify (server-side):**
```
python3 /home/ayush/my2/lib/verify.py
```
→ attackers blocked (recall), attack SYNs leaked pre-block, benign served, benign FP.

## Watch a server live (for a reviewer)
Each server's nginx access log streams to `/tmp/srv_<host>.log`:
```
mininet> xterm h8
#   in the xterm:
tail -f /tmp/srv_h8.log     # each request: "<client ip> -> 200 (GET / HTTP/1.0)"
```

## Reset between runs
Restart `controller.py` — clears block tables + zeroes CMS on the detectors (no
mininet restart). For fresh pcaps, reboot `network.py` (servers capture per boot).

## Caveat (documented in ../TODO.md)
Per-packet spray reorders legit TCP, so a heavy sustained flash *can* make a benign
flow catch a bad window; the reputation score absorbs a single one. If a benign
block ever appears, switch `p4src/ft_edge.p4` to **flowlet spray** (bursts) or add
a small grace delay.
