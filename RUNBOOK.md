# Live testbed — the "real" tools

Replaces the toy scripts with:
- **ApacheBench (`ab`)** for benign + flash crowd (real IPv6 HTTP handshakes)
- **scapy** for the SYN flood (hping3 is IPv4-only; this testbed is IPv6)

## One-time install (WSL)
```bash
sudo apt install -y apache2-utils nginx   # ab (client) + nginx (victim server)
```

## Standing setup (start ONCE, leave running)
1. **Mininet** (terminal A):  `cd /home/ayush/my2 && sudo python3 network.py`
2. **Controller** (terminal B): `cd controller && python3 controller.py` → pick a scenario.
3. **Server on h0** (mininet): `xterm h0` →
   `python3 /home/ayush/my2/server_nginx.py`
   (sets up h0's IPv6 + NDP, then runs nginx — completes handshakes under a
   60-host flash crowd.)

You do **NOT** restart mininet or the server between runs. See "Resetting" below.

**Reputation score:** the controller no longer blocks on one bad window. It keeps
a per-flow score (+1 benign window, −1 attack window, block at ≤ −2), so an
RTT-lagged benign flow survives a transient bad window. STATS now shows
`Benign / Suspicious / Blocked` (Suspicious = a bad window that did NOT block).
Analyze a run with `python3 analyze_evals.py` — in a benign run the
**BLOCK** rows are the true false positives (ATTACK windows are expected/harmless).

---

## A) Flash-crowd / benign FP test  (launch_v2.py)
Edit `MODE` in `launch_v2.py`, then from the mininet prompt:
```
py exec(open('/home/ayush/my2/launch_v2.py').read(), {'net': net, '__builtins__': __builtins__})
```
| MODE | what it does |
|------|--------------|
| `benign` | ab steady (200, c=5) on all 60 hosts → expect 0 blocked |
| `flash`  | ab surge (300, c=20) on all 60 → flash-crowd FP test |
| `attack` | short scapy SYN flood (~3s) from the 20 attackers |
| `spoof`  | same, spoofed source IPv6 — **will EVADE** the per-source CMS |
| `mixed`  | 20 attackers flood + 40 legit ab |

Stop a runaway ab: `mininet> sh pkill -9 ab`

---

## B) hping3-style flood, one host  (attack_rate.py)
Run inside an attacker xterm (`xterm h1` → …), or via `net.get('h1').cmd(...)`:
```
python3 /home/ayush/my2/attack_rate.py --flood            # max rate
python3 /home/ayush/my2/attack_rate.py --rate 100         # 100 pps
python3 /home/ayush/my2/attack_rate.py --count 500 --rate 200
python3 /home/ayush/my2/attack_rate.py --duration 3       # 3s then stop
python3 /home/ayush/my2/attack_rate.py --flood --spoof    # spoofed src (evades)
python3 /home/ayush/my2/attack_rate.py --rate 5 --rand-port   # demo split-dilution
```
**Source-port default is FIXED** (20000) so a flow lands on ONE detector and its
counter accumulates — this measures the detector's true floor. Add `--rand-port`
to reproduce hping3's random port, which DILUTES the flow across the 3 SYN-split
detectors (a real evasion for low rates — that's a finding, not a bug).

---

## C) LR-DDoS rate sweep — find the minimum detected pps  (lrddos_sweep.py)
From the mininet prompt (network + controller + server up):
```
py exec(open('/home/ayush/my2/lrddos_sweep.py').read(), {'net': net, '__builtins__': __builtins__})
```
Puts h1..h8 at 1 / 2 / 5 / 10 / 25 / 50 / 100 / 250 pps, each sending 100
half-open SYNs (fixed port, so each attacker crosses several windows and the
reputation score reaches the block threshold). Read the controller's `Blocked`
list, or run `analyze_evals.py`, against the ladder the sweep prints:
`::1`=1pps, `::2`=2, `::3`=5, `::4`=10, `::5`=25, `::6`=50, `::7`=100, `::8`=250.
The **lowest-rate source IP that gets blocked = your minimum detected pps.**
(At 1 pps the slowest host takes ~40s — let it finish before reading results.)

---

## Resetting between runs  (NO mininet/server restart needed)
The switch keeps CMS counters and block rules across runs — that's why a
second run looked "polluted". To get a clean slate:

**Just restart the controller** (Ctrl+C in terminal B, re-run, pick the scenario).
On startup the controller now automatically:
  * clears `dangerous_table` (removes all old block rules), and
  * zeroes `cms_row0`/`cms_row1` on A, B, C via thrift (9092/9093/9094).

Mininet and the server keep running. Only restart mininet if you change the
topology or the P4 code.

Manual reset without restarting the controller (optional):
```bash
for p in 9092 9093 9094; do
  printf 'register_reset MyIngress.cms_row0\nregister_reset MyIngress.cms_row1\n' \
    | simple_switch_CLI --thrift-port $p
done
```
(This clears counters only; block rules are cleared by the controller.)

---

## Notes
- **Attack is scapy, not hping3** — hping3 is IPv4-only; the P4 switch parses IPv6.
- **`ab` is benign only** — it completes handshakes; it does not SYN-flood.
- **Spoof / --rand-port will not be caught** — documented limitations / future work.
- Logs per host: `/tmp/ab_<h>.log`, `/tmp/atk_<h>.log`, `/tmp/lr_<h>.log`.
