# P4-Based SYN Flood DDoS Detection — Full Diamond Topology

In-network SYN flood DDoS detection and mitigation on BMv2 P4 software switches using a **5-switch full-diamond topology** (2 splitters × 3 detectors). Each detector runs a **Count-Min Sketch (CMS)** in the data plane; the control-plane controller reconstructs each flow's behaviour from digests, scores it with a **lean trained model over 6 computable features**, and blocks sustained attackers using a **reputation / hysteresis rule** — without packet sampling, mirroring, or external monitoring.

Splitter routing is **table-driven**: a single compile supports 10 different asymmetric-routing scenarios, selectable at controller startup. No recompile between experiments.

## Headline results (scenario 3 — the even 3-way SYN split, the hardest case)

| Traffic (generated with real tools) | Result |
|---|---|
| Steady benign (ApacheBench, 60 hosts) | **0% false positives** (0 blocked / ~278 windows) |
| Flash crowd (ApacheBench, high concurrency) | **0% false positives** (0 blocked / ~480 windows) |
| Low-rate attack sweep (1 → 250 pps, scapy) | **100% detection**, all 8 blocked, **floor at 1 pps** |

→ Precision ≈ 100%, Recall 100% (down to 1 pps), FPR 0% on benign + flash. Benign traffic is generated with **ApacheBench** (real HTTP handshakes) and attacks with **scapy** (IPv6 SYN flood), so the numbers reflect real client/attacker behaviour rather than synthetic loops.

---

## Table of Contents

1. [System Overview](#system-overview)
2. [Topology](#topology)
3. [Prerequisites & Installation](#prerequisites--installation)
4. [Project Structure](#project-structure)
5. [P4 Data Plane](#p4-data-plane)
6. [Control Plane — Detection & Mitigation](#control-plane--detection--mitigation)
7. [Running the System](#running-the-system)
8. [Traffic & Analysis Tools](#traffic--analysis-tools)
9. [The 10 Routing Scenarios](#the-10-routing-scenarios)
10. [Key Design Decisions](#key-design-decisions)
11. [Limitations & Future Work](#limitations--future-work)

---

## System Overview

```
┌────────────────────────────────────────────────────────────────────┐
│                          CONTROL PLANE                             │
│   controller.py                                                    │
│     pick_scenario()                                                │
│     LeanModel (single classifier, 6 features)                      │
│     FlowTable [first_seen, ack_count, last_eval, last_cms, score]  │
│     FIRST_SEEN / THRESHOLD / EVIDENCE digest handlers              │
│     reputation score  →  block on all detectors when score <= -2   │
│              gRPC / P4Runtime (5 switches)                         │
└────────────────────────┼───────────────────────────────────────────┘
                         │ block rule (src IP → drop on A + B + C)
┌────────────────────────┼───────────────────────────────────────────┐
│                      DATA PLANE (BMv2)                             │
│   h1..h30  ─── s1 ──┐               ┌── A ──┐                      │
│                     ├──(full diamond,┤       │                     │
│   h31..h60 ── s2 ──┘  no s1↔s2 link) │── B ──┤── h0 (3 NICs        │
│                                      │       │      same MAC,      │
│                                      └── C ──┘      IPv6 on eth0)  │
│   s1, s2  : traffic_splitter.p4 (table-driven hash-bucket routing) │
│   A, B, C : ddos_detector.p4    (identical CMS + 3 digest types)   │
└────────────────────────────────────────────────────────────────────┘
```

**Detection flow:**

1. Splitters `s1`/`s2` hash each TCP packet's `(src_ip, src_port, dst_port)` into a 0..99 bucket, looked up in `syn_split` (pure SYNs) or `ack_split` (everything else). The controller fills these tables at runtime per the chosen scenario.
2. Each detector runs the same CMS P4 — increments the sketch on every pure SYN, fires `FIRST_SEEN` on new flows, and fires a `THRESHOLD` digest every 32 SYNs. A pure ACK decrements the sketch; an ACK arriving where the SYN was never seen (asymmetric path) fires an `EVIDENCE` digest.
3. At each THRESHOLD the controller computes **windowed** features for the flow *since its previous evaluation* (an atomic snapshot-and-reset): `syn_count`, `ack_count`, `unacked`, `completion_ratio`, `syn_rate_pps`, `duration_s`, and asks the lean model for a per-window verdict.
4. A single bad window does **not** block. Each flow carries a reputation **score** (+1 benign window, −1 attack window, capped at +3). The drop rule is installed on **all three** detectors only when the score reaches **−2** — i.e. the flow behaved like an attack across several windows.

---

## Topology

```
   h1  (2001:1:1::1)   ─ port  1 ──┐
   ...                              ├─ s1 ─┐
   h30 (2001:1:1::1e)  ─ port 30 ──┘  31│32│33  ──┐         ┌── A ── h0-eth0
                                          │  │  │           │
   h31 (2001:1:1::1f)  ─ port  1 ──┐  31│32│33  ──┤────────├── B ── h0-eth1
   ...                              ├─ s2 ─┘                └── C ── h0-eth2
   h60 (2001:1:1::3c)  ─ port 30 ──┘
```

### Port assignments

| Switch | Port | Connected to        |
|--------|------|---------------------|
| s1     | 1–30 | h1..h30 (clients)   |
| s1     | 31/32/33 | A/B/C port 1    |
| s2     | 1–30 | h31..h60 (clients)  |
| s2     | 31/32/33 | A/B/C port 2    |
| A/B/C  | 1    | s1                  |
| A/B/C  | 2    | s2                  |
| A/B/C  | 3    | h0-eth0/eth1/eth2   |

**No `s1↔s2` link.** Both splitters connect directly to every detector — each detector is equidistant from each splitter, so there is no shared backbone that would bias asymmetric-routing measurements.

### Host addresses

| Host | IPv6 | MAC | Role |
|------|------|-----|------|
| h0   | 2001:1:1::100 | aa:00:00:00:00:00 | Server (victim) |
| h_i  | 2001:1:1::{i:x} | aa:00:00:00:00:{i:02x} | Clients (h1..h30 on s1, h31..h60 on s2) |

**h0 uses `::100`** (not `::10`) to avoid colliding with h16's natural address (`16 = 0x10`). h0 has the **same MAC** on all three interfaces (one L2 entry per detector), its IPv6 is on eth0 only, and Linux's weak-host model accepts packets on eth1/eth2. **IPv6-only** on `2001:1:1::/64`. NDP is static (set up by `server_nginx.py` and the traffic launcher) since the P4 path is unicast-only.

---

## Prerequisites & Installation

```bash
# System: Ubuntu 20.04/22.04 or WSL2; Python 3.8+; p4-utils (BMv2 + p4c); Mininet
pip3 install scapy numpy scikit-learn xgboost pandas
sudo apt install -y apache2-utils nginx      # ab (benign client) + nginx (victim server)

# check p4-utils
python3 -c "from p4utils.mininetlib.network_API import NetworkAPI; print('ok')"
```

The trained model (`ml/models/lean_model.pkl` + `lean_feature_order.pkl`) is included. It was trained on a purpose-built, honestly-labelled dataset generated with real tools (hping3 / ApacheBench / NFStream) on a separate testbed — not on the flawed public CIC-DDoS2019 SYN CSV.

---

## Project Structure

```
my2/
├── network.py             # Mininet topology — 5-switch full diamond
├── p4src/
│   ├── traffic_splitter.p4 (+ .json, _p4rt.txt)   # s1, s2 — table-driven splitter
│   └── ddos_detector.p4    (+ .json, _p4rt.txt)   # A, B, C — CMS detector + 3 digests
├── controller/
│   └── controller.py      # P4Runtime controller: lean model + windowing + reputation score
├── ml/models/
│   ├── lean_model.pkl              # single trained classifier (6 features)
│   └── lean_feature_order.pkl      # feature order used at inference
├── server_nginx.py        # victim server on h0 — nginx over IPv6 (+ NDP setup, pcaps)
├── nginx_h0.conf          # standalone nginx config (IPv6, high backlog)
├── launch_v2.py           # traffic launcher — benign / flash / attack / spoof / mixed
├── attack_rate.py         # hping3-style IPv6 SYN flooder (rate / count / flood / spoof)
├── attack_short.py        # short (<5s) IPv6 SYN flood
├── lrddos_sweep.py        # low-rate DDoS sweep (1..250 pps) — finds the detection floor
├── analyze_evals.py       # reads /tmp/threshold_evals.csv → FP / detection breakdown
├── RUNBOOK.md             # step-by-step run instructions
├── TODO.md                # design notes + deferred work
├── topology.json          # auto-generated by p4-utils at runtime
├── weekly reports.txt     # progress reports
└── resume.txt             # CV bullet content
```

---

## P4 Data Plane

### `traffic_splitter.p4` — runs on `s1` and `s2`

Splits client→server traffic by TCP flag with **runtime-configurable percentages**. `syn_split` (pure SYNs) and `ack_split` (everything else) are keyed on `crc16({src_ip, src_port, dst_port}) mod 100`. Return traffic (ingress port 31/32/33) is L2-forwarded unchanged, never re-classified.

### `ddos_detector.p4` — runs on `A`, `B`, `C` (identical)

**Pipeline:** `dangerous_table` (drop blocklisted src IP) → CMS logic → `l2_forward`.

| CMS parameter | Value |
|---|---|
| Rows × Columns | 2 × 1024, 32-bit counters (~8 KiB/detector) |
| Hash | CRC16 & CRC32 on `{src_ip, dst_ip, dst_port, proto}` |
| Increment | pure SYN (SYN=1, ACK=0) |
| Decrement | pure ACK (ACK=1, SYN=0) — **not** SYN-ACK |
| `cms_min` | `min(c0, c1)` |

**Flow key:** `(src_ip, dst_ip, dst_port, protocol)` — source port excluded, so all connections from one host to one port accumulate in one counter. **THRESHOLD** fires when `cms_min & 0x1F == 0` (every 32 SYNs, lowered from 64 to compensate for SYN-fraction dilution under 3-way splits).

**Digests** (controller tells them apart by field count): `first_seen_digest_t` (5), `threshold_digest_t` (6, carries `cms_min`), `evidence_digest_t` (4). EVIDENCE fires when a pure ACK hits a detector whose CMS row for that flow is zero — i.e. the SYN took a different path (asymmetric-routing reconstruction).

---

## Control Plane — Detection & Mitigation

**File:** `controller/controller.py` (P4Runtime / gRPC).

### Startup
Pick scenario (1–10) → connect to 5 switches → **reset switch state** (clear `dangerous_table` + zero CMS registers over thrift, so every restart is a clean slate without restarting Mininet) → install L2 + split tables → enable digests → one receiver thread per detector.

### FlowTable (windowed)
`flow_key → [first_seen_us, ack_count, last_eval_us, last_cms_syn, score]`, bounded (LRU), lock-protected.
- `first_seen_us` — immutable flow-age reference (logging only).
- `ack_count` — EVIDENCE-reconstructed remote ACKs **this window** (reset each eval).
- `last_eval_us`, `last_cms_syn` — window clock and CMS snapshot.
- `score` — reputation score (cross-window memory).

### THRESHOLD handler — windowed features + reputation
On each THRESHOLD, `snapshot_and_reset()` atomically reads the window and resets it (ACKs arriving after count toward the next window — no race, none lost). Features for the window:
```
syn_count        = cms_min - last_cms_syn        (≈32 in the asymmetric case)
ack_count        = remote ACKs this window
unacked          = max(0, syn_count - ack_count)
completion_ratio = ack_count / syn_count
syn_rate_pps     = syn_count / window_duration
duration_s       = window_duration
```
The lean model returns a per-window verdict. The flow's score moves `+1` (benign) or `−1` (attack, capped at +3), and the drop rule is pushed to **A, B, and C** only when `score <= -2`. So a transient bad window (e.g. an RTT-lagged completion) is absorbed, while a sustained attacker crosses −2 within ~2 windows.

### Lean model
A single trained classifier (RandomForest/XGBoost) over the 6 features above — no 5-model ensemble, no packet-rate scaling hack. Features are defined identically in training and at runtime.

Every evaluation is also dumped to `/tmp/threshold_evals.csv` for `analyze_evals.py`.

---

## Running the System

> **Mininet first, then the controller.** The controller reads `topology.json` and connects over gRPC — both only exist after `network.py` boots. **Restart only the controller between runs** — it auto-resets the CMS registers and block rules on startup, so Mininet and the server keep running.

```bash
# 1) Mininet (terminal A)
cd /home/ayush/my2 && sudo python3 network.py         # wait for mininet> and P4 compile

# 2) Controller (terminal B) — pick a scenario at the prompt
cd /home/ayush/my2/controller && python3 controller.py

# 3) Server on h0 (mininet)
mininet> xterm h0
#   in the h0 xterm:
python3 /home/ayush/my2/server_nginx.py

# 4) Traffic — set MODE in launch_v2.py, then from the mininet prompt
mininet> py exec(open('/home/ayush/my2/launch_v2.py').read(), {'net': net, '__builtins__': __builtins__})

# 5) Analyse a run
python3 /home/ayush/my2/analyze_evals.py
```

See **RUNBOOK.md** for the full workflow, modes, and the reset details.

---

## Traffic & Analysis Tools

| Tool | Purpose |
|---|---|
| `launch_v2.py` | Fan-out launcher. `MODE` = `benign` / `flash` (ApacheBench), `attack` / `spoof` (scapy), `mixed`. |
| `attack_rate.py` | hping3-style IPv6 SYN flooder: `--rate N`, `--flood`, `--count`, `--duration`, `--spoof`, `--rand-port`. |
| `attack_short.py` | Short (<5 s) IPv6 SYN flood. |
| `lrddos_sweep.py` | Rate ladder (1 → 250 pps across 8 hosts) — measures the minimum detected rate. |
| `analyze_evals.py` | Reads the per-eval CSV. In a benign run, **BLOCK rows are the true false positives** (a single ATTACK-verdict window is expected and absorbed by the score). |
| `server_nginx.py` + `nginx_h0.conf` | Victim server (nginx, IPv6, high backlog) — completes handshakes under a 60-host flash crowd. |

**Notes:** benign/flash use ApacheBench (real handshakes); attacks use scapy because the testbed is IPv6 and hping3 is IPv4-only. Spoofed / random-source-port floods are documented evasions (per-source CMS + SYN-split dilution) — see below.

---

## The 10 Routing Scenarios

Selectable at controller startup; each installs different `syn_split`/`ack_split` entries. Same compiled P4 for all.

| # | Description | SYN A/B/C | ACK A/B/C |
|---|---|---|---|
| 1 | Baseline — single SYN path, single ACK path | 100/0/0 | 0/100/0 |
| 2 | SYN split across 2 detectors (A+C) | 50/0/50 | 0/100/0 |
| 3 | **SYN split across all 3 (worst case)** | 33/33/33 | 0/100/0 |
| 4 | All SYNs on A, ACK split (B+C) | 100/0/0 | 0/50/50 |
| 5 | All SYNs on A, ACK split 3-way | 100/0/0 | 33/33/33 |
| 6 | ECMP-realistic — mild spread both | 80/10/10 | 10/80/10 |
| 7 | Cross-contamination | 70/30/0 | 30/70/0 |
| 8 | Max contamination | 50/25/25 | 25/50/25 |
| 9 | Mirror symmetry (negative control) | 50/50/0 | 50/50/0 |
| 10 | Mid-experiment shift @ t=30s | 100/0/0 → 50/0/50 | 0/100/0 |

Scenario 3 is the hardest (each detector sees only ~33% of an attacker's SYNs); the validated results above are on scenario 3.

---

## Key Design Decisions

1. **Full diamond, no s1↔s2 link** — every detector equidistant from every splitter; no shared-backbone bias.
2. **Table-driven splitter** — one compile, 10 scenarios chosen at runtime; no compile-time tuning per experiment.
3. **Identical P4 on all detectors, block pushed to all three** — an attacker is blocked regardless of which path it uses next.
4. **Source port excluded from the CMS key** — all of one host's connections accumulate in one counter (SYN-flood aggregation).
5. **SYN-ACK excluded from the decrement** — avoids server retransmits colliding with attacker buckets and delaying detection.
6. **Windowed counting (atomic snapshot-and-reset)** — features are scoped per evaluation and bounded, matching the model's training definition; no counting/reset race.
7. **Reputation / hysteresis score** — never block on one window. A per-flow score (+1/−1, cap +3, block at −2) absorbs transient RTT-lagged windows and blocks only sustained attackers — this is what makes benign + flash reach 0% FP while every attacker down to 1 pps is still caught.
8. **Threshold = 32 (not 64)** — compensates for per-detector SYN-fraction dilution under splits.
9. **EVIDENCE digest uses OR (`c0==0 || c1==0`)** — one collision-free CMS row is enough to confirm asymmetric routing.
10. **Real tools for evaluation** — ApacheBench for benign/flash, scapy for attack, so results reflect real behaviour.

---

## Limitations & Future Work

- **IP spoofing evades** — the CMS keys on source IP, so a randomised-source-IP flood never accumulates in one counter (`launch_v2.py MODE=spoof` / `attack_rate.py --spoof` demonstrate it). Aggregate destination-side detection (entropy / RST accounting) is the direction to close this.
- **Random source port dilutes across the split** — the splitter hashes on `src_port`, so a random-port low-rate flood scatters across A/B/C and no single detector reaches its 32-SYN threshold (`attack_rate.py --rand-port`). The fix is **cross-detector SYN aggregation** at the controller (sum a flow's counts across all detectors instead of trusting one detector's per-bucket threshold).
- **BMv2 throughput bounds runtime, not recall** — the single-threaded software switch sustains only a few kpps, so a flood designed to finish in seconds takes minutes; detection depends on SYN *count*, not speed, so recall is unaffected.
- **Deferred:** full 10-scenario sweep with the lean+reputation pipeline, cross-detector aggregation, and a topology change from the diamond to a denser real-world topology. See `TODO.md`.
