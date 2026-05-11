# P4-Based SYN Flood DDoS Detection — Full Diamond Topology

In-network SYN flood DDoS detection and mitigation on BMv2 P4 software switches using a **5-switch full-diamond topology** (2 splitters × 3 detectors). The system combines a **Count-Min Sketch (CMS)** in the data plane with a **5-model ML ensemble** in the control plane to detect and block SYN flood attackers across multiple asymmetric routing scenarios — without packet sampling, mirroring, or external monitoring.

Splitter routing is **table-driven**: a single compile supports 10 different asymmetric-routing scenarios, selectable at controller startup. No recompile between experiments.

Improves on the P4M3 paper baseline (86% recall, 89% F1).

**Headline numbers** (60 attackers, threshold = 32, full diamond):

| Scenario                  | SYN split          | ACK split          | Recall    | Precision | F1      |
|---------------------------|--------------------|--------------------|-----------|-----------|---------|
| 1 — Baseline asymmetry    | 100/0/0            | 0/100/0            | ~97.5%    | 100%      | ~98.7%  |
| 6 — ECMP-realistic noise  | 80/10/10           | 10/80/10           | ~97.0%    | 100%      | ~98.5%  |
| 7 — Cross-contamination   | 70/30/0            | 30/70/0            | ~96.8%    | 100%      | ~98.4%  |
| 3 — Even 3-way SYN (worst) | 33/33/33          | 0/100/0            | ~94.5%    | 100%      | ~97.2%  |

---

## Table of Contents

1. [System Overview](#system-overview)
2. [Topology](#topology)
3. [Prerequisites & Installation](#prerequisites--installation)
4. [Project Structure](#project-structure)
5. [P4 Data Plane](#p4-data-plane)
6. [Control Plane & ML Ensemble](#control-plane--ml-ensemble)
7. [Running the System](#running-the-system)
8. [Traffic Scripts](#traffic-scripts)
9. [The 10 Routing Scenarios](#the-10-routing-scenarios)
10. [Verification & Metrics](#verification--metrics)
11. [Key Design Decisions](#key-design-decisions)
12. [Limitations & Math](#limitations--math)

---

## System Overview

```
┌────────────────────────────────────────────────────────────────────┐
│                          CONTROL PLANE                             │
│                                                                    │
│   controller.py                                                    │
│   ┌────────────────────────────────────────────────────────────┐   │
│   │  pick_scenario()           EnsembleClassifier              │   │
│   │      │                     (KNN+RF+DT+XGB+SVM → majority)  │   │
│   │      ↓                              │                      │   │
│   │  install syn_split + ack_split       │                      │   │
│   │  (100 entries each, on s1 and s2)    │                      │   │
│   │                                      │                      │   │
│   │  FlowTable                  THRESHOLD handler              │   │
│   │  [start_time, ack_count]         │                         │   │
│   │      │                           │                         │   │
│   │  FIRST_SEEN    EVIDENCE          │                         │   │
│   │  handler       handler           │                         │   │
│   │      └─────────────┬──────────────┘                         │   │
│   │             gRPC / P4Runtime (5 switches)                  │   │
│   └────────────────────┼───────────────────────────────────────┘   │
└────────────────────────┼───────────────────────────────────────────┘
                         │ table_add (block rule → A + B + C)
┌────────────────────────┼───────────────────────────────────────────┐
│                      DATA PLANE (BMv2)                             │
│                                                                    │
│   h1..h30  ─── s1 ──┐               ┌── A ──┐                      │
│                     ├──(full diamond,┤       │                     │
│   h31..h60 ── s2 ──┘  no s1↔s2 link) │── B ──┤── h0 (3 NICs        │
│                                      │       │      same MAC      │
│                                      └── C ──┘      IPv6 only on  │
│                                                     eth0 = A path)│
│                                                                    │
│   s1, s2  : traffic_splitter.p4 (table-driven hash-bucket routing) │
│   A, B, C : ddos_detector.p4    (identical CMS + 3 digest types)   │
└────────────────────────────────────────────────────────────────────┘
```

**Detection flow:**

1. Splitters `s1`/`s2` hash each TCP packet's `(src_ip, src_port, dst_port)` into a 0..99 bucket. The bucket is looked up in `syn_split` (for pure SYNs) or `ack_split` (for everything else). Each table is filled at runtime by the controller based on the chosen scenario.
2. Each detector runs the same CMS detector P4 — increments a Count-Min Sketch on every pure SYN, fires `FIRST_SEEN` digests on new flows, fires `THRESHOLD` digests every 32 SYNs (lowered from 64 in the baseline paper to compensate for SYN-fraction dilution under ECMP splits — see [Limitations & Math](#limitations--math)).
3. ACKs arriving at a detector that hasn't seen the corresponding SYN (because it took a different path) fire `EVIDENCE` digests. The controller accumulates `ack_count` per flow_key across all detectors.
4. At each THRESHOLD, the controller computes `pps = max(0, cms_min - ack_count) / elapsed`. If the 5-model ML ensemble votes ATTACK (≥3/5), the drop rule is installed on **all three** detectors so the attacker is blocked regardless of which path they next use.

---

## Topology

```
   h1  (2001:1:1::1)   ─ port  1 ──┐
   h2  (2001:1:1::2)   ─ port  2 ──┤
   ...                              ├─ s1 ─┐
   h30 (2001:1:1::1e)  ─ port 30 ──┘  31│32│33  ──┐         ┌── A ── h0-eth0
                                          │  │  │           │
   h31 (2001:1:1::1f)  ─ port  1 ──┐  31│32│33  ──┤────────├── B ── h0-eth1
   h32 (2001:1:1::20)  ─ port  2 ──┤      │  │  │           │
   ...                              ├─ s2 ─┘                └── C ── h0-eth2
   h60 (2001:1:1::3c)  ─ port 30 ──┘
```

### Port assignments

| Switch | Port | Connected to             |
|--------|------|--------------------------|
| s1     | 1–30 | h1..h30 (clients)        |
| s1     | 31   | A port 1                 |
| s1     | 32   | B port 1                 |
| s1     | 33   | C port 1                 |
| s2     | 1–30 | h31..h60 (clients)       |
| s2     | 31   | A port 2                 |
| s2     | 32   | B port 2                 |
| s2     | 33   | C port 2                 |
| A      | 1    | s1 port 31               |
| A      | 2    | s2 port 31               |
| A      | 3    | h0-eth0                  |
| B      | 1    | s1 port 32               |
| B      | 2    | s2 port 32               |
| B      | 3    | h0-eth1                  |
| C      | 1    | s1 port 33               |
| C      | 2    | s2 port 33               |
| C      | 3    | h0-eth2                  |

**No `s1↔s2` link.** Both splitters connect directly to every detector — each detector is equidistant from each splitter. This avoids the cross-splitter bottleneck that a "shared backbone" topology would introduce.

### Host addresses

| Host   | IPv6 address      | MAC                | Role                |
|--------|-------------------|--------------------|---------------------|
| h0     | 2001:1:1::100     | aa:00:00:00:00:00  | Server (victim)     |
| h1     | 2001:1:1::1       | aa:00:00:00:00:01  | Client (s1)         |
| h2     | 2001:1:1::2       | aa:00:00:00:00:02  | Client (s1)         |
| ...    | ...               | ...                | ...                 |
| h15    | 2001:1:1::f       | aa:00:00:00:00:0f  | Client (s1)         |
| h16    | 2001:1:1::10      | aa:00:00:00:00:10  | Client (s1)         |
| ...    | ...               | ...                | ...                 |
| h30    | 2001:1:1::1e      | aa:00:00:00:00:1e  | Client (s1)         |
| h31    | 2001:1:1::1f      | aa:00:00:00:00:1f  | Client (s2)         |
| ...    | ...               | ...                | ...                 |
| h60    | 2001:1:1::3c      | aa:00:00:00:00:3c  | Client (s2)         |

**h0 uses `2001:1:1::100`** (NOT `::10`) — this avoids a collision with h16's natural address (`16 decimal = 0x10`). Clients live on `::1..::3c`. h0 is well above that range.

h0 has the **same MAC** on all three interfaces — L2 tables on each detector switch need only one entry for h0. h0's IPv6 (`2001:1:1::100/64`) is assigned only to eth0; Linux's weak-host model accepts packets on eth1 and eth2 too, and responses always leave via eth0.

**IPv6 only.** No IPv4. All traffic uses the `2001:1:1::/64` prefix. Static NDP entries are pre-installed by `server.py` (60 entries) and each client script (self-assigns from IPV6_MAP fallback).

---

## Prerequisites & Installation

### System requirements
- Ubuntu 20.04 / 22.04 (or WSL2 with Ubuntu)
- Python 3.8+
- p4-utils (BMv2 + p4c + p4runtime tools)
- Mininet

### Python dependencies
```bash
pip3 install scapy numpy scikit-learn xgboost
```

### Verify p4-utils is installed
```bash
python3 -c "from p4utils.mininetlib.network_API import NetworkAPI; print('ok')"
```

### ML models
Trained models live in `ml/models/`. If missing, retrain from CIC-DDoS2019:
```bash
python3 ml/train_models.py --csv /path/to/Syn.csv
```

---

## Project Structure

```
my2/
├── network.py                       # Mininet topology — 5-switch full diamond
├── p4src/
│   ├── traffic_splitter.p4          # s1, s2 — table-driven SYN/ACK splitter
│   ├── traffic_splitter.json        # Compiled BMv2 JSON (auto-generated)
│   ├── traffic_splitter_p4rt.txt    # P4Info (auto-generated)
│   ├── ddos_detector.p4             # A, B, C — CMS detector + 3 digests
│   ├── ddos_detector.json           # Compiled BMv2 JSON (auto-generated)
│   └── ddos_detector_p4rt.txt       # P4Info (auto-generated)
├── controller/
│   └── controller.py                # gRPC controller — 5 switches, scenario picker
├── ml/
│   ├── train_models.py
│   └── models/                      # 5 pickled models + scaler
├── server.py                        # IPv6 TCP server on h0 — tcpdump on 3 NICs
├── attack.py                        # SYN flood — 2000 raw Scapy SYNs per host
├── attacks.py                       # Run attack.py on all 60 hosts
├── traffic.py                       # Legit TCP — 80 conns/host at 3/sec
├── legit-traffic.py                 # Run traffic.py on all 60 hosts
├── flood.py                         # Flash crowd — 200 conns/host (4 phases)
├── flooding.py                      # Run flood.py on all 60 hosts
├── legit.py                         # Single-host BENIGN demo (Scapy, 8 pps)
├── run_all.py                       # Mixed: 20 atk (h1-h10, h31-h40) +
│                                    #         40 legit (h11-h30, h41-h60)
├── verify.py                        # Post-experiment pcap metrics (3 pcaps)
├── test.txt                         # Full scenario + FN/recall math doc
├── limitation.txt                   # BMv2 throughput + multiplier rationale
└── topology.json                    # Auto-generated by p4-utils at runtime
```

---

## P4 Data Plane

### `traffic_splitter.p4` — runs on `s1` and `s2` (table-driven)

Splits client→server traffic by TCP flag, but with **runtime-configurable percentages**. Two tables (`syn_split` and `ack_split`) are keyed on a CRC16 hash bucket of `(src_ip, src_port, dst_port)` mod 100. The controller fills these tables with entries that realise the chosen scenario's SYN/ACK distribution.

Return traffic (from detector → splitter) is L2-forwarded unchanged — the ingress port check (31, 32, 33) prevents the splitter from running its split logic on return traffic.

**Apply logic:**
```
if ingress_port in {31, 32, 33}:        // from a detector — return path
    l2_forward()
else if tcp.isValid() and ipv6.isValid():
    bucket = crc16({src_ip, src_port, dst_port}) mod 100
    if pure SYN (SYN=1, ACK=0):
        syn_split.apply()                // controller decides destination
    else:                                // ACK, SYN-ACK, FIN, data
        ack_split.apply()
else:                                    // non-TCP
    l2_forward()
```

Each table holds 100 entries — one per bucket. Different scenarios just mean different `send_to_A` / `send_to_B` / `send_to_C` actions for different bucket ranges.

---

### `ddos_detector.p4` — runs on `A`, `B`, and `C` (identical)

All three detector switches run **identical P4 logic**. Their behaviour differs only because of which traffic the splitters route to each.

#### Packet pipeline (ingress order)

```
Packet in
   │
   ▼
① dangerous_table       ← drop if src_ip is blocklisted → EXIT
   │
   ▼
② Parse TCP flags
   ├── pure SYN (SYN=1, ACK=0)?
   │       ├── compute CMS indices: CRC16 → idx0, CRC32 → idx1
   │       ├── read c0, c1
   │       ├── if (c0==0 || c1==0) → FIRST_SEEN digest
   │       ├── c0++, c1++; write back
   │       ├── cms_min = min(c0, c1)
   │       └── if (cms_min & 0x1F == 0 && cms_min > 0) → THRESHOLD digest
   │                          ▲
   │                          └── every 32 SYNs (lowered from every 64)
   │
   └── pure ACK (ACK=1, SYN=0)?
           ├── read c0, c1
           ├── if (c0==0 || c1==0) → EVIDENCE digest
           └── if c0>0: c0--; if c1>0: c1--; write back
   │
   ▼
③ l2_forward            ← forward by destination MAC
```

#### Count-Min Sketch (CMS)

| Parameter  | Value                                              |
|------------|----------------------------------------------------|
| Rows       | 2                                                  |
| Columns    | 1024                                               |
| Cell width | 32-bit counter                                     |
| Hash row 0 | CRC16 on `{src_ip, dst_ip, dst_port, proto}`       |
| Hash row 1 | CRC32 on `{src_ip, dst_ip, dst_port, proto}`       |
| Memory     | 2 × 1024 × 32 = 65,536 bits = **8 KiB per detector** |
| Increment  | pure SYN only (SYN=1, ACK=0)                       |
| Decrement  | pure ACK only (ACK=1, SYN=0) — **NOT SYN-ACK**     |
| `cms_min`  | `min(c0, c1)` after increment                      |

**Flow key:** `(src_ip, dst_ip, dst_port, protocol)` — source port excluded. All connections from one host to one server port accumulate in one bucket regardless of ephemeral source port.

**THRESHOLD mask: `0x1F`** — fires every 32 SYNs. Lowered from `0x3F` (every 64) in the baseline paper because with multi-detector ECMP splits each detector sees only a fraction of an attacker's SYNs. See [Limitations & Math](#limitations--math) for the derivation.

#### Digest structs

**`first_seen_digest_t`** (5 fields) — first SYN of a new flow:
```
src_ip    bit<128>
dst_ip    bit<128>
dst_port  bit<16>
protocol  bit<8>
timestamp bit<48>    # ingress_global_timestamp (microseconds)
```

**`threshold_digest_t`** (6 fields) — every 32 SYNs:
```
src_ip    bit<128>
dst_ip    bit<128>
dst_port  bit<16>
protocol  bit<8>
cms_min   bit<32>
timestamp bit<48>
```

**`evidence_digest_t`** (4 fields) — ACK arrived on a switch that never saw the SYN:
```
src_ip    bit<128>
dst_ip    bit<128>
dst_port  bit<16>
protocol  bit<8>
```

The controller identifies digest type by **field count**: 4 → evidence, 5 → first_seen, 6 → threshold.

#### Tables

| Table             | Key                       | Action(s)      | Size |
|-------------------|---------------------------|----------------|------|
| `dangerous_table` | `hdr.ipv6.srcAddr` (exact)| `drop`         | 1024 |
| `l2_forward`      | `hdr.ethernet.dstAddr`    | `forward(port)`| 128  |

---

## Control Plane & ML Ensemble

**File:** `controller/controller.py`

### Switch roles

```python
SPLITTER_SWITCHES = {'s1', 's2'}      # no digests, no block rules
# A, B, C → detector switches (identical treatment)
```

### Startup sequence

1. **Pick scenario** (interactive prompt — choose 1-10)
2. Load 5 ML models + scaler from `ml/models/`
3. Connect to all 5 switches via gRPC (P4Runtime)
4. Install L2 forwarding rules on all 5 switches
5. **Install `syn_split` + `ack_split` entries on s1 and s2** based on the chosen scenario (100 entries per table per splitter — 400 entries total)
6. Enable all 3 digest types on A, B, C
7. Spawn one digest receiver thread per detector switch
8. Print "RUNNING" banner — **wait for this before launching traffic**

### FlowTable

Single in-memory table: `flow_key → [start_time_us, ack_count]`. Bounded at 100,000 entries (LRU eviction). Protected by a lock.

- `start_time_us` — switch clock timestamp of the first SYN (from FIRST_SEEN digest)
- `ack_count` — cumulative ACK evidence count, **never reset** — mirrors what the symmetric CMS hardware counter did (ACK decrements) in the single-switch baseline

### Digest handlers

- **FIRST_SEEN** — records the flow start time (no-op if already exists).
- **EVIDENCE** — atomically increments `ack_count` for the flow_key.
- **THRESHOLD** — looks up the flow's start_time and ack_count, computes:
  ```
  adjusted   = max(0, cms_min - ack_count)
  elapsed    = (now - start_time) / 1_000_000
  pps        = adjusted / elapsed
  pps_scaled = pps × 5000
  ```
  Runs the ML ensemble on `pps_scaled`. If majority votes ATTACK, installs the drop rule on **A, B, and C**.

The `× 5000` multiplier exists because the ML models were trained on CIC-DDoS2019 (line-rate hardware traffic in the millions of pps), while BMv2 produces SYN rates in the hundreds. See `limitation.txt` for the full rationale.

### ML Ensemble

| Model   | Type                      |
|---------|---------------------------|
| KNN     | K-Nearest Neighbors (k=5) |
| RF      | Random Forest (100 trees) |
| DT      | Decision Tree (depth=10)  |
| XGBoost | Gradient Boosted Trees    |
| SVM     | RBF kernel, C=1.0         |

**Decision rule:** majority vote — ≥3/5 models predict ATTACK → block.

**Feature:** `pps × 5000` (single scalar).

---

## Running the System

### Correct startup order

> ⚠️ **Mininet starts FIRST, then the controller.** The controller reads `topology.json` (written by Mininet at startup) and connects to switches via gRPC — both of which only exist after `network.py` has booted.

**Step 1 — Start Mininet** (terminal 1):
```bash
cd /home/ayush/my2
sudo python3 network.py
```
Wait for the Mininet CLI prompt (`mininet>`) and for p4-utils to finish compiling both `.p4` files.

**Step 2 — Start the controller** (terminal 2):
```bash
cd /home/ayush/my2/controller
python3 controller.py
```

You'll see the scenario picker:
```
================================================================
  DDoS Controller — Pick split scenario
================================================================

   1. Baseline — single SYN path, single ACK path
        SYN: 100% -> A
        ACK: 100% -> B

   2. SYN split across 2 detectors (A+C), all ACKs on B
        SYN:  50% -> A,   50% -> C
        ACK: 100% -> B

   ...

  10. Mid-experiment shift — SYN path changes at t=30s
        SYN: 100% -> A   ──►  50% -> A,  50% -> C  @ t=30s
        ACK: 100% -> B

Enter scenario [1-10]:
```

Pick a number. Then wait for:
```
============================================================
DDoS Detection Controller RUNNING — scenario N
============================================================
```
**This banner is the green light** — do not launch traffic before it appears.

**Step 3 — Start the server on h0** (h0 xterm):
```
mininet> xterm h0
```
In the h0 xterm:
```bash
python3 /home/ayush/my2/server.py
```
Wait for:
```
[server] tcpdump capturing on h0-eth0 -> /home/ayush/my2/capture_path_a.pcap
[server] tcpdump capturing on h0-eth1 -> /home/ayush/my2/capture_path_b.pcap
[server] tcpdump capturing on h0-eth2 -> /home/ayush/my2/capture_path_c.pcap
[server] Listening on [::]:80 (IPv6)
```

**Step 4 — Run a traffic scenario** (Mininet CLI):
```
mininet> py exec(open('/home/ayush/my2/run_all.py').read(), {'net': net, '__builtins__': __builtins__})
```

**Step 5 — Stop and verify**:
```
Ctrl+C    # in h0 xterm (saves all 3 pcaps)
python3 /home/ayush/my2/verify.py
```

### Important notes

- **Always restart both Mininet and the controller between experiments.** BMv2 CMS registers persist across runs. The controller's `FlowTable` (start times, ack counts) and `blocked_ips` also persist. Restarting only the controller without Mininet creates state mismatch.
- The `ALREADY_EXISTS` error on digest configuration means the controller was restarted without restarting Mininet. Restart both.
- With 60 hosts the L2 + split rule install takes a few extra seconds at controller startup. Be patient — wait for the RUNNING banner.

---

## Traffic Scripts

### Per-host scripts (run inside one host's namespace)

| Script        | Behaviour                          | Per-host total                              |
|---------------|------------------------------------|---------------------------------------------|
| `attack.py`   | SYN flood (Scapy, 4-phase pattern) | **2000 raw SYNs** at 1000 pps target (Phase 2/4) |
| `traffic.py`  | Real TCP at 3 conns/sec            | **80 connections**                          |
| `flood.py`    | Flash-crowd, 4 phases, mixed speed | **200 connections** (70 + 70 + 30 + 30)     |
| `legit.py`    | Low-rate Scapy demo (BENIGN proof) | 80 SYNs at 8 pps                            |

### Launchers (run from the Mininet CLI)

| Launcher              | What it does                                                                | Total                                |
|-----------------------|-----------------------------------------------------------------------------|--------------------------------------|
| `attacks.py`          | Runs `attack.py` on **all 60 hosts** simultaneously                         | 60 × 2000 = **120,000 attack SYNs**  |
| `flooding.py`         | Runs `flood.py` on **all 60 hosts** simultaneously                          | 60 × 200 = **12,000 connections**    |
| `legit-traffic.py`    | Runs `traffic.py` on **all 60 hosts** simultaneously                        | 60 × 80 = **4,800 connections**      |
| `run_all.py`          | Mixed: `attack.py` on h1-h10 + h31-h40; `traffic.py` on h11-h30 + h41-h60   | 20 atk × 2000 + 40 legit × 80 = **40,000 SYNs + 3,200 conns** |

The launcher just fans out — each host's namespace runs its own copy of the per-host script.

---

## The 10 Routing Scenarios

The controller picker offers 10 scenarios. Each installs different SYN/ACK split table entries on s1 and s2.

| # | Description                                            | SYN A/B/C   | ACK A/B/C   |
|---|--------------------------------------------------------|-------------|-------------|
| 1 | Baseline — single SYN path, single ACK path            | 100/0/0     | 0/100/0     |
| 2 | SYN split across 2 detectors (A+C)                     | 50/0/50     | 0/100/0     |
| 3 | SYN split across all 3 detectors                       | 33/33/33    | 0/100/0     |
| 4 | All SYNs on A, ACK split across 2 detectors (B+C)      | 100/0/0     | 0/50/50     |
| 5 | All SYNs on A, ACK split across all 3 detectors        | 100/0/0     | 33/33/33    |
| 6 | ECMP-realistic — mild spread on both SYN and ACK       | 80/10/10    | 10/80/10    |
| 7 | Cross-contamination — A and B BOTH see SYN and ACK     | 70/30/0     | 30/70/0     |
| 8 | Max contamination — all 3 detectors see SYN and ACK    | 50/25/25    | 25/50/25    |
| 9 | Mirror symmetry — same split for SYN and ACK           | 50/50/0     | 50/50/0     |
| 10| Mid-experiment shift @ t=30s                           | 100/0/0 → 50/0/50 | 0/100/0 |

See `test.txt` (section 8) for the full per-scenario rationale, expected metrics, and which is the "headline" / "negative control" / "worst case" for paper writing.

---

## Verification & Metrics

**File:** `verify.py`

Reads **all 3 pcap files** captured by `server.py` (one per detector path) and produces:
1. Per-path traffic breakdown (SYN / SYN-ACK / completed-handshake counts on each of A, B, C)
2. IP breakdown aggregated across all 3 paths
3. Confusion matrix (TP, FN, TN, FP) based on the chosen scenario's traffic counts
4. Accuracy, precision, recall, F1

### Pick the right traffic scenario at the prompt

```
  1.  run_all.py  —  20 attackers (h1-h10, h31-h40) | 40 legit (h11-h30, h41-h60)
  2.  attacks.py  —  all 60 hosts attack
  3.  flooding.py —  all 60 hosts flash crowd
  4.  legit-traffic.py — all 60 hosts legit
  5.  Single attack.py from h1 only
  6.  Custom
```

### Confusion matrix definitions

| Metric | Definition                                                |
|--------|-----------------------------------------------------------|
| TP     | Attack SYNs blocked by the switch (`total_attack − FN`)   |
| FN     | Attack SYNs that reached h0 (summed across all 3 pcaps)   |
| TN     | Legit SYNs that reached h0 (summed across all 3 pcaps)    |
| FP     | Legit SYNs incorrectly blocked (`total_legit − TN`)       |

---

## Key Design Decisions

### 1. Full diamond, no s1↔s2 link
Both splitters connect directly to every detector. Every detector is equidistant from every splitter — no shared backbone, no cross-splitter hop tax.

### 2. Table-driven splitter
The splitter P4 is compiled once. Different asymmetric-routing scenarios are realised purely by the controller filling `syn_split` / `ack_split` with different bucket→detector mappings. Reviewers cannot accuse you of compile-time tuning per experiment.

### 3. Identical P4 on all 3 detectors
A, B, and C run exactly the same `ddos_detector.p4`. The controller treats them identically. An attacker who somehow routes around one path is still blocked on the other two.

### 4. Block rule pushed to ALL detectors
When an attack is detected via any detector, the drop rule is installed on **A, B, and C**. This ensures the attacker is blocked regardless of which path their future packets take.

### 5. Cumulative `ack_count` — never reset
Mirrors what the symmetric single-switch CMS did in hardware (ACKs decrement). The formula `adjusted = max(0, cms_min − ack_count)` reconstructs the net unacknowledged SYN count in software. Resetting per-window would defeat the purpose.

### 6. Source port excluded from CMS hash
Flow key: `(src_ip, dst_ip, dst_port, protocol)` — no src_port. All connections from one host to one server port accumulate in a single bucket. 32 connections from the same attacker hit threshold, not 32 × N connections spread across N source ports.

### 7. SYN-ACK excluded from decrement
ACK decrement condition: `ACK=1 AND SYN=0`. SYN-ACK excluded — server SYN-ACK retransmits would otherwise collide with attacker CMS buckets and delay detection ~16×.

### 8. Threshold = 32 (not 64)
The P4M3 baseline used threshold 64 with a single detector seeing 100% of SYNs. In a multi-detector ECMP topology, each detector sees a fraction. Lowering to 32 compensates for SYN-fraction dilution. See `test.txt` section 12 for the full math.

### 9. Evidence digest uses OR
`c0 == 0 || c1 == 0` (not AND). In a real environment, CMS hash collisions can leave one row non-zero for an unrelated flow. OR ensures at least one clean row is enough to confirm asymmetric routing.

### 10. h0 at `2001:1:1::100`, not `::10`
`::10` is hex for 16, which collides with h16's natural address (`16 → 0x10`). h0 was moved out of the client range entirely.

### 11. Triple pcap capture
`server.py` starts `tcpdump` on **all 3** h0 interfaces (eth0 → A, eth1 → B, eth2 → C) before listening. `verify.py` reads all 3 and produces a per-path breakdown — the empirical proof that each scenario's split table is doing what it claims.

### 12. Majority vote ensemble
≥3/5 models must vote ATTACK. Individual model noise is suppressed. Legitimate flash crowd traffic (`adjusted ≈ 0`) votes 0/5. Attack traffic votes 4/5 or 5/5 at threshold rates.

---

## Limitations & Math

The detection floor under this design is bounded by the threshold and the SYN-split fraction. The exact formula:

```
FN_per_attacker  =  STRUCTURAL_FLOOR  +  LATENCY_PACKETS

   STRUCTURAL_FLOOR  =  THRESHOLD / max(SYN_fraction_to_any_detector)
   LATENCY_PACKETS   =  observed_pps × (digest_poll_s + grpc_install_s)
                     ≈  14 × 1.2  ≈  17   (at 60-host scale with current config)

Recall = 1 − (N_attackers × FN_per_attacker) / total_attack_sent
```

For scenario 3 (worst case — 33% max SYN fraction) at T=32:
```
FN/atk ≈ 32 / 0.34 + 17 ≈ 111
Recall ≈ 1 − (60 × 111) / 120000 ≈ 94.5%
```

**BMv2 throughput is the binding constraint.** With 60 hosts running `attack.py` simultaneously, each splitter sees ~30,000 pps requested and saturates around 3–10 kpps. Each attacker's effective rate drops to ~14 pps. Attack runs take ~140 seconds instead of the designed ~4 seconds — this is BMv2/software-switch reality, not a bug. Recall is barely affected (the floor depends on SYN count, not speed); experiment runtime is heavily affected.

For the full derivation, scenario-by-scenario recall projections, and the levers available to push recall higher (lower threshold further, parallelise gRPC pushes, etc.), see:

- **`test.txt`** — section 12 has the full FN formula, projection tables for T=32 / T=16 / T=8, and the threshold change log
- **`limitation.txt`** — full rationale for the 5000× ML multiplier, BMv2 throughput numbers, CMS memory math (8 KiB per detector)
