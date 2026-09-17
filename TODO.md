# TODO — my2 DDoS detector

## [~] Window the ACK counter (reset per THRESHOLD evaluation)  — IMPLEMENTED 2026-09-17, NEEDS VALIDATION

**DONE (controller.py):** FlowTable entry is now
`[first_seen_us, ack_count, last_eval_us, last_cms_syn]`. New atomic
`snapshot_and_reset()` reads the window (ACKs since last eval, previous CMS
snapshot, window-start) AND resets it under one lock. `_handle_threshold` now
uses WINDOWED features: `syn_count = cms_min − last_cms_syn` (CMS snapshot delta,
≈32 in the asymmetric case), `ack_count` = remote ACKs this window (then reset),
`duration_s`/`syn_rate_pps` measured from `last_eval` not `first_seen`.
`first_seen` is kept immutable (returned for logging only). Fallback: if the CMS
delta ≤ 0 (contamination / local-ACK dip) it falls back to raw `cms_min`.
THRESHOLD log now prints `[window] synΔ=.. ackΔ=.. win=..s`.
→ MUST re-validate: all-attack (still 100% caught?) + all-benign/flash
(still 0% FP? — this is where the RTT-lag risk shows up). If flash FPs appear,
add a grace delay or EMA per catch #3 below, or revert to cumulative.

**VALIDATION RESULT 2026-09-17 — windowing REGRESSED the benign side (confirmed).**
- attack side fine: LR sweep still 8/8 blocked, 1-pps floor intact.
- benign (ab c=5, 60 hosts): 7 FP / 292 evals (~2.4%).  [baseline cumulative = 0 FP]
- flash  (ab c=20, 60 hosts): 21 FP / 458 evals (~4.6%).  [baseline cumulative = 0 FP]
- Cause CONFIRMED (RTT-lag, from live log): a flow's FIRST window is evaluated
  before its completing ACKs arrive → compl≈0 → ATTACK → blocked; later windows
  of OTHER flows show ackΔ≫synΔ (compl 7–11), proving the ACKs DO arrive, just
  after the block. So windowing threw away the catch-up cushion.
- DECISION PENDING: try (a) nginx (kills the server-choke component of the FPs),
  then (b) the reputation/hysteresis score below (kills the residual RTT-lag FP).
  If both fail to reach ~0 FP, REVERT to cumulative (proven 0 FP / 100 % detect)
  and document windowing as "explored, did not beat baseline".

**Original problem.** `ack_count` in the controller accumulated over the whole life of
a flow. For legit HTTP it drifts to `ack/syn` = 8+ (data ACKs, not just handshake
ACKs). It's not *wrong* (high ratio still separates benign from a ~0-ratio attacker),
but it's unbounded, carries stale history, and does NOT match how the model was
trained (training features were computed per 2s window; live they are cumulative).

**Idea (mine, to implement later).** When a THRESHOLD digest fires: use the ACK
count for the features, then reset it, so the next window only sees NEW ACKs.
This turns it into COUNT-windowing (consistent with the packet-count philosophy)
and aligns live features with the training definition.

**Catches to respect when implementing (don't just zero ack):**
1. **Window BOTH syn and ack, not ack alone.** SYN count from the CMS is also
   cumulative (32, 64, 96…). If you reset `ack` but leave `syn` cumulative,
   `completion_ratio = ack/syn` collapses toward 0 → benign flows look like
   attacks → FALSE POSITIVES. Use `syn_delta = cms_now − cms_at_last_threshold`
   (≈32) together with the freshly-reset ack. Reset both or neither.
2. **Atomic fetch-and-zero under the lock.** Grab the value AND set 0 in the SAME
   locked step, then compute features from the copy:
   `with self._lock: used_ack = ack_count; ack_count = 0`.
   ACKs arriving after that line are NOT lost — they count toward the next window.
3. **Completions lag their SYNs (RTT).** If you evaluate the instant 32 SYNs land
   and zero everything, the completing ACKs for those SYNs haven't come back yet
   → the window looks unacked → FP risk on a bursty *legit* client. This is WHY
   the cumulative version is forgiving (lets ACKs catch up). Consider a short
   **grace delay** before evaluating, or an **EMA/decay** instead of a hard reset
   (bounded values without throwing away in-flight completions).

**Status.** Cumulative version currently works (scenario 3: 100% precision, 0% FP,
LR-DDoS blocked down to 1 pps). So this is a cleanup / train-deploy alignment /
robustness improvement, NOT a bug fix. Safe to defer.

Files that would change: `controller/controller.py` (`_handle_threshold`, FlowTable,
EVIDENCE handler). No dataplane change needed.

---

## [x] Reputation / hysteresis score — DONE + VALIDATED 2026-09-17
Implemented in controller.py (FlowTable `score` field + `bump_score()`;
`_handle_threshold` blocks on `score <= -2`). Constants SCORE_REWARD=1,
SCORE_PENALTY=1, SCORE_CAP=+3, BLOCK_SCORE=-2. VALIDATED scenario 3: benign 5->0,
flash 21->0 (Python AND nginx), LR sweep 8/8 blocked (1..250 pps, each in 2
windows, 1-pps floor intact). Precision ~100%, Recall 100%, FPR 0% benign+flash.
Original idea/rationale below.

## [ ] Reputation / hysteresis score — design notes (MY IDEA 2026-09-17)

**Why.** The windowing FPs all come from a flow's FIRST window being judged before
its ACKs land. A single bad window shouldn't block. Accumulate evidence across
windows instead of a single-shot verdict.

**Design (signed score per flow, extra FlowTable column).**
- each THRESHOLD eval: BENIGN verdict → `score += 1` (cap at e.g. +5);
  ATTACK verdict → `score -= 1` (or a bigger penalty).
- BLOCK only when `score <= -K` (e.g. K=2..3), not on the first attack verdict.
- RTT-lag benign flow: one bad window → score dips to −1, then good windows
  pull it back up → never reaches −K → NOT blocked.  ✅ fixes the FP.
- real attacker: every window is bad → −1,−2,−3 → blocked after K windows.
- This is the "rating column" idea: the score is CROSS-window memory that
  survives the count resets — best of both (bounded features + behavioural memory).

**Tradeoff.** Block is delayed by ~K windows (K×32 SYNs). For a 1-pps attacker
that's ~K×32 s. Acceptable; LR attacks are slow anyway. Slightly weakens the
"instant block" story but is a MORE principled sequential-decision design
(defensible for the thesis; SynFloWatch-style methods also decide over windows).

**Better than a fixed grace delay** (the RTT-grace variant): the score is adaptive
and needs no RTT estimation. Prefer the score. Pairs with nginx (nginx removes the
server-choke FPs; score removes the residual RTT-lag FPs).

## [~] Swap python server.py → nginx (IPv6)  — IMPLEMENTED 2026-09-17, NEEDS `apt install nginx`
DONE: nginx_h0.conf (standalone, IPv6, backlog=8192, reuseport, /tmp
paths) + server_nginx.py (does h0 IPv6+NDP setup, validates config,
runs nginx foreground, optional pcaps, syn-recv monitor). Run it on h0 as the
victim server. Requires `sudo apt install -y nginx`.

## [ ] (later) Cross-detector SYN aggregation to close the split-dilution evasion
Splitter hashes on 5-tuple incl. src port (`traffic_splitter.p4:166`); detector CMS
keys on 4-tuple (no src port). A random-source-port low-rate flood scatters across
A/B/C, so no single detector reaches the 32-SYN threshold → evades. Fix: controller
sums a flow's SYNs across all detectors' digests instead of trusting one detector's
per-bucket threshold. (Reproduce with `attack_rate.py --rand-port`.)

## [ ] (later) LR-DDoS proper + topology change (diamond → GÉANT-style) + nginx server
