# TODO — my2 DDoS detector

## [ ] Window the ACK counter (reset per THRESHOLD evaluation)  — deferred, come back to this

**Problem.** `ack_count` in the controller accumulates over the whole lifetime of
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

## [ ] (later) Cross-detector SYN aggregation to close the split-dilution evasion
Splitter hashes on 5-tuple incl. src port (`traffic_splitter.p4:166`); detector CMS
keys on 4-tuple (no src port). A random-source-port low-rate flood scatters across
A/B/C, so no single detector reaches the 32-SYN threshold → evades. Fix: controller
sums a flow's SYNs across all detectors' digests instead of trusting one detector's
per-bucket threshold. (Reproduce with `attack_rate.py --rand-port`.)

## [ ] (later) LR-DDoS proper + topology change (diamond → GÉANT-style) + nginx server
