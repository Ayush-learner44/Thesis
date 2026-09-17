#!/usr/bin/env python3
"""
analyze_evals.py -- read the controller's per-eval dump (/tmp/threshold_evals.csv)
and explain the verdicts.

With the reputation/hysteresis score, a single-window ATTACK verdict is EXPECTED
and harmless (RTT-lagged benign windows produce them). What actually matters is a
BLOCK, which only happens once a flow's score reaches the block threshold. So in a
BENIGN run:
  * ATTACK-verdict windows  -> noisy per-window verdicts (fine, absorbed by score)
  * BLOCK rows              -> the TRUE false positives (score-confirmed)

RUN (after a run finishes):
    python3 /home/ayush/my2/analyze_evals.py
"""
import sys
import pandas as pd

CSV = '/tmp/threshold_evals.csv'

def main():
    try:
        df = pd.read_csv(CSV).fillna({'blocked': ''})
    except Exception as e:
        print(f"cannot read {CSV}: {e}"); sys.exit(1)
    if df.empty:
        print("no evals recorded."); return

    has_block = 'blocked' in df.columns
    n_atk = int((df.verdict == 'ATTACK').sum())
    n_ben = int((df.verdict == 'BENIGN').sum())
    n_block = int((df.blocked == 'BLOCK').sum()) if has_block else n_atk

    print(f"total threshold evals   : {len(df)}")
    print(f"  BENIGN windows        : {n_ben}")
    print(f"  ATTACK windows        : {n_atk}   (per-window; absorbed by the score)")
    print(f"  BLOCK events          : {n_block}   <-- the real decisions")
    print(f"  distinct source IPs   : {df.src_ip.nunique()}")

    # ---- the real false positives in a benign run: BLOCK rows -------------
    blocks = df[df.blocked == 'BLOCK'] if has_block else df[df.verdict == 'ATTACK']
    print("\n" + "=" * 74)
    print("BLOCK rows  (in a BENIGN run these are the TRUE false positives)")
    print("=" * 74)
    if blocks.empty:
        print("  none — 0 hosts blocked. Reputation score held. ")
    else:
        cols = ['sw', 'src_ip', 'syn_d', 'ack_d', 'unacked',
                'completion_ratio', 'syn_rate_pps'] + (['score'] if 'score' in df else [])
        print(blocks[cols].to_string(index=False))

    # ---- per-IP: how many bad windows before the score acted -------------
    print("\n" + "=" * 74)
    print("per source IP: total windows / ATTACK windows / blocked?")
    print("=" * 74)
    agg = {'windows': ('verdict', 'size'),
           'attack_windows': ('verdict', lambda s: (s == 'ATTACK').sum())}
    if has_block:
        agg['blocked'] = ('blocked', lambda s: (s == 'BLOCK').any())
    g = df.groupby('src_ip').agg(**agg)
    interesting = g[g.attack_windows > 0].sort_values('attack_windows', ascending=False)
    if interesting.empty:
        print("  (no IP ever produced an attack window)")
    else:
        print(interesting.to_string())
        print("\n  Key check: an IP with attack_windows>=1 but blocked=False means")
        print("  the score correctly ABSORBED a transient bad window (a saved FP).")

    print("\n" + "=" * 74)
    print("completion_ratio by per-window verdict")
    print("=" * 74)
    print(df.groupby('verdict')['completion_ratio'].describe()[
          ['count', 'mean', 'min', '25%', '50%', '75%', 'max']].to_string())

if __name__ == '__main__':
    main()
