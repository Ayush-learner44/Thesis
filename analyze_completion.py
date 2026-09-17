#!/usr/bin/env python3
"""
analyze_completion.py -- results for the partial-completion sweep.

Joins the IP->completion% map (/tmp/completion_map.csv, written by
completion_test.py) with the controller's per-eval dump
(/tmp/threshold_evals.csv), and reports, per completion level, whether the host
was blocked and the completion_ratio the detector actually measured. The
boundary = the lowest completion% that survived (and the highest that got
blocked).

RUN:  python3 /home/ayush/my2/analyze_completion.py
"""
import sys
import pandas as pd

MAP  = '/tmp/completion_map.csv'
EVAL = '/tmp/threshold_evals.csv'


def main():
    try:
        m = pd.read_csv(MAP)
        df = pd.read_csv(EVAL).fillna({'blocked': ''})
    except Exception as e:
        print(f"cannot read inputs: {e}"); sys.exit(1)

    rows = []
    for _, r in m.iterrows():
        ip, pct = r['src_ip'], int(r['pct'])
        sub = df[df.src_ip == ip]
        if sub.empty:
            rows.append((pct, ip, 0, 0, float('nan'), float('nan'), None))
            continue
        windows   = len(sub)
        atk_wins  = int((sub.verdict == 'ATTACK').sum())
        blocked   = bool((sub.blocked == 'BLOCK').any()) if 'blocked' in sub else atk_wins > 0
        mean_cr   = float(sub.completion_ratio.mean())
        min_score = int(sub.score.min()) if 'score' in sub else float('nan')
        rows.append((pct, ip, windows, atk_wins, mean_cr, min_score, blocked))

    rows.sort(key=lambda t: t[0])

    print("=" * 78)
    print("PARTIAL-COMPLETION SWEEP — did the host get blocked at each completion %?")
    print("=" * 78)
    print(f"  {'pct':>4}  {'source IP':<16}  {'windows':>7}  {'atk_win':>7}  "
          f"{'mean_compl':>10}  {'min_score':>9}  blocked")
    print("  " + "-" * 74)
    for pct, ip, w, aw, cr, sc, blk in rows:
        crs = f"{cr:.3f}" if cr == cr else "  -"
        scs = f"{sc}"     if sc == sc else "  -"
        blks = "YES  <-- blocked" if blk else ("no" if blk is not None else "no data")
        print(f"  {pct:>3}%  {ip:<16}  {w:>7}  {aw:>7}  {crs:>10}  {scs:>9}  {blks}")

    blocked_pcts = [p for p, *_1, blk in rows if blk]
    safe_pcts    = [p for p, *_1, blk in rows if blk is False]
    print("\n" + "=" * 78)
    if blocked_pcts and safe_pcts:
        print(f"BOUNDARY: blocked up to {max(blocked_pcts)}% completion; "
              f"survived from {min(safe_pcts)}% completion.")
        print(f"  => an attacker needs to complete about >{max(blocked_pcts)}% of its "
              f"handshakes to evade (in this run).")
    elif blocked_pcts:
        print(f"All tested levels up to {max(blocked_pcts)}% were blocked "
              f"(raise the top of the ladder to find where it survives).")
    elif safe_pcts:
        print(f"Nothing was blocked (even {min(safe_pcts)}%). Lower the ladder / raise "
              f"TOTAL, or check the controller is on scenario 1.")
    print("Note: mean_compl is what the detector measured; pct is the % of "
          "connections told to complete.")
    print("=" * 78)


if __name__ == '__main__':
    main()
