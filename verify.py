#!/usr/bin/env python3
"""
verify.py — Post-experiment DDoS detection metrics (3-path version).

Reads up to 3 pcaps captured by server.py (paths A, B, C) and produces:
  1. Per-path traffic breakdown (SYN / SYN-ACK / handshake counts)
  2. IP breakdown aggregated across all 3 paths
  3. Confusion matrix and accuracy/precision/recall/F1 metrics

Usage:
    python3 /home/ayush/my2/verify.py
    python3 /home/ayush/my2/verify.py /path/to/path_a.pcap /path/to/path_b.pcap /path/to/path_c.pcap
"""

from scapy.all import rdpcap, IPv6, TCP
import sys, os

# IP → host name mapping (extends to 60 clients)
IP_TO_HOST = {f'2001:1:1::{i:x}': f'h{i}' for i in range(1, 61)}
IP_TO_HOST['2001:1:1::100'] = 'h0 (server)'

SERVER_IP = '2001:1:1::100'

# All 60 client hosts. h1..h30 live on s1, h31..h60 on s2.
ALL_CLIENT_IPS = {f'2001:1:1::{i:x}' for i in range(1, 61)}

# run_all.py split: 20 attackers (h1..h10 + h31..h40), 40 legit (h11..h30 + h41..h60)
_RUNALL_ATK_IDS = list(range(1, 11)) + list(range(31, 41))
_RUNALL_LEG_IDS = list(range(11, 31)) + list(range(41, 61))
RUNALL_ATTACKERS = {f'2001:1:1::{i:x}' for i in _RUNALL_ATK_IDS}
RUNALL_LEGIT     = {f'2001:1:1::{i:x}' for i in _RUNALL_LEG_IDS}

SCENARIOS = {
    '1': {
        'name':          'run_all.py  —  20 attackers (h1-h10, h31-h40)  |  40 legit (h11-h30, h41-h60)',
        'attacker_ips':  RUNALL_ATTACKERS,
        'legit_ips':     RUNALL_LEGIT,
        'total_attack':  40000,    # 20 attackers × 2000 SYNs each
        'total_legit':   3200,     # 40 legit    × 80 conns  each
    },
    '2': {
        'name':          'attacks.py  —  all 60 hosts (h1-h60) attack',
        'attacker_ips':  ALL_CLIENT_IPS.copy(),
        'legit_ips':     set(),
        'total_attack':  120000,   # 60 × 2000
        'total_legit':   0,
    },
    '3': {
        'name':          'flooding.py  —  all 60 hosts flash crowd (legit burst)',
        'attacker_ips':  set(),
        'legit_ips':     ALL_CLIENT_IPS.copy(),
        'total_attack':  0,
        'total_legit':   12000,    # 60 × 200 conns
    },
    '4': {
        'name':          'legit-traffic.py  —  all 60 hosts slow legit traffic',
        'attacker_ips':  set(),
        'legit_ips':     ALL_CLIENT_IPS.copy(),
        'total_attack':  0,
        'total_legit':   4800,     # 60 × 80 conns
    },
    '5': {
        'name':          'Single attack.py from h1 only',
        'attacker_ips':  {'2001:1:1::1'},
        'legit_ips':     set(),
        'total_attack':  2000,
        'total_legit':   0,
    },
}


def pick_scenario():
    print("\n" + "=" * 60)
    print("  verify.py — DDoS Detection Metrics (3-path topology)")
    print("=" * 60)
    print("\nWhich script did you run?\n")
    for k, v in SCENARIOS.items():
        print(f"  {k}.  {v['name']}")
    print("  6.  Custom — enter IPs and counts manually\n")

    choice = input("Enter choice [1-6]: ").strip()

    if choice in SCENARIOS:
        s = SCENARIOS[choice]
        attacker_ips = s['attacker_ips']
        legit_ips    = s['legit_ips']
        total_attack = s['total_attack']
        total_legit  = s['total_legit']

    elif choice == '6':
        print("\nEnter attacker IPs comma-separated (e.g. 2001:1:1::1,2001:1:1::2):")
        raw = input("  Attacker IPs (blank = none): ").strip()
        attacker_ips = {ip.strip() for ip in raw.split(',') if ip.strip()}

        print("Enter legit IPs comma-separated (blank = none):")
        raw = input("  Legit IPs: ").strip()
        legit_ips = {ip.strip() for ip in raw.split(',') if ip.strip()}

        total_attack = int(input("  Total attack SYNs sent: ").strip())
        total_legit  = int(input("  Total legit conns sent: ").strip())

    else:
        print("Invalid choice. Exiting.")
        sys.exit(1)

    return attacker_ips, legit_ips, total_attack, total_legit


def count_flags(pkts):
    """Count SYNs / SYN-ACKs / completed handshakes (3rd ACK) in a pcap.

    ACKs are counted by unique (src_ip, src_port) pairs — one entry per
    TCP connection regardless of how many ACK packets it sends.
    Server-originated ACKs (sport=80) are excluded.
    """
    TCP_SYN = 0x002
    TCP_ACK = 0x010
    syns = 0; synacks = 0
    per_ip_syn = {}
    ack_connections = set()

    for pkt in pkts:
        if IPv6 not in pkt or TCP not in pkt:
            continue
        flags = int(pkt[TCP].flags)
        src   = pkt[IPv6].src
        is_syn = bool(flags & TCP_SYN)
        is_ack = bool(flags & TCP_ACK)
        if is_syn and not is_ack:
            syns += 1
            per_ip_syn[src] = per_ip_syn.get(src, 0) + 1
        elif is_syn and is_ack:
            synacks += 1
        elif is_ack and not is_syn:
            if src != SERVER_IP:
                ack_connections.add((src, pkt[TCP].sport))

    acks = len(ack_connections)
    per_ip_ack = {}
    for (src, _) in ack_connections:
        per_ip_ack[src] = per_ip_ack.get(src, 0) + 1

    return syns, synacks, acks, per_ip_syn, per_ip_ack


def print_path_breakdown(path_pkts):
    """path_pkts: dict of label → packet list (one entry per active path)."""
    print("\n" + "=" * 60)
    print("PER-PATH TRAFFIC BREAKDOWN")
    print("=" * 60)
    for label, pkts in path_pkts.items():
        syns, synacks, acks, per_ip_syn, per_ip_ack = count_flags(pkts)
        print(f"\n  {label}  ({len(pkts)} packets)")
        print(f"    Pure SYNs                          : {syns:6d}")
        print(f"    SYN-ACKs                           : {synacks:6d}")
        print(f"    Completed handshakes (client ACK)  : {acks:6d}")
        if per_ip_syn:
            print(f"    SYNs by IP  :", end='')
            for ip, n in sorted(per_ip_syn.items()):
                host = IP_TO_HOST.get(ip, ip)
                print(f"  {host}={n}", end='')
            print()
        if per_ip_ack:
            print(f"    ACKs by IP  :", end='')
            for ip, n in sorted(per_ip_ack.items()):
                host = IP_TO_HOST.get(ip, ip)
                print(f"  {host}={n}", end='')
            print()


def count_syns(pkts, attacker_ips, legit_ips):
    TCP_SYN = 0x002
    TCP_ACK = 0x010
    attack_reached, legit_reached = 0, 0
    attack_per_ip, legit_per_ip   = {}, {}
    for pkt in pkts:
        if IPv6 not in pkt or TCP not in pkt:
            continue
        flags = int(pkt[TCP].flags)
        if not ((flags & TCP_SYN) and not (flags & TCP_ACK)):
            continue
        src = pkt[IPv6].src
        if src in attacker_ips:
            attack_reached += 1
            attack_per_ip[src] = attack_per_ip.get(src, 0) + 1
        elif src in legit_ips:
            legit_reached += 1
            legit_per_ip[src] = legit_per_ip.get(src, 0) + 1
    return attack_reached, legit_reached, attack_per_ip, legit_per_ip


def count_syns_all_paths(path_pkts, attacker_ips, legit_ips):
    """Aggregate SYN counts across all pcaps. A SYN reaching h0 on ANY
    path counts as 'reached' — each connection only hashes to one path,
    so there's no double-counting risk."""
    a_total, l_total = 0, 0
    a_ip, l_ip = {}, {}
    for pkts in path_pkts.values():
        a, l, ai, li = count_syns(pkts, attacker_ips, legit_ips)
        a_total += a
        l_total += l
        for ip, n in ai.items():
            a_ip[ip] = a_ip.get(ip, 0) + n
        for ip, n in li.items():
            l_ip[ip] = l_ip.get(ip, 0) + n
    return a_total, l_total, a_ip, l_ip


def print_results(attack_reached, legit_reached, attack_per_ip, legit_per_ip,
                  attacker_ips, legit_ips, total_attack, total_legit):

    FN = attack_reached
    TN = legit_reached
    TP = max(0, total_attack - FN)
    FP = max(0, total_legit  - TN)

    total     = TP + TN + FP + FN
    accuracy  = (TP + TN) / total                         if total            > 0 else 0
    precision = TP / (TP + FP)                            if (TP + FP)        > 0 else 0
    recall    = TP / (TP + FN)                            if (TP + FN)        > 0 else 0
    f1        = 2*precision*recall / (precision + recall) if (precision+recall)> 0 else 0

    print("\n" + "=" * 60)
    print("IP BREAKDOWN  (aggregated across all 3 paths)")
    print("=" * 60)

    per_attacker = (total_attack // len(attacker_ips)) if attacker_ips else 0
    print(f"\n  Attacker IPs ({len(attacker_ips)}):")
    if attacker_ips:
        for ip in sorted(attacker_ips):
            host    = IP_TO_HOST.get(ip, ip)
            reached = attack_per_ip.get(ip, 0)
            blocked = max(0, per_attacker - reached)
            print(f"    {host:6s} ({ip})  —  reached h0: {reached:4d}  blocked: {blocked:4d}")
    else:
        print("    none")

    print(f"\n  Legit IPs ({len(legit_ips)}):")
    if legit_ips:
        for ip in sorted(legit_ips):
            host    = IP_TO_HOST.get(ip, ip)
            reached = legit_per_ip.get(ip, 0)
            print(f"    {host:6s} ({ip})  —  SYNs reached h0: {reached:4d}")
    else:
        print("    none")

    # Per-class percentages (TP/FN against total attack, TN/FP against total legit)
    tp_pct = (TP / total_attack * 100) if total_attack > 0 else 0.0
    fn_pct = (FN / total_attack * 100) if total_attack > 0 else 0.0
    tn_pct = (TN / total_legit  * 100) if total_legit  > 0 else 0.0
    fp_pct = (FP / total_legit  * 100) if total_legit  > 0 else 0.0

    print("\n" + "=" * 60)
    print("CONFUSION MATRIX")
    print("=" * 60)
    print(f"  TP  attack SYNs blocked          : {TP:6d}  ({tp_pct:6.2f}%  of attack)")
    print(f"  FN  attack SYNs reached h0       : {FN:6d}  ({fn_pct:6.2f}%  of attack)")
    print(f"  TN  legit SYNs reached h0        : {TN:6d}  ({tn_pct:6.2f}%  of legit )")
    print(f"  FP  legit SYNs blocked           : {FP:6d}  ({fp_pct:6.2f}%  of legit )")
    print(f"  ---")
    print(f"  total_attack_sent                : {total_attack:6d}")
    print(f"  total_legit_sent                 : {total_legit:6d}")

    print("\n" + "=" * 60)
    print("METRICS")
    print("=" * 60)
    print(f"  accuracy  : {accuracy:.4f}   ({accuracy:.2%})")
    print(f"  precision : {precision:.4f}   ({precision:.2%})")
    print(f"  recall    : {recall:.4f}   ({recall:.2%})")
    print(f"  f1        : {f1:.4f}   ({f1:.2%})")
    print("=" * 60)


def main():
    pcap_a = sys.argv[1] if len(sys.argv) > 1 else '/home/ayush/my2/capture_path_a.pcap'
    pcap_b = sys.argv[2] if len(sys.argv) > 2 else '/home/ayush/my2/capture_path_b.pcap'
    pcap_c = sys.argv[3] if len(sys.argv) > 3 else '/home/ayush/my2/capture_path_c.pcap'

    if not os.path.exists(pcap_a):
        print(f"\nERROR: pcap not found: {pcap_a}")
        print("Run server.py on h0 before the experiment — it starts tcpdump automatically.")
        sys.exit(1)

    attacker_ips, legit_ips, total_attack, total_legit = pick_scenario()

    path_pkts = {}
    print(f"\nReading {pcap_a} ...")
    pa = rdpcap(pcap_a)
    path_pkts['PATH_A  (eth0 — detector A)'] = pa
    print(f"  {len(pa)} packets")

    if os.path.exists(pcap_b):
        print(f"Reading {pcap_b} ...")
        pb = rdpcap(pcap_b)
        path_pkts['PATH_B  (eth1 — detector B)'] = pb
        print(f"  {len(pb)} packets")
    else:
        print(f"  (path_b pcap not found — skipping)")

    if os.path.exists(pcap_c):
        print(f"Reading {pcap_c} ...")
        pc = rdpcap(pcap_c)
        path_pkts['PATH_C  (eth2 — detector C)'] = pc
        print(f"  {len(pc)} packets")
    else:
        print(f"  (path_c pcap not found — skipping)")

    print_path_breakdown(path_pkts)

    attack_reached, legit_reached, attack_per_ip, legit_per_ip = \
        count_syns_all_paths(path_pkts, attacker_ips, legit_ips)

    print_results(attack_reached, legit_reached, attack_per_ip, legit_per_ip,
                  attacker_ips, legit_ips, total_attack, total_legit)


if __name__ == '__main__':
    main()
