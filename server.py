"""
server.py — IPv6 TCP server for h0 — 3-interface version (paths A, B, C)

Listens on port 80. Auto-assigns h0's IPv6 to the first interface
(eth0 = A path) only. Paths B and C use the weak-host receive model:
same MAC on all 3 interfaces, kernel accepts packets on any of them.

Starts tcpdump on the first 3 interfaces — captures go to
  /home/ayush/my2/capture_path_a.pcap   (A path — SYNs in baseline)
  /home/ayush/my2/capture_path_b.pcap   (B path — ACKs in baseline)
  /home/ayush/my2/capture_path_c.pcap   (C path)

Run on h0 xterm BEFORE firing any traffic:
    python3 /home/ayush/my2/server.py
"""

import socket, threading, re, subprocess, time

subprocess.run(['sysctl', '-w', 'net.ipv6.conf.all.disable_ipv6=0'], capture_output=True)
subprocess.run(['sysctl', '-w', 'net.ipv6.conf.default.disable_ipv6=0'], capture_output=True)

HOST    = "::"
PORT    = 80
H0_IPV6 = "2001:1:1::100"   # avoids collision with h16's natural addr (::10 = 0x10 = 16)

PCAP_PATH_A = "/home/ayush/my2/capture_path_a.pcap"
PCAP_PATH_B = "/home/ayush/my2/capture_path_b.pcap"
PCAP_PATH_C = "/home/ayush/my2/capture_path_c.pcap"

# Static NDP entries for all 60 clients (h1..h60)
CLIENT_NEIGHBORS = {
    f'2001:1:1::{i:x}': f'aa:00:00:00:00:{i:02x}'
    for i in range(1, 61)
}

stats = {'connections': 0}


def get_all_ifaces():
    result = subprocess.run(['ip', 'link'], capture_output=True, text=True)
    ifaces = []
    for line in result.stdout.split('\n'):
        m = re.search(r'\d+:\s+([\w-]+eth\d+)', line)
        if m:
            ifaces.append(m.group(1))
    return ifaces


def setup_ipv6(iface):
    """Assign H0_IPV6 to iface if not already present."""
    result = subprocess.run(['ip', '-6', 'addr', 'show', iface], capture_output=True, text=True)
    if H0_IPV6 not in result.stdout:
        subprocess.run(['ip', '-6', 'addr', 'add', 'nodad', H0_IPV6 + '/64', 'dev', iface],
                       capture_output=True)
        print(f"[server] Assigned {H0_IPV6}/64 to {iface} (nodad)")


def install_ndp(iface):
    """Install permanent NDP entries for all 60 clients on iface."""
    for ip, mac in CLIENT_NEIGHBORS.items():
        subprocess.run(['ip', '-6', 'neigh', 'replace', ip,
                        'lladdr', mac, 'dev', iface, 'nud', 'permanent'],
                       capture_output=True)
    print(f"[server] Static NDP installed for {len(CLIENT_NEIGHBORS)} clients on {iface}")


def _monitor_synrecv():
    prev = 0
    while True:
        try:
            r = subprocess.run(['ss', '-6', '-n', 'state', 'syn-recv'],
                               capture_output=True, text=True)
            lines = [l for l in r.stdout.strip().split('\n')
                     if l and 'Recv-Q' not in l]
            count = len(lines)
            if count != prev:
                if count > 0:
                    print(f"[server] *** ATTACK TRAFFIC: {count} half-open SYNs hitting h0 ***")
                elif prev > 0:
                    print(f"[server] Attack stopped — half-open connections cleared (block rule working)")
                prev = count
        except Exception:
            pass
        time.sleep(0.3)


def handle(conn, addr):
    stats['connections'] += 1
    n = stats['connections']
    print(f"[server] Connection #{n} from {addr[0]}")
    try:
        conn.recv(1024)
        conn.send(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nOK")
        conn.close()
    except Exception as e:
        print(f"[server] Connection #{n} error: {e}")


def start():
    all_ifaces = get_all_ifaces()
    if not all_ifaces:
        print("[server] WARNING: no interfaces detected")
    else:
        # IPv6 on the first interface (A path) only — B and C use weak host
        setup_ipv6(all_ifaces[0])
        # NDP entries live on the interface that owns h0's IPv6 (eth0).
        # Server responses always exit via eth0 because the destination
        # route is via eth0.
        install_ndp(all_ifaces[0])

    # Start tcpdump on the first 3 interfaces (A, B, C paths)
    pcap_paths = [PCAP_PATH_A, PCAP_PATH_B, PCAP_PATH_C]
    tcpdump_procs = []
    for i, ifc in enumerate(all_ifaces[:3]):
        path = pcap_paths[i]
        p = subprocess.Popen(
            ['tcpdump', '-i', ifc, '-w', path],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        tcpdump_procs.append((ifc, path, p))
        print(f"[server] tcpdump capturing on {ifc} -> {path}")
    if tcpdump_procs:
        time.sleep(0.3)
    else:
        print("[server] WARNING: tcpdump not started")

    threading.Thread(target=_monitor_synrecv, daemon=True).start()

    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen(1000)
    print(f"[server] Listening on [::]:{PORT} (IPv6)")
    print(f"[server] Ctrl+C to stop")
    try:
        while True:
            conn, addr = s.accept()
            threading.Thread(target=handle, args=(conn, addr), daemon=True).start()
    except KeyboardInterrupt:
        print(f"\n[server] Done. Total connections served: {stats['connections']}")
        s.close()
        for ifc, path, p in tcpdump_procs:
            p.terminate()
            p.wait()
            print(f"[server] Capture saved: {ifc} -> {path}")


if __name__ == '__main__':
    start()
