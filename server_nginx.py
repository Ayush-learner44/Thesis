"""
server_nginx.py -- run nginx on the h0 victim (IPv6). Completes handshakes even
under a 60-host flash crowd.

It assigns h0's IPv6 on eth0, installs static NDP for all 60 clients, starts
optional per-path tcpdump, then launches a standalone nginx (nginx_h0.conf)
INSIDE h0's namespace. No Docker, no systemd — nginx runs as an ordinary
process here.

One-time install (on WSL):   sudo apt install -y nginx

Run on h0 xterm BEFORE firing traffic:
    python3 /home/ayush/my2/server_nginx.py
Ctrl+C to stop (shuts nginx + captures down cleanly).
"""

import os, re, sys, time, signal, threading, subprocess

CONF     = '/home/ayush/my2/nginx_h0.conf'
H0_IPV6  = '2001:1:1::100'
CAPTURE  = True    # set False to skip the per-path pcaps
PCAPS    = ['/home/ayush/my2/capture_path_a.pcap',
            '/home/ayush/my2/capture_path_b.pcap',
            '/home/ayush/my2/capture_path_c.pcap']
CLIENTS  = {f'2001:1:1::{i:x}': f'aa:00:00:00:00:{i:02x}' for i in range(1, 61)}

subprocess.run(['sysctl', '-w', 'net.ipv6.conf.all.disable_ipv6=0'], capture_output=True)
subprocess.run(['sysctl', '-w', 'net.ipv6.conf.default.disable_ipv6=0'], capture_output=True)


def nginx_bin():
    for p in ('nginx', '/usr/sbin/nginx', '/usr/local/sbin/nginx'):
        if subprocess.run(['sh', '-c', f'command -v {p} >/dev/null 2>&1']).returncode == 0 \
           or os.path.exists(p):
            return p
    return None


def ifaces():
    out = subprocess.run(['ip', 'link'], capture_output=True, text=True).stdout
    return [m.group(1) for line in out.split('\n')
            if (m := re.search(r'\d+:\s+([\w-]+eth\d+)', line))]


def setup(iface):
    r = subprocess.run(['ip', '-6', 'addr', 'show', iface], capture_output=True, text=True)
    if H0_IPV6 not in r.stdout:
        subprocess.run(['ip', '-6', 'addr', 'add', 'nodad', H0_IPV6 + '/64', 'dev', iface],
                       capture_output=True)
        print(f"[nginx] assigned {H0_IPV6}/64 to {iface}")
    for ip, mac in CLIENTS.items():
        subprocess.run(['ip', '-6', 'neigh', 'replace', ip, 'lladdr', mac,
                        'dev', iface, 'nud', 'permanent'], capture_output=True)
    print(f"[nginx] static NDP installed for {len(CLIENTS)} clients on {iface}")


def monitor_synrecv():
    prev = 0
    while True:
        try:
            r = subprocess.run(['ss', '-6', '-n', 'state', 'syn-recv'],
                               capture_output=True, text=True)
            n = len([l for l in r.stdout.strip().split('\n') if l and 'Recv-Q' not in l])
            if n != prev:
                if n > 0:
                    print(f"[nginx] *** {n} half-open SYNs hitting h0 ***")
                elif prev > 0:
                    print("[nginx] half-open connections cleared (block rule working)")
                prev = n
        except Exception:
            pass
        time.sleep(0.3)


def main():
    nb = nginx_bin()
    if not nb:
        print("[nginx] nginx not found. Install it first:  sudo apt install -y nginx")
        sys.exit(1)

    ifs = ifaces()
    if ifs:
        setup(ifs[0])
    else:
        print("[nginx] WARNING: no interfaces detected")

    for d in ('body', 'proxy', 'fcgi', 'uwsgi', 'scgi'):
        os.makedirs(f'/tmp/nginx_h0/{d}', exist_ok=True)

    # validate the config before launching
    t = subprocess.run([nb, '-t', '-c', CONF], capture_output=True, text=True)
    if t.returncode != 0:
        print("[nginx] config test FAILED:\n" + t.stderr)
        sys.exit(1)
    print("[nginx] config OK")

    caps = []
    if CAPTURE:
        for ifc, path in zip(ifs[:3], PCAPS):
            p = subprocess.Popen(['tcpdump', '-i', ifc, '-w', path],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            caps.append((ifc, path, p)); print(f"[nginx] tcpdump {ifc} -> {path}")
        time.sleep(0.3)

    threading.Thread(target=monitor_synrecv, daemon=True).start()

    # launch nginx in the foreground so we own its lifetime
    proc = subprocess.Popen([nb, '-c', CONF, '-g', 'daemon off;'])
    print(f"[nginx] serving 200 OK on [{H0_IPV6}]:80 (IPv6) — Ctrl+C to stop")
    try:
        proc.wait()
    except KeyboardInterrupt:
        print("\n[nginx] stopping...")
        proc.send_signal(signal.SIGQUIT)   # graceful nginx shutdown
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.terminate()
        for ifc, path, p in caps:
            p.terminate(); p.wait(); print(f"[nginx] capture saved: {ifc} -> {path}")


if __name__ == '__main__':
    main()
