"""nginx (IPv6) + pcap for one Clos server host. Auto-started per server by
network.py; also runnable by hand to watch its access log live.
Access log -> stdout (so `tail -f /tmp/srv_<host>.log` shows requests live).
"""
import os, re, sys, time, signal, subprocess
try: sys.stdout.reconfigure(line_buffering=True)
except Exception: pass

HERE = os.path.dirname(os.path.abspath(__file__))
CONF = os.path.join(HERE, 'lib', 'nginx_ft.conf')
TMP  = os.path.join(HERE, 'tmp')                      # run artifacts (gitignored)
os.makedirs(TMP, exist_ok=True)
subprocess.run(['sysctl', '-w', 'net.ipv6.conf.all.disable_ipv6=0'], capture_output=True)

# our interface + hostname (for unique pid / pcap paths, so 8 servers coexist)
iface = next((m.group(1) for l in subprocess.run(['ip', 'link'], capture_output=True, text=True)
              .stdout.split('\n') if (m := re.search(r'\d+:\s+(h\d+-eth\d+)', l))), None)
host = iface.split('-')[0] if iface else 'h'
pid, elog = f'/tmp/nginx_{host}.pid', f'/tmp/nginx_{host}_err.log'   # nginx internals
pcap = f'{TMP}/cap_{host}.pcap'                                       # capture -> project tmp

def nginx_bin():
    for p in ('nginx', '/usr/sbin/nginx'):
        if os.path.exists(p) or subprocess.run(['sh', '-c', f'command -v {p}']).returncode == 0:
            return p
    return None

nb = nginx_bin()
if not nb:
    print("[server] nginx missing: sudo apt install -y nginx"); sys.exit(1)
for d in ('body', 'proxy', 'fcgi', 'uwsgi', 'scgi'):
    os.makedirs(f'/tmp/nginx_ft/{d}', exist_ok=True)

cap = subprocess.Popen(['tcpdump', '-i', iface, '-w', pcap],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) if iface else None
time.sleep(0.2)
# per-host pid/log via -g so all servers can share one config file
gopt = f'daemon off; pid {pid}; error_log {elog} crit;'
proc = subprocess.Popen([nb, '-c', CONF, '-g', gopt])
print(f"[server:{host}] nginx on [::]:80, pcap -> {pcap}")
try:
    proc.wait()
except KeyboardInterrupt:
    proc.send_signal(signal.SIGQUIT)
    if cap: cap.terminate(); cap.wait()
    print(f"[server:{host}] stopped, capture saved {pcap}")
