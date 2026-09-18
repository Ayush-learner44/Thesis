"""Regenerate fattree_topology.svg from fattree.py (single source of truth).
Servers = red, clients = blue, aggregations = green (detectors), core/edge = sky.
Run:  python3 lib/draw_topo.py        (writes ../fattree_topology.svg)
"""
import os
import fattree as ft

W, H = 2000, 1160
MX = 80
INNER = W - 2 * MX
POD_W = INNER / ft.K
CORE_Y, AGG_Y, EDGE_Y, HOST_Y = 132, 336, 524, 772      # switch centres; HOST_Y = host box top
HB_W, HB_H = 40, 26                                       # host box
SB_W, SB_H = 72, 34                                       # switch box

SERVER, CLIENT, AGG, FWD = '#dc2626', '#2563eb', '#16a34a', '#0ea5e9'   # red/blue/green/sky

def core_c(name):
    i = ft.CORES.index(name)
    return (MX + (i + 0.5) * INNER / len(ft.CORES), CORE_Y)

def agg_c(name):    # a{p}{a}
    p, a = int(name[1]), int(name[2])
    return (MX + p * POD_W + (a + 0.5) * POD_W / 2, AGG_Y)

def edge_c(name):   # e{p}{e}
    p, e = int(name[1]), int(name[2])
    return (MX + p * POD_W + (e + 0.5) * POD_W / 2, EDGE_Y)

def host_c(h):
    ex = MX + h['pod'] * POD_W + (h['edge_idx'] + 0.5) * POD_W / 2
    pos = (h['id'] - 1) % ft.HOSTS_PER_EDGE
    return (ex + (pos - (ft.HOSTS_PER_EDGE - 1) / 2) * 46, HOST_Y + HB_H / 2)

def center(name):
    if name in ft.CORES: return core_c(name)
    if name in ft.AGGS:  return agg_c(name)
    if name in ft.EDGES: return edge_c(name)
    return host_c(ft.HOST_BY_NAME[name])

def sbox(name, fill):
    cx, cy = center(name)
    x, y = cx - SB_W / 2, cy - SB_H / 2
    return (f'<rect x="{x:.0f}" y="{y:.0f}" width="{SB_W}" height="{SB_H}" rx="7" '
            f'fill="{fill}" stroke="#1e293b" stroke-width="1.2"/>'
            f'<text x="{cx:.0f}" y="{cy+4:.0f}" font-size="13" font-weight="700" '
            f'text-anchor="middle" fill="#fff" font-family="monospace">{name}</text>')

def hbox(h):
    cx, cy = host_c(h)
    x, y = cx - HB_W / 2, HOST_Y
    fill = SERVER if h['name'] in ft.SERVERS else CLIENT
    return (f'<rect x="{x:.0f}" y="{y}" width="{HB_W}" height="{HB_H}" rx="6" '
            f'fill="{fill}" stroke="#1e293b" stroke-width="1"/>'
            f'<text x="{cx:.0f}" y="{y+17}" font-size="11" font-weight="600" '
            f'text-anchor="middle" fill="#fff" font-family="monospace">{h["name"]}</text>'
            f'<text x="{cx:.0f}" y="{y+37}" font-size="9" text-anchor="middle" '
            f'fill="#475569" font-family="monospace">::{h["id"]:x}</text>')

def main():
    out = []
    out.append(f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" '
               f'font-family="Segoe UI,sans-serif">')
    out.append(f'<rect width="{W}" height="{H}" fill="#fff"/>')
    out.append(f'<text x="{W/2:.0f}" y="44" font-size="26" font-weight="700" '
               f'text-anchor="middle" fill="#0f172a">k=4 Fat-Tree (Clos) — 20 switches, '
               f'32 hosts, 8 servers (pod {ft.SERVER_POD})</text>')

    # links (drawn first, behind the boxes)
    for a, _, b, _ in ft.LINKS:
        (x1, y1), (x2, y2) = center(a), center(b)
        out.append(f'<line x1="{x1:.0f}" y1="{y1:.0f}" x2="{x2:.0f}" y2="{y2:.0f}" '
                   f'stroke="#cbd5e1" stroke-width="1"/>')

    # tier labels
    for y, txt in [(CORE_Y, 'CORE (dumb)'), (AGG_Y, 'AGGREGATION (smart detector)'),
                   (EDGE_Y, 'EDGE (dumb + spray)')]:
        out.append(f'<text x="18" y="{y+4}" font-size="12" font-weight="600" '
                   f'fill="#64748b">{txt}</text>')

    for c in ft.CORES:  out.append(sbox(c, FWD))
    for a in ft.AGGS:   out.append(sbox(a, AGG))
    for e in ft.EDGES:  out.append(sbox(e, FWD))
    for h in ft.HOSTS:  out.append(hbox(h))

    # legend
    lx, ly = MX, HOST_Y + 120
    for i, (col, txt) in enumerate([
            (AGG, 'AGGREGATION = smart detector'), (FWD, 'EDGE / CORE = dumb forwarder'),
            (SERVER, f'server host (all of pod {ft.SERVER_POD})'), (CLIENT, 'client host')]):
        yy = ly + i * 26
        out.append(f'<rect x="{lx}" y="{yy}" width="20" height="16" rx="3" fill="{col}"/>'
                   f'<text x="{lx+30}" y="{yy+13}" font-size="14" fill="#0f172a">{txt}</text>')
    out.append(f'<text x="{lx}" y="{ly-16}" font-size="13" fill="#475569">host hN address '
               f'= 2001:1:1::N (N in hex, shown under each box). Servers: '
               f'{ft.SERVERS[0]}..{ft.SERVERS[-1]} (pod {ft.SERVER_POD}).</text>')
    out.append('</svg>')

    dst = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       'fattree_topology.svg')
    open(dst, 'w').write('\n'.join(out))
    print('wrote', dst)

if __name__ == '__main__':
    main()
