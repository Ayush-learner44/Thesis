/* ft_edge.p4  --  edge / ToR switch of the fat-tree.
 *
 * DOWN: forward to a local host by dst MAC (controller installs those rules).
 * UP (table miss): FLOWLET spray across the two aggregation uplinks (ports 5,6).
 *   A flow stays on one uplink within a burst; after an idle gap (> FL_GAP) it
 *   FLIPS to the other uplink. A connection's SYN and its ACK are ~1 RTT apart
 *   (> FL_GAP) so they land on DIFFERENT uplinks -> different detectors (the
 *   asymmetry detection needs); packets within a burst keep one path and stay in
 *   order (TCP healthy, unlike per-packet spray). Non-TCP falls back to round-robin.
 */
#include <core.p4>
#include <v1model.p4>

#define FL_SLOTS 4096
#define FL_GAP   48w2000            // microseconds: > intra-burst, < RTT (~8ms)

header ethernet_t { bit<48> dstAddr; bit<48> srcAddr; bit<16> etherType; }
header ipv6_t { bit<4> version; bit<8> tc; bit<20> fl; bit<16> plen;
                bit<8> nh; bit<8> hop; bit<128> src; bit<128> dst; }
header tcp_t  { bit<16> sport; bit<16> dport; bit<32> seq; bit<32> ackno;
                bit<4> dofs; bit<3> res; bit<9> flags; bit<16> win;
                bit<16> csum; bit<16> urg; }
struct headers_t  { ethernet_t ethernet; ipv6_t ipv6; tcp_t tcp; }
struct metadata_t { }

parser MyParser(packet_in pkt, out headers_t hdr, inout metadata_t meta,
                inout standard_metadata_t sm) {
    state start { pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) { 0x86DD: v6; default: accept; } }
    state v6 { pkt.extract(hdr.ipv6);
        transition select(hdr.ipv6.nh) { 8w6: tcp; default: accept; } }
    state tcp { pkt.extract(hdr.tcp); transition accept; }
}

control MyVerify(inout headers_t hdr, inout metadata_t meta) { apply { } }

control MyIngress(inout headers_t hdr, inout metadata_t meta,
                  inout standard_metadata_t sm) {

    register<bit<48>>(FL_SLOTS) fl_ts;      // last-seen time per flowlet bucket
    register<bit<9>>(FL_SLOTS)  fl_port;    // uplink chosen for that bucket
    register<bit<32>>(1)        rr;         // round-robin for first packet / non-TCP

    action forward(bit<9> port) { sm.egress_spec = port; }
    action drop() { mark_to_drop(sm); }

    table l2_forward {                      // DOWN rules for local hosts (dst MAC)
        key     = { hdr.ethernet.dstAddr : exact; }
        actions = { forward; drop; NoAction; }
        size    = 64;
        default_action = NoAction();
    }

    apply {
        if (!l2_forward.apply().hit) {                 // going UP: pick an uplink
            bit<9>  up = 5;
            bit<32> c;
            if (hdr.tcp.isValid()) {
                bit<32> idx;
                hash(idx, HashAlgorithm.crc32, 32w0,
                     { hdr.ipv6.src, hdr.ipv6.dst, hdr.tcp.sport, hdr.tcp.dport }, 32w4096);
                bit<48> last; bit<9> lp;
                fl_ts.read(last, idx); fl_port.read(lp, idx);
                bit<48> now = sm.ingress_global_timestamp;
                if (last == 0) {                       // first packet -> round robin
                    rr.read(c, 0); up = (bit<9>)(5 + (c % 2)); rr.write(0, c + 1);
                } else if (now - last > FL_GAP) {      // new flowlet -> flip (splits SYN/ACK)
                    if (lp == 5) { up = 6; } else { up = 5; }
                } else {                               // same burst -> same uplink
                    up = lp;
                }
                fl_ts.write(idx, now); fl_port.write(idx, up);
            } else {                                   // non-TCP (ICMPv6 etc): round robin
                rr.read(c, 0); up = (bit<9>)(5 + (c % 2)); rr.write(0, c + 1);
            }
            sm.egress_spec = up;
        }
    }
}

control MyEgress(inout headers_t hdr, inout metadata_t meta,
                 inout standard_metadata_t sm) { apply { } }
control MyComputeChecksum(inout headers_t hdr, inout metadata_t meta) { apply { } }
control MyDeparser(packet_out pkt, in headers_t hdr) {
    apply { pkt.emit(hdr.ethernet); pkt.emit(hdr.ipv6); pkt.emit(hdr.tcp); }
}

V1Switch(MyParser(), MyVerify(), MyIngress(), MyEgress(),
         MyComputeChecksum(), MyDeparser()) main;
