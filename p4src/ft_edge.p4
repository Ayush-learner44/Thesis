/* ft_edge.p4  --  edge / ToR switch of the fat-tree.
 *
 * Forwards DOWN to a local host by destination MAC (controller installs those
 * rules). For anything else (traffic going UP toward the core) it MISSES the
 * table and PER-PACKET SPRAYS across its two aggregation uplinks (ports 3,4).
 * That spray is what makes a connection's SYN and ACK take different upward
 * paths -> different aggregation detectors. No detection here (dumb + spray).
 */
#include <core.p4>
#include <v1model.p4>

header ethernet_t { bit<48> dstAddr; bit<48> srcAddr; bit<16> etherType; }
struct headers_t   { ethernet_t ethernet; }
struct metadata_t  { }

parser MyParser(packet_in pkt, out headers_t hdr, inout metadata_t meta,
                inout standard_metadata_t sm) {
    state start { pkt.extract(hdr.ethernet); transition accept; }
}

control MyVerify(inout headers_t hdr, inout metadata_t meta) { apply { } }

control MyIngress(inout headers_t hdr, inout metadata_t meta,
                  inout standard_metadata_t sm) {

    register<bit<32>>(1) spray_ctr;    // round-robin counter for the spray

    action forward(bit<9> port) { sm.egress_spec = port; }
    action drop() { mark_to_drop(sm); }

    table l2_forward {                 // DOWN rules for local hosts (dst MAC)
        key     = { hdr.ethernet.dstAddr : exact; }
        actions = { forward; drop; NoAction; }
        size    = 64;
        default_action = NoAction();
    }

    apply {
        if (!l2_forward.apply().hit) {
            // UP: per-packet spray across the two aggregation uplinks.
            // Edge has 4 host ports (1-4), so uplinks are 5 and 6.
            bit<32> c;
            spray_ctr.read(c, 0);
            sm.egress_spec = (bit<9>)(5 + (c % 2));   // 5,6,5,6,...
            spray_ctr.write(0, c + 1);
        }
    }
}

control MyEgress(inout headers_t hdr, inout metadata_t meta,
                 inout standard_metadata_t sm) { apply { } }
control MyComputeChecksum(inout headers_t hdr, inout metadata_t meta) { apply { } }
control MyDeparser(packet_out pkt, in headers_t hdr) { apply { pkt.emit(hdr.ethernet); } }

V1Switch(MyParser(), MyVerify(), MyIngress(), MyEgress(),
         MyComputeChecksum(), MyDeparser()) main;
