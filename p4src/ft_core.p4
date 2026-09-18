/* ft_core.p4  --  core / spine switch of the fat-tree.
 *
 * Pure DOWN forwarder: a packet that reaches a core is always heading down to
 * its destination pod. Controller installs one rule per host (dst MAC -> the
 * port toward that host's pod). No spray, no detection.
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
    action forward(bit<9> port) { sm.egress_spec = port; }
    action drop() { mark_to_drop(sm); }

    table l2_forward {
        key     = { hdr.ethernet.dstAddr : exact; }
        actions = { forward; drop; NoAction; }
        size    = 64;
        default_action = drop();       // a core should always have a route down
    }

    apply { l2_forward.apply(); }
}

control MyEgress(inout headers_t hdr, inout metadata_t meta,
                 inout standard_metadata_t sm) { apply { } }
control MyComputeChecksum(inout headers_t hdr, inout metadata_t meta) { apply { } }
control MyDeparser(packet_out pkt, in headers_t hdr) { apply { pkt.emit(hdr.ethernet); } }

V1Switch(MyParser(), MyVerify(), MyIngress(), MyEgress(),
         MyComputeChecksum(), MyDeparser()) main;
