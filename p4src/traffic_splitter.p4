#include <core.p4>
#include <v1model.p4>

// ================================================================
// CONSTANTS
// ================================================================

const bit<16> ETHERTYPE_IPV6 = 0x86DD;
const bit<8>  PROTO_TCP      = 6;
const bit<9>  TCP_SYN        = 9w0x002;
const bit<9>  TCP_ACK        = 9w0x010;

// Ports facing each detector — same numbering on s1 and s2.
// MUST match network.py addLink port1= values for the splitter side.
const bit<9>  PORT_TO_A      = 31;
const bit<9>  PORT_TO_B      = 32;
const bit<9>  PORT_TO_C      = 33;

// CMS hash output range — buckets [0..99] keyed by syn_split/ack_split tables
const bit<32> SPLIT_BUCKETS  = 100;

// ================================================================
// HEADERS
// ================================================================

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header ipv6_t {
    bit<4>   version;
    bit<8>   trafficClass;
    bit<20>  flowLabel;
    bit<16>  payloadLen;
    bit<8>   nextHdr;
    bit<8>   hopLimit;
    bit<128> srcAddr;
    bit<128> dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<9>  flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

struct headers_t {
    ethernet_t ethernet;
    ipv6_t     ipv6;
    tcp_t      tcp;
}

struct metadata_t {
    bit<32> bucket;
}

// ================================================================
// PARSER
// ================================================================

parser MyParser(packet_in packet,
                out headers_t hdr,
                inout metadata_t meta,
                inout standard_metadata_t standard_metadata) {
    state start {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            ETHERTYPE_IPV6: parse_ipv6;
            default:        accept;
        }
    }
    state parse_ipv6 {
        packet.extract(hdr.ipv6);
        transition select(hdr.ipv6.nextHdr) {
            PROTO_TCP: parse_tcp;
            default:   accept;
        }
    }
    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }
}

// ================================================================
// VERIFY CHECKSUM
// ================================================================

control MyVerifyChecksum(inout headers_t hdr, inout metadata_t meta) {
    apply { }
}

// ================================================================
// INGRESS
// ================================================================

control MyIngress(inout headers_t hdr,
                  inout metadata_t meta,
                  inout standard_metadata_t standard_metadata) {

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action forward(bit<9> port) {
        standard_metadata.egress_spec = port;
    }

    // Split actions — used by syn_split / ack_split tables.
    // The controller selects which action a bucket maps to.
    action send_to_A() { standard_metadata.egress_spec = PORT_TO_A; }
    action send_to_B() { standard_metadata.egress_spec = PORT_TO_B; }
    action send_to_C() { standard_metadata.egress_spec = PORT_TO_C; }

    // L2 forwarding for return traffic (detector → client).
    // Controller installs MAC → port for each client owned by this splitter.
    table l2_forward {
        key     = { hdr.ethernet.dstAddr: exact; }
        actions = { forward; drop; NoAction; }
        size    = 128;
        default_action = NoAction();
    }

    // SYN split — controller fills 100 entries per scenario, one per hash bucket.
    table syn_split {
        key     = { meta.bucket: exact; }
        actions = { send_to_A; send_to_B; send_to_C; NoAction; }
        size    = 128;
        default_action = NoAction();
    }

    // ACK split — controller fills 100 entries per scenario.
    table ack_split {
        key     = { meta.bucket: exact; }
        actions = { send_to_A; send_to_B; send_to_C; NoAction; }
        size    = 128;
        default_action = NoAction();
    }

    apply {

        // Return path: traffic arriving FROM a detector switch →
        // L2-forward back to the client (no flag-based splitting).
        if (standard_metadata.ingress_port == PORT_TO_A ||
            standard_metadata.ingress_port == PORT_TO_B ||
            standard_metadata.ingress_port == PORT_TO_C) {

            l2_forward.apply();

        } else {

            // Host → server path. Hash the flow into a bucket and
            // let the split tables decide the destination detector.
            if (hdr.tcp.isValid() && hdr.ipv6.isValid()) {

                hash(meta.bucket, HashAlgorithm.crc16, (bit<32>)0,
                     { hdr.ipv6.srcAddr, hdr.tcp.srcPort, hdr.tcp.dstPort },
                     SPLIT_BUCKETS);

                if ((hdr.tcp.flags & TCP_SYN) != 0 &&
                    (hdr.tcp.flags & TCP_ACK) == 0) {
                    // Pure SYN — apply syn_split table
                    syn_split.apply();
                } else {
                    // Everything else (ACK, SYN-ACK, FIN, data) — apply ack_split
                    ack_split.apply();
                }

            } else {
                // Non-TCP / non-IPv6 traffic — just L2 forward
                l2_forward.apply();
            }
        }
    }
}

// ================================================================
// EGRESS
// ================================================================

control MyEgress(inout headers_t hdr,
                 inout metadata_t meta,
                 inout standard_metadata_t standard_metadata) {
    apply { }
}

// ================================================================
// COMPUTE CHECKSUM
// ================================================================

control MyComputeChecksum(inout headers_t hdr, inout metadata_t meta) {
    apply { }
}

// ================================================================
// DEPARSER
// ================================================================

control MyDeparser(packet_out packet, in headers_t hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv6);
        packet.emit(hdr.tcp);
    }
}

// ================================================================
// SWITCH INSTANTIATION
// ================================================================

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
