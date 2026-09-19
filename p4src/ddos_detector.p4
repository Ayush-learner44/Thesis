#include <core.p4>
#include <v1model.p4>

// ================================================================
// CONSTANTS
// ================================================================

const bit<16> ETHERTYPE_IPV6 = 0x86DD;
const bit<8>  PROTO_TCP      = 6;
const bit<9>  TCP_SYN        = 9w0x002;
const bit<9>  TCP_ACK        = 9w0x010;
const bit<32> CMS_COLUMNS    = 2048;

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

struct metadata_t { }

// ================================================================
// DIGESTS
// ================================================================

// Sent on the first SYN of a new flow (at least one CMS row is zero before increment)
struct first_seen_digest_t {
    bit<128> src_ip;
    bit<128> dst_ip;
    bit<16>  dst_port;
    bit<8>   protocol;
    bit<48>  timestamp;
}

// Sent every 64 SYNs for a flow (cms_min hits an exact multiple of 64)
struct threshold_digest_t {
    bit<128> src_ip;
    bit<128> dst_ip;
    bit<16>  dst_port;
    bit<8>   protocol;
    bit<32>  cms_min;
    bit<48>  timestamp;
}

// Sent from the ACK branch when c0==0 OR c1==0 (can't decrement)
// Signals that an ACK arrived for a flow whose SYN took a different path —
// evidence of asymmetric routing. No timestamp needed; controller only counts.
struct evidence_digest_t {
    bit<128> src_ip;
    bit<128> dst_ip;
    bit<16>  dst_port;
    bit<8>   protocol;
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

    // Count-Min Sketch: 2 rows x CMS_COLUMNS. Each 7-bit cell = [ flag:1 (MSB) | count:6 ].
    // count resets to 0 at THRESHOLD (never exceeds 32); flag = "completion already
    // signalled for this bucket" (set on the first completing ACK, cleared when count->0).
    register<bit<7>>(CMS_COLUMNS) cms_row0;    // packed [flag|count] (SRAM, not TCAM)
    register<bit<7>>(CMS_COLUMNS) cms_row1;

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action forward(bit<9> port) {
        standard_metadata.egress_spec = port;
    }

    // Step 1 — block known-attack source IPv6 addresses
    // Controller installs entries with drop action when ML predicts ATTACK
    table dangerous_table {
        key     = { hdr.ipv6.srcAddr: exact; }
        actions = { drop; NoAction; }
        size    = 1024;
        default_action = NoAction();
    }

    // Step 8 — L2 forwarding by destination MAC
    // Controller installs rules at startup for all hosts
    table l2_forward {
        key     = { hdr.ethernet.dstAddr: exact; }
        actions = { forward; drop; NoAction; }
        size    = 128;
        default_action = NoAction();
    }

    apply {

        // Step 1: drop immediately if src IPv6 is in blocklist
        if (hdr.ipv6.isValid()) {
            if (dangerous_table.apply().hit) {
                return;
            }
        }

        // Steps 2-7: detection logic — IPv6 TCP packets only
        if (hdr.ipv6.isValid() && hdr.tcp.isValid()) {

            // Steps 3-4: hash 5-tuple into two CMS row indices
            bit<32> idx0;
            bit<32> idx1;
            hash(idx0, HashAlgorithm.crc16, (bit<32>)0,
                 { hdr.ipv6.srcAddr, hdr.ipv6.dstAddr,
                   hdr.tcp.dstPort,
                   hdr.ipv6.nextHdr },
                 CMS_COLUMNS);
            hash(idx1, HashAlgorithm.crc32, (bit<32>)0,
                 { hdr.ipv6.srcAddr, hdr.ipv6.dstAddr,
                   hdr.tcp.dstPort,
                   hdr.ipv6.nextHdr },
                 CMS_COLUMNS);

            bit<7> cell0; bit<7> cell1;        // packed [ flag:1 | count:6 ]
            bit<6> c0;    bit<6> c1;           // count portion
            bit<1> f0;    bit<1> f1;           // completion-notified flag

            // Step 5a: pure SYN (SYN=1, ACK=0) — increment CMS
            if ((hdr.tcp.flags & TCP_SYN) != 0 &&
                (hdr.tcp.flags & TCP_ACK) == 0) {

                cms_row0.read(cell0, idx0); c0 = cell0[5:0]; f0 = cell0[6:6];
                cms_row1.read(cell1, idx1); c1 = cell1[5:0]; f1 = cell1[6:6];

                // FIRST_SEEN: at least one CMS slot is zero → new flow
                if (c0 == 0 || c1 == 0) {
                    digest<first_seen_digest_t>(1, {
                        hdr.ipv6.srcAddr,
                        hdr.ipv6.dstAddr,
                        hdr.tcp.dstPort,
                        hdr.ipv6.nextHdr,
                        standard_metadata.ingress_global_timestamp
                    });
                }

                c0 = c0 + 1;
                c1 = c1 + 1;

                // cms_min = min of the two post-increment counts
                bit<6> cms_min;
                if (c0 < c1) { cms_min = c0; } else { cms_min = c1; }

                // reset-on-threshold: at 32 SYNs fire ONE digest and zero the cell
                // (clears flag+count). count is 6-bit, never exceeds 32 -> no overflow.
                if (cms_min >= 32) {
                    digest<threshold_digest_t>(1, {
                        hdr.ipv6.srcAddr,
                        hdr.ipv6.dstAddr,
                        hdr.tcp.dstPort,
                        hdr.ipv6.nextHdr,
                        (bit<32>)cms_min,
                        standard_metadata.ingress_global_timestamp
                    });
                    cms_row0.write(idx0, 0);
                    cms_row1.write(idx1, 0);
                } else {
                    cms_row0.write(idx0, f0 ++ c0);   // preserve flag, store count
                    cms_row1.write(idx1, f1 ++ c1);
                }

            // Step 5b: pure ACK only (ACK=1, SYN=0)
            } else if ((hdr.tcp.flags & TCP_ACK) != 0 &&
                       (hdr.tcp.flags & TCP_SYN) == 0) {

                cms_row0.read(cell0, idx0); c0 = cell0[5:0]; f0 = cell0[6:6];
                cms_row1.read(cell1, idx1); c1 = cell1[5:0]; f1 = cell1[6:6];

                if (c0 == 0 || c1 == 0) {
                    // ASYMMETRIC: ACK at a switch that never saw the SYN. Per-ACK
                    // evidence (controller counts the ack + drops src from spoof set).
                    digest<evidence_digest_t>(1, {
                        hdr.ipv6.srcAddr,
                        hdr.ipv6.dstAddr,
                        hdr.tcp.dstPort,
                        hdr.ipv6.nextHdr
                    });
                } else {
                    // SYMMETRIC: this switch saw the SYN. Fire completion ONCE per flow
                    // via the flag (two-row: fire unless BOTH rows already notified).
                    if (f0 == 0 || f1 == 0) {
                        digest<evidence_digest_t>(1, {
                            hdr.ipv6.srcAddr,
                            hdr.ipv6.dstAddr,
                            hdr.tcp.dstPort,
                            hdr.ipv6.nextHdr
                        });
                        f0 = 1; f1 = 1;
                    }
                }

                // decrement (floor 0); clear the flag once a bucket empties
                if (c0 > 0) { c0 = c0 - 1; }
                if (c1 > 0) { c1 = c1 - 1; }
                if (c0 == 0) { f0 = 0; }
                if (c1 == 0) { f1 = 0; }
                cms_row0.write(idx0, f0 ++ c0);
                cms_row1.write(idx1, f1 ++ c1);
            }
        }

        // Step 8: forward all non-dropped packets via L2 table
        l2_forward.apply();
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
