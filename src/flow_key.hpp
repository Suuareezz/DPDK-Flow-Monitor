// The 5-tuple that identifies a flow.
#pragma once

#include <stdint.h>

// Fields are in network byte order, copied from the packet unchanged.
struct FlowKey {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t proto;
    // rte_hash hashes and compares all 16 bytes of the key. Without this
    // field the compiler would add 3 padding bytes holding leftover data,
    // and two packets of the same flow could give different keys.
    // Always zero.
    uint8_t pad[3];
};
