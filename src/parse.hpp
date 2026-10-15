// Extract a flow key from a received packet.
#pragma once

#include <rte_mbuf.h>

#include "flow_key.hpp"

// Fills key from an IPv4 packet and returns true. Returns false for any
// other packet, or one too short to hold its headers.
bool parse_packet(rte_mbuf* m, FlowKey* key);
