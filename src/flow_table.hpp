// The flow table: a DPDK rte_hash that maps a flow key to the flow's state.
#pragma once

#include <stdint.h>
#include <vector>

#include <rte_hash.h>

#include "flow_key.hpp"

// Firewall verdict for a flow, decided on its first packet.
enum Verdict { VERDICT_NONE, VERDICT_ALLOW, VERDICT_DENY };

struct FlowState {
    uint64_t packets;
    uint64_t bytes;
    uint64_t first_seen_tsc;
    uint64_t last_seen_tsc;
    int rule;         // index of the firewall rule that matched, -1 if none
    Verdict verdict;  // VERDICT_NONE when no rules file is loaded
};

struct FlowEntry {
    FlowKey key;
    FlowState state;
};

// rte_hash stores only keys. For each key it returns a position, a number
// from 0 to capacity - 1 that stays the same while the key is in the table.
// The flow's state is kept in an array at that position.
class FlowTable {
public:
    bool create(uint32_t capacity, int socket_id);
    void destroy();

    // Returns the flow's state, adding the flow with zeroed state if it is
    // new. Returns NULL if the table is full.
    FlowState* lookup_or_insert(FlowKey* key);

    uint32_t size();
    std::vector<FlowEntry> entries();

private:
    rte_hash* hash = NULL;
    FlowState* states = NULL;
};
