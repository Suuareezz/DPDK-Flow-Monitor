#include <stdio.h>

#include <rte_errno.h>
#include <rte_hash_crc.h>
#include <rte_malloc.h>

#include "flow_table.hpp"

bool FlowTable::create(uint32_t capacity, int socket_id)
{
    rte_hash_parameters params = {};
    params.name = "flow_table";
    params.entries = capacity;
    params.key_len = sizeof(FlowKey);
    params.hash_func = rte_hash_crc;  // CRC32-C, computed with the crc32 instruction
    params.socket_id = socket_id;
    // No concurrency flags: only one core uses the table, so it needs no locks.

    hash = rte_hash_create(&params);
    if (hash == NULL) {
        printf("rte_hash_create failed: %s\n", rte_strerror(rte_errno));
        return false;
    }

    // Zeroed memory, and flows are never removed, so every new position
    // starts with zeroed state.
    states = (FlowState*)rte_zmalloc_socket("flow_states", capacity * sizeof(FlowState),
                                            RTE_CACHE_LINE_SIZE, socket_id);
    if (states == NULL) {
        printf("could not allocate memory for flow states\n");
        rte_hash_free(hash);
        return false;
    }
    return true;
}

void FlowTable::destroy()
{
    rte_free(states);
    rte_hash_free(hash);
}

FlowState* FlowTable::lookup_or_insert(FlowKey* key)
{
    // Hash once; the lookup and the add both use it.
    hash_sig_t sig = rte_hash_hash(hash, key);

    int pos = rte_hash_lookup_with_hash(hash, key, sig);
    if (pos >= 0)
        return &states[pos];

    // Add only when the lookup fails. Adding a key that is already present
    // rewrites its entry, which would write to memory on every packet.
    pos = rte_hash_add_key_with_hash(hash, key, sig);
    if (pos < 0)
        return NULL;
    return &states[pos];
}

uint32_t FlowTable::size()
{
    return rte_hash_count(hash);
}

std::vector<FlowEntry> FlowTable::entries()
{
    std::vector<FlowEntry> result;
    const void* key;
    void* data;
    uint32_t next = 0;
    int pos;
    // rte_hash_iterate returns the same position that a lookup returns.
    while ((pos = rte_hash_iterate(hash, &key, &data, &next)) >= 0) {
        FlowEntry entry;
        entry.key = *(const FlowKey*)key;
        entry.state = states[pos];
        result.push_back(entry);
    }
    return result;
}
