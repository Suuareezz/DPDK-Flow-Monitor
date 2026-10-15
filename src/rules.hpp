// Firewall rules, monitor mode: each flow gets a verdict, nothing is dropped.
#pragma once

#include <stdint.h>
#include <string>
#include <vector>

#include "flow_key.hpp"
#include "flow_table.hpp"

// One line of the rules file:  action proto src sport dst dport
// Addresses and ports are in host byte order.
struct Rule {
    Verdict action;     // VERDICT_ALLOW or VERDICT_DENY
    int proto;          // -1 matches any protocol
    uint32_t src_net;   // a mask of 0 matches any address
    uint32_t src_mask;
    uint32_t dst_net;
    uint32_t dst_mask;
    uint16_t sport_lo;
    uint16_t sport_hi;
    uint16_t dport_lo;
    uint16_t dport_hi;
    int line;           // line number in the rules file
    std::string text;   // the rule as written, for the report
};

// Reads rules from a file. On a bad line, prints the line number and the
// reason, and returns false.
bool load_rules(const char* path, std::vector<Rule>& rules);

// Returns the index of the first rule that matches the key, or -1.
int match_rules(std::vector<Rule>& rules, FlowKey* key);
