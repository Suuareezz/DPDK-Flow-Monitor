#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "rules.hpp"

// Parses the whole string as a decimal number from 0 to max.
bool to_number(char* s, long max, long* out)
{
    char* end;
    *out = strtol(s, &end, 10);
    return end != s && *end == '\0' && *out >= 0 && *out <= max;
}

// "allow" or "deny"
bool parse_action(char* s, Verdict* action)
{
    if (strcmp(s, "allow") == 0)
        *action = VERDICT_ALLOW;
    else if (strcmp(s, "deny") == 0)
        *action = VERDICT_DENY;
    else
        return false;
    return true;
}

// "any", "tcp", "udp", "icmp", or a protocol number
bool parse_proto(char* s, int* proto)
{
    long n;
    if (strcmp(s, "any") == 0)
        *proto = -1;
    else if (strcmp(s, "tcp") == 0)
        *proto = IPPROTO_TCP;
    else if (strcmp(s, "udp") == 0)
        *proto = IPPROTO_UDP;
    else if (strcmp(s, "icmp") == 0)
        *proto = IPPROTO_ICMP;
    else if (to_number(s, 255, &n))
        *proto = n;
    else
        return false;
    return true;
}

// "any", "10.10.10.99", or "10.10.10.0/24"
bool parse_prefix(char* s, uint32_t* net, uint32_t* mask)
{
    if (strcmp(s, "any") == 0) {
        *net = 0;
        *mask = 0;
        return true;
    }

    long prefix_len = 32;
    char* slash = strchr(s, '/');
    if (slash != NULL) {
        *slash = '\0';  // s now holds only the address
        if (!to_number(slash + 1, 32, &prefix_len))
            return false;
    }

    in_addr addr;
    if (inet_pton(AF_INET, s, &addr) != 1)
        return false;
    *mask = prefix_len == 0 ? 0 : 0xffffffff << (32 - prefix_len);
    *net = ntohl(addr.s_addr) & *mask;
    return true;
}

// "any", "53", or "20000-20099"
bool parse_ports(char* s, uint16_t* lo, uint16_t* hi)
{
    if (strcmp(s, "any") == 0) {
        *lo = 0;
        *hi = 65535;
        return true;
    }

    long first, last;
    char* dash = strchr(s, '-');
    if (dash == NULL) {
        if (!to_number(s, 65535, &first))
            return false;
        last = first;
    } else {
        *dash = '\0';
        if (!to_number(s, 65535, &first) || !to_number(dash + 1, 65535, &last) || first > last)
            return false;
    }
    *lo = first;
    *hi = last;
    return true;
}

bool load_rules(const char* path, std::vector<Rule>& rules)
{
    FILE* file = fopen(path, "r");
    if (file == NULL) {
        printf("cannot open rules file %s\n", path);
        return false;
    }

    char line[512];
    int line_no = 0;
    while (fgets(line, sizeof(line), file) != NULL) {
        line_no++;
        char* comment = strchr(line, '#');
        if (comment != NULL)
            *comment = '\0';

        char f[6][64];
        char extra[2];
        int n = sscanf(line, "%63s %63s %63s %63s %63s %63s %1s", f[0], f[1], f[2], f[3], f[4],
                       f[5], extra);
        if (n <= 0)
            continue;  // blank or comment-only line

        Rule rule;
        rule.line = line_no;

        // Keep the text before parsing, which modifies the fields.
        char text[400];
        snprintf(text, sizeof(text), "%s %s %s %s %s %s", f[0], f[1], f[2], f[3], f[4], f[5]);
        rule.text = text;

        const char* error = NULL;
        if (n != 6)
            error = "expected 6 fields: action proto src sport dst dport";
        else if (!parse_action(f[0], &rule.action))
            error = "action must be allow or deny";
        else if (!parse_proto(f[1], &rule.proto))
            error = "protocol must be tcp, udp, icmp, any, or a number from 0 to 255";
        else if (!parse_prefix(f[2], &rule.src_net, &rule.src_mask))
            error = "bad source address";
        else if (!parse_ports(f[3], &rule.sport_lo, &rule.sport_hi))
            error = "bad source port";
        else if (!parse_prefix(f[4], &rule.dst_net, &rule.dst_mask))
            error = "bad destination address";
        else if (!parse_ports(f[5], &rule.dport_lo, &rule.dport_hi))
            error = "bad destination port";

        if (error != NULL) {
            printf("%s line %d: %s\n", path, line_no, error);
            fclose(file);
            return false;
        }
        rules.push_back(rule);
    }
    fclose(file);

    if (rules.empty()) {
        printf("%s: no rules found\n", path);
        return false;
    }
    return true;
}

int match_rules(std::vector<Rule>& rules, FlowKey* key)
{
    // Rules hold host byte order; the key holds network byte order.
    uint32_t src = ntohl(key->src_ip);
    uint32_t dst = ntohl(key->dst_ip);
    uint16_t sport = ntohs(key->src_port);
    uint16_t dport = ntohs(key->dst_port);

    for (size_t i = 0; i < rules.size(); i++) {
        Rule& r = rules[i];
        if (r.proto != -1 && r.proto != key->proto)
            continue;
        if ((src & r.src_mask) != r.src_net || (dst & r.dst_mask) != r.dst_net)
            continue;
        if (sport < r.sport_lo || sport > r.sport_hi || dport < r.dport_lo || dport > r.dport_hi)
            continue;
        return i;
    }
    return -1;
}
