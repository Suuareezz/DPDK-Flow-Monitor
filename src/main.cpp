// flow-monitor: receive packets on one DPDK port, group them into flows by
// 5-tuple, count packets and bytes per flow, and measure the CPU cycles
// spent classifying each packet. Optional firewall rules give each flow an
// allow or deny verdict; nothing is dropped.
//
//   sudo ./build/flow-monitor -l 1 -a 0000:02:00.0 -- --rules=rules/example.rules

#include <arpa/inet.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <algorithm>
#include <vector>

#include <rte_cycles.h>
#include <rte_debug.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>

#include "flow_key.hpp"
#include "flow_table.hpp"
#include "parse.hpp"
#include "rules.hpp"

#define BURST_SIZE 32
#define RX_RING_SIZE 1024
#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 256
#define TABLE_CAPACITY (1 << 21)  // rte_hash entries, enough for 1 million flows

struct Stats {
    uint64_t packets;         // received
    uint64_t ipv4;            // counted in a flow
    uint64_t not_ipv4;
    uint64_t table_full;      // IPv4, but no room for a new flow
    uint64_t new_flows;
    uint64_t cycles;          // spent in classify(), all bursts
    uint64_t steady_cycles;   // spent in classify(), bursts that created no flow
    uint64_t steady_packets;  // packets in those bursts
};

volatile sig_atomic_t quit = 0;

void on_signal(int)
{
    quit = 1;
}

// rdtsc reads the CPU's time stamp counter, but it does not wait for
// earlier instructions to finish. lfence does: the first read completes
// before the timed code starts, and the second waits until it has finished.
uint64_t tsc_begin()
{
    uint64_t t = rte_rdtsc();
    asm volatile("lfence" ::: "memory");
    return t;
}

uint64_t tsc_end()
{
    asm volatile("lfence" ::: "memory");
    return rte_rdtsc();
}

// Parses one packet, finds or creates its flow, and updates the flow's
// counters. Returns 1 if the packet created a new flow, otherwise 0.
int classify(rte_mbuf* m, FlowTable& table, std::vector<Rule>& rules, uint64_t now, Stats& stats)
{
    FlowKey key;
    if (!parse_packet(m, &key)) {
        stats.not_ipv4++;
        return 0;
    }

    FlowState* flow = table.lookup_or_insert(&key);
    if (flow == NULL) {
        stats.table_full++;
        return 0;
    }

    int is_new = 0;
    if (flow->packets == 0) {
        is_new = 1;
        flow->first_seen_tsc = now;
        if (!rules.empty()) {
            // Rules are checked once, on the first packet; later packets
            // of the flow keep this verdict.
            flow->rule = match_rules(rules, &key);
            flow->verdict = flow->rule >= 0 ? rules[flow->rule].action : VERDICT_DENY;
        }
    }
    flow->packets++;
    flow->bytes += rte_pktmbuf_pkt_len(m);
    flow->last_seen_tsc = now;
    stats.ipv4++;
    return is_new;
}

void setup_port(uint16_t port, rte_mempool* pool)
{
    rte_eth_conf conf = {};
    if (rte_eth_dev_configure(port, 1, 0, &conf) != 0)  // one receive queue, no transmit
        rte_exit(EXIT_FAILURE, "cannot configure port %u\n", port);

    uint16_t rx_desc = RX_RING_SIZE;
    if (rte_eth_dev_adjust_nb_rx_tx_desc(port, &rx_desc, NULL) != 0)
        rte_exit(EXIT_FAILURE, "cannot set receive ring size on port %u\n", port);

    if (rte_eth_rx_queue_setup(port, 0, rx_desc, rte_eth_dev_socket_id(port), NULL, pool) != 0)
        rte_exit(EXIT_FAILURE, "cannot set up receive queue on port %u\n", port);

    if (rte_eth_dev_start(port) != 0)
        rte_exit(EXIT_FAILURE, "cannot start port %u\n", port);

    // A monitor should see every frame on the link, not only frames addressed to it.
    if (rte_eth_promiscuous_enable(port) != 0)
        printf("warning: cannot enable promiscuous mode on port %u\n", port);
}

void print_second(int sec, Stats& now, Stats& prev)
{
    uint64_t packets = now.packets - prev.packets;
    uint64_t cycles = now.cycles - prev.cycles;
    printf("%6d %10lu %10lu %10lu ", sec, packets, now.new_flows - prev.new_flows, now.new_flows);
    if (packets > 0)
        printf("%12.1f\n", (double)cycles / packets);
    else
        printf("%12s\n", "-");
    fflush(stdout);  // so each line appears at once when the output is piped to tee
}

void print_ratio(const char* label, uint64_t cycles, uint64_t packets)
{
    if (packets > 0)
        printf("%-42s %10.1f  over %lu packets\n", label, (double)cycles / packets, packets);
    else
        printf("%-42s %10s\n", label, "-");
}

void print_summary(Stats& s, uint32_t table_size)
{
    printf("\n=== summary ===\n");
    printf("packets received           %12lu\n", s.packets);
    printf("  IPv4, counted in a flow  %12lu\n", s.ipv4);
    printf("  not IPv4                 %12lu\n", s.not_ipv4);
    printf("  IPv4, table full         %12lu\n", s.table_full);
    printf("flows created              %12lu\n", s.new_flows);
    printf("flows in the table         %12u\n", table_size);
    print_ratio("cycles per packet, all bursts", s.cycles, s.packets);
    print_ratio("cycles per packet, bursts with no new flow", s.steady_cycles, s.steady_packets);
    print_ratio("cycles per packet, bursts with a new flow", s.cycles - s.steady_cycles,
                s.packets - s.steady_packets);
}

void format_key(FlowKey* key, char* buf, int len)
{
    char src[INET_ADDRSTRLEN];
    char dst[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &key->src_ip, src, sizeof(src));
    inet_ntop(AF_INET, &key->dst_ip, dst, sizeof(dst));
    snprintf(buf, len, "%s:%u -> %s:%u proto %u", src, ntohs(key->src_port), dst,
             ntohs(key->dst_port), key->proto);
}

const char* verdict_name(Verdict v)
{
    if (v == VERDICT_ALLOW)
        return "allow";
    if (v == VERDICT_DENY)
        return "deny";
    return "-";
}

bool more_packets(const FlowEntry& a, const FlowEntry& b)
{
    return a.state.packets > b.state.packets;
}

void print_flows(std::vector<FlowEntry>& entries, int top, uint64_t ipv4, uint64_t hz,
                 uint64_t start)
{
    // Every IPv4 packet counted adds 1 to exactly one flow.
    uint64_t sum = 0;
    for (size_t i = 0; i < entries.size(); i++)
        sum += entries[i].state.packets;
    printf("packets summed over flows  %12lu  (must equal IPv4 counted: %lu)\n", sum, ipv4);

    std::sort(entries.begin(), entries.end(), more_packets);
    printf("\ntop flows by packets:\n");
    printf("%10s %12s %9s %9s  %-7s %s\n", "packets", "bytes", "first(s)", "last(s)", "verdict",
           "flow");
    char buf[128];
    for (size_t i = 0; i < entries.size() && (int)i < top; i++) {
        FlowState& s = entries[i].state;
        format_key(&entries[i].key, buf, sizeof(buf));
        printf("%10lu %12lu %9.2f %9.2f  %-7s %s\n", s.packets, s.bytes,
               (double)(s.first_seen_tsc - start) / hz, (double)(s.last_seen_tsc - start) / hz,
               verdict_name(s.verdict), buf);
    }
}

void print_firewall(std::vector<FlowEntry>& entries, std::vector<Rule>& rules)
{
    // One slot per rule, plus a last slot for flows that matched no rule.
    size_t no_match = rules.size();
    std::vector<uint64_t> flows(rules.size() + 1, 0);
    std::vector<uint64_t> packets(rules.size() + 1, 0);
    uint64_t allow_flows = 0, allow_packets = 0, deny_flows = 0, deny_packets = 0;

    for (size_t i = 0; i < entries.size(); i++) {
        FlowState& s = entries[i].state;
        size_t slot = no_match;
        if (s.rule >= 0)
            slot = s.rule;
        flows[slot]++;
        packets[slot] += s.packets;
        if (s.verdict == VERDICT_ALLOW) {
            allow_flows++;
            allow_packets += s.packets;
        } else {
            deny_flows++;
            deny_packets += s.packets;
        }
    }

    printf("\nfirewall (monitor mode, nothing dropped): rules that matched flows\n");
    printf("%6s %6s %10s %12s  %s\n", "rule", "line", "flows", "packets", "rule");
    int unmatched_rules = 0;
    for (size_t i = 0; i < rules.size(); i++) {
        if (flows[i] == 0) {
            unmatched_rules++;
            continue;
        }
        printf("%6zu %6d %10lu %12lu  %s\n", i + 1, rules[i].line, flows[i], packets[i],
               rules[i].text.c_str());
    }
    printf("%6s %6s %10lu %12lu  no rule matched, so deny\n", "-", "-", flows[no_match],
           packets[no_match]);
    printf("%d of %zu rules matched no flow\n", unmatched_rules, rules.size());
    printf("allowed:    %lu flows, %lu packets\n", allow_flows, allow_packets);
    printf("would deny: %lu flows, %lu packets\n", deny_flows, deny_packets);
}

int main(int argc, char** argv)
{
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    int ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "rte_eal_init failed\n");
    argc -= ret;
    argv += ret;

    int top = 10;
    char* rules_path = NULL;
    for (int i = 1; i < argc; i++) {
        if (strncmp(argv[i], "--top=", 6) == 0)
            top = atoi(argv[i] + 6);
        else if (strncmp(argv[i], "--rules=", 8) == 0)
            rules_path = argv[i] + 8;
        else
            rte_exit(EXIT_FAILURE,
                     "unknown option %s\nusage: flow-monitor <EAL options> -- [--rules=FILE] [--top=N]\n",
                     argv[i]);
    }

    std::vector<Rule> rules;
    if (rules_path != NULL) {
        if (!load_rules(rules_path, rules))
            rte_exit(EXIT_FAILURE, "cannot load rules\n");
        printf("firewall: %zu rules from %s, monitor mode\n", rules.size(), rules_path);
    }

    // The port is the one device allowed with -a, so it is port 0.
    if (rte_eth_dev_count_avail() != 1)
        rte_exit(EXIT_FAILURE, "expected exactly one port; allow one with -a <PCI address>\n");
    uint16_t port = 0;

    rte_mempool* pool = rte_pktmbuf_pool_create("mbufs", NUM_MBUFS, MBUF_CACHE_SIZE, 0,
                                                RTE_MBUF_DEFAULT_BUF_SIZE,
                                                rte_eth_dev_socket_id(port));
    if (pool == NULL)
        rte_exit(EXIT_FAILURE, "cannot create mbuf pool\n");

    FlowTable table;
    if (!table.create(TABLE_CAPACITY, rte_socket_id()))
        rte_exit(EXIT_FAILURE, "cannot create flow table\n");

    setup_port(port, pool);

    rte_ether_addr mac;
    rte_eth_macaddr_get(port, &mac);
    uint64_t hz = rte_get_tsc_hz();
    printf("port %u, MAC " RTE_ETHER_ADDR_PRT_FMT ", lcore %u, TSC %lu Hz. Ctrl+C to stop.\n",
           port, RTE_ETHER_ADDR_BYTES(&mac), rte_lcore_id(), hz);
    printf("%6s %10s %10s %10s %12s\n", "sec", "rx/s", "new/s", "flows", "cycles/pkt");

    Stats total = {};
    Stats last = {};
    rte_mbuf* pkts[BURST_SIZE];
    uint64_t start = rte_rdtsc();
    uint64_t next_report = start + hz;
    int sec = 0;

    while (!quit) {
        uint16_t n = rte_eth_rx_burst(port, 0, pkts, BURST_SIZE);
        if (n > 0) {
            // Timed: classification only, not the receive and not the free.
            int new_flows = 0;
            uint64_t t0 = tsc_begin();
            for (int i = 0; i < n; i++)
                new_flows += classify(pkts[i], table, rules, t0, total);
            uint64_t cycles = tsc_end() - t0;

            // Monitor only: every packet is freed after it is counted.
            rte_pktmbuf_free_bulk(pkts, n);

            total.packets += n;
            total.new_flows += new_flows;
            total.cycles += cycles;
            if (new_flows == 0) {
                // A burst that only looked up existing flows: the steady state.
                total.steady_packets += n;
                total.steady_cycles += cycles;
            }
        }

        if (rte_rdtsc() >= next_report) {
            sec++;
            print_second(sec, total, last);
            last = total;
            next_report += hz;
        }
    }

    print_summary(total, table.size());
    std::vector<FlowEntry> entries = table.entries();
    print_flows(entries, top, total.ipv4, hz, start);
    if (!rules.empty())
        print_firewall(entries, rules);

    rte_eth_dev_stop(port);
    rte_eth_dev_close(port);
    table.destroy();
    rte_eal_cleanup();
    return 0;
}
