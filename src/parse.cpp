#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>

#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>

#include "parse.hpp"

bool parse_packet(rte_mbuf* m, FlowKey* key)
{
    // Every header is checked against the packet length before it is read.
    uint32_t len = rte_pktmbuf_data_len(m);
    uint32_t offset = sizeof(rte_ether_hdr);
    if (len < offset)
        return false;

    rte_ether_hdr* eth = rte_pktmbuf_mtod(m, rte_ether_hdr*);
    if (eth->ether_type != htons(RTE_ETHER_TYPE_IPV4))
        return false;

    if (len < offset + sizeof(rte_ipv4_hdr))
        return false;
    rte_ipv4_hdr* ip = rte_pktmbuf_mtod_offset(m, rte_ipv4_hdr*, offset);

    // The header length comes from the packet: IP options make it longer than 20.
    uint32_t ip_len = rte_ipv4_hdr_len(ip);
    if ((ip->version_ihl >> 4) != 4 || ip_len < sizeof(rte_ipv4_hdr) || len < offset + ip_len)
        return false;

    memset(key, 0, sizeof(*key));  // zeroes the padding, and the ports for non-TCP/UDP
    key->src_ip = ip->src_addr;
    key->dst_ip = ip->dst_addr;
    key->proto = ip->next_proto_id;

    // Only the first fragment of a packet carries the TCP or UDP header.
    bool first_fragment = (ntohs(ip->fragment_offset) & RTE_IPV4_HDR_OFFSET_MASK) == 0;
    if (first_fragment && (key->proto == IPPROTO_TCP || key->proto == IPPROTO_UDP)) {
        offset += ip_len;
        if (len < offset + 4)  // the two 16-bit port numbers
            return false;
        // TCP and UDP headers both start with source port, then destination port.
        rte_udp_hdr* ports = rte_pktmbuf_mtod_offset(m, rte_udp_hdr*, offset);
        key->src_port = ports->src_port;
        key->dst_port = ports->dst_port;
    }
    return true;
}
