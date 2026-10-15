#!/usr/bin/env python3
"""Send UDP packets with many distinct 5-tuples, to test flow-monitor.

Runs on the host, with ordinary UDP sockets. Every packet goes from
10.10.10.1 to 10.10.10.99. Flow i uses source port 10000 + i // 40000 and
destination port 20000 + i % 40000, so one million flows need only 25
sockets, one per source port.

Each pass sends every flow exactly once, in a new random order.

Before running, on the host:
    sudo ip addr add 10.10.10.1/24 dev virbr-dpdk
    sudo ip neigh replace 10.10.10.99 lladdr <MAC of the DPDK port> dev virbr-dpdk nud permanent
Nothing answers ARP for 10.10.10.99, so without the second command the
kernel has no MAC address to send to and discards the packets.
"""

import argparse
import math
import random
import socket
import sys
import time

SRC = "10.10.10.1"
DST = "10.10.10.99"
SRC_PORT_BASE = 10000
DST_PORT_BASE = 20000
DST_PORTS = 40000         # destination ports per source port
PAYLOAD = bytes(18)       # 18 bytes of UDP payload make a 60-byte frame, the Ethernet minimum


def has_neighbour_entry(ip):
    """True if the host kernel has a MAC address for ip."""
    with open("/proc/net/arp") as f:
        next(f)  # column headings
        for line in f:
            fields = line.split()
            # Flag 0x2 means the entry holds a usable MAC address.
            if fields[0] == ip and int(fields[2], 16) & 0x2:
                return True
    return False


def main():
    parser = argparse.ArgumentParser(description="Send UDP packets with many distinct 5-tuples.")
    parser.add_argument("--flows", type=int, default=1000, help="distinct flows (default 1000)")
    parser.add_argument("--rate", type=int, default=20000,
                        help="packets per second, 0 for as fast as possible (default 20000)")
    parser.add_argument("--passes", type=int, default=0,
                        help="stop after this many passes over all flows; 0 runs until Ctrl+C")
    args = parser.parse_args()

    if not has_neighbour_entry(DST):
        sys.exit(f"No MAC address for {DST}; see the commands at the top of this file.")

    ports_per_source = min(args.flows, DST_PORTS)
    sockets = []
    for i in range(math.ceil(args.flows / ports_per_source)):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind((SRC, SRC_PORT_BASE + i))
        sockets.append(s)

    print(f"{args.flows} flows from {SRC} to {DST}, {args.rate or 'unlimited'} packets per second")

    order = list(range(args.flows))
    batch = 32  # packets sent between clock checks
    sent = 0
    passes = 0
    start = time.perf_counter()
    next_send = start
    next_report = start + 1

    try:
        while args.passes == 0 or passes < args.passes:
            random.shuffle(order)
            for i in order:
                source, dst_offset = divmod(i, ports_per_source)
                sockets[source].sendto(PAYLOAD, (DST, DST_PORT_BASE + dst_offset))
                sent += 1
                if sent % batch != 0:
                    continue
                now = time.perf_counter()
                if args.rate:
                    next_send += batch / args.rate
                    if next_send > now:
                        time.sleep(next_send - now)
                    elif now - next_send > 0.1:
                        next_send = now  # fell behind: do not send a burst to catch up
                if now >= next_report:
                    print(f"{now - start:6.1f}s  sent {sent}  pass {passes + 1}", flush=True)
                    next_report += 1
            passes += 1
    except KeyboardInterrupt:
        pass

    print(f"sent {sent} packets in {time.perf_counter() - start:.1f}s, {passes} complete passes")


if __name__ == "__main__":
    main()
