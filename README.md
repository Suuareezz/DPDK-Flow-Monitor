# dpdk-flow-monitor

A passive packet monitor built on DPDK. It receives packets on one port, groups
them into flows by 5-tuple in a DPDK `rte_hash` table, counts packets and bytes
per flow, and measures the CPU cycles spent classifying each packet.

An optional rules file adds a firewall in monitor mode: each flow gets an allow
or deny verdict, and the program reports what it would have allowed or denied.
Nothing is dropped and nothing is transmitted.

## Files

```
CMakeLists.txt        build, DPDK linked statically
src/main.cpp          port setup, receive loop, timing, reports
src/flow_key.hpp      the 5-tuple key
src/parse.*           Ethernet / IPv4 / TCP / UDP parsing into a key
src/flow_table.*      the rte_hash flow table
src/rules.*           firewall rules: read from a file, match a flow
rules/example.rules   example rules
tools/gen_traffic.py  UDP traffic generator for testing, runs on the host
```

## Requirements

- DPDK built from source and installed, including its static libraries
  (tested with DPDK 25.11.3, g++ 13, Ubuntu 24.04)
- 2 MB huge pages reserved, for example `sudo sysctl -w vm.nr_hugepages=512`
- One network port bound to `vfio-pci` (tested with a virtio-net device in a KVM
  guest, `vfio` in no-IOMMU mode)

## Build

```bash
cmake -B build -S . && cmake --build build
```

## Run

```bash
sudo ./build/flow-monitor -l 1 -a 0000:02:00.0 -- --rules=rules/example.rules
```

- `-l 1` runs the receive loop on CPU 1. `-a` names the one port to use.
- `--rules=FILE` is optional. Without it, flows get no verdict.
- `--top=N` sets how many flows are listed at exit (default 10).

It prints one line per second. Ctrl+C prints a summary, the flows with the most
packets, and, with rules, the flows and packets per rule.

## Test traffic

`tools/gen_traffic.py` sends UDP from `10.10.10.1` to `10.10.10.99` on the bridge
the DPDK port is attached to. On the host, once per boot:

```bash
sudo ip addr add 10.10.10.1/24 dev virbr-dpdk
```

```bash
sudo ip neigh replace 10.10.10.99 lladdr <MAC printed at startup> dev virbr-dpdk nud permanent
```

Then, with flow-monitor running:

```bash
python3 tools/gen_traffic.py --flows 1000 --passes 400
```

Each pass sends every flow once, so with these settings every flow should show
400 packets, and `rules/example.rules` should put 100 flows on rule 1 and 900 on
rule 2. Rule 3 may also catch a flow or two that the host sends by itself, such
as mDNS.

## Rules file

One rule per line: `action proto src sport dst dport`. The first matching rule
wins; a flow that matches no rule is denied.

| Field | Values |
|---|---|
| action | `allow`, `deny` |
| proto | `tcp`, `udp`, `icmp`, `any`, or a number from 0 to 255 |
| src, dst | `any`, an address, or an address with prefix length (`10.10.10.0/24`) |
| sport, dport | `any`, a port, or a range (`20000-20099`) |
