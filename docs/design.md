# TUN FWMark PoC Design

This document describes the PoC in this repository: how it transfers Linux
`skb->mark` across a TUN userspace boundary, why it uses two different
mechanisms for the TUN write and read paths, and what limitations remain.

## Problem

Linux TUN exposes packet bytes to userspace, but it does not expose `skb->mark`
in the native PI header or virtio net header. This is inconvenient for tunneling
software that wants to preserve routing metadata such as fwmark across the
kernel/userspace boundary.

The hard part is the **TUN Read Path**:

```text
kernel stack -> TUN netdev -> TUN fd -> userspace
```

For high throughput, TUN may pass a TCP or UDP GSO super-packet to userspace via
`IFF_VNET_HDR`. A super-packet is one skb with one `skb->mark`, one virtio net
header, and a large payload that will be segmented later. Any scheme that changes
packet bytes before the IP header can invalidate header offsets, checksum
metadata, or GSO state.

## Chosen Design

The PoC uses a PI-mode `IFF_VNET_HDR` TUN and tc BPF:

- **TUN Write Path** uses an in-band 4-byte mark prefix.
- **TUN Read Path** uses an out-of-band BPF ringbuf metadata event.

These two directions are asymmetric on purpose.

## TUN Write Path

Userspace writes:

```text
tun_pi + virtio_net_hdr + be32 fwmark + packet
```

The tc ingress BPF program runs after TUN has consumed `tun_pi` and
`virtio_net_hdr`, so the skb data starts with:

```text
be32 fwmark + packet
```

The BPF program:

1. reads the first 4 bytes as a big-endian fwmark;
2. assigns the value to `skb->mark`;
3. removes those 4 bytes with `bpf_skb_adjust_room()`;
4. emits a ringbuf event for test visibility.

After this, the kernel sees a clean packet with the desired `skb->mark`.

This works with PI+VNET because the custom mark prefix is placed after the
virtio net header and is stripped before the packet continues through the stack.

## TUN Read Path

The tc egress BPF program does not modify packet bytes. For every skb, including
GSO super-packets, it emits one ringbuf event:

```text
direction, ifindex, queue_mapping, skb->mark, skb->len, skb->hash, gso_size,
gso_segs, eth protocol, L4 protocol, source port, destination port,
IP source, IP destination, IP ID, L4 cookie
```

Userspace reads the TUN fd normally and consumes the matching metadata event out
of band.

The simplest matching model is FIFO per TUN queue:

```text
tc egress event queue[N] -> userspace metadata FIFO for TUN queue N
TUN fd queue[N]          -> userspace packet read for TUN queue N
```

For a single-queue TUN, userspace can treat the ringbuf events as sideband
headers and pop one read-path event for each TUN packet read. For a multi-queue
TUN, use `queue_mapping` to maintain one FIFO per TUN queue/fd.

The robust production shape is still simple:

1. drain global ringbuf events into `metadata_fifo[queue_mapping]`;
2. for each TUN fd, pop the next metadata event from its queue FIFO and read one
   packet from that TUN queue;
3. treat a missing metadata event, an empty FIFO, or a full bounded FIFO as
   desynchronization for that queue;
4. compare the metadata fingerprint with the actual TUN packet.

The fingerprint is intentionally cheap: packet length, GSO size, IP protocol,
ports, IPv4 source/destination, IPv4 ID, and an L4 cookie. The L4 cookie is TCP
sequence number for TCP and UDP length for UDP. This is not a cryptographic
identity, but it catches the important mismatch classes without modifying packet
bytes or adding per-packet BPF locking.

The BPF program also maintains a per-CPU drop counter for ringbuf reservation
failures. The PoC asserts that this counter remains zero during tests and
benchmarks. A strict per-queue sequence number is possible, but doing it with a
shared BPF counter needs synchronization and was measurably heavier in mixed
traffic than the FIFO-plus-fingerprint-plus-drop-counter shape.

For a GSO super-packet this is the correct granularity: the whole skb has one
`skb->mark`, so one metadata event per skb/super-packet is enough. The packet
itself remains unchanged, so the virtio net header still describes the real
packet bytes and GSO is preserved.

## Why Not Prepend On Read Path

Prepending bytes at tc egress changes where the IP header appears in skb data.
That conflicts with TUN's later virtio header serialization and can break TCP
GSO or checksum metadata. In local experiments, a prepend-based read-path BPF
program made TCP throughput collapse because the TCP/GSO hot path stopped
delivering the data skb to the TUN fd correctly.

For non-GSO packets only, direct prepend is viable. The repository includes a
separate `tun_read_path_prepend_mark` BPF program that rejects any skb with
`gso_size != 0`, prepends a 4-byte big-endian fwmark, and lets userspace strip
that prefix after reading from the TUN fd. This is simpler than the ringbuf side
channel for scalar packets, but it is deliberately not used for GSO traffic.

Run:

```sh
make bench-prepend
```

On the development host, 20000 UDP scalar packets produced:

```text
PREPEND_READ_PATH_UDP_SCALAR: mark=0x00000042 tun_len=174
BENCH_PREPEND_UDP_SCALAR baseline=2.185 Gbit/s prepend=2.005 Gbit/s drop=8.2% iterations=20000
```

The runner also has a stricter comparison against a GSO-enabled no-fwmark
baseline:

```sh
make bench-nogso-prepend-udp
make bench-nogso-prepend-tcp
```

The comparison is:

1. baseline: TUN offloads enabled, no fwmark BPF;
2. no-GSO prepend: TUN offloads disabled, tc egress prepends 4-byte fwmark to
   scalar packets.

On the development host:

```text
BENCH_NOGSO_PREPEND_UDP baseline_gso=4.351 Gbit/s nogso_prepend=7.292 Gbit/s drop=-67.6% iterations=5000
BENCH_NOGSO_PREPEND_TCP baseline_gso=0.468 Gbit/s nogso_prepend=0.000 Gbit/s drop=100.0% baseline_mbps=467.58 nogso_mbps=0.04 iterations=10
```

The UDP number is a local microbenchmark result, not a general claim that
disabling GSO is faster. In this runner, the GSO side uses `UDP_SEGMENT` cmsg,
while the no-GSO side sends ordinary UDP datagrams. TCP is the more important
warning: with TUN offloads disabled, the prepend path degrades to about
0.04 Mbit/s in this userspace TCP-peer benchmark.

## Why Not Append To The Tail

Tail metadata looks attractive because it does not move the IP header. However,
the BPF helper needed for tail growth is `bpf_skb_change_tail()`. The kernel
documents and implements this helper as a slow-path operation: it linearizes,
unclones, and drops offload state. In other words, using it defeats the goal of
preserving GSO super-packets.

Appending raw bytes also changes skb length. If those bytes are treated as packet
payload, checksums and lengths become wrong. If they are intended to sit outside
the IP packet, userspace and kernel still need an out-of-band length convention.
The ringbuf side channel is cleaner.

## Limitations

- Single-queue users can usually consume ringbuf events and TUN packets in FIFO
  order.
- Multi-queue users should maintain one metadata FIFO per queue/fd using
  `queue_mapping`.
- FIFO matching assumes packets are not dropped after the tc egress hook has
  emitted metadata and that ringbuf events are not lost. Production code should
  count ringbuf drops, use bounded metadata FIFOs, size the TUN queue/ringbuf
  conservatively, and treat fingerprint mismatch as a queue-level
  desynchronization signal.
- Ringbuf overflow means metadata loss. A production implementation needs
  counters and a resynchronization policy.
- The PoC verifies UDP GSO with `UDP_SEGMENT` and TCP GSO with a minimal TCP
  peer implemented against the TUN fd. The TCP test completes a SYN/SYN-ACK/ACK
  handshake, sends marked TCP data through the kernel TCP stack, and verifies
  that the TUN fd reads a TCP GSO super-packet while the ringbuf carries the same
  fwmark.
- This does not make `SO_RCVMARK` work on TUN. From userspace, the TUN fd is a
  character device, and existing TUN read paths do not expose socket control
  messages.

## Run

```sh
make test
```

Expected result:

```text
WRITE_PATH: imported mark=0x00000042 ...
WRITE_PATH_UDP_GSO: imported mark=0x00000042 ... gso_size=1200
READ_PATH_UDP_SCALAR: event mark=0x00000043 ...
READ_PATH_ZERO_MARK: event mark=0x00000000 ...
READ_PATH_UDP: event mark=0x00000042 ... gso_size=1200 gso_segs=3
READ_PATH_TCP: event mark=0x00000042 ... gso_size=1460 gso_segs=5
PASS: TUN write path imports fwmark; TUN read path exports fwmark out-of-band while preserving UDP and TCP GSO super-packets
```

## Performance And Stress Test

The runner also provides:

```sh
make bench
```

This runs baseline and fwmark read-path loops in fresh isolated network
namespaces:

1. baseline: no fwmark BPF, send traffic and read the TUN fd;
2. fwmark: attach only the read-path ringbuf BPF, send the same workload, read
   the TUN fd, and consume metadata events.

It covers:

- UDP GSO super-packets;
- TCP GSO burst packets from the minimal TCP peer;
- mixed traffic with one UDP scalar packet, one UDP GSO super-packet, and one
  TCP GSO burst per iteration.

On the development host, 5000 iterations produced:

```text
BENCH_UDP_GSO baseline=2.663 Gbit/s fwmark=2.054 Gbit/s drop=22.9% events=5000/5000
BENCH_TCP_GSO baseline=3.296 Gbit/s fwmark=2.546 Gbit/s drop=22.8% gso_events=5000/5000 total_events=19999
BENCH_MIXED baseline=2.363 Gbit/s fwmark=1.856 Gbit/s drop=21.5% gso_events=10000/10000 total_events=30741
```

The GSO event count is part of the assertion. A mismatch fails the benchmark,
which catches ringbuf/event loss under this stress workload. `total_events`
includes scalar TCP control packets such as SYN, ACK, and FIN, so it is expected
to be higher than the GSO data event count for TCP and mixed cases.
The functional test also verifies that valid metadata matches the actual TUN
packet fingerprint and that crossed UDP/TCP metadata is rejected as a mismatch.

These numbers are PoC-runner numbers. They include ringbuf polling, userspace
event validation, socket setup for short TCP bursts, and the minimal TCP peer's
ACK path. They are useful for regression and order-of-magnitude overhead checks,
but they are not a tuned maximum-throughput result.
