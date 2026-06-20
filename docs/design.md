# TUN FWMark PoC Design

This document describes the current PoC for carrying Linux `skb->mark` across a
TUN userspace boundary, the kernel constraints behind the design, and the next
viable optimization directions.

## Goals And Constraints

Linux TUN exposes packet bytes to userspace, but it does not expose `skb->mark`
in the native PI header or virtio-net header. Tunneling software that wants to
preserve policy-routing metadata needs another convention for carrying the mark
across both directions:

```text
userspace -> TUN fd -> TUN netdev -> kernel stack
kernel stack -> TUN netdev -> TUN fd -> userspace
```

The write path is relatively easy because userspace controls the bytes written
to the TUN fd. The read path is harder because the kernel may deliver TCP or UDP
GSO super-packets via `IFF_VNET_HDR`; arbitrary header insertion before the IP
header can break protocol, checksum, and GSO assumptions later in the transmit
path.

The current PoC intentionally stays Linux-only and requires `CAP_NET_ADMIN`,
TUN/TAP, tc BPF, and MPLS route encapsulation support.

## Current Implementation

The PoC uses a PI-mode `IFF_VNET_HDR` TUN device and two tc BPF classifiers.

### Write Path: Userspace To Kernel

Userspace writes:

```text
tun_pi + virtio_net_hdr + be32 fwmark + packet
```

TUN consumes `tun_pi` and `virtio_net_hdr` before tc ingress, so the ingress BPF
program sees:

```text
be32 fwmark + packet
```

The ingress program:

1. reads the first four bytes as a big-endian mark;
2. assigns the value to `skb->mark`;
3. removes those four bytes with `bpf_skb_adjust_room()`;
4. records a small sample in a BPF array map for functional-test visibility.

After ingress, the kernel stack sees a clean packet with the desired
`skb->mark`.

### Read Path: Kernel To Userspace

The read path carries `skb->mark` in an MPLS label stack entry:

```text
tun_pi + virtio_net_hdr + be32 fwmark + IP packet
```

The MPLS header is pushed by the kernel routing path:

```text
ip route ... encap mpls ... dev tunfw0
```

After the MPLS LSE exists, tc egress BPF overwrites its top 32 bits with
`skb->mark`. Userspace reads the TUN fd, parses the virtio-net header, reads the
4-byte LSE as the mark, then parses the inner IPv4 packet after the LSE.

## Why MPLS Must Be Pushed By The Kernel

Pure eBPF insertion of an MPLS shim is not a correct read-path design here:

- tc BPF cannot directly write `__sk_buff.protocol`;
- `bpf_skb_change_proto()` only supports IPv4/IPv6 translation;
- if eBPF prepends four bytes while the skb still advertises IPv4, later GSO
  validation still parses skb data as an IP header and sees the prepended mark.

Using `ip route ... encap mpls ...` lets the kernel update skb protocol and
related metadata consistently. eBPF only changes bytes that already belong to
the MPLS LSE.

## Kernel GSO Constraint

The current read-path performance limit is in the kernel transmit feature
selection for MPLS packets.

Relevant kernel behavior:

- `netif_skb_features()` reaches `net_mpls_features()` in `net/core/dev.c`;
- when the packet protocol is MPLS, features are masked with
  `skb->dev->mpls_features`;
- TUN exposes TCP/UDP GSO through `TUNSETOFFLOAD`, but it does not expose
  equivalent MPLS TSO/USO features through `dev->mpls_features`;
- `validate_xmit_skb()` then calls `skb_gso_segment()` and software-segments the
  MPLS skb before it reaches the TUN fd.

TUN fd read behavior then amplifies this:

- `tun_ring_recv()` consumes one skb from the TUN file ring;
- `tun_do_read()` copies that one skb to userspace;
- once one GSO skb becomes N scalar MPLS skbs, userspace needs N reads.

So the current read-path comparison is:

```text
baseline:    one TCP/UDP GSO skb -> one TUN read
MPLS mark:   one TCP/UDP GSO skb -> software segmentation -> many TUN reads
```

This means the MPLS design is functionally valid, but it is not a GSO-preserving
read-path design on current TUN.

## Benchmark Method

The benchmark has C and Go implementations. Both test:

- UDP GSO;
- TCP GSO data bursts;
- mixed traffic containing UDP scalar, UDP GSO, and TCP GSO.

The TCP benchmark uses one TCP connection per benchmark case and sends many data
bursts over that connection. This keeps the measured loop focused on
`tcp_write_xmit()` and TUN read-path behavior.

Two benchmark artifacts were fixed:

- Per-burst TCP connection setup was removed. Creating a fresh TCP socket and
  synthetic handshake for every burst mostly measured `tcp_connect_init()`, SYN
  transmission, and userspace handshake emulation.
- Per-segment ACKs on the MPLS TCP path were removed. The synthetic peer now
  reads all scalar MPLS segments for one burst and writes one cumulative ACK.
  ACKing every scalar segment added one userspace TUN write per segment and
  overstated the TCP-specific cost.

After these corrections, Go UDP fwmark drop and Go TCP fwmark drop are similar.
That is strong evidence that the remaining drop is not TCP-specific; it is the
generic cost of MPLS scalar reads after GSO loss.

## Rejected Alternatives

### Direct eBPF Prepend On Read Path

Prepending bytes at tc egress changes where the IP header appears in skb data.
In the TCP tests this caused pathological behavior: queued data advanced through
`ICSK_TIME_PROBE0` and `tcp_write_wakeup(LINUX_MIB_TCPWINPROBE)` roughly once
per 200 ms. The current PoC does not keep a direct-prepend read-path mode.

### Tail Append

Tail metadata avoids moving the IP header, but the BPF helper needed for tail
growth is `bpf_skb_change_tail()`. The kernel implements that helper as a
slow-path operation that linearizes, unclones, and drops offload state. It also
creates packet length and checksum ambiguity unless userspace and kernel share
an additional out-of-band convention.

### `tc action mpls push`

`tc action mpls push protocol mpls_uc label ...` can also create MPLS headers,
but it is not part of the current PoC. The retained path is route encap because
the route owns the read-path forwarding decision and the BPF program only needs
to rewrite an existing LSE.

### Ringbuffer Read Path

A BPF ringbuffer can export marks out of band, but the old version was removed
from this PoC because the current MPLS design carries the mark in packet bytes.
Side-channel metadata remains a future optimization direction, not part of the
current implementation.

## Future Optimization Directions

### Preferred: Side-Channel Metadata

The best non-kernel-patch direction is to avoid modifying read-path packet bytes:

1. tc egress BPF records `skb->mark` into an ordered side channel;
2. userspace reads the original TUN packet, preserving IP/TCP/UDP GSO;
3. userspace matches the side-channel mark to the TUN packet and carries it as
   packet metadata.

This is closest to what an overlay such as Nylon should eventually want: mark as
metadata, not as a fake packet header.

Open risks:

- proving ordering between TUN fd reads and BPF events;
- handling event loss or ring/map overflow;
- supporting multi-queue TUN and multiple readers;
- matching packets robustly under GRO/GSO, retransmission, and non-IP traffic.

The recommended next experiment is a single-queue, single-reader side-channel
prototype for IPv4 TCP/UDP GSO.

### Experimental: Higher TUN MTU

Increasing TUN MTU can reduce the number of scalar MPLS skbs after software
segmentation. This may improve the MPLS in-band path without kernel patches.

Risks:

- userspace overlay may receive packets larger than the real outer path MTU;
- the overlay must segment correctly later, or it may cause fragmentation/PMTU
  failures;
- benchmarks must dynamically drain scalar segments instead of assuming fixed
  segment counts.

This should be treated as an experiment or fallback, not as the primary design.

### Not Viable: `readv()` Batching

Linux TUN supports `readv()`/`writev()` as scatter/gather I/O, but current
upstream TUN does not use `readv()` to return multiple packets in one syscall.
The read path is still:

```text
tun_chr_read_iter()
  -> tun_do_read()
    -> tun_ring_recv()
      -> ptr_ring_consume()   // one skb
```

`tun_do_read()` then copies that single skb into the provided `iov_iter`. Multiple
iovecs can split one packet across buffers, but they do not drain multiple TUN
packets.

`recvmmsg()` is not a practical replacement either: the userspace TUN fd is a
character device fd, not a socket fd. Public discussions about reducing TUN
syscall overhead point to the same gap. There was an RFC patch for an
`IFF_MULTI_READ` flag that would allow one read to return multiple full packets,
but that interface is not part of the current upstream TUN ABI.

### Fallback: Keep MPLS In-Band

The current MPLS in-band path remains useful for functional validation, debugging
and low-throughput cases. It is simple and easy to inspect, but it should not be
treated as the high-performance read-path design.

## Running The PoC

```sh
make test
make test-go
make bench
make bench-go
```

`make test` and `make bench` run the C implementation. `make test-go` and
`make bench-go` run the pure Go implementation.
