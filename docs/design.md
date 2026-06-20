# TUN FWMark PoC Design

This document describes the current PoC for carrying Linux `skb->mark` across a
TUN userspace boundary.

## Problem

Linux TUN exposes packet bytes to userspace, but it does not expose `skb->mark`
in the native PI header or virtio-net header. Tunneling software that wants to
preserve routing metadata therefore needs another convention for carrying the
mark across:

```text
userspace -> TUN fd -> TUN netdev -> kernel stack
kernel stack -> TUN netdev -> TUN fd -> userspace
```

The read path is harder than the write path. TUN may pass TCP or UDP GSO
super-packets to userspace via `IFF_VNET_HDR`; prepending arbitrary bytes before
the IP header can invalidate protocol, checksum, and GSO assumptions later in
the transmit path.

## Current Design

The PoC uses a PI-mode `IFF_VNET_HDR` TUN device and tc BPF.

### TUN Write Path

Userspace writes:

```text
tun_pi + virtio_net_hdr + be32 fwmark + packet
```

The tc ingress BPF program runs after TUN has consumed `tun_pi` and
`virtio_net_hdr`, so skb data starts with:

```text
be32 fwmark + packet
```

The BPF program:

1. reads the first 4 bytes as a big-endian fwmark;
2. assigns the value to `skb->mark`;
3. removes those 4 bytes with `bpf_skb_adjust_room()`;
4. records a tiny sample in a BPF array map for functional-test visibility.

After this, the kernel sees a clean packet with the desired `skb->mark`.

### TUN Read Path

The read path carries `skb->mark` in an MPLS label stack entry:

```text
tun_pi + virtio_net_hdr + be32 fwmark + IP packet
```

The MPLS header is pushed by the kernel route encapsulation path, not by eBPF:

```text
ip route ... encap mpls ... dev tunfw0
```

After the MPLS LSE exists, tc egress BPF overwrites its top 32 bits with
`skb->mark`. Userspace reads the TUN fd, parses the virtio-net header, reads the
4-byte LSE as the mark, and then parses the inner IPv4 packet after the LSE.

## Why Kernel MPLS Push

Pure eBPF insertion of an MPLS shim is not a correct read-path design here:

- tc BPF cannot directly write `__sk_buff.protocol`;
- `bpf_skb_change_proto()` only supports IPv4/IPv6 translation;
- if eBPF prepends four bytes while the skb still advertises IPv4, later GSO
  validation still parses skb data as an IP header and sees the prepended mark.

Using the kernel MPLS path lets the kernel update skb protocol and related
metadata consistently. eBPF only changes bytes that already belong to the MPLS
LSE.

## GSO Behavior

On the current TUN device, MPLS read-path packets are software-segmented before
userspace reads them. The relevant limitation is that TUN does not advertise
MPLS TSO/USO capabilities through `dev->mpls_features`, so after MPLS
encapsulation the stack cannot hand an MPLS GSO super-packet to this TUN device.

As a result:

- the baseline side can still read UDP/TCP GSO super-packets from TUN;
- the fwmark/MPLS side reads scalar MPLS segments;
- the benchmark compares a scalar MPLS fwmark path against a GSO baseline.

This is still useful for measuring the practical cost of this PoC shape, but it
does not prove MPLS preserves TUN GSO super-packets.

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

## Run

```sh
make test
make bench
```

`make bench` runs the route-encap MPLS mode.
