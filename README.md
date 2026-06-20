# TUN fwmark PoC

This repository contains one Linux-only PoC for carrying `skb->mark` across a
TUN userspace boundary.

The PoC uses a PI-mode `IFF_VNET_HDR` TUN device:

- **TUN Write Path**: userspace writes `tun_pi + virtio_net_hdr + mark + packet`.
  A tc ingress BPF program reads the 4-byte big-endian mark, assigns it to
  `skb->mark`, strips the mark bytes, and lets the clean packet enter the kernel
  stack.
- **TUN Read Path**: the PoC installs an `ip route ... encap mpls ...` route for
  the test peer. The kernel pushes an MPLS label stack entry, then tc egress BPF
  overwrites the top 32-bit MPLS LSE with `skb->mark`. Userspace reads PI +
  virtio-net header + MPLS LSE + IP packet from the TUN fd and recovers the mark
  from the LSE.

This avoids the failed pure-BPF prepend design. eBPF alone cannot set
`skb->protocol` to `ETH_P_MPLS_UC`, so MPLS push is done by the kernel route
encap path and eBPF only rewrites the existing LSE.

## Run

```sh
make test
```

The test requires `sudo -n` for TUN, tc BPF, MPLS configuration, and `SO_MARK`.
There is also a Go implementation of the same PoC:

```sh
make test-go
```

Expected output:

```text
WRITE_PATH: imported mark=0x00000042 ...
WRITE_PATH_UDP_GSO: imported mark=0x00000042 ... gso_size=1200
READ_PATH_MPLS_UDP_SCALAR: mark=0x00000043 ...
READ_PATH_MPLS_ZERO_MARK: mark=0x00000000 ...
READ_PATH_MPLS_UDP_SEGMENTS: mark=0x00000042 ...
READ_PATH_MPLS_TCP_SEGMENTS: mark=0x00000042 ...
PASS: TUN write path imports fwmark; TUN read path exports fwmark in an MPLS shim after route encap; MPLS packets are read as scalar segments on this TUN device
```

For a route-encap read-path baseline comparison:

```sh
make bench
make bench-go
```

The benchmark runs each case in a fresh network namespace:

- UDP GSO super-packets;
- TCP GSO burst packets from a minimal userspace TCP peer;
- mixed traffic: UDP scalar, UDP GSO, and TCP GSO per iteration.

On the development host, 2000 iterations produced:

```text
BENCH_UDP_GSO baseline=2.713 Gbit/s fwmark=2.258 Gbit/s drop=16.8% segments=2000/2000
BENCH_TCP_GSO baseline=14.491 Gbit/s fwmark=4.349 Gbit/s drop=70.0% bursts=2000/2000 segments=2000
BENCH_MIXED baseline=4.025 Gbit/s fwmark=2.668 Gbit/s drop=33.7% bursts=4000/4000 segments=6000
```

After adding the Go implementation, the same host produced this C/Go comparison
with 2000 iterations:

```text
C:
BENCH_UDP_GSO baseline=2.713 Gbit/s fwmark=2.258 Gbit/s drop=16.8% segments=2000/2000
BENCH_TCP_GSO baseline=14.491 Gbit/s fwmark=4.349 Gbit/s drop=70.0% bursts=2000/2000 segments=2000
BENCH_MIXED baseline=4.025 Gbit/s fwmark=2.668 Gbit/s drop=33.7% bursts=4000/4000 segments=6000

Go:
BENCH_UDP_GSO baseline=13.802 Gbit/s fwmark=6.693 Gbit/s drop=51.5% segments=2000/2000
BENCH_TCP_GSO baseline=13.508 Gbit/s fwmark=3.611 Gbit/s drop=73.3% bursts=2000/2000 segments=2000
BENCH_MIXED baseline=10.053 Gbit/s fwmark=3.875 Gbit/s drop=61.5% bursts=4000/4000 segments=6000
```

The Go version uses `github.com/cilium/ebpf`, `github.com/vishvananda/netlink`,
and `golang.org/x/sys/unix` instead of cgo/libbpf wrappers or shelling out to
`ip`/`tc` for steady-state setup. Both C and Go TCP benchmarks use one TCP
connection per benchmark case and send many data bursts over it; the earlier
per-burst connection shape mostly measured `tcp_connect_init()`/SYN setup and
userspace handshake overhead rather than steady-state TCP GSO transmission. The
Go benchmark hot path also reuses UDP sockets, control messages, payloads, and
TUN read buffers.

On this TUN device, MPLS packets are software-segmented before userspace reads
them because TUN does not advertise MPLS TSO/USO features through
`dev->mpls_features`. The fwmark result is therefore a scalar MPLS read-path
comparison against a GSO baseline, not proof that MPLS preserves TUN GSO
super-packets.

## Files

- `bpf/tun_fwmark.bpf.c`: tc ingress/write-path mark import and tc
  egress/read-path MPLS LSE rewrite.
- `scripts/tun_fwmark_poc.c`: creates a temporary PI+VNET TUN, attaches the BPF
  programs, sends test traffic, reads TUN packets, and verifies fwmark handling.
- `scripts/tun_fwmark_poc.go`: Go implementation of the same functional and
  benchmark flow, using pure Go eBPF/netlink/unix libraries.
- `docs/design.md`: technical design notes, rejected alternatives, and
  limitations.

## Notes

- PI mode is intentional. The write path places a raw 4-byte mark after the
  virtio header, and tc ingress strips it before the packet enters the stack.
- `SO_RCVMARK` is not available on a TUN file descriptor because the fd is a
  character device from userspace's point of view.
