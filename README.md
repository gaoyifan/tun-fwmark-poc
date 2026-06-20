# TUN fwmark PoC

This repository contains one Linux-only PoC for carrying `skb->mark` across a
TUN userspace boundary without breaking TUN GSO/GRO behavior.

The PoC uses a PI-mode `IFF_VNET_HDR` TUN device:

- **TUN Write Path**: userspace writes `tun_pi + virtio_net_hdr + mark + packet`.
  A tc ingress BPF program reads the 4-byte big-endian mark, assigns it to
  `skb->mark`, strips the mark bytes, and lets the clean packet enter the kernel
  stack.
- **TUN Read Path**: tc egress BPF does not modify packet bytes. It emits one
  ringbuf metadata event per skb/super-packet containing `skb->mark`, `len`,
  `gso_size`, `gso_segs`, and `queue_mapping`. Userspace reads the normal TUN
  packet and consumes the matching metadata event out of band. The intended
  matching model is FIFO per TUN queue.

This avoids the failed designs:

- prepending mark bytes on tc egress can break TCP/GSO packets because it changes
  protocol header offsets before TUN serializes the virtio header;
- appending mark bytes with `bpf_skb_change_tail()` is also unsuitable because
  that helper linearizes the skb and drops offload state.

## Run

```sh
make test
```

The test requires `sudo -n` for TUN, tc BPF, and `SO_MARK`.

Expected output:

```text
WRITE_PATH: imported mark=0x00000042 ...
WRITE_PATH_UDP_GSO: imported mark=0x00000042 ... gso_size=1200
READ_PATH_UDP_SCALAR: event mark=0x00000043 ...
READ_PATH_ZERO_MARK: event mark=0x00000000 ...
READ_PATH_UDP: event mark=0x00000042 ... gso_size=1200 gso_segs=3
READ_PATH_TCP: event mark=0x00000042 ... gso_size=1460 gso_segs=5
PASS: TUN write path imports fwmark; TUN read path exports fwmark out-of-band while preserving UDP and TCP GSO super-packets
```

For a read-path baseline comparison:

```sh
make bench
```

The benchmark runs each case in a fresh network namespace:

- UDP GSO super-packets;
- TCP GSO burst packets from a minimal userspace TCP peer;
- mixed traffic: UDP scalar, UDP GSO, and TCP GSO per iteration.

On the development host, 5000 iterations produced:

```text
BENCH_UDP_GSO baseline=2.648 Gbit/s fwmark=2.183 Gbit/s drop=17.5% events=5000/5000
BENCH_TCP_GSO baseline=3.301 Gbit/s fwmark=2.703 Gbit/s drop=18.1% gso_events=5000/5000 total_events=19999
BENCH_MIXED baseline=2.430 Gbit/s fwmark=1.977 Gbit/s drop=18.6% gso_events=10000/10000 total_events=30445
```

This measures the side-channel cost in the PoC runner, including ringbuf
polling, userspace validation, and TCP control-packet metadata events. It is
intended as a regression/stress check, not a tuned maximum-throughput benchmark.

## Files

- `bpf/tun_fwmark.bpf.c`: tc ingress/write-path mark import and tc
  egress/read-path metadata export.
- `scripts/tun_fwmark_poc.c`: creates a temporary PI+VNET TUN, attaches the BPF
  programs, sends test traffic, reads TUN packets, and verifies ringbuf events.
- `docs/design.md`: technical design notes, rejected alternatives, and
  limitations.

## Notes

- PI mode is intentional. With `IFF_NO_PI`, TUN validates the first byte after
  the virtio header as an IP version, so a raw 4-byte mark prefix can be rejected
  before tc ingress gets a chance to strip it.
- `SO_RCVMARK` is not available on a TUN file descriptor because the fd is a
  character device from userspace's point of view.
- The read-path side channel exports one mark per skb. For a GSO super-packet
  that is the correct granularity: the whole skb has one `skb->mark`.
- The event includes L4 protocol and ports so userspace can distinguish real
  data events from control traffic such as ICMP errors, especially for mark `0`.
