# TUN fwmark PoC

This repository keeps two small PoCs for passing Linux `skb->mark` across a
TUN device boundary.

TUN does not expose `skb->mark` through its native PI header. The scripts keep
the TUN device in PI mode and use tc eBPF to add or remove a 4-byte big-endian
fwmark prefix immediately before the IPv4 packet.

## PoCs

- Ingress, user writes to TUN: userspace writes `tun_pi + mark + ipv4_packet`.
  A tc ingress classifier reads the first 4 bytes after the PI header, assigns
  the value to `skb->mark`, strips those 4 bytes, and lets a clean IPv4 packet
  continue through the network stack.
- Egress, user reads from TUN: a marked socket sends a packet routed to the TUN
  device. A tc egress classifier prepends the packet's `skb->mark`, so userspace
  reads `tun_pi + mark + ipv4_packet`.

## Run

```sh
./run_poc.sh
```

The script uses temporary network namespaces and will re-exec through `sudo`
when needed.

Expected result:

```text
PASS: ingress imports fwmark from a 4-byte prefix; egress exports skb mark as a 4-byte prefix
```

## Notes

- PI mode is intentional. With `IFF_NO_PI`, TUN validates the first byte as the
  IP version, so a raw 4-byte mark prefix is rejected before tc can fix it.
- `SO_RCVMARK` does not work on a TUN file descriptor because it is not a socket.
- The eBPF programs use `BPF_ADJ_ROOM_MAC`; for TUN skbs this adjusts the data
  location that tc sees before the IP header.
