#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
	exec sudo -- "$0" "$@"
fi

cd "$(dirname "$0")"

cleanup() {
	ip netns del tunmarkin 2>/dev/null || true
	ip netns del tunmarkout 2>/dev/null || true
}
trap cleanup EXIT

make
cleanup

echo "[1/3] Proving IFF_NO_PI rejects a raw 4-byte prefix"
echo "[2/3] Attaching tc ingress eBPF to PI-mode TUN"
echo "[3/3] Verifying fwmark and stripped IPv4 packet at nft prerouting"
ip netns add tunmarkin
ip -n tunmarkin link set lo up
ip netns exec tunmarkin ./scripts/tun_ingress_test.py \
	--dev tunin0 \
	--obj bpf/tun_ingress_mark_strip.bpf.o

echo "[4/5] Reading native PI-mode TUN packets without fwmark"
ip netns del tunmarkin
ip netns add tunmarkout
ip -n tunmarkout link set lo up
ip netns exec tunmarkout ./scripts/tun_egress_test.py --dev tunout0

echo "[5/5] Exporting skb mark to PI-mode TUN read path with tc egress"
ip netns del tunmarkout
ip netns add tunmarkout
ip -n tunmarkout link set lo up
ip netns exec tunmarkout ./scripts/tun_egress_test.py \
	--dev tunout0 \
	--obj bpf/tun_egress_mark_prepend.bpf.o

echo "PASS: ingress imports fwmark from a 4-byte prefix; egress exports skb mark as a 4-byte prefix"
