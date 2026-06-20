// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("classifier")
int tun_egress_mark_prepend(struct __sk_buff *skb)
{
	__u32 mark = bpf_htonl(skb->mark);
	int ret;

	ret = bpf_skb_adjust_room(skb, (int)sizeof(mark), BPF_ADJ_ROOM_MAC, 0);
	if (ret < 0)
		return TC_ACT_SHOT;

	ret = bpf_skb_store_bytes(skb, 0, &mark, sizeof(mark), 0);
	if (ret < 0)
		return TC_ACT_SHOT;

	return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
