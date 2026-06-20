// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("classifier")
int tun_ingress_mark_strip(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	__u32 mark_be;
	int ret;

	if (data + sizeof(mark_be) > data_end)
		return TC_ACT_SHOT;

	__builtin_memcpy(&mark_be, data, sizeof(mark_be));
	skb->mark = bpf_ntohl(mark_be);

	ret = bpf_skb_adjust_room(skb, -(int)sizeof(mark_be),
				  BPF_ADJ_ROOM_MAC, 0);
	if (ret < 0)
		return TC_ACT_SHOT;

	return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
