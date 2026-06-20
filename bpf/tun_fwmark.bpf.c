// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct fwmark_sample {
	__u32 seen;
	__u32 mark;
	__u32 len;
	__u32 gso_size;
	__u32 gso_segs;
	__u32 ip_proto;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 2);
	__type(key, __u32);
	__type(value, struct fwmark_sample);
} fwmark_samples SEC(".maps");

static __always_inline void record_write_sample(struct __sk_buff *skb,
						__u32 mark)
{
	struct fwmark_sample sample = {};
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	__u32 key = skb->gso_size ? 1 : 0;

	if (data + 20 <= data_end && (((__u8 *)data)[0] >> 4) == 4)
		sample.ip_proto = ((__u8 *)data)[9];

	sample.seen = 1;
	sample.mark = mark;
	sample.len = skb->len;
	sample.gso_size = skb->gso_size;
	sample.gso_segs = skb->gso_segs;
	bpf_map_update_elem(&fwmark_samples, &key, &sample, BPF_ANY);
}

SEC("classifier")
int tun_write_path_mark_strip(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	__u32 mark;
	int ret;

	if (data + sizeof(mark) > data_end)
		return TC_ACT_SHOT;

	mark = bpf_ntohl(*(__u32 *)data);
	skb->mark = mark;

	ret = bpf_skb_adjust_room(skb, -(int)sizeof(mark), BPF_ADJ_ROOM_MAC,
				  BPF_F_ADJ_ROOM_FIXED_GSO |
				  BPF_F_ADJ_ROOM_NO_CSUM_RESET);
	if (ret < 0)
		return TC_ACT_SHOT;

	record_write_sample(skb, mark);
	return TC_ACT_OK;
}

static __always_inline int rewrite_top_mpls_lse_with_mark(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	__u32 mark = bpf_htonl(skb->mark);

	if (data + sizeof(mark) > data_end)
		return TC_ACT_SHOT;

	*(__u32 *)data = mark;
	return TC_ACT_OK;
}

SEC("classifier")
int tun_read_path_mpls_mark(struct __sk_buff *skb)
{
	return rewrite_top_mpls_lse_with_mark(skb);
}

char _license[] SEC("license") = "GPL";
