// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define DIR_WRITE_PATH 1
#define DIR_READ_PATH 2

struct fwmark_event {
	__u64 tstamp_ns;
	__u32 direction;
	__u32 ifindex;
	__u32 queue_mapping;
	__u32 ip_saddr;
	__u32 ip_daddr;
	__u32 ip_id;
	__u32 mark;
	__u32 len;
	__u32 hash;
	__u32 gso_size;
	__u32 gso_segs;
	__u32 protocol;
	__u32 ip_proto;
	__u32 sport;
	__u32 dport;
	__u32 l4_cookie;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} fwmark_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} fwmark_event_drops SEC(".maps");

static __always_inline void emit_event(struct __sk_buff *skb, __u32 direction,
				       __u32 mark)
{
	struct fwmark_event *event;
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	__u32 ip_saddr = 0;
	__u32 ip_daddr = 0;
	__u32 ip_id = 0;
	__u32 l4_cookie = 0;
	__u8 ip_proto = 0;
	__u16 sport = 0;
	__u16 dport = 0;

	event = bpf_ringbuf_reserve(&fwmark_events, sizeof(*event), 0);
	if (!event) {
		__u32 key = 0;
		__u64 *drops = bpf_map_lookup_elem(&fwmark_event_drops, &key);

		if (drops)
			(*drops)++;
		return;
	}

	if (data + 20 <= data_end && (((__u8 *)data)[0] >> 4) == 4) {
		__u8 ihl = (((__u8 *)data)[0] & 0x0f) * 4;
		void *l4 = data + ihl;

		ip_id = bpf_ntohs(*(__u16 *)(data + 4));
		ip_saddr = *(__u32 *)(data + 12);
		ip_daddr = *(__u32 *)(data + 16);
		ip_proto = ((__u8 *)data)[9];
		if (ihl >= 20 && l4 + 4 <= data_end &&
		    (ip_proto == IPPROTO_TCP || ip_proto == IPPROTO_UDP)) {
			sport = bpf_ntohs(*(__u16 *)l4);
			dport = bpf_ntohs(*(__u16 *)(l4 + 2));
			if (ip_proto == IPPROTO_TCP && l4 + 8 <= data_end)
				l4_cookie = bpf_ntohl(*(__u32 *)(l4 + 4));
			else if (ip_proto == IPPROTO_UDP && l4 + 6 <= data_end)
				l4_cookie = bpf_ntohs(*(__u16 *)(l4 + 4));
		}
	}

	event->tstamp_ns = bpf_ktime_get_ns();
	event->direction = direction;
	event->ifindex = skb->ifindex;
	event->queue_mapping = skb->queue_mapping;
	event->ip_saddr = ip_saddr;
	event->ip_daddr = ip_daddr;
	event->ip_id = ip_id;
	event->mark = mark;
	event->len = skb->len;
	event->hash = skb->hash;
	event->gso_size = skb->gso_size;
	event->gso_segs = skb->gso_segs;
	event->protocol = skb->protocol;
	event->ip_proto = ip_proto;
	event->sport = sport;
	event->dport = dport;
	event->l4_cookie = l4_cookie;

	bpf_ringbuf_submit(event, 0);
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

	emit_event(skb, DIR_WRITE_PATH, mark);
	return TC_ACT_OK;
}

SEC("classifier")
int tun_read_path_mark_event(struct __sk_buff *skb)
{
	emit_event(skb, DIR_READ_PATH, skb->mark);
	return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
