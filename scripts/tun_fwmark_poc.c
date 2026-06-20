// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_tun.h>
#include <linux/udp.h>
#include <linux/virtio_net.h>
#include <netinet/in.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#ifndef SOL_UDP
#define SOL_UDP 17
#endif

#define DEV_NAME "tunfw0"
#define BPF_OBJ "bpf/tun_fwmark.bpf.o"
#define EXPECTED_MARK 0x00000042u
#define SECOND_MARK 0x00000043u
#define GSO_SIZE 1200
#define TCP_SERVER_SEQ 0xabc00000u
#define DIR_WRITE_PATH 1
#define DIR_READ_PATH 2

struct fwmark_event {
	uint64_t tstamp_ns;
	uint32_t direction;
	uint32_t ifindex;
	uint32_t queue_mapping;
	uint32_t ip_saddr;
	uint32_t ip_daddr;
	uint32_t ip_id;
	uint32_t mark;
	uint32_t len;
	uint32_t hash;
	uint32_t gso_size;
	uint32_t gso_segs;
	uint32_t protocol;
	uint32_t ip_proto;
	uint32_t sport;
	uint32_t dport;
	uint32_t l4_cookie;
};

struct packet_meta {
	uint32_t len;
	uint32_t gso_size;
	uint32_t ip_proto;
	uint32_t sport;
	uint32_t dport;
	uint32_t ip_saddr;
	uint32_t ip_daddr;
	uint32_t ip_id;
	uint32_t l4_cookie;
};

struct event_state {
	bool write_seen;
	bool write_gso_seen;
	bool scalar_seen;
	bool zero_seen;
	unsigned int total_read_events;
	unsigned int read_events;
	struct fwmark_event write_event;
	struct fwmark_event write_gso_event;
	struct fwmark_event scalar_event;
	struct fwmark_event zero_event;
	struct fwmark_event udp_read_event;
	struct fwmark_event tcp_read_event;
};

struct tc_attachment {
	struct bpf_tc_hook hook;
	struct bpf_tc_opts opts;
};

static int enter_new_netns(void);

static void run_cmd_quiet(const char *cmd)
{
	(void)system(cmd);
}

static int run_cmd(const char *cmd)
{
	int ret = system(cmd);

	if (ret != 0)
		fprintf(stderr, "command failed: %s\n", cmd);
	return ret;
}

static uint16_t csum16(const void *data, size_t len)
{
	const uint8_t *p = data;
	uint32_t sum = 0;

	while (len > 1) {
		sum += ((uint16_t)p[0] << 8) | p[1];
		p += 2;
		len -= 2;
	}
	if (len)
		sum += (uint16_t)p[0] << 8;
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	return (uint16_t)~sum;
}

static int parse_tun_packet_meta(const uint8_t *buf, ssize_t len,
				 struct packet_meta *meta)
{
	const struct virtio_net_hdr *hdr = (const struct virtio_net_hdr *)(buf + 4);
	const uint8_t *ip = buf + 4 + sizeof(*hdr);
	const uint8_t *l4;
	uint8_t ihl;

	if (!meta)
		return 0;
	memset(meta, 0, sizeof(*meta));
	if (len < 4 + (ssize_t)sizeof(*hdr) + 20)
		return -1;
	if ((ip[0] >> 4) != 4)
		return -1;

	ihl = (ip[0] & 0x0f) * 4;
	if (ihl < 20 || len < 4 + (ssize_t)sizeof(*hdr) + ihl)
		return -1;
	l4 = ip + ihl;

	meta->len = (uint32_t)(len - 4 - sizeof(*hdr));
	meta->gso_size = hdr->gso_size;
	meta->ip_proto = ip[9];
	meta->ip_id = ((uint16_t)ip[4] << 8) | ip[5];
	memcpy(&meta->ip_saddr, ip + 12, sizeof(meta->ip_saddr));
	memcpy(&meta->ip_daddr, ip + 16, sizeof(meta->ip_daddr));

	if ((meta->ip_proto == IPPROTO_TCP || meta->ip_proto == IPPROTO_UDP) &&
	    len >= 4 + (ssize_t)sizeof(*hdr) + ihl + 4) {
		meta->sport = ((uint16_t)l4[0] << 8) | l4[1];
		meta->dport = ((uint16_t)l4[2] << 8) | l4[3];
		if (meta->ip_proto == IPPROTO_TCP &&
		    len >= 4 + (ssize_t)sizeof(*hdr) + ihl + 8) {
			uint32_t seq;

			memcpy(&seq, l4 + 4, sizeof(seq));
			meta->l4_cookie = ntohl(seq);
		} else if (meta->ip_proto == IPPROTO_UDP &&
			 len >= 4 + (ssize_t)sizeof(*hdr) + ihl + 6)
			meta->l4_cookie = ((uint16_t)l4[4] << 8) | l4[5];
	}

	return 0;
}

static bool event_matches_packet(const struct fwmark_event *event,
				 const struct packet_meta *meta)
{
	return event->len == meta->len &&
	       event->gso_size == meta->gso_size &&
	       event->ip_proto == meta->ip_proto &&
	       event->sport == meta->sport &&
	       event->dport == meta->dport &&
	       event->ip_saddr == meta->ip_saddr &&
	       event->ip_daddr == meta->ip_daddr &&
	       event->ip_id == meta->ip_id &&
	       event->l4_cookie == meta->l4_cookie;
}

static int open_vnet_tun(const char *name)
{
	struct ifreq ifr = { 0 };
	int fd, offloads, vnet_hdr_len;

	fd = open("/dev/net/tun", O_RDWR | O_CLOEXEC | O_NONBLOCK);
	if (fd < 0) {
		perror("open /dev/net/tun");
		return -1;
	}

	strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
	ifr.ifr_flags = IFF_TUN | IFF_VNET_HDR;
	if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
		perror("TUNSETIFF");
		close(fd);
		return -1;
	}

	vnet_hdr_len = sizeof(struct virtio_net_hdr);
	if (ioctl(fd, TUNSETVNETHDRSZ, &vnet_hdr_len) < 0) {
		perror("TUNSETVNETHDRSZ");
		close(fd);
		return -1;
	}

	offloads = TUN_F_CSUM | TUN_F_TSO4 | TUN_F_TSO6 | TUN_F_USO4 | TUN_F_USO6;
	if (ioctl(fd, TUNSETOFFLOAD, offloads) < 0) {
		offloads = TUN_F_CSUM | TUN_F_TSO4 | TUN_F_TSO6;
		if (ioctl(fd, TUNSETOFFLOAD, offloads) < 0) {
			perror("TUNSETOFFLOAD");
			close(fd);
			return -1;
		}
	}

	return fd;
}

static int configure_tun(const char *name, const char *addr)
{
	char cmd[256];

	snprintf(cmd, sizeof(cmd), "ip addr add %s dev %s", addr, name);
	if (run_cmd(cmd))
		return -1;
	snprintf(cmd, sizeof(cmd), "ip link set dev %s mtu 1500 up", name);
	if (run_cmd(cmd))
		return -1;
	return 0;
}

static int get_ifindex(const char *dev)
{
	struct ifreq ifr = { 0 };
	int fd, ifindex;

	fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0) {
		perror("socket ifindex");
		return -1;
	}
	strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);
	if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
		perror("SIOCGIFINDEX");
		close(fd);
		return -1;
	}
	ifindex = ifr.ifr_ifindex;
	close(fd);
	return ifindex;
}

static int attach_one_tc(int ifindex, enum bpf_tc_attach_point attach_point,
			 int prog_fd, struct tc_attachment *attach)
{
	int err;

	memset(attach, 0, sizeof(*attach));
	attach->hook.sz = sizeof(attach->hook);
	attach->hook.ifindex = ifindex;
	attach->hook.attach_point = attach_point;

	attach->opts.sz = sizeof(attach->opts);
	attach->opts.prog_fd = prog_fd;
	attach->opts.handle = attach_point == BPF_TC_INGRESS ? 1 : 2;
	attach->opts.priority = 1;
	err = bpf_tc_attach(&attach->hook, &attach->opts);
	if (err) {
		fprintf(stderr, "bpf_tc_attach failed: %d\n", err);
		return -1;
	}

	return 0;
}

static int create_clsact(int ifindex)
{
	struct bpf_tc_hook hook = {
		.sz = sizeof(hook),
		.ifindex = ifindex,
		.attach_point = BPF_TC_INGRESS | BPF_TC_EGRESS,
	};
	int err = bpf_tc_hook_create(&hook);

	if (err && err != -EEXIST) {
		fprintf(stderr, "bpf_tc_hook_create failed: %d\n", err);
		return -1;
	}
	return 0;
}

static int attach_bpf(const char *dev, const char *obj_path,
		      struct bpf_object **obj_out,
		      struct tc_attachment *ingress,
		      struct tc_attachment *egress)
{
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	struct bpf_program *ingress_prog, *egress_prog;
	struct bpf_object *obj;
	int ifindex, err;

	ifindex = get_ifindex(dev);
	if (ifindex < 0)
		return -1;
	if (create_clsact(ifindex))
		return -1;

	obj = bpf_object__open_file(obj_path, &open_opts);
	if (!obj) {
		fprintf(stderr, "failed to open %s\n", obj_path);
		return -1;
	}
	err = bpf_object__load(obj);
	if (err) {
		fprintf(stderr, "failed to load %s: %d\n", obj_path, err);
		goto err_close;
	}

	ingress_prog = bpf_object__find_program_by_name(obj, "tun_write_path_mark_strip");
	egress_prog = bpf_object__find_program_by_name(obj, "tun_read_path_mark_event");
	if (!ingress_prog || !egress_prog) {
		fprintf(stderr, "BPF programs not found\n");
		goto err_close;
	}

	if (attach_one_tc(ifindex, BPF_TC_INGRESS, bpf_program__fd(ingress_prog), ingress))
		goto err_close;
	if (attach_one_tc(ifindex, BPF_TC_EGRESS, bpf_program__fd(egress_prog), egress))
		goto err_detach_ingress;

	*obj_out = obj;
	return 0;

err_detach_ingress:
	bpf_tc_detach(&ingress->hook, &ingress->opts);
	bpf_tc_hook_destroy(&ingress->hook);
err_close:
	bpf_object__close(obj);
	return -1;
}

static int attach_read_bpf(const char *dev, const char *obj_path,
			   struct bpf_object **obj_out,
			   struct tc_attachment *egress)
{
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	struct bpf_program *egress_prog;
	struct bpf_object *obj;
	int ifindex, err;

	ifindex = get_ifindex(dev);
	if (ifindex < 0)
		return -1;
	if (create_clsact(ifindex))
		return -1;

	obj = bpf_object__open_file(obj_path, &open_opts);
	if (!obj) {
		fprintf(stderr, "failed to open %s\n", obj_path);
		return -1;
	}
	err = bpf_object__load(obj);
	if (err) {
		fprintf(stderr, "failed to load %s: %d\n", obj_path, err);
		goto err_close;
	}

	egress_prog = bpf_object__find_program_by_name(obj, "tun_read_path_mark_event");
	if (!egress_prog) {
		fprintf(stderr, "read-path BPF program not found\n");
		goto err_close;
	}

	if (attach_one_tc(ifindex, BPF_TC_EGRESS, bpf_program__fd(egress_prog), egress))
		goto err_close;

	*obj_out = obj;
	return 0;

err_close:
	bpf_object__close(obj);
	return -1;
}

static int attach_egress_prog(const char *dev, const char *obj_path,
			      const char *prog_name, struct bpf_object **obj_out,
			      struct tc_attachment *egress)
{
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	struct bpf_program *prog;
	struct bpf_object *obj;
	int ifindex, err;

	ifindex = get_ifindex(dev);
	if (ifindex < 0)
		return -1;
	if (create_clsact(ifindex))
		return -1;

	obj = bpf_object__open_file(obj_path, &open_opts);
	if (!obj) {
		fprintf(stderr, "failed to open %s\n", obj_path);
		return -1;
	}
	err = bpf_object__load(obj);
	if (err) {
		fprintf(stderr, "failed to load %s: %d\n", obj_path, err);
		goto err_close;
	}

	prog = bpf_object__find_program_by_name(obj, prog_name);
	if (!prog) {
		fprintf(stderr, "BPF program not found: %s\n", prog_name);
		goto err_close;
	}
	if (attach_one_tc(ifindex, BPF_TC_EGRESS, bpf_program__fd(prog), egress))
		goto err_close;

	*obj_out = obj;
	return 0;

err_close:
	bpf_object__close(obj);
	return -1;
}

static uint64_t read_drop_count(struct bpf_object *obj)
{
	struct bpf_map *map = bpf_object__find_map_by_name(obj, "fwmark_event_drops");
	unsigned int nr_cpus;
	uint64_t *values;
	uint64_t total = 0;
	uint32_t key = 0;

	if (!map)
		return UINT64_MAX;
	nr_cpus = libbpf_num_possible_cpus();
	values = calloc(nr_cpus, sizeof(*values));
	if (!values)
		return UINT64_MAX;
	if (bpf_map_lookup_elem(bpf_map__fd(map), &key, values) < 0) {
		free(values);
		return UINT64_MAX;
	}
	for (unsigned int i = 0; i < nr_cpus; i++)
		total += values[i];
	free(values);
	return total;
}

static int assert_no_drops(struct bpf_object *obj)
{
	uint64_t drops = read_drop_count(obj);

	if (drops == UINT64_MAX) {
		fprintf(stderr, "failed to read ringbuf drop counter\n");
		return -1;
	}
	if (drops) {
		fprintf(stderr, "ringbuf metadata drops: %llu\n",
			(unsigned long long)drops);
		return -1;
	}
	return 0;
}

static int handle_event(void *ctx, void *data, size_t len)
{
	struct event_state *state = ctx;
	struct fwmark_event event;

	if (len < sizeof(event))
		return 0;
	memcpy(&event, data, sizeof(event));
	if (event.direction == DIR_READ_PATH)
		state->total_read_events++;

	if (event.direction == DIR_WRITE_PATH && event.mark == EXPECTED_MARK &&
	    event.gso_size == 0 && !state->write_seen) {
		state->write_seen = true;
		state->write_event = event;
	} else if (event.direction == DIR_WRITE_PATH &&
		   event.mark == EXPECTED_MARK && event.gso_size == GSO_SIZE &&
		   event.ip_proto == IPPROTO_UDP && !state->write_gso_seen) {
		state->write_gso_seen = true;
		state->write_gso_event = event;
	} else if (event.direction == DIR_READ_PATH && event.mark == SECOND_MARK &&
		   event.gso_size == 0 && event.ip_proto == IPPROTO_UDP &&
		   event.dport == 5555 && !state->scalar_seen) {
		state->scalar_seen = true;
		state->scalar_event = event;
	} else if (event.direction == DIR_READ_PATH && event.mark == 0 &&
		   event.gso_size == 0 && event.ip_proto == IPPROTO_UDP &&
		   event.dport == 5555 && !state->zero_seen) {
		state->zero_seen = true;
		state->zero_event = event;
	} else if (event.direction == DIR_READ_PATH && event.mark == EXPECTED_MARK &&
		   event.gso_size > 0 && (event.ip_proto == IPPROTO_UDP ||
					  event.ip_proto == IPPROTO_TCP)) {
		if (state->read_events == 0)
			state->udp_read_event = event;
		else if (state->read_events == 1)
			state->tcp_read_event = event;
		state->read_events++;
	}
	return 0;
}

static int poll_until(struct ring_buffer *rb, bool *flag)
{
	for (int i = 0; i < 20 && !*flag; i++)
		ring_buffer__poll(rb, 100);
	return *flag ? 0 : -1;
}

static int poll_until_read_events(struct ring_buffer *rb, struct event_state *state,
				  unsigned int target)
{
	for (int i = 0; i < 20 && state->read_events < target; i++)
		ring_buffer__poll(rb, 100);
	return state->read_events >= target ? 0 : -1;
}

static size_t build_ipv4_udp(uint8_t *out, size_t out_len)
{
	const char payload[] = "tun-fwmark-write-path";
	size_t payload_len = sizeof(payload) - 1;
	size_t total_len = 20 + 8 + payload_len;
	uint8_t *ip = out;
	uint8_t *udp = out + 20;

	if (out_len < total_len)
		return 0;
	memset(out, 0, total_len);

	ip[0] = 0x45;
	ip[2] = (uint8_t)(total_len >> 8);
	ip[3] = (uint8_t)total_len;
	ip[4] = 0x12;
	ip[5] = 0x34;
	ip[8] = 64;
	ip[9] = IPPROTO_UDP;
	inet_pton(AF_INET, "10.99.0.2", ip + 12);
	inet_pton(AF_INET, "10.99.0.1", ip + 16);
	*(uint16_t *)(ip + 10) = htons(csum16(ip, 20));

	*(uint16_t *)(udp + 0) = htons(5555);
	*(uint16_t *)(udp + 2) = htons(5555);
	*(uint16_t *)(udp + 4) = htons(8 + payload_len);
	memcpy(udp + 8, payload, payload_len);
	return total_len;
}

static int write_vnet_packet_to_tun(int tun_fd, const uint8_t *packet,
				    size_t packet_len,
				    const struct virtio_net_hdr *vnet,
				    bool with_mark_prefix)
{
	uint8_t frame[4 + sizeof(struct virtio_net_hdr) + 4 + 4096];
	uint32_t mark_be = htonl(EXPECTED_MARK);
	size_t at = 0;
	size_t mark_len = with_mark_prefix ? sizeof(mark_be) : 0;

	if (packet_len + 4 + sizeof(*vnet) + mark_len > sizeof(frame))
		return -1;

	memset(frame, 0, sizeof(frame));
	frame[2] = ETH_P_IP >> 8;
	frame[3] = ETH_P_IP & 0xff;
	at += 4;
	memcpy(frame + at, vnet, sizeof(*vnet));
	at += sizeof(*vnet);
	if (with_mark_prefix) {
		memcpy(frame + at, &mark_be, sizeof(mark_be));
		at += sizeof(mark_be);
	}
	memcpy(frame + at, packet, packet_len);
	at += packet_len;

	if (write(tun_fd, frame, at) != (ssize_t)at) {
		perror("write TUN packet");
		return -1;
	}
	return 0;
}

static int write_marked_vnet_packet_to_tun(int tun_fd, const uint8_t *packet,
					   size_t packet_len,
					   const struct virtio_net_hdr *vnet)
{
	return write_vnet_packet_to_tun(tun_fd, packet, packet_len, vnet, true);
}

static int write_marked_udp_packet_to_tun(int tun_fd)
{
	uint8_t ip_packet[256];
	struct virtio_net_hdr vnet = { 0 };
	size_t ip_len = build_ipv4_udp(ip_packet, sizeof(ip_packet));

	if (!ip_len)
		return -1;
	return write_marked_vnet_packet_to_tun(tun_fd, ip_packet, ip_len, &vnet);
}

static size_t build_ipv4_udp_gso(uint8_t *out, size_t out_len)
{
	size_t payload_len = GSO_SIZE * 3;
	size_t total_len = 20 + 8 + payload_len;
	uint8_t *ip = out;
	uint8_t *udp = out + 20;

	if (out_len < total_len)
		return 0;
	memset(out, 0, total_len);

	ip[0] = 0x45;
	ip[2] = (uint8_t)(total_len >> 8);
	ip[3] = (uint8_t)total_len;
	ip[4] = 0x34;
	ip[5] = 0x56;
	ip[8] = 64;
	ip[9] = IPPROTO_UDP;
	inet_pton(AF_INET, "10.99.0.2", ip + 12);
	inet_pton(AF_INET, "10.99.0.1", ip + 16);
	*(uint16_t *)(ip + 10) = htons(csum16(ip, 20));

	*(uint16_t *)(udp + 0) = htons(5555);
	*(uint16_t *)(udp + 2) = htons(5555);
	*(uint16_t *)(udp + 4) = htons(8 + payload_len);
	for (size_t i = 0; i < payload_len; i++)
		udp[8 + i] = (uint8_t)('g' + (i % 16));
	return total_len;
}

static int write_marked_udp_gso_to_tun(int tun_fd)
{
	uint8_t packet[4096];
	struct virtio_net_hdr vnet = {
		.flags = VIRTIO_NET_HDR_F_NEEDS_CSUM,
		.gso_type = VIRTIO_NET_HDR_GSO_UDP_L4,
		.hdr_len = 28,
		.gso_size = GSO_SIZE,
		.csum_start = 20,
		.csum_offset = 6,
	};
	size_t len = build_ipv4_udp_gso(packet, sizeof(packet));

	if (!len)
		return -1;
	return write_marked_vnet_packet_to_tun(tun_fd, packet, len, &vnet);
}

struct tcp_packet {
	uint32_t saddr;
	uint32_t daddr;
	uint32_t seq;
	uint16_t sport;
	uint16_t dport;
	uint8_t flags;
};

static uint16_t tcp_checksum(const uint8_t *ip, const uint8_t *tcp,
			     size_t tcp_len)
{
	uint32_t sum = 0;

	for (int i = 12; i < 20; i += 2)
		sum += ((uint16_t)ip[i] << 8) | ip[i + 1];
	sum += IPPROTO_TCP;
	sum += tcp_len;
	for (size_t i = 0; i + 1 < tcp_len; i += 2)
		sum += ((uint16_t)tcp[i] << 8) | tcp[i + 1];
	if (tcp_len & 1)
		sum += (uint16_t)tcp[tcp_len - 1] << 8;
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	return (uint16_t)~sum;
}

static int read_tcp_control_from_tun(int tun_fd, struct tcp_packet *packet,
				     uint8_t required_flags)
{
	uint8_t buf[4096];

	for (int i = 0; i < 256; i++) {
		ssize_t n = read(tun_fd, buf, sizeof(buf));
		uint8_t *ip = buf + 4 + sizeof(struct virtio_net_hdr);
		uint8_t *tcp;

		if (n < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				usleep(100000);
				continue;
			}
			perror("read TCP control from TUN");
			return -1;
		}
		if (n < 4 + (ssize_t)sizeof(struct virtio_net_hdr) + 40)
			continue;
		if ((ip[0] >> 4) != 4 || ip[9] != IPPROTO_TCP)
			continue;
		tcp = ip + ((ip[0] & 0x0f) * 4);
		if ((tcp[13] & required_flags) != required_flags)
			continue;
		memcpy(&packet->saddr, ip + 12, sizeof(packet->saddr));
		memcpy(&packet->daddr, ip + 16, sizeof(packet->daddr));
		packet->sport = ((uint16_t)tcp[0] << 8) | tcp[1];
		packet->dport = ((uint16_t)tcp[2] << 8) | tcp[3];
		packet->seq = ntohl(*(uint32_t *)(tcp + 4));
		packet->flags = tcp[13];
		return 0;
	}

	fprintf(stderr, "TCP control packet not read from TUN\n");
	return -1;
}

static int write_tcp_synack_to_tun(int tun_fd, const struct tcp_packet *syn,
				   bool with_mark_prefix)
{
	uint8_t packet[20 + 24];
	uint8_t *ip = packet;
	uint8_t *tcp = packet + 20;
	struct virtio_net_hdr vnet = { 0 };
	size_t total_len = sizeof(packet);
	uint32_t seq = htonl(TCP_SERVER_SEQ);
	uint32_t ack = htonl(syn->seq + 1);
	uint16_t mss = htons(1460);

	memset(packet, 0, sizeof(packet));
	ip[0] = 0x45;
	ip[2] = (uint8_t)(total_len >> 8);
	ip[3] = (uint8_t)total_len;
	ip[4] = 0x9a;
	ip[5] = 0xbc;
	ip[8] = 64;
	ip[9] = IPPROTO_TCP;
	memcpy(ip + 12, &syn->daddr, sizeof(syn->daddr));
	memcpy(ip + 16, &syn->saddr, sizeof(syn->saddr));
	*(uint16_t *)(ip + 10) = htons(csum16(ip, 20));

	*(uint16_t *)(tcp + 0) = htons(syn->dport);
	*(uint16_t *)(tcp + 2) = htons(syn->sport);
	memcpy(tcp + 4, &seq, sizeof(seq));
	memcpy(tcp + 8, &ack, sizeof(ack));
	tcp[12] = 6 << 4;
	tcp[13] = 0x12;
	*(uint16_t *)(tcp + 14) = htons(65535);
	tcp[20] = 2;
	tcp[21] = 4;
	memcpy(tcp + 22, &mss, sizeof(mss));
	*(uint16_t *)(tcp + 16) = htons(tcp_checksum(ip, tcp, 24));

	return write_vnet_packet_to_tun(tun_fd, packet, sizeof(packet), &vnet,
					with_mark_prefix);
}

static int write_tcp_ack_to_tun(int tun_fd, const struct tcp_packet *data,
				uint32_t payload_len)
{
	uint8_t packet[20 + 20];
	uint8_t *ip = packet;
	uint8_t *tcp = packet + 20;
	struct virtio_net_hdr vnet = { 0 };
	uint32_t seq = htonl(TCP_SERVER_SEQ + 1);
	uint32_t ack = htonl(data->seq + payload_len);
	size_t total_len = sizeof(packet);

	memset(packet, 0, sizeof(packet));
	ip[0] = 0x45;
	ip[2] = (uint8_t)(total_len >> 8);
	ip[3] = (uint8_t)total_len;
	ip[4] = 0x9a;
	ip[5] = 0xbd;
	ip[8] = 64;
	ip[9] = IPPROTO_TCP;
	memcpy(ip + 12, &data->daddr, sizeof(data->daddr));
	memcpy(ip + 16, &data->saddr, sizeof(data->saddr));
	*(uint16_t *)(ip + 10) = htons(csum16(ip, 20));

	*(uint16_t *)(tcp + 0) = htons(data->dport);
	*(uint16_t *)(tcp + 2) = htons(data->sport);
	memcpy(tcp + 4, &seq, sizeof(seq));
	memcpy(tcp + 8, &ack, sizeof(ack));
	tcp[12] = 5 << 4;
	tcp[13] = 0x10;
	*(uint16_t *)(tcp + 14) = htons(65535);
	*(uint16_t *)(tcp + 16) = htons(tcp_checksum(ip, tcp, 20));

	return write_vnet_packet_to_tun(tun_fd, packet, sizeof(packet), &vnet,
					false);
}

static int start_marked_tcp_client(void)
{
	struct sockaddr_in dst = { 0 };
	uint32_t mark = EXPECTED_MARK;
	int fd, flags;

	fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0) {
		perror("socket TCP");
		return -1;
	}
	if (setsockopt(fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark)) < 0) {
		perror("setsockopt TCP SO_MARK");
		close(fd);
		return -1;
	}
	flags = fcntl(fd, F_GETFL, 0);
	if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
		perror("fcntl TCP nonblock");
		close(fd);
		return -1;
	}

	dst.sin_family = AF_INET;
	dst.sin_port = htons(443);
	if (inet_pton(AF_INET, "10.99.0.2", &dst.sin_addr) != 1) {
		close(fd);
		return -1;
	}
	if (connect(fd, (struct sockaddr *)&dst, sizeof(dst)) < 0 &&
	    errno != EINPROGRESS) {
		perror("connect TCP");
		close(fd);
		return -1;
	}
	return fd;
}

static int finish_tcp_connect(int fd)
{
	fd_set wfds;
	struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
	int err = 0;
	socklen_t err_len = sizeof(err);

	FD_ZERO(&wfds);
	FD_SET(fd, &wfds);
	if (select(fd + 1, NULL, &wfds, NULL, &tv) <= 0) {
		perror("select TCP connect");
		return -1;
	}
	if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &err_len) < 0 || err) {
		errno = err;
		perror("TCP connect completion");
		return -1;
	}
	return 0;
}

static int send_tcp_payload_len(int fd, size_t payload_len)
{
	char payload[1 << 20];
	size_t sent = 0;

	if (payload_len > sizeof(payload))
		return -1;

	memset(payload, 'T', payload_len);
	for (int i = 0; sent < payload_len && i < 100; i++) {
		ssize_t n = send(fd, payload + sent, payload_len - sent,
				 MSG_NOSIGNAL);

		if (n > 0) {
			sent += (size_t)n;
			continue;
		}
		if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			fd_set wfds;
			struct timeval tv = { .tv_sec = 0, .tv_usec = 100000 };

			FD_ZERO(&wfds);
			FD_SET(fd, &wfds);
			if (select(fd + 1, NULL, &wfds, NULL, &tv) < 0) {
				perror("select TCP send");
				return -1;
			}
			continue;
		}
		if (n < 0)
			perror("send TCP payload");
		return -1;
	}
	if (sent != payload_len) {
		fprintf(stderr, "short TCP payload send: %zu/%zu\n", sent, payload_len);
		return -1;
	}
	return 0;
}

static int send_tcp_payload(int fd)
{
	return send_tcp_payload_len(fd, 1460 * 5);
}

static int send_marked_udp_gso(void)
{
	char payload[GSO_SIZE * 3] = { 0 };
	char control[CMSG_SPACE(sizeof(uint16_t))] = { 0 };
	struct sockaddr_in dst = { 0 };
	struct msghdr msg = { 0 };
	struct cmsghdr *cmsg;
	struct iovec iov;
	uint16_t gso_size = GSO_SIZE;
	uint32_t mark = EXPECTED_MARK;
	int fd, ret;

	fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0) {
		perror("socket UDP");
		return -1;
	}
	if (setsockopt(fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark)) < 0) {
		perror("setsockopt SO_MARK");
		close(fd);
		return -1;
	}

	for (size_t i = 0; i < sizeof(payload); i++)
		payload[i] = (char)('a' + (i % 26));

	dst.sin_family = AF_INET;
	dst.sin_port = htons(5555);
	if (inet_pton(AF_INET, "10.99.0.2", &dst.sin_addr) != 1) {
		close(fd);
		return -1;
	}

	iov.iov_base = payload;
	iov.iov_len = sizeof(payload);
	msg.msg_name = &dst;
	msg.msg_namelen = sizeof(dst);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = control;
	msg.msg_controllen = sizeof(control);

	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_UDP;
	cmsg->cmsg_type = UDP_SEGMENT;
	cmsg->cmsg_len = CMSG_LEN(sizeof(gso_size));
	memcpy(CMSG_DATA(cmsg), &gso_size, sizeof(gso_size));

	ret = sendmsg(fd, &msg, 0);
	if (ret < 0)
		perror("sendmsg UDP_SEGMENT");
	close(fd);
	return ret < 0 ? -1 : 0;
}

static int send_udp_datagram(uint32_t mark, size_t payload_len)
{
	struct sockaddr_in dst = { 0 };
	char payload[512];
	int fd, ret;

	if (payload_len > sizeof(payload))
		return -1;

	fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0) {
		perror("socket UDP scalar");
		return -1;
	}
	if (setsockopt(fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark)) < 0) {
		perror("setsockopt UDP scalar SO_MARK");
		close(fd);
		return -1;
	}

	memset(payload, 'U', payload_len);
	dst.sin_family = AF_INET;
	dst.sin_port = htons(5555);
	if (inet_pton(AF_INET, "10.99.0.2", &dst.sin_addr) != 1) {
		close(fd);
		return -1;
	}
	ret = sendto(fd, payload, payload_len, 0,
		     (struct sockaddr *)&dst, sizeof(dst));
	if (ret < 0)
		perror("sendto UDP scalar");
	close(fd);
	return ret < 0 ? -1 : 0;
}

static int open_udp_sender(uint32_t mark)
{
	struct sockaddr_in dst = { 0 };
	int fd;

	fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0) {
		perror("socket UDP bench");
		return -1;
	}
	if (setsockopt(fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark)) < 0) {
		perror("setsockopt UDP bench SO_MARK");
		close(fd);
		return -1;
	}
	dst.sin_family = AF_INET;
	dst.sin_port = htons(5555);
	if (inet_pton(AF_INET, "10.99.0.2", &dst.sin_addr) != 1 ||
	    connect(fd, (struct sockaddr *)&dst, sizeof(dst)) < 0) {
		perror("connect UDP bench");
		close(fd);
		return -1;
	}
	return fd;
}

static int send_udp_payload(int fd, size_t payload_len)
{
	char payload[512];
	ssize_t ret;

	if (payload_len > sizeof(payload))
		return -1;
	memset(payload, 'P', payload_len);
	ret = send(fd, payload, payload_len, 0);
	if (ret != (ssize_t)payload_len) {
		if (ret < 0)
			perror("send UDP bench");
		else
			fprintf(stderr, "short UDP bench send: %zd/%zu\n", ret,
				payload_len);
		return -1;
	}
	return 0;
}

static int read_udp_scalar_from_tun(int tun_fd, size_t *packet_len,
				    struct packet_meta *meta)
{
	uint8_t buf[2048];

	for (int i = 0; i < 256; i++) {
		struct virtio_net_hdr *hdr = (struct virtio_net_hdr *)(buf + 4);
		uint8_t *ip = buf + 4 + sizeof(*hdr);
		ssize_t n = read(tun_fd, buf, sizeof(buf));

		if (n < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				usleep(100000);
				continue;
			}
			perror("read UDP scalar from TUN");
			return -1;
		}
		if (n < 4 + (ssize_t)sizeof(*hdr) + 28)
			continue;
		if (hdr->gso_type != VIRTIO_NET_HDR_GSO_NONE)
			continue;
		if ((ip[0] >> 4) != 4 || ip[9] != IPPROTO_UDP)
			continue;
		if (parse_tun_packet_meta(buf, n, meta))
			continue;
		*packet_len = (size_t)n;
		return 0;
	}

	fprintf(stderr, "UDP scalar packet not read from TUN\n");
	return -1;
}

static int read_prepended_udp_from_tun(int tun_fd, uint32_t expected_mark,
				       size_t *packet_len)
{
	uint8_t buf[2048];
	uint32_t mark_be;

	for (int i = 0; i < 256; i++) {
		struct virtio_net_hdr *hdr = (struct virtio_net_hdr *)(buf + 4);
		uint8_t *mark = buf + 4 + sizeof(*hdr);
		uint8_t *ip = mark + 4;
		ssize_t n = read(tun_fd, buf, sizeof(buf));

		if (n < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				usleep(100000);
				continue;
			}
			perror("read prepended UDP from TUN");
			return -1;
		}
		if (n < 4 + (ssize_t)sizeof(*hdr) + 4 + 28)
			continue;
		if (hdr->gso_type != VIRTIO_NET_HDR_GSO_NONE)
			continue;
		memcpy(&mark_be, mark, sizeof(mark_be));
		if (ntohl(mark_be) != expected_mark)
			continue;
		if ((ip[0] >> 4) != 4 || ip[9] != IPPROTO_UDP)
			continue;
		*packet_len = (size_t)n;
		return 0;
	}

	fprintf(stderr, "prepended UDP packet not read from TUN\n");
	return -1;
}

static int read_gso_from_tun(int tun_fd, uint8_t expected_gso_type,
			     size_t *packet_len, uint16_t *gso_size,
			     struct packet_meta *meta)
{
	uint8_t buf[8192];
	uint8_t last_gso_type = 0;
	uint16_t last_gso_size = 0;

	for (int i = 0; i < 256; i++) {
		struct virtio_net_hdr *hdr = (struct virtio_net_hdr *)(buf + 4);
		ssize_t n = read(tun_fd, buf, sizeof(buf));

		if (n < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				usleep(100000);
				continue;
			}
			perror("read tun");
			return -1;
		}
		if (n < 4 + (ssize_t)sizeof(*hdr) + 20)
			continue;
		last_gso_type = hdr->gso_type;
		last_gso_size = hdr->gso_size;
		if (hdr->gso_type != expected_gso_type)
			continue;
		if (parse_tun_packet_meta(buf, n, meta))
			continue;
		*packet_len = (size_t)n;
		*gso_size = hdr->gso_size;
		return 0;
	}

	fprintf(stderr, "expected GSO packet not read from TUN; last gso_type=%u gso_size=%u\n",
		last_gso_type, last_gso_size);
	return -1;
}

static int read_tcp_gso_data_from_tun(int tun_fd, size_t *packet_len,
				      uint16_t *gso_size,
				      struct tcp_packet *packet,
				      uint32_t *payload_len,
				      struct packet_meta *meta)
{
	uint8_t buf[8192];
	uint8_t last_gso_type = 0;
	uint16_t last_gso_size = 0;

	for (int i = 0; i < 256; i++) {
		struct virtio_net_hdr *hdr = (struct virtio_net_hdr *)(buf + 4);
		uint8_t *ip = buf + 4 + sizeof(*hdr);
		uint8_t *tcp;
		uint16_t total_len;
		uint8_t ihl, thl;
		ssize_t n = read(tun_fd, buf, sizeof(buf));

		if (n < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				usleep(100000);
				continue;
			}
			perror("read TCP GSO from TUN");
			return -1;
		}
		if (n < 4 + (ssize_t)sizeof(*hdr) + 40)
			continue;
		last_gso_type = hdr->gso_type;
		last_gso_size = hdr->gso_size;
		if (hdr->gso_type != VIRTIO_NET_HDR_GSO_TCPV4)
			continue;
		if ((ip[0] >> 4) != 4 || ip[9] != IPPROTO_TCP)
			continue;

		ihl = (ip[0] & 0x0f) * 4;
		if (ihl < 20 || n < 4 + (ssize_t)sizeof(*hdr) + ihl + 20)
			continue;
		tcp = ip + ihl;
		thl = (tcp[12] >> 4) * 4;
		total_len = ((uint16_t)ip[2] << 8) | ip[3];
		if (thl < 20 || total_len < ihl + thl)
			continue;
		if (parse_tun_packet_meta(buf, n, meta))
			continue;

		memcpy(&packet->saddr, ip + 12, sizeof(packet->saddr));
		memcpy(&packet->daddr, ip + 16, sizeof(packet->daddr));
		packet->sport = ((uint16_t)tcp[0] << 8) | tcp[1];
		packet->dport = ((uint16_t)tcp[2] << 8) | tcp[3];
		packet->seq = ntohl(*(uint32_t *)(tcp + 4));
		packet->flags = tcp[13];
		*payload_len = total_len - ihl - thl;
		*packet_len = (size_t)n;
		*gso_size = hdr->gso_size;
		return 0;
	}

	fprintf(stderr, "expected TCP GSO packet not read from TUN; last gso_type=%u gso_size=%u\n",
		last_gso_type, last_gso_size);
	return -1;
}

static uint64_t now_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ull + ts.tv_nsec;
}

static int run_udp_gso_bench_case(const char *obj_path, bool with_bpf,
				  int iterations, double *gbps,
				  unsigned int *events)
{
	struct tc_attachment egress = { 0 };
	struct bpf_object *obj = NULL;
	struct ring_buffer *rb = NULL;
	struct event_state state = { 0 };
	struct bpf_map *map;
	size_t total_bytes = 0;
	uint64_t start, end;
	int tun_fd = -1;
	int err = -1;

	run_cmd_quiet("ip link del " DEV_NAME " >/dev/null 2>&1");
	tun_fd = open_vnet_tun(DEV_NAME);
	if (tun_fd < 0)
		goto out;
	if (configure_tun(DEV_NAME, "10.99.0.1/24"))
		goto out;

	if (with_bpf) {
		if (attach_read_bpf(DEV_NAME, obj_path, &obj, &egress))
			goto out;
		map = bpf_object__find_map_by_name(obj, "fwmark_events");
		if (!map)
			goto out;
		rb = ring_buffer__new(bpf_map__fd(map), handle_event, &state, NULL);
		if (!rb)
			goto out;
	}

	start = now_ns();
	for (int i = 0; i < iterations; i++) {
		size_t packet_len = 0;
		uint16_t gso_size = 0;

		if (send_marked_udp_gso())
			goto out;
		if (with_bpf && poll_until_read_events(rb, &state, i + 1))
			goto out;
		if (read_gso_from_tun(tun_fd, VIRTIO_NET_HDR_GSO_UDP_L4,
				      &packet_len, &gso_size, NULL))
			goto out;
		total_bytes += packet_len;
	}
	end = now_ns();

	*gbps = (double)total_bytes * 8.0 / (double)(end - start);
	*events = state.read_events;
	if (with_bpf && assert_no_drops(obj))
		goto out;
	err = 0;

out:
	if (rb)
		ring_buffer__free(rb);
	if (obj) {
		bpf_tc_detach(&egress.hook, &egress.opts);
		bpf_tc_hook_destroy(&egress.hook);
		bpf_object__close(obj);
	}
	if (tun_fd >= 0)
		close(tun_fd);
	run_cmd_quiet("ip link del " DEV_NAME " >/dev/null 2>&1");
	return err;
}

static int run_tcp_gso_burst(int tun_fd, struct ring_buffer *rb,
			     struct event_state *state,
			     unsigned int expected_gso_events,
			     size_t *packet_len)
{
	struct tcp_packet syn = { 0 };
	struct tcp_packet data = { 0 };
	uint32_t payload_len = 0;
	uint16_t gso_size = 0;
	int tcp_fd = -1;
	int err = -1;

	tcp_fd = start_marked_tcp_client();
	if (tcp_fd < 0)
		goto out;
	if (read_tcp_control_from_tun(tun_fd, &syn, 0x02))
		goto out;
	if (write_tcp_synack_to_tun(tun_fd, &syn, false))
		goto out;
	if (finish_tcp_connect(tcp_fd))
		goto out;
	if (send_tcp_payload_len(tcp_fd, 1460 * 5))
		goto out;
	if (rb && poll_until_read_events(rb, state, expected_gso_events))
		goto out;
	if (read_tcp_gso_data_from_tun(tun_fd, packet_len, &gso_size, &data,
				       &payload_len, NULL))
		goto out;
	if (!gso_size) {
		fprintf(stderr, "unexpected TCP benchmark GSO size: %u\n", gso_size);
		goto out;
	}
	if (write_tcp_ack_to_tun(tun_fd, &data, payload_len))
		goto out;

	err = 0;

out:
	if (tcp_fd >= 0)
		close(tcp_fd);
	return err;
}

static int run_tcp_gso_bench_case(const char *obj_path, bool with_bpf,
				  int iterations, double *gbps,
				  unsigned int *gso_events,
				  unsigned int *total_events)
{
	struct tc_attachment egress = { 0 };
	struct bpf_object *obj = NULL;
	struct ring_buffer *rb = NULL;
	struct event_state state = { 0 };
	struct bpf_map *map;
	size_t total_bytes = 0;
	uint64_t start, end;
	int tun_fd = -1;
	int err = -1;

	run_cmd_quiet("ip link del " DEV_NAME " >/dev/null 2>&1");
	tun_fd = open_vnet_tun(DEV_NAME);
	if (tun_fd < 0)
		goto out;
	if (configure_tun(DEV_NAME, "10.99.0.1/24"))
		goto out;

	if (with_bpf) {
		if (attach_read_bpf(DEV_NAME, obj_path, &obj, &egress))
			goto out;
		map = bpf_object__find_map_by_name(obj, "fwmark_events");
		if (!map)
			goto out;
		rb = ring_buffer__new(bpf_map__fd(map), handle_event, &state, NULL);
		if (!rb)
			goto out;
	}

	start = now_ns();
	for (int i = 0; i < iterations; i++) {
		size_t packet_len = 0;

		if (run_tcp_gso_burst(tun_fd, rb, &state, i + 1, &packet_len))
			goto out;
		total_bytes += packet_len;
	}
	end = now_ns();

	*gbps = (double)total_bytes * 8.0 / (double)(end - start);
	*gso_events = state.read_events;
	*total_events = state.total_read_events;
	if (with_bpf && assert_no_drops(obj))
		goto out;
	err = 0;

out:
	if (rb)
		ring_buffer__free(rb);
	if (obj) {
		bpf_tc_detach(&egress.hook, &egress.opts);
		bpf_tc_hook_destroy(&egress.hook);
		bpf_object__close(obj);
	}
	if (tun_fd >= 0)
		close(tun_fd);
	run_cmd_quiet("ip link del " DEV_NAME " >/dev/null 2>&1");
	return err;
}

static int run_mixed_bench_case(const char *obj_path, bool with_bpf,
				int iterations, double *gbps,
				unsigned int *gso_events,
				unsigned int *total_events)
{
	struct tc_attachment egress = { 0 };
	struct bpf_object *obj = NULL;
	struct ring_buffer *rb = NULL;
	struct event_state state = { 0 };
	struct bpf_map *map;
	size_t total_bytes = 0;
	uint64_t start, end;
	int tun_fd = -1;
	int err = -1;

	run_cmd_quiet("ip link del " DEV_NAME " >/dev/null 2>&1");
	tun_fd = open_vnet_tun(DEV_NAME);
	if (tun_fd < 0)
		goto out;
	if (configure_tun(DEV_NAME, "10.99.0.1/24"))
		goto out;

	if (with_bpf) {
		if (attach_read_bpf(DEV_NAME, obj_path, &obj, &egress))
			goto out;
		map = bpf_object__find_map_by_name(obj, "fwmark_events");
		if (!map)
			goto out;
		rb = ring_buffer__new(bpf_map__fd(map), handle_event, &state, NULL);
		if (!rb)
			goto out;
	}

	start = now_ns();
	for (int i = 0; i < iterations; i++) {
		size_t packet_len = 0;
		uint16_t gso_size = 0;

		if (send_udp_datagram(SECOND_MARK, 64))
			goto out;
		if (rb)
			ring_buffer__poll(rb, 0);
		if (read_udp_scalar_from_tun(tun_fd, &packet_len, NULL))
			goto out;
		total_bytes += packet_len;

		if (send_marked_udp_gso())
			goto out;
		if (rb && poll_until_read_events(rb, &state, (i * 2) + 1))
			goto out;
		if (read_gso_from_tun(tun_fd, VIRTIO_NET_HDR_GSO_UDP_L4,
				      &packet_len, &gso_size, NULL))
			goto out;
		total_bytes += packet_len;

		if (run_tcp_gso_burst(tun_fd, rb, &state, (i * 2) + 2,
				      &packet_len))
			goto out;
		total_bytes += packet_len;
	}
	end = now_ns();

	*gbps = (double)total_bytes * 8.0 / (double)(end - start);
	*gso_events = state.read_events;
	*total_events = state.total_read_events;
	if (with_bpf && assert_no_drops(obj))
		goto out;
	err = 0;

out:
	if (rb)
		ring_buffer__free(rb);
	if (obj) {
		bpf_tc_detach(&egress.hook, &egress.opts);
		bpf_tc_hook_destroy(&egress.hook);
		bpf_object__close(obj);
	}
	if (tun_fd >= 0)
		close(tun_fd);
	run_cmd_quiet("ip link del " DEV_NAME " >/dev/null 2>&1");
	return err;
}

static double drop_percent(double baseline, double fwmark)
{
	return baseline > 0.0 ? (baseline - fwmark) * 100.0 / baseline : 0.0;
}

static int run_prepend_correctness(const char *obj_path)
{
	struct tc_attachment egress = { 0 };
	struct bpf_object *obj = NULL;
	size_t packet_len = 0;
	int tun_fd = -1;
	int err = 1;

	if (enter_new_netns())
		return 1;
	run_cmd_quiet("ip link del " DEV_NAME " >/dev/null 2>&1");
	tun_fd = open_vnet_tun(DEV_NAME);
	if (tun_fd < 0)
		goto out;
	if (configure_tun(DEV_NAME, "10.99.0.1/24"))
		goto out;
	if (attach_egress_prog(DEV_NAME, obj_path, "tun_read_path_prepend_mark",
			       &obj, &egress))
		goto out;
	if (send_udp_datagram(EXPECTED_MARK, 128))
		goto out;
	if (read_prepended_udp_from_tun(tun_fd, EXPECTED_MARK, &packet_len))
		goto out;
	printf("PREPEND_READ_PATH_UDP_SCALAR: mark=0x%08x tun_len=%zu\n",
	       EXPECTED_MARK, packet_len);
	err = 0;

out:
	if (obj) {
		bpf_tc_detach(&egress.hook, &egress.opts);
		bpf_tc_hook_destroy(&egress.hook);
		bpf_object__close(obj);
	}
	if (tun_fd >= 0)
		close(tun_fd);
	run_cmd_quiet("ip link del " DEV_NAME " >/dev/null 2>&1");
	return err;
}

static int run_prepend_bench_case(const char *obj_path, bool with_bpf,
				  int iterations, double *gbps)
{
	struct tc_attachment egress = { 0 };
	struct bpf_object *obj = NULL;
	size_t total_bytes = 0;
	uint64_t start, end;
	int tun_fd = -1, udp_fd = -1;
	int err = -1;

	run_cmd_quiet("ip link del " DEV_NAME " >/dev/null 2>&1");
	tun_fd = open_vnet_tun(DEV_NAME);
	if (tun_fd < 0)
		goto out;
	if (configure_tun(DEV_NAME, "10.99.0.1/24"))
		goto out;
	if (with_bpf && attach_egress_prog(DEV_NAME, obj_path,
					   "tun_read_path_prepend_mark", &obj,
					   &egress))
		goto out;
	udp_fd = open_udp_sender(EXPECTED_MARK);
	if (udp_fd < 0)
		goto out;

	start = now_ns();
	for (int i = 0; i < iterations; i++) {
		size_t packet_len = 0;

		if (send_udp_payload(udp_fd, 256))
			goto out;
		if (with_bpf) {
			if (read_prepended_udp_from_tun(tun_fd, EXPECTED_MARK,
							&packet_len))
				goto out;
			packet_len -= 4;
		} else if (read_udp_scalar_from_tun(tun_fd, &packet_len, NULL)) {
			goto out;
		}
		total_bytes += packet_len;
	}
	end = now_ns();

	*gbps = (double)total_bytes * 8.0 / (double)(end - start);
	err = 0;

out:
	if (udp_fd >= 0)
		close(udp_fd);
	if (obj) {
		bpf_tc_detach(&egress.hook, &egress.opts);
		bpf_tc_hook_destroy(&egress.hook);
		bpf_object__close(obj);
	}
	if (tun_fd >= 0)
		close(tun_fd);
	run_cmd_quiet("ip link del " DEV_NAME " >/dev/null 2>&1");
	return err;
}

static int run_prepend_bench(const char *obj_path, int iterations)
{
	double baseline = 0.0, prepend = 0.0;

	if (run_prepend_correctness(obj_path))
		return 1;
	if (enter_new_netns())
		return 1;
	if (run_prepend_bench_case(obj_path, false, iterations, &baseline))
		return 1;
	if (enter_new_netns())
		return 1;
	if (run_prepend_bench_case(obj_path, true, iterations, &prepend))
		return 1;

	printf("BENCH_PREPEND_UDP_SCALAR baseline=%.3f Gbit/s prepend=%.3f Gbit/s drop=%.1f%% iterations=%d\n",
	       baseline, prepend, drop_percent(baseline, prepend), iterations);
	return 0;
}

static int enter_new_netns(void)
{
	if (unshare(CLONE_NEWNET) < 0) {
		perror("unshare CLONE_NEWNET");
		return -1;
	}
	run_cmd_quiet("ip link set lo up >/dev/null 2>&1");
	return 0;
}

static int run_bench(const char *obj_path, int iterations)
{
	double base_udp = 0.0, fwmark_udp = 0.0;
	double base_tcp = 0.0, fwmark_tcp = 0.0;
	double base_mixed = 0.0, fwmark_mixed = 0.0;
	unsigned int baseline_events = 0, fwmark_events = 0;
	unsigned int baseline_total = 0, fwmark_total = 0;

	if (enter_new_netns())
		return 1;
	if (run_udp_gso_bench_case(obj_path, false, iterations, &base_udp,
				   &baseline_events))
		return 1;
	if (enter_new_netns())
		return 1;
	if (run_udp_gso_bench_case(obj_path, true, iterations, &fwmark_udp,
				   &fwmark_events))
		return 1;

	printf("BENCH_UDP_GSO baseline=%.3f Gbit/s fwmark=%.3f Gbit/s drop=%.1f%% events=%u/%d\n",
	       base_udp, fwmark_udp, drop_percent(base_udp, fwmark_udp),
	       fwmark_events, iterations);
	if (fwmark_events != (unsigned int)iterations)
		return 1;

	if (enter_new_netns())
		return 1;
	if (run_tcp_gso_bench_case(obj_path, false, iterations, &base_tcp,
				   &baseline_events, &baseline_total))
		return 1;
	if (enter_new_netns())
		return 1;
	if (run_tcp_gso_bench_case(obj_path, true, iterations, &fwmark_tcp,
				   &fwmark_events, &fwmark_total))
		return 1;

	printf("BENCH_TCP_GSO baseline=%.3f Gbit/s fwmark=%.3f Gbit/s drop=%.1f%% gso_events=%u/%d total_events=%u\n",
	       base_tcp, fwmark_tcp, drop_percent(base_tcp, fwmark_tcp),
	       fwmark_events, iterations, fwmark_total);
	if (fwmark_events != (unsigned int)iterations)
		return 1;

	if (enter_new_netns())
		return 1;
	if (run_mixed_bench_case(obj_path, false, iterations, &base_mixed,
				 &baseline_events, &baseline_total))
		return 1;
	if (enter_new_netns())
		return 1;
	if (run_mixed_bench_case(obj_path, true, iterations, &fwmark_mixed,
				 &fwmark_events, &fwmark_total))
		return 1;

	printf("BENCH_MIXED baseline=%.3f Gbit/s fwmark=%.3f Gbit/s drop=%.1f%% gso_events=%u/%d total_events=%u\n",
	       base_mixed, fwmark_mixed, drop_percent(base_mixed, fwmark_mixed),
	       fwmark_events, iterations * 2, fwmark_total);
	if (fwmark_events != (unsigned int)iterations * 2)
		return 1;
	return 0;
}

int main(int argc, char **argv)
{
	const char *obj_path = BPF_OBJ;
	struct tc_attachment ingress = { 0 }, egress = { 0 };
	struct bpf_object *obj = NULL;
	struct ring_buffer *rb = NULL;
	struct event_state state = { 0 };
	struct bpf_map *map;
	struct packet_meta scalar_meta = { 0 }, zero_meta = { 0 };
	struct packet_meta udp_gso_meta = { 0 }, tcp_gso_meta = { 0 };
	struct rlimit rlim = { RLIM_INFINITY, RLIM_INFINITY };
	struct tcp_packet syn = { 0 };
	size_t scalar_packet_len = 0, zero_packet_len = 0;
	size_t udp_gso_packet_len = 0, tcp_gso_packet_len = 0;
	uint16_t udp_tun_gso_size = 0, tcp_tun_gso_size = 0;
	int tun_fd = -1, tcp_fd = -1, map_fd, err = 1;

	setrlimit(RLIMIT_MEMLOCK, &rlim);
	if (argc > 1 && strcmp(argv[1], "--bench") == 0) {
		int iterations = argc > 2 ? atoi(argv[2]) : 2000;

		return run_bench(obj_path, iterations);
	}
	if (argc > 1 && strcmp(argv[1], "--bench-prepend") == 0) {
		int iterations = argc > 2 ? atoi(argv[2]) : 20000;

		return run_prepend_bench(obj_path, iterations);
	}
	if (argc > 1)
		obj_path = argv[1];
	if (unshare(CLONE_NEWNET) < 0) {
		perror("unshare CLONE_NEWNET");
		goto out;
	}
	run_cmd_quiet("ip link set lo up >/dev/null 2>&1");
	run_cmd_quiet("ip link del " DEV_NAME " >/dev/null 2>&1");

	tun_fd = open_vnet_tun(DEV_NAME);
	if (tun_fd < 0)
		goto out;
	if (configure_tun(DEV_NAME, "10.99.0.1/24"))
		goto out;
	if (attach_bpf(DEV_NAME, obj_path, &obj, &ingress, &egress))
		goto out;

	map = bpf_object__find_map_by_name(obj, "fwmark_events");
	if (!map) {
		fprintf(stderr, "ringbuf map not found\n");
		goto out;
	}
	map_fd = bpf_map__fd(map);
	rb = ring_buffer__new(map_fd, handle_event, &state, NULL);
	if (!rb) {
		fprintf(stderr, "ring_buffer__new failed\n");
		goto out;
	}

	if (write_marked_udp_packet_to_tun(tun_fd))
		goto out;
	if (poll_until(rb, &state.write_seen)) {
		fprintf(stderr, "write-path fwmark event not received\n");
		goto out;
	}

	if (write_marked_udp_gso_to_tun(tun_fd))
		goto out;
	if (poll_until(rb, &state.write_gso_seen)) {
		fprintf(stderr, "write-path UDP GSO fwmark event not received\n");
		goto out;
	}

	if (send_udp_datagram(SECOND_MARK, 64))
		goto out;
	if (poll_until(rb, &state.scalar_seen)) {
		fprintf(stderr, "read-path scalar fwmark event not received\n");
		goto out;
	}
	if (read_udp_scalar_from_tun(tun_fd, &scalar_packet_len, &scalar_meta))
		goto out;
	if (!event_matches_packet(&state.scalar_event, &scalar_meta)) {
		fprintf(stderr, "read-path scalar metadata mismatch\n");
		goto out;
	}

	if (send_udp_datagram(0, 32))
		goto out;
	if (poll_until(rb, &state.zero_seen)) {
		fprintf(stderr, "read-path zero-mark event not received\n");
		goto out;
	}
	if (read_udp_scalar_from_tun(tun_fd, &zero_packet_len, &zero_meta))
		goto out;
	if (!event_matches_packet(&state.zero_event, &zero_meta)) {
		fprintf(stderr, "read-path zero-mark metadata mismatch\n");
		goto out;
	}

	if (send_marked_udp_gso())
		goto out;
	if (poll_until_read_events(rb, &state, 1)) {
		fprintf(stderr, "UDP read-path fwmark event not received\n");
		goto out;
	}
	if (read_gso_from_tun(tun_fd, VIRTIO_NET_HDR_GSO_UDP_L4,
			      &udp_gso_packet_len, &udp_tun_gso_size,
			      &udp_gso_meta)) {
		fprintf(stderr, "UDP GSO TUN read failed\n");
		goto out;
	}
	if (!event_matches_packet(&state.udp_read_event, &udp_gso_meta)) {
		fprintf(stderr, "read-path UDP GSO metadata mismatch\n");
		goto out;
	}
	if (udp_tun_gso_size != GSO_SIZE) {
		fprintf(stderr, "unexpected UDP TUN GSO size: %u\n", udp_tun_gso_size);
		goto out;
	}

	tcp_fd = start_marked_tcp_client();
	if (tcp_fd < 0)
		goto out;
	if (read_tcp_control_from_tun(tun_fd, &syn, 0x02))
		goto out;
	if (write_tcp_synack_to_tun(tun_fd, &syn, true))
		goto out;
	if (finish_tcp_connect(tcp_fd))
		goto out;
	if (send_tcp_payload(tcp_fd))
		goto out;
	if (poll_until_read_events(rb, &state, 2)) {
		fprintf(stderr, "TCP read-path fwmark event not received\n");
		goto out;
	}
	if (read_gso_from_tun(tun_fd, VIRTIO_NET_HDR_GSO_TCPV4,
			      &tcp_gso_packet_len, &tcp_tun_gso_size,
			      &tcp_gso_meta)) {
		fprintf(stderr, "TCP GSO TUN read failed\n");
		goto out;
	}
	if (!event_matches_packet(&state.tcp_read_event, &tcp_gso_meta)) {
		fprintf(stderr, "read-path TCP GSO metadata mismatch\n");
		goto out;
	}
	if (event_matches_packet(&state.udp_read_event, &tcp_gso_meta) ||
	    event_matches_packet(&state.tcp_read_event, &udp_gso_meta)) {
		fprintf(stderr, "metadata mismatch detector accepted crossed events\n");
		goto out;
	}
	if (!tcp_tun_gso_size) {
		fprintf(stderr, "unexpected TCP TUN GSO size: %u\n", tcp_tun_gso_size);
		goto out;
	}
	if (assert_no_drops(obj))
		goto out;

	printf("WRITE_PATH: imported mark=0x%08x len=%u\n",
	       state.write_event.mark, state.write_event.len);
	printf("WRITE_PATH_UDP_GSO: imported mark=0x%08x len=%u gso_size=%u gso_segs=%u\n",
	       state.write_gso_event.mark, state.write_gso_event.len,
	       state.write_gso_event.gso_size, state.write_gso_event.gso_segs);
	printf("READ_PATH_UDP_SCALAR: event mark=0x%08x len=%u tun_len=%zu\n",
	       state.scalar_event.mark, state.scalar_event.len, scalar_packet_len);
	printf("READ_PATH_ZERO_MARK: event mark=0x%08x len=%u tun_len=%zu\n",
	       state.zero_event.mark, state.zero_event.len, zero_packet_len);
	printf("READ_PATH_UDP: event mark=0x%08x len=%u gso_size=%u gso_segs=%u tun_len=%zu\n",
	       state.udp_read_event.mark, state.udp_read_event.len,
	       state.udp_read_event.gso_size, state.udp_read_event.gso_segs,
	       udp_gso_packet_len);
	printf("READ_PATH_TCP: event mark=0x%08x len=%u gso_size=%u gso_segs=%u tun_len=%zu\n",
	       state.tcp_read_event.mark, state.tcp_read_event.len,
	       state.tcp_read_event.gso_size, state.tcp_read_event.gso_segs,
	       tcp_gso_packet_len);
	printf("PASS: TUN write path imports fwmark; TUN read path exports fwmark out-of-band while preserving UDP and TCP GSO super-packets\n");
	err = 0;

out:
	if (rb)
		ring_buffer__free(rb);
	if (obj) {
		bpf_tc_detach(&ingress.hook, &ingress.opts);
		bpf_tc_detach(&egress.hook, &egress.opts);
		bpf_tc_hook_destroy(&ingress.hook);
		bpf_tc_hook_destroy(&egress.hook);
		bpf_object__close(obj);
	}
	if (tcp_fd >= 0)
		close(tcp_fd);
	if (tun_fd >= 0)
		close(tun_fd);
	run_cmd_quiet("ip link del " DEV_NAME " >/dev/null 2>&1");
	return err;
}
