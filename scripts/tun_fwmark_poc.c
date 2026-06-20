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
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/wait.h>
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

struct fwmark_sample {
	uint32_t seen;
	uint32_t mark;
	uint32_t len;
	uint32_t gso_size;
	uint32_t gso_segs;
	uint32_t ip_proto;
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

struct mpls_packet_meta {
	uint32_t mark;
	struct packet_meta packet;
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

static int parse_tun_packet_meta_at(const uint8_t *buf, ssize_t len,
				    size_t ip_offset, size_t vnet_offset,
				    struct packet_meta *meta)
{
	const struct virtio_net_hdr *hdr = (const struct virtio_net_hdr *)(buf + vnet_offset);
	const uint8_t *ip = buf + ip_offset;
	const uint8_t *l4;
	uint8_t ihl;

	if (!meta)
		return 0;
	memset(meta, 0, sizeof(*meta));
	if (len < (ssize_t)ip_offset + 20)
		return -1;
	if ((ip[0] >> 4) != 4)
		return -1;

	ihl = (ip[0] & 0x0f) * 4;
	if (ihl < 20 || len < (ssize_t)ip_offset + ihl)
		return -1;
	l4 = ip + ihl;

	meta->len = (uint32_t)(len - ip_offset);
	meta->gso_size = hdr->gso_size;
	meta->ip_proto = ip[9];
	meta->ip_id = ((uint16_t)ip[4] << 8) | ip[5];
	memcpy(&meta->ip_saddr, ip + 12, sizeof(meta->ip_saddr));
	memcpy(&meta->ip_daddr, ip + 16, sizeof(meta->ip_daddr));

	if ((meta->ip_proto == IPPROTO_TCP || meta->ip_proto == IPPROTO_UDP) &&
	    len >= (ssize_t)ip_offset + ihl + 4) {
		meta->sport = ((uint16_t)l4[0] << 8) | l4[1];
		meta->dport = ((uint16_t)l4[2] << 8) | l4[3];
		if (meta->ip_proto == IPPROTO_TCP &&
		    len >= (ssize_t)ip_offset + ihl + 8) {
			uint32_t seq;

			memcpy(&seq, l4 + 4, sizeof(seq));
			meta->l4_cookie = ntohl(seq);
		} else if (meta->ip_proto == IPPROTO_UDP &&
			 len >= (ssize_t)ip_offset + ihl + 6)
			meta->l4_cookie = ((uint16_t)l4[4] << 8) | l4[5];
	}

	return 0;
}

static int parse_tun_packet_meta(const uint8_t *buf, ssize_t len,
				 struct packet_meta *meta)
{
	return parse_tun_packet_meta_at(buf, len, 4 + sizeof(struct virtio_net_hdr),
					4, meta);
}

static int parse_mpls_tun_packet_meta(const uint8_t *buf, ssize_t len,
				      struct mpls_packet_meta *meta)
{
	uint32_t mark_be;

	if (!meta)
		return 0;
	memset(meta, 0, sizeof(*meta));
	if (len < 4 + (ssize_t)sizeof(struct virtio_net_hdr) + 4 + 20)
		return -1;
	memcpy(&mark_be, buf + 4 + sizeof(struct virtio_net_hdr), sizeof(mark_be));
	meta->mark = ntohl(mark_be);
	return parse_tun_packet_meta_at(buf, len,
					4 + sizeof(struct virtio_net_hdr) + 4,
					4, &meta->packet);
}

static int open_vnet_tun_with_offloads(const char *name, bool enable_offloads)
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

	if (!enable_offloads)
		return fd;

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

static int open_vnet_tun(const char *name)
{
	return open_vnet_tun_with_offloads(name, true);
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

static int configure_mpls_encap_route(const char *name)
{
	char cmd[256];

	run_cmd_quiet("modprobe mpls_router >/dev/null 2>&1");
	run_cmd_quiet("modprobe mpls_iptunnel >/dev/null 2>&1");
	run_cmd_quiet("sysctl -q -w net.mpls.platform_labels=1048575 >/dev/null 2>&1");
	snprintf(cmd, sizeof(cmd),
		 "ip route replace 10.99.0.2/32 encap mpls 16 dev %s", name);
	return run_cmd(cmd);
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
	egress_prog = bpf_object__find_program_by_name(obj, "tun_read_path_mpls_mark");
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

	egress_prog = bpf_object__find_program_by_name(obj, "tun_read_path_mpls_mark");
	if (!egress_prog) {
		fprintf(stderr, "read-path BPF program not found\n");
		goto err_close;
	}

	if (attach_one_tc(ifindex, BPF_TC_EGRESS, bpf_program__fd(egress_prog),
			  egress))
		goto err_close;

	*obj_out = obj;
	return 0;

err_close:
	bpf_object__close(obj);
	return -1;
}

static int read_fwmark_sample(struct bpf_object *obj, uint32_t key,
			      struct fwmark_sample *sample)
{
	struct bpf_map *map = bpf_object__find_map_by_name(obj, "fwmark_samples");

	if (!map) {
		fprintf(stderr, "fwmark sample map not found\n");
		return -1;
	}
	if (bpf_map_lookup_elem(bpf_map__fd(map), &key, sample) < 0) {
		perror("read fwmark sample");
		return -1;
	}
	return 0;
}

static int poll_fwmark_sample(struct bpf_object *obj, uint32_t key,
			      struct fwmark_sample *sample)
{
	for (int i = 0; i < 200; i++) {
		if (read_fwmark_sample(obj, key, sample))
			return -1;
		if (sample->seen)
			return 0;
		usleep(1000);
	}
	return -1;
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
				usleep(1000);
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

static int write_tcp_synack_mss_to_tun(int tun_fd, const struct tcp_packet *syn,
				       bool with_mark_prefix, uint16_t mss_value)
{
	uint8_t packet[20 + 24];
	uint8_t *ip = packet;
	uint8_t *tcp = packet + 20;
	struct virtio_net_hdr vnet = { 0 };
	size_t total_len = sizeof(packet);
	uint32_t seq = htonl(TCP_SERVER_SEQ);
	uint32_t ack = htonl(syn->seq + 1);
	uint16_t mss = htons(mss_value);

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

static int write_tcp_synack_to_tun(int tun_fd, const struct tcp_packet *syn,
				   bool with_mark_prefix)
{
	return write_tcp_synack_mss_to_tun(tun_fd, syn, with_mark_prefix, 1460);
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
				usleep(1000);
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

static int read_mpls_udp_from_tun(int tun_fd, uint32_t expected_mark,
				  size_t *packet_len, struct packet_meta *meta)
{
	uint8_t buf[2048];

	for (int i = 0; i < 256; i++) {
		struct virtio_net_hdr *hdr = (struct virtio_net_hdr *)(buf + 4);
		struct mpls_packet_meta mpls_meta;
		ssize_t n = read(tun_fd, buf, sizeof(buf));

		if (n < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				usleep(1000);
				continue;
			}
			perror("read MPLS UDP from TUN");
			return -1;
		}
		if (n < 4 + (ssize_t)sizeof(*hdr) + 4 + 28)
			continue;
		if (hdr->gso_type != VIRTIO_NET_HDR_GSO_NONE)
			continue;
		if (parse_mpls_tun_packet_meta(buf, n, &mpls_meta))
			continue;
		if (mpls_meta.mark != expected_mark ||
		    mpls_meta.packet.ip_proto != IPPROTO_UDP)
			continue;
		if (meta)
			*meta = mpls_meta.packet;
		*packet_len = (size_t)n;
		return 0;
	}

	fprintf(stderr, "MPLS UDP packet not read from TUN\n");
	return -1;
}

static int read_mpls_tcp_from_tun(int tun_fd, uint32_t expected_mark,
				  struct tcp_packet *packet,
				  uint32_t *payload_len,
				  size_t *packet_len,
				  uint8_t required_flags,
				  bool require_payload)
{
	uint8_t buf[4096];
	uint8_t last_gso_type = 0;

	for (int i = 0; i < 512; i++) {
		struct virtio_net_hdr *hdr = (struct virtio_net_hdr *)(buf + 4);
		uint8_t *ip = buf + 4 + sizeof(*hdr) + 4;
		struct mpls_packet_meta mpls_meta;
		uint8_t *tcp;
		uint16_t total_len;
		uint8_t ihl, thl;
		uint32_t plen;
		ssize_t n = read(tun_fd, buf, sizeof(buf));

		if (n < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				usleep(1000);
				continue;
			}
			perror("read MPLS TCP from TUN");
			return -1;
		}
		if (n < 4 + (ssize_t)sizeof(*hdr) + 4 + 40)
			continue;
		last_gso_type = hdr->gso_type;
		if (hdr->gso_type != VIRTIO_NET_HDR_GSO_NONE)
			continue;
		if (parse_mpls_tun_packet_meta(buf, n, &mpls_meta))
			continue;
		if (mpls_meta.mark != expected_mark ||
		    mpls_meta.packet.ip_proto != IPPROTO_TCP)
			continue;
		ihl = (ip[0] & 0x0f) * 4;
		if (ihl < 20 || n < 4 + (ssize_t)sizeof(*hdr) + 4 + ihl + 20)
			continue;
		tcp = ip + ihl;
		thl = (tcp[12] >> 4) * 4;
		total_len = ((uint16_t)ip[2] << 8) | ip[3];
		if (thl < 20 || total_len < ihl + thl)
			continue;
		plen = total_len - ihl - thl;
		if ((tcp[13] & required_flags) != required_flags)
			continue;
		if (require_payload && !plen)
			continue;

		memcpy(&packet->saddr, ip + 12, sizeof(packet->saddr));
		memcpy(&packet->daddr, ip + 16, sizeof(packet->daddr));
		packet->sport = ((uint16_t)tcp[0] << 8) | tcp[1];
		packet->dport = ((uint16_t)tcp[2] << 8) | tcp[3];
		packet->seq = ntohl(*(uint32_t *)(tcp + 4));
		packet->flags = tcp[13];
		*payload_len = plen;
		*packet_len = (size_t)n;
		return 0;
	}

	fprintf(stderr, "MPLS TCP packet not read from TUN; last gso_type=%u\n",
		last_gso_type);
	return -1;
}

static int read_gso_from_tun(int tun_fd, uint8_t expected_gso_type,
			     size_t *packet_len, uint16_t *gso_size,
			     struct packet_meta *meta)
{
	uint8_t buf[131072];
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
	uint8_t buf[131072];
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

static int run_udp_gso_bench_case(const char *obj_path, bool with_mpls,
				  int iterations, double *gbps,
				  unsigned int *segments)
{
	struct tc_attachment egress = { 0 };
	struct bpf_object *obj = NULL;
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

	if (with_mpls) {
		if (configure_mpls_encap_route(DEV_NAME))
			goto out;
		if (attach_read_bpf(DEV_NAME, obj_path, &obj, &egress))
			goto out;
	}

	start = now_ns();
	for (int i = 0; i < iterations; i++) {
		size_t packet_len = 0;
		uint16_t gso_size = 0;

		if (send_marked_udp_gso())
			goto out;
		if (with_mpls) {
			for (int seg = 0; seg < 3; seg++) {
				if (read_mpls_udp_from_tun(tun_fd, EXPECTED_MARK,
							   &packet_len, NULL))
					goto out;
				total_bytes += packet_len - 4;
			}
		} else {
			if (read_gso_from_tun(tun_fd, VIRTIO_NET_HDR_GSO_UDP_L4,
					      &packet_len, &gso_size, NULL))
				goto out;
			total_bytes += packet_len;
		}
	}
	end = now_ns();

	*gbps = (double)total_bytes * 8.0 / (double)(end - start);
	*segments = with_mpls ? (unsigned int)iterations : 0;
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

struct tcp_bench_conn {
	int fd;
	bool with_mpls;
};

static void close_tcp_bench_conn(struct tcp_bench_conn *conn)
{
	if (conn->fd >= 0) {
		close(conn->fd);
		conn->fd = -1;
	}
}

static int start_tcp_bench_conn(int tun_fd, bool with_mpls,
				struct tcp_bench_conn *conn)
{
	struct tcp_packet syn = { 0 };
	uint32_t payload_len = 0;
	int tcp_fd;

	conn->fd = -1;
	conn->with_mpls = with_mpls;
	tcp_fd = start_marked_tcp_client();
	if (tcp_fd < 0)
		return -1;
	if (with_mpls) {
		size_t syn_packet_len = 0;

		if (read_mpls_tcp_from_tun(tun_fd, EXPECTED_MARK, &syn,
					   &payload_len, &syn_packet_len, 0x02,
					   false))
			goto err_close;
	} else {
		if (read_tcp_control_from_tun(tun_fd, &syn, 0x02))
			goto err_close;
	}
	if (write_tcp_synack_to_tun(tun_fd, &syn, false))
		goto err_close;
	if (finish_tcp_connect(tcp_fd))
		goto err_close;
	conn->fd = tcp_fd;
	return 0;

err_close:
	close(tcp_fd);
	return -1;
}

static int run_tcp_bench_conn_burst(int tun_fd, struct tcp_bench_conn *conn,
				    size_t *packet_len)
{
	struct tcp_packet data = { 0 };
	uint32_t payload_len = 0;
	uint16_t gso_size = 0;

	if (send_tcp_payload_len(conn->fd, 1460 * 5))
		return -1;
	if (conn->with_mpls) {
		size_t received_payload = 0;
		size_t total_packet_len = 0;
		struct tcp_packet last_data = { 0 };
		uint32_t last_payload_len = 0;

		while (received_payload < 1460 * 5) {
			size_t one_packet_len = 0;

			if (read_mpls_tcp_from_tun(tun_fd, EXPECTED_MARK,
						   &data, &payload_len,
						   &one_packet_len, 0x10, true))
				return -1;
			last_data = data;
			last_payload_len = payload_len;
			received_payload += payload_len;
			total_packet_len += one_packet_len - 4;
		}
		if (write_tcp_ack_to_tun(tun_fd, &last_data, last_payload_len))
			return -1;
		*packet_len = total_packet_len;
	} else {
		if (read_tcp_gso_data_from_tun(tun_fd, packet_len, &gso_size,
					       &data, &payload_len, NULL))
			return -1;
		if (!gso_size) {
			fprintf(stderr, "unexpected TCP benchmark GSO size: %u\n", gso_size);
			return -1;
		}
		if (write_tcp_ack_to_tun(tun_fd, &data, payload_len))
			return -1;
	}
	return 0;
}

static int run_tcp_gso_bench_case(const char *obj_path, bool with_mpls,
				  int iterations, double *gbps,
				  unsigned int *bursts,
				  unsigned int *segments)
{
	struct tc_attachment egress = { 0 };
	struct bpf_object *obj = NULL;
	struct tcp_bench_conn tcp_conn = { .fd = -1 };
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

	if (with_mpls) {
		if (configure_mpls_encap_route(DEV_NAME))
			goto out;
		if (attach_read_bpf(DEV_NAME, obj_path, &obj, &egress))
			goto out;
	}
	if (start_tcp_bench_conn(tun_fd, with_mpls, &tcp_conn))
		goto out;

	start = now_ns();
	for (int i = 0; i < iterations; i++) {
		size_t packet_len = 0;

		if (run_tcp_bench_conn_burst(tun_fd, &tcp_conn, &packet_len))
			goto out;
		total_bytes += packet_len;
	}
	end = now_ns();

	*gbps = (double)total_bytes * 8.0 / (double)(end - start);
	*bursts = with_mpls ? (unsigned int)iterations : 0;
	*segments = *bursts;
	err = 0;

out:
	close_tcp_bench_conn(&tcp_conn);
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

static int run_mixed_bench_case(const char *obj_path, bool with_mpls,
				int iterations, double *gbps,
				unsigned int *bursts,
				unsigned int *segments)
{
	struct tc_attachment egress = { 0 };
	struct bpf_object *obj = NULL;
	struct tcp_bench_conn tcp_conn = { .fd = -1 };
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

	if (with_mpls) {
		if (configure_mpls_encap_route(DEV_NAME))
			goto out;
		if (attach_read_bpf(DEV_NAME, obj_path, &obj, &egress))
			goto out;
	}
	if (start_tcp_bench_conn(tun_fd, with_mpls, &tcp_conn))
		goto out;

	start = now_ns();
	for (int i = 0; i < iterations; i++) {
		size_t packet_len = 0;
		uint16_t gso_size = 0;

		if (send_udp_datagram(SECOND_MARK, 64))
			goto out;
		if (with_mpls) {
			if (read_mpls_udp_from_tun(tun_fd, SECOND_MARK,
						   &packet_len, NULL))
				goto out;
			total_bytes += packet_len - 4;
		} else {
			if (read_udp_scalar_from_tun(tun_fd, &packet_len, NULL))
				goto out;
			total_bytes += packet_len;
		}

		if (send_marked_udp_gso())
			goto out;
		if (with_mpls) {
			for (int seg = 0; seg < 3; seg++) {
				if (read_mpls_udp_from_tun(tun_fd, EXPECTED_MARK,
							   &packet_len, NULL))
					goto out;
				total_bytes += packet_len - 4;
			}
		} else {
			if (read_gso_from_tun(tun_fd, VIRTIO_NET_HDR_GSO_UDP_L4,
					      &packet_len, &gso_size, NULL))
				goto out;
			total_bytes += packet_len;
		}

		if (run_tcp_bench_conn_burst(tun_fd, &tcp_conn, &packet_len))
			goto out;
		total_bytes += packet_len;
	}
	end = now_ns();

	*gbps = (double)total_bytes * 8.0 / (double)(end - start);
	*bursts = with_mpls ? (unsigned int)iterations * 2 : 0;
	*segments = with_mpls ? (unsigned int)iterations * 3 : 0;
	err = 0;

out:
	close_tcp_bench_conn(&tcp_conn);
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
	unsigned int baseline_bursts = 0, fwmark_bursts = 0;
	unsigned int baseline_segments = 0, fwmark_segments = 0;

	if (enter_new_netns())
		return 1;
	if (run_udp_gso_bench_case(obj_path, false, iterations, &base_udp,
				   &baseline_bursts))
		return 1;
	if (enter_new_netns())
		return 1;
	if (run_udp_gso_bench_case(obj_path, true, iterations, &fwmark_udp,
				   &fwmark_bursts))
		return 1;

	printf("BENCH_UDP_GSO baseline=%.3f Gbit/s fwmark=%.3f Gbit/s drop=%.1f%% segments=%u/%d\n",
	       base_udp, fwmark_udp, drop_percent(base_udp, fwmark_udp),
	       fwmark_bursts, iterations);
	if (fwmark_bursts != (unsigned int)iterations)
		return 1;

	if (enter_new_netns())
		return 1;
	if (run_tcp_gso_bench_case(obj_path, false, iterations, &base_tcp,
				   &baseline_bursts, &baseline_segments))
		return 1;
	if (enter_new_netns())
		return 1;
	if (run_tcp_gso_bench_case(obj_path, true, iterations, &fwmark_tcp,
				   &fwmark_bursts, &fwmark_segments))
		return 1;

	printf("BENCH_TCP_GSO baseline=%.3f Gbit/s fwmark=%.3f Gbit/s drop=%.1f%% bursts=%u/%d segments=%u\n",
	       base_tcp, fwmark_tcp, drop_percent(base_tcp, fwmark_tcp),
	       fwmark_bursts, iterations, fwmark_segments);
	if (fwmark_bursts != (unsigned int)iterations)
		return 1;

	if (enter_new_netns())
		return 1;
	if (run_mixed_bench_case(obj_path, false, iterations, &base_mixed,
				 &baseline_bursts, &baseline_segments))
		return 1;
	if (enter_new_netns())
		return 1;
	if (run_mixed_bench_case(obj_path, true, iterations, &fwmark_mixed,
				 &fwmark_bursts, &fwmark_segments))
		return 1;

	printf("BENCH_MIXED baseline=%.3f Gbit/s fwmark=%.3f Gbit/s drop=%.1f%% bursts=%u/%d segments=%u\n",
	       base_mixed, fwmark_mixed, drop_percent(base_mixed, fwmark_mixed),
	       fwmark_bursts, iterations * 2, fwmark_segments);
	if (fwmark_bursts != (unsigned int)iterations * 2)
		return 1;
	return 0;
}

int main(int argc, char **argv)
{
	const char *obj_path = BPF_OBJ;
	struct tc_attachment ingress = { 0 }, egress = { 0 };
	struct bpf_object *obj = NULL;
	struct fwmark_sample write_sample = { 0 };
	struct fwmark_sample write_gso_sample = { 0 };
	struct packet_meta scalar_meta = { 0 }, zero_meta = { 0 };
	struct packet_meta udp_gso_meta = { 0 }, tcp_gso_meta = { 0 };
	struct rlimit rlim = { RLIM_INFINITY, RLIM_INFINITY };
	struct tcp_packet syn = { 0 };
	size_t scalar_packet_len = 0, zero_packet_len = 0;
	size_t udp_gso_packet_len = 0, tcp_gso_packet_len = 0;
	int tun_fd = -1, tcp_fd = -1, err = 1;

	setrlimit(RLIMIT_MEMLOCK, &rlim);
	if (argc > 1 && strcmp(argv[1], "--bench") == 0) {
		int iterations = argc > 2 ? atoi(argv[2]) : 2000;

		return run_bench(obj_path, iterations);
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
	if (configure_mpls_encap_route(DEV_NAME))
		goto out;
	if (attach_bpf(DEV_NAME, obj_path, &obj, &ingress, &egress))
		goto out;

	if (write_marked_udp_packet_to_tun(tun_fd))
		goto out;
	if (poll_fwmark_sample(obj, 0, &write_sample)) {
		fprintf(stderr, "write-path fwmark sample not recorded\n");
		goto out;
	}
	if (write_sample.mark != EXPECTED_MARK || write_sample.gso_size != 0) {
		fprintf(stderr, "unexpected write-path sample mark=0x%08x gso_size=%u\n",
			write_sample.mark, write_sample.gso_size);
		goto out;
	}

	if (write_marked_udp_gso_to_tun(tun_fd))
		goto out;
	if (poll_fwmark_sample(obj, 1, &write_gso_sample)) {
		fprintf(stderr, "write-path UDP GSO fwmark sample not recorded\n");
		goto out;
	}
	if (write_gso_sample.mark != EXPECTED_MARK ||
	    write_gso_sample.gso_size != GSO_SIZE ||
	    write_gso_sample.ip_proto != IPPROTO_UDP) {
		fprintf(stderr,
			"unexpected write-path GSO sample mark=0x%08x gso_size=%u ip_proto=%u\n",
			write_gso_sample.mark, write_gso_sample.gso_size,
			write_gso_sample.ip_proto);
		goto out;
	}

	if (send_udp_datagram(SECOND_MARK, 64))
		goto out;
	if (read_mpls_udp_from_tun(tun_fd, SECOND_MARK, &scalar_packet_len,
				   &scalar_meta))
		goto out;

	if (send_udp_datagram(0, 32))
		goto out;
	if (read_mpls_udp_from_tun(tun_fd, 0, &zero_packet_len, &zero_meta))
		goto out;

	if (send_marked_udp_gso())
		goto out;
	for (int seg = 0; seg < 3; seg++) {
		size_t one_packet_len = 0;

		if (read_mpls_udp_from_tun(tun_fd, EXPECTED_MARK,
					   &one_packet_len, &udp_gso_meta)) {
			fprintf(stderr, "UDP MPLS segment TUN read failed\n");
			goto out;
		}
		udp_gso_packet_len += one_packet_len - 4;
	}

	tcp_fd = start_marked_tcp_client();
	if (tcp_fd < 0)
		goto out;
	if (read_mpls_tcp_from_tun(tun_fd, EXPECTED_MARK, &syn,
				   &(uint32_t){ 0 }, &(size_t){ 0 }, 0x02,
				   false))
		goto out;
	if (write_tcp_synack_to_tun(tun_fd, &syn, true))
		goto out;
	if (finish_tcp_connect(tcp_fd))
		goto out;
	if (send_tcp_payload(tcp_fd))
		goto out;
	{
		size_t received_payload = 0;

		while (received_payload < 1460 * 5) {
			struct tcp_packet data = { 0 };
			uint32_t payload_len = 0;
			size_t one_packet_len = 0;

			if (read_mpls_tcp_from_tun(tun_fd, EXPECTED_MARK,
						   &data, &payload_len,
						   &one_packet_len, 0x10, true)) {
				fprintf(stderr, "TCP MPLS segment TUN read failed\n");
				goto out;
			}
			if (write_tcp_ack_to_tun(tun_fd, &data, payload_len))
				goto out;
			received_payload += payload_len;
			tcp_gso_packet_len += one_packet_len - 4;
			tcp_gso_meta.gso_size = 0;
		}
	}
	printf("WRITE_PATH: imported mark=0x%08x len=%u\n",
	       write_sample.mark, write_sample.len);
	printf("WRITE_PATH_UDP_GSO: imported mark=0x%08x len=%u gso_size=%u gso_segs=%u\n",
	       write_gso_sample.mark, write_gso_sample.len,
	       write_gso_sample.gso_size, write_gso_sample.gso_segs);
	printf("READ_PATH_MPLS_UDP_SCALAR: mark=0x%08x len=%u tun_len=%zu\n",
	       SECOND_MARK, scalar_meta.len, scalar_packet_len);
	printf("READ_PATH_MPLS_ZERO_MARK: mark=0x%08x len=%u tun_len=%zu\n",
	       0, zero_meta.len, zero_packet_len);
	printf("READ_PATH_MPLS_UDP_SEGMENTS: mark=0x%08x last_len=%u gso_size=%u tun_len=%zu\n",
	       EXPECTED_MARK, udp_gso_meta.len, udp_gso_meta.gso_size,
	       udp_gso_packet_len);
	printf("READ_PATH_MPLS_TCP_SEGMENTS: mark=0x%08x len=%u gso_size=%u tun_len=%zu\n",
	       EXPECTED_MARK, tcp_gso_meta.len, tcp_gso_meta.gso_size,
	       tcp_gso_packet_len);
	printf("PASS: TUN write path imports fwmark; TUN read path exports fwmark in an MPLS shim after route encap; MPLS packets are read as scalar segments on this TUN device\n");
	err = 0;

out:
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
