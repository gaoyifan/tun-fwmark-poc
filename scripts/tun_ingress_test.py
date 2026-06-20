#!/usr/bin/env python3
import argparse
import errno
import fcntl
import os
import re
import socket
import struct
import subprocess
import sys
import time

TUNSETIFF = 0x400454CA
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000
ETH_P_IP = 0x0800


def checksum(data):
    if len(data) & 1:
        data += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def open_tun(name, no_pi):
    fd = os.open("/dev/net/tun", os.O_RDWR | os.O_CLOEXEC)
    flags = IFF_TUN | (IFF_NO_PI if no_pi else 0)
    fcntl.ioctl(fd, TUNSETIFF, struct.pack("16sH22x", name.encode(), flags))
    return fd


def make_echo_request(src, dst, ident):
    payload = b"tun-fwmark-poc"
    icmp = struct.pack("!BBHHH", 8, 0, 0, ident, 1) + payload
    icmp = struct.pack("!BBHHH", 8, 0, checksum(icmp), ident, 1) + payload
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, 20 + len(icmp), ident, 0, 64, socket.IPPROTO_ICMP, 0,
        socket.inet_aton(src), socket.inet_aton(dst),
    )
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    return ip + icmp


def write_marked_ipv4(fd, mark, ident):
    tun_pi = struct.pack("!HH", 0, ETH_P_IP)
    mark_hdr = struct.pack("!I", mark)
    ip_packet = make_echo_request("10.0.0.2", "203.0.113.1", ident)
    os.write(fd, tun_pi + mark_hdr + ip_packet)


def nft_counter():
    out = subprocess.check_output(
        ["nft", "list", "chain", "ip", "fwmarkpoc", "prerouting"],
        text=True,
    )
    match = re.search(r"counter packets (\d+)", out)
    return int(match.group(1)) if match else -1


def prove_no_pi_rejects_prefix():
    fd = open_tun("tunbad0", no_pi=True)
    try:
        subprocess.run(["ip", "link", "set", "tunbad0", "up"], check=True)
        pkt = struct.pack("!I", 0x42) + make_echo_request("10.0.0.2", "10.0.0.1", 1)
        try:
            os.write(fd, pkt)
        except OSError as exc:
            if exc.errno == errno.EINVAL:
                print("NO_PI_NEGATIVE: write rejected with EINVAL as expected")
                return
            raise
        raise RuntimeError("IFF_NO_PI unexpectedly accepted the prefixed packet")
    finally:
        os.close(fd)
        subprocess.run(["ip", "link", "del", "tunbad0"], stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL)


def configure_validation(dev, obj):
    subprocess.run(["ip", "addr", "add", "10.0.0.1/24", "dev", dev], check=True)
    subprocess.run(["ip", "link", "set", dev, "up"], check=True)
    subprocess.run(["tc", "qdisc", "add", "dev", dev, "clsact"], check=True)
    subprocess.run([
        "tc", "filter", "add", "dev", dev, "ingress", "bpf", "da",
        "obj", obj, "sec", "classifier",
    ], check=True)
    subprocess.run(["nft", "add", "table", "ip", "fwmarkpoc"], check=True)
    subprocess.run([
        "nft", "add", "chain", "ip", "fwmarkpoc", "prerouting",
        "{", "type", "filter", "hook", "prerouting", "priority",
        "mangle", ";", "policy", "accept", ";", "}",
    ], check=True)
    subprocess.run([
        "nft", "add", "rule", "ip", "fwmarkpoc", "prerouting",
        "meta", "mark", "0x42",
        "ip", "saddr", "10.0.0.2",
        "ip", "daddr", "203.0.113.1",
        "counter",
    ], check=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dev", default="tunpoc0")
    parser.add_argument("--obj", default="bpf/tun_ingress_mark_strip.bpf.o")
    args = parser.parse_args()

    prove_no_pi_rejects_prefix()

    fd = open_tun(args.dev, no_pi=False)
    try:
        configure_validation(args.dev, args.obj)
        write_marked_ipv4(fd, 0x41, 0x4100)
        time.sleep(0.2)
        wrong = nft_counter()
        print(f"SCENARIO: nft packets after wrong mark={wrong}")

        write_marked_ipv4(fd, 0x42, 0x4200)
        time.sleep(0.2)
        right = nft_counter()
        print(f"SCENARIO: nft packets after expected mark={right}")

        if wrong != 0 or right != 1:
            return 1
        return 0
    finally:
        os.close(fd)


if __name__ == "__main__":
    sys.exit(main())
