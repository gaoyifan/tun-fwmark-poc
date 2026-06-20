#!/usr/bin/env python3
import argparse
import ctypes
import errno
import fcntl
import os
import socket
import struct
import subprocess
import sys
import time

TUNSETIFF = 0x400454CA
IFF_TUN = 0x0001
ETH_P_IP = 0x0800
SO_MARK = 36
SO_RCVMARK = 75


def open_pi_tun(name):
    fd = os.open("/dev/net/tun", os.O_RDWR | os.O_NONBLOCK | os.O_CLOEXEC)
    ifr = struct.pack("16sH22x", name.encode(), IFF_TUN)
    fcntl.ioctl(fd, TUNSETIFF, ifr)
    return fd


def setsockopt_on_fd(fd, optname, value):
    libc = ctypes.CDLL(None, use_errno=True)
    val = ctypes.c_int(value)
    ret = libc.setsockopt(fd, socket.SOL_SOCKET, optname,
                          ctypes.byref(val), ctypes.sizeof(val))
    if ret != 0:
        return ctypes.get_errno()
    return 0


def configure(dev, obj=None):
    subprocess.run(["ip", "addr", "add", "10.55.0.1/24", "dev", dev], check=True)
    subprocess.run(["ip", "link", "set", dev, "up"], check=True)
    subprocess.run(["ip", "route", "add", "203.0.113.9/32", "dev", dev], check=True)
    if obj:
        subprocess.run(["tc", "qdisc", "add", "dev", dev, "clsact"], check=True)
        subprocess.run([
            "tc", "filter", "add", "dev", dev, "egress", "bpf", "da",
            "obj", obj, "sec", "classifier",
        ], check=True)


def send_marked_udp(mark):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, SO_MARK, mark)
        sock.sendto(b"tun-egress-fwmark-poc", ("203.0.113.9", 9999))
    finally:
        sock.close()


def read_tun_packet(fd):
    deadline = time.time() + 2.0
    while time.time() < deadline:
        try:
            packet = os.read(fd, 4096)
        except BlockingIOError:
            time.sleep(0.02)
            continue
        if len(packet) >= 4:
            flags, proto = struct.unpack("!HH", packet[:4])
            if flags == 0 and proto == ETH_P_IP:
                return packet
    raise TimeoutError("no IPv4 packet read from TUN")


def describe_packet(label, packet):
    payload = packet[4:]
    first = payload[:8].hex()
    prefixed = len(payload) >= 5 and payload[:4] == b"\x00\x00\x00\x42" and payload[4] == 0x45
    plain = len(payload) >= 1 and payload[0] == 0x45
    print(f"{label}: len={len(packet)} payload_first8={first} plain_ipv4={plain} mark_prefix={prefixed}")
    return plain, prefixed


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dev", default="tunout0")
    parser.add_argument("--obj")
    args = parser.parse_args()

    fd = open_pi_tun(args.dev)
    try:
        errno_rcvmark = setsockopt_on_fd(fd, SO_RCVMARK, 1)
        print(f"NATIVE: setsockopt(SO_RCVMARK) errno={errno_rcvmark} ({errno.errorcode.get(errno_rcvmark, 'OK')})")

        configure(args.dev, args.obj)
        send_marked_udp(0x42)
        packet = read_tun_packet(fd)
        plain, prefixed = describe_packet("READ", packet)

        if args.obj:
            return 0 if prefixed else 1
        return 0 if plain and not prefixed else 1
    finally:
        os.close(fd)


if __name__ == "__main__":
    sys.exit(main())
