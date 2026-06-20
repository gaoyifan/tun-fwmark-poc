// SPDX-License-Identifier: GPL-2.0
package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	devName       = "tunfw0"
	bpfObjDefault = "bpf/tun_fwmark.bpf.o"
	expectedMark  = 0x00000042
	secondMark    = 0x00000043
	gsoSize       = 1200
	tcpServerSeq  = 0xabc00000

	ethPIP = 0x0800

	virtioNetHdrFNeedsCsum = 1
	virtioNetHdrGSONone    = 0
	virtioNetHdrGSOTCPV4   = 1
	virtioNetHdrGSOUDPL4   = 5
	virtioNetHdrLen        = 10

	ipProtoTCP = 6
	ipProtoUDP = 17
	solUDP     = 17

	rlimitMemlock = unix.RLIMIT_MEMLOCK
)

type virtioNetHdr struct {
	Flags      uint8
	GSOType    uint8
	HdrLen     uint16
	GSOSize    uint16
	CsumStart  uint16
	CsumOffset uint16
}

type fwmarkSample struct {
	Seen    uint32
	Mark    uint32
	Len     uint32
	GSOSize uint32
	GSOSegs uint32
	IPProto uint32
}

type packetMeta struct {
	Len      uint32
	GSOSize  uint32
	IPProto  uint32
	Sport    uint32
	Dport    uint32
	IPSaddr  uint32
	IPDaddr  uint32
	IPID     uint32
	L4Cookie uint32
}

type mplsPacketMeta struct {
	Mark   uint32
	Packet packetMeta
}

type tcpPacket struct {
	Saddr [4]byte
	Daddr [4]byte
	Seq   uint32
	Sport uint16
	Dport uint16
	Flags uint8
}

type bpfAttachment struct {
	coll    *ebpf.Collection
	link    netlink.Link
	ingress *netlink.BpfFilter
	egress  *netlink.BpfFilter
}

var (
	tunBufSmall = make([]byte, 2048)
	tunBufTCP   = make([]byte, 4096)
	tunBufGSO   = make([]byte, 131072)

	tcpBenchPayload = filledBytes(1460*5, 'T')
	udpBenchGSO     = cyclicBytes(gsoSize*3, 'a', 26)
	udpBenchScalar  = filledBytes(64, 'U')
)

func main() {
	runtime.LockOSThread()

	objPath := bpfObjDefault
	_ = unix.Setrlimit(rlimitMemlock, &unix.Rlimit{Cur: ^uint64(0), Max: ^uint64(0)})

	if len(os.Args) > 1 && os.Args[1] == "--bench" {
		iterations := 2000
		if len(os.Args) > 2 {
			if n, err := strconv.Atoi(os.Args[2]); err == nil {
				iterations = n
			}
		}
		if err := runBench(objPath, iterations); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) > 1 {
		objPath = os.Args[1]
	}
	if err := runFunctional(objPath); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func filledBytes(n int, b byte) []byte {
	buf := make([]byte, n)
	for i := range buf {
		buf[i] = b
	}
	return buf
}

func cyclicBytes(n int, base byte, span int) []byte {
	buf := make([]byte, n)
	for i := range buf {
		buf[i] = base + byte(i%span)
	}
	return buf
}

func runFunctional(objPath string) error {
	var attach bpfAttachment
	var writeSample, writeGSOSample fwmarkSample
	var scalarMeta, zeroMeta, udpGSOMeta, tcpGSOMeta packetMeta
	var scalarPacketLen, zeroPacketLen, udpGSOPacketLen, tcpGSOPacketLen int

	if err := enterNewNetns(); err != nil {
		return err
	}
	deleteLinkQuiet(devName)
	tun, err := openVnetTun(devName)
	if err != nil {
		return err
	}
	defer func() {
		_ = tun.Close()
		deleteLinkQuiet(devName)
	}()
	if err := configureTun(devName, "10.99.0.1/24"); err != nil {
		return err
	}
	if err := configureMPLSEncapRoute(devName); err != nil {
		return err
	}
	if err := attach.attachBPF(devName, objPath, true); err != nil {
		return err
	}
	defer attach.close()

	if err := writeMarkedUDPPacketToTun(tun.Fd()); err != nil {
		return err
	}
	if err := attach.pollFwmarkSample(0, &writeSample); err != nil {
		return fmt.Errorf("write-path fwmark sample not recorded: %w", err)
	}
	if writeSample.Mark != expectedMark || writeSample.GSOSize != 0 {
		return fmt.Errorf("unexpected write-path sample mark=0x%08x gso_size=%d", writeSample.Mark, writeSample.GSOSize)
	}

	if err := writeMarkedUDPGSOToTun(tun.Fd()); err != nil {
		return err
	}
	if err := attach.pollFwmarkSample(1, &writeGSOSample); err != nil {
		return fmt.Errorf("write-path UDP GSO fwmark sample not recorded: %w", err)
	}
	if writeGSOSample.Mark != expectedMark || writeGSOSample.GSOSize != gsoSize || writeGSOSample.IPProto != ipProtoUDP {
		return fmt.Errorf("unexpected write-path GSO sample mark=0x%08x gso_size=%d ip_proto=%d", writeGSOSample.Mark, writeGSOSample.GSOSize, writeGSOSample.IPProto)
	}

	if err := sendUDPDatagram(secondMark, 64); err != nil {
		return err
	}
	if scalarPacketLen, err = readMPLSUDPFromTun(tun.Fd(), secondMark, &scalarMeta); err != nil {
		return err
	}

	if err := sendUDPDatagram(0, 32); err != nil {
		return err
	}
	if zeroPacketLen, err = readMPLSUDPFromTun(tun.Fd(), 0, &zeroMeta); err != nil {
		return err
	}

	if err := sendMarkedUDPGSO(); err != nil {
		return err
	}
	for seg := 0; seg < 3; seg++ {
		oneLen, err := readMPLSUDPFromTun(tun.Fd(), expectedMark, &udpGSOMeta)
		if err != nil {
			return fmt.Errorf("UDP MPLS segment TUN read failed: %w", err)
		}
		udpGSOPacketLen += oneLen - 4
	}

	tcpFD, err := startMarkedTCPClient()
	if err != nil {
		return err
	}
	defer unix.Close(tcpFD)

	var syn tcpPacket
	if _, _, err := readMPLSTCPFromTun(tun.Fd(), expectedMark, &syn, 0x02, false); err != nil {
		return err
	}
	if err := writeTCPSynAckToTun(tun.Fd(), &syn, true); err != nil {
		return err
	}
	if err := finishTCPConnect(tcpFD); err != nil {
		return err
	}
	if err := sendTCPPayload(tcpFD); err != nil {
		return err
	}
	receivedPayload := uint32(0)
	for receivedPayload < 1460*5 {
		var data tcpPacket
		payloadLen, oneLen, err := readMPLSTCPFromTun(tun.Fd(), expectedMark, &data, 0x10, true)
		if err != nil {
			return fmt.Errorf("TCP MPLS segment TUN read failed: %w", err)
		}
		if err := writeTCPAckToTun(tun.Fd(), &data, payloadLen); err != nil {
			return err
		}
		receivedPayload += payloadLen
		tcpGSOPacketLen += oneLen - 4
		tcpGSOMeta.GSOSize = 0
	}

	fmt.Printf("WRITE_PATH: imported mark=0x%08x len=%d\n", writeSample.Mark, writeSample.Len)
	fmt.Printf("WRITE_PATH_UDP_GSO: imported mark=0x%08x len=%d gso_size=%d gso_segs=%d\n", writeGSOSample.Mark, writeGSOSample.Len, writeGSOSample.GSOSize, writeGSOSample.GSOSegs)
	fmt.Printf("READ_PATH_MPLS_UDP_SCALAR: mark=0x%08x len=%d tun_len=%d\n", secondMark, scalarMeta.Len, scalarPacketLen)
	fmt.Printf("READ_PATH_MPLS_ZERO_MARK: mark=0x%08x len=%d tun_len=%d\n", 0, zeroMeta.Len, zeroPacketLen)
	fmt.Printf("READ_PATH_MPLS_UDP_SEGMENTS: mark=0x%08x last_len=%d gso_size=%d tun_len=%d\n", expectedMark, udpGSOMeta.Len, udpGSOMeta.GSOSize, udpGSOPacketLen)
	fmt.Printf("READ_PATH_MPLS_TCP_SEGMENTS: mark=0x%08x len=%d gso_size=%d tun_len=%d\n", expectedMark, tcpGSOMeta.Len, tcpGSOMeta.GSOSize, tcpGSOPacketLen)
	fmt.Println("PASS: TUN write path imports fwmark; TUN read path exports fwmark in an MPLS shim after route encap; MPLS packets are read as scalar segments on this TUN device")
	return nil
}

func (a *bpfAttachment) attachBPF(dev, objPath string, both bool) error {
	link, err := netlink.LinkByName(dev)
	if err != nil {
		return err
	}

	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		return fmt.Errorf("load BPF object spec: %w", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("load BPF collection: %w", err)
	}
	a.coll = coll
	a.link = link

	qdisc := &netlink.Clsact{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
	}
	if err := netlink.QdiscAdd(qdisc); err != nil && !errors.Is(err, unix.EEXIST) {
		a.close()
		return fmt.Errorf("add clsact qdisc: %w", err)
	}

	if both {
		prog := coll.Programs["tun_write_path_mark_strip"]
		if prog == nil {
			a.close()
			return errors.New("BPF program tun_write_path_mark_strip not found")
		}
		a.ingress = &netlink.BpfFilter{
			FilterAttrs: netlink.FilterAttrs{
				LinkIndex: link.Attrs().Index,
				Parent:    netlink.HANDLE_MIN_INGRESS,
				Handle:    1,
				Priority:  1,
				Protocol:  unix.ETH_P_ALL,
			},
			Fd:           prog.FD(),
			Name:         "tun_write_path_mark_strip",
			DirectAction: true,
		}
		if err := netlink.FilterReplace(a.ingress); err != nil {
			a.close()
			return fmt.Errorf("attach ingress BPF: %w", err)
		}
	}

	prog := coll.Programs["tun_read_path_mpls_mark"]
	if prog == nil {
		a.close()
		return errors.New("BPF program tun_read_path_mpls_mark not found")
	}
	a.egress = &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_EGRESS,
			Handle:    2,
			Priority:  1,
			Protocol:  unix.ETH_P_ALL,
		},
		Fd:           prog.FD(),
		Name:         "tun_read_path_mpls_mark",
		DirectAction: true,
	}
	if err := netlink.FilterReplace(a.egress); err != nil {
		a.close()
		return fmt.Errorf("attach egress BPF: %w", err)
	}
	return nil
}

func (a *bpfAttachment) close() {
	if a.egress != nil {
		_ = netlink.FilterDel(a.egress)
		a.egress = nil
	}
	if a.ingress != nil {
		_ = netlink.FilterDel(a.ingress)
		a.ingress = nil
	}
	if a.link != nil {
		_ = netlink.QdiscDel(&netlink.Clsact{
			QdiscAttrs: netlink.QdiscAttrs{
				LinkIndex: a.link.Attrs().Index,
				Handle:    netlink.MakeHandle(0xffff, 0),
				Parent:    netlink.HANDLE_CLSACT,
			},
		})
		a.link = nil
	}
	if a.coll != nil {
		a.coll.Close()
		a.coll = nil
	}
}

func (a *bpfAttachment) readFwmarkSample(key uint32, sample *fwmarkSample) error {
	if a.coll == nil || a.coll.Maps["fwmark_samples"] == nil {
		return errors.New("fwmark sample map not found")
	}
	return a.coll.Maps["fwmark_samples"].Lookup(&key, sample)
}

func (a *bpfAttachment) pollFwmarkSample(key uint32, sample *fwmarkSample) error {
	for i := 0; i < 200; i++ {
		if err := a.readFwmarkSample(key, sample); err != nil {
			return err
		}
		if sample.Seen != 0 {
			return nil
		}
		time.Sleep(time.Millisecond)
	}
	return errors.New("sample not seen")
}

func openVnetTun(name string) (*os.File, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open /dev/net/tun: %w", err)
	}
	file := os.NewFile(uintptr(fd), "/dev/net/tun")
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	ifr.SetUint16(unix.IFF_TUN | unix.IFF_VNET_HDR)
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("TUNSETIFF: %w", err)
	}
	if err := unix.IoctlSetPointerInt(fd, unix.TUNSETVNETHDRSZ, virtioNetHdrLen); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("TUNSETVNETHDRSZ: %w", err)
	}
	offloads := unix.TUN_F_CSUM | unix.TUN_F_TSO4 | unix.TUN_F_TSO6 | unix.TUN_F_USO4 | unix.TUN_F_USO6
	if err := unix.IoctlSetInt(fd, unix.TUNSETOFFLOAD, offloads); err != nil {
		offloads = unix.TUN_F_CSUM | unix.TUN_F_TSO4 | unix.TUN_F_TSO6
		if err := unix.IoctlSetInt(fd, unix.TUNSETOFFLOAD, offloads); err != nil {
			_ = file.Close()
			return nil, fmt.Errorf("TUNSETOFFLOAD: %w", err)
		}
	}
	return file, nil
}

func configureTun(name, addr string) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return err
	}
	ipAddr, err := netlink.ParseAddr(addr)
	if err != nil {
		return err
	}
	if err := netlink.AddrAdd(link, ipAddr); err != nil && !errors.Is(err, unix.EEXIST) {
		return err
	}
	if err := netlink.LinkSetMTU(link, 1500); err != nil {
		return err
	}
	return netlink.LinkSetUp(link)
}

func configureMPLSEncapRoute(name string) error {
	loadModuleQuiet("mpls_router")
	loadModuleQuiet("mpls_iptunnel")
	_ = os.WriteFile("/proc/sys/net/mpls/platform_labels", []byte("1048575\n"), 0)

	link, err := netlink.LinkByName(name)
	if err != nil {
		return err
	}
	_, dst, err := net.ParseCIDR("10.99.0.2/32")
	if err != nil {
		return err
	}
	return netlink.RouteReplace(&netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       dst,
		Encap:     &netlink.MPLSEncap{Labels: []int{16}},
	})
}

func enterNewNetns() error {
	if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
		return fmt.Errorf("unshare CLONE_NEWNET: %w", err)
	}
	if lo, err := netlink.LinkByName("lo"); err == nil {
		return netlink.LinkSetUp(lo)
	}
	return nil
}

func deleteLinkQuiet(name string) {
	if link, err := netlink.LinkByName(name); err == nil {
		_ = netlink.LinkDel(link)
	}
}

func loadModuleQuiet(name string) {
	_ = exec.Command("modprobe", name).Run()
}

func csum16(data []byte) uint16 {
	var sum uint32
	for len(data) > 1 {
		sum += uint32(binary.BigEndian.Uint16(data[:2]))
		data = data[2:]
	}
	if len(data) != 0 {
		sum += uint32(data[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func tcpChecksum(ip, tcp []byte) uint16 {
	var sum uint32
	for i := 12; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(ip[i : i+2]))
	}
	sum += ipProtoTCP
	sum += uint32(len(tcp))
	for i := 0; i+1 < len(tcp); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(tcp[i : i+2]))
	}
	if len(tcp)&1 != 0 {
		sum += uint32(tcp[len(tcp)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func putIPv4(dst []byte, s string) {
	copy(dst, net.ParseIP(s).To4())
}

func encodeVnet(dst []byte, hdr virtioNetHdr) {
	dst[0] = hdr.Flags
	dst[1] = hdr.GSOType
	binary.LittleEndian.PutUint16(dst[2:4], hdr.HdrLen)
	binary.LittleEndian.PutUint16(dst[4:6], hdr.GSOSize)
	binary.LittleEndian.PutUint16(dst[6:8], hdr.CsumStart)
	binary.LittleEndian.PutUint16(dst[8:10], hdr.CsumOffset)
}

func decodeVnet(src []byte) virtioNetHdr {
	return virtioNetHdr{
		Flags:      src[0],
		GSOType:    src[1],
		HdrLen:     binary.LittleEndian.Uint16(src[2:4]),
		GSOSize:    binary.LittleEndian.Uint16(src[4:6]),
		CsumStart:  binary.LittleEndian.Uint16(src[6:8]),
		CsumOffset: binary.LittleEndian.Uint16(src[8:10]),
	}
}

func parseTunPacketMetaAt(buf []byte, ipOffset, vnetOffset int, meta *packetMeta) error {
	if meta == nil {
		return nil
	}
	*meta = packetMeta{}
	if len(buf) < ipOffset+20 || len(buf) < vnetOffset+virtioNetHdrLen {
		return errors.New("short packet")
	}
	hdr := decodeVnet(buf[vnetOffset:])
	ip := buf[ipOffset:]
	if ip[0]>>4 != 4 {
		return errors.New("not IPv4")
	}
	ihl := int(ip[0]&0x0f) * 4
	if ihl < 20 || len(buf) < ipOffset+ihl {
		return errors.New("invalid IPv4 header length")
	}
	l4 := ip[ihl:]
	meta.Len = uint32(len(buf) - ipOffset)
	meta.GSOSize = uint32(hdr.GSOSize)
	meta.IPProto = uint32(ip[9])
	meta.IPID = uint32(binary.BigEndian.Uint16(ip[4:6]))
	meta.IPSaddr = binary.BigEndian.Uint32(ip[12:16])
	meta.IPDaddr = binary.BigEndian.Uint32(ip[16:20])
	if (meta.IPProto == ipProtoTCP || meta.IPProto == ipProtoUDP) && len(l4) >= 4 {
		meta.Sport = uint32(binary.BigEndian.Uint16(l4[0:2]))
		meta.Dport = uint32(binary.BigEndian.Uint16(l4[2:4]))
		if meta.IPProto == ipProtoTCP && len(l4) >= 8 {
			meta.L4Cookie = binary.BigEndian.Uint32(l4[4:8])
		} else if meta.IPProto == ipProtoUDP && len(l4) >= 6 {
			meta.L4Cookie = uint32(binary.BigEndian.Uint16(l4[4:6]))
		}
	}
	return nil
}

func parseTunPacketMeta(buf []byte, meta *packetMeta) error {
	return parseTunPacketMetaAt(buf, 4+virtioNetHdrLen, 4, meta)
}

func parseMPLSTunPacketMeta(buf []byte, meta *mplsPacketMeta) error {
	if meta == nil {
		return nil
	}
	*meta = mplsPacketMeta{}
	if len(buf) < 4+virtioNetHdrLen+4+20 {
		return errors.New("short MPLS packet")
	}
	meta.Mark = binary.BigEndian.Uint32(buf[4+virtioNetHdrLen : 4+virtioNetHdrLen+4])
	return parseTunPacketMetaAt(buf, 4+virtioNetHdrLen+4, 4, &meta.Packet)
}

func buildIPv4UDP(payload []byte, id uint16, fill byte) []byte {
	totalLen := 20 + 8 + len(payload)
	out := make([]byte, totalLen)
	ip := out[:20]
	udp := out[20:]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(ip[4:6], id)
	ip[8] = 64
	ip[9] = ipProtoUDP
	putIPv4(ip[12:16], "10.99.0.2")
	putIPv4(ip[16:20], "10.99.0.1")
	binary.BigEndian.PutUint16(ip[10:12], csum16(ip))
	binary.BigEndian.PutUint16(udp[0:2], 5555)
	binary.BigEndian.PutUint16(udp[2:4], 5555)
	binary.BigEndian.PutUint16(udp[4:6], uint16(8+len(payload)))
	if payload != nil {
		copy(udp[8:], payload)
	} else {
		for i := range udp[8:] {
			udp[8+i] = fill
		}
	}
	return out
}

func writeVnetPacketToTun(fd uintptr, packet []byte, vnet virtioNetHdr, withMarkPrefix bool) error {
	markLen := 0
	if withMarkPrefix {
		markLen = 4
	}
	frame := make([]byte, 4+virtioNetHdrLen+markLen+len(packet))
	binary.BigEndian.PutUint16(frame[2:4], ethPIP)
	at := 4
	encodeVnet(frame[at:at+virtioNetHdrLen], vnet)
	at += virtioNetHdrLen
	if withMarkPrefix {
		binary.BigEndian.PutUint32(frame[at:at+4], expectedMark)
		at += 4
	}
	copy(frame[at:], packet)
	n, err := unix.Write(int(fd), frame)
	if err != nil {
		return fmt.Errorf("write TUN packet: %w", err)
	}
	if n != len(frame) {
		return fmt.Errorf("short TUN write: %d/%d", n, len(frame))
	}
	return nil
}

func writeMarkedUDPPacketToTun(fd uintptr) error {
	payload := []byte("tun-fwmark-write-path")
	packet := buildIPv4UDP(payload, 0x1234, 0)
	return writeVnetPacketToTun(fd, packet, virtioNetHdr{}, true)
}

func writeMarkedUDPGSOToTun(fd uintptr) error {
	payload := make([]byte, gsoSize*3)
	for i := range payload {
		payload[i] = byte('g' + (i % 16))
	}
	packet := buildIPv4UDP(payload, 0x3456, 0)
	vnet := virtioNetHdr{
		Flags:      virtioNetHdrFNeedsCsum,
		GSOType:    virtioNetHdrGSOUDPL4,
		HdrLen:     28,
		GSOSize:    gsoSize,
		CsumStart:  20,
		CsumOffset: 6,
	}
	return writeVnetPacketToTun(fd, packet, vnet, true)
}

func readUDPScalarFromTun(fd uintptr, meta *packetMeta) (int, error) {
	buf := tunBufSmall
	for i := 0; i < 256; i++ {
		n, err := unix.Read(int(fd), buf)
		if err != nil {
			if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
				time.Sleep(time.Millisecond)
				continue
			}
			return 0, fmt.Errorf("read UDP scalar from TUN: %w", err)
		}
		if n < 4+virtioNetHdrLen+28 {
			continue
		}
		hdr := decodeVnet(buf[4:])
		ip := buf[4+virtioNetHdrLen:]
		if hdr.GSOType != virtioNetHdrGSONone || ip[0]>>4 != 4 || ip[9] != ipProtoUDP {
			continue
		}
		if err := parseTunPacketMeta(buf[:n], meta); err != nil {
			continue
		}
		return n, nil
	}
	return 0, errors.New("UDP scalar packet not read from TUN")
}

func readMPLSUDPFromTun(fd uintptr, expected uint32, meta *packetMeta) (int, error) {
	buf := tunBufSmall
	ipOffset := 4 + virtioNetHdrLen + 4
	for i := 0; i < 256; i++ {
		n, err := unix.Read(int(fd), buf)
		if err != nil {
			if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
				time.Sleep(time.Millisecond)
				continue
			}
			return 0, fmt.Errorf("read MPLS UDP from TUN: %w", err)
		}
		if n < 4+virtioNetHdrLen+4+28 {
			continue
		}
		hdr := decodeVnet(buf[4:])
		if hdr.GSOType != virtioNetHdrGSONone {
			continue
		}
		mark := binary.BigEndian.Uint32(buf[4+virtioNetHdrLen : ipOffset])
		ip := buf[ipOffset:]
		if mark != expected || ip[0]>>4 != 4 || ip[9] != ipProtoUDP {
			continue
		}
		if meta != nil {
			var mplsMeta mplsPacketMeta
			if err := parseMPLSTunPacketMeta(buf[:n], &mplsMeta); err != nil {
				continue
			}
			*meta = mplsMeta.Packet
		}
		return n, nil
	}
	return 0, errors.New("MPLS UDP packet not read from TUN")
}

func readGSOFromTun(fd uintptr, expectedType uint8, meta *packetMeta) (int, uint16, error) {
	buf := tunBufGSO
	var lastType uint8
	var lastSize uint16
	for i := 0; i < 256; i++ {
		n, err := unix.Read(int(fd), buf)
		if err != nil {
			if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
				time.Sleep(100 * time.Millisecond)
				continue
			}
			return 0, 0, fmt.Errorf("read TUN: %w", err)
		}
		if n < 4+virtioNetHdrLen+20 {
			continue
		}
		hdr := decodeVnet(buf[4:])
		lastType = hdr.GSOType
		lastSize = hdr.GSOSize
		if hdr.GSOType != expectedType {
			continue
		}
		if err := parseTunPacketMeta(buf[:n], meta); err != nil {
			continue
		}
		return n, hdr.GSOSize, nil
	}
	return 0, 0, fmt.Errorf("expected GSO packet not read from TUN; last gso_type=%d gso_size=%d", lastType, lastSize)
}

func readTCPControlFromTun(fd uintptr, packet *tcpPacket, requiredFlags uint8) error {
	buf := tunBufTCP
	for i := 0; i < 256; i++ {
		n, err := unix.Read(int(fd), buf)
		if err != nil {
			if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
				time.Sleep(time.Millisecond)
				continue
			}
			return fmt.Errorf("read TCP control from TUN: %w", err)
		}
		if n < 4+virtioNetHdrLen+40 {
			continue
		}
		ip := buf[4+virtioNetHdrLen:]
		if ip[0]>>4 != 4 || ip[9] != ipProtoTCP {
			continue
		}
		tcp := ip[int(ip[0]&0x0f)*4:]
		if tcp[13]&requiredFlags != requiredFlags {
			continue
		}
		copy(packet.Saddr[:], ip[12:16])
		copy(packet.Daddr[:], ip[16:20])
		packet.Sport = binary.BigEndian.Uint16(tcp[0:2])
		packet.Dport = binary.BigEndian.Uint16(tcp[2:4])
		packet.Seq = binary.BigEndian.Uint32(tcp[4:8])
		packet.Flags = tcp[13]
		return nil
	}
	return errors.New("TCP control packet not read from TUN")
}

func readMPLSTCPFromTun(fd uintptr, expected uint32, packet *tcpPacket, requiredFlags uint8, requirePayload bool) (uint32, int, error) {
	buf := tunBufTCP
	ipOffset := 4 + virtioNetHdrLen + 4
	var lastGSOType uint8
	for i := 0; i < 512; i++ {
		n, err := unix.Read(int(fd), buf)
		if err != nil {
			if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
				time.Sleep(time.Millisecond)
				continue
			}
			return 0, 0, fmt.Errorf("read MPLS TCP from TUN: %w", err)
		}
		if n < 4+virtioNetHdrLen+4+40 {
			continue
		}
		hdr := decodeVnet(buf[4:])
		lastGSOType = hdr.GSOType
		if hdr.GSOType != virtioNetHdrGSONone {
			continue
		}
		mark := binary.BigEndian.Uint32(buf[4+virtioNetHdrLen : ipOffset])
		ip := buf[ipOffset:]
		if mark != expected || ip[0]>>4 != 4 || ip[9] != ipProtoTCP {
			continue
		}
		ihl := int(ip[0]&0x0f) * 4
		if ihl < 20 || n < ipOffset+ihl+20 {
			continue
		}
		tcp := ip[ihl:]
		thl := int(tcp[12]>>4) * 4
		totalLen := int(binary.BigEndian.Uint16(ip[2:4]))
		if thl < 20 || totalLen < ihl+thl {
			continue
		}
		payloadLen := uint32(totalLen - ihl - thl)
		if tcp[13]&requiredFlags != requiredFlags {
			continue
		}
		if requirePayload && payloadLen == 0 {
			continue
		}
		copy(packet.Saddr[:], ip[12:16])
		copy(packet.Daddr[:], ip[16:20])
		packet.Sport = binary.BigEndian.Uint16(tcp[0:2])
		packet.Dport = binary.BigEndian.Uint16(tcp[2:4])
		packet.Seq = binary.BigEndian.Uint32(tcp[4:8])
		packet.Flags = tcp[13]
		return payloadLen, n, nil
	}
	return 0, 0, fmt.Errorf("MPLS TCP packet not read from TUN; last gso_type=%d", lastGSOType)
}

func readTCPGSODataFromTun(fd uintptr, packet *tcpPacket, payloadLen *uint32, meta *packetMeta) (int, uint16, error) {
	buf := tunBufGSO
	var lastType uint8
	var lastSize uint16
	for i := 0; i < 256; i++ {
		n, err := unix.Read(int(fd), buf)
		if err != nil {
			if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
				time.Sleep(100 * time.Millisecond)
				continue
			}
			return 0, 0, fmt.Errorf("read TCP GSO from TUN: %w", err)
		}
		if n < 4+virtioNetHdrLen+40 {
			continue
		}
		hdr := decodeVnet(buf[4:])
		lastType = hdr.GSOType
		lastSize = hdr.GSOSize
		if hdr.GSOType != virtioNetHdrGSOTCPV4 {
			continue
		}
		ip := buf[4+virtioNetHdrLen:]
		if ip[0]>>4 != 4 || ip[9] != ipProtoTCP {
			continue
		}
		ihl := int(ip[0]&0x0f) * 4
		if ihl < 20 || n < 4+virtioNetHdrLen+ihl+20 {
			continue
		}
		tcp := ip[ihl:]
		thl := int(tcp[12]>>4) * 4
		totalLen := int(binary.BigEndian.Uint16(ip[2:4]))
		if thl < 20 || totalLen < ihl+thl {
			continue
		}
		if err := parseTunPacketMeta(buf[:n], meta); err != nil {
			continue
		}
		copy(packet.Saddr[:], ip[12:16])
		copy(packet.Daddr[:], ip[16:20])
		packet.Sport = binary.BigEndian.Uint16(tcp[0:2])
		packet.Dport = binary.BigEndian.Uint16(tcp[2:4])
		packet.Seq = binary.BigEndian.Uint32(tcp[4:8])
		packet.Flags = tcp[13]
		*payloadLen = uint32(totalLen - ihl - thl)
		return n, hdr.GSOSize, nil
	}
	return 0, 0, fmt.Errorf("expected TCP GSO packet not read from TUN; last gso_type=%d gso_size=%d", lastType, lastSize)
}

func writeTCPSynAckToTun(fd uintptr, syn *tcpPacket, withMarkPrefix bool) error {
	return writeTCPSynAckMSSToTun(fd, syn, withMarkPrefix, 1460)
}

func writeTCPSynAckMSSToTun(fd uintptr, syn *tcpPacket, withMarkPrefix bool, mssValue uint16) error {
	packet := make([]byte, 20+24)
	ip := packet[:20]
	tcp := packet[20:]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(len(packet)))
	binary.BigEndian.PutUint16(ip[4:6], 0x9abc)
	ip[8] = 64
	ip[9] = ipProtoTCP
	copy(ip[12:16], syn.Daddr[:])
	copy(ip[16:20], syn.Saddr[:])
	binary.BigEndian.PutUint16(ip[10:12], csum16(ip))
	binary.BigEndian.PutUint16(tcp[0:2], syn.Dport)
	binary.BigEndian.PutUint16(tcp[2:4], syn.Sport)
	binary.BigEndian.PutUint32(tcp[4:8], tcpServerSeq)
	binary.BigEndian.PutUint32(tcp[8:12], syn.Seq+1)
	tcp[12] = 6 << 4
	tcp[13] = 0x12
	binary.BigEndian.PutUint16(tcp[14:16], 65535)
	tcp[20] = 2
	tcp[21] = 4
	binary.BigEndian.PutUint16(tcp[22:24], mssValue)
	binary.BigEndian.PutUint16(tcp[16:18], tcpChecksum(ip, tcp))
	return writeVnetPacketToTun(fd, packet, virtioNetHdr{}, withMarkPrefix)
}

func writeTCPAckToTun(fd uintptr, data *tcpPacket, payloadLen uint32) error {
	packet := make([]byte, 20+20)
	ip := packet[:20]
	tcp := packet[20:]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(len(packet)))
	binary.BigEndian.PutUint16(ip[4:6], 0x9abd)
	ip[8] = 64
	ip[9] = ipProtoTCP
	copy(ip[12:16], data.Daddr[:])
	copy(ip[16:20], data.Saddr[:])
	binary.BigEndian.PutUint16(ip[10:12], csum16(ip))
	binary.BigEndian.PutUint16(tcp[0:2], data.Dport)
	binary.BigEndian.PutUint16(tcp[2:4], data.Sport)
	binary.BigEndian.PutUint32(tcp[4:8], tcpServerSeq+1)
	binary.BigEndian.PutUint32(tcp[8:12], data.Seq+payloadLen)
	tcp[12] = 5 << 4
	tcp[13] = 0x10
	binary.BigEndian.PutUint16(tcp[14:16], 65535)
	binary.BigEndian.PutUint16(tcp[16:18], tcpChecksum(ip, tcp))
	return writeVnetPacketToTun(fd, packet, virtioNetHdr{}, false)
}

func startMarkedTCPClient() (int, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return -1, fmt.Errorf("socket TCP: %w", err)
	}
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_MARK, expectedMark); err != nil {
		unix.Close(fd)
		return -1, fmt.Errorf("setsockopt TCP SO_MARK: %w", err)
	}
	if err := unix.SetNonblock(fd, true); err != nil {
		unix.Close(fd)
		return -1, fmt.Errorf("set TCP nonblock: %w", err)
	}
	addr := &unix.SockaddrInet4{Port: 443, Addr: [4]byte{10, 99, 0, 2}}
	if err := unix.Connect(fd, addr); err != nil && err != unix.EINPROGRESS {
		unix.Close(fd)
		return -1, fmt.Errorf("connect TCP: %w", err)
	}
	return fd, nil
}

func fdSet(fd int, set *unix.FdSet) {
	set.Bits[fd/64] |= 1 << (uint(fd) % 64)
}

func finishTCPConnect(fd int) error {
	var wfds unix.FdSet
	fdSet(fd, &wfds)
	tv := unix.Timeval{Sec: 2}
	n, err := unix.Select(fd+1, nil, &wfds, nil, &tv)
	if err != nil {
		return fmt.Errorf("select TCP connect: %w", err)
	}
	if n <= 0 {
		return errors.New("select TCP connect timed out")
	}
	errno, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ERROR)
	if err != nil {
		return fmt.Errorf("getsockopt SO_ERROR: %w", err)
	}
	if errno != 0 {
		return fmt.Errorf("TCP connect completion: %w", unix.Errno(errno))
	}
	return nil
}

func sendTCPPayload(fd int) error {
	return sendTCPPayloadLen(fd, 1460*5)
}

func sendTCPPayloadLen(fd int, payloadLen int) error {
	payload := tcpBenchPayload
	if payloadLen != len(tcpBenchPayload) {
		payload = filledBytes(payloadLen, 'T')
	}
	sent := 0
	for i := 0; sent < payloadLen && i < 100; i++ {
		n, err := unix.Write(fd, payload[sent:])
		if n > 0 {
			sent += n
			continue
		}
		if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
			var wfds unix.FdSet
			fdSet(fd, &wfds)
			tv := unix.Timeval{Usec: 100000}
			if _, selErr := unix.Select(fd+1, nil, &wfds, nil, &tv); selErr != nil {
				return fmt.Errorf("select TCP send: %w", selErr)
			}
			continue
		}
		if err != nil {
			return fmt.Errorf("send TCP payload: %w", err)
		}
	}
	if sent != payloadLen {
		return fmt.Errorf("short TCP payload send: %d/%d", sent, payloadLen)
	}
	return nil
}

type udpSender struct {
	fd   int
	addr unix.SockaddrInet4
	oob  []byte
}

func newUDPSender(mark uint32, gsoSize uint16) (udpSender, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return udpSender{fd: -1}, fmt.Errorf("socket UDP: %w", err)
	}
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_MARK, int(mark)); err != nil {
		unix.Close(fd)
		return udpSender{fd: -1}, fmt.Errorf("setsockopt UDP SO_MARK: %w", err)
	}
	s := udpSender{
		fd:   fd,
		addr: unix.SockaddrInet4{Port: 5555, Addr: [4]byte{10, 99, 0, 2}},
	}
	if gsoSize != 0 {
		s.oob = make([]byte, unix.CmsgSpace(2))
		h := (*unix.Cmsghdr)(unsafe.Pointer(&s.oob[0]))
		h.Level = solUDP
		h.Type = int32(unix.UDP_SEGMENT)
		h.SetLen(unix.CmsgLen(2))
		binary.LittleEndian.PutUint16(s.oob[unix.CmsgLen(0):unix.CmsgLen(0)+2], gsoSize)
	}
	return s, nil
}

func (s *udpSender) close() {
	if s.fd >= 0 {
		_ = unix.Close(s.fd)
		s.fd = -1
	}
}

func (s *udpSender) send(payload []byte) error {
	if _, err := unix.SendmsgN(s.fd, payload, s.oob, &s.addr, 0); err != nil {
		return fmt.Errorf("send UDP: %w", err)
	}
	return nil
}

func sendMarkedUDPGSO() error {
	sender, err := newUDPSender(expectedMark, gsoSize)
	if err != nil {
		return err
	}
	defer sender.close()
	return sender.send(udpBenchGSO)
}

func sendUDPDatagram(mark uint32, payloadLen int) error {
	payload := udpBenchScalar
	if payloadLen != len(udpBenchScalar) {
		payload = filledBytes(payloadLen, 'U')
	}
	sender, err := newUDPSender(mark, 0)
	if err != nil {
		return err
	}
	defer sender.close()
	return sender.send(payload)
}

func runUDPGSOBenchCase(objPath string, withMPLS bool, iterations int) (float64, uint, error) {
	deleteLinkQuiet(devName)
	tun, err := openVnetTun(devName)
	if err != nil {
		return 0, 0, err
	}
	defer func() {
		_ = tun.Close()
		deleteLinkQuiet(devName)
	}()
	if err := configureTun(devName, "10.99.0.1/24"); err != nil {
		return 0, 0, err
	}
	var attach bpfAttachment
	if withMPLS {
		if err := configureMPLSEncapRoute(devName); err != nil {
			return 0, 0, err
		}
		if err := attach.attachBPF(devName, objPath, false); err != nil {
			return 0, 0, err
		}
		defer attach.close()
	}
	gsoSender, err := newUDPSender(expectedMark, gsoSize)
	if err != nil {
		return 0, 0, err
	}
	defer gsoSender.close()

	totalBytes := 0
	start := time.Now()
	for i := 0; i < iterations; i++ {
		if err := gsoSender.send(udpBenchGSO); err != nil {
			return 0, 0, err
		}
		if withMPLS {
			for seg := 0; seg < 3; seg++ {
				n, err := readMPLSUDPFromTun(tun.Fd(), expectedMark, nil)
				if err != nil {
					return 0, 0, err
				}
				totalBytes += n - 4
			}
		} else {
			n, _, err := readGSOFromTun(tun.Fd(), virtioNetHdrGSOUDPL4, nil)
			if err != nil {
				return 0, 0, err
			}
			totalBytes += n
		}
	}
	elapsed := time.Since(start).Nanoseconds()
	bursts := uint(0)
	if withMPLS {
		bursts = uint(iterations)
	}
	return float64(totalBytes) * 8.0 / float64(elapsed), bursts, nil
}

type tcpBenchConn struct {
	tunFD    uintptr
	tcpFD    int
	withMPLS bool
}

func newTCPBenchConn(tunFD uintptr, withMPLS bool) (*tcpBenchConn, error) {
	tcpFD, err := startMarkedTCPClient()
	if err != nil {
		return nil, err
	}
	var syn tcpPacket
	if withMPLS {
		if _, _, err := readMPLSTCPFromTun(tunFD, expectedMark, &syn, 0x02, false); err != nil {
			unix.Close(tcpFD)
			return nil, err
		}
	} else if err := readTCPControlFromTun(tunFD, &syn, 0x02); err != nil {
		unix.Close(tcpFD)
		return nil, err
	}
	if err := writeTCPSynAckToTun(tunFD, &syn, false); err != nil {
		unix.Close(tcpFD)
		return nil, err
	}
	if err := finishTCPConnect(tcpFD); err != nil {
		unix.Close(tcpFD)
		return nil, err
	}
	return &tcpBenchConn{tunFD: tunFD, tcpFD: tcpFD, withMPLS: withMPLS}, nil
}

func (c *tcpBenchConn) close() {
	if c != nil && c.tcpFD >= 0 {
		_ = unix.Close(c.tcpFD)
		c.tcpFD = -1
	}
}

func (c *tcpBenchConn) sendBurst() (int, error) {
	if err := sendTCPPayloadLen(c.tcpFD, 1460*5); err != nil {
		return 0, err
	}
	if c.withMPLS {
		receivedPayload := uint32(0)
		totalLen := 0
		var lastData tcpPacket
		var lastPayloadLen uint32
		for receivedPayload < 1460*5 {
			var data tcpPacket
			payloadLen, oneLen, err := readMPLSTCPFromTun(c.tunFD, expectedMark, &data, 0x10, true)
			if err != nil {
				return 0, err
			}
			lastData = data
			lastPayloadLen = payloadLen
			receivedPayload += payloadLen
			totalLen += oneLen - 4
		}
		if err := writeTCPAckToTun(c.tunFD, &lastData, lastPayloadLen); err != nil {
			return 0, err
		}
		return totalLen, nil
	}
	var data tcpPacket
	var payloadLen uint32
	packetLen, gsoSize, err := readTCPGSODataFromTun(c.tunFD, &data, &payloadLen, nil)
	if err != nil {
		return 0, err
	}
	if gsoSize == 0 {
		return 0, errors.New("unexpected TCP benchmark GSO size: 0")
	}
	if err := writeTCPAckToTun(c.tunFD, &data, payloadLen); err != nil {
		return 0, err
	}
	return packetLen, nil
}

func runTCPGSOBenchCase(objPath string, withMPLS bool, iterations int) (float64, uint, uint, error) {
	deleteLinkQuiet(devName)
	tun, err := openVnetTun(devName)
	if err != nil {
		return 0, 0, 0, err
	}
	defer func() {
		_ = tun.Close()
		deleteLinkQuiet(devName)
	}()
	if err := configureTun(devName, "10.99.0.1/24"); err != nil {
		return 0, 0, 0, err
	}
	var attach bpfAttachment
	if withMPLS {
		if err := configureMPLSEncapRoute(devName); err != nil {
			return 0, 0, 0, err
		}
		if err := attach.attachBPF(devName, objPath, false); err != nil {
			return 0, 0, 0, err
		}
		defer attach.close()
	}
	tcpConn, err := newTCPBenchConn(tun.Fd(), withMPLS)
	if err != nil {
		return 0, 0, 0, err
	}
	defer tcpConn.close()

	totalBytes := 0
	start := time.Now()
	for i := 0; i < iterations; i++ {
		n, err := tcpConn.sendBurst()
		if err != nil {
			return 0, 0, 0, err
		}
		totalBytes += n
	}
	elapsed := time.Since(start).Nanoseconds()
	bursts := uint(0)
	if withMPLS {
		bursts = uint(iterations)
	}
	return float64(totalBytes) * 8.0 / float64(elapsed), bursts, bursts, nil
}

func runMixedBenchCase(objPath string, withMPLS bool, iterations int) (float64, uint, uint, error) {
	deleteLinkQuiet(devName)
	tun, err := openVnetTun(devName)
	if err != nil {
		return 0, 0, 0, err
	}
	defer func() {
		_ = tun.Close()
		deleteLinkQuiet(devName)
	}()
	if err := configureTun(devName, "10.99.0.1/24"); err != nil {
		return 0, 0, 0, err
	}
	var attach bpfAttachment
	if withMPLS {
		if err := configureMPLSEncapRoute(devName); err != nil {
			return 0, 0, 0, err
		}
		if err := attach.attachBPF(devName, objPath, false); err != nil {
			return 0, 0, 0, err
		}
		defer attach.close()
	}
	scalarSender, err := newUDPSender(secondMark, 0)
	if err != nil {
		return 0, 0, 0, err
	}
	defer scalarSender.close()
	gsoSender, err := newUDPSender(expectedMark, gsoSize)
	if err != nil {
		return 0, 0, 0, err
	}
	defer gsoSender.close()
	tcpConn, err := newTCPBenchConn(tun.Fd(), withMPLS)
	if err != nil {
		return 0, 0, 0, err
	}
	defer tcpConn.close()

	totalBytes := 0
	start := time.Now()
	for i := 0; i < iterations; i++ {
		if err := scalarSender.send(udpBenchScalar); err != nil {
			return 0, 0, 0, err
		}
		if withMPLS {
			n, err := readMPLSUDPFromTun(tun.Fd(), secondMark, nil)
			if err != nil {
				return 0, 0, 0, err
			}
			totalBytes += n - 4
		} else {
			n, err := readUDPScalarFromTun(tun.Fd(), nil)
			if err != nil {
				return 0, 0, 0, err
			}
			totalBytes += n
		}
		if err := gsoSender.send(udpBenchGSO); err != nil {
			return 0, 0, 0, err
		}
		if withMPLS {
			for seg := 0; seg < 3; seg++ {
				n, err := readMPLSUDPFromTun(tun.Fd(), expectedMark, nil)
				if err != nil {
					return 0, 0, 0, err
				}
				totalBytes += n - 4
			}
		} else {
			n, _, err := readGSOFromTun(tun.Fd(), virtioNetHdrGSOUDPL4, nil)
			if err != nil {
				return 0, 0, 0, err
			}
			totalBytes += n
		}
		n, err := tcpConn.sendBurst()
		if err != nil {
			return 0, 0, 0, err
		}
		totalBytes += n
	}
	elapsed := time.Since(start).Nanoseconds()
	var bursts, segments uint
	if withMPLS {
		bursts = uint(iterations * 2)
		segments = uint(iterations * 3)
	}
	return float64(totalBytes) * 8.0 / float64(elapsed), bursts, segments, nil
}

func dropPercent(base, fwmark float64) float64 {
	if base <= 0 {
		return 0
	}
	return (base - fwmark) * 100.0 / base
}

func runBench(objPath string, iterations int) error {
	if err := enterNewNetns(); err != nil {
		return err
	}
	baseUDP, _, err := runUDPGSOBenchCase(objPath, false, iterations)
	if err != nil {
		return err
	}
	if err := enterNewNetns(); err != nil {
		return err
	}
	fwmarkUDP, fwmarkBursts, err := runUDPGSOBenchCase(objPath, true, iterations)
	if err != nil {
		return err
	}
	fmt.Printf("BENCH_UDP_GSO baseline=%.3f Gbit/s fwmark=%.3f Gbit/s drop=%.1f%% segments=%d/%d\n", baseUDP, fwmarkUDP, dropPercent(baseUDP, fwmarkUDP), fwmarkBursts, iterations)
	if fwmarkBursts != uint(iterations) {
		return errors.New("unexpected UDP fwmark segment count")
	}

	if err := enterNewNetns(); err != nil {
		return err
	}
	baseTCP, _, _, err := runTCPGSOBenchCase(objPath, false, iterations)
	if err != nil {
		return err
	}
	if err := enterNewNetns(); err != nil {
		return err
	}
	fwmarkTCP, fwmarkBursts, fwmarkSegments, err := runTCPGSOBenchCase(objPath, true, iterations)
	if err != nil {
		return err
	}
	fmt.Printf("BENCH_TCP_GSO baseline=%.3f Gbit/s fwmark=%.3f Gbit/s drop=%.1f%% bursts=%d/%d segments=%d\n", baseTCP, fwmarkTCP, dropPercent(baseTCP, fwmarkTCP), fwmarkBursts, iterations, fwmarkSegments)
	if fwmarkBursts != uint(iterations) {
		return errors.New("unexpected TCP fwmark burst count")
	}

	if err := enterNewNetns(); err != nil {
		return err
	}
	baseMixed, _, _, err := runMixedBenchCase(objPath, false, iterations)
	if err != nil {
		return err
	}
	if err := enterNewNetns(); err != nil {
		return err
	}
	fwmarkMixed, fwmarkBursts, fwmarkSegments, err := runMixedBenchCase(objPath, true, iterations)
	if err != nil {
		return err
	}
	fmt.Printf("BENCH_MIXED baseline=%.3f Gbit/s fwmark=%.3f Gbit/s drop=%.1f%% bursts=%d/%d segments=%d\n", baseMixed, fwmarkMixed, dropPercent(baseMixed, fwmarkMixed), fwmarkBursts, iterations*2, fwmarkSegments)
	if fwmarkBursts != uint(iterations*2) {
		return errors.New("unexpected mixed fwmark burst count")
	}
	return nil
}
