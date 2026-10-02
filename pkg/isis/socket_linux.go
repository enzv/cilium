// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package isis

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"golang.org/x/sys/unix"
)

const (
	llcHeaderLength = 3
	maxISISPDUSize  = maxLSPPDUSize

	packetFilterLoadByteAbsolute uint16 = 0x30
	packetFilterJumpEqual        uint16 = 0x15
	packetFilterReturn           uint16 = 0x06
)

var (
	isisLLCHeader = [llcHeaderLength]byte{0xfe, 0xfe, 0x03}
	// AllISs is the recommended multicast destination for point-to-point
	// IS-IS operation over LAN media (RFC 5309).
	allISsAddress = [6]byte{0x09, 0x00, 0x2b, 0x00, 0x00, 0x05}

	errPacketSocketTimeout   = errors.New("IS-IS packet socket read timed out")
	errPacketNotISISEthernet = errors.New("packet does not contain IS-IS LLC encapsulation")
)

type packetSocket struct {
	fd      int
	ifindex int
	mtu     int
	ipv4    netip.Addr
}

func openPacketSocket(interfaceName string) (_ *packetSocket, err error) {
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return nil, fmt.Errorf("find IS-IS interface %q: %w", interfaceName, err)
	}
	if iface.Flags&net.FlagUp == 0 {
		return nil, fmt.Errorf("IS-IS interface %q is down", interfaceName)
	}
	if iface.MTU <= llcHeaderLength {
		return nil, fmt.Errorf("IS-IS interface %q MTU %d is too small", interfaceName, iface.MTU)
	}
	ipv4, err := interfaceIPv4(iface)
	if err != nil {
		return nil, err
	}

	protocol := hostToNetwork16(unix.ETH_P_ALL)
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, int(protocol))
	if err != nil {
		return nil, fmt.Errorf("open AF_PACKET socket: %w", err)
	}
	defer func() {
		if err != nil {
			_ = unix.Close(fd)
		}
	}()

	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: protocol, Ifindex: iface.Index}); err != nil {
		return nil, fmt.Errorf("bind IS-IS packet socket to %q: %w", interfaceName, err)
	}
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 1<<20); err != nil {
		return nil, fmt.Errorf("set IS-IS receive buffer: %w", err)
	}
	if err := unix.SetsockoptInt(fd, unix.SOL_PACKET, unix.PACKET_IGNORE_OUTGOING, 1); err != nil {
		return nil, fmt.Errorf("ignore outgoing IS-IS packets: %w", err)
	}
	membership := &unix.PacketMreq{
		Ifindex: int32(iface.Index),
		Type:    unix.PACKET_MR_MULTICAST,
		Alen:    uint16(len(allISsAddress)),
	}
	copy(membership.Address[:], allISsAddress[:])
	if err := unix.SetsockoptPacketMreq(fd, unix.SOL_PACKET, unix.PACKET_ADD_MEMBERSHIP, membership); err != nil {
		return nil, fmt.Errorf("join AllISs multicast on %q: %w", interfaceName, err)
	}
	if err := attachISISPDUFilter(fd); err != nil {
		return nil, fmt.Errorf("attach IS-IS packet filter: %w", err)
	}

	return &packetSocket{fd: fd, ifindex: iface.Index, mtu: iface.MTU, ipv4: ipv4}, nil
}

func interfaceIPv4(iface *net.Interface) (netip.Addr, error) {
	addresses, err := iface.Addrs()
	if err != nil {
		return netip.Addr{}, fmt.Errorf("list addresses for IS-IS interface %q: %w", iface.Name, err)
	}
	var ipv4 netip.Addr
	for _, address := range addresses {
		prefix, err := netip.ParsePrefix(address.String())
		if err != nil || !prefix.Addr().Is4() || prefix.Addr().IsUnspecified() {
			continue
		}
		if ipv4.IsValid() {
			return netip.Addr{}, fmt.Errorf("IS-IS interface %q has more than one IPv4 address", iface.Name)
		}
		ipv4 = prefix.Addr()
	}
	if !ipv4.IsValid() {
		return netip.Addr{}, fmt.Errorf("IS-IS interface %q must have an IPv4 address", iface.Name)
	}
	return ipv4, nil
}

func (s *packetSocket) receive(ctx context.Context, timeout time.Duration) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	timeoutMillis := int(timeout / time.Millisecond)
	if timeoutMillis < 1 {
		timeoutMillis = 1
	}
	pollFD := []unix.PollFd{{Fd: int32(s.fd), Events: unix.POLLIN}}
	ready, err := unix.Poll(pollFD, timeoutMillis)
	if err != nil {
		if errors.Is(err, unix.EINTR) {
			return nil, errPacketSocketTimeout
		}
		return nil, fmt.Errorf("poll IS-IS packet socket: %w", err)
	}
	if ready == 0 {
		return nil, errPacketSocketTimeout
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	bufferSize := min(s.mtu, maxISISPDUSize+llcHeaderLength)
	buffer := make([]byte, bufferSize)
	n, _, flags, _, err := unix.Recvmsg(s.fd, buffer, nil, unix.MSG_DONTWAIT)
	if err != nil {
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EINTR) {
			return nil, errPacketSocketTimeout
		}
		return nil, fmt.Errorf("receive IS-IS packet: %w", err)
	}
	if flags&unix.MSG_TRUNC != 0 {
		return nil, fmt.Errorf("drop truncated IS-IS Ethernet payload")
	}
	return decodeLLCPayload(buffer[:n])
}

func decodeLLCPayload(payload []byte) ([]byte, error) {
	if len(payload) < len(isisLLCHeader) || string(payload[:llcHeaderLength]) != string(isisLLCHeader[:]) {
		return nil, errPacketNotISISEthernet
	}
	return payload[llcHeaderLength:], nil
}

func (s *packetSocket) send(packet []byte) error {
	if len(packet) > maxISISPDUSize || len(packet)+llcHeaderLength > s.mtu {
		return fmt.Errorf("IS-IS PDU size %d exceeds interface MTU %d", len(packet), s.mtu-llcHeaderLength)
	}
	frame := make([]byte, 0, len(packet)+llcHeaderLength)
	frame = append(frame, isisLLCHeader[:]...)
	frame = append(frame, packet...)
	address := &unix.SockaddrLinklayer{
		// For an 802.3 frame, sll_protocol carries the LLC payload length.
		// FRR uses the same convention for its SOCK_DGRAM packet socket.
		Protocol: hostToNetwork16(uint16(len(frame))),
		Ifindex:  s.ifindex,
		Halen:    uint8(len(allISsAddress)),
	}
	copy(address.Addr[:], allISsAddress[:])
	if err := unix.Sendto(s.fd, frame, 0, address); err != nil {
		return fmt.Errorf("send IS-IS packet: %w", err)
	}
	return nil
}

func (s *packetSocket) close() error {
	if s.fd < 0 {
		return nil
	}
	err := unix.Close(s.fd)
	s.fd = -1
	return err
}

func (s *packetSocket) mtuSize() int {
	return s.mtu - llcHeaderLength
}

func (s *packetSocket) localIPv4() netip.Addr {
	return s.ipv4
}

func (s *packetSocket) circuitID() uint32 {
	return uint32(s.ifindex)
}

func attachISISPDUFilter(fd int) error {
	filter := isisPDUFilter()
	program := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	return unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &program)
}

func isisPDUFilter() []unix.SockFilter {
	return []unix.SockFilter{
		{Code: packetFilterLoadByteAbsolute, K: 0},
		{Code: packetFilterJumpEqual, Jf: 9, K: 0xfe},
		{Code: packetFilterLoadByteAbsolute, K: 1},
		{Code: packetFilterJumpEqual, Jf: 7, K: 0xfe},
		{Code: packetFilterLoadByteAbsolute, K: 2},
		{Code: packetFilterJumpEqual, Jf: 5, K: 0x03},
		{Code: packetFilterLoadByteAbsolute, K: 7},
		{Code: packetFilterJumpEqual, Jt: 4, K: uint32(pduTypeP2PHello)},
		{Code: packetFilterJumpEqual, Jt: 3, K: uint32(pduTypeL2LSP)},
		{Code: packetFilterJumpEqual, Jt: 2, K: uint32(pduTypeL2CSNP)},
		{Code: packetFilterJumpEqual, Jt: 1, K: uint32(pduTypeL2PSNP)},
		{Code: packetFilterReturn, K: 0},
		{Code: packetFilterReturn, K: 0xffff},
	}
}

func hostToNetwork16(value uint16) uint16 {
	var bytes [2]byte
	binary.BigEndian.PutUint16(bytes[:], value)
	return binary.NativeEndian.Uint16(bytes[:])
}
