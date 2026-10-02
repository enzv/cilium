// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package isis

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
)

const (
	protocolDiscriminator = 0x83
	protocolVersion       = 1
	defaultIDLength       = 0

	commonHeaderLength = 8
	systemIDLength     = 6
	nodeIDLength       = 7
	lspIDLength        = 8
	maxLSPPDUSize      = 0xffff
	maxTLVValueLength  = 255
	maxAreaAddressSize = 13
)

const (
	pduTypeP2PHello pduType = 17
	pduTypeL2LSP    pduType = 20
	pduTypeL2CSNP   pduType = 25
	pduTypeL2PSNP   pduType = 27
)

const (
	tlvAreaAddresses           byte = 1
	tlvLSPEntries              byte = 9
	tlvExtendedISReachability  byte = 22
	tlvProtocolsSupported      byte = 129
	tlvIPv4InterfaceAddresses  byte = 132
	tlvExtendedIPReachability  byte = 135
	tlvP2PThreeWayAdjacency    byte = 240
	ipv4NetworkLayerProtocolID byte = 0xcc
	lspFlagOverload            byte = 0x04
	lspFlagLevel2IS            byte = 0x03
	threeWayStateUp            byte = 0
	threeWayStateInitializing  byte = 1
	threeWayStateDown          byte = 2
)

const (
	p2pHelloHeaderLength = 20
	lspHeaderLength      = 27
	csnpHeaderLength     = 33
	psnpHeaderLength     = 17

	lspLengthOffset      = 8
	lspIDOffset          = 12
	lspChecksumOffset    = 24
	p2pHelloLengthOffset = 17
	snpLengthOffset      = 8
)

var (
	errMalformedPDU = errors.New("malformed IS-IS PDU")
	errMalformedTLV = errors.New("malformed IS-IS TLV")
)

type pduType byte
type systemID [systemIDLength]byte
type nodeID [nodeIDLength]byte
type lspID [lspIDLength]byte

// tlv stores an uninterpreted TLV. Keeping its value opaque lets an LSP retain
// unknown extensions for flooding without treating them as invalid.
type tlv struct {
	code  byte
	value []byte
}

type areaAddress []byte

type lspEntry struct {
	remainingLifetime uint16
	id                lspID
	sequenceNumber    uint32
	checksum          uint16
}

type extendedISReachabilityEntry struct {
	neighborID nodeID
	metric     uint32
	subTLVs    []byte
}

type extendedIPReachabilityEntry struct {
	metric  uint32
	upDown  bool
	prefix  netip.Prefix
	subTLVs []byte
}

type threeWayAdjacency struct {
	state                byte
	localCircuitID       uint32
	neighborSystemID     systemID
	hasNeighborSystemID  bool
	neighborCircuitID    uint32
	hasNeighborCircuitID bool
}

type p2pHelloPDU struct {
	circuitType    byte
	sourceID       systemID
	holdingTime    uint16
	localCircuitID byte
	tlvData        []byte
}

type lspPDU struct {
	remainingLifetime uint16
	id                lspID
	sequenceNumber    uint32
	checksum          uint16
	flags             byte
	tlvData           []byte
	raw               []byte
}

type csnpPDU struct {
	sourceID nodeID
	startID  lspID
	endID    lspID
	tlvData  []byte
}

type psnpPDU struct {
	sourceID nodeID
	tlvData  []byte
}

func appendTLV(dst []byte, code byte, value []byte) ([]byte, error) {
	if len(value) > maxTLVValueLength {
		return nil, fmt.Errorf("TLV %d value is %d bytes; maximum is %d", code, len(value), maxTLVValueLength)
	}
	dst = append(dst, code, byte(len(value)))
	dst = append(dst, value...)
	return dst, nil
}

func encodeTLVs(tlvs []tlv) ([]byte, error) {
	var data []byte
	for _, item := range tlvs {
		var err error
		data, err = appendTLV(data, item.code, item.value)
		if err != nil {
			return nil, err
		}
	}
	return data, nil
}

func decodeTLVs(data []byte) ([]tlv, error) {
	tlvs := make([]tlv, 0, len(data)/2)
	for len(data) != 0 {
		if len(data) < 2 {
			return nil, fmt.Errorf("%w: truncated TLV header", errMalformedTLV)
		}
		valueLength := int(data[1])
		if valueLength > len(data)-2 {
			return nil, fmt.Errorf("%w: TLV %d length %d exceeds remaining data", errMalformedTLV, data[0], valueLength)
		}
		tlvs = append(tlvs, tlv{code: data[0], value: data[2 : 2+valueLength]})
		data = data[2+valueLength:]
	}
	return tlvs, nil
}

func encodeAreaAddresses(addresses []areaAddress) (tlv, error) {
	var value []byte
	for _, address := range addresses {
		if len(address) == 0 || len(address) > maxAreaAddressSize {
			return tlv{}, fmt.Errorf("area address length %d is outside 1..%d", len(address), maxAreaAddressSize)
		}
		if len(value)+1+len(address) > maxTLVValueLength {
			return tlv{}, fmt.Errorf("area addresses exceed TLV length limit")
		}
		value = append(value, byte(len(address)))
		value = append(value, address...)
	}
	if len(value) == 0 {
		return tlv{}, fmt.Errorf("area address TLV must contain at least one address")
	}
	return tlv{code: tlvAreaAddresses, value: value}, nil
}

func decodeAreaAddresses(value []byte) ([]areaAddress, error) {
	var addresses []areaAddress
	for len(value) != 0 {
		addressLength := int(value[0])
		if addressLength == 0 || addressLength > maxAreaAddressSize {
			return nil, fmt.Errorf("%w: invalid area address length %d", errMalformedTLV, addressLength)
		}
		if addressLength > len(value)-1 {
			return nil, fmt.Errorf("%w: area address length %d exceeds remaining data", errMalformedTLV, addressLength)
		}
		addresses = append(addresses, areaAddress(value[1:1+addressLength]))
		value = value[1+addressLength:]
	}
	if len(addresses) == 0 {
		return nil, fmt.Errorf("%w: empty area address TLV", errMalformedTLV)
	}
	return addresses, nil
}

func encodeProtocolsSupported(protocols []byte) (tlv, error) {
	if len(protocols) == 0 || len(protocols) > maxTLVValueLength {
		return tlv{}, fmt.Errorf("protocols supported TLV length %d is outside 1..%d", len(protocols), maxTLVValueLength)
	}
	return tlv{code: tlvProtocolsSupported, value: bytes.Clone(protocols)}, nil
}

func decodeProtocolsSupported(value []byte) ([]byte, error) {
	if len(value) == 0 {
		return nil, fmt.Errorf("%w: empty protocols supported TLV", errMalformedTLV)
	}
	return bytes.Clone(value), nil
}

func encodeIPv4InterfaceAddresses(addresses []netip.Addr) (tlv, error) {
	if len(addresses) == 0 || len(addresses) > maxTLVValueLength/4 {
		return tlv{}, fmt.Errorf("IPv4 interface address count %d is outside 1..%d", len(addresses), maxTLVValueLength/4)
	}
	value := make([]byte, 0, len(addresses)*4)
	for _, address := range addresses {
		if !address.Is4() {
			return tlv{}, fmt.Errorf("interface address %s is not IPv4", address)
		}
		ipv4 := address.As4()
		value = append(value, ipv4[:]...)
	}
	return tlv{code: tlvIPv4InterfaceAddresses, value: value}, nil
}

func decodeIPv4InterfaceAddresses(value []byte) ([]netip.Addr, error) {
	if len(value) == 0 || len(value)%4 != 0 {
		return nil, fmt.Errorf("%w: IPv4 interface address TLV length %d is not a non-zero multiple of 4", errMalformedTLV, len(value))
	}
	addresses := make([]netip.Addr, 0, len(value)/4)
	for len(value) != 0 {
		var address [4]byte
		copy(address[:], value[:4])
		addresses = append(addresses, netip.AddrFrom4(address))
		value = value[4:]
	}
	return addresses, nil
}

func encodeLSPEntries(entries []lspEntry) (tlv, error) {
	valueLength := len(entries) * 16
	if valueLength > maxTLVValueLength {
		return tlv{}, fmt.Errorf("LSP entries require %d bytes; maximum is %d", valueLength, maxTLVValueLength)
	}
	value := make([]byte, 0, valueLength)
	for _, entry := range entries {
		var encoded [16]byte
		binary.BigEndian.PutUint16(encoded[0:2], entry.remainingLifetime)
		copy(encoded[2:10], entry.id[:])
		binary.BigEndian.PutUint32(encoded[10:14], entry.sequenceNumber)
		binary.BigEndian.PutUint16(encoded[14:16], entry.checksum)
		value = append(value, encoded[:]...)
	}
	return tlv{code: tlvLSPEntries, value: value}, nil
}

func decodeLSPEntries(value []byte) ([]lspEntry, error) {
	if len(value)%16 != 0 {
		return nil, fmt.Errorf("%w: LSP entries length %d is not a multiple of 16", errMalformedTLV, len(value))
	}
	entries := make([]lspEntry, 0, len(value)/16)
	for len(value) != 0 {
		var entry lspEntry
		entry.remainingLifetime = binary.BigEndian.Uint16(value[0:2])
		copy(entry.id[:], value[2:10])
		entry.sequenceNumber = binary.BigEndian.Uint32(value[10:14])
		entry.checksum = binary.BigEndian.Uint16(value[14:16])
		entries = append(entries, entry)
		value = value[16:]
	}
	return entries, nil
}

func encodeExtendedISReachability(entries []extendedISReachabilityEntry) (tlv, error) {
	var value []byte
	for _, entry := range entries {
		if entry.metric > 0xffffff {
			return tlv{}, fmt.Errorf("extended IS metric %d exceeds 24 bits", entry.metric)
		}
		if len(entry.subTLVs) > 244 {
			return tlv{}, fmt.Errorf("extended IS sub-TLV data is %d bytes; maximum is 244", len(entry.subTLVs))
		}
		if _, err := decodeTLVs(entry.subTLVs); err != nil {
			return tlv{}, fmt.Errorf("invalid extended IS sub-TLV data: %w", err)
		}
		if len(value)+11+len(entry.subTLVs) > maxTLVValueLength {
			return tlv{}, fmt.Errorf("extended IS reachability entries exceed TLV length limit")
		}
		value = append(value, entry.neighborID[:]...)
		value = append(value, byte(entry.metric>>16), byte(entry.metric>>8), byte(entry.metric), byte(len(entry.subTLVs)))
		value = append(value, entry.subTLVs...)
	}
	return tlv{code: tlvExtendedISReachability, value: value}, nil
}

func decodeExtendedISReachability(value []byte) ([]extendedISReachabilityEntry, error) {
	var entries []extendedISReachabilityEntry
	for len(value) != 0 {
		if len(value) < 11 {
			return nil, fmt.Errorf("%w: extended IS reachability entry is shorter than 11 bytes", errMalformedTLV)
		}
		var entry extendedISReachabilityEntry
		copy(entry.neighborID[:], value[:nodeIDLength])
		entry.metric = uint32(value[7])<<16 | uint32(value[8])<<8 | uint32(value[9])
		subTLVLength := int(value[10])
		if subTLVLength > len(value)-11 {
			return nil, fmt.Errorf("%w: extended IS sub-TLV length %d exceeds remaining data", errMalformedTLV, subTLVLength)
		}
		entry.subTLVs = value[11 : 11+subTLVLength]
		if _, err := decodeTLVs(entry.subTLVs); err != nil {
			return nil, fmt.Errorf("%w: invalid extended IS sub-TLV data: %v", errMalformedTLV, err)
		}
		entries = append(entries, entry)
		value = value[11+subTLVLength:]
	}
	return entries, nil
}

func encodeExtendedIPReachability(entries []extendedIPReachabilityEntry) (tlv, error) {
	var value []byte
	for _, entry := range entries {
		if !entry.prefix.IsValid() || !entry.prefix.Addr().Is4() {
			return tlv{}, fmt.Errorf("extended IP prefix %s is not a valid IPv4 prefix", entry.prefix)
		}
		if len(entry.subTLVs) > 250 {
			return tlv{}, fmt.Errorf("extended IP sub-TLV data is %d bytes; maximum is 250", len(entry.subTLVs))
		}
		if _, err := decodeTLVs(entry.subTLVs); err != nil {
			return tlv{}, fmt.Errorf("invalid extended IP sub-TLV data: %w", err)
		}
		prefix := entry.prefix.Masked()
		prefixLength := prefix.Bits()
		prefixOctets := (prefixLength + 7) / 8
		entryLength := 5 + prefixOctets
		if len(entry.subTLVs) != 0 {
			entryLength += 1 + len(entry.subTLVs)
		}
		if len(value)+entryLength > maxTLVValueLength {
			return tlv{}, fmt.Errorf("extended IP reachability entries exceed TLV length limit")
		}
		var metric [4]byte
		binary.BigEndian.PutUint32(metric[:], entry.metric)
		value = append(value, metric[:]...)
		control := byte(prefixLength)
		if entry.upDown {
			control |= 0x80
		}
		if len(entry.subTLVs) != 0 {
			control |= 0x40
		}
		value = append(value, control)
		if prefixOctets != 0 {
			address := prefix.Addr().As4()
			value = append(value, address[:prefixOctets]...)
		}
		if len(entry.subTLVs) != 0 {
			value = append(value, byte(len(entry.subTLVs)))
			value = append(value, entry.subTLVs...)
		}
	}
	return tlv{code: tlvExtendedIPReachability, value: value}, nil
}

func decodeExtendedIPReachability(value []byte) ([]extendedIPReachabilityEntry, error) {
	var entries []extendedIPReachabilityEntry
	for len(value) != 0 {
		if len(value) < 5 {
			return nil, fmt.Errorf("%w: extended IP reachability entry is shorter than 5 bytes", errMalformedTLV)
		}
		entry := extendedIPReachabilityEntry{metric: binary.BigEndian.Uint32(value[:4])}
		control := value[4]
		prefixLength := int(control & 0x3f)
		if prefixLength > 32 {
			return nil, fmt.Errorf("%w: invalid IPv4 prefix length %d", errMalformedTLV, prefixLength)
		}
		entry.upDown = control&0x80 != 0
		prefixOctets := (prefixLength + 7) / 8
		if prefixOctets > len(value)-5 {
			return nil, fmt.Errorf("%w: IPv4 prefix needs %d bytes", errMalformedTLV, prefixOctets)
		}
		var address [4]byte
		copy(address[:], value[5:5+prefixOctets])
		entry.prefix = netip.PrefixFrom(netip.AddrFrom4(address), prefixLength).Masked()
		consumed := 5 + prefixOctets
		if control&0x40 != 0 {
			if len(value)-consumed < 1 {
				return nil, fmt.Errorf("%w: missing extended IP sub-TLV length", errMalformedTLV)
			}
			subTLVLength := int(value[consumed])
			consumed++
			if subTLVLength > len(value)-consumed {
				return nil, fmt.Errorf("%w: extended IP sub-TLV length %d exceeds remaining data", errMalformedTLV, subTLVLength)
			}
			entry.subTLVs = value[consumed : consumed+subTLVLength]
			if _, err := decodeTLVs(entry.subTLVs); err != nil {
				return nil, fmt.Errorf("%w: invalid extended IP sub-TLV data: %v", errMalformedTLV, err)
			}
			consumed += subTLVLength
		}
		entries = append(entries, entry)
		value = value[consumed:]
	}
	return entries, nil
}

func encodeThreeWayAdjacency(adjacency threeWayAdjacency) (tlv, error) {
	if adjacency.state > threeWayStateDown {
		return tlv{}, fmt.Errorf("invalid three-way adjacency state %d", adjacency.state)
	}
	if adjacency.hasNeighborCircuitID && !adjacency.hasNeighborSystemID {
		return tlv{}, fmt.Errorf("neighbor circuit ID requires a neighbor system ID")
	}
	value := []byte{adjacency.state}
	var localCircuitID [4]byte
	binary.BigEndian.PutUint32(localCircuitID[:], adjacency.localCircuitID)
	value = append(value, localCircuitID[:]...)
	if adjacency.hasNeighborSystemID {
		value = append(value, adjacency.neighborSystemID[:]...)
	}
	if adjacency.hasNeighborCircuitID {
		var neighborCircuitID [4]byte
		binary.BigEndian.PutUint32(neighborCircuitID[:], adjacency.neighborCircuitID)
		value = append(value, neighborCircuitID[:]...)
	}
	return tlv{code: tlvP2PThreeWayAdjacency, value: value}, nil
}

func decodeThreeWayAdjacency(value []byte) (threeWayAdjacency, error) {
	var adjacency threeWayAdjacency
	if len(value) != 1 && len(value) != 5 && len(value) != 11 && len(value) != 15 {
		return adjacency, fmt.Errorf("%w: three-way adjacency TLV length %d is invalid for a six-byte system ID", errMalformedTLV, len(value))
	}
	adjacency.state = value[0]
	if adjacency.state > threeWayStateDown {
		return adjacency, fmt.Errorf("%w: invalid three-way adjacency state %d", errMalformedTLV, adjacency.state)
	}
	if len(value) >= 5 {
		adjacency.localCircuitID = binary.BigEndian.Uint32(value[1:5])
	}
	if len(value) >= 11 {
		copy(adjacency.neighborSystemID[:], value[5:11])
		adjacency.hasNeighborSystemID = true
	}
	if len(value) == 15 {
		adjacency.neighborCircuitID = binary.BigEndian.Uint32(value[11:15])
		adjacency.hasNeighborCircuitID = true
	}
	return adjacency, nil
}

func (p p2pHelloPDU) marshalBinary() ([]byte, error) {
	if p.circuitType == 0 || p.circuitType&^byte(0x03) != 0 {
		return nil, fmt.Errorf("invalid P2P circuit type %d", p.circuitType)
	}
	length := p2pHelloHeaderLength + len(p.tlvData)
	if length > 0xffff {
		return nil, fmt.Errorf("P2P IIH length %d exceeds 65535 bytes", length)
	}
	data := makeCommonHeader(pduTypeP2PHello, p2pHelloHeaderLength)
	data = append(data, p.circuitType)
	data = append(data, p.sourceID[:]...)
	data = binary.BigEndian.AppendUint16(data, p.holdingTime)
	data = binary.BigEndian.AppendUint16(data, uint16(length))
	data = append(data, p.localCircuitID)
	data = append(data, p.tlvData...)
	return data, nil
}

func decodeP2PHello(data []byte) (p2pHelloPDU, error) {
	var p p2pHelloPDU
	data, err := validatePDU(data, pduTypeP2PHello, p2pHelloHeaderLength, p2pHelloLengthOffset)
	if err != nil {
		return p, err
	}
	p.circuitType = data[8]
	if p.circuitType == 0 || p.circuitType&^byte(0x03) != 0 {
		return p, fmt.Errorf("%w: invalid P2P circuit type %d", errMalformedPDU, p.circuitType)
	}
	copy(p.sourceID[:], data[9:15])
	p.holdingTime = binary.BigEndian.Uint16(data[15:17])
	p.localCircuitID = data[19]
	p.tlvData = data[p2pHelloHeaderLength:]
	return p, nil
}

func (p lspPDU) marshalBinary() ([]byte, error) {
	length := lspHeaderLength + len(p.tlvData)
	if length > maxLSPPDUSize {
		return nil, fmt.Errorf("LSP length %d exceeds 65535 bytes", length)
	}
	data := makeCommonHeader(pduTypeL2LSP, lspHeaderLength)
	data = binary.BigEndian.AppendUint16(data, uint16(length))
	data = binary.BigEndian.AppendUint16(data, p.remainingLifetime)
	data = append(data, p.id[:]...)
	data = binary.BigEndian.AppendUint32(data, p.sequenceNumber)
	data = binary.BigEndian.AppendUint16(data, 0)
	data = append(data, p.flags)
	data = append(data, p.tlvData...)
	setLSPChecksum(data)
	return data, nil
}

func decodeLSP(data []byte) (lspPDU, error) {
	var p lspPDU
	data, err := validatePDU(data, pduTypeL2LSP, lspHeaderLength, lspLengthOffset)
	if err != nil {
		return p, err
	}
	p.remainingLifetime = binary.BigEndian.Uint16(data[10:12])
	p.checksum = binary.BigEndian.Uint16(data[lspChecksumOffset : lspChecksumOffset+2])
	if !(p.remainingLifetime == 0 && p.checksum == 0) && !validLSPChecksum(data) {
		return p, fmt.Errorf("%w: invalid LSP checksum", errMalformedPDU)
	}
	copy(p.id[:], data[lspIDOffset:lspIDOffset+lspIDLength])
	p.sequenceNumber = binary.BigEndian.Uint32(data[20:24])
	p.flags = data[26]
	p.raw = bytes.Clone(data)
	p.tlvData = p.raw[lspHeaderLength:]
	return p, nil
}

func (p csnpPDU) marshalBinary() ([]byte, error) {
	length := csnpHeaderLength + len(p.tlvData)
	if length > 0xffff {
		return nil, fmt.Errorf("CSNP length %d exceeds 65535 bytes", length)
	}
	data := makeCommonHeader(pduTypeL2CSNP, csnpHeaderLength)
	data = binary.BigEndian.AppendUint16(data, uint16(length))
	data = append(data, p.sourceID[:]...)
	data = append(data, p.startID[:]...)
	data = append(data, p.endID[:]...)
	data = append(data, p.tlvData...)
	return data, nil
}

func decodeCSNP(data []byte) (csnpPDU, error) {
	var p csnpPDU
	data, err := validatePDU(data, pduTypeL2CSNP, csnpHeaderLength, snpLengthOffset)
	if err != nil {
		return p, err
	}
	copy(p.sourceID[:], data[10:17])
	copy(p.startID[:], data[17:25])
	copy(p.endID[:], data[25:33])
	p.tlvData = data[csnpHeaderLength:]
	return p, nil
}

func (p psnpPDU) marshalBinary() ([]byte, error) {
	length := psnpHeaderLength + len(p.tlvData)
	if length > 0xffff {
		return nil, fmt.Errorf("PSNP length %d exceeds 65535 bytes", length)
	}
	data := makeCommonHeader(pduTypeL2PSNP, psnpHeaderLength)
	data = binary.BigEndian.AppendUint16(data, uint16(length))
	data = append(data, p.sourceID[:]...)
	data = append(data, p.tlvData...)
	return data, nil
}

func decodePSNP(data []byte) (psnpPDU, error) {
	var p psnpPDU
	data, err := validatePDU(data, pduTypeL2PSNP, psnpHeaderLength, snpLengthOffset)
	if err != nil {
		return p, err
	}
	copy(p.sourceID[:], data[10:17])
	p.tlvData = data[psnpHeaderLength:]
	return p, nil
}

func makeCommonHeader(kind pduType, headerLength byte) []byte {
	return []byte{
		protocolDiscriminator,
		headerLength,
		protocolVersion,
		defaultIDLength,
		byte(kind),
		protocolVersion,
		0,
		0,
	}
}

func validatePDU(data []byte, kind pduType, headerLength byte, lengthOffset int) ([]byte, error) {
	if len(data) < commonHeaderLength {
		return nil, fmt.Errorf("%w: truncated common header", errMalformedPDU)
	}
	if data[0] != protocolDiscriminator {
		return nil, fmt.Errorf("%w: protocol discriminator is %#x", errMalformedPDU, data[0])
	}
	if data[1] != headerLength {
		return nil, fmt.Errorf("%w: header length is %d, want %d", errMalformedPDU, data[1], headerLength)
	}
	if data[2] != protocolVersion || data[5] != protocolVersion {
		return nil, fmt.Errorf("%w: unsupported protocol version", errMalformedPDU)
	}
	if data[3] != defaultIDLength && data[3] != systemIDLength {
		return nil, fmt.Errorf("%w: unsupported ID length %d", errMalformedPDU, data[3])
	}
	if data[4]&0xe0 != 0 || pduType(data[4]&0x1f) != kind {
		return nil, fmt.Errorf("%w: PDU type is %#x, want %d", errMalformedPDU, data[4], kind)
	}
	if len(data) < int(headerLength) {
		return nil, fmt.Errorf("%w: truncated fixed header", errMalformedPDU)
	}
	if lengthOffset < 0 || lengthOffset+2 > int(headerLength) {
		return nil, fmt.Errorf("invalid PDU length offset %d", lengthOffset)
	}
	pduLength := int(binary.BigEndian.Uint16(data[lengthOffset : lengthOffset+2]))
	if pduLength < int(headerLength) {
		return nil, fmt.Errorf("%w: PDU length %d is shorter than fixed header %d", errMalformedPDU, pduLength, headerLength)
	}
	if pduLength > len(data) {
		return nil, fmt.Errorf("%w: PDU length %d exceeds packet length %d", errMalformedPDU, pduLength, len(data))
	}
	return data[:pduLength], nil
}

func setLSPChecksum(data []byte) {
	checksumOffset := lspChecksumOffset - lspIDOffset
	section := data[lspIDOffset:]
	section[checksumOffset] = 0
	section[checksumOffset+1] = 0
	c0, c1 := fletcherSums(section)

	x := ((len(section)-checksumOffset-1)*c0 - c1) % 255
	if x <= 0 {
		x += 255
	}
	y := 510 - c0 - x
	if y > 255 {
		y -= 255
	}
	section[checksumOffset] = byte(x)
	section[checksumOffset+1] = byte(y)
}

func validLSPChecksum(data []byte) bool {
	if len(data) < lspHeaderLength {
		return false
	}
	c0, c1 := fletcherSums(data[lspIDOffset:])
	return c0 == 0 && c1 == 0
}

func fletcherSums(data []byte) (int, int) {
	c0, c1 := 0, 0
	for _, value := range data {
		c0 = (c0 + int(value)) % 255
		c1 = (c1 + c0) % 255
	}
	return c0, c1
}
