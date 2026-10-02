// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package isis

import (
	"bytes"
	"encoding/hex"
	"net/netip"
	"testing"
)

func TestP2PHelloCodec(t *testing.T) {
	tests := []struct {
		name string
		pdu  p2pHelloPDU
		want string
	}{
		{
			name: "minimal",
			pdu: p2pHelloPDU{
				circuitType:    2,
				sourceID:       systemID{1, 2, 3, 4, 5, 6},
				holdingTime:    9,
				localCircuitID: 1,
			},
			want: "8314010011010000020102030405060009001401",
		},
		{
			name: "with three-way TLV",
			pdu: p2pHelloPDU{
				circuitType:    2,
				sourceID:       systemID{1, 2, 3, 4, 5, 6},
				holdingTime:    9,
				localCircuitID: 1,
				tlvData:        mustDecodeHex(t, "f0050201020304"),
			},
			want: "8314010011010000020102030405060009001b01f0050201020304",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			want := mustDecodeHex(t, tt.want)
			got, err := tt.pdu.marshalBinary()
			if err != nil {
				t.Fatalf("marshalBinary() error = %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("marshalBinary() = %x, want %x", got, want)
			}

			decoded, err := decodeP2PHello(want)
			if err != nil {
				t.Fatalf("decodeP2PHello() error = %v", err)
			}
			if decoded.circuitType != tt.pdu.circuitType || decoded.sourceID != tt.pdu.sourceID ||
				decoded.holdingTime != tt.pdu.holdingTime || decoded.localCircuitID != tt.pdu.localCircuitID ||
				!bytes.Equal(decoded.tlvData, tt.pdu.tlvData) {
				t.Fatalf("decodeP2PHello() = %+v, want %+v", decoded, tt.pdu)
			}
		})
	}
}

func TestDecodeP2PHelloIgnoresFramePadding(t *testing.T) {
	packet := mustDecodeHex(t, "8314010011010000020102030405060009001401")
	packet = append(packet, 0, 0, 0, 0)
	if _, err := decodeP2PHello(packet); err != nil {
		t.Fatalf("decodeP2PHello() with frame padding error = %v", err)
	}
}

func TestLSPCodecFixtures(t *testing.T) {
	neighbor, err := encodeExtendedISReachability([]extendedISReachabilityEntry{{
		neighborID: nodeID{0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0},
		metric:     10,
	}})
	if err != nil {
		t.Fatalf("encodeExtendedISReachability() error = %v", err)
	}
	ipReachability, err := encodeExtendedIPReachability([]extendedIPReachabilityEntry{{
		prefix: netip.MustParsePrefix("10.200.0.42/32"),
	}})
	if err != nil {
		t.Fatalf("encodeExtendedIPReachability() error = %v", err)
	}
	reachabilityTLVs, err := encodeTLVs([]tlv{neighbor, ipReachability})
	if err != nil {
		t.Fatalf("encodeTLVs() error = %v", err)
	}

	tests := []struct {
		name string
		pdu  lspPDU
		want string
	}{
		{
			name: "minimal L2 LSP",
			pdu: lspPDU{
				remainingLifetime: 0x04b0,
				id:                lspID{1, 2, 3, 4, 5, 6, 0, 0},
				sequenceNumber:    1,
				flags:             lspFlagOverload | lspFlagLevel2IS,
			},
			want: "831b010014010000001b04b001020304050600000000000139a907",
		},
		{
			name: "LSP with neighbor and IPv4 prefix",
			pdu: lspPDU{
				remainingLifetime: 0x04b0,
				id:                lspID{1, 2, 3, 4, 5, 6, 0, 0},
				sequenceNumber:    1,
				flags:             lspFlagOverload | lspFlagLevel2IS,
				tlvData:           reachabilityTLVs,
			},
			want: "831b010014010000003304b00102030405060000000000013f5507160b1112131415160000000a00870900000000200ac8002a",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			want := mustDecodeHex(t, tt.want)
			got, err := tt.pdu.marshalBinary()
			if err != nil {
				t.Fatalf("marshalBinary() error = %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("marshalBinary() = %x, want %x", got, want)
			}
			if !validLSPChecksum(want) {
				t.Fatal("golden LSP checksum is invalid")
			}

			decoded, err := decodeLSP(want)
			if err != nil {
				t.Fatalf("decodeLSP() error = %v", err)
			}
			if decoded.remainingLifetime != tt.pdu.remainingLifetime || decoded.id != tt.pdu.id ||
				decoded.sequenceNumber != tt.pdu.sequenceNumber || decoded.flags != tt.pdu.flags ||
				!bytes.Equal(decoded.tlvData, tt.pdu.tlvData) {
				t.Fatalf("decodeLSP() = %+v, want %+v", decoded, tt.pdu)
			}
			if !bytes.Equal(decoded.raw, want) {
				t.Fatalf("decoded raw LSP = %x, want %x", decoded.raw, want)
			}
		})
	}
}

func TestDecodeLSPRejectsBadChecksum(t *testing.T) {
	packet := mustDecodeHex(t, "831b010014010000001b04b00102030405060000000000013aa708")
	packet[lspChecksumOffset] ^= 1
	if _, err := decodeLSP(packet); err == nil {
		t.Fatal("decodeLSP() accepted an invalid checksum")
	}
}

func TestDecodeLSPAcceptsZeroChecksumPurge(t *testing.T) {
	packet := mustDecodeHex(t, "831b010014010000001b0000010203040506000000000001000008")
	if _, err := decodeLSP(packet); err != nil {
		t.Fatalf("decodeLSP() zero-checksum purge error = %v", err)
	}
}

func TestDecodeLSPKeepsOpaqueTLVData(t *testing.T) {
	pdu := lspPDU{
		remainingLifetime: 0x04b0,
		id:                lspID{1, 2, 3, 4, 5, 6, 0, 0},
		sequenceNumber:    1,
		tlvData:           []byte{0xfe, 1, 0xaa, 0xfd, 2, 0xbb},
	}
	packet, err := pdu.marshalBinary()
	if err != nil {
		t.Fatalf("marshalBinary() error = %v", err)
	}

	decoded, err := decodeLSP(packet)
	if err != nil {
		t.Fatalf("decodeLSP() error = %v", err)
	}
	if !bytes.Equal(decoded.raw, packet) || !bytes.Equal(decoded.tlvData, pdu.tlvData) {
		t.Fatalf("decodeLSP() did not preserve opaque TLV data: raw=%x TLVs=%x", decoded.raw, decoded.tlvData)
	}
}

func TestCSNPCodecFixture(t *testing.T) {
	entry := lspEntry{
		remainingLifetime: 0x04b0,
		id:                lspID{0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0, 0},
		sequenceNumber:    1,
		checksum:          0xabcd,
	}
	entries, err := encodeLSPEntries([]lspEntry{entry})
	if err != nil {
		t.Fatalf("encodeLSPEntries() error = %v", err)
	}
	tlvData, err := encodeTLVs([]tlv{entries})
	if err != nil {
		t.Fatalf("encodeTLVs() error = %v", err)
	}
	pdu := csnpPDU{
		sourceID: nodeID{1, 2, 3, 4, 5, 6, 0},
		startID:  lspID{},
		endID:    lspID{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		tlvData:  tlvData,
	}
	want := mustDecodeHex(t, "83210100190100000033010203040506000000000000000000ffffffffffffffff091004b0111213141516000000000001abcd")

	got, err := pdu.marshalBinary()
	if err != nil {
		t.Fatalf("marshalBinary() error = %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("marshalBinary() = %x, want %x", got, want)
	}
	decoded, err := decodeCSNP(want)
	if err != nil {
		t.Fatalf("decodeCSNP() error = %v", err)
	}
	if decoded.sourceID != pdu.sourceID || decoded.startID != pdu.startID || decoded.endID != pdu.endID || !bytes.Equal(decoded.tlvData, tlvData) {
		t.Fatalf("decodeCSNP() = %+v, want %+v", decoded, pdu)
	}
}

func TestPSNPCodecFixture(t *testing.T) {
	entries, err := encodeLSPEntries([]lspEntry{{
		remainingLifetime: 0x04b0,
		id:                lspID{0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0, 0},
		sequenceNumber:    1,
		checksum:          0xabcd,
	}})
	if err != nil {
		t.Fatalf("encodeLSPEntries() error = %v", err)
	}
	tlvData, err := encodeTLVs([]tlv{entries})
	if err != nil {
		t.Fatalf("encodeTLVs() error = %v", err)
	}
	pdu := psnpPDU{sourceID: nodeID{0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0}, tlvData: tlvData}
	want := mustDecodeHex(t, "831101001b0100000023a1a2a3a4a5a600091004b0111213141516000000000001abcd")

	got, err := pdu.marshalBinary()
	if err != nil {
		t.Fatalf("marshalBinary() error = %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("marshalBinary() = %x, want %x", got, want)
	}
	decoded, err := decodePSNP(want)
	if err != nil {
		t.Fatalf("decodePSNP() error = %v", err)
	}
	if decoded.sourceID != pdu.sourceID || !bytes.Equal(decoded.tlvData, tlvData) {
		t.Fatalf("decodePSNP() = %+v, want %+v", decoded, pdu)
	}
}

func TestTLVCodecs(t *testing.T) {
	t.Run("area addresses", func(t *testing.T) {
		want := []areaAddress{{0x49, 0, 1}, {0x49, 0, 2}}
		encoded, err := encodeAreaAddresses(want)
		if err != nil {
			t.Fatalf("encodeAreaAddresses() error = %v", err)
		}
		if encoded.code != tlvAreaAddresses || !bytes.Equal(encoded.value, []byte{3, 0x49, 0, 1, 3, 0x49, 0, 2}) {
			t.Fatalf("encodeAreaAddresses() = %+v", encoded)
		}
		got, err := decodeAreaAddresses(encoded.value)
		if err != nil {
			t.Fatalf("decodeAreaAddresses() error = %v", err)
		}
		if len(got) != len(want) || !bytes.Equal(got[0], want[0]) || !bytes.Equal(got[1], want[1]) {
			t.Fatalf("decodeAreaAddresses() = %x, want %x", got, want)
		}
	})

	t.Run("protocols supported", func(t *testing.T) {
		encoded, err := encodeProtocolsSupported([]byte{ipv4NetworkLayerProtocolID})
		if err != nil {
			t.Fatalf("encodeProtocolsSupported() error = %v", err)
		}
		if encoded.code != tlvProtocolsSupported || !bytes.Equal(encoded.value, []byte{0xcc}) {
			t.Fatalf("encodeProtocolsSupported() = %+v", encoded)
		}
		got, err := decodeProtocolsSupported(encoded.value)
		if err != nil || !bytes.Equal(got, []byte{0xcc}) {
			t.Fatalf("decodeProtocolsSupported() = %x, %v", got, err)
		}
	})

	t.Run("IPv4 interface addresses", func(t *testing.T) {
		want := []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")}
		encoded, err := encodeIPv4InterfaceAddresses(want)
		if err != nil {
			t.Fatalf("encodeIPv4InterfaceAddresses() error = %v", err)
		}
		if encoded.code != tlvIPv4InterfaceAddresses || !bytes.Equal(encoded.value, []byte{192, 0, 2, 1, 192, 0, 2, 2}) {
			t.Fatalf("encodeIPv4InterfaceAddresses() = %+v", encoded)
		}
		got, err := decodeIPv4InterfaceAddresses(encoded.value)
		if err != nil || len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
			t.Fatalf("decodeIPv4InterfaceAddresses() = %v, %v", got, err)
		}
	})

	t.Run("LSP entries", func(t *testing.T) {
		want := []lspEntry{{
			remainingLifetime: 0x04b0,
			id:                lspID{1, 2, 3, 4, 5, 6, 0, 0},
			sequenceNumber:    7,
			checksum:          0xabcd,
		}}
		encoded, err := encodeLSPEntries(want)
		if err != nil {
			t.Fatalf("encodeLSPEntries() error = %v", err)
		}
		got, err := decodeLSPEntries(encoded.value)
		if err != nil || len(got) != 1 || got[0] != want[0] {
			t.Fatalf("decodeLSPEntries() = %+v, %v", got, err)
		}
	})

	t.Run("extended IS reachability", func(t *testing.T) {
		want := []extendedISReachabilityEntry{{
			neighborID: nodeID{1, 2, 3, 4, 5, 6, 0},
			metric:     0x010203,
			subTLVs:    []byte{0xaa, 1, 0x55},
		}}
		encoded, err := encodeExtendedISReachability(want)
		if err != nil {
			t.Fatalf("encodeExtendedISReachability() error = %v", err)
		}
		got, err := decodeExtendedISReachability(encoded.value)
		if err != nil || len(got) != 1 || got[0].neighborID != want[0].neighborID || got[0].metric != want[0].metric || !bytes.Equal(got[0].subTLVs, want[0].subTLVs) {
			t.Fatalf("decodeExtendedISReachability() = %+v, %v", got, err)
		}
	})

	t.Run("extended IP reachability", func(t *testing.T) {
		want := []extendedIPReachabilityEntry{{
			metric:  0x01020304,
			upDown:  true,
			prefix:  netip.MustParsePrefix("10.200.0.42/32"),
			subTLVs: []byte{0xaa, 1, 0x55},
		}}
		encoded, err := encodeExtendedIPReachability(want)
		if err != nil {
			t.Fatalf("encodeExtendedIPReachability() error = %v", err)
		}
		got, err := decodeExtendedIPReachability(encoded.value)
		if err != nil || len(got) != 1 || got[0].metric != want[0].metric || got[0].upDown != want[0].upDown ||
			got[0].prefix != want[0].prefix || !bytes.Equal(got[0].subTLVs, want[0].subTLVs) {
			t.Fatalf("decodeExtendedIPReachability() = %+v, %v", got, err)
		}

		got, err = decodeExtendedIPReachability([]byte{0, 0, 0, 1, 25, 192, 0, 2, 0xff})
		if err != nil || len(got) != 1 || got[0].prefix != netip.MustParsePrefix("192.0.2.128/25") {
			t.Fatalf("decodeExtendedIPReachability() did not mask unused prefix bits: %+v, %v", got, err)
		}
	})

	t.Run("three-way adjacency", func(t *testing.T) {
		want := threeWayAdjacency{
			state:                threeWayStateInitializing,
			localCircuitID:       0x01020304,
			neighborSystemID:     systemID{1, 2, 3, 4, 5, 6},
			hasNeighborSystemID:  true,
			neighborCircuitID:    0xa0b0c0d0,
			hasNeighborCircuitID: true,
		}
		encoded, err := encodeThreeWayAdjacency(want)
		if err != nil {
			t.Fatalf("encodeThreeWayAdjacency() error = %v", err)
		}
		if encoded.code != tlvP2PThreeWayAdjacency || !bytes.Equal(encoded.value, []byte{1, 1, 2, 3, 4, 1, 2, 3, 4, 5, 6, 0xa0, 0xb0, 0xc0, 0xd0}) {
			t.Fatalf("encodeThreeWayAdjacency() = %+v", encoded)
		}
		got, err := decodeThreeWayAdjacency(encoded.value)
		if err != nil || got != want {
			t.Fatalf("decodeThreeWayAdjacency() = %+v, %v; want %+v", got, err, want)
		}
	})
}

func TestTLVDecodersRejectMalformedValues(t *testing.T) {
	tests := []struct {
		name string
		fn   func() error
	}{
		{name: "area address", fn: func() error { _, err := decodeAreaAddresses([]byte{0}); return err }},
		{name: "protocols supported", fn: func() error { _, err := decodeProtocolsSupported(nil); return err }},
		{name: "IPv4 interface address", fn: func() error { _, err := decodeIPv4InterfaceAddresses([]byte{1, 2, 3}); return err }},
		{name: "LSP entry", fn: func() error { _, err := decodeLSPEntries(make([]byte, 15)); return err }},
		{name: "extended IS entry", fn: func() error { _, err := decodeExtendedISReachability(make([]byte, 10)); return err }},
		{name: "extended IS sub-TLV", fn: func() error {
			_, err := decodeExtendedISReachability([]byte{1, 2, 3, 4, 5, 6, 0, 0, 0, 0, 1})
			return err
		}},
		{name: "extended IP prefix length", fn: func() error { _, err := decodeExtendedIPReachability([]byte{0, 0, 0, 0, 33}); return err }},
		{name: "extended IP prefix bytes", fn: func() error { _, err := decodeExtendedIPReachability([]byte{0, 0, 0, 0, 32}); return err }},
		{name: "three-way length", fn: func() error { _, err := decodeThreeWayAdjacency(make([]byte, 6)); return err }},
		{name: "three-way state", fn: func() error { _, err := decodeThreeWayAdjacency([]byte{3}); return err }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.fn(); err == nil {
				t.Fatal("decoder accepted malformed value")
			}
		})
	}
}

func TestDecodeTLVs(t *testing.T) {
	got, err := decodeTLVs([]byte{tlvProtocolsSupported, 1, 0xcc, 250, 2, 0xaa, 0xbb})
	if err != nil {
		t.Fatalf("decodeTLVs() error = %v", err)
	}
	if len(got) != 2 || got[0].code != tlvProtocolsSupported || !bytes.Equal(got[0].value, []byte{0xcc}) ||
		got[1].code != 250 || !bytes.Equal(got[1].value, []byte{0xaa, 0xbb}) {
		t.Fatalf("decodeTLVs() = %+v", got)
	}
	encoded, err := encodeTLVs(got)
	if err != nil {
		t.Fatalf("encodeTLVs() error = %v", err)
	}
	if !bytes.Equal(encoded, []byte{tlvProtocolsSupported, 1, 0xcc, 250, 2, 0xaa, 0xbb}) {
		t.Fatalf("encodeTLVs() = %x", encoded)
	}
}

func TestDecodeTLVsRejectsTruncatedInput(t *testing.T) {
	for _, input := range [][]byte{{0xaa}, {0xaa, 2, 1}} {
		if _, err := decodeTLVs(input); err == nil {
			t.Fatalf("decodeTLVs(%x) succeeded", input)
		}
	}
}

func TestPDUDecodersRejectInvalidLengthsAndTypes(t *testing.T) {
	tests := []struct {
		name       string
		valid      string
		lengthOff  int
		fixedLen   int
		decodeFunc func([]byte) error
	}{
		{
			name:      "P2P IIH",
			valid:     "8314010011010000020102030405060009001401",
			lengthOff: p2pHelloLengthOffset,
			fixedLen:  p2pHelloHeaderLength,
			decodeFunc: func(data []byte) error {
				_, err := decodeP2PHello(data)
				return err
			},
		},
		{
			name:      "L2 LSP",
			valid:     "831b010014010000001b04b00102030405060000000000013aa708",
			lengthOff: lspLengthOffset,
			fixedLen:  lspHeaderLength,
			decodeFunc: func(data []byte) error {
				_, err := decodeLSP(data)
				return err
			},
		},
		{
			name:      "L2 CSNP",
			valid:     "83210100190100000021010203040506000000000000000000ffffffffffffffff",
			lengthOff: snpLengthOffset,
			fixedLen:  csnpHeaderLength,
			decodeFunc: func(data []byte) error {
				_, err := decodeCSNP(data)
				return err
			},
		},
		{
			name:      "L2 PSNP",
			valid:     "831101001b0100000011a1a2a3a4a5a600",
			lengthOff: snpLengthOffset,
			fixedLen:  psnpHeaderLength,
			decodeFunc: func(data []byte) error {
				_, err := decodePSNP(data)
				return err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid := mustDecodeHex(t, tt.valid)
			for _, input := range [][]byte{
				{},
				valid[:commonHeaderLength-1],
				mutateUint16(valid, tt.lengthOff, uint16(tt.fixedLen-1)),
				mutateUint16(valid, tt.lengthOff, uint16(len(valid)+1)),
				mutateByte(valid, 4, 0),
			} {
				if err := tt.decodeFunc(input); err == nil {
					t.Fatalf("decoder accepted invalid PDU %x", input)
				}
			}
		})
	}
}

func mustDecodeHex(t testing.TB, value string) []byte {
	t.Helper()
	data, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("hex.DecodeString(%q) error = %v", value, err)
	}
	return data
}

func mutateUint16(packet []byte, offset int, value uint16) []byte {
	mutated := bytes.Clone(packet)
	mutated[offset] = byte(value >> 8)
	mutated[offset+1] = byte(value)
	return mutated
}

func mutateByte(packet []byte, offset int, value byte) []byte {
	mutated := bytes.Clone(packet)
	mutated[offset] = value
	return mutated
}
