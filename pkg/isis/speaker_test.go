// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package isis

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"math"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type fakeSpeakerSocket struct {
	packets [][]byte
	mtu     int
}

func (s *fakeSpeakerSocket) receive(context.Context, time.Duration) ([]byte, error) {
	return nil, errPacketSocketTimeout
}

func (s *fakeSpeakerSocket) send(packet []byte) error {
	s.packets = append(s.packets, bytes.Clone(packet))
	return nil
}

func (s *fakeSpeakerSocket) close() error { return nil }
func (s *fakeSpeakerSocket) mtuSize() int { return s.mtu }
func (s *fakeSpeakerSocket) localIPv4() netip.Addr {
	return netip.MustParseAddr("192.0.2.0")
}
func (s *fakeSpeakerSocket) circuitID() uint32 { return 1 }

func testSpeaker(t *testing.T) *speaker {
	t.Helper()
	parsed, err := parseNET("49.0001.0000.0000.00c1.00")
	require.NoError(t, err)
	return &speaker{
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		net:    parsed,
	}
}

func TestSpeakerOriginatesAndWithdrawsServicePrefix(t *testing.T) {
	sp := testSpeaker(t)
	socket := &fakeSpeakerSocket{mtu: 1500}
	state := newProtocolState(sp, socket, netip.MustParseAddr("192.0.2.0"), 11)
	now := time.Now()
	serviceIP := netip.MustParsePrefix("10.200.0.42/32")

	require.NoError(t, state.setDesiredPrefixes([]netip.Prefix{serviceIP}, now))
	require.Equal(t, uint32(1), state.sequenceNumber)
	first, err := decodeLSP(state.localLSP)
	require.NoError(t, err)
	require.Equal(t, byte(lspFlagOverload|lspFlagLevel2IS), first.flags)
	require.True(t, hasIPv4Prefix(t, first, serviceIP))

	require.NoError(t, state.setDesiredPrefixes(nil, now.Add(2*time.Second)))
	require.Equal(t, uint32(2), state.sequenceNumber)
	second, err := decodeLSP(state.localLSP)
	require.NoError(t, err)
	require.False(t, hasIPv4Prefix(t, second, serviceIP))
}

func TestSpeakerOriginatesMultipleServicePrefixes(t *testing.T) {
	sp := testSpeaker(t)
	socket := &fakeSpeakerSocket{mtu: 1500}
	state := newProtocolState(sp, socket, netip.MustParseAddr("192.0.2.0"), 11)
	now := time.Now()
	prefixes := []netip.Prefix{
		netip.MustParsePrefix("10.200.0.42/32"),
		netip.MustParsePrefix("10.200.0.43/32"),
		netip.MustParsePrefix("10.200.0.44/32"),
	}

	require.NoError(t, state.setDesiredPrefixes(prefixes, now))
	localLSP, err := decodeLSP(state.localLSP)
	require.NoError(t, err)
	require.Equal(t, prefixes, ipv4PrefixesFromLSP(t, localLSP))
}

func TestSpeakerWithdrawsAllServicePrefixesWhenLSPExceedsMTU(t *testing.T) {
	sp := testSpeaker(t)
	socket := &fakeSpeakerSocket{}
	state := newProtocolState(sp, socket, netip.MustParseAddr("192.0.2.0"), 11)
	now := time.Now()
	baseLSP, err := state.buildLocalLSPForPrefixes(now, nil)
	require.NoError(t, err)
	socket.mtu = len(baseLSP) + servicePrefixTLVSize

	first := netip.MustParsePrefix("10.200.0.42/32")
	second := netip.MustParsePrefix("10.200.0.43/32")
	require.NoError(t, state.setDesiredPrefixes([]netip.Prefix{first}, now))
	localLSP, err := decodeLSP(state.localLSP)
	require.NoError(t, err)
	require.Equal(t, []netip.Prefix{first}, ipv4PrefixesFromLSP(t, localLSP))

	require.NoError(t, state.setDesiredPrefixes([]netip.Prefix{first, second}, now.Add(2*time.Second)))
	require.Empty(t, state.prefixes)
	localLSP, err = decodeLSP(state.localLSP)
	require.NoError(t, err)
	require.Empty(t, ipv4PrefixesFromLSP(t, localLSP))
}

func TestSpeakerRequiresThreeWayConfirmation(t *testing.T) {
	sp := testSpeaker(t)
	socket := &fakeSpeakerSocket{mtu: 1500}
	state := newProtocolState(sp, socket, netip.MustParseAddr("192.0.2.0"), 11)
	remote := systemID{0, 0, 0, 0, 0, 0xf1}
	local := sp.net.systemID
	now := time.Now()

	require.NoError(t, state.handleHello(testHello(t, remote, 22, threeWayStateDown, nil, 0), now))
	require.NotNil(t, state.peer)
	require.Equal(t, byte(threeWayStateInitializing), state.peer.state)
	require.Empty(t, state.database)

	require.NoError(t, state.handleHello(testHello(t, remote, 22, threeWayStateInitializing, &local, 11), now.Add(time.Second)))
	require.Equal(t, byte(threeWayStateUp), state.peer.state)
	require.Equal(t, uint32(1), state.sequenceNumber)
	require.NotEmpty(t, state.database)
	require.True(t, containsPDUType(socket.packets, pduTypeL2CSNP))

	localLSP, err := decodeLSP(state.localLSP)
	require.NoError(t, err)
	reachability := findTLV(t, localLSP.tlvData, tlvExtendedISReachability)
	entries, err := decodeExtendedISReachability(reachability)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	require.Equal(t, remote, systemID(entries[0].neighborID[:systemIDLength]))
}

func TestSpeakerRejectsUnconfirmedHelloAndExpiresNeighbor(t *testing.T) {
	sp := testSpeaker(t)
	socket := &fakeSpeakerSocket{mtu: 1500}
	state := newProtocolState(sp, socket, netip.MustParseAddr("192.0.2.0"), 11)
	remote := systemID{0, 0, 0, 0, 0, 0xf1}
	local := sp.net.systemID
	now := time.Now()

	require.NoError(t, state.handleHello(testHello(t, remote, 22, threeWayStateInitializing, nil, 0), now))
	require.Nil(t, state.peer)

	require.NoError(t, state.handleHello(testHello(t, remote, 22, threeWayStateDown, nil, 0), now))
	require.NoError(t, state.handleHello(testHello(t, remote, 22, threeWayStateInitializing, &local, 11), now.Add(time.Second)))
	require.Equal(t, byte(threeWayStateUp), state.peer.state)

	require.NoError(t, state.tick(now.Add(11*time.Second)))
	require.Nil(t, state.peer)
	localLSP, err := decodeLSP(state.localLSP)
	require.NoError(t, err)
	require.Empty(t, findTLVOptional(localLSP.tlvData, tlvExtendedISReachability))
}

func TestSpeakerRejectsHelloWithOwnSystemID(t *testing.T) {
	sp := testSpeaker(t)
	socket := &fakeSpeakerSocket{mtu: 1500}
	state := newProtocolState(sp, socket, netip.MustParseAddr("192.0.2.0"), 11)

	require.NoError(t, state.handleHello(testHello(t, sp.net.systemID, 22, threeWayStateDown, nil, 0), time.Now()))
	require.Nil(t, state.peer)
	require.Empty(t, state.database)
	require.Empty(t, socket.packets)
}

func TestSpeakerCSNPSplitCoversDatabase(t *testing.T) {
	sp := testSpeaker(t)
	socket := &fakeSpeakerSocket{mtu: 100}
	state := newProtocolState(sp, socket, netip.MustParseAddr("192.0.2.0"), 11)
	now := time.Now()
	for value := byte(1); value <= 9; value++ {
		var id lspID
		id[0] = value
		pdu, err := (lspPDU{id: id, sequenceNumber: 1, remainingLifetime: 1200}).marshalBinary()
		require.NoError(t, err)
		decoded, err := decodeLSP(pdu)
		require.NoError(t, err)
		require.True(t, state.storeEntry(decoded, now))
	}

	require.NoError(t, state.sendCompleteCSNP(now))
	require.Len(t, socket.packets, 3)
	var entriesSeen int
	var previousEnd lspID
	for i, packet := range socket.packets {
		csnp, err := decodeCSNP(packet)
		require.NoError(t, err)
		if i == 0 {
			require.Equal(t, lspID{}, csnp.startID)
		} else {
			require.Equal(t, incrementLSPID(previousEnd), csnp.startID)
		}
		previousEnd = csnp.endID
		tlvs, err := decodeTLVs(csnp.tlvData)
		require.NoError(t, err)
		for _, item := range tlvs {
			if item.code == tlvLSPEntries {
				entries, err := decodeLSPEntries(item.value)
				require.NoError(t, err)
				entriesSeen += len(entries)
			}
		}
	}
	var allOnes lspID
	for i := range allOnes {
		allOnes[i] = 0xff
	}
	require.Equal(t, allOnes, previousEnd)
	require.Equal(t, 9, entriesSeen)
}

func TestSpeakerRequestsNewerLSPFromCSNP(t *testing.T) {
	sp := testSpeaker(t)
	socket := &fakeSpeakerSocket{mtu: 1500}
	state := newProtocolState(sp, socket, netip.MustParseAddr("192.0.2.0"), 11)
	remote := systemID{0, 0, 0, 0, 0, 0xf1}
	state.peer = &adjacency{systemID: remote, state: threeWayStateUp}
	now := time.Now()

	older := testLSP(t, remote, 1, 1200)
	require.True(t, state.storeEntry(older, now))
	newer := testLSP(t, remote, 2, 1200)
	entry := lspEntry{
		remainingLifetime: newer.remainingLifetime,
		id:                newer.id,
		sequenceNumber:    newer.sequenceNumber,
		checksum:          newer.checksum,
	}
	entries, err := encodeLSPEntries([]lspEntry{entry})
	require.NoError(t, err)
	tlvData, err := encodeTLVs([]tlv{entries})
	require.NoError(t, err)
	var source nodeID
	copy(source[:systemIDLength], remote[:])
	var endID lspID
	for i := range endID {
		endID[i] = 0xff
	}
	csnp, err := (csnpPDU{sourceID: source, endID: endID, tlvData: tlvData}).marshalBinary()
	require.NoError(t, err)

	require.NoError(t, state.handleCSNP(mustDecodeCSNP(t, csnp), now))
	require.Len(t, socket.packets, 1)
	request, err := decodePSNP(socket.packets[0])
	require.NoError(t, err)
	requested := lspEntriesFromTLVs(t, request.tlvData)
	require.Equal(t, []lspEntry{{id: newer.id}}, requested)
}

func TestSpeakerFloodsExpiredLSPPurge(t *testing.T) {
	sp := testSpeaker(t)
	socket := &fakeSpeakerSocket{mtu: 1500}
	state := newProtocolState(sp, socket, netip.MustParseAddr("192.0.2.0"), 11)
	remote := systemID{0, 0, 0, 0, 0, 0xf1}
	state.peer = &adjacency{systemID: remote, state: threeWayStateUp}
	startedAt := time.Now()
	lsp := testLSP(t, remote, 1, 1)
	require.True(t, state.storeEntry(lsp, startedAt))

	require.NoError(t, state.expireDatabase(startedAt.Add(time.Second)))
	require.Contains(t, state.database, lsp.id)
	require.NotZero(t, state.database[lsp.id].zeroAt)
	require.Contains(t, state.pendingAck, lsp.id)
	require.Len(t, socket.packets, 1)
	purge, err := decodeLSP(socket.packets[0])
	require.NoError(t, err)
	require.Equal(t, uint16(0), purge.remainingLifetime)
	require.Empty(t, purge.tlvData)

	require.NoError(t, state.expireDatabase(startedAt.Add(time.Second+lspZeroAgeLifetime)))
	require.NotContains(t, state.database, lsp.id)
}

func TestSpeakerLSDBEntryLimit(t *testing.T) {
	sp := testSpeaker(t)
	state := newProtocolState(sp, &fakeSpeakerSocket{mtu: 1500}, netip.MustParseAddr("192.0.2.0"), 11)
	now := time.Now()
	for value := 0; value < lsdbMaximumEntries; value++ {
		var id lspID
		id[0] = byte(value >> 8)
		id[1] = byte(value)
		pdu, err := (lspPDU{id: id, sequenceNumber: 1, remainingLifetime: 1200}).marshalBinary()
		require.NoError(t, err)
		decoded, err := decodeLSP(pdu)
		require.NoError(t, err)
		require.True(t, state.storeEntry(decoded, now))
	}
	var extraID lspID
	extraID[0], extraID[1] = 0x10, 0
	extra, err := (lspPDU{id: extraID, sequenceNumber: 1, remainingLifetime: 1200}).marshalBinary()
	require.NoError(t, err)
	decoded, err := decodeLSP(extra)
	require.NoError(t, err)
	require.False(t, state.storeEntry(decoded, now))
	require.Len(t, state.database, lsdbMaximumEntries)
}

func TestThreeWayStateTransitions(t *testing.T) {
	tests := []struct {
		name   string
		local  byte
		remote byte
		want   byte
	}{
		{"down down", threeWayStateDown, threeWayStateDown, threeWayStateInitializing},
		{"down initializing", threeWayStateDown, threeWayStateInitializing, threeWayStateUp},
		{"down up", threeWayStateDown, threeWayStateUp, threeWayStateDown},
		{"initializing down", threeWayStateInitializing, threeWayStateDown, threeWayStateInitializing},
		{"initializing initializing", threeWayStateInitializing, threeWayStateInitializing, threeWayStateUp},
		{"initializing up", threeWayStateInitializing, threeWayStateUp, threeWayStateUp},
		{"up down", threeWayStateUp, threeWayStateDown, threeWayStateInitializing},
		{"up initializing", threeWayStateUp, threeWayStateInitializing, threeWayStateUp},
		{"up up", threeWayStateUp, threeWayStateUp, threeWayStateUp},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, nextThreeWayState(tt.local, tt.remote))
		})
	}
}

func TestSpeakerStoresAcknowledgesAndResendsLSPs(t *testing.T) {
	sp := testSpeaker(t)
	socket := &fakeSpeakerSocket{mtu: 1500}
	state := newProtocolState(sp, socket, netip.MustParseAddr("192.0.2.0"), 11)
	remote := systemID{0, 0, 0, 0, 0, 0xf1}
	state.peer = &adjacency{systemID: remote, state: threeWayStateUp}
	now := time.Now()

	newer := testLSP(t, remote, 2, 1200)
	require.NoError(t, state.handleLSP(newer, now))
	require.Contains(t, state.database, newer.id)
	ack, err := decodePSNP(socket.packets[len(socket.packets)-1])
	require.NoError(t, err)
	ackEntries := lspEntriesFromTLVs(t, ack.tlvData)
	require.Len(t, ackEntries, 1)
	require.Equal(t, uint32(2), ackEntries[0].sequenceNumber)

	older := testLSP(t, remote, 1, 1200)
	require.NoError(t, state.handleLSP(older, now.Add(time.Second)))
	resent, err := decodeLSP(socket.packets[len(socket.packets)-1])
	require.NoError(t, err)
	require.Equal(t, uint32(2), resent.sequenceNumber)

	duplicate := testLSP(t, remote, 2, 1200)
	require.NoError(t, state.handleLSP(duplicate, now.Add(2*time.Second)))
	ack, err = decodePSNP(socket.packets[len(socket.packets)-1])
	require.NoError(t, err)
	require.Equal(t, uint32(2), lspEntriesFromTLVs(t, ack.tlvData)[0].sequenceNumber)
}

func TestSpeakerFightsBackAgainstStaleSelfLSP(t *testing.T) {
	sp := testSpeaker(t)
	socket := &fakeSpeakerSocket{mtu: 1500}
	state := newProtocolState(sp, socket, netip.MustParseAddr("192.0.2.0"), 11)
	state.peer = &adjacency{systemID: systemID{0, 0, 0, 0, 0, 0xf1}, state: threeWayStateUp}
	now := time.Now()
	require.NoError(t, state.setDesiredPrefixes([]netip.Prefix{netip.MustParsePrefix("10.200.0.42/32")}, now))

	stale := testLSP(t, sp.net.systemID, 8, 1200)
	require.NoError(t, state.handleLSP(stale, now.Add(2*time.Second)))
	require.Equal(t, uint32(9), state.sequenceNumber)
	current, err := decodeLSP(state.localLSP)
	require.NoError(t, err)
	require.Equal(t, uint32(9), current.sequenceNumber)
	require.True(t, hasIPv4Prefix(t, current, netip.MustParsePrefix("10.200.0.42/32")))
}

func TestSpeakerFailsClosedAtMaximumLSPSequence(t *testing.T) {
	state := newProtocolState(testSpeaker(t), &fakeSpeakerSocket{mtu: 1500}, netip.MustParseAddr("192.0.2.0"), 11)
	state.sequenceNumber = math.MaxUint32
	require.ErrorIs(t, state.flushLocalLSP(time.Now()), errLSPSequenceExhausted)
}

func TestSpeakerRefreshesLocalLSP(t *testing.T) {
	sp := testSpeaker(t)
	socket := &fakeSpeakerSocket{mtu: 1500}
	state := newProtocolState(sp, socket, netip.MustParseAddr("192.0.2.0"), 11)
	state.peer = &adjacency{
		systemID:      systemID{0, 0, 0, 0, 0, 0xf1},
		state:         threeWayStateUp,
		holdExpiresAt: time.Now().Add(time.Hour),
	}
	start := time.Now()
	state.nextHelloAt = start.Add(time.Hour)
	require.NoError(t, state.setDesiredPrefixes([]netip.Prefix{netip.MustParsePrefix("10.200.0.42/32")}, start))
	state.nextRefresh = start.Add(time.Second)

	refreshTime := start.Add(2 * time.Second)
	require.NoError(t, state.tick(refreshTime))
	require.Equal(t, uint32(2), state.sequenceNumber)
	refreshed, err := decodeLSP(state.localLSP)
	require.NoError(t, err)
	require.Equal(t, uint32(2), refreshed.sequenceNumber)
	require.True(t, hasIPv4Prefix(t, refreshed, netip.MustParsePrefix("10.200.0.42/32")))
	require.True(t, state.nextRefresh.After(refreshTime))
}

func TestSpeakerIgnoresChecksumCorruptLSP(t *testing.T) {
	sp := testSpeaker(t)
	socket := &fakeSpeakerSocket{mtu: 1500}
	state := newProtocolState(sp, socket, netip.MustParseAddr("192.0.2.0"), 11)
	state.peer = &adjacency{
		systemID:      systemID{0, 0, 0, 0, 0, 0xf1},
		state:         threeWayStateUp,
		holdExpiresAt: time.Now().Add(time.Hour),
	}
	valid := testLSP(t, systemID{0, 0, 0, 0, 0, 0xf2}, 1, 1200)
	packet := bytes.Clone(valid.raw)
	packet[len(packet)-1] ^= 0xff

	require.NoError(t, state.handlePacket(packet, time.Now()))
	require.Empty(t, state.database)
	require.Empty(t, socket.packets)
}

func testHello(t *testing.T, source systemID, localCircuit uint32, state byte, neighbor *systemID, neighborCircuit uint32) p2pHelloPDU {
	t.Helper()
	threeWay := threeWayAdjacency{state: state, localCircuitID: localCircuit}
	if neighbor != nil {
		threeWay.neighborSystemID = *neighbor
		threeWay.hasNeighborSystemID = true
		threeWay.neighborCircuitID = neighborCircuit
		threeWay.hasNeighborCircuitID = true
	}
	tlvValue, err := encodeThreeWayAdjacency(threeWay)
	require.NoError(t, err)
	protocols, err := encodeProtocolsSupported([]byte{isisIPv4NLPID})
	require.NoError(t, err)
	addresses, err := encodeIPv4InterfaceAddresses([]netip.Addr{netip.MustParseAddr("192.0.2.1")})
	require.NoError(t, err)
	tlvData, err := encodeTLVs([]tlv{protocols, addresses, tlvValue})
	require.NoError(t, err)
	return p2pHelloPDU{
		circuitType:    isisLevel2CircuitType,
		sourceID:       source,
		holdingTime:    helloHoldingTime,
		localCircuitID: 3,
		tlvData:        tlvData,
	}
}

func testLSP(t *testing.T, source systemID, sequence uint32, lifetime uint16) lspPDU {
	t.Helper()
	var id lspID
	copy(id[:systemIDLength], source[:])
	packet, err := (lspPDU{id: id, sequenceNumber: sequence, remainingLifetime: lifetime, flags: lspFlagOverload | lspFlagLevel2IS}).marshalBinary()
	require.NoError(t, err)
	decoded, err := decodeLSP(packet)
	require.NoError(t, err)
	return decoded
}

func mustDecodeCSNP(t *testing.T, packet []byte) csnpPDU {
	t.Helper()
	pdu, err := decodeCSNP(packet)
	require.NoError(t, err)
	return pdu
}

func lspEntriesFromTLVs(t *testing.T, data []byte) []lspEntry {
	t.Helper()
	tlvs, err := decodeTLVs(data)
	require.NoError(t, err)
	var entries []lspEntry
	for _, item := range tlvs {
		if item.code != tlvLSPEntries {
			continue
		}
		decoded, err := decodeLSPEntries(item.value)
		require.NoError(t, err)
		entries = append(entries, decoded...)
	}
	return entries
}

func hasIPv4Prefix(t *testing.T, pdu lspPDU, expected netip.Prefix) bool {
	t.Helper()
	value := findTLVOptional(pdu.tlvData, tlvExtendedIPReachability)
	if len(value) == 0 {
		return false
	}
	entries, err := decodeExtendedIPReachability(value)
	require.NoError(t, err)
	for _, entry := range entries {
		if entry.prefix == expected {
			return true
		}
	}
	return false
}

func ipv4PrefixesFromLSP(t *testing.T, pdu lspPDU) []netip.Prefix {
	t.Helper()
	tlvs, err := decodeTLVs(pdu.tlvData)
	require.NoError(t, err)
	var prefixes []netip.Prefix
	for _, item := range tlvs {
		if item.code != tlvExtendedIPReachability {
			continue
		}
		entries, err := decodeExtendedIPReachability(item.value)
		require.NoError(t, err)
		for _, entry := range entries {
			prefixes = append(prefixes, entry.prefix)
		}
	}
	return prefixes
}

func findTLV(t *testing.T, data []byte, code byte) []byte {
	t.Helper()
	value := findTLVOptional(data, code)
	require.NotEmpty(t, value)
	return value
}

func findTLVOptional(data []byte, code byte) []byte {
	tlvs, err := decodeTLVs(data)
	if err != nil {
		return nil
	}
	for _, item := range tlvs {
		if item.code == code {
			return item.value
		}
	}
	return nil
}

func containsPDUType(packets [][]byte, kind pduType) bool {
	for _, packet := range packets {
		if len(packet) > 4 && pduType(packet[4]&0x1f) == kind {
			return true
		}
	}
	return false
}

func incrementLSPID(id lspID) lspID {
	for i := len(id) - 1; i >= 0; i-- {
		id[i]++
		if id[i] != 0 {
			break
		}
	}
	return id
}
