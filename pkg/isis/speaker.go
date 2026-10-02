// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package isis

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"math/rand/v2"
	"net/netip"
	"slices"
	"time"
)

const (
	isisLevel2CircuitType = 2
	isisIPv4NLPID         = 0xcc

	helloInterval          = 3 * time.Second
	helloHoldingTime       = 9
	lspMaximumAge          = 20 * time.Minute
	lspRefreshInterval     = 15 * time.Minute
	lspRetransmitInterval  = 5 * time.Second
	lspZeroAgeLifetime     = time.Minute
	lspOriginationInterval = time.Second
	speakerPollInterval    = 250 * time.Millisecond
	lsdbMaximumEntries     = 4096
	lsdbMaximumBytes       = 16 << 20
	servicePrefixTLVSize   = 11 // TLV header plus one IPv4 /32 reachability entry.
	isisInterfaceMetric    = 10
)

var errLSPSequenceExhausted = errors.New("IS-IS LSP sequence number exhausted")

type speaker struct {
	enabled bool
	logger  *slog.Logger
	config  Config
	net     isisNET
	waiter  DatapathWaiter

	prefixUpdates chan []netip.Prefix
}

func newSpeaker(logger *slog.Logger, cfg Config, waiter DatapathWaiter) (*speaker, error) {
	parsedNET, err := cfg.validate()
	if err != nil {
		return nil, err
	}
	return &speaker{
		enabled:       cfg.Enabled,
		logger:        logger,
		config:        cfg,
		net:           parsedNET,
		waiter:        waiter,
		prefixUpdates: make(chan []netip.Prefix, 1),
	}, nil
}

// SetPrefixes replaces the full desired set. It is safe for the StateDB
// watcher to call while the protocol goroutine is running.
func (s *speaker) SetPrefixes(prefixes []netip.Prefix) {
	prefixes = canonicalPrefixes(prefixes)
	select {
	case s.prefixUpdates <- prefixes:
		return
	default:
	}
	select {
	case <-s.prefixUpdates:
	default:
	}
	s.prefixUpdates <- prefixes
}

func canonicalPrefixes(prefixes []netip.Prefix) []netip.Prefix {
	result := make([]netip.Prefix, 0, len(prefixes))
	seen := make(map[netip.Prefix]struct{}, len(prefixes))
	for _, prefix := range prefixes {
		if !prefix.IsValid() || !prefix.Addr().Is4() || prefix.Bits() != 32 || !prefix.Addr().IsGlobalUnicast() {
			continue
		}
		prefix = prefix.Masked()
		if _, ok := seen[prefix]; ok {
			continue
		}
		seen[prefix] = struct{}{}
		result = append(result, prefix)
	}
	slices.SortFunc(result, func(a, b netip.Prefix) int { return a.Addr().Compare(b.Addr()) })
	return result
}

func (s *speaker) run(ctx context.Context) error {
	if err := s.waiter.Wait(ctx); err != nil {
		return fmt.Errorf("wait for Cilium datapath initialization: %w", err)
	}
	sock, err := openPacketSocket(s.config.Interface)
	if err != nil {
		return err
	}
	defer sock.close()
	return s.runProtocol(ctx, sock, sock.localIPv4(), sock.circuitID())
}

func (s *speaker) runProtocol(ctx context.Context, socket speakerSocket, localAddress netip.Addr, localCircuitID uint32) error {
	state := newProtocolState(s, socket, localAddress, localCircuitID)
	defer state.shutdown()
	if err := state.sendHello(time.Now()); err != nil {
		return err
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case prefixes := <-s.prefixUpdates:
			if err := state.setDesiredPrefixes(prefixes, time.Now()); err != nil {
				return err
			}
		default:
		}

		packet, err := socket.receive(ctx, speakerPollInterval)
		if err == nil {
			if err := state.handlePacket(packet, time.Now()); err != nil {
				return err
			}
		} else if !errors.Is(err, errPacketSocketTimeout) && !errors.Is(err, context.DeadlineExceeded) {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		if err := state.tick(time.Now()); err != nil {
			return err
		}
	}
}

type speakerSocket interface {
	receive(context.Context, time.Duration) ([]byte, error)
	send([]byte) error
	close() error
	mtuSize() int
	localIPv4() netip.Addr
	circuitID() uint32
}

type adjacency struct {
	systemID      systemID
	circuitID     uint32
	state         byte
	holdExpiresAt time.Time
}

type lsdbEntry struct {
	pdu        lspPDU
	receivedAt time.Time
	zeroAt     time.Time
}

type protocolState struct {
	speaker      *speaker
	socket       speakerSocket
	localAddress netip.Addr
	localCircuit uint32
	pduCircuitID byte

	peer          *adjacency
	database      map[lspID]*lsdbEntry
	databaseBytes int
	prefixes      []netip.Prefix
	nextHelloAt   time.Time

	sequenceNumber  uint32
	localLSP        []byte
	localDirty      bool
	lastOrigination time.Time
	nextRefresh     time.Time
	pendingAck      map[lspID]time.Time
}

func newProtocolState(s *speaker, socket speakerSocket, address netip.Addr, circuitID uint32) *protocolState {
	pduCircuitID := byte(circuitID)
	if pduCircuitID == 0 {
		pduCircuitID = 1
	}
	return &protocolState{
		speaker:      s,
		socket:       socket,
		localAddress: address,
		localCircuit: circuitID,
		pduCircuitID: pduCircuitID,
		database:     make(map[lspID]*lsdbEntry),
		pendingAck:   make(map[lspID]time.Time),
		localDirty:   true,
	}
}

func (p *protocolState) tick(now time.Time) error {
	if p.peer != nil && !now.Before(p.peer.holdExpiresAt) {
		p.speaker.logger.Info("IS-IS neighbor hold timer expired", "system-id", formatSystemID(p.peer.systemID))
		if err := p.adjacencyDown(now); err != nil {
			return err
		}
	}
	if p.nextHelloAt.IsZero() || !now.Before(p.nextHelloAt) {
		if err := p.sendHello(now); err != nil {
			return err
		}
	}
	if !p.nextRefresh.IsZero() && !now.Before(p.nextRefresh) {
		p.localDirty = true
	}
	if err := p.flushLocalLSP(now); err != nil {
		return err
	}
	if p.peer != nil && p.peer.state == threeWayStateUp {
		for id, sentAt := range p.pendingAck {
			if now.Sub(sentAt) >= lspRetransmitInterval {
				if err := p.sendLocalOrDatabaseLSP(id, now); err != nil {
					return err
				}
				p.pendingAck[id] = now
			}
		}
	}
	return p.expireDatabase(now)
}

func (p *protocolState) setDesiredPrefixes(prefixes []netip.Prefix, now time.Time) error {
	prefixes = canonicalPrefixes(prefixes)
	if slices.Equal(prefixes, p.prefixes) {
		return nil
	}
	p.prefixes = slices.Clone(prefixes)
	p.localDirty = true
	if err := p.flushLocalLSP(now); err != nil {
		return fmt.Errorf("originate IS-IS LSP after Service IP update: %w", err)
	}
	return nil
}

func (p *protocolState) sendHello(now time.Time) error {
	areas, err := encodeAreaAddresses([]areaAddress{p.speaker.net.area})
	if err != nil {
		return err
	}
	protocols, err := encodeProtocolsSupported([]byte{isisIPv4NLPID})
	if err != nil {
		return err
	}
	addresses, err := encodeIPv4InterfaceAddresses([]netip.Addr{p.localAddress})
	if err != nil {
		return err
	}
	threeWay := threeWayAdjacency{state: threeWayStateDown, localCircuitID: p.localCircuit}
	if p.peer != nil {
		threeWay.state = p.peer.state
		threeWay.neighborSystemID = p.peer.systemID
		threeWay.hasNeighborSystemID = true
		threeWay.neighborCircuitID = p.peer.circuitID
		threeWay.hasNeighborCircuitID = true
	}
	threeWayTLV, err := encodeThreeWayAdjacency(threeWay)
	if err != nil {
		return err
	}
	tlvData, err := encodeTLVs([]tlv{areas, protocols, addresses, threeWayTLV})
	if err != nil {
		return err
	}
	pdu, err := (p2pHelloPDU{
		circuitType:    isisLevel2CircuitType,
		sourceID:       p.speaker.net.systemID,
		holdingTime:    helloHoldingTime,
		localCircuitID: p.pduCircuitID,
		tlvData:        tlvData,
	}).marshalBinary()
	if err != nil {
		return err
	}
	if err := p.socket.send(pdu); err != nil {
		return err
	}
	p.nextHelloAt = now.Add(jitterDuration(helloInterval, 0.9, 1.1))
	return nil
}

func (p *protocolState) handlePacket(packet []byte, now time.Time) error {
	if len(packet) < commonHeaderLength {
		return nil
	}
	switch pduType(packet[4] & 0x1f) {
	case pduTypeP2PHello:
		hello, err := decodeP2PHello(packet)
		if err != nil {
			p.speaker.logger.Debug("Ignoring malformed IS-IS IIH", "error", err)
			return nil
		}
		return p.handleHello(hello, now)
	case pduTypeL2LSP:
		if p.peer == nil || p.peer.state != threeWayStateUp {
			return nil
		}
		lsp, err := decodeLSP(packet)
		if err != nil {
			p.speaker.logger.Debug("Ignoring malformed IS-IS LSP", "error", err)
			return nil
		}
		return p.handleLSP(lsp, now)
	case pduTypeL2CSNP:
		if p.peer == nil || p.peer.state != threeWayStateUp {
			return nil
		}
		csnp, err := decodeCSNP(packet)
		if err != nil {
			p.speaker.logger.Debug("Ignoring malformed IS-IS CSNP", "error", err)
			return nil
		}
		return p.handleCSNP(csnp, now)
	case pduTypeL2PSNP:
		if p.peer == nil || p.peer.state != threeWayStateUp {
			return nil
		}
		psnp, err := decodePSNP(packet)
		if err != nil {
			p.speaker.logger.Debug("Ignoring malformed IS-IS PSNP", "error", err)
			return nil
		}
		return p.handlePSNP(psnp, now)
	default:
		return nil
	}
}

func (p *protocolState) handleHello(hello p2pHelloPDU, now time.Time) error {
	if hello.sourceID == p.speaker.net.systemID || hello.holdingTime == 0 || hello.circuitType&isisLevel2CircuitType == 0 {
		return nil
	}
	tlvs, err := decodeTLVs(hello.tlvData)
	if err != nil {
		p.speaker.logger.Debug("Ignoring IS-IS IIH with malformed TLVs", "error", err)
		return nil
	}
	var threeWay *threeWayAdjacency
	hasIPv4 := false
	hasIPv4Address := false
	for _, item := range tlvs {
		switch item.code {
		case tlvProtocolsSupported:
			protocols, err := decodeProtocolsSupported(item.value)
			if err != nil {
				return nil
			}
			for _, protocol := range protocols {
				if protocol == isisIPv4NLPID {
					hasIPv4 = true
				}
			}
		case tlvIPv4InterfaceAddresses:
			if _, err := decodeIPv4InterfaceAddresses(item.value); err != nil {
				return nil
			}
			hasIPv4Address = true
		case tlvP2PThreeWayAdjacency:
			decoded, err := decodeThreeWayAdjacency(item.value)
			if err != nil || threeWay != nil {
				return nil
			}
			threeWay = &decoded
		}
	}
	if !hasIPv4 || !hasIPv4Address {
		return nil
	}
	if threeWay == nil {
		return nil
	}
	if threeWay.state != threeWayStateDown && (!threeWay.hasNeighborSystemID || !threeWay.hasNeighborCircuitID) {
		return nil
	}
	if threeWay.hasNeighborSystemID && threeWay.neighborSystemID != p.speaker.net.systemID {
		return nil
	}
	if threeWay.hasNeighborCircuitID && threeWay.neighborCircuitID != p.localCircuit {
		return nil
	}
	if p.peer != nil && p.peer.systemID != hello.sourceID {
		p.speaker.logger.Warn("Ignoring IS-IS IIH from a second neighbor on the single-neighbor circuit", "system-id", formatSystemID(hello.sourceID))
		return nil
	}
	if p.peer == nil {
		p.peer = &adjacency{systemID: hello.sourceID, circuitID: threeWay.localCircuitID, state: threeWayStateDown}
	}
	p.peer.circuitID = threeWay.localCircuitID
	p.peer.holdExpiresAt = now.Add(time.Duration(hello.holdingTime) * time.Second)

	wasUp := p.peer.state == threeWayStateUp
	p.peer.state = nextThreeWayState(p.peer.state, threeWay.state)
	if !wasUp && p.peer.state == threeWayStateUp {
		p.speaker.logger.Info("IS-IS neighbor is Up", "system-id", formatSystemID(p.peer.systemID))
		p.localDirty = true
		if err := p.flushLocalLSP(now); err != nil {
			return err
		}
		return p.sendCompleteCSNP(now)
	}
	if wasUp && p.peer.state != threeWayStateUp {
		p.localDirty = true
		if err := p.flushLocalLSP(now); err != nil {
			return err
		}
	}
	if err := p.sendHello(now); err != nil {
		return err
	}
	return nil
}

func nextThreeWayState(local, remote byte) byte {
	switch local {
	case threeWayStateDown:
		switch remote {
		case threeWayStateDown:
			return threeWayStateInitializing
		case threeWayStateInitializing:
			return threeWayStateUp
		default:
			return threeWayStateDown
		}
	case threeWayStateInitializing:
		if remote == threeWayStateDown {
			return threeWayStateInitializing
		}
		return threeWayStateUp
	case threeWayStateUp:
		if remote == threeWayStateDown {
			return threeWayStateInitializing
		}
		return threeWayStateUp
	default:
		return threeWayStateDown
	}
}

func formatSystemID(id systemID) string {
	return fmt.Sprintf("%02x%02x.%02x%02x.%02x%02x", id[0], id[1], id[2], id[3], id[4], id[5])
}

func (p *protocolState) adjacencyDown(now time.Time) error {
	if p.peer == nil {
		return nil
	}
	peerID := p.peer.systemID
	p.peer.state = threeWayStateDown
	if err := p.sendHello(now); err != nil {
		return err
	}
	p.peer = nil
	p.pendingAck = make(map[lspID]time.Time)
	p.speaker.logger.Info("IS-IS neighbor is Down", "system-id", formatSystemID(peerID))
	p.localDirty = true
	return p.flushLocalLSP(now)
}

func (p *protocolState) flushLocalLSP(now time.Time) error {
	if !p.localDirty {
		return nil
	}
	if p.sequenceNumber != 0 && now.Sub(p.lastOrigination) < lspOriginationInterval {
		return nil
	}
	if p.sequenceNumber == math.MaxUint32 {
		return fmt.Errorf("%w for %s", errLSPSequenceExhausted, formatSystemID(p.speaker.net.systemID))
	}
	p.sequenceNumber++
	budget := min(p.socket.mtuSize(), maxLSPPDUSize)
	baseLSP, err := p.buildLocalLSPForPrefixes(now, nil)
	if err != nil {
		return err
	}
	if len(baseLSP) > budget {
		return fmt.Errorf("base IS-IS LSP size %d exceeds PDU budget %d", len(baseLSP), budget)
	}

	lsp := baseLSP
	if len(p.prefixes) != 0 {
		remainingBudget := budget - len(baseLSP)
		if len(p.prefixes) > remainingBudget/servicePrefixTLVSize {
			count := len(p.prefixes)
			minimumSize := len(baseLSP) + count*servicePrefixTLVSize
			p.prefixes = nil
			p.speaker.logger.Warn("IS-IS LSP exceeds PDU budget; withdrawing all Service routes",
				"service-prefixes", count,
				"minimum-lsp-size", minimumSize,
				"pdu-budget", budget,
			)
		} else {
			lsp, err = p.buildLocalLSPForPrefixes(now, p.prefixes)
			if err != nil {
				return err
			}
		}
	}
	decoded, err := decodeLSP(lsp)
	if err != nil {
		return fmt.Errorf("decode newly originated IS-IS LSP: %w", err)
	}
	id := decoded.id
	if !p.storeEntry(decoded, now) {
		return errors.New("unable to store locally originated IS-IS LSP within bounded LSDB")
	}
	p.localLSP = lsp
	p.localDirty = false
	p.lastOrigination = now
	p.nextRefresh = now.Add(jitterDuration(lspRefreshInterval, 0.9, 1.1))
	if p.peer != nil && p.peer.state == threeWayStateUp {
		if err := p.sendLSP(lsp, now); err != nil {
			return err
		}
		p.pendingAck[id] = now
	}
	return nil
}

func jitterDuration(duration time.Duration, min, max float64) time.Duration {
	return time.Duration(float64(duration) * (min + rand.Float64()*(max-min)))
}

func (p *protocolState) buildLocalLSPForPrefixes(now time.Time, prefixes []netip.Prefix) ([]byte, error) {
	area, err := encodeAreaAddresses([]areaAddress{p.speaker.net.area})
	if err != nil {
		return nil, err
	}
	protocols, err := encodeProtocolsSupported([]byte{isisIPv4NLPID})
	if err != nil {
		return nil, err
	}
	addresses, err := encodeIPv4InterfaceAddresses([]netip.Addr{p.localAddress})
	if err != nil {
		return nil, err
	}
	tlvs := []tlv{area, protocols, addresses}
	if p.peer != nil && p.peer.state == threeWayStateUp {
		var neighbor nodeID
		copy(neighbor[:systemIDLength], p.peer.systemID[:])
		reachability, err := encodeExtendedISReachability([]extendedISReachabilityEntry{{neighborID: neighbor, metric: isisInterfaceMetric}})
		if err != nil {
			return nil, err
		}
		tlvs = append(tlvs, reachability)
	}
	for _, prefix := range prefixes {
		reachability, err := encodeExtendedIPReachability([]extendedIPReachabilityEntry{{metric: 0, prefix: prefix}})
		if err != nil {
			return nil, err
		}
		tlvs = append(tlvs, reachability)
	}
	tlvData, err := encodeTLVs(tlvs)
	if err != nil {
		return nil, err
	}
	return (lspPDU{
		remainingLifetime: uint16(lspMaximumAge / time.Second),
		id:                p.localLSPID(),
		sequenceNumber:    p.sequenceNumber,
		flags:             lspFlagOverload | lspFlagLevel2IS,
		tlvData:           tlvData,
	}).marshalBinary()
}

func (p *protocolState) localLSPID() lspID {
	var id lspID
	copy(id[:systemIDLength], p.speaker.net.systemID[:])
	return id
}

func (p *protocolState) handleLSP(received lspPDU, now time.Time) error {
	if received.remainingLifetime > uint16(lspMaximumAge/time.Second) || received.sequenceNumber == 0 {
		return nil
	}
	if received.id == p.localLSPID() {
		var localChecksum uint16
		if localLSP, err := decodeLSP(p.localLSP); err == nil {
			localChecksum = localLSP.checksum
		}
		if received.sequenceNumber > p.sequenceNumber || (received.sequenceNumber == p.sequenceNumber && received.checksum != localChecksum) {
			if received.sequenceNumber == math.MaxUint32 {
				return fmt.Errorf("%w after receiving a self-originated LSP", errLSPSequenceExhausted)
			}
			p.sequenceNumber = received.sequenceNumber
			p.localDirty = true
			return p.flushLocalLSP(now)
		}
		if received.sequenceNumber < p.sequenceNumber {
			return p.sendLocalLSP(now)
		}
		return p.sendAcknowledgement(received, now)
	}
	current, found := p.database[received.id]
	if !found {
		if received.remainingLifetime != 0 && !p.storeEntry(received, now) {
			p.speaker.logger.Warn("Ignoring IS-IS LSP because the bounded LSDB is full", "lsp-id", formatLSPID(received.id))
			return nil
		}
		if received.remainingLifetime == 0 {
			return p.sendAcknowledgement(received, now)
		}
		return p.sendAcknowledgement(received, now)
	}
	comparison := compareLSPVersions(received, pduAt(current, now))
	switch {
	case comparison > 0:
		if received.remainingLifetime == 0 {
			if !p.storeEntry(received, now) {
				return nil
			}
		} else if !p.storeEntry(received, now) {
			p.speaker.logger.Warn("Ignoring newer IS-IS LSP because the bounded LSDB is full", "lsp-id", formatLSPID(received.id))
			return nil
		}
		return p.sendAcknowledgement(received, now)
	case comparison == 0:
		return p.sendAcknowledgement(received, now)
	default:
		return p.sendLSP(current.pdu.raw, now)
	}
}

func pduAt(entry *lsdbEntry, now time.Time) lspPDU {
	result := entry.pdu
	if result.remainingLifetime == 0 {
		return result
	}
	elapsed := uint16(now.Sub(entry.receivedAt) / time.Second)
	if elapsed >= result.remainingLifetime {
		result.remainingLifetime = 0
	} else {
		result.remainingLifetime -= elapsed
	}
	return result
}

func compareLSPVersions(a, b lspPDU) int {
	if a.sequenceNumber < b.sequenceNumber {
		return -1
	}
	if a.sequenceNumber > b.sequenceNumber {
		return 1
	}
	aZero, bZero := a.remainingLifetime == 0, b.remainingLifetime == 0
	if aZero != bZero {
		if aZero {
			return 1
		}
		return -1
	}
	if a.checksum == b.checksum {
		return 0
	}
	// Equal sequence numbers with different content are treated as a
	// doppelganger. This deterministic tie break lets both systems converge.
	if a.checksum > b.checksum {
		return 1
	}
	return -1
}

func (p *protocolState) storeEntry(pdu lspPDU, now time.Time) bool {
	existing, exists := p.database[pdu.id]
	currentBytes := p.databaseBytes
	if exists {
		currentBytes -= len(existing.pdu.raw)
	}
	if len(p.database) >= lsdbMaximumEntries {
		if !exists {
			return false
		}
	}
	if currentBytes+len(pdu.raw) > lsdbMaximumBytes {
		return false
	}
	entry := &lsdbEntry{pdu: pdu, receivedAt: now}
	if pdu.remainingLifetime == 0 {
		entry.zeroAt = now
	}
	p.database[pdu.id] = entry
	p.databaseBytes = currentBytes + len(pdu.raw)
	return true
}

func (p *protocolState) removeEntry(id lspID) {
	if entry, found := p.database[id]; found {
		p.databaseBytes -= len(entry.pdu.raw)
		delete(p.database, id)
	}
	delete(p.pendingAck, id)
}

func (p *protocolState) expireDatabase(now time.Time) error {
	for id, entry := range p.database {
		if entry.pdu.remainingLifetime == 0 {
			if !entry.zeroAt.IsZero() && now.Sub(entry.zeroAt) >= lspZeroAgeLifetime {
				p.removeEntry(id)
			}
			continue
		}
		if now.Sub(entry.receivedAt) >= time.Duration(entry.pdu.remainingLifetime)*time.Second {
			purge, err := makePurgeLSP(entry.pdu.raw)
			if err != nil {
				return fmt.Errorf("purge expired IS-IS LSP %s: %w", formatLSPID(id), err)
			}
			decoded, err := decodeLSP(purge)
			if err != nil {
				return fmt.Errorf("decode purged IS-IS LSP %s: %w", formatLSPID(id), err)
			}
			if !p.storeEntry(decoded, now) {
				return fmt.Errorf("store purged IS-IS LSP %s within bounded LSDB", formatLSPID(id))
			}
			if p.peer != nil && p.peer.state == threeWayStateUp {
				if err := p.sendLSP(purge, now); err != nil {
					return fmt.Errorf("flood purged IS-IS LSP %s: %w", formatLSPID(id), err)
				}
				p.pendingAck[id] = now
			}
		}
	}
	return nil
}

func (p *protocolState) sendAcknowledgement(pdu lspPDU, now time.Time) error {
	entry := pdu
	if stored, found := p.database[pdu.id]; found {
		entry = pduAt(stored, now)
	}
	return p.sendPSNP([]lspEntry{{
		remainingLifetime: entry.remainingLifetime,
		id:                entry.id,
		sequenceNumber:    entry.sequenceNumber,
		checksum:          entry.checksum,
	}})
}

func (p *protocolState) handleCSNP(csnp csnpPDU, now time.Time) error {
	if !bytes.Equal(csnp.sourceID[:systemIDLength], p.peer.systemID[:]) {
		return nil
	}
	tlvs, err := decodeTLVs(csnp.tlvData)
	if err != nil {
		return nil
	}
	remote := make(map[lspID]lspEntry)
	for _, item := range tlvs {
		if item.code != tlvLSPEntries {
			continue
		}
		entries, err := decodeLSPEntries(item.value)
		if err != nil {
			return nil
		}
		for _, entry := range entries {
			if bytes.Compare(entry.id[:], csnp.startID[:]) >= 0 && bytes.Compare(entry.id[:], csnp.endID[:]) <= 0 {
				remote[entry.id] = entry
			}
		}
	}
	for id, their := range remote {
		local, found := p.database[id]
		if !found {
			if their.sequenceNumber != 0 && their.remainingLifetime != 0 && their.checksum != 0 {
				if err := p.sendPSNP([]lspEntry{{id: id}}); err != nil {
					return err
				}
			}
			continue
		}
		comparison := compareLSPVersions(pduAt(local, now), lspPDU{remainingLifetime: their.remainingLifetime, id: their.id, sequenceNumber: their.sequenceNumber, checksum: their.checksum})
		if comparison > 0 {
			if err := p.sendLSP(local.pdu.raw, now); err != nil {
				return err
			}
		} else if comparison < 0 {
			// A zero sequence number and checksum make this a request for the
			// newer LSP advertised by the neighbor's CSNP.
			if err := p.sendPSNP([]lspEntry{{id: id}}); err != nil {
				return err
			}
		} else {
			delete(p.pendingAck, id)
		}
	}
	localIDs := make([]lspID, 0, len(p.database))
	for id, entry := range p.database {
		if bytes.Compare(id[:], csnp.startID[:]) >= 0 && bytes.Compare(id[:], csnp.endID[:]) <= 0 && entry.pdu.sequenceNumber != 0 && entry.pdu.remainingLifetime != 0 {
			localIDs = append(localIDs, id)
		}
	}
	slices.SortFunc(localIDs, func(a, b lspID) int { return bytes.Compare(a[:], b[:]) })
	for _, id := range localIDs {
		if _, exists := remote[id]; exists {
			continue
		}
		if err := p.sendLSP(p.database[id].pdu.raw, now); err != nil {
			return err
		}
	}
	return nil
}

func (p *protocolState) handlePSNP(psnp psnpPDU, now time.Time) error {
	if !bytes.Equal(psnp.sourceID[:systemIDLength], p.peer.systemID[:]) {
		return nil
	}
	tlvs, err := decodeTLVs(psnp.tlvData)
	if err != nil {
		return nil
	}
	for _, item := range tlvs {
		if item.code != tlvLSPEntries {
			continue
		}
		entries, err := decodeLSPEntries(item.value)
		if err != nil {
			return nil
		}
		for _, their := range entries {
			local, found := p.database[their.id]
			if !found {
				continue
			}
			ours := pduAt(local, now)
			if their.sequenceNumber == 0 {
				if err := p.sendLSP(local.pdu.raw, now); err != nil {
					return err
				}
				continue
			}
			comparison := compareLSPVersions(ours, lspPDU{remainingLifetime: their.remainingLifetime, id: their.id, sequenceNumber: their.sequenceNumber, checksum: their.checksum})
			if comparison > 0 {
				if err := p.sendLSP(local.pdu.raw, now); err != nil {
					return err
				}
			} else if comparison < 0 {
				if err := p.sendPSNP([]lspEntry{{id: their.id, sequenceNumber: ours.sequenceNumber, checksum: ours.checksum, remainingLifetime: ours.remainingLifetime}}); err != nil {
					return err
				}
			} else {
				delete(p.pendingAck, their.id)
			}
		}
	}
	return nil
}

func (p *protocolState) sendCompleteCSNP(now time.Time) error {
	ids := make([]lspID, 0, len(p.database))
	for id := range p.database {
		ids = append(ids, id)
	}
	slices.SortFunc(ids, func(a, b lspID) int { return bytes.Compare(a[:], b[:]) })
	maxEntries := min(15, (p.socket.mtuSize()-csnpHeaderLength-2)/16)
	if maxEntries < 1 {
		maxEntries = 1
	}
	var zero, end lspID
	for i := range end {
		end[i] = 0xff
	}
	if len(ids) == 0 {
		return p.sendCSNP(zero, end, nil, now)
	}
	for offset := 0; offset < len(ids); {
		limit := min(offset+maxEntries, len(ids))
		entries := make([]lspEntry, 0, limit-offset)
		for _, id := range ids[offset:limit] {
			entry := pduAt(p.database[id], now)
			entries = append(entries, lspEntry{
				remainingLifetime: entry.remainingLifetime,
				id:                id,
				sequenceNumber:    entry.sequenceNumber,
				checksum:          entry.checksum,
			})
		}
		start := zero
		if offset > 0 {
			start = ids[offset]
		}
		finish := end
		if limit < len(ids) {
			finish = decrementLSPID(ids[limit])
		}
		if err := p.sendCSNP(start, finish, entries, now); err != nil {
			return err
		}
		offset = limit
	}
	return nil
}

func decrementLSPID(id lspID) lspID {
	for i := len(id) - 1; i >= 0; i-- {
		if id[i] != 0 {
			id[i]--
			for j := i + 1; j < len(id); j++ {
				id[j] = 0xff
			}
			return id
		}
	}
	return id
}

func (p *protocolState) sendCSNP(start, end lspID, entries []lspEntry, _ time.Time) error {
	var tlvData []byte
	if len(entries) != 0 {
		entryTLV, err := encodeLSPEntries(entries)
		if err != nil {
			return err
		}
		encoded, err := appendTLV(tlvData, entryTLV.code, entryTLV.value)
		if err != nil {
			return err
		}
		tlvData = encoded
	}
	var source nodeID
	copy(source[:systemIDLength], p.speaker.net.systemID[:])
	pdu, err := (csnpPDU{sourceID: source, startID: start, endID: end, tlvData: tlvData}).marshalBinary()
	if err != nil {
		return err
	}
	return p.socket.send(pdu)
}

func (p *protocolState) sendPSNP(entries []lspEntry) error {
	if len(entries) == 0 {
		return nil
	}
	slices.SortFunc(entries, func(a, b lspEntry) int { return bytes.Compare(a.id[:], b.id[:]) })
	var tlvData []byte
	for offset := 0; offset < len(entries); {
		limit := min(offset+15, len(entries))
		entryTLV, err := encodeLSPEntries(entries[offset:limit])
		if err != nil {
			return err
		}
		encoded, err := appendTLV(tlvData, entryTLV.code, entryTLV.value)
		if err != nil {
			return err
		}
		tlvData = encoded
		offset = limit
	}
	var source nodeID
	copy(source[:systemIDLength], p.speaker.net.systemID[:])
	pdu, err := (psnpPDU{sourceID: source, tlvData: tlvData}).marshalBinary()
	if err != nil {
		return err
	}
	return p.socket.send(pdu)
}

func (p *protocolState) sendLocalLSP(now time.Time) error {
	if len(p.localLSP) == 0 {
		return nil
	}
	if err := p.sendLSP(p.localLSP, now); err != nil {
		return err
	}
	p.pendingAck[p.localLSPID()] = now
	return nil
}

func (p *protocolState) sendLocalOrDatabaseLSP(id lspID, now time.Time) error {
	if entry, ok := p.database[id]; ok {
		return p.sendLSP(entry.pdu.raw, now)
	}
	return nil
}

func (p *protocolState) sendLSP(raw []byte, now time.Time) error {
	decoded, err := decodeLSP(raw)
	if err != nil {
		return fmt.Errorf("refuse invalid IS-IS LSP from LSDB: %w", err)
	}
	if decoded.remainingLifetime == 0 {
		return p.socket.send(raw)
	}
	remaining := decoded.remainingLifetime
	if entry, found := p.database[decoded.id]; found {
		remaining = pduAt(entry, now).remainingLifetime
	}
	if remaining == 0 {
		purge, err := makePurgeLSP(raw)
		if err != nil {
			return err
		}
		return p.socket.send(purge)
	}
	if remaining == decoded.remainingLifetime {
		remaining--
	}
	packet := bytes.Clone(raw)
	binary.BigEndian.PutUint16(packet[10:12], remaining)
	if err := p.socket.send(packet); err != nil {
		return err
	}
	if decoded.id == p.localLSPID() {
		p.pendingAck[decoded.id] = now
	}
	return nil
}

func (p *protocolState) shutdown() {
	if p.peer == nil || p.peer.state != threeWayStateUp {
		return
	}
	now := time.Now()
	if len(p.localLSP) != 0 {
		if purge, err := makePurgeLSP(p.localLSP); err == nil {
			_ = p.socket.send(purge)
		}
	}
	p.peer.state = threeWayStateDown
	_ = p.sendHello(now)
}

func makePurgeLSP(raw []byte) ([]byte, error) {
	lsp, err := decodeLSP(raw)
	if err != nil {
		return nil, err
	}
	lsp.remainingLifetime = 0
	lsp.tlvData = nil
	lsp.raw = nil
	return lsp.marshalBinary()
}

func formatLSPID(id lspID) string {
	return fmt.Sprintf("%02x%02x.%02x%02x.%02x%02x-%02x-%02x", id[0], id[1], id[2], id[3], id[4], id[5], id[6], id[7])
}
