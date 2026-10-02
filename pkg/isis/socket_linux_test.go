// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package isis

import (
	"encoding/binary"
	"testing"

	"golang.org/x/sys/unix"
)

func TestDecodeLLCPayload(t *testing.T) {
	payload := []byte{0xfe, 0xfe, 0x03, 0x83, 0x14, 0x01}
	got, err := decodeLLCPayload(payload)
	if err != nil {
		t.Fatalf("decodeLLCPayload() error = %v", err)
	}
	if string(got) != string(payload[llcHeaderLength:]) {
		t.Fatalf("decodeLLCPayload() = %x, want %x", got, payload[llcHeaderLength:])
	}
	for _, malformed := range [][]byte{nil, {0xfe}, {0xfe, 0xfe, 0x04}} {
		if _, err := decodeLLCPayload(malformed); err == nil {
			t.Errorf("decodeLLCPayload(%x) succeeded", malformed)
		}
	}
}

func TestP2POverLANMulticastAddress(t *testing.T) {
	want := [6]byte{0x09, 0x00, 0x2b, 0x00, 0x00, 0x05}
	if allISsAddress != want {
		t.Fatalf("AllISs multicast address = %x, want %x", allISsAddress, want)
	}
}

func TestISISPDUFilter(t *testing.T) {
	for _, kind := range []pduType{pduTypeP2PHello, pduTypeL2LSP, pduTypeL2CSNP, pduTypeL2PSNP} {
		if !runISISPDUFilter(isisPDUFilter(), llcPayload(kind)) {
			t.Errorf("IS-IS filter rejected PDU type %d", kind)
		}
	}
	for _, packet := range [][]byte{
		llcPayload(18),
		llcPayloadWithLLC([llcHeaderLength]byte{0xfe, 0xfe, 0x04}, pduTypeL2LSP),
	} {
		if runISISPDUFilter(isisPDUFilter(), packet) {
			t.Errorf("IS-IS filter accepted unrelated frame %x", packet)
		}
	}
}

func llcPayload(kind pduType) []byte {
	return llcPayloadWithLLC(isisLLCHeader, kind)
}

func llcPayloadWithLLC(llc [llcHeaderLength]byte, kind pduType) []byte {
	frame := append([]byte(nil), llc[:]...)
	pduHeader := make([]byte, commonHeaderLength)
	pduHeader[4] = byte(kind)
	return append(frame, pduHeader...)
}

func runISISPDUFilter(program []unix.SockFilter, packet []byte) bool {
	var accumulator uint32
	for pc := 0; pc < len(program); pc++ {
		instruction := program[pc]
		switch instruction.Code {
		case packetFilterLoadByteAbsolute:
			if int(instruction.K) >= len(packet) {
				return false
			}
			accumulator = uint32(packet[instruction.K])
		case packetFilterJumpEqual:
			if accumulator == instruction.K {
				pc += int(instruction.Jt)
			} else {
				pc += int(instruction.Jf)
			}
		case packetFilterReturn:
			return instruction.K != 0
		default:
			return false
		}
	}
	return false
}

func TestHostToNetwork16(t *testing.T) {
	value := hostToNetwork16(unix.ETH_P_802_2)
	var networkBytes [2]byte
	binary.NativeEndian.PutUint16(networkBytes[:], value)
	if got := binary.BigEndian.Uint16(networkBytes[:]); got != unix.ETH_P_802_2 {
		t.Fatalf("hostToNetwork16(ETH_P_802_2) = %#x, want %#x", got, unix.ETH_P_802_2)
	}
}
