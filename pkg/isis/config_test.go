// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package isis

import (
	"bytes"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/hive"
)

func TestParseNET(t *testing.T) {
	parsed, err := parseNET("49.0001.0000.0000.00c1.00")
	if err != nil {
		t.Fatalf("parseNET() error = %v", err)
	}
	if !bytes.Equal(parsed.area, []byte{0x49, 0x00, 0x01}) {
		t.Errorf("area = %x, want 490001", parsed.area)
	}
	if parsed.systemID != (systemID{0, 0, 0, 0, 0, 0xc1}) {
		t.Errorf("systemID = %x, want 0000000000c1", parsed.systemID)
	}
}

func TestParseNETRejectsInvalidValues(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{name: "empty"},
		{name: "invalid hex", value: "49.0001.0000.0000.00cg.00"},
		{name: "odd group", value: "4.90001.0000.0000.00c1.00"},
		{name: "empty group", value: "49..0001.0000.0000.00c1.00"},
		{name: "too short", value: "49.0000000000.00"},
		{name: "too long area", value: "49.0001.0001.0001.0001.0001.0001.0001.0001.0001.0001.0001.0001.0001.0000.0000.0000.0000.0000.00"},
		{name: "nonzero NSEL", value: "49.0001.0000.0000.00c1.01"},
		{name: "reserved zero AFI", value: "00.0001.0000.0000.00c1.00"},
		{name: "reserved ff AFI", value: "ff.0001.0000.0000.00c1.00"},
		{name: "surrounding whitespace", value: " 49.0001.0000.0000.00c1.00"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := parseNET(tt.value); err == nil {
				t.Fatalf("parseNET(%q) succeeded", tt.value)
			}
		})
	}
}

func TestConfigValidate(t *testing.T) {
	if _, err := (Config{}).validate(); err != nil {
		t.Fatalf("disabled config should not require interface or NET: %v", err)
	}
	if _, err := (Config{Enabled: true, NET: "49.0001.0000.0000.00c1.00"}).validate(); err == nil {
		t.Fatal("enabled config without interface succeeded")
	}
	if _, err := (Config{Enabled: true, Interface: "br0"}).validate(); err == nil {
		t.Fatal("enabled config without NET succeeded")
	}
	if _, err := (Config{Enabled: true, Interface: " br0", NET: "49.0001.0000.0000.00c1.00"}).validate(); err == nil {
		t.Fatal("enabled config with whitespace in interface succeeded")
	}
	if _, err := (Config{Enabled: true, Interface: "br0", NET: "49.0001.0000.0000.00c1.00"}).validate(); err != nil {
		t.Fatalf("valid config error = %v", err)
	}
}

func TestConfigFlags(t *testing.T) {
	var got Config
	h := hive.New(
		cell.Config(DefaultConfig),
		cell.Invoke(func(cfg Config) { got = cfg }),
	)
	flags := pflag.NewFlagSet("isis", pflag.ContinueOnError)
	h.RegisterFlags(flags)
	require.NoError(t, flags.Parse([]string{
		"--enable-isis-control-plane",
		"--isis-interface=br-l2-a",
		"--isis-net=49.0001.0000.0000.00c1.00",
	}))
	require.NoError(t, h.Populate(hivetest.Logger(t)))
	require.Equal(t, Config{
		Enabled:   true,
		Interface: "br-l2-a",
		NET:       "49.0001.0000.0000.00c1.00",
	}, got)
}
