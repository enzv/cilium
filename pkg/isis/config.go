// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package isis

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/spf13/pflag"
)

const (
	EnableControlPlaneFlag = "enable-isis-control-plane"
	InterfaceFlag          = "isis-interface"
	NETFlag                = "isis-net"
)

// Config contains the deliberately small set of settings for the IS-IS
// speaker. NET supplies the stable System ID and area address.
type Config struct {
	Enabled   bool   `mapstructure:"enable-isis-control-plane"`
	Interface string `mapstructure:"isis-interface"`
	NET       string `mapstructure:"isis-net"`
}

var DefaultConfig = Config{
	Enabled:   false,
	Interface: "",
	NET:       "",
}

func (def Config) Flags(flags *pflag.FlagSet) {
	flags.Bool(EnableControlPlaneFlag, def.Enabled, "Enable the experimental IS-IS control plane")
	flags.String(InterfaceFlag, def.Interface, "Host interface used for the IS-IS point-to-point circuit")
	flags.String(NETFlag, def.NET, "IS-IS NET for the local system, including NSEL 00")
}

func (c Config) validate() (isisNET, error) {
	if !c.Enabled {
		return isisNET{}, nil
	}
	if c.Interface == "" || strings.TrimSpace(c.Interface) != c.Interface {
		return isisNET{}, fmt.Errorf("%s must name one interface without surrounding whitespace", InterfaceFlag)
	}
	net, err := parseNET(c.NET)
	if err != nil {
		return isisNET{}, fmt.Errorf("invalid %s: %w", NETFlag, err)
	}
	return net, nil
}

type isisNET struct {
	area     areaAddress
	systemID systemID
}

func parseNET(value string) (isisNET, error) {
	var parsed isisNET
	if value == "" || strings.TrimSpace(value) != value {
		return parsed, fmt.Errorf("must be a dotted hexadecimal NET")
	}

	groups := strings.Split(value, ".")
	var compact strings.Builder
	for _, group := range groups {
		if len(group) == 0 || len(group)%2 != 0 {
			return parsed, fmt.Errorf("NET groups must contain whole octets")
		}
		for _, digit := range group {
			if !((digit >= '0' && digit <= '9') || (digit >= 'a' && digit <= 'f') || (digit >= 'A' && digit <= 'F')) {
				return parsed, fmt.Errorf("NET contains non-hexadecimal character %q", digit)
			}
		}
		compact.WriteString(group)
	}
	decoded, err := hex.DecodeString(compact.String())
	if err != nil {
		return parsed, fmt.Errorf("decode hexadecimal value: %w", err)
	}
	areaLength := len(decoded) - len(parsed.systemID) - 1
	if areaLength < 1 || areaLength > maxAreaAddressSize {
		return parsed, fmt.Errorf("area address length %d is outside 1..%d octets", areaLength, maxAreaAddressSize)
	}
	if decoded[len(decoded)-1] != 0 {
		return parsed, fmt.Errorf("NSEL must be 00")
	}
	// The first area-address octet is the AFI. Zero and 255 are reserved.
	if decoded[0] == 0 || decoded[0] == 0xff {
		return parsed, fmt.Errorf("area address has reserved AFI %#02x", decoded[0])
	}
	parsed.area = append(areaAddress(nil), decoded[:areaLength]...)
	copy(parsed.systemID[:], decoded[areaLength:areaLength+len(parsed.systemID)])
	return parsed, nil
}
