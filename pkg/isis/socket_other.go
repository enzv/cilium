// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package isis

import (
	"errors"
	"fmt"
)

var errPacketSocketTimeout = errors.New("IS-IS packet socket read timed out")

func openPacketSocket(interfaceName string) (speakerSocket, error) {
	return nil, fmt.Errorf("IS-IS packet sockets are only supported on Linux (interface %q)", interfaceName)
}
