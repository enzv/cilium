// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package isis

import (
	"iter"
	"net/netip"
	"testing"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
	"github.com/stretchr/testify/require"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/loadbalancer"
)

func TestSelectedServicePrefixesDeduplicatesFrontendPorts(t *testing.T) {
	first := selectedFrontend("10.200.0.42", 0, loadbalancer.SVCTypeLoadBalancer, loadbalancer.SVCTrafficPolicyCluster, reconciler.StatusKindDone, "true")
	second := selectedFrontend("10.200.0.42", 0, loadbalancer.SVCTypeLoadBalancer, loadbalancer.SVCTrafficPolicyCluster, reconciler.StatusKindDone, "true")

	prefixes := selectedServicePrefixes(frontendSequence(first, second))
	require.Equal(t, []netip.Prefix{netip.MustParsePrefix("10.200.0.42/32")}, prefixes)
}

func TestSelectedServicePrefixesReturnsMultipleDistinctIPsInOrder(t *testing.T) {
	frontends := []*loadbalancer.Frontend{
		selectedFrontend("10.200.0.43", 0, loadbalancer.SVCTypeLoadBalancer, loadbalancer.SVCTrafficPolicyCluster, reconciler.StatusKindDone, "true"),
		selectedFrontend("10.200.0.42", 0, loadbalancer.SVCTypeLoadBalancer, loadbalancer.SVCTrafficPolicyCluster, reconciler.StatusKindDone, "true"),
		selectedFrontend("10.200.0.43", 0, loadbalancer.SVCTypeLoadBalancer, loadbalancer.SVCTrafficPolicyCluster, reconciler.StatusKindDone, "true"),
	}

	prefixes := selectedServicePrefixes(frontendSequence(frontends...))
	require.Equal(t, []netip.Prefix{
		netip.MustParsePrefix("10.200.0.42/32"),
		netip.MustParsePrefix("10.200.0.43/32"),
	}, prefixes)
}

func TestSelectedServicePrefixesFiltersUnsupportedFrontends(t *testing.T) {
	eligible := selectedFrontend("10.200.0.42", 0, loadbalancer.SVCTypeLoadBalancer, loadbalancer.SVCTrafficPolicyCluster, reconciler.StatusKindDone, "true")
	ignored := []*loadbalancer.Frontend{
		selectedFrontend("10.200.0.43", 0, loadbalancer.SVCTypeLoadBalancer, loadbalancer.SVCTrafficPolicyCluster, reconciler.StatusKindDone, "false"),
		selectedFrontend("10.200.0.44", 0, loadbalancer.SVCTypeLoadBalancer, loadbalancer.SVCTrafficPolicyLocal, reconciler.StatusKindDone, "true"),
		selectedFrontend("10.200.0.45", 0, loadbalancer.SVCTypeLoadBalancer, loadbalancer.SVCTrafficPolicyCluster, reconciler.StatusKindPending, "true"),
		selectedFrontend("10.200.0.46", 1, loadbalancer.SVCTypeLoadBalancer, loadbalancer.SVCTrafficPolicyCluster, reconciler.StatusKindDone, "true"),
		selectedFrontend("10.200.0.47", 0, loadbalancer.SVCTypeExternalIPs, loadbalancer.SVCTrafficPolicyCluster, reconciler.StatusKindDone, "true"),
		selectedFrontend("2001:db8::1", 0, loadbalancer.SVCTypeLoadBalancer, loadbalancer.SVCTrafficPolicyCluster, reconciler.StatusKindDone, "true"),
	}
	prefixes := selectedServicePrefixes(frontendSequence(append([]*loadbalancer.Frontend{eligible}, ignored...)...))
	require.Equal(t, []netip.Prefix{netip.MustParsePrefix("10.200.0.42/32")}, prefixes)
}

func selectedFrontend(address string, clusterID uint32, kind loadbalancer.SVCType, policy loadbalancer.SVCTrafficPolicy, status reconciler.StatusKind, advertise string) *loadbalancer.Frontend {
	addr := netip.MustParseAddr(address)
	return &loadbalancer.Frontend{
		FrontendParams: loadbalancer.FrontendParams{
			Type:    kind,
			Address: loadbalancer.NewL3n4Addr(loadbalancer.TCP, cmtypes.AddrClusterFrom(addr, clusterID), 80, loadbalancer.ScopeExternal),
		},
		Status: reconciler.Status{Kind: status},
		ID:     1,
		Service: &loadbalancer.Service{
			ExtTrafficPolicy: policy,
			Annotations:      map[string]string{advertiseAnnotation: advertise},
		},
	}
}

func frontendSequence(frontends ...*loadbalancer.Frontend) iter.Seq2[*loadbalancer.Frontend, statedb.Revision] {
	return func(yield func(*loadbalancer.Frontend, statedb.Revision) bool) {
		for _, frontend := range frontends {
			if !yield(frontend, 1) {
				return
			}
		}
	}
}
