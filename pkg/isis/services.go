// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package isis

import (
	"context"
	"iter"
	"net/netip"
	"slices"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"

	"github.com/cilium/cilium/pkg/loadbalancer"
)

const advertiseAnnotation = "isis.cilium.io/advertise"

// watchServiceFrontends reconstructs the complete advertised prefix set from
// the current StateDB view whenever the frontend table changes.
func watchServiceFrontends(
	ctx context.Context,
	db *statedb.DB,
	frontends statedb.Table[*loadbalancer.Frontend],
	speaker *speaker,
) error {
	for {
		txn := db.ReadTxn()
		items, watch := frontends.AllWatch(txn)
		speaker.SetPrefixes(selectedServicePrefixes(items))

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-watch:
		}
	}
}

func selectedServicePrefixes(frontends iter.Seq2[*loadbalancer.Frontend, statedb.Revision]) []netip.Prefix {
	selected := make(map[netip.Addr]struct{})
	for frontend, _ := range frontends {
		if !selectedServiceFrontend(frontend) {
			continue
		}
		address := frontend.Address.AddrCluster().Addr()
		selected[address] = struct{}{}
	}
	prefixes := make([]netip.Prefix, 0, len(selected))
	for address := range selected {
		prefixes = append(prefixes, netip.PrefixFrom(address, 32))
	}
	slices.SortFunc(prefixes, func(a, b netip.Prefix) int { return a.Addr().Compare(b.Addr()) })
	return prefixes
}

func selectedServiceFrontend(frontend *loadbalancer.Frontend) bool {
	if frontend == nil || frontend.Type != loadbalancer.SVCTypeLoadBalancer {
		return false
	}
	if frontend.Address.Scope() != loadbalancer.ScopeExternal || frontend.Address.AddrCluster().ClusterID() != 0 {
		return false
	}
	if frontend.Status.Kind != reconciler.StatusKindDone || frontend.ID == 0 || frontend.Service == nil {
		return false
	}
	if frontend.Service.ExtTrafficPolicy != loadbalancer.SVCTrafficPolicyCluster {
		return false
	}
	if frontend.Service.Annotations[advertiseAnnotation] != "true" {
		return false
	}
	address := frontend.Address.AddrCluster().Addr()
	return address.Is4() && address.IsGlobalUnicast()
}
