// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package isis

import (
	"context"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/loadbalancer"
)

// Cell is the experimental, disabled-by-default IS-IS control plane.
var Cell = cell.Module(
	"isis-control-plane",
	"Experimental IS-IS control plane",
	cell.Config(DefaultConfig),
	cell.ProvidePrivate(newSpeaker),
	cell.Invoke(startSpeaker),
	cell.Invoke(startServiceWatcher),
)

// DatapathWaiter gates route origination on Cilium's host datapath and load
// balancer having completed initialization.
type DatapathWaiter interface {
	Wait(context.Context) error
}

type datapathWaiter struct {
	hostDatapathInitialized <-chan struct{}
	lbInitWait              func(context.Context) error
}

// NewDatapathWaiter constructs the initialization gate used by the speaker.
func NewDatapathWaiter(hostDatapathInitialized <-chan struct{}, lbInitWait func(context.Context) error) DatapathWaiter {
	return datapathWaiter{hostDatapathInitialized: hostDatapathInitialized, lbInitWait: lbInitWait}
}

func (w datapathWaiter) Wait(ctx context.Context) error {
	select {
	case <-w.hostDatapathInitialized:
	case <-ctx.Done():
		return ctx.Err()
	}
	return w.lbInitWait(ctx)
}

func startSpeaker(group job.Group, speaker *speaker) {
	if !speaker.enabled {
		return
	}
	group.Add(job.OneShot("isis-speaker", func(ctx context.Context, _ cell.Health) error {
		return speaker.run(ctx)
	}, job.WithRetry(-1, &job.ExponentialBackoff{Min: time.Second, Max: 30 * time.Second})))
}

func startServiceWatcher(
	group job.Group,
	cfg Config,
	db *statedb.DB,
	frontends statedb.Table[*loadbalancer.Frontend],
	speaker *speaker,
) {
	if !cfg.Enabled {
		return
	}
	group.Add(job.OneShot("isis-service-frontends", func(ctx context.Context, _ cell.Health) error {
		return watchServiceFrontends(ctx, db, frontends, speaker)
	}))
}
