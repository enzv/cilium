// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package isis

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"

	"github.com/stretchr/testify/require"
)

func TestDatapathWaiterWaitsForHostAndLoadBalancer(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		hostReady := make(chan struct{})
		lbReady := make(chan struct{})
		lbWaitCalled := make(chan struct{}, 1)
		waiter := NewDatapathWaiter(hostReady, func(ctx context.Context) error {
			lbWaitCalled <- struct{}{}
			select {
			case <-lbReady:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})
		done := make(chan error, 1)
		go func() { done <- waiter.Wait(context.Background()) }()

		synctest.Wait()
		select {
		case <-lbWaitCalled:
			t.Fatal("load-balancer wait began before the host datapath was ready")
		default:
		}

		close(hostReady)
		synctest.Wait()
		select {
		case <-lbWaitCalled:
		default:
			t.Fatal("load-balancer wait did not begin after the host datapath was ready")
		}

		close(lbReady)
		synctest.Wait()
		require.NoError(t, <-done)
	})
}

func TestDatapathWaiterPropagatesCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	waiter := NewDatapathWaiter(make(chan struct{}), func(context.Context) error {
		return errors.New("load-balancer wait must not be called")
	})
	require.ErrorIs(t, waiter.Wait(ctx), context.Canceled)
}
