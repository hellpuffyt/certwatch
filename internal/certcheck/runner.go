package certcheck

import (
	"context"
	"sync"
	"time"

	"certwatch/internal/inventory"
)

// RunOptions configures a concurrent inventory check.
type RunOptions struct {
	// Concurrency bounds how many hosts are checked at once. Values <= 0
	// default to 10.
	Concurrency int
	// PerHostTimeout bounds a single host's fetch. Values <= 0 default to
	// 10s. It is enforced independently of Deadline so one slow host
	// cannot silently eat the whole run's budget beyond its own timeout.
	PerHostTimeout time.Duration
	// Deadline bounds the whole run. Values <= 0 mean no overall deadline
	// beyond the per-host timeouts.
	Deadline time.Duration
	// Defaults are the inventory-level lead times applied when a host has
	// no override.
	Defaults inventory.LeadTimes
	// Now is the reference time used for severity evaluation. Zero means
	// time.Now().
	Now time.Time
}

// Run checks every host in the inventory concurrently using fetcher,
// respecting a bounded worker pool, a per-host timeout, and an optional
// total deadline. A single host that errors (timeout, connection refused,
// handshake failure) produces a Result with SeverityError instead of
// aborting the run — one unreachable host never stalls or fails the whole
// batch. Results are returned in inventory order regardless of completion
// order.
func Run(ctx context.Context, fetcher Fetcher, hosts []inventory.Host, opts RunOptions) []Result {
	concurrency := opts.Concurrency
	if concurrency <= 0 {
		concurrency = 10
	}
	perHostTimeout := opts.PerHostTimeout
	if perHostTimeout <= 0 {
		perHostTimeout = 10 * time.Second
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}

	runCtx := ctx
	var cancel context.CancelFunc
	if opts.Deadline > 0 {
		runCtx, cancel = context.WithTimeout(ctx, opts.Deadline)
		defer cancel()
	}

	results := make([]Result, len(hosts))
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for i, h := range hosts {
		wg.Add(1)
		go func(i int, h inventory.Host) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			hostCtx, hostCancel := context.WithTimeout(runCtx, perHostTimeout)
			defer hostCancel()

			lt := h.EffectiveLeadTimes(opts.Defaults)

			info, err := fetcher.Fetch(hostCtx, h)
			if err != nil {
				results[i] = EvaluateError(h, now, err)
				return
			}
			results[i] = Evaluate(h, info, lt, now)
		}(i, h)
	}

	wg.Wait()
	return results
}
