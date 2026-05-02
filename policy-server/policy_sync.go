package main

import (
	"context"
	"errors"
	"log"
	"time"
)

func runPolicySyncLoop(ctx context.Context, store *Store, source PolicySource, interval time.Duration) {
	if interval <= 0 {
		interval = 2 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := syncPolicyOnce(ctx, store, source); err != nil {
				log.Printf("policy sync error: %v", err)
			}
		}
	}
}

func syncPolicyOnce(ctx context.Context, store *Store, source PolicySource) error {
	start := time.Now()
	result := "error"
	defer func() {
		policyStoreSyncTotal.WithLabelValues(result).Inc()
		policyStoreSyncDuration.Observe(time.Since(start).Seconds())
	}()

	snapshot, err := source.LoadActive(ctx)
	if err != nil {
		result = "stale"
		store.MarkSyncStale(source.Name(), err)
		policyStoreDBErrorsTotal.WithLabelValues("load_active").Inc()
		return err
	}

	current := store.CurrentInfo()
	if !current.Ready || current.Version != snapshot.Version || current.ContentHash != snapshot.ContentHash {
		if err := store.ApplySnapshot(snapshot); err != nil {
			store.MarkSyncStale(source.Name(), err)
			return err
		}
	} else {
		store.MarkSyncOK(source.Name())
	}

	result = "ok"
	return nil
}

func loadInitialPolicy(ctx context.Context, store *Store, source PolicySource) error {
	if pgSource, ok := source.(*PostgresPolicySource); ok {
		snapshot, err := pgSource.LoadActive(ctx)
		if errors.Is(err, ErrNoActivePolicy) {
			seededSnapshot, seeded, seedErr := pgSource.SeedFromFileIfMissing(ctx, "startup")
			if seedErr != nil {
				store.MarkSyncStale(source.Name(), seedErr)
				policyStoreDBErrorsTotal.WithLabelValues("seed").Inc()
				return seedErr
			}
			if seeded {
				log.Printf("Seeded initial policy version=%s hash=%s", seededSnapshot.Version, seededSnapshot.ContentHash)
			}
			return store.ApplySnapshot(seededSnapshot)
		}
		if err != nil {
			store.MarkSyncStale(source.Name(), err)
			policyStoreDBErrorsTotal.WithLabelValues("load_active").Inc()
			return err
		}
		return store.ApplySnapshot(snapshot)
	}

	_, err := store.ReloadFromSource(ctx, source, "startup")
	return err
}
