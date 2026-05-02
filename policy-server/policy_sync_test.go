package main

import (
	"context"
	"errors"
	"testing"

	"authz-system/internal/authz"
)

func TestSyncPolicyOnceAppliesChangedActiveVersion(t *testing.T) {
	store := &Store{}
	source := &fakePolicySource{
		name:     policySourcePostgres,
		snapshot: testPolicySnapshot(t, "p1-111111111111", "111111111111", "/payments/charge", "allow"),
	}

	if err := syncPolicyOnce(context.Background(), store, source); err != nil {
		t.Fatalf("sync policy: %v", err)
	}

	info := store.CurrentInfo()
	if !info.Ready {
		t.Fatal("store is not ready after sync")
	}
	if info.Version != "p1-111111111111" {
		t.Fatalf("version = %q", info.Version)
	}
	if info.SyncStatus != syncStatusOK {
		t.Fatalf("sync status = %q, want ok", info.SyncStatus)
	}
	if info.LastSyncAt.IsZero() {
		t.Fatal("last sync time is zero")
	}
}

func TestSyncPolicyOnceMarksStaleAndKeepsLastKnownGood(t *testing.T) {
	store := &Store{}
	if err := store.ApplySnapshot(testPolicySnapshot(t, "p1-111111111111", "111111111111", "/payments/charge", "allow")); err != nil {
		t.Fatalf("apply initial snapshot: %v", err)
	}
	source := &fakePolicySource{
		name: policySourcePostgres,
		err:  errors.New("database unavailable"),
	}

	if err := syncPolicyOnce(context.Background(), store, source); err == nil {
		t.Fatal("sync error = nil, want error")
	}

	info := store.CurrentInfo()
	if !info.Ready {
		t.Fatal("store should remain ready with last-known-good policy")
	}
	if info.Version != "p1-111111111111" {
		t.Fatalf("version = %q, want old version", info.Version)
	}
	if info.SyncStatus != syncStatusStale {
		t.Fatalf("sync status = %q, want stale", info.SyncStatus)
	}
	if info.SyncError == "" {
		t.Fatal("sync error is empty")
	}

	resp := store.Decide(context.Background(), authz.NewAuthzRequest("orders", "payments", authz.TransportHTTP, "POST", "/payments/charge"))
	if !resp.Allow {
		t.Fatalf("last-known-good policy stopped allowing request: %+v", resp)
	}
}

func TestSyncPolicyOnceMissingWithoutActivePolicy(t *testing.T) {
	store := &Store{}
	source := &fakePolicySource{
		name: policySourcePostgres,
		err:  errors.New("database unavailable"),
	}

	if err := syncPolicyOnce(context.Background(), store, source); err == nil {
		t.Fatal("sync error = nil, want error")
	}

	info := store.CurrentInfo()
	if info.Ready {
		t.Fatal("store should not be ready without active policy")
	}
	if info.SyncStatus != syncStatusMissing {
		t.Fatalf("sync status = %q, want missing", info.SyncStatus)
	}
}

type fakePolicySource struct {
	name     string
	snapshot PolicySnapshot
	err      error
}

func (s *fakePolicySource) Name() string {
	return s.name
}

func (s *fakePolicySource) LoadActive(context.Context) (PolicySnapshot, error) {
	if s.err != nil {
		return PolicySnapshot{}, s.err
	}
	return s.snapshot, nil
}

func (s *fakePolicySource) Reload(context.Context, string) (PolicySnapshot, error) {
	if s.err != nil {
		return PolicySnapshot{}, s.err
	}
	return s.snapshot, nil
}

func testPolicySnapshot(t *testing.T, version, hash, resource, effect string) PolicySnapshot {
	t.Helper()
	content := []byte(validRepositoryPolicy(resource, effect))
	rules, err := validatePolicyContent(content)
	if err != nil {
		t.Fatalf("validate policy: %v", err)
	}
	return PolicySnapshot{
		Version:     version,
		ContentHash: hash,
		Rules:       rules,
		RawYAML:     content,
		Source:      policySourcePostgres,
		SyncStatus:  syncStatusOK,
	}
}
