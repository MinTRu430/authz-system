package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"authz-system/internal/authz"
)

func TestFilePolicySourceLoadsAndNormalizesYAML(t *testing.T) {
	source := NewFilePolicySource(writePolicyContent(t, strings.Join([]string{
		"- id: R1",
		"  source: orders",
		"  target: payments",
		"  rpc: /payments.v1.Payments/Charge",
		"  effect: ALLOW",
		"",
	}, "\n")))

	snapshot, err := source.LoadActive(context.Background())
	if err != nil {
		t.Fatalf("load active: %v", err)
	}

	if snapshot.Source != policySourceFile {
		t.Fatalf("source = %q, want %q", snapshot.Source, policySourceFile)
	}
	if snapshot.SyncStatus != syncStatusOK {
		t.Fatalf("sync status = %q, want %q", snapshot.SyncStatus, syncStatusOK)
	}
	if snapshot.ContentHash == "" {
		t.Fatal("content hash is empty")
	}
	if !strings.HasPrefix(snapshot.Version, "file-") {
		t.Fatalf("version = %q, want file-*", snapshot.Version)
	}
	if len(snapshot.Rules) != 1 {
		t.Fatalf("rules len = %d, want 1", len(snapshot.Rules))
	}

	rule := snapshot.Rules[0]
	if rule.Transport != authz.TransportGRPC {
		t.Fatalf("transport = %q, want grpc", rule.Transport)
	}
	if rule.Operation != "/payments.v1.Payments/Charge" {
		t.Fatalf("operation = %q, want legacy rpc operation", rule.Operation)
	}
	if rule.Effect != "allow" {
		t.Fatalf("effect = %q, want allow", rule.Effect)
	}
}

func TestFilePolicySourceVersionIsDeterministic(t *testing.T) {
	content := strings.Join([]string{
		"- id: R1",
		"  source: orders",
		"  target: payments",
		"  transport: http",
		"  operation: POST",
		"  resource: /payments/charge",
		"  effect: allow",
		"",
	}, "\n")
	source := NewFilePolicySource(writePolicyContent(t, content))

	first, err := source.LoadActive(context.Background())
	if err != nil {
		t.Fatalf("first load: %v", err)
	}
	second, err := source.LoadActive(context.Background())
	if err != nil {
		t.Fatalf("second load: %v", err)
	}

	if first.ContentHash != second.ContentHash {
		t.Fatalf("content hash changed: %q != %q", first.ContentHash, second.ContentHash)
	}
	if first.Version != second.Version {
		t.Fatalf("version changed: %q != %q", first.Version, second.Version)
	}
}

func TestFilePolicySourceContentChangeChangesVersion(t *testing.T) {
	path := writePolicyContent(t, strings.Join([]string{
		"- id: R1",
		"  source: orders",
		"  target: payments",
		"  transport: http",
		"  operation: POST",
		"  resource: /payments/charge",
		"  effect: allow",
		"",
	}, "\n"))
	source := NewFilePolicySource(path)

	first, err := source.LoadActive(context.Background())
	if err != nil {
		t.Fatalf("first load: %v", err)
	}

	updated := strings.Join([]string{
		"- id: R1",
		"  source: orders",
		"  target: payments",
		"  transport: http",
		"  operation: POST",
		"  resource: /payments/refund",
		"  effect: deny",
		"",
	}, "\n")
	if err := os.WriteFile(path, []byte(updated), 0600); err != nil {
		t.Fatalf("write updated policy: %v", err)
	}

	second, err := source.LoadActive(context.Background())
	if err != nil {
		t.Fatalf("second load: %v", err)
	}

	if first.ContentHash == second.ContentHash {
		t.Fatalf("content hash did not change: %q", first.ContentHash)
	}
	if first.Version == second.Version {
		t.Fatalf("version did not change: %q", first.Version)
	}
}

func TestInvalidReloadDoesNotReplaceActivePolicy(t *testing.T) {
	valid := writeTestPolicy(t)
	invalid := writePolicyContent(t, "- id: R1\n  effect: [unterminated\n")

	store := &Store{}
	if err := store.ReloadFromFile(valid); err != nil {
		t.Fatalf("reload valid policy: %v", err)
	}
	before := store.CurrentInfo()

	if err := store.ReloadFromFile(invalid); err == nil {
		t.Fatal("reload invalid policy error = nil, want error")
	}

	after := store.CurrentInfo()
	if after.Version != before.Version {
		t.Fatalf("version changed after invalid reload: %q != %q", after.Version, before.Version)
	}
	if after.ContentHash != before.ContentHash {
		t.Fatalf("content hash changed after invalid reload: %q != %q", after.ContentHash, before.ContentHash)
	}

	resp := store.Decide(context.Background(), authz.NewAuthzRequest("orders", "payments", authz.TransportHTTP, "POST", "/payments/charge"))
	if !resp.Allow {
		t.Fatalf("old active policy was not preserved: %+v", resp)
	}
}

func TestPolicySourceConfigDefaultsToFile(t *testing.T) {
	path := writeTestPolicy(t)
	source, err := NewPolicySourceFromConfig(PolicySourceConfig{FilePath: path})
	if err != nil {
		t.Fatalf("new source: %v", err)
	}
	if source.Name() != policySourceFile {
		t.Fatalf("source name = %q, want %q", source.Name(), policySourceFile)
	}
}

func TestPolicySourceConfigRejectsUnsupportedSource(t *testing.T) {
	_, err := NewPolicySourceFromConfig(PolicySourceConfig{Source: "consul", FilePath: writeTestPolicy(t)})
	if err == nil {
		t.Fatal("unsupported source error = nil, want error")
	}
	if !strings.Contains(err.Error(), "unsupported POLICY_SOURCE") {
		t.Fatalf("error = %q, want unsupported POLICY_SOURCE", err.Error())
	}
}

func TestPolicySourceConfigPostgresRequiresDSN(t *testing.T) {
	_, err := NewPolicySourceFromConfig(PolicySourceConfig{Source: "postgres", FilePath: writeTestPolicy(t)})
	if err == nil {
		t.Fatal("postgres source error = nil, want error")
	}
	if !strings.Contains(err.Error(), "POLICY_STORE_DSN is required") {
		t.Fatalf("error = %q, want POLICY_STORE_DSN is required", err.Error())
	}
}

func TestPostgresPolicySourceLoadActiveBuildsSnapshot(t *testing.T) {
	activatedAt := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	source := NewPostgresPolicySource(fakePolicyRepository{
		active: PolicyVersion{
			ID:          42,
			Version:     "p42-abcdef123456",
			ContentYAML: []byte(validRepositoryPolicy("/payments/charge", "allow")),
			ContentHash: "abcdef1234567890",
			CreatedAt:   activatedAt.Add(-time.Minute),
			CreatedBy:   "student",
			ActivatedAt: &activatedAt,
		},
	}, "")

	snapshot, err := source.LoadActive(context.Background())
	if err != nil {
		t.Fatalf("load active: %v", err)
	}

	if snapshot.Source != policySourcePostgres {
		t.Fatalf("source = %q, want postgres", snapshot.Source)
	}
	if snapshot.Version != "p42-abcdef123456" {
		t.Fatalf("version = %q", snapshot.Version)
	}
	if !snapshot.LoadedAt.Equal(activatedAt) {
		t.Fatalf("loaded at = %s, want %s", snapshot.LoadedAt, activatedAt)
	}
	if len(snapshot.Rules) != 1 {
		t.Fatalf("rules len = %d, want 1", len(snapshot.Rules))
	}
}

type fakePolicyRepository struct {
	active PolicyVersion
}

func (r fakePolicyRepository) CreateVersion(context.Context, []byte, string, string) (PolicyVersion, error) {
	return PolicyVersion{}, nil
}

func (r fakePolicyRepository) ActivateVersion(context.Context, string, string) (PolicyVersion, error) {
	return PolicyVersion{}, nil
}

func (r fakePolicyRepository) GetActiveVersion(context.Context) (PolicyVersion, error) {
	return r.active, nil
}

func (r fakePolicyRepository) ListVersions(context.Context) ([]PolicyVersion, error) {
	return nil, nil
}

func (r fakePolicyRepository) RollbackToVersion(context.Context, string, string) (PolicyVersion, error) {
	return PolicyVersion{}, nil
}

func writePolicyContent(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policies.yaml")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	return path
}
