package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

func TestPostgresPolicyRepositoryCreateActivateRollback(t *testing.T) {
	db := openPolicyRepositoryTestDB(t)
	repo := NewPostgresPolicyRepository(db)
	ctx := context.Background()

	first, err := repo.CreateVersion(ctx, []byte(validRepositoryPolicy("/payments/charge", "allow")), "student", "initial")
	if err != nil {
		t.Fatalf("create first version: %v", err)
	}
	second, err := repo.CreateVersion(ctx, []byte(validRepositoryPolicy("/payments/refund", "deny")), "student", "updated")
	if err != nil {
		t.Fatalf("create second version: %v", err)
	}

	if first.Version == second.Version {
		t.Fatalf("versions are equal: %q", first.Version)
	}
	if !strings.HasPrefix(first.Version, fmt.Sprintf("p%d-", first.ID)) {
		t.Fatalf("first version = %q, want p%d-*", first.Version, first.ID)
	}

	active, err := repo.ActivateVersion(ctx, first.Version, "student")
	if err != nil {
		t.Fatalf("activate first: %v", err)
	}
	if active.Version != first.Version {
		t.Fatalf("active version = %q, want %q", active.Version, first.Version)
	}

	active, err = repo.ActivateVersion(ctx, second.Version, "student")
	if err != nil {
		t.Fatalf("activate second: %v", err)
	}
	if active.Version != second.Version {
		t.Fatalf("active version = %q, want %q", active.Version, second.Version)
	}

	current, err := repo.GetActiveVersion(ctx)
	if err != nil {
		t.Fatalf("get active: %v", err)
	}
	if current.Version != second.Version {
		t.Fatalf("current version = %q, want %q", current.Version, second.Version)
	}
	if got := countRows(t, db, "policy_active"); got != 1 {
		t.Fatalf("policy_active rows = %d, want 1", got)
	}

	rolledBack, err := repo.RollbackToVersion(ctx, first.Version, "student")
	if err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if rolledBack.Version != first.Version {
		t.Fatalf("rollback version = %q, want %q", rolledBack.Version, first.Version)
	}

	if got := countAuditRows(t, db, "ok"); got != 5 {
		t.Fatalf("ok audit rows = %d, want 5", got)
	}
}

func TestPostgresPolicyRepositoryRejectsInvalidYAMLAndAudits(t *testing.T) {
	db := openPolicyRepositoryTestDB(t)
	repo := NewPostgresPolicyRepository(db)
	ctx := context.Background()

	_, err := repo.CreateVersion(ctx, []byte("- id: R1\n  effect: [unterminated\n"), "student", "bad")
	if err == nil {
		t.Fatal("create invalid policy error = nil, want error")
	}
	if !errors.Is(err, ErrInvalidPolicyContent) {
		t.Fatalf("error = %v, want ErrInvalidPolicyContent", err)
	}
	if got := countRows(t, db, "policy_versions"); got != 0 {
		t.Fatalf("policy_versions rows = %d, want 0", got)
	}
	if got := countAuditRows(t, db, "error"); got != 1 {
		t.Fatalf("error audit rows = %d, want 1", got)
	}
	if _, err := repo.GetActiveVersion(ctx); !errors.Is(err, ErrNoActivePolicy) {
		t.Fatalf("get active error = %v, want ErrNoActivePolicy", err)
	}
}

func TestPostgresPolicyRepositoryDuplicateContentAllowed(t *testing.T) {
	db := openPolicyRepositoryTestDB(t)
	repo := NewPostgresPolicyRepository(db)
	ctx := context.Background()
	content := []byte(validRepositoryPolicy("/payments/charge", "allow"))

	first, err := repo.CreateVersion(ctx, content, "student", "first")
	if err != nil {
		t.Fatalf("create first: %v", err)
	}
	second, err := repo.CreateVersion(ctx, content, "student", "second")
	if err != nil {
		t.Fatalf("create second: %v", err)
	}

	if first.ContentHash != second.ContentHash {
		t.Fatalf("content hashes differ: %q != %q", first.ContentHash, second.ContentHash)
	}
	if first.Version == second.Version {
		t.Fatalf("duplicate content reused version: %q", first.Version)
	}

	versions, err := repo.ListVersions(ctx)
	if err != nil {
		t.Fatalf("list versions: %v", err)
	}
	if len(versions) != 2 {
		t.Fatalf("versions len = %d, want 2", len(versions))
	}
}

func TestPostgresPolicyRepositorySeedIsIdempotent(t *testing.T) {
	db := openPolicyRepositoryTestDB(t)
	repo := NewPostgresPolicyRepository(db)
	ctx := context.Background()
	content := []byte(validRepositoryPolicy("/payments/charge", "allow"))

	first, seeded, err := repo.SeedInitialVersion(ctx, content, "policy-server-1", "seed")
	if err != nil {
		t.Fatalf("seed first: %v", err)
	}
	if !seeded {
		t.Fatal("first seed reported seeded=false")
	}

	second, seeded, err := repo.SeedInitialVersion(ctx, content, "policy-server-2", "seed")
	if err != nil {
		t.Fatalf("seed second: %v", err)
	}
	if seeded {
		t.Fatal("second seed reported seeded=true, want existing active")
	}
	if second.Version != first.Version {
		t.Fatalf("second seed version = %q, want %q", second.Version, first.Version)
	}
	if got := countRows(t, db, "policy_active"); got != 1 {
		t.Fatalf("policy_active rows = %d, want 1", got)
	}
	if got := countRows(t, db, "policy_versions"); got != 1 {
		t.Fatalf("policy_versions rows = %d, want 1", got)
	}
}

func TestPostgresPolicySourceReloadCreatesAndActivatesVersion(t *testing.T) {
	db := openPolicyRepositoryTestDB(t)
	repo := NewPostgresPolicyRepository(db)
	ctx := context.Background()
	policyFile := writePolicyContent(t, validRepositoryPolicy("/payments/charge", "allow"))
	source := NewPostgresPolicySource(repo, policyFile)

	initial, seeded, err := source.SeedFromFileIfMissing(ctx, "policy-server-1")
	if err != nil {
		t.Fatalf("seed source: %v", err)
	}
	if !seeded {
		t.Fatal("initial source seed reported seeded=false")
	}

	if err := os.WriteFile(policyFile, []byte(validRepositoryPolicy("/payments/refund", "deny")), 0600); err != nil {
		t.Fatalf("write changed policy: %v", err)
	}

	reloaded, err := source.Reload(ctx, "student")
	if err != nil {
		t.Fatalf("reload source: %v", err)
	}
	if reloaded.Version == initial.Version {
		t.Fatalf("reload version did not change: %q", reloaded.Version)
	}

	active, err := source.LoadActive(ctx)
	if err != nil {
		t.Fatalf("load active: %v", err)
	}
	if active.Version != reloaded.Version {
		t.Fatalf("active version = %q, want %q", active.Version, reloaded.Version)
	}
}

func TestPostgresPolicyRepositoryFailedActivateDoesNotChangeActive(t *testing.T) {
	db := openPolicyRepositoryTestDB(t)
	repo := NewPostgresPolicyRepository(db)
	ctx := context.Background()

	created, err := repo.CreateVersion(ctx, []byte(validRepositoryPolicy("/payments/charge", "allow")), "student", "initial")
	if err != nil {
		t.Fatalf("create version: %v", err)
	}
	if _, err := repo.ActivateVersion(ctx, created.Version, "student"); err != nil {
		t.Fatalf("activate version: %v", err)
	}

	_, err = repo.ActivateVersion(ctx, "missing-version", "student")
	if !errors.Is(err, ErrPolicyVersionNotFound) {
		t.Fatalf("activate missing error = %v, want ErrPolicyVersionNotFound", err)
	}

	active, err := repo.GetActiveVersion(ctx)
	if err != nil {
		t.Fatalf("get active: %v", err)
	}
	if active.Version != created.Version {
		t.Fatalf("active version changed: %q != %q", active.Version, created.Version)
	}
	if got := countAuditRows(t, db, "error"); got != 1 {
		t.Fatalf("error audit rows = %d, want 1", got)
	}
}

func TestEnsurePolicyStoreSchemaIsIdempotent(t *testing.T) {
	db := openPolicyRepositoryTestDB(t)
	ctx := context.Background()

	if err := EnsurePolicyStoreSchema(ctx, db); err != nil {
		t.Fatalf("ensure schema second time: %v", err)
	}
	if err := EnsurePolicyStoreSchema(ctx, db); err != nil {
		t.Fatalf("ensure schema third time: %v", err)
	}
}

func openPolicyRepositoryTestDB(t *testing.T) *sql.DB {
	t.Helper()
	rawDSN := os.Getenv("POLICY_STORE_TEST_DSN")
	if rawDSN == "" {
		t.Skip("POLICY_STORE_TEST_DSN is not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	adminDB, err := sql.Open("postgres", rawDSN)
	if err != nil {
		t.Fatalf("open admin db: %v", err)
	}
	t.Cleanup(func() {
		_ = adminDB.Close()
	})
	if err := adminDB.PingContext(ctx); err != nil {
		t.Fatalf("ping admin db: %v", err)
	}

	schema := fmt.Sprintf("policy_repo_test_%d", time.Now().UnixNano())
	if _, err := adminDB.ExecContext(ctx, `CREATE SCHEMA `+schema); err != nil {
		t.Fatalf("create test schema: %v", err)
	}
	t.Cleanup(func() {
		_, _ = adminDB.ExecContext(context.Background(), `DROP SCHEMA IF EXISTS `+schema+` CASCADE`)
	})

	db, err := sql.Open("postgres", dsnWithSearchPath(t, rawDSN, schema))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
	})
	if err := db.PingContext(ctx); err != nil {
		t.Fatalf("ping db: %v", err)
	}
	if err := EnsurePolicyStoreSchema(ctx, db); err != nil {
		t.Fatalf("ensure schema: %v", err)
	}
	return db
}

func dsnWithSearchPath(t *testing.T, rawDSN, schema string) string {
	t.Helper()
	u, err := url.Parse(rawDSN)
	if err != nil || u.Scheme == "" {
		if strings.Contains(rawDSN, " search_path=") {
			return rawDSN
		}
		return rawDSN + " search_path=" + schema
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	return u.String()
}

func validRepositoryPolicy(resource, effect string) string {
	return strings.Join([]string{
		"- id: R1",
		"  source: orders",
		"  target: payments",
		"  transport: http",
		"  operation: POST",
		"  resource: " + resource,
		"  effect: " + effect,
		"",
	}, "\n")
}

func countRows(t *testing.T, db *sql.DB, table string) int {
	t.Helper()
	var count int
	if err := db.QueryRow(`SELECT count(*) FROM ` + table).Scan(&count); err != nil {
		t.Fatalf("count rows in %s: %v", table, err)
	}
	return count
}

func countAuditRows(t *testing.T, db *sql.DB, status string) int {
	t.Helper()
	var count int
	if err := db.QueryRow(`SELECT count(*) FROM policy_audit WHERE status = $1`, status).Scan(&count); err != nil {
		t.Fatalf("count audit rows: %v", err)
	}
	return count
}
