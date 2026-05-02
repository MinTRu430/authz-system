package main

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"time"

	"authz-system/internal/authz"

	"gopkg.in/yaml.v3"
)

//go:embed migrations/*.sql
var policyStoreMigrations embed.FS

var (
	ErrNoActivePolicy        = errors.New("no active policy version")
	ErrPolicyVersionNotFound = errors.New("policy version not found")
	ErrInvalidPolicyContent  = errors.New("invalid policy content")
)

type PolicyVersion struct {
	ID              int64
	Version         string
	ContentYAML     []byte
	ContentHash     string
	CreatedAt       time.Time
	CreatedBy       string
	ActivatedAt     *time.Time
	Comment         string
	ValidationError string
}

type PolicyRepository interface {
	CreateVersion(ctx context.Context, content []byte, actor, comment string) (PolicyVersion, error)
	ActivateVersion(ctx context.Context, version string, actor string) (PolicyVersion, error)
	GetActiveVersion(ctx context.Context) (PolicyVersion, error)
	ListVersions(ctx context.Context) ([]PolicyVersion, error)
	RollbackToVersion(ctx context.Context, version string, actor string) (PolicyVersion, error)
}

type PostgresPolicyRepository struct {
	db *sql.DB
}

func NewPostgresPolicyRepository(db *sql.DB) *PostgresPolicyRepository {
	return &PostgresPolicyRepository{db: db}
}

func EnsurePolicyStoreSchema(ctx context.Context, db *sql.DB) error {
	entries, err := fs.ReadDir(policyStoreMigrations, "migrations")
	if err != nil {
		return err
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name() < entries[j].Name()
	})
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		sqlBytes, err := policyStoreMigrations.ReadFile("migrations/" + entry.Name())
		if err != nil {
			return err
		}
		if _, err := db.ExecContext(ctx, string(sqlBytes)); err != nil {
			return fmt.Errorf("apply migration %s: %w", entry.Name(), err)
		}
	}
	return nil
}

func (r *PostgresPolicyRepository) CreateVersion(ctx context.Context, content []byte, actor, comment string) (PolicyVersion, error) {
	actor = normalizeRepositoryActor(actor)
	if _, err := validatePolicyContent(content); err != nil {
		_ = r.insertAudit(ctx, "create", actor, "", "", "error", err.Error())
		return PolicyVersion{}, err
	}

	hash := policyContentHash(content)
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		_ = r.insertAudit(ctx, "create", actor, "", "", "error", err.Error())
		return PolicyVersion{}, err
	}
	defer rollbackTx(tx)

	id, err := nextPolicyVersionID(ctx, tx)
	if err != nil {
		_ = r.insertAudit(ctx, "create", actor, "", "", "error", err.Error())
		return PolicyVersion{}, err
	}
	version := postgresPolicyVersion(id, hash)

	row := tx.QueryRowContext(ctx, `
INSERT INTO policy_versions (id, version, content_yaml, content_hash, created_by, comment)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING id, version, content_yaml, content_hash, created_at, created_by, activated_at, comment, validation_error
`, id, version, string(content), hash, actor, nullableString(comment))

	pv, err := scanPolicyVersion(row)
	if err != nil {
		_ = r.insertAudit(ctx, "create", actor, "", version, "error", err.Error())
		return PolicyVersion{}, err
	}
	if err := insertAuditTx(ctx, tx, "create", actor, "", version, "ok", ""); err != nil {
		_ = r.insertAudit(ctx, "create", actor, "", version, "error", err.Error())
		return PolicyVersion{}, err
	}
	if err := tx.Commit(); err != nil {
		_ = r.insertAudit(ctx, "create", actor, "", version, "error", err.Error())
		return PolicyVersion{}, err
	}
	return pv, nil
}

func (r *PostgresPolicyRepository) SeedInitialVersion(ctx context.Context, content []byte, actor, comment string) (PolicyVersion, bool, error) {
	actor = normalizeRepositoryActor(actor)
	if _, err := validatePolicyContent(content); err != nil {
		_ = r.insertAudit(ctx, "seed", actor, "", "", "error", err.Error())
		return PolicyVersion{}, false, err
	}

	hash := policyContentHash(content)
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		_ = r.insertAudit(ctx, "seed", actor, "", "", "error", err.Error())
		return PolicyVersion{}, false, err
	}
	defer rollbackTx(tx)

	if _, err := tx.ExecContext(ctx, `LOCK TABLE policy_active IN EXCLUSIVE MODE`); err != nil {
		_ = r.insertAudit(ctx, "seed", actor, "", "", "error", err.Error())
		return PolicyVersion{}, false, err
	}

	oldVersion, err := activeVersionStringTx(ctx, tx)
	if err == nil {
		pv, err := getVersionTx(ctx, tx, oldVersion)
		if err != nil {
			_ = r.insertAudit(ctx, "seed", actor, oldVersion, "", "error", err.Error())
			return PolicyVersion{}, false, err
		}
		if err := tx.Commit(); err != nil {
			_ = r.insertAudit(ctx, "seed", actor, oldVersion, "", "error", err.Error())
			return PolicyVersion{}, false, err
		}
		return pv, false, nil
	}
	if err != nil && !errors.Is(err, ErrNoActivePolicy) {
		_ = r.insertAudit(ctx, "seed", actor, "", "", "error", err.Error())
		return PolicyVersion{}, false, err
	}

	id, err := nextPolicyVersionID(ctx, tx)
	if err != nil {
		_ = r.insertAudit(ctx, "seed", actor, "", "", "error", err.Error())
		return PolicyVersion{}, false, err
	}
	version := postgresPolicyVersion(id, hash)

	row := tx.QueryRowContext(ctx, `
INSERT INTO policy_versions (id, version, content_yaml, content_hash, created_by, comment)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING id, version, content_yaml, content_hash, created_at, created_by, activated_at, comment, validation_error
`, id, version, string(content), hash, actor, nullableString(comment))
	pv, err := scanPolicyVersion(row)
	if err != nil {
		_ = r.insertAudit(ctx, "seed", actor, "", version, "error", err.Error())
		return PolicyVersion{}, false, err
	}

	var activatedAt time.Time
	if err := tx.QueryRowContext(ctx, `
INSERT INTO policy_active (id, version_id, activated_by)
VALUES (1, $1, $2)
RETURNING activated_at
`, pv.ID, actor).Scan(&activatedAt); err != nil {
		_ = r.insertAudit(ctx, "seed", actor, "", version, "error", err.Error())
		return PolicyVersion{}, false, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE policy_versions SET activated_at = $1 WHERE id = $2`, activatedAt, pv.ID); err != nil {
		_ = r.insertAudit(ctx, "seed", actor, "", version, "error", err.Error())
		return PolicyVersion{}, false, err
	}
	if err := insertAuditTx(ctx, tx, "seed", actor, "", version, "ok", ""); err != nil {
		_ = r.insertAudit(ctx, "seed", actor, "", version, "error", err.Error())
		return PolicyVersion{}, false, err
	}
	if err := tx.Commit(); err != nil {
		_ = r.insertAudit(ctx, "seed", actor, "", version, "error", err.Error())
		return PolicyVersion{}, false, err
	}

	pv.ActivatedAt = &activatedAt
	return pv, true, nil
}

func (r *PostgresPolicyRepository) ActivateVersion(ctx context.Context, version string, actor string) (PolicyVersion, error) {
	return r.activateVersion(ctx, "activate", version, actor)
}

func (r *PostgresPolicyRepository) RollbackToVersion(ctx context.Context, version string, actor string) (PolicyVersion, error) {
	return r.activateVersion(ctx, "rollback", version, actor)
}

func (r *PostgresPolicyRepository) GetActiveVersion(ctx context.Context) (PolicyVersion, error) {
	row := r.db.QueryRowContext(ctx, `
SELECT v.id, v.version, v.content_yaml, v.content_hash, v.created_at, v.created_by, v.activated_at, v.comment, v.validation_error
FROM policy_active a
JOIN policy_versions v ON v.id = a.version_id
WHERE a.id = 1
`)
	pv, err := scanPolicyVersion(row)
	if errors.Is(err, sql.ErrNoRows) {
		return PolicyVersion{}, ErrNoActivePolicy
	}
	if err != nil {
		return PolicyVersion{}, err
	}
	return pv, nil
}

func (r *PostgresPolicyRepository) ListVersions(ctx context.Context) ([]PolicyVersion, error) {
	rows, err := r.db.QueryContext(ctx, `
SELECT id, version, content_yaml, content_hash, created_at, created_by, activated_at, comment, validation_error
FROM policy_versions
ORDER BY id
`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []PolicyVersion
	for rows.Next() {
		pv, err := scanPolicyVersion(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, pv)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (r *PostgresPolicyRepository) activateVersion(ctx context.Context, action, version string, actor string) (PolicyVersion, error) {
	actor = normalizeRepositoryActor(actor)
	version = strings.TrimSpace(version)
	if version == "" {
		err := fmt.Errorf("%w: empty version", ErrPolicyVersionNotFound)
		_ = r.insertAudit(ctx, action, actor, "", "", "error", err.Error())
		return PolicyVersion{}, err
	}

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		_ = r.insertAudit(ctx, action, actor, "", version, "error", err.Error())
		return PolicyVersion{}, err
	}
	defer rollbackTx(tx)

	if _, err := tx.ExecContext(ctx, `LOCK TABLE policy_active IN EXCLUSIVE MODE`); err != nil {
		_ = r.insertAudit(ctx, action, actor, "", version, "error", err.Error())
		return PolicyVersion{}, err
	}

	oldVersion, err := activeVersionStringTx(ctx, tx)
	if err != nil && !errors.Is(err, ErrNoActivePolicy) {
		_ = r.insertAudit(ctx, action, actor, "", version, "error", err.Error())
		return PolicyVersion{}, err
	}

	pv, err := getVersionTx(ctx, tx, version)
	if errors.Is(err, sql.ErrNoRows) {
		repoErr := fmt.Errorf("%w: %s", ErrPolicyVersionNotFound, version)
		_ = r.insertAudit(ctx, action, actor, oldVersion, version, "error", repoErr.Error())
		return PolicyVersion{}, repoErr
	}
	if err != nil {
		_ = r.insertAudit(ctx, action, actor, oldVersion, version, "error", err.Error())
		return PolicyVersion{}, err
	}
	if pv.ValidationError != "" {
		repoErr := fmt.Errorf("%w: %s", ErrInvalidPolicyContent, pv.ValidationError)
		_ = r.insertAudit(ctx, action, actor, oldVersion, version, "error", repoErr.Error())
		return PolicyVersion{}, repoErr
	}
	if _, err := validatePolicyContent(pv.ContentYAML); err != nil {
		_ = r.insertAudit(ctx, action, actor, oldVersion, version, "error", err.Error())
		return PolicyVersion{}, err
	}

	var activatedAt time.Time
	if err := tx.QueryRowContext(ctx, `
INSERT INTO policy_active (id, version_id, activated_by)
VALUES (1, $1, $2)
ON CONFLICT (id) DO UPDATE
SET version_id = EXCLUDED.version_id,
    activated_at = now(),
    activated_by = EXCLUDED.activated_by
RETURNING activated_at
`, pv.ID, actor).Scan(&activatedAt); err != nil {
		_ = r.insertAudit(ctx, action, actor, oldVersion, version, "error", err.Error())
		return PolicyVersion{}, err
	}

	if _, err := tx.ExecContext(ctx, `UPDATE policy_versions SET activated_at = $1 WHERE id = $2`, activatedAt, pv.ID); err != nil {
		_ = r.insertAudit(ctx, action, actor, oldVersion, version, "error", err.Error())
		return PolicyVersion{}, err
	}
	if err := insertAuditTx(ctx, tx, action, actor, oldVersion, version, "ok", ""); err != nil {
		_ = r.insertAudit(ctx, action, actor, oldVersion, version, "error", err.Error())
		return PolicyVersion{}, err
	}
	if err := tx.Commit(); err != nil {
		_ = r.insertAudit(ctx, action, actor, oldVersion, version, "error", err.Error())
		return PolicyVersion{}, err
	}

	pv.ActivatedAt = &activatedAt
	return pv, nil
}

func (r *PostgresPolicyRepository) insertAudit(ctx context.Context, action, actor, oldVersion, newVersion, status, message string) error {
	return insertAuditExec(ctx, r.db, action, actor, oldVersion, newVersion, status, message)
}

type queryScanner interface {
	Scan(dest ...any) error
}

type auditExecutor interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

func scanPolicyVersion(row queryScanner) (PolicyVersion, error) {
	var pv PolicyVersion
	var activatedAt sql.NullTime
	var comment sql.NullString
	var validationError sql.NullString
	var contentYAML string
	if err := row.Scan(
		&pv.ID,
		&pv.Version,
		&contentYAML,
		&pv.ContentHash,
		&pv.CreatedAt,
		&pv.CreatedBy,
		&activatedAt,
		&comment,
		&validationError,
	); err != nil {
		return PolicyVersion{}, err
	}
	pv.ContentYAML = []byte(contentYAML)
	if activatedAt.Valid {
		pv.ActivatedAt = &activatedAt.Time
	}
	if comment.Valid {
		pv.Comment = comment.String
	}
	if validationError.Valid {
		pv.ValidationError = validationError.String
	}
	return pv, nil
}

func nextPolicyVersionID(ctx context.Context, tx *sql.Tx) (int64, error) {
	var id int64
	err := tx.QueryRowContext(ctx, `SELECT nextval(pg_get_serial_sequence('policy_versions','id'))`).Scan(&id)
	return id, err
}

func getVersionTx(ctx context.Context, tx *sql.Tx, version string) (PolicyVersion, error) {
	row := tx.QueryRowContext(ctx, `
SELECT id, version, content_yaml, content_hash, created_at, created_by, activated_at, comment, validation_error
FROM policy_versions
WHERE version = $1
`, version)
	return scanPolicyVersion(row)
}

func activeVersionStringTx(ctx context.Context, tx *sql.Tx) (string, error) {
	var version string
	err := tx.QueryRowContext(ctx, `
SELECT v.version
FROM policy_active a
JOIN policy_versions v ON v.id = a.version_id
WHERE a.id = 1
`).Scan(&version)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNoActivePolicy
	}
	if err != nil {
		return "", err
	}
	return version, nil
}

func insertAuditTx(ctx context.Context, tx *sql.Tx, action, actor, oldVersion, newVersion, status, message string) error {
	return insertAuditExec(ctx, tx, action, actor, oldVersion, newVersion, status, message)
}

func insertAuditExec(ctx context.Context, exec auditExecutor, action, actor, oldVersion, newVersion, status, message string) error {
	_, err := exec.ExecContext(ctx, `
INSERT INTO policy_audit (action, actor, old_version, new_version, status, message)
VALUES ($1, $2, $3, $4, $5, $6)
`, action, normalizeRepositoryActor(actor), nullableString(oldVersion), nullableString(newVersion), status, nullableString(message))
	return err
}

func validatePolicyContent(content []byte) ([]authz.PolicyRule, error) {
	var rules []authz.PolicyRule
	if err := yaml.Unmarshal(content, &rules); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidPolicyContent, err)
	}
	normalized := authz.NormalizePolicyRules(rules)
	_ = authz.CompilePolicyRules(normalized)
	return normalized, nil
}

func postgresPolicyVersion(id int64, hash string) string {
	return fmt.Sprintf("p%d-%s", id, shortContentHash(hash))
}

func shortContentHash(hash string) string {
	if len(hash) <= 12 {
		return hash
	}
	return hash[:12]
}

func normalizeRepositoryActor(actor string) string {
	actor = strings.TrimSpace(actor)
	if actor == "" {
		return "unknown"
	}
	return actor
}

func nullableString(value string) sql.NullString {
	value = strings.TrimSpace(value)
	if value == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: value, Valid: true}
}

func rollbackTx(tx *sql.Tx) {
	_ = tx.Rollback()
}
