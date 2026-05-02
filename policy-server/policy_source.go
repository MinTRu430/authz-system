package main

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"authz-system/internal/authz"

	_ "github.com/lib/pq"
)

const (
	policySourceFile     = "file"
	policySourcePostgres = "postgres"
	syncStatusOK         = "ok"
	syncStatusStale      = "stale"
	syncStatusMissing    = "missing"
)

type PolicySnapshot struct {
	Version     string
	ContentHash string
	Rules       []authz.PolicyRule
	RawYAML     []byte
	LoadedAt    time.Time
	Source      string
	SyncStatus  string
}

type PolicySource interface {
	Name() string
	LoadActive(ctx context.Context) (PolicySnapshot, error)
	Reload(ctx context.Context, actor string) (PolicySnapshot, error)
}

type PolicySourceConfig struct {
	Source       string
	FilePath     string
	StoreDSN     string
	SyncInterval time.Duration
}

type PolicySourceRuntime struct {
	Source       PolicySource
	DB           *sql.DB
	SyncInterval time.Duration
}

func (r *PolicySourceRuntime) Close() error {
	if r == nil || r.DB == nil {
		return nil
	}
	return r.DB.Close()
}

func NewPolicySourceFromConfig(cfg PolicySourceConfig) (PolicySource, error) {
	runtime, err := NewPolicySourceRuntime(context.Background(), cfg)
	if err != nil {
		return nil, err
	}
	return runtime.Source, nil
}

func NewPolicySourceRuntime(ctx context.Context, cfg PolicySourceConfig) (*PolicySourceRuntime, error) {
	source := normalizePolicySourceName(cfg.Source)
	switch source {
	case policySourceFile:
		if strings.TrimSpace(cfg.FilePath) == "" {
			return nil, fmt.Errorf("POLICY_FILE is required when POLICY_SOURCE=%s", policySourceFile)
		}
		return &PolicySourceRuntime{
			Source: NewFilePolicySource(cfg.FilePath),
		}, nil
	case policySourcePostgres:
		if strings.TrimSpace(cfg.StoreDSN) == "" {
			return nil, fmt.Errorf("POLICY_STORE_DSN is required when POLICY_SOURCE=%s", policySourcePostgres)
		}
		db, err := sql.Open("postgres", cfg.StoreDSN)
		if err != nil {
			return nil, fmt.Errorf("open policy store: %w", err)
		}
		if err := EnsurePolicyStoreSchema(ctx, db); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("ensure policy store schema: %w", err)
		}
		interval := cfg.SyncInterval
		if interval <= 0 {
			interval = 2 * time.Second
		}
		return &PolicySourceRuntime{
			Source:       NewPostgresPolicySource(NewPostgresPolicyRepository(db), cfg.FilePath),
			DB:           db,
			SyncInterval: interval,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported POLICY_SOURCE %q", cfg.Source)
	}
}

func normalizePolicySourceName(source string) string {
	source = strings.TrimSpace(strings.ToLower(source))
	if source == "" {
		return policySourceFile
	}
	return source
}
