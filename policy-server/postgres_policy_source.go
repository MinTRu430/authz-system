package main

import (
	"context"
	"errors"
	"os"
)

type PostgresPolicySource struct {
	repo       PolicyRepository
	policyFile string
}

type PolicySeedRepository interface {
	PolicyRepository
	SeedInitialVersion(ctx context.Context, content []byte, actor, comment string) (PolicyVersion, bool, error)
}

func NewPostgresPolicySource(repo PolicyRepository, policyFile string) *PostgresPolicySource {
	return &PostgresPolicySource{
		repo:       repo,
		policyFile: policyFile,
	}
}

func (s *PostgresPolicySource) Name() string {
	return policySourcePostgres
}

func (s *PostgresPolicySource) LoadActive(ctx context.Context) (PolicySnapshot, error) {
	version, err := s.repo.GetActiveVersion(ctx)
	if err != nil {
		return PolicySnapshot{}, err
	}
	return snapshotFromPolicyVersion(version, syncStatusOK)
}

func (s *PostgresPolicySource) Reload(ctx context.Context, actor string) (PolicySnapshot, error) {
	if s.policyFile == "" {
		return PolicySnapshot{}, errors.New("POLICY_FILE is required for postgres reload")
	}
	content, err := os.ReadFile(s.policyFile)
	if err != nil {
		return PolicySnapshot{}, err
	}
	created, err := s.repo.CreateVersion(ctx, content, actor, "reload from POLICY_FILE")
	if err != nil {
		return PolicySnapshot{}, err
	}
	activated, err := s.repo.ActivateVersion(ctx, created.Version, actor)
	if err != nil {
		return PolicySnapshot{}, err
	}
	return snapshotFromPolicyVersion(activated, syncStatusOK)
}

func (s *PostgresPolicySource) SeedFromFileIfMissing(ctx context.Context, actor string) (PolicySnapshot, bool, error) {
	seeder, ok := s.repo.(PolicySeedRepository)
	if !ok {
		return PolicySnapshot{}, false, errors.New("postgres policy repository does not support seed")
	}
	if s.policyFile == "" {
		return PolicySnapshot{}, false, ErrNoActivePolicy
	}
	content, err := os.ReadFile(s.policyFile)
	if err != nil {
		return PolicySnapshot{}, false, err
	}
	version, seeded, err := seeder.SeedInitialVersion(ctx, content, actor, "seed from POLICY_FILE")
	if err != nil {
		return PolicySnapshot{}, false, err
	}
	snapshot, err := snapshotFromPolicyVersion(version, syncStatusOK)
	return snapshot, seeded, err
}

func (s *PostgresPolicySource) ListVersions(ctx context.Context) ([]PolicyVersion, error) {
	return s.repo.ListVersions(ctx)
}

func (s *PostgresPolicySource) Activate(ctx context.Context, version, actor string) (PolicySnapshot, error) {
	activated, err := s.repo.ActivateVersion(ctx, version, actor)
	if err != nil {
		return PolicySnapshot{}, err
	}
	return snapshotFromPolicyVersion(activated, syncStatusOK)
}

func (s *PostgresPolicySource) Rollback(ctx context.Context, version, actor string) (PolicySnapshot, error) {
	activated, err := s.repo.RollbackToVersion(ctx, version, actor)
	if err != nil {
		return PolicySnapshot{}, err
	}
	return snapshotFromPolicyVersion(activated, syncStatusOK)
}

func (s *PostgresPolicySource) CreateVersion(ctx context.Context, content []byte, actor, comment string) (PolicyVersion, error) {
	return s.repo.CreateVersion(ctx, content, actor, comment)
}

func snapshotFromPolicyVersion(version PolicyVersion, syncStatus string) (PolicySnapshot, error) {
	rules, err := validatePolicyContent(version.ContentYAML)
	if err != nil {
		return PolicySnapshot{}, err
	}
	loadedAt := version.CreatedAt
	if version.ActivatedAt != nil {
		loadedAt = *version.ActivatedAt
	}
	return PolicySnapshot{
		Version:     version.Version,
		ContentHash: version.ContentHash,
		Rules:       rules,
		RawYAML:     append([]byte(nil), version.ContentYAML...),
		LoadedAt:    loadedAt.UTC(),
		Source:      policySourcePostgres,
		SyncStatus:  syncStatus,
	}, nil
}
