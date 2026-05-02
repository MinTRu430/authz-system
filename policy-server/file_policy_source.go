package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"time"

	"authz-system/internal/authz"

	"gopkg.in/yaml.v3"
)

type FilePolicySource struct {
	path string
	now  func() time.Time
}

func NewFilePolicySource(path string) *FilePolicySource {
	return &FilePolicySource{
		path: path,
		now:  time.Now,
	}
}

func (s *FilePolicySource) Name() string {
	return policySourceFile
}

func (s *FilePolicySource) LoadActive(ctx context.Context) (PolicySnapshot, error) {
	return s.load(ctx)
}

func (s *FilePolicySource) Reload(ctx context.Context, _ string) (PolicySnapshot, error) {
	return s.load(ctx)
}

func (s *FilePolicySource) load(ctx context.Context) (PolicySnapshot, error) {
	if err := ctx.Err(); err != nil {
		return PolicySnapshot{}, err
	}

	data, err := os.ReadFile(s.path)
	if err != nil {
		return PolicySnapshot{}, err
	}
	if err := ctx.Err(); err != nil {
		return PolicySnapshot{}, err
	}

	var rules []authz.PolicyRule
	if err := yaml.Unmarshal(data, &rules); err != nil {
		return PolicySnapshot{}, err
	}

	hash := policyContentHash(data)
	return PolicySnapshot{
		Version:     policyVersionFromHash(policySourceFile, hash),
		ContentHash: hash,
		Rules:       authz.NormalizePolicyRules(rules),
		RawYAML:     append([]byte(nil), data...),
		LoadedAt:    s.now().UTC(),
		Source:      policySourceFile,
		SyncStatus:  syncStatusOK,
	}, nil
}

func policyContentHash(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func policyVersionFromHash(source, hash string) string {
	short := hash
	if len(short) > 12 {
		short = short[:12]
	}
	if source == "" {
		return short
	}
	return source + "-" + short
}
