package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"authz-system/internal/authz"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel/attribute"
)

type Store struct {
	mu          sync.RWMutex
	policy      *authz.CompiledPolicy
	version     string
	contentHash string
	loadedAt    time.Time
	source      string
	syncStatus  string
	lastSyncAt  time.Time
	syncError   string
	stats       authz.PolicyIndexStats
}

type StoreInfo struct {
	Ready       bool
	Version     string
	ContentHash string
	LoadedAt    time.Time
	Source      string
	SyncStatus  string
	LastSyncAt  time.Time
	SyncError   string
	Stats       authz.PolicyIndexStats
}

func (s *Store) Decide(ctx context.Context, req authz.AuthzRequest) authz.CheckResponse {
	s.mu.RLock()
	policy := s.policy
	version := s.version
	stats := s.stats
	s.mu.RUnlock()

	ctx, span := authz.StartSpan(ctx, "policy_server.match",
		attribute.Int("policy.rules_count", stats.Rules),
		attribute.Int("policy.index_buckets", stats.Buckets),
	)
	defer span.End()

	start := time.Now()
	if policy == nil {
		policyMatchLatency.Observe(time.Since(start).Seconds())
		resp := authz.CheckResponse{Allow: false, Reason: "no active policy", Version: version}
		authz.EndSpanWithResult(span, "deny", nil)
		span.SetAttributes(attribute.String("policy.result", "deny"))
		return resp
	}

	resp := policy.Decide(version, req)
	policyMatchLatency.Observe(time.Since(start).Seconds())
	if resp.Allow {
		authz.EndSpanWithResult(span, "allow", nil)
		span.SetAttributes(attribute.String("policy.result", "allow"))
	} else {
		authz.EndSpanWithResult(span, "deny", nil)
		span.SetAttributes(attribute.String("policy.result", "deny"))
	}
	return resp
}

func (s *Store) CurrentInfo() StoreInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()

	info := StoreInfo{
		Ready:       s.policy != nil && s.version != "",
		Version:     s.version,
		ContentHash: s.contentHash,
		LoadedAt:    s.loadedAt,
		Source:      s.source,
		SyncStatus:  s.syncStatus,
		LastSyncAt:  s.lastSyncAt,
		SyncError:   s.syncError,
		Stats:       s.stats,
	}
	if info.SyncStatus == "" {
		info.SyncStatus = "unknown"
	}
	return info
}

func (s *Store) HealthHandler(w http.ResponseWriter, r *http.Request) {
	ctx := authz.ExtractHTTP(r.Context(), r.Header)
	_, span := authz.StartSpan(ctx, "policy_server.health")
	defer span.End()

	if r.Method != http.MethodGet {
		authz.EndSpanWithResult(span, "error", nil)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	info := s.CurrentInfo()
	span.SetAttributes(
		attribute.Int("policy.rules_count", info.Stats.Rules),
		attribute.Int("policy.index_buckets", info.Stats.Buckets),
	)
	w.Header().Set("Content-Type", "application/json")
	if !info.Ready {
		span.SetAttributes(attribute.String("policy.result", "unhealthy"))
		authz.EndSpanWithResult(span, "unhealthy", nil)
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":        "unhealthy",
			"version":       info.Version,
			"content_hash":  info.ContentHash,
			"policy_source": info.Source,
			"sync_status":   info.SyncStatus,
			"last_sync_at":  formatOptionalTime(info.LastSyncAt),
			"sync_error":    info.SyncError,
		})
		return
	}

	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":        "ok",
		"version":       info.Version,
		"content_hash":  info.ContentHash,
		"rules":         info.Stats.Rules,
		"buckets":       info.Stats.Buckets,
		"policy_source": info.Source,
		"sync_status":   info.SyncStatus,
		"last_sync_at":  formatOptionalTime(info.LastSyncAt),
		"sync_error":    info.SyncError,
	})
	span.SetAttributes(attribute.String("policy.result", "ok"))
	authz.EndSpanWithResult(span, "ok", nil)
}

func (s *Store) CheckHandler(w http.ResponseWriter, r *http.Request) {
	ctx := authz.ExtractHTTP(r.Context(), r.Header)
	ctx, span := authz.StartSpan(ctx, "policy_server.check")
	defer span.End()

	start := time.Now()
	result := "error"
	var spanErr error
	defer func() {
		policyCheckRequestsTotal.WithLabelValues(result).Inc()
		policyCheckDuration.Observe(time.Since(start).Seconds())
		span.SetAttributes(attribute.String("policy.result", result))
		authz.EndSpanWithResult(span, result, spanErr)
	}()
	defer r.Body.Close()

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		spanErr = err
		decisionTotal.WithLabelValues("error").Inc()
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}

	var req authz.AuthzRequest
	if err := json.Unmarshal(body, &req); err != nil {
		spanErr = err
		decisionTotal.WithLabelValues("error").Inc()
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	resp := s.Decide(ctx, req)

	if resp.Allow {
		result = "allow"
		decisionTotal.WithLabelValues("allow").Inc()
	} else {
		result = "deny"
		decisionTotal.WithLabelValues("deny").Inc()
	}
	decisionLatency.Observe(time.Since(start).Seconds())

	_ = json.NewEncoder(w).Encode(resp)
}

func (s *Store) ReloadFromFile(path string) error {
	return s.ReloadFromFileContext(context.Background(), path)
}

func (s *Store) ReloadFromFileContext(ctx context.Context, path string) error {
	_, err := s.ReloadFromSource(ctx, NewFilePolicySource(path), "file")
	return err
}

func (s *Store) ReloadFromSource(ctx context.Context, source PolicySource, actor string) (PolicySnapshot, error) {
	ctx, span := authz.StartSpan(ctx, "policy_server.reload")
	_ = ctx
	start := time.Now()
	result := "error"
	var spanErr error
	defer func() {
		policyReloadTotal.WithLabelValues(result).Inc()
		policyReloadDuration.Observe(time.Since(start).Seconds())
		span.SetAttributes(attribute.String("policy.reload_result", result))
		authz.EndSpanWithResult(span, result, spanErr)
		span.End()
	}()

	snapshot, err := source.Reload(ctx, actor)
	if err != nil {
		spanErr = err
		return PolicySnapshot{}, err
	}
	if err := s.ApplySnapshot(snapshot); err != nil {
		spanErr = err
		return PolicySnapshot{}, err
	}

	stats := s.CurrentInfo().Stats
	span.SetAttributes(
		attribute.Int("policy.rules_count", stats.Rules),
		attribute.Int("policy.index_buckets", stats.Buckets),
	)
	result = "ok"
	return snapshot, nil
}

func (s *Store) LoadActiveFromSource(ctx context.Context, source PolicySource) (PolicySnapshot, error) {
	snapshot, err := source.LoadActive(ctx)
	if err != nil {
		return PolicySnapshot{}, err
	}
	if err := s.ApplySnapshot(snapshot); err != nil {
		return PolicySnapshot{}, err
	}
	return snapshot, nil
}

func (s *Store) ApplySnapshot(snapshot PolicySnapshot) error {
	if snapshot.Version == "" {
		return errors.New("policy snapshot version is empty")
	}
	if snapshot.ContentHash == "" {
		return errors.New("policy snapshot content hash is empty")
	}

	policy := authz.CompilePolicyRules(snapshot.Rules)
	stats := policy.Stats()
	loadedAt := snapshot.LoadedAt
	if loadedAt.IsZero() {
		loadedAt = time.Now().UTC()
	}
	source := snapshot.Source
	if source == "" {
		source = "unknown"
	}
	syncStatus := snapshot.SyncStatus
	if syncStatus == "" {
		syncStatus = syncStatusOK
	}

	s.mu.Lock()
	s.policy = policy
	s.version = snapshot.Version
	s.contentHash = snapshot.ContentHash
	s.loadedAt = loadedAt
	s.source = source
	s.syncStatus = syncStatus
	s.lastSyncAt = time.Now().UTC()
	s.syncError = ""
	s.stats = stats
	s.mu.Unlock()

	policyRulesTotal.Set(float64(stats.Rules))
	policyIndexBucketsTotal.Set(float64(stats.Buckets))
	policyStoreLastSyncTimestampSeconds.Set(float64(s.CurrentInfo().LastSyncAt.Unix()))
	policyReplicaInSync.Set(1)
	return nil
}

func (s *Store) MarkSyncOK(source string) {
	s.mu.Lock()
	if source != "" {
		s.source = source
	}
	s.syncStatus = syncStatusOK
	s.lastSyncAt = time.Now().UTC()
	s.syncError = ""
	s.mu.Unlock()

	policyStoreLastSyncTimestampSeconds.Set(float64(s.CurrentInfo().LastSyncAt.Unix()))
	policyReplicaInSync.Set(1)
}

func (s *Store) MarkSyncStale(source string, err error) {
	s.mu.Lock()
	if source != "" {
		s.source = source
	}
	if s.policy == nil || s.version == "" {
		s.syncStatus = syncStatusMissing
	} else {
		s.syncStatus = syncStatusStale
	}
	s.lastSyncAt = time.Now().UTC()
	if err != nil {
		s.syncError = err.Error()
	}
	s.mu.Unlock()

	policyStoreLastSyncTimestampSeconds.Set(float64(s.CurrentInfo().LastSyncAt.Unix()))
	policyReplicaInSync.Set(0)
}

func (s *Store) Version() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.version
}

func (s *Store) ContentHash() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.contentHash
}

func formatOptionalTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func mustTLSConfig(certFile, keyFile, caFile string) *tls.Config {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Fatalf("load server keypair: %v", err)
	}
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		log.Fatalf("read ca file: %v", err)
	}
	caPool := x509.NewCertPool()
	if ok := caPool.AppendCertsFromPEM(caPEM); !ok {
		log.Fatalf("append ca failed")
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		ClientCAs:    caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}
}

func isAdmin(r *http.Request, token string) bool {
	return token != "" && r.Header.Get("X-Admin-Token") == token
}

func actorFromRequest(r *http.Request) string {
	if v := r.Header.Get("X-Actor"); v != "" {
		return v
	}
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		c := r.TLS.PeerCertificates[0]
		if c.Subject.CommonName != "" {
			return c.Subject.CommonName
		}
		if len(c.DNSNames) > 0 {
			return c.DNSNames[0]
		}
	}
	return "unknown"
}

type AuditEvent struct {
	Time      string `json:"time"`
	Action    string `json:"action"`
	Actor     string `json:"actor"`
	RemoteIP  string `json:"remote_ip"`
	UserAgent string `json:"user_agent"`
	OldVer    string `json:"old_ver"`
	NewVer    string `json:"new_ver"`
	OldHash   string `json:"old_hash,omitempty"`
	NewHash   string `json:"new_hash,omitempty"`
	Source    string `json:"source,omitempty"`
	Status    string `json:"status"`
	Error     string `json:"error,omitempty"`
}

func appendAudit(path string, ev AuditEvent) {
	if path == "" {
		return
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		log.Printf("audit open error: %v", err)
		return
	}
	defer f.Close()
	b, _ := json.Marshal(ev)
	_, _ = f.Write(append(b, '\n'))
}

var (
	decisionTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "policy_decisions_total", Help: "Total policy decisions"},
		[]string{"result"},
	)
	decisionLatency = prometheus.NewHistogram(
		prometheus.HistogramOpts{Name: "policy_decision_latency_seconds", Help: "Decision latency seconds"},
	)
	policyRulesTotal = prometheus.NewGauge(
		prometheus.GaugeOpts{Name: "policy_rules_total", Help: "Number of active policy rules"},
	)
	policyIndexBucketsTotal = prometheus.NewGauge(
		prometheus.GaugeOpts{Name: "policy_index_buckets_total", Help: "Number of active policy index buckets"},
	)
	policyMatchLatency = prometheus.NewHistogram(
		prometheus.HistogramOpts{Name: "policy_match_latency_seconds", Help: "Policy matching latency seconds"},
	)
	policyReloadTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "policy_reload_total", Help: "Policy reload attempts"},
		[]string{"result"},
	)
	policyReloadDuration = prometheus.NewHistogram(
		prometheus.HistogramOpts{Name: "policy_reload_duration_seconds", Help: "Policy reload duration seconds"},
	)
	policyCheckRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "policy_check_requests_total", Help: "Policy check HTTP requests"},
		[]string{"result"},
	)
	policyCheckDuration = prometheus.NewHistogram(
		prometheus.HistogramOpts{Name: "policy_check_duration_seconds", Help: "Policy check HTTP request duration seconds"},
	)
	policyStoreSyncTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "policy_store_sync_total", Help: "Policy store sync attempts"},
		[]string{"result"},
	)
	policyStoreSyncDuration = prometheus.NewHistogram(
		prometheus.HistogramOpts{Name: "policy_store_sync_duration_seconds", Help: "Policy store sync duration seconds"},
	)
	policyStoreDBErrorsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "policy_store_db_errors_total", Help: "Policy store database errors"},
		[]string{"operation"},
	)
	policyStoreLastSyncTimestampSeconds = prometheus.NewGauge(
		prometheus.GaugeOpts{Name: "policy_store_last_sync_timestamp_seconds", Help: "Last policy store sync attempt timestamp"},
	)
	policyReplicaInSync = prometheus.NewGauge(
		prometheus.GaugeOpts{Name: "policy_replica_in_sync", Help: "Whether this policy-server replica is in sync with the active policy store version"},
	)
)

func registerPolicyMetrics(reg prometheus.Registerer) {
	reg.MustRegister(
		decisionTotal,
		decisionLatency,
		policyRulesTotal,
		policyIndexBucketsTotal,
		policyMatchLatency,
		policyReloadTotal,
		policyReloadDuration,
		policyCheckRequestsTotal,
		policyCheckDuration,
		policyStoreSyncTotal,
		policyStoreSyncDuration,
		policyStoreDBErrorsTotal,
		policyStoreLastSyncTimestampSeconds,
		policyReplicaInSync,
	)
	initPolicyMetricSeries()
}

func initPolicyMetricSeries() {
	for _, result := range []string{"allow", "deny", "error"} {
		decisionTotal.WithLabelValues(result)
		policyCheckRequestsTotal.WithLabelValues(result)
	}
	for _, result := range []string{"ok", "error"} {
		policyReloadTotal.WithLabelValues(result)
	}
	for _, result := range []string{"ok", "stale", "error"} {
		policyStoreSyncTotal.WithLabelValues(result)
	}
	for _, operation := range []string{"load_active", "create", "activate", "rollback", "seed", "list"} {
		policyStoreDBErrorsTotal.WithLabelValues(operation)
	}
}

func main() {
	policyFile := os.Getenv("POLICY_FILE")
	policySourceName := os.Getenv("POLICY_SOURCE")
	policyStoreDSN := os.Getenv("POLICY_STORE_DSN")
	policyStoreSyncInterval, err := parseDurationEnv("POLICY_STORE_SYNC_INTERVAL", 2*time.Second)
	if err != nil {
		log.Fatal(err)
	}
	certFile := os.Getenv("CERT_FILE")
	keyFile := os.Getenv("KEY_FILE")
	caFile := os.Getenv("CA_FILE")
	adminToken := os.Getenv("ADMIN_TOKEN")
	auditFile := os.Getenv("AUDIT_FILE")

	if certFile == "" || keyFile == "" || caFile == "" {
		log.Fatal("CERT_FILE, KEY_FILE, CA_FILE are required")
	}
	policyRuntime, err := NewPolicySourceRuntime(context.Background(), PolicySourceConfig{
		Source:       policySourceName,
		FilePath:     policyFile,
		StoreDSN:     policyStoreDSN,
		SyncInterval: policyStoreSyncInterval,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer policyRuntime.Close()
	policySource := policyRuntime.Source

	shutdownTracing, err := authz.InitTracingFromEnv(context.Background(), "policy-server")
	if err != nil {
		log.Fatalf("init tracing: %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = shutdownTracing(ctx)
	}()

	registerPolicyMetrics(prometheus.DefaultRegisterer)

	store := &Store{}
	if err := loadInitialPolicy(context.Background(), store, policySource); err != nil {
		if policySource.Name() == policySourcePostgres {
			log.Printf("initial policy load failed; server will start unhealthy until sync succeeds: %v", err)
		} else {
			log.Fatal(err)
		}
	}
	if policySource.Name() == policySourcePostgres {
		syncCtx, cancelSync := context.WithCancel(context.Background())
		defer cancelSync()
		go runPolicySyncLoop(syncCtx, store, policySource, policyRuntime.SyncInterval)
	}
	info := store.CurrentInfo()
	log.Printf("Policy loaded. source=%s version=%s hash=%s", info.Source, info.Version, info.ContentHash)

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/v1/health", store.HealthHandler)
	mux.Handle("/metrics", promhttp.Handler())

	mux.HandleFunc("/v1/policies/version", func(w http.ResponseWriter, _ *http.Request) {
		info := store.CurrentInfo()
		_ = json.NewEncoder(w).Encode(map[string]any{
			"version":       info.Version,
			"content_hash":  info.ContentHash,
			"policy_source": info.Source,
			"sync_status":   info.SyncStatus,
			"last_sync_at":  formatOptionalTime(info.LastSyncAt),
			"sync_error":    info.SyncError,
		})
	})

	mux.HandleFunc("/v1/policies/reload", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !isAdmin(r, adminToken) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}

		old := store.CurrentInfo()
		actor := actorFromRequest(r)
		ev := AuditEvent{
			Time:      time.Now().Format(time.RFC3339),
			Action:    "reload",
			Actor:     actor,
			RemoteIP:  r.RemoteAddr,
			UserAgent: r.UserAgent(),
			OldVer:    old.Version,
			OldHash:   old.ContentHash,
			Source:    policySource.Name(),
			Status:    "error",
		}

		snapshot, err := store.ReloadFromSource(r.Context(), policySource, actor)
		if err != nil {
			ev.Error = err.Error()
			appendAudit(auditFile, ev)
			http.Error(w, "reload failed: "+err.Error(), http.StatusInternalServerError)
			return
		}

		info := store.CurrentInfo()
		ev.NewVer = snapshot.Version
		ev.NewHash = snapshot.ContentHash
		ev.Status = "ok"
		appendAudit(auditFile, ev)

		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":       "ok",
			"version":      info.Version,
			"content_hash": info.ContentHash,
			"rules":        info.Stats.Rules,
			"buckets":      info.Stats.Buckets,
			"source":       info.Source,
		})
	})

	mux.HandleFunc("/v1/policies/versions", func(w http.ResponseWriter, r *http.Request) {
		handlePolicyVersions(w, r, policySource, store, adminToken)
	})
	mux.HandleFunc("/v1/policies/versions/", func(w http.ResponseWriter, r *http.Request) {
		handlePolicyVersionAction(w, r, policySource, store, adminToken)
	})

	mux.HandleFunc("/v1/audit/tail", func(w http.ResponseWriter, r *http.Request) {
		if !isAdmin(r, adminToken) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if auditFile == "" {
			http.Error(w, "audit disabled", http.StatusNotFound)
			return
		}
		b, err := os.ReadFile(auditFile)
		if err != nil {
			http.Error(w, "read audit error: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write(b)
	})

	mux.HandleFunc("/v1/check", store.CheckHandler)

	srv := &http.Server{
		Addr:      ":8443",
		Handler:   mux,
		TLSConfig: mustTLSConfig(certFile, keyFile, caFile),
	}

	log.Println("policy-server listening on :8443 (mTLS)")
	log.Fatal(srv.ListenAndServeTLS("", ""))
}
