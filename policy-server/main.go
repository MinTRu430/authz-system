package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"authz-system/internal/authz"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"gopkg.in/yaml.v3"
)

type Store struct {
	mu      sync.RWMutex
	rules   []authz.PolicyRule
	version string
}

func (s *Store) Decide(req authz.AuthzRequest) authz.CheckResponse {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return authz.DecidePolicy(s.rules, s.version, req)
}

func computeVersion(data []byte) string {
	sum := sha256.Sum256(data)
	short := hex.EncodeToString(sum[:])[:12]
	return short + "-" + time.Now().Format("20060102T150405")
}

func loadRulesFromFile(path string) ([]authz.PolicyRule, string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, "", err
	}
	var rules []authz.PolicyRule
	if err := yaml.Unmarshal(data, &rules); err != nil {
		return nil, "", err
	}
	return authz.NormalizePolicyRules(rules), computeVersion(data), nil
}

func (s *Store) ReloadFromFile(path string) error {
	rules, ver, err := loadRulesFromFile(path)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.rules = rules
	s.version = ver
	s.mu.Unlock()
	return nil
}

func (s *Store) Version() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.version
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
)

func main() {
	policyFile := os.Getenv("POLICY_FILE")
	certFile := os.Getenv("CERT_FILE")
	keyFile := os.Getenv("KEY_FILE")
	caFile := os.Getenv("CA_FILE")
	adminToken := os.Getenv("ADMIN_TOKEN")
	auditFile := os.Getenv("AUDIT_FILE")

	if policyFile == "" || certFile == "" || keyFile == "" || caFile == "" {
		log.Fatal("POLICY_FILE, CERT_FILE, KEY_FILE, CA_FILE are required")
	}

	prometheus.MustRegister(decisionTotal, decisionLatency)

	store := &Store{}
	if err := store.ReloadFromFile(policyFile); err != nil {
		log.Fatal(err)
	}
	log.Printf("Policy loaded. version=%s", store.Version())

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.Handle("/metrics", promhttp.Handler())

	mux.HandleFunc("/v1/policies/version", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"version": store.Version()})
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

		old := store.Version()
		ev := AuditEvent{
			Time:      time.Now().Format(time.RFC3339),
			Action:    "reload",
			Actor:     actorFromRequest(r),
			RemoteIP:  r.RemoteAddr,
			UserAgent: r.UserAgent(),
			OldVer:    old,
			Status:    "error",
		}

		if err := store.ReloadFromFile(policyFile); err != nil {
			ev.Error = err.Error()
			appendAudit(auditFile, ev)
			http.Error(w, "reload failed: "+err.Error(), http.StatusInternalServerError)
			return
		}

		ev.NewVer = store.Version()
		ev.Status = "ok"
		appendAudit(auditFile, ev)

		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok", "version": store.Version()})
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

	mux.HandleFunc("/v1/check", func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		defer r.Body.Close()

		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			decisionTotal.WithLabelValues("error").Inc()
			http.Error(w, "read error", http.StatusBadRequest)
			return
		}

		var req authz.AuthzRequest
		if err := json.Unmarshal(body, &req); err != nil {
			decisionTotal.WithLabelValues("error").Inc()
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		resp := store.Decide(req)

		if resp.Allow {
			decisionTotal.WithLabelValues("allow").Inc()
		} else {
			decisionTotal.WithLabelValues("deny").Inc()
		}
		decisionLatency.Observe(time.Since(start).Seconds())

		_ = json.NewEncoder(w).Encode(resp)
	})

	srv := &http.Server{
		Addr:      ":8443",
		Handler:   mux,
		TLSConfig: mustTLSConfig(certFile, keyFile, caFile),
	}

	log.Println("policy-server listening on :8443 (mTLS)")
	log.Fatal(srv.ListenAndServeTLS("", ""))
}
