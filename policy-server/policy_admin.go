package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

type policyVersionResponse struct {
	ID              int64   `json:"id"`
	Version         string  `json:"version"`
	ContentHash     string  `json:"content_hash"`
	CreatedAt       string  `json:"created_at"`
	CreatedBy       string  `json:"created_by"`
	ActivatedAt     *string `json:"activated_at,omitempty"`
	Comment         string  `json:"comment,omitempty"`
	ValidationError string  `json:"validation_error,omitempty"`
}

func handlePolicyVersions(w http.ResponseWriter, r *http.Request, source PolicySource, _ *Store, adminToken string) {
	if !isAdmin(r, adminToken) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	pgSource, ok := source.(*PostgresPolicySource)
	if !ok {
		http.Error(w, "policy versions are only available when POLICY_SOURCE=postgres", http.StatusNotFound)
		return
	}

	switch r.Method {
	case http.MethodGet:
		versions, err := pgSource.ListVersions(r.Context())
		if err != nil {
			policyStoreDBErrorsTotal.WithLabelValues("list").Inc()
			http.Error(w, "list versions failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		out := make([]policyVersionResponse, 0, len(versions))
		for _, version := range versions {
			out = append(out, policyVersionToResponse(version))
		}
		writeJSON(w, http.StatusOK, map[string]any{"versions": out})
	case http.MethodPost:
		content, comment, err := readCreatePolicyVersionRequest(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		created, err := pgSource.CreateVersion(r.Context(), content, actorFromRequest(r), comment)
		if err != nil {
			policyStoreDBErrorsTotal.WithLabelValues("create").Inc()
			http.Error(w, "create version failed: "+err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusCreated, policyVersionToResponse(created))
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func handlePolicyVersionAction(w http.ResponseWriter, r *http.Request, source PolicySource, store *Store, adminToken string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !isAdmin(r, adminToken) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	pgSource, ok := source.(*PostgresPolicySource)
	if !ok {
		http.Error(w, "policy version actions are only available when POLICY_SOURCE=postgres", http.StatusNotFound)
		return
	}

	version, action, err := parsePolicyVersionActionPath(r.URL.Path)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	actor := actorFromRequest(r)
	var snapshot PolicySnapshot
	switch action {
	case "activate":
		snapshot, err = pgSource.Activate(r.Context(), version, actor)
		if err != nil {
			policyStoreDBErrorsTotal.WithLabelValues("activate").Inc()
		}
	case "rollback":
		snapshot, err = pgSource.Rollback(r.Context(), version, actor)
		if err != nil {
			policyStoreDBErrorsTotal.WithLabelValues("rollback").Inc()
		}
	default:
		http.Error(w, "unknown policy version action", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, action+" failed: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := store.ApplySnapshot(snapshot); err != nil {
		http.Error(w, "apply policy failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	info := store.CurrentInfo()
	writeJSON(w, http.StatusOK, map[string]any{
		"status":       "ok",
		"action":       action,
		"version":      info.Version,
		"content_hash": info.ContentHash,
		"rules":        info.Stats.Rules,
		"buckets":      info.Stats.Buckets,
	})
}

func parsePolicyVersionActionPath(path string) (string, string, error) {
	rest := strings.TrimPrefix(path, "/v1/policies/versions/")
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("expected /v1/policies/versions/{version}/{activate|rollback}")
	}
	return parts[0], parts[1], nil
}

func readCreatePolicyVersionRequest(r *http.Request) ([]byte, string, error) {
	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
	if err != nil {
		return nil, "", fmt.Errorf("read request: %w", err)
	}
	if len(body) == 0 {
		return nil, "", fmt.Errorf("policy content is empty")
	}

	if strings.Contains(strings.ToLower(r.Header.Get("Content-Type")), "application/json") {
		var req struct {
			ContentYAML string `json:"content_yaml"`
			Comment     string `json:"comment"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			return nil, "", fmt.Errorf("bad json: %w", err)
		}
		if strings.TrimSpace(req.ContentYAML) == "" {
			return nil, "", fmt.Errorf("content_yaml is required")
		}
		return []byte(req.ContentYAML), req.Comment, nil
	}

	return body, r.Header.Get("X-Policy-Comment"), nil
}

func policyVersionToResponse(version PolicyVersion) policyVersionResponse {
	resp := policyVersionResponse{
		ID:              version.ID,
		Version:         version.Version,
		ContentHash:     version.ContentHash,
		CreatedAt:       version.CreatedAt.UTC().Format(time.RFC3339),
		CreatedBy:       version.CreatedBy,
		Comment:         version.Comment,
		ValidationError: version.ValidationError,
	}
	if version.ActivatedAt != nil {
		value := version.ActivatedAt.UTC().Format(time.RFC3339)
		resp.ActivatedAt = &value
	}
	return resp
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func parseDurationEnv(name string, fallback time.Duration) (time.Duration, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback, nil
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", name, err)
	}
	return parsed, nil
}
