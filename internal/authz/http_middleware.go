package authz

import (
	"errors"
	"net/http"
	"path"
	"strings"
)

func NewHTTPMiddleware(cfg Config) func(http.Handler) http.Handler {
	authorizer, err := NewAuthorizer(cfg)
	if err != nil {
		panic("authz: init http authorizer: " + err.Error())
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			resource := NormalizeHTTPResource(r)
			authReq := NewAuthzRequest("", cfg.TargetService, TransportHTTP, r.Method, resource)

			source, err := ExtractHTTPServiceIdentity(r)
			if err != nil {
				recordAuthzCheck("unauthenticated", authReq)
				http.Error(w, "mtls identity error: "+err.Error(), http.StatusUnauthorized)
				return
			}
			authReq.Source = source

			if _, err := authorizer.Authorize(r.Context(), authReq); err != nil {
				if errors.Is(err, ErrDenied) || errors.Is(err, ErrFailClosed) {
					http.Error(w, err.Error(), http.StatusForbidden)
					return
				}
				http.Error(w, "authz error: "+err.Error(), http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func NormalizeHTTPResource(r *http.Request) string {
	if r.Pattern != "" {
		return normalizeHTTPPath(stripHTTPMethodFromPattern(r.Pattern))
	}
	if r.URL == nil {
		return "/"
	}
	return normalizeHTTPPath(r.URL.Path)
}

func stripHTTPMethodFromPattern(pattern string) string {
	if idx := strings.IndexByte(pattern, ' '); idx >= 0 {
		return strings.TrimSpace(pattern[idx+1:])
	}
	return pattern
}

func normalizeHTTPPath(p string) string {
	if p == "" {
		return "/"
	}
	cleaned := path.Clean("/" + strings.TrimPrefix(p, "/"))
	if cleaned == "." {
		return "/"
	}
	return cleaned
}
