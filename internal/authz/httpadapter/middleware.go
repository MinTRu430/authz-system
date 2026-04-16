package httpadapter

import (
	"errors"
	"net/http"
	"path"
	"strings"

	"authz-system/internal/authz"
)

func NewMiddleware(cfg authz.Config) func(http.Handler) http.Handler {
	authorizer, err := authz.NewAuthorizer(cfg)
	if err != nil {
		panic("authz: init http authorizer: " + err.Error())
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			resource := NormalizeResource(r)
			authReq := authz.NewAuthzRequest("", cfg.TargetService, authz.TransportHTTP, r.Method, resource)

			source, err := ExtractServiceIdentity(r)
			if err != nil {
				authz.RecordAuthzCheck("unauthenticated", authReq)
				http.Error(w, "mtls identity error: "+err.Error(), http.StatusUnauthorized)
				return
			}
			authReq.Source = source

			if _, err := authorizer.Authorize(r.Context(), authReq); err != nil {
				if errors.Is(err, authz.ErrDenied) || errors.Is(err, authz.ErrFailClosed) {
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

func NormalizeResource(r *http.Request) string {
	if r.Pattern != "" {
		return normalizeHTTPPath(stripHTTPMethodFromPattern(r.Pattern))
	}
	if r.URL == nil {
		return "/"
	}
	return normalizeHTTPPath(r.URL.Path)
}

func ExtractServiceIdentity(r *http.Request) (string, error) {
	if r.TLS == nil {
		return "", errors.New("request is not TLS")
	}
	if len(r.TLS.PeerCertificates) == 0 {
		return "", errors.New("no peer certificates")
	}
	return authz.ServiceIdentityFromCertificate(r.TLS.PeerCertificates[0])
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
