package httpadapter

import (
	"errors"
	"net/http"
	"path"
	"strings"

	"authz-system/internal/authz"

	"go.opentelemetry.io/otel/attribute"
)

func NewMiddleware(cfg authz.Config) func(http.Handler) http.Handler {
	authorizer, err := authz.NewAuthorizer(cfg)
	if err != nil {
		panic("authz: init http authorizer: " + err.Error())
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := authz.ExtractHTTP(r.Context(), r.Header)
			resource := NormalizeResource(r)
			authReq := authz.NewAuthzRequest("", cfg.TargetService, authz.TransportHTTP, r.Method, resource)
			ctx, span := authz.StartSpan(ctx, "transport.http.authorize", append(authz.SafeAuthzAttrs(authReq), attribute.String("http.method", r.Method))...)
			defer span.End()

			source, err := ExtractServiceIdentity(r)
			if err != nil {
				authz.RecordAuthzCheck("unauthenticated", authReq)
				authz.EndSpanWithResult(span, "unauthenticated", err)
				http.Error(w, "mtls identity error: "+err.Error(), http.StatusUnauthorized)
				return
			}
			authReq.Source = source

			if _, err := authorizer.Authorize(ctx, authReq); err != nil {
				if errors.Is(err, authz.ErrDenied) || errors.Is(err, authz.ErrFailClosed) {
					spanErr := error(nil)
					if errors.Is(err, authz.ErrFailClosed) {
						spanErr = err
					}
					authz.EndSpanWithResult(span, "deny", spanErr)
					http.Error(w, err.Error(), http.StatusForbidden)
					return
				}
				authz.EndSpanWithResult(span, "error", err)
				http.Error(w, "authz error: "+err.Error(), http.StatusForbidden)
				return
			}

			authz.EndSpanWithResult(span, "allow", nil)
			next.ServeHTTP(w, r.WithContext(ctx))
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
