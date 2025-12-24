package authz

import (
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func NewStreamInterceptor(cfg Config) grpc.StreamServerInterceptor {
	RegisterMetrics()

	client, err := NewPolicyClient(cfg.PolicyURL, cfg.Timeout, cfg.PolicyClientTLS)
	if err != nil {
		panic("authz: init policy client (stream): " + err.Error())
	}

	var cache *DecisionCache
	if cfg.CacheTTL > 0 {
		cache = NewDecisionCache(cfg.CacheTTL)
	}

	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if strings.Contains(info.FullMethod, "grpc.health.v1.Health") {
			return handler(srv, ss)
		}

		source, err := ExtractServiceIdentity(ss.Context())
		if err != nil {
			authzChecksTotal.WithLabelValues("unauthenticated").Inc()
			return status.Error(codes.Unauthenticated, "mtls identity error: "+err.Error())
		}

		method := info.FullMethod
		target := cfg.TargetService

		if cache != nil {
			if resp, ok := cache.Get(source, target, method); ok {
				authzCacheTotal.WithLabelValues("hit").Inc()
				if !resp.Allow {
					authzChecksTotal.WithLabelValues("deny").Inc()
					return status.Error(codes.PermissionDenied, "denied: "+resp.Reason)
				}
				authzChecksTotal.WithLabelValues("allow").Inc()
				return handler(srv, ss)
			}
			authzCacheTotal.WithLabelValues("miss").Inc()
		}

		start := time.Now()
		dec, err := client.Check(ss.Context(), CheckRequest{SourceService: source, TargetService: target, RPCMethod: method})
		authzPolicyLatency.Observe(time.Since(start).Seconds())

		if err != nil {
			authzChecksTotal.WithLabelValues("unavailable").Inc()
			if cfg.FailOpen {
				return handler(srv, ss)
			}
			return status.Error(codes.Unavailable, "policy unavailable: "+err.Error())
		}

		if cache != nil {
			cache.Put(source, target, method, dec)
		}

		if !dec.Allow {
			authzChecksTotal.WithLabelValues("deny").Inc()
			return status.Error(codes.PermissionDenied, "denied: "+dec.Reason)
		}

		authzChecksTotal.WithLabelValues("allow").Inc()
		return handler(srv, ss)
	}
}
