package authz

import (
	"context"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Config struct {
	TargetService   string
	PolicyURL       string // https://policy-server:8443
	FailOpen        bool
	Timeout         time.Duration
	CacheTTL        time.Duration
	PolicyClientTLS TLSFiles
}

func NewUnaryInterceptor(cfg Config) grpc.UnaryServerInterceptor {
	RegisterMetrics()

	client, err := NewPolicyClient(cfg.PolicyURL, cfg.Timeout, cfg.PolicyClientTLS)
	if err != nil {
		panic("authz: init policy client: " + err.Error())
	}

	var cache *DecisionCache
	if cfg.CacheTTL > 0 {
		cache = NewDecisionCache(cfg.CacheTTL)
	}

	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if strings.Contains(info.FullMethod, "grpc.health.v1.Health") {
			return handler(ctx, req)
		}

		source, err := ExtractServiceIdentity(ctx)
		if err != nil {
			authzChecksTotal.WithLabelValues("unauthenticated").Inc()
			return nil, status.Error(codes.Unauthenticated, "mtls identity error: "+err.Error())
		}

		method := info.FullMethod
		target := cfg.TargetService

		if cache != nil {
			if resp, ok := cache.Get(source, target, method); ok {
				authzCacheTotal.WithLabelValues("hit").Inc()
				if !resp.Allow {
					authzChecksTotal.WithLabelValues("deny").Inc()
					return nil, status.Error(codes.PermissionDenied, "denied: "+resp.Reason)
				}
				authzChecksTotal.WithLabelValues("allow").Inc()
				return handler(ctx, req)
			}
			authzCacheTotal.WithLabelValues("miss").Inc()
		}

		start := time.Now()
		dec, err := client.Check(ctx, CheckRequest{SourceService: source, TargetService: target, RPCMethod: method})
		authzPolicyLatency.Observe(time.Since(start).Seconds())

		if err != nil {
			authzChecksTotal.WithLabelValues("unavailable").Inc()
			if cfg.FailOpen {
				return handler(ctx, req)
			}
			return nil, status.Error(codes.Unavailable, "policy unavailable: "+err.Error())
		}

		if cache != nil {
			cache.Put(source, target, method, dec)
		}

		if !dec.Allow {
			authzChecksTotal.WithLabelValues("deny").Inc()
			return nil, status.Error(codes.PermissionDenied, "denied: "+dec.Reason)
		}

		authzChecksTotal.WithLabelValues("allow").Inc()
		return handler(ctx, req)
	}
}
