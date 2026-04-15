package authz

import (
	"context"
	"errors"
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
	authorizer, err := NewAuthorizer(cfg)
	if err != nil {
		panic("authz: init authorizer: " + err.Error())
	}

	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if strings.Contains(info.FullMethod, "grpc.health.v1.Health") {
			return handler(ctx, req)
		}

		source, err := ExtractServiceIdentity(ctx)
		if err != nil {
			recordAuthzCheck("unauthenticated", NewGRPCAuthzRequest("", cfg.TargetService, info.FullMethod))
			return nil, status.Error(codes.Unauthenticated, "mtls identity error: "+err.Error())
		}

		method := info.FullMethod
		target := cfg.TargetService
		authReq := NewGRPCAuthzRequest(source, target, method)

		_, err = authorizer.Authorize(ctx, authReq)
		if err != nil {
			if errors.Is(err, ErrDenied) || errors.Is(err, ErrFailClosed) {
				return nil, status.Error(codes.PermissionDenied, err.Error())
			}
			return nil, status.Error(codes.PermissionDenied, "authz error: "+err.Error())
		}

		return handler(ctx, req)
	}
}
