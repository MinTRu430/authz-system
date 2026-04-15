package authz

import (
	"errors"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func NewStreamInterceptor(cfg Config) grpc.StreamServerInterceptor {
	authorizer, err := NewAuthorizer(cfg)
	if err != nil {
		panic("authz: init authorizer (stream): " + err.Error())
	}

	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if strings.Contains(info.FullMethod, "grpc.health.v1.Health") {
			return handler(srv, ss)
		}

		source, err := ExtractServiceIdentity(ss.Context())
		if err != nil {
			recordAuthzCheck("unauthenticated", NewGRPCAuthzRequest("", cfg.TargetService, info.FullMethod))
			return status.Error(codes.Unauthenticated, "mtls identity error: "+err.Error())
		}

		method := info.FullMethod
		target := cfg.TargetService
		authReq := NewGRPCAuthzRequest(source, target, method)

		_, err = authorizer.Authorize(ss.Context(), authReq)
		if err != nil {
			if errors.Is(err, ErrDenied) || errors.Is(err, ErrFailClosed) {
				return status.Error(codes.PermissionDenied, err.Error())
			}
			return status.Error(codes.PermissionDenied, "authz error: "+err.Error())
		}

		return handler(srv, ss)
	}
}
