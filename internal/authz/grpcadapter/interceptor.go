package grpcadapter

import (
	"context"
	"errors"
	"strings"

	"authz-system/internal/authz"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

func NewUnaryInterceptor(cfg authz.Config) grpc.UnaryServerInterceptor {
	authorizer, err := authz.NewAuthorizer(cfg)
	if err != nil {
		panic("authz: init authorizer: " + err.Error())
	}

	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if strings.Contains(info.FullMethod, "grpc.health.v1.Health") {
			return handler(ctx, req)
		}

		source, err := ExtractServiceIdentity(ctx)
		if err != nil {
			authz.RecordAuthzCheck("unauthenticated", authz.NewGRPCAuthzRequest("", cfg.TargetService, info.FullMethod))
			return nil, status.Error(codes.Unauthenticated, "mtls identity error: "+err.Error())
		}

		method := info.FullMethod
		target := cfg.TargetService
		authReq := authz.NewGRPCAuthzRequest(source, target, method)

		_, err = authorizer.Authorize(ctx, authReq)
		if err != nil {
			if errors.Is(err, authz.ErrDenied) || errors.Is(err, authz.ErrFailClosed) {
				return nil, status.Error(codes.PermissionDenied, err.Error())
			}
			return nil, status.Error(codes.PermissionDenied, "authz error: "+err.Error())
		}

		return handler(ctx, req)
	}
}

func NewStreamInterceptor(cfg authz.Config) grpc.StreamServerInterceptor {
	authorizer, err := authz.NewAuthorizer(cfg)
	if err != nil {
		panic("authz: init authorizer (stream): " + err.Error())
	}

	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if strings.Contains(info.FullMethod, "grpc.health.v1.Health") {
			return handler(srv, ss)
		}

		source, err := ExtractServiceIdentity(ss.Context())
		if err != nil {
			authz.RecordAuthzCheck("unauthenticated", authz.NewGRPCAuthzRequest("", cfg.TargetService, info.FullMethod))
			return status.Error(codes.Unauthenticated, "mtls identity error: "+err.Error())
		}

		method := info.FullMethod
		target := cfg.TargetService
		authReq := authz.NewGRPCAuthzRequest(source, target, method)

		_, err = authorizer.Authorize(ss.Context(), authReq)
		if err != nil {
			if errors.Is(err, authz.ErrDenied) || errors.Is(err, authz.ErrFailClosed) {
				return status.Error(codes.PermissionDenied, err.Error())
			}
			return status.Error(codes.PermissionDenied, "authz error: "+err.Error())
		}

		return handler(srv, ss)
	}
}

func ExtractServiceIdentity(ctx context.Context) (string, error) {
	p, ok := peer.FromContext(ctx)
	if !ok || p.AuthInfo == nil {
		return "", errors.New("no peer auth info")
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return "", errors.New("auth info is not TLS")
	}
	if len(tlsInfo.State.PeerCertificates) == 0 {
		return "", errors.New("no peer certificates")
	}
	return authz.ServiceIdentityFromCertificate(tlsInfo.State.PeerCertificates[0])
}
