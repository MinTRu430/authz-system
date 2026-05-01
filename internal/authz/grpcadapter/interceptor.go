package grpcadapter

import (
	"context"
	"errors"
	"strings"

	"authz-system/internal/authz"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/propagation"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
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
		ctx = extractGRPCTraceContext(ctx)
		traceReq := authz.NewGRPCAuthzRequest("", cfg.TargetService, info.FullMethod)
		ctx, span := authz.StartSpan(ctx, "transport.grpc.authorize", authz.SafeAuthzAttrs(traceReq)...)
		defer span.End()

		source, err := ExtractServiceIdentity(ctx)
		if err != nil {
			authz.RecordAuthzCheck("unauthenticated", authz.NewGRPCAuthzRequest("", cfg.TargetService, info.FullMethod))
			authz.EndSpanWithResult(span, "unauthenticated", err)
			return nil, status.Error(codes.Unauthenticated, "mtls identity error: "+err.Error())
		}

		method := info.FullMethod
		target := cfg.TargetService
		authReq := authz.NewGRPCAuthzRequest(source, target, method)
		span.SetAttributes(authz.SafeAuthzAttrs(authReq)...)

		_, err = authorizer.Authorize(ctx, authReq)
		if err != nil {
			if errors.Is(err, authz.ErrDenied) || errors.Is(err, authz.ErrFailClosed) {
				spanErr := error(nil)
				if errors.Is(err, authz.ErrFailClosed) {
					spanErr = err
				}
				authz.EndSpanWithResult(span, "deny", spanErr)
				return nil, status.Error(codes.PermissionDenied, err.Error())
			}
			authz.EndSpanWithResult(span, "error", err)
			return nil, status.Error(codes.PermissionDenied, "authz error: "+err.Error())
		}

		authz.EndSpanWithResult(span, "allow", nil)
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

		ctx := extractGRPCTraceContext(ss.Context())
		traceReq := authz.NewGRPCAuthzRequest("", cfg.TargetService, info.FullMethod)
		ctx, span := authz.StartSpan(ctx, "transport.grpc.authorize", append(authz.SafeAuthzAttrs(traceReq), attribute.Bool("grpc.stream", true))...)
		defer span.End()

		source, err := ExtractServiceIdentity(ctx)
		if err != nil {
			authz.RecordAuthzCheck("unauthenticated", authz.NewGRPCAuthzRequest("", cfg.TargetService, info.FullMethod))
			authz.EndSpanWithResult(span, "unauthenticated", err)
			return status.Error(codes.Unauthenticated, "mtls identity error: "+err.Error())
		}

		method := info.FullMethod
		target := cfg.TargetService
		authReq := authz.NewGRPCAuthzRequest(source, target, method)
		span.SetAttributes(authz.SafeAuthzAttrs(authReq)...)

		_, err = authorizer.Authorize(ctx, authReq)
		if err != nil {
			if errors.Is(err, authz.ErrDenied) || errors.Is(err, authz.ErrFailClosed) {
				spanErr := error(nil)
				if errors.Is(err, authz.ErrFailClosed) {
					spanErr = err
				}
				authz.EndSpanWithResult(span, "deny", spanErr)
				return status.Error(codes.PermissionDenied, err.Error())
			}
			authz.EndSpanWithResult(span, "error", err)
			return status.Error(codes.PermissionDenied, "authz error: "+err.Error())
		}

		authz.EndSpanWithResult(span, "allow", nil)
		return handler(srv, ss)
	}
}

func extractGRPCTraceContext(ctx context.Context) context.Context {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ctx
	}
	carrier := propagation.MapCarrier{}
	for key, values := range md {
		if len(values) > 0 {
			carrier[key] = values[0]
		}
	}
	return authz.ExtractTextMap(ctx, carrier)
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
