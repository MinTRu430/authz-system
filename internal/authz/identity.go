package authz

import (
	"context"
	"crypto/x509"
	"errors"
	"net/http"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

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
	return serviceIdentityFromCertificate(tlsInfo.State.PeerCertificates[0])
}

func ExtractHTTPServiceIdentity(r *http.Request) (string, error) {
	if r.TLS == nil {
		return "", errors.New("request is not TLS")
	}
	if len(r.TLS.PeerCertificates) == 0 {
		return "", errors.New("no peer certificates")
	}
	return serviceIdentityFromCertificate(r.TLS.PeerCertificates[0])
}

func serviceIdentityFromCertificate(cert *x509.Certificate) (string, error) {
	if len(cert.DNSNames) > 0 && cert.DNSNames[0] != "" {
		return cert.DNSNames[0], nil
	}
	if cert.Subject.CommonName != "" {
		return cert.Subject.CommonName, nil
	}
	return "", errors.New("empty identity in certificate")
}
