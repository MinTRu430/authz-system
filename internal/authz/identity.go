package authz

import (
	"crypto/x509"
	"errors"
)

func ServiceIdentityFromCertificate(cert *x509.Certificate) (string, error) {
	if len(cert.DNSNames) > 0 && cert.DNSNames[0] != "" {
		return cert.DNSNames[0], nil
	}
	if cert.Subject.CommonName != "" {
		return cert.Subject.CommonName, nil
	}
	return "", errors.New("empty identity in certificate")
}
