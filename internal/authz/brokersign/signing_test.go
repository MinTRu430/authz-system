package brokersign

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestSignVerifyValidSignature(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	signer := mustSigner(t, "orders-secret", now)
	verifier := mustVerifier(t, map[string][]byte{"orders": []byte("orders-secret")}, now)

	headers, err := signer.Sign(validInput())
	if err != nil {
		t.Fatal(err)
	}

	if err := verifier.Verify(verifyInput(headers)); err != nil {
		t.Fatalf("Verify error = %v, want nil", err)
	}
}

func TestCanonicalStringFormat(t *testing.T) {
	got := CanonicalString("kafka", "payments.requested", "orders", "payment.requested.v1", 123, "ABC")
	want := strings.Join([]string{
		"v1",
		"broker=kafka",
		"resource=payments.requested",
		"source=orders",
		"message_type=payment.requested.v1",
		"timestamp=123",
		"payload_sha256=abc",
	}, "\n")
	if got != want {
		t.Fatalf("canonical string = %q, want %q", got, want)
	}
}

func TestVerifyRejectsTamperedFields(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	signer := mustSigner(t, "orders-secret", now)
	verifier := mustVerifier(t, map[string][]byte{"orders": []byte("orders-secret")}, now)
	headers, err := signer.Sign(validInput())
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		mutate func(VerifyInput) VerifyInput
	}{
		{name: "source", mutate: func(in VerifyInput) VerifyInput { in.Source = "evil"; return in }},
		{name: "message_type", mutate: func(in VerifyInput) VerifyInput { in.MessageType = "payment.refund.forced.v1"; return in }},
		{name: "resource", mutate: func(in VerifyInput) VerifyInput { in.Resource = "payments.refund.forced"; return in }},
		{name: "payload", mutate: func(in VerifyInput) VerifyInput { in.Payload = []byte("tampered"); return in }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := verifier.Verify(tt.mutate(verifyInput(headers)))
			if err == nil {
				t.Fatal("Verify error = nil, want reject")
			}
			if tt.name == "payload" && !errors.Is(err, ErrPayloadHashMismatch) {
				t.Fatalf("Verify error = %v, want ErrPayloadHashMismatch", err)
			}
		})
	}
}

func TestVerifyRejectsExpiredTimestamp(t *testing.T) {
	signTime := time.Unix(1_700_000_000, 0)
	verifyTime := signTime.Add(DefaultMaxAge + time.Second)
	signer := mustSigner(t, "orders-secret", signTime)
	verifier := mustVerifier(t, map[string][]byte{"orders": []byte("orders-secret")}, verifyTime)
	headers, err := signer.Sign(validInput())
	if err != nil {
		t.Fatal(err)
	}

	err = verifier.Verify(verifyInput(headers))
	if !errors.Is(err, ErrExpiredTimestamp) {
		t.Fatalf("Verify error = %v, want ErrExpiredTimestamp", err)
	}
}

func TestVerifyRejectsFutureTimestamp(t *testing.T) {
	signTime := time.Unix(1_700_000_000, 0)
	verifyTime := signTime.Add(-DefaultFutureSkew - time.Second)
	signer := mustSigner(t, "orders-secret", signTime)
	verifier := mustVerifier(t, map[string][]byte{"orders": []byte("orders-secret")}, verifyTime)
	headers, err := signer.Sign(validInput())
	if err != nil {
		t.Fatal(err)
	}

	err = verifier.Verify(verifyInput(headers))
	if !errors.Is(err, ErrFutureTimestamp) {
		t.Fatalf("Verify error = %v, want ErrFutureTimestamp", err)
	}
}

func TestVerifyRejectsMissingSignature(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	signer := mustSigner(t, "orders-secret", now)
	verifier := mustVerifier(t, map[string][]byte{"orders": []byte("orders-secret")}, now)
	headers, err := signer.Sign(validInput())
	if err != nil {
		t.Fatal(err)
	}
	delete(headers, HeaderSignature)

	err = verifier.Verify(verifyInput(headers))
	if !errors.Is(err, ErrMissingSignature) {
		t.Fatalf("Verify error = %v, want ErrMissingSignature", err)
	}
}

func TestVerifyRejectsWrongSecret(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	signer := mustSigner(t, "orders-secret", now)
	verifier := mustVerifier(t, map[string][]byte{"orders": []byte("wrong-secret")}, now)
	headers, err := signer.Sign(validInput())
	if err != nil {
		t.Fatal(err)
	}

	err = verifier.Verify(verifyInput(headers))
	if !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("Verify error = %v, want ErrInvalidSignature", err)
	}
}

func TestVerifyRejectsUnknownService(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	signer := mustSigner(t, "orders-secret", now)
	verifier := mustVerifier(t, map[string][]byte{"payments": []byte("payments-secret")}, now)
	headers, err := signer.Sign(validInput())
	if err != nil {
		t.Fatal(err)
	}

	err = verifier.Verify(verifyInput(headers))
	if !errors.Is(err, ErrUnknownServiceSecret) {
		t.Fatalf("Verify error = %v, want ErrUnknownServiceSecret", err)
	}
}

func TestVerifyRejectsUnsupportedVersion(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	signer := mustSigner(t, "orders-secret", now)
	verifier := mustVerifier(t, map[string][]byte{"orders": []byte("orders-secret")}, now)
	headers, err := signer.Sign(validInput())
	if err != nil {
		t.Fatal(err)
	}
	headers[HeaderSignatureVersion] = "v2"

	err = verifier.Verify(verifyInput(headers))
	if !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("Verify error = %v, want ErrUnsupportedVersion", err)
	}
}

func TestVerifyRejectsMalformedTimestamp(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	signer := mustSigner(t, "orders-secret", now)
	verifier := mustVerifier(t, map[string][]byte{"orders": []byte("orders-secret")}, now)
	headers, err := signer.Sign(validInput())
	if err != nil {
		t.Fatal(err)
	}
	headers[HeaderTimestamp] = "not-a-number"

	err = verifier.Verify(verifyInput(headers))
	if !errors.Is(err, ErrMalformedTimestamp) {
		t.Fatalf("Verify error = %v, want ErrMalformedTimestamp", err)
	}
}

func TestParseVerificationSecretsSupportsBase64AndPlainSecrets(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte("orders-secret"))
	secrets, err := ParseVerificationSecrets("orders=base64:" + encoded + ",payments=payments-secret")
	if err != nil {
		t.Fatal(err)
	}
	if got := string(secrets["orders"]); got != "orders-secret" {
		t.Fatalf("orders secret = %q", got)
	}
	if got := string(secrets["payments"]); got != "payments-secret" {
		t.Fatalf("payments secret = %q", got)
	}
}

func TestParseVerificationSecretsRejectsMalformedConfig(t *testing.T) {
	_, err := ParseVerificationSecrets("orders")
	if !errors.Is(err, ErrMalformedSecretConfig) {
		t.Fatalf("ParseVerificationSecrets error = %v, want ErrMalformedSecretConfig", err)
	}

	_, err = ParseVerificationSecrets("orders=base64:not-valid")
	if !errors.Is(err, ErrMalformedSecretConfig) {
		t.Fatalf("ParseVerificationSecrets error = %v, want ErrMalformedSecretConfig", err)
	}
}

func mustSigner(t *testing.T, secret string, now time.Time) *Signer {
	t.Helper()
	signer, err := NewSigner(SignerConfig{Secret: []byte(secret), Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func mustVerifier(t *testing.T, secrets map[string][]byte, now time.Time) *Verifier {
	t.Helper()
	verifier, err := NewVerifier(VerifierConfig{Secrets: secrets, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	return verifier
}

func validInput() SignInput {
	return SignInput{
		Broker:      "kafka",
		Resource:    "payments.requested",
		Source:      "orders",
		MessageType: "payment.requested.v1",
		Payload:     []byte(`{"order_id":"o-1"}`),
	}
}

func verifyInput(headers map[string]string) VerifyInput {
	return VerifyInput{
		Broker:      "kafka",
		Resource:    "payments.requested",
		Source:      "orders",
		MessageType: "payment.requested.v1",
		Payload:     []byte(`{"order_id":"o-1"}`),
		Headers:     headers,
	}
}
