package brokersign

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const (
	VersionV1 = "v1"

	ModeRequired = "required"
	ModeDisabled = "disabled"

	HeaderServiceName      = "X-Service-Name"
	HeaderMessageType      = "X-Message-Type"
	HeaderSignatureVersion = "X-Authz-Signature-Version"
	HeaderTimestamp        = "X-Authz-Timestamp"
	HeaderPayloadSHA256    = "X-Authz-Payload-SHA256"
	HeaderSignature        = "X-Authz-Signature"

	DefaultMaxAge     = 5 * time.Minute
	DefaultFutureSkew = 30 * time.Second
)

var (
	ErrMissingSignature        = errors.New("message signature missing")
	ErrUnsupportedVersion      = errors.New("message signature version unsupported")
	ErrMalformedTimestamp      = errors.New("message signature timestamp malformed")
	ErrExpiredTimestamp        = errors.New("message signature timestamp expired")
	ErrFutureTimestamp         = errors.New("message signature timestamp is too far in the future")
	ErrPayloadHashMismatch     = errors.New("message payload hash mismatch")
	ErrUnknownServiceSecret    = errors.New("message source secret unknown")
	ErrInvalidSignature        = errors.New("message signature invalid")
	ErrMalformedSecretConfig   = errors.New("message verification secrets malformed")
	ErrMissingSigningSecret    = errors.New("message signing secret missing")
	ErrMissingVerificationKeys = errors.New("message verification secrets missing")
	ErrUnsupportedMode         = errors.New("message signing mode unsupported")
)

type SignerConfig struct {
	Secret []byte
	Now    func() time.Time
}

type VerifierConfig struct {
	Secrets    map[string][]byte
	MaxAge     time.Duration
	FutureSkew time.Duration
	Now        func() time.Time
}

type SignInput struct {
	Broker      string
	Resource    string
	Source      string
	MessageType string
	Payload     []byte
}

type VerifyInput struct {
	Broker      string
	Resource    string
	Source      string
	MessageType string
	Payload     []byte
	Headers     map[string]string
}

type Signer struct {
	secret []byte
	now    func() time.Time
}

type Verifier struct {
	secrets    map[string][]byte
	maxAge     time.Duration
	futureSkew time.Duration
	now        func() time.Time
}

func NormalizeMode(mode string) (string, error) {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" {
		return ModeRequired, nil
	}
	switch mode {
	case ModeRequired, ModeDisabled:
		return mode, nil
	default:
		return "", fmt.Errorf("%w: %s", ErrUnsupportedMode, mode)
	}
}

func NewSigner(cfg SignerConfig) (*Signer, error) {
	if len(cfg.Secret) == 0 {
		return nil, ErrMissingSigningSecret
	}
	return &Signer{secret: append([]byte(nil), cfg.Secret...), now: cfg.Now}, nil
}

func NewVerifier(cfg VerifierConfig) (*Verifier, error) {
	if len(cfg.Secrets) == 0 {
		return nil, ErrMissingVerificationKeys
	}
	secrets := make(map[string][]byte, len(cfg.Secrets))
	for source, secret := range cfg.Secrets {
		source = strings.TrimSpace(source)
		if source == "" || len(secret) == 0 {
			return nil, ErrMalformedSecretConfig
		}
		secrets[source] = append([]byte(nil), secret...)
	}
	if cfg.MaxAge <= 0 {
		cfg.MaxAge = DefaultMaxAge
	}
	if cfg.FutureSkew <= 0 {
		cfg.FutureSkew = DefaultFutureSkew
	}
	return &Verifier{secrets: secrets, maxAge: cfg.MaxAge, futureSkew: cfg.FutureSkew, now: cfg.Now}, nil
}

func (s *Signer) Sign(input SignInput) (map[string]string, error) {
	if s == nil || len(s.secret) == 0 {
		return nil, ErrMissingSigningSecret
	}
	now := clockNow(s.now).Unix()
	payloadHash := PayloadSHA256(input.Payload)
	canonical := CanonicalString(input.Broker, input.Resource, input.Source, input.MessageType, now, payloadHash)
	signature := signCanonical(s.secret, canonical)
	return map[string]string{
		HeaderSignatureVersion: VersionV1,
		HeaderTimestamp:        strconv.FormatInt(now, 10),
		HeaderPayloadSHA256:    payloadHash,
		HeaderSignature:        signature,
	}, nil
}

func (v *Verifier) Verify(input VerifyInput) error {
	if v == nil || len(v.secrets) == 0 {
		return ErrMissingVerificationKeys
	}
	signature := input.Headers[HeaderSignature]
	if signature == "" {
		return ErrMissingSignature
	}
	version := input.Headers[HeaderSignatureVersion]
	if version != VersionV1 {
		return ErrUnsupportedVersion
	}
	timestampRaw := input.Headers[HeaderTimestamp]
	ts, err := strconv.ParseInt(timestampRaw, 10, 64)
	if timestampRaw == "" || err != nil {
		return ErrMalformedTimestamp
	}
	payloadHash := strings.ToLower(input.Headers[HeaderPayloadSHA256])
	if payloadHash == "" || payloadHash != PayloadSHA256(input.Payload) {
		return ErrPayloadHashMismatch
	}
	if err := v.validateTimestamp(ts); err != nil {
		return err
	}
	secret, ok := v.secrets[input.Source]
	if !ok {
		return ErrUnknownServiceSecret
	}
	canonical := CanonicalString(input.Broker, input.Resource, input.Source, input.MessageType, ts, payloadHash)
	expected := signCanonical(secret, canonical)
	if !hmac.Equal([]byte(signature), []byte(expected)) {
		return ErrInvalidSignature
	}
	return nil
}

func (v *Verifier) validateTimestamp(ts int64) error {
	now := clockNow(v.now)
	t := time.Unix(ts, 0)
	if t.After(now.Add(v.futureSkew)) {
		return ErrFutureTimestamp
	}
	if t.Before(now.Add(-v.maxAge)) {
		return ErrExpiredTimestamp
	}
	return nil
}

func CanonicalString(broker, resource, source, messageType string, timestamp int64, payloadHash string) string {
	return strings.Join([]string{
		VersionV1,
		"broker=" + broker,
		"resource=" + resource,
		"source=" + source,
		"message_type=" + messageType,
		"timestamp=" + strconv.FormatInt(timestamp, 10),
		"payload_sha256=" + strings.ToLower(payloadHash),
	}, "\n")
}

func PayloadSHA256(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func ParseVerificationSecrets(raw string) (map[string][]byte, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, ErrMissingVerificationKeys
	}
	out := map[string][]byte{}
	for _, item := range strings.Split(raw, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		source, encoded, ok := strings.Cut(item, "=")
		source = strings.TrimSpace(source)
		encoded = strings.TrimSpace(encoded)
		if !ok || source == "" || encoded == "" {
			return nil, ErrMalformedSecretConfig
		}
		secret, err := parseSecret(encoded)
		if err != nil {
			return nil, err
		}
		out[source] = secret
	}
	if len(out) == 0 {
		return nil, ErrMissingVerificationKeys
	}
	return out, nil
}

func ParseSecret(raw string) ([]byte, error) {
	return parseSecret(strings.TrimSpace(raw))
}

func FailureReason(err error) string {
	switch {
	case errors.Is(err, ErrMissingSignature):
		return "missing_signature"
	case errors.Is(err, ErrUnsupportedVersion):
		return "unsupported_version"
	case errors.Is(err, ErrMalformedTimestamp):
		return "malformed_timestamp"
	case errors.Is(err, ErrExpiredTimestamp):
		return "expired_timestamp"
	case errors.Is(err, ErrFutureTimestamp):
		return "future_timestamp"
	case errors.Is(err, ErrPayloadHashMismatch):
		return "payload_hash_mismatch"
	case errors.Is(err, ErrUnknownServiceSecret):
		return "unknown_service_secret"
	case errors.Is(err, ErrInvalidSignature):
		return "invalid_signature"
	case errors.Is(err, ErrMalformedSecretConfig):
		return "malformed_secret_config"
	case errors.Is(err, ErrMissingSigningSecret):
		return "missing_signing_secret"
	case errors.Is(err, ErrMissingVerificationKeys):
		return "missing_verification_keys"
	case errors.Is(err, ErrUnsupportedMode):
		return "unsupported_mode"
	default:
		return "unknown"
	}
}

func parseSecret(raw string) ([]byte, error) {
	if raw == "" {
		return nil, ErrMalformedSecretConfig
	}
	if !strings.HasPrefix(raw, "base64:") {
		return []byte(raw), nil
	}
	encoded := strings.TrimPrefix(raw, "base64:")
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(encoded)
	}
	if err != nil {
		decoded, err = base64.RawURLEncoding.DecodeString(encoded)
	}
	if err != nil || len(decoded) == 0 {
		return nil, fmt.Errorf("%w: invalid base64 secret", ErrMalformedSecretConfig)
	}
	return decoded, nil
}

func signCanonical(secret []byte, canonical string) string {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func clockNow(now func() time.Time) time.Time {
	if now != nil {
		return now()
	}
	return time.Now()
}
