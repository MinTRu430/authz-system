package brokerreliability

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"authz-system/internal/authz"
	"authz-system/internal/authz/brokersign"
)

func TestClassifyTerminalErrors(t *testing.T) {
	tests := []struct {
		err    error
		reason string
	}{
		{brokersign.ErrMissingSignature, ReasonMissingSignature},
		{brokersign.ErrInvalidSignature, ReasonInvalidSignature},
		{brokersign.ErrPayloadHashMismatch, ReasonPayloadHashMismatch},
		{brokersign.ErrUnknownServiceSecret, ReasonUnknownServiceSecret},
		{authz.ErrDenied, ReasonDenied},
		{errors.New("kafka message missing X-Service-Name header"), ReasonMalformedHeaders},
	}

	for _, tt := range tests {
		got := Classify(tt.err)
		if !got.Terminal || got.Reason != tt.reason {
			t.Fatalf("Classify(%v) = %+v, want terminal %s", tt.err, got, tt.reason)
		}
	}
}

func TestClassifyTransientPolicyUnavailable(t *testing.T) {
	for _, err := range []error{authz.ErrFailClosed, authz.ErrPolicyUnavailable} {
		got := Classify(err)
		if !got.Transient || got.Reason != ReasonPolicyUnavailable {
			t.Fatalf("Classify(%v) = %+v, want transient policy_unavailable", err, got)
		}
	}
}

func TestInvalidSignatureDeadLettersWithoutAuthzOrHandler(t *testing.T) {
	var authzCalls, handlerCalls, dlqCalls int
	_, err := Process(context.Background(), testConfig(), testMessage(), func(context.Context) error {
		authzCalls++
		return brokersign.ErrInvalidSignature
	}, func(context.Context) error {
		handlerCalls++
		return nil
	}, func(_ context.Context, env Envelope) error {
		dlqCalls++
		if env.Reason != ReasonInvalidSignature {
			t.Fatalf("DLQ reason = %q", env.Reason)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if authzCalls != 1 || handlerCalls != 0 || dlqCalls != 1 {
		t.Fatalf("authz=%d handler=%d dlq=%d, want 1/0/1", authzCalls, handlerCalls, dlqCalls)
	}
}

func TestMissingSignatureDeadLetters(t *testing.T) {
	var dlqCalls int
	out, err := Process(context.Background(), testConfig(), testMessage(), func(context.Context) error {
		return brokersign.ErrMissingSignature
	}, nil, func(_ context.Context, env Envelope) error {
		dlqCalls++
		if env.Reason != ReasonMissingSignature {
			t.Fatalf("DLQ reason = %q", env.Reason)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !out.DeadLettered || dlqCalls != 1 {
		t.Fatalf("out=%+v dlq=%d, want deadlettered once", out, dlqCalls)
	}
}

func TestDenyDeadLettersWithoutHandler(t *testing.T) {
	var handlerCalls, dlqCalls int
	out, err := Process(context.Background(), testConfig(), testMessage(), func(context.Context) error {
		return authz.ErrDenied
	}, func(context.Context) error {
		handlerCalls++
		return nil
	}, func(_ context.Context, env Envelope) error {
		dlqCalls++
		if env.Reason != ReasonDenied {
			t.Fatalf("DLQ reason = %q", env.Reason)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !out.DeadLettered || handlerCalls != 0 || dlqCalls != 1 {
		t.Fatalf("out=%+v handler=%d dlq=%d, want DLQ/no handler", out, handlerCalls, dlqCalls)
	}
}

func TestPolicyUnavailableRetriesNoImmediateDLQ(t *testing.T) {
	cfg := testConfig()
	cfg.MaxRetries = 3
	var authzCalls, dlqCalls int
	out, err := Process(context.Background(), cfg, testMessage(), func(context.Context) error {
		authzCalls++
		if authzCalls < 3 {
			return authz.ErrPolicyUnavailable
		}
		return nil
	}, nil, func(context.Context, Envelope) error {
		dlqCalls++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.DeadLettered || authzCalls != 3 || dlqCalls != 0 {
		t.Fatalf("out=%+v authz=%d dlq=%d, want retry success without DLQ", out, authzCalls, dlqCalls)
	}
}

func TestPolicyUnavailableAfterRetriesDeadLetters(t *testing.T) {
	cfg := testConfig()
	cfg.MaxRetries = 2
	var authzCalls, dlqCalls int
	out, err := Process(context.Background(), cfg, testMessage(), func(context.Context) error {
		authzCalls++
		return authz.ErrPolicyUnavailable
	}, nil, func(_ context.Context, env Envelope) error {
		dlqCalls++
		if env.Reason != ReasonPolicyUnavailable {
			t.Fatalf("DLQ reason = %q", env.Reason)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !out.DeadLettered || authzCalls != 3 || dlqCalls != 1 {
		t.Fatalf("out=%+v authz=%d dlq=%d, want retry exhausted DLQ", out, authzCalls, dlqCalls)
	}
}

func TestHandlerErrorRetriesThenDeadLetters(t *testing.T) {
	cfg := testConfig()
	cfg.MaxRetries = 2
	var handlerCalls, dlqCalls int
	out, err := Process(context.Background(), cfg, testMessage(), func(context.Context) error {
		return nil
	}, func(context.Context) error {
		handlerCalls++
		return errors.New("handler failed")
	}, func(_ context.Context, env Envelope) error {
		dlqCalls++
		if env.Reason != ReasonHandlerError {
			t.Fatalf("DLQ reason = %q", env.Reason)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !out.DeadLettered || handlerCalls != 3 || dlqCalls != 1 {
		t.Fatalf("out=%+v handler=%d dlq=%d, want handler retry exhausted DLQ", out, handlerCalls, dlqCalls)
	}
}

func TestAllowPathUnchanged(t *testing.T) {
	var handlerCalls, dlqCalls int
	out, err := Process(context.Background(), testConfig(), testMessage(), func(context.Context) error {
		return nil
	}, func(context.Context) error {
		handlerCalls++
		return nil
	}, func(context.Context, Envelope) error {
		dlqCalls++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Result != ResultProcessed || handlerCalls != 1 || dlqCalls != 0 {
		t.Fatalf("out=%+v handler=%d dlq=%d, want processed once", out, handlerCalls, dlqCalls)
	}
}

func TestDLQPublishFailureIsReturned(t *testing.T) {
	want := errors.New("dlq unavailable")
	_, err := Process(context.Background(), testConfig(), testMessage(), func(context.Context) error {
		return authz.ErrDenied
	}, nil, func(context.Context, Envelope) error {
		return want
	})
	if !errors.Is(err, want) {
		t.Fatalf("Process error = %v, want DLQ publish error", err)
	}
}

func TestDLQEnvelopeAndResource(t *testing.T) {
	msg := testMessage()
	env := NewEnvelope(msg, ReasonDenied, authz.ErrDenied, time.Unix(1_700_000_000, 0))
	if env.Broker != "kafka" || env.Resource != "payments.requested" || env.Reason != ReasonDenied {
		t.Fatalf("envelope = %+v", env)
	}
	if got := env.PayloadBase64; got != base64.StdEncoding.EncodeToString(msg.Payload) {
		t.Fatalf("payload_base64 = %q", got)
	}
	if _, ok := env.Headers["Authorization"]; ok {
		t.Fatal("unexpected non-allowlisted header in envelope")
	}
	if got := BuildDLQResource("authz.dlq", "payments.requested"); got != "authz.dlq.payments.requested" {
		t.Fatalf("DLQ resource = %q", got)
	}
}

func testConfig() Config {
	return Config{
		DLQEnabled:                 true,
		DLQPrefix:                  DefaultDLQPrefix,
		MaxRetries:                 2,
		RetryBackoff:               time.Nanosecond,
		DeadLetterOnDeny:           true,
		DeadLetterOnSignatureError: true,
	}
}

func testMessage() Message {
	return Message{
		Broker:           "kafka",
		Resource:         "payments.requested",
		OriginalResource: "payments.requested",
		Source:           "orders",
		MessageType:      "payment.requested.v1",
		Payload:          []byte(`{"order_id":"o-1"}`),
		Headers: map[string]string{
			brokersign.HeaderServiceName:      "orders",
			brokersign.HeaderMessageType:      "payment.requested.v1",
			brokersign.HeaderSignature:        "signature",
			brokersign.HeaderPayloadSHA256:    "payload-hash",
			brokersign.HeaderSignatureVersion: brokersign.VersionV1,
			"Authorization":                   "secret",
		},
	}
}
