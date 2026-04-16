package httpadapter

import (
	"net/http"
	"testing"
)

func TestNormalizeResourceUsesRoutePatternWithoutMethod(t *testing.T) {
	req := &http.Request{Pattern: "POST /payments/charge"}

	got := NormalizeResource(req)
	if got != "/payments/charge" {
		t.Fatalf("resource = %q, want /payments/charge", got)
	}
}

func TestNormalizeResourceDropsQuery(t *testing.T) {
	req, err := http.NewRequest(http.MethodPost, "https://payments/payments/refund?id=123", nil)
	if err != nil {
		t.Fatal(err)
	}

	got := NormalizeResource(req)
	if got != "/payments/refund" {
		t.Fatalf("resource = %q, want /payments/refund", got)
	}
}
