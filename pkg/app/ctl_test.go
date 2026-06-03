package app

import (
	"net/http"
	"testing"
	"time"
)

func TestCTLHTTPErrorClassification(t *testing.T) {
	for _, status := range []int{
		http.StatusTooManyRequests,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout,
	} {
		err := ctlHTTPError{status: status}
		if !isCTLSkipError(err) {
			t.Fatalf("expected status %d to be skippable", status)
		}
	}

	if isCTLSkipError(ctlHTTPError{status: http.StatusForbidden}) {
		t.Fatal("did not expect 403 to be skippable")
	}
}

func TestParseRetryAfter(t *testing.T) {
	if got := parseRetryAfter("12"); got != 12*time.Second {
		t.Fatalf("parseRetryAfter seconds = %s, want 12s", got)
	}

	future := time.Now().UTC().Add(30 * time.Second).Format(http.TimeFormat)
	if got := parseRetryAfter(future); got <= 0 || got > 31*time.Second {
		t.Fatalf("parseRetryAfter date = %s, want positive delay near 30s", got)
	}

	if got := parseRetryAfter("not-a-date"); got != 0 {
		t.Fatalf("parseRetryAfter invalid = %s, want 0", got)
	}
}
