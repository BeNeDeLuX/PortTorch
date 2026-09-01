package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"porttorch/scanner/internal/config"
	"porttorch/scanner/internal/pipeline"
)

// TestSubmitTLSCertificateNilSANs is a regression test: cert.SANs comes
// from x509.Certificate.DNSNames, which is nil (not an empty slice) for a
// certificate with no SANs. A nil slice marshals to JSON `null`, which the
// webserver's sanList schema (z.array(z.string()).optional()) rejected
// with a 400 - seen in production against real certificates that predate
// SANs being standard practice. SubmitTLSCertificate must send `[]`
// instead.
func TestSubmitTLSCertificateNilSANs(t *testing.T) {
	var body map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decoding request body: %v", err)
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()

	cfg := &config.Config{WebserverURL: server.URL, APIKey: "test"}
	c, err := New(cfg)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	cert := pipeline.TLSCertificate{
		Port:      443,
		SubjectCN: "example.invalid",
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(24 * time.Hour),
		SANs:      nil,
	}
	if err := c.SubmitTLSCertificate(t.Context(), "job-1", "127.0.0.1", cert); err != nil {
		t.Fatalf("SubmitTLSCertificate failed: %v", err)
	}

	sanList, ok := body["sanList"]
	if !ok {
		t.Fatalf("sanList missing from submitted body: %v", body)
	}
	if sanList == nil {
		t.Errorf("sanList serialized as null, want an empty array")
	}
	if arr, ok := sanList.([]any); !ok || len(arr) != 0 {
		t.Errorf("sanList = %#v, want an empty array", sanList)
	}
}

func testClient(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	c, err := New(&config.Config{WebserverURL: server.URL, APIKey: "test-key"})
	if err != nil {
		t.Fatalf("building test client: %v", err)
	}
	return c
}

// The scanner has no way to push its retry-queue backlog size to the
// webserver directly (all communication is scanner-initiated, and there's
// no dedicated endpoint for this) - it piggybacks on the same
// X-Scanner-Submit-Queue-Pending header sent on every request, same as
// X-Scanner-Version already does. Confirms SetSubmitQueuePending actually
// reaches the wire, not just that it's plumbed through unused.
func TestSetSubmitQueuePendingReflectedInHeader(t *testing.T) {
	var gotHeader string
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get("X-Scanner-Submit-Queue-Pending")
		w.WriteHeader(http.StatusNoContent)
	})

	c.SetSubmitQueuePending(7)
	if err := c.CompleteScanJob(context.Background(), "job-1", "completed"); err != nil {
		t.Fatalf("CompleteScanJob: %v", err)
	}
	if gotHeader != "7" {
		t.Errorf("X-Scanner-Submit-Queue-Pending = %q, want %q", gotHeader, "7")
	}
}

// A Client that's never had SetSubmitQueuePending called (the common case
// - most scans never fail a submission at all) should report 0, not an
// empty/missing header - the webserver's apiKeyAuth.ts needs a value it
// can parse on every request, not just once a backlog has ever existed.
func TestSubmitQueuePendingDefaultsToZero(t *testing.T) {
	var gotHeader string
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get("X-Scanner-Submit-Queue-Pending")
		w.WriteHeader(http.StatusNoContent)
	})

	if err := c.CompleteScanJob(context.Background(), "job-1", "completed"); err != nil {
		t.Fatalf("CompleteScanJob: %v", err)
	}
	if gotHeader != "0" {
		t.Errorf("X-Scanner-Submit-Queue-Pending = %q, want %q", gotHeader, "0")
	}
}

// The X-Scanner-Scan-Slots header is a contract with the webserver's
// parseScanSlotsHeader: "running/max", and *absent* when this process has
// no scan slots at all. Absence is load-bearing - it's how the webserver
// distinguishes "unknown" from a reported 0, and a one-shot "scan"/"menu"
// run must not overwrite a serve process's reported capacity.
func TestScanSlotsHeader(t *testing.T) {
	var got []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.Header.Get("X-Scanner-Scan-Slots"))
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	c, err := New(&config.Config{WebserverURL: server.URL, APIKey: "test"})
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// Nothing has set any slots yet - the one-shot modes never do.
	if _, err := c.PollNextScanRequest(context.Background()); err != nil {
		t.Fatalf("PollNextScanRequest: %v", err)
	}
	if got[0] != "" {
		t.Errorf("expected no header before slots are known, got %q", got[0])
	}

	c.SetScanSlots(0, 3)
	if _, err := c.PollNextScanRequest(context.Background()); err != nil {
		t.Fatalf("PollNextScanRequest: %v", err)
	}
	if got[1] != "0/3" {
		t.Errorf("expected an idle scanner to report 0/3, got %q", got[1])
	}

	c.SetScanSlots(2, 3)
	if _, err := c.PollNextScanRequest(context.Background()); err != nil {
		t.Fatalf("PollNextScanRequest: %v", err)
	}
	if got[2] != "2/3" {
		t.Errorf("expected 2/3, got %q", got[2])
	}
}
