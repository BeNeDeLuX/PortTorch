package client

import (
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
