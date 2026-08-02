package pipeline

import (
	"context"
	"net"
	"testing"
	"time"
)

// TestTLSCertProbeAgainstRealTarget is a real integration test: it
// connects via TLS to the locally running PortTorch webserver
// (127.0.0.1:443, self-signed certificate) and checks that the certificate
// data read back is plausible. Skipped if the port is unreachable (e.g.
// the Docker stack isn't running).
func TestTLSCertProbeAgainstRealTarget(t *testing.T) {
	conn, err := net.DialTimeout("tcp", "127.0.0.1:443", 2*time.Second)
	if err != nil {
		t.Skip("localhost:443 unreachable (Docker stack not started?), skipping integration test")
	}
	conn.Close()

	cfg := Config{TLSCertTimeoutSeconds: 8}.withDefaults()

	cert, err := RunTLSCertProbe(context.Background(), cfg, "127.0.0.1", 443, "127.0.0.1")
	if err != nil {
		t.Fatalf("RunTLSCertProbe failed: %v", err)
	}

	if cert.FingerprintSHA256 == "" || len(cert.FingerprintSHA256) != 64 {
		t.Errorf("expected a 64-char hex sha256 fingerprint, got %q", cert.FingerprintSHA256)
	}
	if !cert.SelfSigned {
		t.Errorf("expected the PortTorch webserver's dev certificate to be self-signed")
	}
	if cert.NotAfter.Before(time.Now()) {
		t.Errorf("expected certificate to not be expired, NotAfter=%v", cert.NotAfter)
	}
	if cert.SubjectCN == "" {
		t.Errorf("expected a non-empty subject CN")
	}
}

func TestIsTLSPort(t *testing.T) {
	cases := []struct {
		name string
		port PortResult
		want bool
	}{
		{"https by name", PortResult{Port: 8443, ServiceName: "https"}, true},
		{"ssl wrapped", PortResult{Port: 993, ServiceName: "ssl/imap"}, true},
		{"imaps by name", PortResult{Port: 993, ServiceName: "imaps"}, true},
		{"unknown on 443", PortResult{Port: 443, ServiceName: "unknown"}, true},
		{"plain ssh", PortResult{Port: 22, ServiceName: "ssh"}, false},
		{"plain http", PortResult{Port: 80, ServiceName: "http"}, false},
		// Regression: nmap's generic "http" name on port 443 (see
		// TestIsHTTPPort) must still get a TLS cert probe.
		{"named http on 443", PortResult{Port: 443, ServiceName: "http"}, true},
		{"ssl tunnel on a non-hinted port", PortResult{Port: 8080, ServiceName: "domain", Tunnel: "ssl"}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isTLSPort(c.port); got != c.want {
				t.Errorf("isTLSPort(%+v) = %v, want %v", c.port, got, c.want)
			}
		})
	}
}
