package pipeline

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"
)

func generateSelfSignedCertPEM(t *testing.T, commonName string) tls.Certificate {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating key for %q: %v", commonName, err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating certificate for %q: %v", commonName, err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("loading generated keypair for %q: %v", commonName, err)
	}
	return cert
}

// TestRunTLSCertProbeUsesSNI is a real, non-mocked regression test for the
// exact bug reported: RunTLSCertProbe used to hardcode ServerName to the
// bare ip, which Go's crypto/tls treats as "send no SNI at all" (an IP
// literal isn't a valid server name per RFC 6066) - meaning it could never
// reach the right virtual host on a server that selects its certificate
// (or rejects the handshake entirely, as real nginx does with
// ssl_reject_handshake/a strict default_server) based on SNI.
//
// This spins up a real local TLS listener - a miniature version of
// exactly that SNI-routing behavior - presenting a different self-signed
// certificate depending on the ClientHello's requested ServerName, then
// calls RunTLSCertProbe with different sni values against the same
// ip:port and asserts the certificate that comes back actually differs
// accordingly. This proves the sni parameter reaches the wire and
// influences which certificate the server selects, not just that it's
// plumbed through as an unused parameter.
func TestRunTLSCertProbeUsesSNI(t *testing.T) {
	certA := generateSelfSignedCertPEM(t, "host-a.test")
	certB := generateSelfSignedCertPEM(t, "host-b.test")

	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if hello.ServerName == "host-b.test" {
				return &certB, nil
			}
			return &certA, nil
		},
	})
	if err != nil {
		t.Fatalf("starting local TLS listener: %v", err)
	}
	defer listener.Close()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			// The handshake (and so GetCertificate) only completes once
			// something actually drives it - explicitly triggering it
			// server-side (rather than just closing the raw connection)
			// mirrors what a real server does and lets the client's own
			// HandshakeContext below actually succeed.
			go func(c net.Conn) {
				defer c.Close()
				if tlsConn, ok := c.(*tls.Conn); ok {
					_ = tlsConn.Handshake()
				}
			}(conn)
		}
	}()

	addr := listener.Addr().(*net.TCPAddr)
	cfg := Config{TLSCertTimeoutSeconds: 5}.withDefaults()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	certForA, err := RunTLSCertProbe(ctx, cfg, "127.0.0.1", addr.Port, "host-a.test")
	if err != nil {
		t.Fatalf("probe with sni=host-a.test failed: %v", err)
	}
	if certForA.SubjectCN != "host-a.test" {
		t.Errorf("sni=host-a.test got certificate for %q, want host-a.test", certForA.SubjectCN)
	}

	certForB, err := RunTLSCertProbe(ctx, cfg, "127.0.0.1", addr.Port, "host-b.test")
	if err != nil {
		t.Fatalf("probe with sni=host-b.test failed: %v", err)
	}
	if certForB.SubjectCN != "host-b.test" {
		t.Errorf("sni=host-b.test got certificate for %q, want host-b.test", certForB.SubjectCN)
	}
}
