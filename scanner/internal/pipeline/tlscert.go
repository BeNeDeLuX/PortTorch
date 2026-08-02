package pipeline

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// tlsVersionName maps a negotiated tls.VersionTLSxx constant to its
// human-readable name, since crypto/tls doesn't expose one itself.
func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%04x", version)
	}
}

// publicKeyBits returns the key size in bits for the public key types
// crypto/x509 can produce (RSA/ECDSA/Ed25519); 0 for anything else.
func publicKeyBits(pub any) int {
	switch key := pub.(type) {
	case *rsa.PublicKey:
		return key.N.BitLen()
	case *ecdsa.PublicKey:
		return key.Curve.Params().BitSize
	case ed25519.PublicKey:
		return len(key) * 8
	default:
		return 0
	}
}

// tlsServiceNameHints is used to detect ports that carry TLS but aren't
// classified as HTTP(S) (isHTTPPort only covers the HTTP(S) cases).
var tlsServiceNameHints = []string{"ssl", "tls", "imaps", "pop3s", "smtps", "ldaps", "ftps"}

// isTLSPort decides whether a port is worth a real TLS handshake attempt
// for certificate extraction - deliberately covers more than just the
// HTTP(S) ports from isHTTPPort.
func isTLSPort(p PortResult) bool {
	if strings.ToLower(p.Tunnel) == "ssl" {
		return true
	}
	if _, useTLS := isHTTPPort(p); useTLS {
		return true
	}
	name := strings.ToLower(p.ServiceName)
	for _, hint := range tlsServiceNameHints {
		if strings.Contains(name, hint) {
			return true
		}
	}
	return false
}

// RunTLSCertProbe performs a real TLS handshake against ip:port and reads
// the certificate presented by the server. Uses only the Go standard
// library - no external tool needed. InsecureSkipVerify is deliberately
// set here: we want to read and evaluate the certificate (even if it's
// expired/self-signed/for a different name), not classify the connection
// as trustworthy.
//
// sni is the value sent as the TLS SNI extension - normally just ip
// (Go's crypto/tls treats an IP-literal ServerName as "don't send SNI at
// all", per RFC 6066, so this reproduces today's exact behavior for hosts
// with no override), but can be a manually-configured hostname (hosts.
// probe_hostname) for a target that rejects an unmatched/absent SNI - e.g.
// nginx-style virtual hosting that sends a fatal "internal_error" alert
// when the ClientHello's server name doesn't match any configured
// server_name. Confirmed via manual testing against a real such server:
// no SNI (today's default) and a wrong SNI both fail identically: only
// the correct hostname lets the handshake complete. The TCP dial itself
// always targets the exact scanned ip regardless of sni - only the SNI
// value changes, so this never risks probing the wrong device.
func RunTLSCertProbe(ctx context.Context, cfg Config, ip string, port int, sni string) (*TLSCertificate, error) {
	dialer := &net.Dialer{Timeout: cfg.tlsCertTimeout()}
	// net.JoinHostPort brackets an IPv6 literal ("[fe80::1]:443") - a plain
	// fmt.Sprintf("%s:%d", ip, port) is ambiguous/invalid for IPv6 and
	// DialContext would fail to parse it.
	address := net.JoinHostPort(ip, strconv.Itoa(port))

	rawConn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("tcp dial %s: %w", address, err)
	}
	defer rawConn.Close()

	tlsConn := tls.Client(rawConn, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // Certificate is deliberately read, not verified.
		ServerName:         sni,
		MinVersion:         tls.VersionTLS10,
	})
	defer tlsConn.Close()

	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("tls handshake with %s: %w", address, err)
	}

	state := tlsConn.ConnectionState()
	certs := state.PeerCertificates
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificate presented by %s", address)
	}
	cert := certs[0]
	fingerprint := sha256.Sum256(cert.Raw)

	return &TLSCertificate{
		Port:               port,
		SubjectCN:          cert.Subject.CommonName,
		IssuerCN:           cert.Issuer.CommonName,
		SANs:               cert.DNSNames,
		NotBefore:          cert.NotBefore,
		NotAfter:           cert.NotAfter,
		FingerprintSHA256:  hex.EncodeToString(fingerprint[:]),
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		SelfSigned:         bytes.Equal(cert.RawIssuer, cert.RawSubject),
		TLSVersion:         tlsVersionName(state.Version),
		CipherSuite:        tls.CipherSuiteName(state.CipherSuite),
		KeyAlgorithm:       cert.PublicKeyAlgorithm.String(),
		KeyBits:            publicKeyBits(cert.PublicKey),
	}, nil
}
