package pipeline

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The exact bytes MS-RDPBCGR 2.2.1.1 specifies. Pinned literally rather
// than rebuilt from the same constants the code uses, which would only
// prove the function agrees with itself - a wrong length byte here is
// invisible until a real server hangs up, which is the failure this test
// exists to catch early.
func TestBuildRDPNegotiationRequestBytes(t *testing.T) {
	want := []byte{
		0x03, 0x00, 0x00, 0x13, // TPKT: version 3, reserved, length 19
		0x0E,       // X.224 length indicator: 14 bytes follow
		0xE0,       // Connection Request
		0x00, 0x00, // DST-REF
		0x00, 0x00, // SRC-REF
		0x00,       // class options
		0x01, 0x00, // RDP_NEG_REQ, no flags
		0x08, 0x00, // length 8, little-endian
		0x03, 0x00, 0x00, 0x00, // PROTOCOL_SSL | PROTOCOL_HYBRID
	}
	got := buildRDPNegotiationRequest()
	if !bytes.Equal(got, want) {
		t.Fatalf("negotiation request mismatch\n got %x\nwant %x", got, want)
	}
	if len(got) != 19 {
		t.Fatalf("length %d, want 19 - the TPKT header states 19 and a server reads exactly that many", len(got))
	}
}

// Builds the server side of the exchange: a Connection Confirm carrying
// the given negotiation structure, or none at all when negType is 0.
func connectionConfirm(negType byte, value uint32) []byte {
	body := []byte{0x0E, 0xD0, 0x00, 0x00, 0x12, 0x34, 0x00}
	if negType != 0 {
		neg := []byte{negType, 0x00}
		neg = binary.LittleEndian.AppendUint16(neg, 8)
		neg = binary.LittleEndian.AppendUint32(neg, value)
		body = append(body, neg...)
	}
	out := []byte{0x03, 0x00}
	out = binary.BigEndian.AppendUint16(out, uint16(len(body)+4))
	return append(out, body...)
}

func TestParseRDPNegotiationResponse(t *testing.T) {
	cases := []struct {
		name       string
		payload    []byte
		wantTLS    bool
		wantReason string
		wantErr    bool
	}{
		{name: "server selects TLS", payload: connectionConfirm(rdpNegTypeResponse, rdpProtocolSSL), wantTLS: true},
		{name: "server selects CredSSP, which still does TLS first", payload: connectionConfirm(rdpNegTypeResponse, rdpProtocolHybrid), wantTLS: true},
		{
			// Not an error: the server answered correctly, there is simply
			// no certificate to read, and saying so is the useful outcome.
			name:       "server selects legacy RDP security",
			payload:    connectionConfirm(rdpNegTypeResponse, 0),
			wantReason: "legacy RDP security",
		},
		{
			name:       "no negotiation structure at all",
			payload:    connectionConfirm(0, 0),
			wantReason: "legacy RDP security",
		},
		{
			name:       "known failure code is named",
			payload:    connectionConfirm(rdpNegTypeFailure, 0x00000001),
			wantReason: "NLA/CredSSP",
		},
		{
			name:       "unknown failure code still reports the number",
			payload:    connectionConfirm(rdpNegTypeFailure, 0x000000ff),
			wantReason: "0x000000ff",
		},
		{name: "not TPKT at all", payload: []byte{0x16, 0x03, 0x01, 0x00}, wantErr: true},
		{name: "truncated", payload: []byte{0x03, 0x00}, wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tlsFollows, reason, err := parseRDPNegotiationResponse(bytes.NewReader(tc.payload))
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got tlsFollows=%v reason=%q", tlsFollows, reason)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tlsFollows != tc.wantTLS {
				t.Fatalf("tlsFollows = %v, want %v", tlsFollows, tc.wantTLS)
			}
			if tc.wantReason != "" && !strings.Contains(reason, tc.wantReason) {
				t.Fatalf("reason = %q, want it to mention %q", reason, tc.wantReason)
			}
		})
	}
}

// The end-to-end shape, against a server that actually speaks the
// exchange: X.224 first, TLS second, on one socket. This is what proves
// the byte layout is right - a plain TLS handshake against the same
// listener would fail, which is precisely why RDP needed its own path.
func TestRunRDPCertProbeAgainstRealNegotiatingServer(t *testing.T) {
	cert := generateSelfSignedCertPEM(t, "rdp-host.internal")

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		req := make([]byte, 19)
		if _, err := io.ReadFull(conn, req); err != nil {
			return
		}
		if _, err := conn.Write(connectionConfirm(rdpNegTypeResponse, rdpProtocolSSL)); err != nil {
			return
		}
		// Only now does TLS begin, on the same connection.
		tlsConn := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}})
		_ = tlsConn.Handshake()
		_ = tlsConn.Close()
	}()

	addr := listener.Addr().(*net.TCPAddr)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	got, err := RunRDPCertProbe(ctx, Config{}, "127.0.0.1", addr.Port, "rdp-host.internal")
	if err != nil {
		t.Fatalf("RunRDPCertProbe: %v", err)
	}
	if got.SubjectCN != "rdp-host.internal" {
		t.Fatalf("SubjectCN = %q, want the certificate the server presented", got.SubjectCN)
	}
	if !got.SelfSigned {
		t.Fatal("expected the certificate to be reported as self-signed, which is the usual case on RDP")
	}
	if got.Port != addr.Port {
		t.Fatalf("Port = %d, want %d", got.Port, addr.Port)
	}
}

// A server that answers the negotiation with "legacy RDP security" has no
// certificate, and that has to read as a clear explanation rather than a
// handshake error from somewhere deeper.
func TestRunRDPCertProbeReportsLegacySecurityClearly(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		req := make([]byte, 19)
		if _, err := io.ReadFull(conn, req); err != nil {
			return
		}
		_, _ = conn.Write(connectionConfirm(rdpNegTypeFailure, 0x00000003))
	}()

	addr := listener.Addr().(*net.TCPAddr)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err = RunRDPCertProbe(ctx, Config{}, "127.0.0.1", addr.Port, "127.0.0.1")
	if err == nil {
		t.Fatal("expected an error when the server offers no TLS")
	}
	if !strings.Contains(err.Error(), "RDP security only") {
		t.Fatalf("error should explain why there is no certificate, got: %v", err)
	}
	if !strings.Contains(err.Error(), net.JoinHostPort("127.0.0.1", strconv.Itoa(addr.Port))) {
		t.Fatalf("error should name the target, got: %v", err)
	}
}
