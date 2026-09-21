package pipeline

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

// RDP does not start with TLS, which is why a plain handshake against
// 3389 gets nothing: the connection opens with an X.224 Connection
// Request in which client and server agree on a security layer, and only
// if TLS is selected does a TLS handshake follow on the same socket.
//
// That exchange is 19 bytes out and 19 back, so speaking it here is
// cheaper than the alternatives and keeps the certificate probe on the
// standard library, as the rest of tlscert.go already is.
//
// Worth extracting: an RDP certificate is usually self-signed, carries
// the machine's real hostname in its CN, and has an expiry nobody is
// watching - three things this platform reports for every other TLS port.
const (
	// MS-RDPBCGR 2.2.1.1.1: the requestedProtocols bit field.
	rdpProtocolSSL    = 0x00000001
	rdpProtocolHybrid = 0x00000002 // TLS first, then CredSSP - still a TLS handshake.

	rdpNegTypeResponse = 0x02
	rdpNegTypeFailure  = 0x03

	x224ConnectionConfirm = 0xD0
)

// rdpNegotiationFailure names the codes worth telling apart. The rest are
// reported by number - an unexpected one is rare enough that a lookup
// table would be more maintenance than it saves.
var rdpNegFailureReasons = map[uint32]string{
	0x00000001: "server requires NLA/CredSSP and refused a plain TLS request",
	0x00000002: "server requires an SSL certificate it does not have",
	0x00000003: "server is configured for RDP security only, without TLS",
	0x00000005: "server requires NLA and the client did not offer it",
	0x00000006: "server refused the requested protocol",
}

// buildRDPNegotiationRequest assembles the TPKT + X.224 Connection
// Request carrying an RDP_NEG_REQ.
//
// Both TLS and CredSSP are requested, not TLS alone: CredSSP still runs
// its TLS handshake first, so the certificate is readable either way, and
// asking for both is accepted by servers that would refuse plain TLS.
func buildRDPNegotiationRequest() []byte {
	const (
		tpktHeaderLen = 4
		x224CRLen     = 7
		negReqLen     = 8
		total         = tpktHeaderLen + x224CRLen + negReqLen
	)
	buf := make([]byte, 0, total)

	// TPKT header: version 3, reserved, total length big-endian.
	buf = append(buf, 0x03, 0x00)
	buf = binary.BigEndian.AppendUint16(buf, uint16(total))

	// X.224 Connection Request. The length indicator counts everything
	// after itself, so the negotiation request is included.
	buf = append(buf, byte(x224CRLen+negReqLen-1))
	buf = append(buf, 0xE0)       // CR CDT
	buf = append(buf, 0x00, 0x00) // DST-REF
	buf = append(buf, 0x00, 0x00) // SRC-REF
	buf = append(buf, 0x00)       // class options

	// RDP_NEG_REQ: type, flags, length (little-endian), requestedProtocols.
	buf = append(buf, 0x01, 0x00)
	buf = binary.LittleEndian.AppendUint16(buf, negReqLen)
	buf = binary.LittleEndian.AppendUint32(buf, rdpProtocolSSL|rdpProtocolHybrid)
	return buf
}

// parseRDPNegotiationResponse reads the server's answer and reports
// whether TLS follows on this connection.
//
// A response without a negotiation structure is not an error in the
// protocol's terms - it means the server selected plain RDP security, so
// there is simply no certificate to read, which is a finding rather than
// a failure and is reported as such.
func parseRDPNegotiationResponse(r io.Reader) (tlsFollows bool, reason string, err error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(r, header); err != nil {
		return false, "", fmt.Errorf("reading TPKT header: %w", err)
	}
	if header[0] != 0x03 {
		return false, "", fmt.Errorf("not a TPKT response (first byte 0x%02x)", header[0])
	}
	total := binary.BigEndian.Uint16(header[2:4])
	if total < 7 || total > 512 {
		return false, "", fmt.Errorf("implausible TPKT length %d", total)
	}

	body := make([]byte, int(total)-4)
	if _, err := io.ReadFull(r, body); err != nil {
		return false, "", fmt.Errorf("reading X.224 response: %w", err)
	}
	// body[0] is the length indicator, body[1] the X.224 type.
	if len(body) < 2 || body[1] != x224ConnectionConfirm {
		return false, "", fmt.Errorf("expected an X.224 Connection Confirm, got type 0x%02x", body[1])
	}

	// The negotiation structure, when present, follows the 7-byte X.224
	// Connection Confirm. Its absence is the "plain RDP security" case.
	const x224CCLen = 7
	if len(body) < x224CCLen+8 {
		return false, "server selected legacy RDP security, which has no certificate", nil
	}
	neg := body[x224CCLen:]
	switch neg[0] {
	case rdpNegTypeResponse:
		selected := binary.LittleEndian.Uint32(neg[4:8])
		if selected&(rdpProtocolSSL|rdpProtocolHybrid) != 0 {
			return true, "", nil
		}
		return false, "server selected legacy RDP security, which has no certificate", nil
	case rdpNegTypeFailure:
		code := binary.LittleEndian.Uint32(neg[4:8])
		if known, ok := rdpNegFailureReasons[code]; ok {
			return false, known, nil
		}
		return false, fmt.Sprintf("server refused TLS (failure code 0x%08x)", code), nil
	default:
		return false, "", fmt.Errorf("unexpected RDP negotiation type 0x%02x", neg[0])
	}
}

// RunRDPCertProbe reads the certificate an RDP service presents, by
// performing the X.224 negotiation above and then handing the same
// connection to the shared TLS-certificate code.
//
// The target is always the exact scanned ip; sni follows the same rule as
// RunTLSCertProbe, so a host with a configured probe hostname gets it
// here too.
func RunRDPCertProbe(ctx context.Context, cfg Config, ip string, port int, sni string) (*TLSCertificate, error) {
	address := net.JoinHostPort(ip, strconv.Itoa(port))
	dialer := &net.Dialer{Timeout: cfg.tlsCertTimeout()}
	rawConn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("tcp dial %s: %w", address, err)
	}
	// Closed by certificateFromConn on the success path; closed here when
	// the negotiation never gets that far.
	negotiated := false
	defer func() {
		if !negotiated {
			_ = rawConn.Close()
		}
	}()

	// A zero timeout means "no limit" everywhere else - RunTLSCertProbe
	// hands the same value to net.Dialer, which treats 0 that way - so it
	// must not become a deadline of "now", which is what Add(0) produces.
	// Caught by the end-to-end test against a real negotiating server,
	// where every handshake failed with i/o timeout before the server had
	// said anything at all.
	setDeadline := func() {
		if deadline, ok := ctx.Deadline(); ok {
			_ = rawConn.SetDeadline(deadline)
			return
		}
		if timeout := cfg.tlsCertTimeout(); timeout > 0 {
			_ = rawConn.SetDeadline(time.Now().Add(timeout))
		}
	}
	setDeadline()

	if _, err := rawConn.Write(buildRDPNegotiationRequest()); err != nil {
		return nil, fmt.Errorf("sending RDP negotiation request to %s: %w", address, err)
	}
	tlsFollows, reason, err := parseRDPNegotiationResponse(rawConn)
	if err != nil {
		return nil, fmt.Errorf("RDP negotiation with %s: %w", address, err)
	}
	if !tlsFollows {
		return nil, fmt.Errorf("no certificate available from %s: %s", address, reason)
	}

	// Refreshed so the handshake gets the full budget rather than
	// whatever the negotiation left of it.
	setDeadline()
	negotiated = true
	return certificateFromConn(ctx, rawConn, address, port, sni)
}
