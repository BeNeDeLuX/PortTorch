package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"porttorch/scanner/internal/config"
	"porttorch/scanner/internal/pipeline"
	"porttorch/scanner/internal/progress"
	"porttorch/scanner/internal/version"
)

// setAuthHeaders sets the API key and this scanner's version on every
// request - the webserver records the version alongside last_seen_at/
// last_seen_ip (see apiKeyAuth.ts) so the dashboard's Scanner Agents page
// can show which version each agent is actually running.
func setAuthHeaders(req *http.Request, apiKey string) {
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("X-Scanner-Version", version.Version)
}

// Client talks to the webserver's authenticated ingest API.
type Client struct {
	baseURL string
	apiKey  string
	http    *http.Client
}

// New builds a Client based on the scanner configuration. If
// ServerCACertPath is set, only that certificate is trusted; otherwise
// InsecureSkipVerify applies (intended only for quick internal tests - the
// self-signed server certificate should normally be configured).
func New(cfg *config.Config) (*Client, error) {
	tlsConfig := &tls.Config{}

	if cfg.ServerCACertPath != "" {
		pemBytes, err := os.ReadFile(cfg.ServerCACertPath)
		if err != nil {
			return nil, fmt.Errorf("reading serverCaCertPath: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemBytes) {
			return nil, fmt.Errorf("no valid certificate found in %s", cfg.ServerCACertPath)
		}
		tlsConfig.RootCAs = pool
	} else if cfg.InsecureSkipVerify {
		tlsConfig.InsecureSkipVerify = true
	}

	return &Client{
		baseURL: strings.TrimSuffix(cfg.WebserverURL, "/"),
		apiKey:  cfg.APIKey,
		http: &http.Client{
			Timeout:   60 * time.Second,
			Transport: &http.Transport{TLSClientConfig: tlsConfig},
		},
	}, nil
}

type scanJobResponse struct {
	ID string `json:"id"`
}

// CreateScanJob registers a new scan run with the webserver and returns
// its job ID. cancellable should only be true from a long-running "serve"
// process (its own REST-triggered ad-hoc scans and queue-triggered ones) -
// only "serve" runs the concurrent watcher (see StartCancelWatcher in
// internal/api) that can notice a cancellation request while the scan is
// in progress. A one-shot "scan"/"menu" process has nothing polling
// during its single blocking scan and would never see it.
func (c *Client) CreateScanJob(ctx context.Context, targetSpec, portSpec string, cancellable bool) (string, error) {
	body := map[string]any{"targetSpec": targetSpec, "portSpec": portSpec, "cancellable": cancellable}
	var resp scanJobResponse
	if err := c.doJSON(ctx, http.MethodPost, "/api/ingest/scan-jobs", body, &resp); err != nil {
		return "", err
	}
	return resp.ID, nil
}

// CompleteScanJob marks a scan job as completed, failed, or cancelled.
func (c *Client) CompleteScanJob(ctx context.Context, jobID, status string) error {
	body := map[string]string{"status": status}
	return c.doJSON(ctx, http.MethodPatch, "/api/ingest/scan-jobs/"+jobID, body, nil)
}

// CheckCancelRequested asks whether an operator has requested that this
// specific job stop (only ever true for a job created with
// cancellable=true - see CreateScanJob). Polled by StartCancelWatcher
// while a cancellable scan is in progress, separately from the main
// scan-requests poll loop, since that loop is busy blocking on the same
// scan.
func (c *Client) CheckCancelRequested(ctx context.Context, jobID string) (bool, error) {
	var resp struct {
		CancelRequested bool `json:"cancelRequested"`
	}
	if err := c.doJSON(ctx, http.MethodGet, "/api/ingest/scan-jobs/"+jobID+"/cancel-requested", nil, &resp); err != nil {
		return false, err
	}
	return resp.CancelRequested, nil
}

// PushScanProgress sends the current stage/detail/recent-log-lines
// snapshot for a running scan - see progress.Tracker, which calls this
// periodically while a scan is in progress. Satisfies progress.Pusher.
func (c *Client) PushScanProgress(ctx context.Context, jobID, stage, detail string, logs []progress.LogLine) error {
	body := map[string]any{"stage": stage, "stageDetail": detail, "logs": logs}
	return c.doJSON(ctx, http.MethodPatch, "/api/ingest/scan-jobs/"+jobID+"/progress", body, nil)
}

type ingestSSHHostKey struct {
	KeyType           string `json:"keyType"`
	Bits              int    `json:"bits,omitempty"`
	FingerprintMD5    string `json:"fingerprintMd5,omitempty"`
	FingerprintSHA256 string `json:"fingerprintSha256"`
}

type ingestNSEScript struct {
	ID     string `json:"id"`
	Output string `json:"output"`
}

type ingestPort struct {
	Port           int                `json:"port"`
	Protocol       string             `json:"protocol"`
	State          string             `json:"state"`
	ServiceName    string             `json:"serviceName,omitempty"`
	ServiceProduct string             `json:"serviceProduct,omitempty"`
	ServiceVersion string             `json:"serviceVersion,omitempty"`
	ExtraInfo      string             `json:"extraInfo,omitempty"`
	OSType         string             `json:"osType,omitempty"`
	CPEs           []string           `json:"cpes,omitempty"`
	Banner         string             `json:"banner,omitempty"`
	SSHHostKeys    []ingestSSHHostKey `json:"sshHostKeys,omitempty"`
	FTPAnonListing string             `json:"ftpAnonListing,omitempty"`
	SMBShares      string             `json:"smbShares,omitempty"`
	ExtraScripts   []ingestNSEScript  `json:"extraScripts,omitempty"`
}

type ingestHost struct {
	IP         string       `json:"ip"`
	Hostname   string       `json:"hostname,omitempty"`
	OSName     string       `json:"osName,omitempty"`
	OSFamily   string       `json:"osFamily,omitempty"`
	OSVendor   string       `json:"osVendor,omitempty"`
	DeviceType string       `json:"deviceType,omitempty"`
	OSAccuracy int          `json:"osAccuracy,omitempty"`
	MACAddress string       `json:"macAddress,omitempty"`
	MACVendor  string       `json:"macVendor,omitempty"`
	Ports      []ingestPort `json:"ports"`
}

// SubmitHosts submits the host/port results of a scan job.
func (c *Client) SubmitHosts(ctx context.Context, jobID string, hosts []pipeline.HostResult) error {
	if len(hosts) == 0 {
		return nil
	}

	payloadHosts := make([]ingestHost, 0, len(hosts))
	for _, h := range hosts {
		ports := make([]ingestPort, 0, len(h.Ports))
		for _, p := range h.Ports {
			var sshHostKeys []ingestSSHHostKey
			for _, k := range p.SSHHostKeys {
				sshHostKeys = append(sshHostKeys, ingestSSHHostKey{
					KeyType:           k.KeyType,
					Bits:              k.Bits,
					FingerprintMD5:    k.FingerprintMD5,
					FingerprintSHA256: k.FingerprintSHA256,
				})
			}
			var extraScripts []ingestNSEScript
			for _, s := range p.ExtraScripts {
				extraScripts = append(extraScripts, ingestNSEScript{ID: s.ID, Output: s.Output})
			}
			ports = append(ports, ingestPort{
				Port:           p.Port,
				Protocol:       p.Protocol,
				State:          p.State,
				ServiceName:    p.ServiceName,
				ServiceProduct: p.ServiceProduct,
				ServiceVersion: p.ServiceVersion,
				ExtraInfo:      p.ExtraInfo,
				OSType:         p.OSType,
				CPEs:           p.CPEs,
				Banner:         p.Banner,
				SSHHostKeys:    sshHostKeys,
				FTPAnonListing: p.FTPAnonListing,
				SMBShares:      p.SMBShares,
				ExtraScripts:   extraScripts,
			})
		}
		payloadHosts = append(payloadHosts, ingestHost{
			IP:         h.IP,
			Hostname:   h.Hostname,
			OSName:     h.OSName,
			OSFamily:   h.OSFamily,
			OSVendor:   h.OSVendor,
			DeviceType: h.DeviceType,
			OSAccuracy: h.OSAccuracy,
			MACAddress: h.MACAddress,
			MACVendor:  h.MACVendor,
			Ports:      ports,
		})
	}

	body := map[string]any{
		"scanJobId": jobID,
		"hosts":     payloadHosts,
	}
	return c.doJSON(ctx, http.MethodPost, "/api/ingest/hosts", body, nil)
}

// SubmitHostResult submits everything captured for a single host (port
// observations, screenshots, RDP screenshots, TLS certificates) in one
// call - shared by all three entry points (scan/menu/serve) so a scan can
// submit each host as soon as its own pipeline finishes rather than
// batching the whole target range into one call at the very end (see
// pipeline.RunScan's HostCompleteFunc). A failure submitting the host/port
// data itself is returned as an error, since that's the primary data with
// no other path to correct it; a failure submitting one of its
// screenshots/RDP screenshots/TLS certificates only reaches
// onSubItemError (kind is "screenshot", "rdp_screenshot", or
// "tls_certificate") - those are a supplement to the host/port data
// that's already been persisted by that point, not a reason to treat the
// whole host as failed.
func (c *Client) SubmitHostResult(ctx context.Context, jobID string, host pipeline.HostResult, onSubItemError func(kind string, port int, err error)) error {
	if err := c.SubmitHosts(ctx, jobID, []pipeline.HostResult{host}); err != nil {
		return err
	}
	hosts := []pipeline.HostResult{host}
	c.SubmitScreenshots(ctx, jobID, hosts, func(hostIP string, port int, err error) {
		onSubItemError("screenshot", port, err)
	})
	c.SubmitRDPScreenshots(ctx, jobID, hosts, func(hostIP string, port int, err error) {
		onSubItemError("rdp_screenshot", port, err)
	})
	c.SubmitTLSCertificates(ctx, jobID, hosts, func(hostIP string, port int, err error) {
		onSubItemError("tls_certificate", port, err)
	})
	return nil
}

// SubmitScreenshots submits all screenshots of a scan result. Failures on
// individual screenshots don't abort the submission (screenshots are a
// supplement to the already-persisted host/port results); instead, onError
// is called for each failed screenshot, if set.
func (c *Client) SubmitScreenshots(ctx context.Context, jobID string, hosts []pipeline.HostResult, onError func(hostIP string, port int, err error)) {
	for _, h := range hosts {
		for _, shot := range h.Screenshots {
			if err := c.SubmitScreenshot(ctx, jobID, h.IP, shot); err != nil && onError != nil {
				onError(h.IP, shot.Port, err)
			}
		}
	}
}

// SubmitScreenshot submits a single screenshot taken by gowitness via
// multipart/form-data to the ingest API. The image is read from
// shot.ImagePath; cleaning up the temporary file remains the caller's
// responsibility.
func (c *Client) SubmitScreenshot(ctx context.Context, jobID, hostIP string, shot pipeline.Screenshot) error {
	fields := map[string]string{
		"scanJobId": jobID,
		"hostIp":    hostIP,
		"port":      strconv.Itoa(shot.Port),
		"url":       shot.URL,
		"pageTitle": shot.PageTitle,
	}
	if shot.HTTPStatus > 0 {
		fields["httpStatus"] = strconv.Itoa(shot.HTTPStatus)
	}
	if shot.TLSProtocol != "" {
		fields["tlsProtocol"] = shot.TLSProtocol
	}
	if shot.TLSCipher != "" {
		fields["tlsCipher"] = shot.TLSCipher
	}
	if shot.TLSSubject != "" {
		fields["tlsSubject"] = shot.TLSSubject
	}
	if shot.TLSIssuer != "" {
		fields["tlsIssuer"] = shot.TLSIssuer
	}
	if shot.TLSValidFrom != "" {
		fields["tlsValidFrom"] = shot.TLSValidFrom
	}
	if shot.TLSValidTo != "" {
		fields["tlsValidTo"] = shot.TLSValidTo
	}
	if len(shot.Technologies) > 0 {
		fields["technologies"] = strings.Join(shot.Technologies, ",")
	}
	if len(shot.Headers) > 0 {
		if headersJSON, err := json.Marshal(shot.Headers); err == nil {
			fields["headers"] = string(headersJSON)
		}
	}
	if shot.OCRText != "" {
		fields["ocrText"] = shot.OCRText
	}
	return c.uploadImage(ctx, "/api/ingest/screenshots", shot.ImagePath, fields)
}

// SubmitRDPScreenshots submits all RDP screenshots of a scan result. As
// with SubmitScreenshots, individual failures don't abort the submission.
func (c *Client) SubmitRDPScreenshots(ctx context.Context, jobID string, hosts []pipeline.HostResult, onError func(hostIP string, port int, err error)) {
	for _, h := range hosts {
		for _, shot := range h.RDPScreenshots {
			if err := c.SubmitRDPScreenshot(ctx, jobID, h.IP, shot); err != nil && onError != nil {
				onError(h.IP, shot.Port, err)
			}
		}
	}
}

// SubmitRDPScreenshot submits a single RDP screenshot via
// multipart/form-data to the ingest API.
func (c *Client) SubmitRDPScreenshot(ctx context.Context, jobID, hostIP string, shot pipeline.RDPScreenshot) error {
	fields := map[string]string{
		"scanJobId": jobID,
		"hostIp":    hostIP,
		"port":      strconv.Itoa(shot.Port),
	}
	if shot.OCRText != "" {
		fields["ocrText"] = shot.OCRText
	}
	return c.uploadImage(ctx, "/api/ingest/rdp-screenshots", shot.ImagePath, fields)
}

// SubmitTLSCertificates submits all certificates read via TLS handshake
// for a scan result. Failures on individual certificates don't abort the
// submission.
func (c *Client) SubmitTLSCertificates(ctx context.Context, jobID string, hosts []pipeline.HostResult, onError func(hostIP string, port int, err error)) {
	for _, h := range hosts {
		for _, cert := range h.TLSCertificates {
			if err := c.SubmitTLSCertificate(ctx, jobID, h.IP, cert); err != nil && onError != nil {
				onError(h.IP, cert.Port, err)
			}
		}
	}
}

// SubmitTLSCertificate submits a single TLS certificate as JSON to the
// ingest API (no image upload needed).
func (c *Client) SubmitTLSCertificate(ctx context.Context, jobID, hostIP string, cert pipeline.TLSCertificate) error {
	// cert.SANs comes straight from x509.Certificate.DNSNames, which is a
	// nil (not empty) slice when the certificate has no SANs - json.Marshal
	// encodes that as `null`, which the webserver's sanList schema
	// (z.array(z.string()).optional()) rejects. A certificate with no SANs
	// is common (e.g. older/internal certs issued before SANs were
	// standard practice), so this isn't an edge case worth failing on.
	sanList := cert.SANs
	if sanList == nil {
		sanList = []string{}
	}
	body := map[string]any{
		"scanJobId":          jobID,
		"hostIp":             hostIP,
		"port":               cert.Port,
		"subjectCn":          cert.SubjectCN,
		"issuerCn":           cert.IssuerCN,
		"sanList":            sanList,
		"notBefore":          cert.NotBefore.UTC().Format(time.RFC3339),
		"notAfter":           cert.NotAfter.UTC().Format(time.RFC3339),
		"fingerprintSha256":  cert.FingerprintSHA256,
		"signatureAlgorithm": cert.SignatureAlgorithm,
		"selfSigned":         cert.SelfSigned,
		"tlsVersion":         cert.TLSVersion,
		"cipherSuite":        cert.CipherSuite,
		"keyAlgorithm":       cert.KeyAlgorithm,
		"keyBits":            cert.KeyBits,
	}
	return c.doJSON(ctx, http.MethodPost, "/api/ingest/tls-certificates", body, nil)
}

// uploadImage submits an image file together with form fields via
// multipart/form-data to path.
func (c *Client) uploadImage(ctx context.Context, path, imagePath string, fields map[string]string) error {
	f, err := os.Open(imagePath)
	if err != nil {
		return fmt.Errorf("opening image file: %w", err)
	}
	defer f.Close()

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	for key, value := range fields {
		if err := writer.WriteField(key, value); err != nil {
			return fmt.Errorf("writing multipart field %s: %w", key, err)
		}
	}

	part, err := writer.CreateFormFile("image", "screenshot.png")
	if err != nil {
		return fmt.Errorf("creating multipart file field: %w", err)
	}
	if _, err := io.Copy(part, f); err != nil {
		return fmt.Errorf("copying image into request: %w", err)
	}
	if err := writer.Close(); err != nil {
		return fmt.Errorf("closing multipart writer: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, &buf)
	if err != nil {
		return fmt.Errorf("building request: %w", err)
	}
	setAuthHeaders(req, c.apiKey)
	req.Header.Set("Content-Type", writer.FormDataContentType())

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("uploading image failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("uploading image to %s: unexpected status %d: %s", path, resp.StatusCode, string(respBody))
	}
	return nil
}

// ScanRequest is a scan job created by the webserver via the rescan button
// or a schedule, picked up via polling.
type ScanRequest struct {
	ID         string
	TargetSpec string
	PortSpec   string
}

// PollNextScanRequest asks the webserver for the next pending scan request
// for this scanner and atomically claims it. Returns (nil, nil) if nothing
// is currently pending.
func (c *Client) PollNextScanRequest(ctx context.Context) (*ScanRequest, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/api/ingest/scan-requests/next", nil)
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	setAuthHeaders(req, c.apiKey)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("polling scan requests failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent {
		return nil, nil
	}
	if resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("polling scan requests: unexpected status %d: %s", resp.StatusCode, string(respBody))
	}

	var out struct {
		ID         string `json:"id"`
		TargetSpec string `json:"targetSpec"`
		PortSpec   string `json:"portSpec"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decoding scan request: %w", err)
	}
	return &ScanRequest{ID: out.ID, TargetSpec: out.TargetSpec, PortSpec: out.PortSpec}, nil
}

// CompleteScanRequest reports back the result of a claimed scan request
// and links it to the scan job created for it.
func (c *Client) CompleteScanRequest(ctx context.Context, requestID, scanJobID, status string) error {
	body := map[string]string{"scanJobId": scanJobID, "status": status}
	return c.doJSON(ctx, http.MethodPatch, "/api/ingest/scan-requests/"+requestID, body, nil)
}

// GetExcludes fetches the webserver's central exclude list (IPs/CIDR
// ranges and ports/port ranges that must never be scanned). Called fresh
// before every scan (see pipeline.RunScan) rather than cached, so an
// admin's most recent excludes always take effect immediately.
func (c *Client) GetExcludes(ctx context.Context) (pipeline.Excludes, error) {
	var out struct {
		IPs     []string `json:"ips"`
		Ports   []string `json:"ports"`
		IPPorts []struct {
			IP       string `json:"ip"`
			PortSpec string `json:"portSpec"`
		} `json:"ipPorts"`
	}
	if err := c.doJSON(ctx, http.MethodGet, "/api/ingest/excludes", nil, &out); err != nil {
		return pipeline.Excludes{}, fmt.Errorf("fetching excludes: %w", err)
	}
	ipPorts := make([]pipeline.IPPortExclude, 0, len(out.IPPorts))
	for _, e := range out.IPPorts {
		ipPorts = append(ipPorts, pipeline.IPPortExclude{IP: e.IP, PortSpec: e.PortSpec})
	}
	return pipeline.Excludes{IPs: out.IPs, Ports: out.Ports, IPPorts: ipPorts}, nil
}

// GetProbeHostnames fetches the manual per-host SNI/screenshot-URL
// hostname overrides (see CLAUDE.md's "Manual probe hostname override"
// section) for hosts owned by this scanner agent - a plain map is enough
// here (unlike Excludes, nothing else needs a richer type), keyed by IP
// for O(1) lookup during a scan.
func (c *Client) GetProbeHostnames(ctx context.Context) (map[string]string, error) {
	var out []struct {
		IP       string `json:"ip"`
		Hostname string `json:"hostname"`
	}
	if err := c.doJSON(ctx, http.MethodGet, "/api/ingest/probe-hostnames", nil, &out); err != nil {
		return nil, fmt.Errorf("fetching probe hostnames: %w", err)
	}
	hostnames := make(map[string]string, len(out))
	for _, e := range out {
		hostnames[e.IP] = e.Hostname
	}
	return hostnames, nil
}

func (c *Client) doJSON(ctx context.Context, method, path string, body any, out any) error {
	var reqBody io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("encoding request body: %w", err)
		}
		reqBody = bytes.NewReader(encoded)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reqBody)
	if err != nil {
		return fmt.Errorf("building request: %w", err)
	}
	setAuthHeaders(req, c.apiKey)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("request to %s failed: %w", path, err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return fmt.Errorf("%s %s: unexpected status %d: %s", method, path, resp.StatusCode, string(respBody))
	}

	if out != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, out); err != nil {
			return fmt.Errorf("decoding response from %s: %w", path, err)
		}
	}
	return nil
}
