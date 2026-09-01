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
	"sync/atomic"
	"time"

	"porttorch/scanner/internal/config"
	"porttorch/scanner/internal/pipeline"
	"porttorch/scanner/internal/progress"
	"porttorch/scanner/internal/version"
)

// HTTPStatusError wraps a non-2xx response from the webserver's ingest
// API, carrying the actual numeric status code so a caller (see
// internal/submitqueue's IsPermanentFailure) can tell a permanent client
// error (4xx - the payload itself is invalid or rejected, retrying it
// unchanged will never succeed) apart from a transient one (a 5xx, or no
// response at all - worth retrying). Unlike gowitness/xfreerdp elsewhere
// in this codebase, which only ever report their own failures as opaque
// text, the status code here is already a real field on the response
// this scanner's own HTTP client received, so there's no need to fall
// back to string-matching to recover it.
type HTTPStatusError struct {
	StatusCode int
	Body       string
}

func (e *HTTPStatusError) Error() string {
	return fmt.Sprintf("unexpected status %d: %s", e.StatusCode, e.Body)
}

// setAuthHeaders sets the API key, this scanner's version, and its
// current submit-queue backlog size on every request - the webserver
// records all three alongside last_seen_at/last_seen_ip (see
// apiKeyAuth.ts) so the Scanner Agents/Fleet Health pages can show which
// version each agent is actually running, and whether it has host
// submissions stuck in its local retry queue, without either needing a
// dedicated endpoint.
func (c *Client) setAuthHeaders(req *http.Request) {
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("X-Scanner-Version", version.Version)
	req.Header.Set("X-Scanner-Submit-Queue-Pending", strconv.Itoa(int(atomic.LoadInt32(&c.submitQueuePending))))
	// Omitted entirely rather than sent as "0/0" when this process has no
	// scan slots at all ("scan"/"menu"), so the webserver's own
	// "unknown" (a missing header) keeps its meaning.
	if max := atomic.LoadInt32(&c.scanSlotsMax); max > 0 {
		req.Header.Set("X-Scanner-Scan-Slots", strconv.Itoa(int(atomic.LoadInt32(&c.scanSlotsRunning)))+"/"+strconv.Itoa(int(max)))
	}
	// Omitted entirely when unknown (nuclei not installed, templates
	// never fetched) rather than sent as an empty or epoch value - the
	// webserver distinguishes "no templates" from "templates from 1970",
	// and only the former is true here.
	if ts, ok := c.nucleiTemplatesUpdatedAt.Load().(time.Time); ok && !ts.IsZero() {
		req.Header.Set("X-Scanner-Nuclei-Templates-Updated", ts.UTC().Format(time.RFC3339))
	}
}

// SetNucleiTemplatesUpdatedAt records when this scanner's nuclei template
// tree was last written, reported on every subsequent request via the
// same piggyback mechanism as version and submit-queue depth. Set once at
// startup and refreshed after anything that could rewrite the tree -
// atomic because the value is read from whichever goroutine happens to be
// making a request at the time.
// A zero time means "unknown" and simply stops the header being sent;
// atomic.Value panics on a nil Store, so the zero value is what carries
// that state rather than nil.
func (c *Client) SetNucleiTemplatesUpdatedAt(t time.Time) {
	c.nucleiTemplatesUpdatedAt.Store(t)
}

// Client talks to the webserver's authenticated ingest API.
type Client struct {
	baseURL string
	apiKey  string
	http    *http.Client
	// submitQueuePending mirrors internal/submitqueue's current backlog
	// size for this process (see SetSubmitQueuePending) - read from
	// setAuthHeaders on every request, and written both by the
	// serve-mode retry watcher's periodic Drain and immediately after
	// any Enqueue call, from whichever goroutine is running the scan at
	// the time, hence the atomic access rather than a plain int.
	submitQueuePending int32
	// scanSlotsRunning/scanSlotsMax mirror serve mode's own scan-slot
	// accounting (see SetScanSlots). Packed as two atomics rather than a
	// mutex-guarded pair because they are only ever read together to
	// build one header line, and a momentarily mismatched pair - "2/1"
	// during the instant a lowered limit is being applied - is a
	// cosmetically odd number on a dashboard, not a correctness problem.
	//
	// max stays 0 until something sets it, which is how "unknown" is
	// expressed: the one-shot "scan"/"menu" modes have no queue loop and
	// no slots, so they send no header at all rather than claiming 0/1.
	scanSlotsRunning int32
	scanSlotsMax     int32
	// nil until known - see SetNucleiTemplatesUpdatedAt. atomic.Value
	// rather than a plain field for the same reason as the counter above.
	nucleiTemplatesUpdatedAt atomic.Value
}

// SetScanSlots records how many scans this process is running and how many
// it will run at once, reported on every subsequent request via the
// X-Scanner-Scan-Slots header. Safe to call concurrently.
func (c *Client) SetScanSlots(running, max int) {
	atomic.StoreInt32(&c.scanSlotsRunning, int32(running))
	atomic.StoreInt32(&c.scanSlotsMax, int32(max))
}

// SetSubmitQueuePending records the scanner's current internal/submitqueue
// backlog size, reported on every subsequent request via the
// X-Scanner-Submit-Queue-Pending header (see setAuthHeaders). Safe to
// call concurrently.
func (c *Client) SetSubmitQueuePending(n int) {
	atomic.StoreInt32(&c.submitQueuePending, int32(n))
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

	c := &Client{
		baseURL: strings.TrimSuffix(cfg.WebserverURL, "/"),
		apiKey:  cfg.APIKey,
		http: &http.Client{
			Timeout:   60 * time.Second,
			Transport: &http.Transport{TLSClientConfig: tlsConfig},
		},
	}
	// Resolved here rather than at each of the four call sites, so every
	// mode (scan/menu/serve/doctor) reports it without duplication. Purely
	// best-effort: a missing directory (nuclei not installed, or templates
	// never fetched) just leaves it unknown and omits the header - it must
	// never stop a client being constructed.
	c.RefreshNucleiTemplatesUpdatedAt()
	return c, nil
}

// RefreshNucleiTemplatesUpdatedAt re-stats the template tree. Called once
// at construction and again before each queue-triggered scan, so a
// long-running serve process notices a manual `nuclei -update-templates`
// rather than reporting whatever was true when it started days ago.
func (c *Client) RefreshNucleiTemplatesUpdatedAt() {
	updated, err := pipeline.NucleiTemplatesUpdatedAt(pipeline.DefaultNucleiTemplatesDir())
	if err != nil {
		c.SetNucleiTemplatesUpdatedAt(time.Time{})
		return
	}
	c.SetNucleiTemplatesUpdatedAt(updated)
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

// PushFullScanLog uploads the complete accumulated progress log once, at
// scan completion - see progress.Tracker.Close, which calls this exactly
// once per scan. Satisfies progress.Pusher.
func (c *Client) PushFullScanLog(ctx context.Context, jobID string, logs []progress.LogLine) error {
	body := map[string]any{"logs": logs}
	return c.doJSON(ctx, http.MethodPatch, "/api/ingest/scan-jobs/"+jobID+"/full-log", body, nil)
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

type ingestNucleiFinding struct {
	Port        int      `json:"port"`
	TemplateID  string   `json:"templateId"`
	Name        string   `json:"name"`
	Severity    string   `json:"severity"`
	MatchedAt   string   `json:"matchedAt"`
	Description string   `json:"description,omitempty"`
	Reference   []string `json:"reference,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	CurlCommand string   `json:"curlCommand,omitempty"`
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
	IP             string                `json:"ip"`
	Hostname       string                `json:"hostname,omitempty"`
	OSName         string                `json:"osName,omitempty"`
	OSFamily       string                `json:"osFamily,omitempty"`
	OSVendor       string                `json:"osVendor,omitempty"`
	DeviceType     string                `json:"deviceType,omitempty"`
	OSAccuracy     int                   `json:"osAccuracy,omitempty"`
	MACAddress     string                `json:"macAddress,omitempty"`
	MACVendor      string                `json:"macVendor,omitempty"`
	Ports          []ingestPort          `json:"ports"`
	NucleiFindings []ingestNucleiFinding `json:"nucleiFindings,omitempty"`
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
		var nucleiFindings []ingestNucleiFinding
		for _, f := range h.NucleiFindings {
			nucleiFindings = append(nucleiFindings, ingestNucleiFinding{
				Port:        f.Port,
				TemplateID:  f.TemplateID,
				Name:        f.Name,
				Severity:    f.Severity,
				MatchedAt:   f.MatchedAt,
				Description: f.Description,
				Reference:   f.Reference,
				Tags:        f.Tags,
				CurlCommand: f.CurlCommand,
			})
		}
		payloadHosts = append(payloadHosts, ingestHost{
			IP:             h.IP,
			Hostname:       h.Hostname,
			OSName:         h.OSName,
			OSFamily:       h.OSFamily,
			OSVendor:       h.OSVendor,
			DeviceType:     h.DeviceType,
			OSAccuracy:     h.OSAccuracy,
			MACAddress:     h.MACAddress,
			MACVendor:      h.MACVendor,
			Ports:          ports,
			NucleiFindings: nucleiFindings,
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
	c.setAuthHeaders(req)
	req.Header.Set("Content-Type", writer.FormDataContentType())

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("uploading image failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("uploading image to %s: %w", path, &HTTPStatusError{StatusCode: resp.StatusCode, Body: string(respBody)})
	}
	return nil
}

// ScanRequest is a scan job created by the webserver via the rescan button
// or a schedule, picked up via polling.
//
// NSEProfile/NSEScripts carry the scan-profile pick (see
// internal/pipeline's nse_default_scripts.go/nse_safe_scripts.go and
// internal/api/server.go's resolveNSEScripts) - both are absent-safe: an
// older webserver that predates the scan-profile feature simply never
// sends them, decoding to zero values, which resolveNSEScripts already
// treats as "Default", today's unchanged behavior.
type ScanRequest struct {
	ID            string
	TargetSpec    string
	PortSpec      string
	NSEProfile    string
	NSEScripts    []string
	NucleiProfile string
	NucleiTags    []string
	// Per-scan override of the scanner's own configured masscanRate - nil
	// means "no override", i.e. keep using config.yaml's value. A pointer
	// rather than an int so "not set" is distinguishable from a literal 0,
	// which would otherwise silently look like a request for rate 0.
	MasscanRate *int
}

// PollNextScanRequest asks the webserver for the next pending scan request
// for this scanner and atomically claims it. Returns (nil, nil) if nothing
// is currently pending.
func (c *Client) PollNextScanRequest(ctx context.Context) (*ScanRequest, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/api/ingest/scan-requests/next", nil)
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	c.setAuthHeaders(req)

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
		ID            string   `json:"id"`
		TargetSpec    string   `json:"targetSpec"`
		PortSpec      string   `json:"portSpec"`
		NSEProfile    string   `json:"nseProfile"`
		NSEScripts    []string `json:"nseScripts"`
		NucleiProfile string   `json:"nucleiProfile"`
		NucleiTags    []string `json:"nucleiTags"`
		MasscanRate   *int     `json:"masscanRate"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decoding scan request: %w", err)
	}
	return &ScanRequest{
		ID: out.ID, TargetSpec: out.TargetSpec, PortSpec: out.PortSpec,
		NSEProfile: out.NSEProfile, NSEScripts: out.NSEScripts,
		NucleiProfile: out.NucleiProfile, NucleiTags: out.NucleiTags,
		MasscanRate: out.MasscanRate,
	}, nil
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

// GetConfigOverrides fetches this agent's dashboard-managed config
// overrides (GET /api/ingest/config). A map rather than a struct on
// purpose: the webserver only ever sends the keys an admin actually set,
// and the scanner ignores anything it doesn't recognise - so adding a
// tunable on the dashboard side doesn't need a matching scanner release
// to avoid an unmarshalling error.
//
// An empty map is the normal answer and means "use config.yaml as
// written" - it is not an error and must not be treated as one.
func (c *Client) GetConfigOverrides(ctx context.Context) (map[string]int, error) {
	var out map[string]int
	if err := c.doJSON(ctx, http.MethodGet, "/api/ingest/config", nil, &out); err != nil {
		return nil, fmt.Errorf("fetching config overrides: %w", err)
	}
	if out == nil {
		out = map[string]int{}
	}
	return out, nil
}

// ReportBaseConfig tells the webserver what this scanner's config.yaml
// actually says for the dashboard-tunable settings, so the Configure
// dialog can show real values instead of the shipped defaults.
//
// Deliberately the *base* config, not the effective one: the dialog's
// question is "what applies if I leave this field blank", and the
// effective config already has any dashboard override folded into it -
// reporting that would make an override look like the file's own value
// and there would be nothing left to clear back to.
func (c *Client) ReportBaseConfig(ctx context.Context, values map[string]int) error {
	return c.doJSON(ctx, http.MethodPut, "/api/ingest/config-report", values, nil)
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

// CheckUpdateRequested asks whether an admin has requested this scanner
// self-update (see the ScannerAgents "Update" button) - polled by
// internal/updater's StartUpdateWatcher, mirroring CheckCancelRequested's
// shape exactly. Scoped implicitly to this scanner's own authenticated
// agent, unlike CheckCancelRequested (which takes a job ID) - the
// scanner never needs to know its own scanner_agents.id.
func (c *Client) CheckUpdateRequested(ctx context.Context) (bool, error) {
	var resp struct {
		Requested bool `json:"requested"`
	}
	if err := c.doJSON(ctx, http.MethodGet, "/api/ingest/update-requested", nil, &resp); err != nil {
		return false, err
	}
	return resp.Requested, nil
}

// ReleaseInfo is the webserver's cached view of the latest published
// scanner-vX.Y.Z GitHub release (see server/src/scannerUpdate/githubSync.ts).
// LatestVersion/LatestTag/ReleaseURL are all empty strings if the webserver
// hasn't synced one yet.
type ReleaseInfo struct {
	LatestVersion string
	LatestTag     string
	ReleaseURL    string
}

// GetScannerRelease fetches the webserver's cached latest-release info -
// the scanner needs this to know *which* version to actually
// download/verify once CheckUpdateRequested says an update was requested.
func (c *Client) GetScannerRelease(ctx context.Context) (ReleaseInfo, error) {
	var out struct {
		LatestVersion *string `json:"latestVersion"`
		LatestTag     *string `json:"latestTag"`
		ReleaseURL    *string `json:"releaseUrl"`
	}
	if err := c.doJSON(ctx, http.MethodGet, "/api/ingest/scanner-release", nil, &out); err != nil {
		return ReleaseInfo{}, fmt.Errorf("fetching scanner release info: %w", err)
	}
	info := ReleaseInfo{}
	if out.LatestVersion != nil {
		info.LatestVersion = *out.LatestVersion
	}
	if out.LatestTag != nil {
		info.LatestTag = *out.LatestTag
	}
	if out.ReleaseURL != nil {
		info.ReleaseURL = *out.ReleaseURL
	}
	return info, nil
}

// ReportUpdateOutcome tells the webserver whether a self-update attempt
// succeeded or failed - a "failed" outcome needs a human-readable reason
// so it's visible on the Scanner Agents page (update_failure_reason).
func (c *Client) ReportUpdateOutcome(ctx context.Context, succeeded bool, failureReason string) error {
	var body map[string]string
	if succeeded {
		body = map[string]string{"status": "succeeded"}
	} else {
		body = map[string]string{"status": "failed", "reason": failureReason}
	}
	return c.doJSON(ctx, http.MethodPatch, "/api/ingest/update-outcome", body, nil)
}

// CheckTemplateUpdateRequested asks whether an admin has requested this
// scanner refresh its nuclei templates (see the ScannerAgents "Update
// templates" button) - the template counterpart to CheckUpdateRequested,
// same implicit scoping to this scanner's own authenticated agent.
func (c *Client) CheckTemplateUpdateRequested(ctx context.Context) (bool, error) {
	var resp struct {
		Requested bool `json:"requested"`
	}
	if err := c.doJSON(ctx, http.MethodGet, "/api/ingest/template-update-requested", nil, &resp); err != nil {
		return false, err
	}
	return resp.Requested, nil
}

// ReportTemplateUpdateOutcome is ReportUpdateOutcome's template
// counterpart - same body shape, same "a failure needs a human-readable
// reason so it's visible on the dashboard" contract.
func (c *Client) ReportTemplateUpdateOutcome(ctx context.Context, succeeded bool, failureReason string) error {
	var body map[string]string
	if succeeded {
		body = map[string]string{"status": "succeeded"}
	} else {
		body = map[string]string{"status": "failed", "reason": failureReason}
	}
	return c.doJSON(ctx, http.MethodPatch, "/api/ingest/template-update-outcome", body, nil)
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
	c.setAuthHeaders(req)
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
		return fmt.Errorf("%s %s: %w", method, path, &HTTPStatusError{StatusCode: resp.StatusCode, Body: string(respBody)})
	}

	if out != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, out); err != nil {
			return fmt.Errorf("decoding response from %s: %w", path, err)
		}
	}
	return nil
}
