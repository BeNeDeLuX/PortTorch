package pipeline

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// NucleiProfile selects which nuclei templates a scan runs, resolved
// webserver-side (server/src/nucleiProfiles/resolve.ts) into the three
// fields below and sent as part of the scan request - see RunScan's doc
// comment for why a nil *NucleiProfile means nuclei doesn't run at all.
type NucleiProfile struct {
	Tags        []string
	Severities  []string
	ExcludeTags []string
}

// nucleiInfo/nucleiJSONLResult mirror nuclei's own -jsonl output shape,
// captured from a real run (nuclei v3.11.1, default templates against a
// deliberately misconfigured nginx target exposing .env/.git/config) -
// see nuclei.go's own tests for a captured sample. Reference/Description
// are absent entirely (not just empty) on many templates, which
// encoding/json already tolerates by leaving the field at its zero value.
type nucleiInfo struct {
	Name        string   `json:"name"`
	Severity    string   `json:"severity"`
	Description string   `json:"description"`
	Reference   []string `json:"reference"`
	Tags        []string `json:"tags"`
}

type nucleiJSONLResult struct {
	TemplateID  string     `json:"template-id"`
	Info        nucleiInfo `json:"info"`
	MatchedAt   string     `json:"matched-at"`
	CurlCommand string     `json:"curl-command"`
}

// RunNuclei runs nuclei against a single HTTP(S) URL and returns every
// matched finding. "-t http/" restricts nuclei to its HTTP template
// category - confirmed via real testing that without it, nuclei also runs
// its dns/network/ssl template categories against the target's hostname
// (DNS rebinding checks, nameserver fingerprinting, wildcard-DNS
// detection, etc.), none of which has anything to do with "does this
// HTTP(S) port have a web finding" and which meaningfully slows the scan
// down for no benefit here.
func RunNuclei(ctx context.Context, cfg Config, url string, port int, profile NucleiProfile) ([]NucleiFinding, error) {
	tmpFile, err := os.CreateTemp("", "nuclei-*.jsonl")
	if err != nil {
		return nil, fmt.Errorf("creating temp file for nuclei: %w", err)
	}
	jsonlPath := tmpFile.Name()
	tmpFile.Close()
	defer os.Remove(jsonlPath)

	args := []string{
		"-target", url,
		"-jsonl", "-silent",
		"-t", "http/",
		"-timeout", strconv.Itoa(cfg.NucleiTimeoutSeconds),
		"-o", jsonlPath,
	}
	if len(profile.Tags) > 0 {
		args = append(args, "-tags", strings.Join(profile.Tags, ","))
	}
	if len(profile.Severities) > 0 {
		args = append(args, "-severity", strings.Join(profile.Severities, ","))
	}
	if len(profile.ExcludeTags) > 0 {
		args = append(args, "-etags", strings.Join(profile.ExcludeTags, ","))
	}

	cmd := exec.CommandContext(ctx, cfg.NucleiPath, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("nuclei failed for %s: %w (stdout: %s, stderr: %s)", url, err, stdout.String(), stderr.String())
	}

	results, err := readNucleiJSONL(jsonlPath)
	if err != nil {
		return nil, fmt.Errorf("reading nuclei result for %s: %w", url, err)
	}

	findings := make([]NucleiFinding, 0, len(results))
	for _, r := range results {
		findings = append(findings, NucleiFinding{
			Port:        port,
			TemplateID:  r.TemplateID,
			Name:        r.Info.Name,
			Severity:    r.Info.Severity,
			MatchedAt:   r.MatchedAt,
			Description: r.Info.Description,
			Reference:   r.Info.Reference,
			Tags:        r.Info.Tags,
			CurlCommand: r.CurlCommand,
		})
	}
	return findings, nil
}

// readNucleiJSONL parses nuclei's -jsonl output - one JSON object per
// matched finding, one per line. Unlike gowitness's JSONL (always exactly
// one result line, success or failure), nuclei writes zero lines at all
// when nothing matched - a missing/empty file is the normal "no findings"
// case, not an error.
func readNucleiJSONL(path string) ([]nucleiJSONLResult, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var results []nucleiJSONLResult
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 10*1024*1024)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var r nucleiJSONLResult
		if err := json.Unmarshal(line, &r); err != nil {
			return nil, err
		}
		results = append(results, r)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return results, nil
}
