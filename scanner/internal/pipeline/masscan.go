package pipeline

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

type masscanPortEntry struct {
	Port   int    `json:"port"`
	Proto  string `json:"proto"`
	Status string `json:"status"`
}

type masscanRecord struct {
	IP    string             `json:"ip"`
	Ports []masscanPortEntry `json:"ports"`
}

// RunMasscan runs masscan against targetSpec (single IP or CIDR range) with
// the given port spec and returns the open ports for each discovered host
// (still without service/banner information, which nmap provides).
// excludeIPs (single IPs or CIDR ranges) are passed to masscan's
// --excludefile, which skips them even when they fall inside targetSpec.
// retries is masscan's own --retries: since masscan is a stateless SYN
// scanner, a single lost packet (in either direction) means a genuinely
// open port is simply not reported that run - retries resend the probe at
// 1-second intervals regardless of whether a reply was already received,
// trading a bit of extra scan time/traffic for materially fewer "open
// port not found this time" false negatives on lossy or slow-to-respond
// networks.
func RunMasscan(ctx context.Context, binPath, targetSpec, portSpec string, excludeIPs []string, rate, retries int) (map[string][]PortResult, error) {
	outFile, err := os.CreateTemp("", "masscan-*.json")
	if err != nil {
		return nil, fmt.Errorf("temp file for masscan output: %w", err)
	}
	outPath := outFile.Name()
	outFile.Close()
	defer os.Remove(outPath)

	args := []string{
		targetSpec,
		"-p", portSpec,
		"--rate", fmt.Sprintf("%d", rate),
		"--retries", fmt.Sprintf("%d", retries),
		"-oJ", outPath,
	}

	if len(excludeIPs) > 0 {
		excludeFile, err := writeExcludeFile(excludeIPs)
		if err != nil {
			return nil, err
		}
		defer os.Remove(excludeFile)
		args = append(args, "--excludefile", excludeFile)
	}

	cmd := exec.CommandContext(ctx, binPath, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("masscan failed: %w (stderr: %s)", err, stderr.String())
	}

	raw, err := os.ReadFile(outPath)
	if err != nil {
		return nil, fmt.Errorf("reading masscan output: %w", err)
	}

	records, err := parseMasscanJSON(raw)
	if err != nil {
		return nil, fmt.Errorf("parsing masscan output: %w", err)
	}

	return hostsFromMasscanRecords(records), nil
}

// hostsFromMasscanRecords converts parsed masscan JSON records into the
// map[string][]PortResult shape RunMasscan returns, deduplicating each
// host's ports on (protocol, port). Split out from RunMasscan so this is
// unit-testable against hand-built records, no real masscan binary needed.
//
// The dedup matters because masscan's own --retries resends each probe, so
// a port that gets a reply to more than one attempt (common on a network
// with duplicate ACKs/retransmits, not just packet loss) shows up as its
// own top-level JSON record each time - without this, the same port number
// ends up in the -p list RunNmap builds more than once, which nmap accepts
// but warns loudly about ("Duplicate port number(s) specified").
func hostsFromMasscanRecords(records []masscanRecord) map[string][]PortResult {
	hosts := make(map[string][]PortResult)
	seen := make(map[string]map[string]bool) // ip -> "proto:port" -> true
	for _, rec := range records {
		for _, p := range rec.Ports {
			key := fmt.Sprintf("%s:%d", p.Proto, p.Port)
			if seen[rec.IP] == nil {
				seen[rec.IP] = make(map[string]bool)
			}
			if seen[rec.IP][key] {
				continue
			}
			seen[rec.IP][key] = true
			hosts[rec.IP] = append(hosts[rec.IP], PortResult{
				Port:     p.Port,
				Protocol: p.Proto,
				State:    p.Status,
			})
		}
	}
	return hosts
}

// parseMasscanJSON tolerates a missing closing "]", in case masscan (e.g.
// due to being interrupted) doesn't write a complete JSON array.
func parseMasscanJSON(raw []byte) ([]masscanRecord, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil, nil
	}

	var records []masscanRecord
	if err := json.Unmarshal(trimmed, &records); err == nil {
		return records, nil
	}

	repaired := strings.TrimRight(string(trimmed), "\n")
	repaired = strings.TrimSuffix(repaired, ",")
	if !strings.HasSuffix(repaired, "]") {
		repaired += "]"
	}
	if err := json.Unmarshal([]byte(repaired), &records); err != nil {
		return nil, err
	}
	return records, nil
}
