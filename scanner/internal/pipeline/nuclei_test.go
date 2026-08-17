package pipeline

import (
	"os"
	"path/filepath"
	"testing"
)

// realNucleiJSONLSample is trimmed from a real "nuclei -jsonl" run
// (nuclei v3.11.1, default templates minus dos/fuzz/intrusive, -t http/)
// against a deliberately misconfigured nginx target exposing .env and
// .git/config - see nuclei.go's own doc comment. The second line
// (codeigniter-env) deliberately has no "reference" key at all, unlike
// the first (laravel-env) - confirming the parser tolerates a field being
// entirely absent, not just empty, since that's genuinely how nuclei
// behaves across different templates.
const realNucleiJSONLSample = `{"template":"http/exposures/configs/laravel-env.yaml","template-id":"laravel-env","info":{"name":"Laravel - Sensitive Information Disclosure","tags":["config","exposure","laravel","vuln"],"description":"A Laravel .env file was discovered, which stores sensitive information like database credentials and tokens. It should not be publicly accessible.\n","reference":["https://laravel.com/docs/master/configuration#environment-configuration"],"severity":"high"},"type":"http","host":"localhost","port":"80","matched-at":"http://localhost//.env","curl-command":"curl -X 'GET' 'http://localhost//.env'","matcher-status":true}
{"template":"http/exposures/configs/codeigniter-env.yaml","template-id":"codeigniter-env","info":{"name":"Codeigniter - .env File Discovery","tags":["config","exposure","codeigniter","vuln"],"description":"Codeigniter .env file was discovered.","severity":"high"},"type":"http","host":"localhost","port":"80","matched-at":"http://localhost//.env","curl-command":"curl -X 'GET' 'http://localhost//.env'","matcher-status":true}
`

func TestReadNucleiJSONLParsesRealSample(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "findings.jsonl")
	if err := os.WriteFile(path, []byte(realNucleiJSONLSample), 0o644); err != nil {
		t.Fatal(err)
	}

	results, err := readNucleiJSONL(path)
	if err != nil {
		t.Fatalf("readNucleiJSONL: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(results))
	}

	first := results[0]
	if first.TemplateID != "laravel-env" {
		t.Errorf("TemplateID = %q, want laravel-env", first.TemplateID)
	}
	if first.Info.Severity != "high" {
		t.Errorf("Severity = %q, want high", first.Info.Severity)
	}
	if first.MatchedAt != "http://localhost//.env" {
		t.Errorf("MatchedAt = %q, want http://localhost//.env", first.MatchedAt)
	}
	if len(first.Info.Reference) != 1 {
		t.Errorf("expected 1 reference on laravel-env, got %d", len(first.Info.Reference))
	}

	second := results[1]
	if second.TemplateID != "codeigniter-env" {
		t.Errorf("TemplateID = %q, want codeigniter-env", second.TemplateID)
	}
	// codeigniter-env's info block has no "reference" key at all in the
	// real sample - must decode to a nil/empty slice, not an error.
	if len(second.Info.Reference) != 0 {
		t.Errorf("expected no references on codeigniter-env, got %v", second.Info.Reference)
	}
}

func TestReadNucleiJSONLMissingFileMeansNoFindings(t *testing.T) {
	results, err := readNucleiJSONL(filepath.Join(t.TempDir(), "does-not-exist.jsonl"))
	if err != nil {
		t.Fatalf("expected no error for a missing file (normal 'no findings' case), got %v", err)
	}
	if results != nil {
		t.Errorf("expected nil results, got %v", results)
	}
}

func TestRunNucleiBuildsFindingsFromResults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "findings.jsonl")
	if err := os.WriteFile(path, []byte(realNucleiJSONLSample), 0o644); err != nil {
		t.Fatal(err)
	}

	results, err := readNucleiJSONL(path)
	if err != nil {
		t.Fatal(err)
	}

	findings := make([]NucleiFinding, 0, len(results))
	for _, r := range results {
		findings = append(findings, NucleiFinding{
			Port:        8443,
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

	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
	if findings[0].Port != 8443 {
		t.Errorf("Port = %d, want 8443 (from the caller, not parsed from nuclei's own string port field)", findings[0].Port)
	}
	if findings[0].Name != "Laravel - Sensitive Information Disclosure" {
		t.Errorf("Name = %q", findings[0].Name)
	}
}
