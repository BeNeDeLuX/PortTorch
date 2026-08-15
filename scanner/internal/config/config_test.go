package config

import (
	"os"
	"path/filepath"
	"testing"
)

// TestLoadExampleConfig parses the actual config.example.yaml shipped in
// the repo root, so a typo or renamed field there is caught by CI instead
// of only being discovered by an operator copying it into production.
func TestLoadExampleConfig(t *testing.T) {
	path := filepath.Join("..", "..", "config.example.yaml")
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load(%s) failed: %v", path, err)
	}

	if cfg.Concurrency != 5 {
		t.Errorf("Concurrency = %d, want 5", cfg.Concurrency)
	}
	if cfg.MasscanRetries != 2 {
		t.Errorf("MasscanRetries = %d, want 2", cfg.MasscanRetries)
	}
	// Deliberately lower than and separate from Concurrency - see
	// orchestrator.go's Config.GowitnessConcurrency doc comment for why.
	if cfg.GowitnessConcurrency != 2 {
		t.Errorf("GowitnessConcurrency = %d, want 2", cfg.GowitnessConcurrency)
	}
	if cfg.RDPConcurrency != 2 {
		t.Errorf("RDPConcurrency = %d, want 2", cfg.RDPConcurrency)
	}
}

// TestDefaultsFillGowitnessAndRDPConcurrency verifies the Config->
// pipeline.Config mapping and pipeline-level defaults independently of
// the example YAML file, in case that file's values ever get out of sync.
func TestPipelineMapsConcurrencyFields(t *testing.T) {
	cfg := Config{
		WebserverURL:         "https://example.invalid",
		APIKey:               "test",
		Concurrency:          5,
		GowitnessConcurrency: 3,
		RDPConcurrency:       4,
	}
	pcfg := cfg.Pipeline()
	if pcfg.Concurrency != 5 || pcfg.GowitnessConcurrency != 3 || pcfg.RDPConcurrency != 4 {
		t.Errorf("Pipeline() concurrency fields = (%d, %d, %d), want (5, 3, 4)",
			pcfg.Concurrency, pcfg.GowitnessConcurrency, pcfg.RDPConcurrency)
	}
}

// TestLoadDefaultsSubmitQueueDirAndAuditLogPath confirms both paths
// default to sibling files/directories next to the config file itself
// (not the current working directory, which a naive relative default
// would get wrong for a service started from an arbitrary directory).
func TestLoadDefaultsSubmitQueueDirAndAuditLogPath(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(configPath, []byte("webserverUrl: https://example.invalid\napiKey: test\n"), 0o644); err != nil {
		t.Fatalf("writing test config: %v", err)
	}

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	wantQueueDir := filepath.Join(dir, "submit-queue")
	if cfg.SubmitQueueDir != wantQueueDir {
		t.Errorf("SubmitQueueDir = %q, want %q", cfg.SubmitQueueDir, wantQueueDir)
	}
	wantAuditLog := filepath.Join(dir, "scan-audit.jsonl")
	if cfg.ScanAuditLogPath != wantAuditLog {
		t.Errorf("ScanAuditLogPath = %q, want %q", cfg.ScanAuditLogPath, wantAuditLog)
	}
}

// An explicit value in the YAML must win over the computed default -
// same override-ability every other configurable path in this file has.
func TestLoadRespectsExplicitSubmitQueueDirAndAuditLogPath(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	yaml := "webserverUrl: https://example.invalid\napiKey: test\nsubmitQueueDir: /custom/queue\nscanAuditLogPath: /custom/audit.jsonl\n"
	if err := os.WriteFile(configPath, []byte(yaml), 0o644); err != nil {
		t.Fatalf("writing test config: %v", err)
	}

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.SubmitQueueDir != "/custom/queue" {
		t.Errorf("SubmitQueueDir = %q, want /custom/queue", cfg.SubmitQueueDir)
	}
	if cfg.ScanAuditLogPath != "/custom/audit.jsonl" {
		t.Errorf("ScanAuditLogPath = %q, want /custom/audit.jsonl", cfg.ScanAuditLogPath)
	}
}
