package main

import (
	"testing"
	"time"
)

// --since takes the forms an operator reaches for, not only Go's own
// duration syntax - "7d" in particular, which time.ParseDuration refuses.
func TestParseSince(t *testing.T) {
	now := time.Now()

	if got, err := parseSince(""); err != nil || !got.IsZero() {
		t.Errorf("empty --since must mean no lower bound, got %v (err %v)", got, err)
	}

	for _, c := range []struct {
		in   string
		back time.Duration
	}{
		{"24h", 24 * time.Hour},
		{"90m", 90 * time.Minute},
		{"7d", 7 * 24 * time.Hour},
		{" 2d ", 2 * 24 * time.Hour},
	} {
		got, err := parseSince(c.in)
		if err != nil {
			t.Errorf("parseSince(%q): %v", c.in, err)
			continue
		}
		diff := now.Add(-c.back).Sub(got)
		if diff < -2*time.Second || diff > 2*time.Second {
			t.Errorf("parseSince(%q) = %v, want about %v ago", c.in, got, c.back)
		}
	}

	got, err := parseSince("2026-09-01")
	if err != nil {
		t.Fatalf("date form: %v", err)
	}
	if got.Year() != 2026 || got.Month() != time.September || got.Day() != 1 {
		t.Errorf("date form parsed to %v", got)
	}

	if _, err := parseSince("last tuesday"); err == nil {
		t.Error("an unparseable --since must be an error, not silently the whole log")
	}
}
