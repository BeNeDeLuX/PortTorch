package pipeline

import (
	"errors"
	"testing"
)

func TestIsTimeoutLikeErr(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil error", nil, false},
		{"gowitness deadline exceeded", errors.New("gowitness could not screenshot http://x:80: context deadline exceeded"), true},
		{"generic timeout wording", errors.New("dial tcp 10.0.0.1:443: i/o timeout"), true},
		{"uppercase Timeout", errors.New("Timeout waiting for response"), true},
		// Deterministic failures that would just fail again identically -
		// retrying these would waste time, not improve success rate.
		{"connection refused", errors.New("dial tcp 10.0.0.1:3389: connect: connection refused"), false},
		{"nla rejection", errors.New("rdp screenshot for 10.0.0.1:3389 was not created"), false},
		{"binary not found", errors.New("starting xfreerdp: exec: \"xfreerdp3\": executable file not found in $PATH"), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isTimeoutLikeErr(c.err); got != c.want {
				t.Errorf("isTimeoutLikeErr(%v) = %v, want %v", c.err, got, c.want)
			}
		})
	}
}
