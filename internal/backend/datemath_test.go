package backend

import (
	"testing"
	"time"
)

func TestParseLookback(t *testing.T) {
	tests := []struct {
		in   string
		want time.Duration
	}{
		{"now-6m", 6 * time.Minute},
		{"now-90d", 90 * 24 * time.Hour},
		{"now-1h/h", time.Hour}, // rounding suffix stripped
		{"now-2w", 14 * 24 * time.Hour},
		{"now", 0},
		{"2026-01-01T00:00:00Z", 0},
		{"", 0},
	}
	for _, tt := range tests {
		if got := ParseLookback(tt.in); got != tt.want {
			t.Errorf("ParseLookback(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestParseInterval(t *testing.T) {
	tests := []struct {
		in   string
		want time.Duration
	}{
		{"5m", 5 * time.Minute},
		{"30s", 30 * time.Second},
		{"1d", 24 * time.Hour},
		{"1M", 30 * 24 * time.Hour},
		{"", 0},
		{"m", 0},
		{"-5m", 0},
		{"5x", 0},
	}
	for _, tt := range tests {
		if got := ParseInterval(tt.in); got != tt.want {
			t.Errorf("ParseInterval(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}
