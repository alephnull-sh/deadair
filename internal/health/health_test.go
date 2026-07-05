package health

import (
	"testing"
	"time"

	"github.com/Big-Comfy/deadair/internal/backend"
)

func TestEvaluate(t *testing.T) {
	now := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	check := Check{MaxStale: 30 * time.Minute, Now: func() time.Time { return now }}

	tests := []struct {
		name   string
		source backend.Source
		want   Status
	}{
		{"fresh", backend.Source{Docs: 10, LastEvent: now.Add(-5 * time.Minute)}, StatusOK},
		{"boundary is not stale", backend.Source{Docs: 10, LastEvent: now.Add(-30 * time.Minute)}, StatusOK},
		{"stale", backend.Source{Docs: 10, LastEvent: now.Add(-31 * time.Minute)}, StatusStale},
		{"empty", backend.Source{Docs: 0}, StatusEmpty},
		{"unknown freshness", backend.Source{Docs: 10}, StatusUnknown},
		{"unknown docs and freshness", backend.Source{Docs: -1}, StatusUnknown},
	}
	for _, tt := range tests {
		if got := check.Evaluate(tt.source); got.Status != tt.want {
			t.Errorf("%s: Evaluate() = %s, want %s", tt.name, got.Status, tt.want)
		}
	}
}

func TestEvaluateDowntimeWindow(t *testing.T) {
	now := time.Date(2026, 7, 5, 2, 30, 0, 0, time.UTC) // Sunday
	check := Check{
		MaxStale: 30 * time.Minute,
		Now:      func() time.Time { return now },
		Downtime: []DowntimeWindow{{
			Name:     "patch",
			Patterns: []string{"logs-*"},
			Days:     map[time.Weekday]bool{time.Sunday: true},
			Start:    2 * time.Hour,
			End:      3 * time.Hour,
			Location: time.UTC,
		}},
	}

	got := check.Evaluate(backend.Source{Name: "logs-app", Docs: 10, LastEvent: now.Add(-2 * time.Hour)})
	if got.Status != StatusMaintenance || !got.ExpectedDowntime {
		t.Fatalf("downtime stale status = %+v, want maintenance", got)
	}

	ok := check.Evaluate(backend.Source{Name: "metrics-app", Docs: 10, LastEvent: now.Add(-2 * time.Hour)})
	if ok.Status != StatusStale {
		t.Fatalf("nonmatching source status = %s, want stale", ok.Status)
	}

	fresh := check.Evaluate(backend.Source{Name: "logs-app", Docs: 10, LastEvent: now.Add(-time.Minute)})
	if fresh.Status != StatusOK {
		t.Fatalf("fresh source status = %s, want ok even during downtime", fresh.Status)
	}
}

func TestDowntimeWindowOvernight(t *testing.T) {
	w := DowntimeWindow{
		Patterns: []string{"winlogbeat-*"},
		Start:    23 * time.Hour,
		End:      time.Hour,
		Location: time.UTC,
	}
	if !w.Matches("winlogbeat-2026", time.Date(2026, 7, 4, 23, 30, 0, 0, time.UTC)) {
		t.Fatal("23:30 should match overnight window")
	}
	if !w.Matches("winlogbeat-2026", time.Date(2026, 7, 5, 0, 30, 0, 0, time.UTC)) {
		t.Fatal("00:30 should match overnight window")
	}
	if w.Matches("winlogbeat-2026", time.Date(2026, 7, 5, 2, 0, 0, 0, time.UTC)) {
		t.Fatal("02:00 should not match overnight window")
	}
}

func TestDowntimeWindowOvernightWithDays(t *testing.T) {
	// Saturday-night maintenance, 22:00-02:00. The post-midnight tail lands
	// on Sunday's calendar day but belongs to Saturday's window.
	w := DowntimeWindow{
		Patterns: []string{"logs-*"},
		Days:     map[time.Weekday]bool{time.Saturday: true},
		Start:    22 * time.Hour,
		End:      2 * time.Hour,
		Location: time.UTC,
	}
	// 2026-07-04 is a Saturday; 07-05 a Sunday.
	cases := []struct {
		at   time.Time
		want bool
		desc string
	}{
		{time.Date(2026, 7, 4, 23, 0, 0, 0, time.UTC), true, "Saturday 23:00 inside window"},
		{time.Date(2026, 7, 5, 1, 0, 0, 0, time.UTC), true, "Sunday 01:00 is Saturday's post-midnight tail"},
		{time.Date(2026, 7, 5, 3, 0, 0, 0, time.UTC), false, "Sunday 03:00 outside window"},
		{time.Date(2026, 7, 3, 23, 0, 0, 0, time.UTC), false, "Friday 23:00 wrong day"},
		{time.Date(2026, 7, 5, 22, 30, 0, 0, time.UTC), false, "Sunday 22:30 wrong day (window is Saturday-start only)"},
	}
	for _, tc := range cases {
		if got := w.Matches("logs-app", tc.at); got != tc.want {
			t.Errorf("%s: Matches = %v, want %v", tc.desc, got, tc.want)
		}
	}
}

func TestDegraded(t *testing.T) {
	if !StatusStale.Degraded() || !StatusEmpty.Degraded() {
		t.Error("stale and empty must be findings")
	}
	if StatusUnknown.Degraded() || StatusOK.Degraded() {
		t.Error("ok and unknown must not be findings")
	}
}
