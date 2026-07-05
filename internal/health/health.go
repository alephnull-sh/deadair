// Package health evaluates per-source telemetry health. v0 is a fixed
// freshness window; seasonality-aware baselines with warmup and hysteresis
// are the L1 design (see docs/architecture.md) — until then, defaults stay
// conservative so the monitor doesn't become its own alert-fatigue problem.
package health

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Big-Comfy/deadair/internal/backend"
)

// Status is the health verdict for a source.
type Status string

const (
	StatusOK      Status = "ok"      // events arriving within the freshness window
	StatusStale   Status = "stale"   // has data, but nothing recent
	StatusEmpty   Status = "empty"   // exists but holds no documents
	StatusUnknown Status = "unknown" // freshness could not be determined
	// StatusMaintenance means the source is in an expected downtime window.
	// It suppresses stale/empty findings for that source.
	StatusMaintenance Status = "maintenance"
)

// Degraded reports whether the status counts as a finding. Unknown is
// deliberately not a finding: a source we cannot date must not page anyone.
func (s Status) Degraded() bool { return s == StatusStale || s == StatusEmpty }

// Assessment is the evaluated health of a single source.
type Assessment struct {
	Status           Status
	Age              time.Duration // time since last event; 0 when unknown
	ExpectedDowntime bool
}

// Check evaluates source health. Now is injectable for tests.
type Check struct {
	MaxStale time.Duration
	Now      func() time.Time
	Downtime []DowntimeWindow
}

// DowntimeWindow is an expected source outage window.
type DowntimeWindow struct {
	Name     string
	Patterns []string
	Days     map[time.Weekday]bool // empty means every day
	Start    time.Duration
	End      time.Duration
	Location *time.Location
}

// Evaluate returns the health assessment for one source.
func (c Check) Evaluate(s backend.Source) Assessment {
	now := time.Now
	if c.Now != nil {
		now = c.Now
	}
	t := now()
	inDowntime := c.InDowntime(s.Name, t)
	if s.Docs == 0 {
		if inDowntime {
			return Assessment{Status: StatusMaintenance, ExpectedDowntime: true}
		}
		return Assessment{Status: StatusEmpty}
	}
	if s.LastEvent.IsZero() {
		return Assessment{Status: StatusUnknown}
	}
	age := t.Sub(s.LastEvent)
	if age > c.MaxStale {
		if inDowntime {
			return Assessment{Status: StatusMaintenance, Age: age, ExpectedDowntime: true}
		}
		return Assessment{Status: StatusStale, Age: age}
	}
	return Assessment{Status: StatusOK, Age: age}
}

// InDowntime reports whether the source is inside any declared downtime
// window at t. Exported so the volume-baseline path can suppress findings for
// the same declared windows freshness already honors.
func (c Check) InDowntime(source string, t time.Time) bool {
	for _, w := range c.Downtime {
		if w.Matches(source, t) {
			return true
		}
	}
	return false
}

// Matches reports whether source is inside this expected downtime window.
func (w DowntimeWindow) Matches(source string, t time.Time) bool {
	if len(w.Patterns) == 0 || !matchAny(w.Patterns, source) {
		return false
	}
	loc := w.Location
	if loc == nil {
		loc = time.UTC
	}
	local := t.In(loc)
	clock := time.Duration(local.Hour())*time.Hour + time.Duration(local.Minute())*time.Minute + time.Duration(local.Second())*time.Second
	if len(w.Days) > 0 {
		day := local.Weekday()
		// The post-midnight tail of an overnight window belongs to the day
		// the window started, not the calendar day of the instant.
		if w.Start > w.End && clock < w.End {
			day = time.Weekday((int(day) + 6) % 7)
		}
		if !w.Days[day] {
			return false
		}
	}
	if w.Start <= w.End {
		return clock >= w.Start && clock < w.End
	}
	return clock >= w.Start || clock < w.End
}

type downtimeFile struct {
	Windows []downtimeWindow `json:"windows"`
}

type downtimeWindow struct {
	Name     string   `json:"name"`
	Sources  []string `json:"sources"`
	Days     []string `json:"days,omitempty"`
	Start    string   `json:"start"`
	End      string   `json:"end"`
	Timezone string   `json:"timezone,omitempty"`
}

// LoadDowntimeFile reads expected downtime windows from JSON.
func LoadDowntimeFile(path string) ([]DowntimeWindow, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading downtime file: %w", err)
	}
	var in downtimeFile
	if err := json.Unmarshal(data, &in); err != nil {
		return nil, fmt.Errorf("parsing downtime file: %w", err)
	}
	out := make([]DowntimeWindow, 0, len(in.Windows))
	for i, w := range in.Windows {
		parsed, err := parseDowntimeWindow(w)
		if err != nil {
			return nil, fmt.Errorf("downtime window %d: %w", i+1, err)
		}
		out = append(out, parsed)
	}
	return out, nil
}

func parseDowntimeWindow(w downtimeWindow) (DowntimeWindow, error) {
	if len(w.Sources) == 0 {
		return DowntimeWindow{}, fmt.Errorf("sources is required")
	}
	start, err := parseClock(w.Start)
	if err != nil {
		return DowntimeWindow{}, fmt.Errorf("start: %w", err)
	}
	end, err := parseClock(w.End)
	if err != nil {
		return DowntimeWindow{}, fmt.Errorf("end: %w", err)
	}
	if start == end {
		return DowntimeWindow{}, fmt.Errorf("start and end must differ")
	}
	loc := time.UTC
	if w.Timezone != "" {
		loc, err = time.LoadLocation(w.Timezone)
		if err != nil {
			return DowntimeWindow{}, fmt.Errorf("timezone: %w", err)
		}
	}
	days := map[time.Weekday]bool{}
	for _, d := range w.Days {
		day, err := parseWeekday(d)
		if err != nil {
			return DowntimeWindow{}, err
		}
		days[day] = true
	}
	return DowntimeWindow{
		Name:     w.Name,
		Patterns: w.Sources,
		Days:     days,
		Start:    start,
		End:      end,
		Location: loc,
	}, nil
}

func parseClock(value string) (time.Duration, error) {
	t, err := time.Parse("15:04", value)
	if err != nil {
		return 0, fmt.Errorf("want HH:MM: %w", err)
	}
	return time.Duration(t.Hour())*time.Hour + time.Duration(t.Minute())*time.Minute, nil
}

func parseWeekday(value string) (time.Weekday, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "sun", "sunday":
		return time.Sunday, nil
	case "mon", "monday":
		return time.Monday, nil
	case "tue", "tues", "tuesday":
		return time.Tuesday, nil
	case "wed", "wednesday":
		return time.Wednesday, nil
	case "thu", "thur", "thurs", "thursday":
		return time.Thursday, nil
	case "fri", "friday":
		return time.Friday, nil
	case "sat", "saturday":
		return time.Saturday, nil
	default:
		return 0, fmt.Errorf("unknown day %q", value)
	}
}

func matchAny(patterns []string, name string) bool {
	for _, p := range patterns {
		if match(p, name) {
			return true
		}
	}
	return false
}

func match(pattern, name string) bool {
	px, nx := 0, 0
	star, mark := -1, 0
	for nx < len(name) {
		switch {
		case px < len(pattern) && pattern[px] == '*':
			star, mark = px, nx
			px++
		case px < len(pattern) && pattern[px] == name[nx]:
			px++
			nx++
		case star >= 0:
			mark++
			px, nx = star+1, mark
		default:
			return false
		}
	}
	for px < len(pattern) && pattern[px] == '*' {
		px++
	}
	return px == len(pattern)
}
