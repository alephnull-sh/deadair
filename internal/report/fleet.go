package report

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"
)

// FleetReport aggregates per-instance (per-tenant / per-SIEM) reports with
// cross-instance rollups. Instance names can be client identities (MSSPs):
// Redact digests them like everything else.
type FleetReport struct {
	GeneratedAt time.Time       `json:"generated_at"`
	Redacted    bool            `json:"redacted,omitempty"`
	Summary     FleetSummary    `json:"summary"`
	Rollups     []FleetRollup   `json:"rollups,omitempty"`
	Errors      []InstanceError `json:"errors,omitempty"`
	Instances   []*Report       `json:"instances"`
}

// InstanceError records a fleet member whose scan failed entirely.
type InstanceError struct {
	Instance string `json:"instance"`
	Error    string `json:"error"`
}

// FleetSummary rolls the per-instance summaries up.
type FleetSummary struct {
	Instances          int   `json:"instances"`
	InstancesFailed    int   `json:"instances_failed,omitempty"`
	DeadDetections     int   `json:"dead_detections"`
	ImpairedDetections int   `json:"impaired_detections,omitempty"`
	DegradedSources    int   `json:"degraded_sources"`
	UnusedBytes        int64 `json:"unused_bytes"`
}

// FleetRollup is one rule identity (matched by name, since IDs differ per
// tenant) counted across instances: "dead in 3 of 12".
type FleetRollup struct {
	Name       string `json:"name"`
	Severity   string `json:"severity"`
	DeadIn     int    `json:"dead_in,omitempty"`
	ImpairedIn int    `json:"impaired_in,omitempty"`
	Of         int    `json:"of"`
}

// BuildFleet assembles the fleet view from per-instance reports.
func BuildFleet(instances []*Report, errs []InstanceError) *FleetReport {
	f := &FleetReport{GeneratedAt: time.Now().UTC(), Instances: instances, Errors: errs}
	f.Summary.Instances = len(instances) + len(errs)
	f.Summary.InstancesFailed = len(errs)

	type agg struct {
		severity       string
		dead, impaired int
	}
	rules := map[string]*agg{}
	for _, r := range instances {
		f.Summary.DeadDetections += r.Summary.DeadDetections
		f.Summary.ImpairedDetections += r.Summary.ImpairedDetections
		f.Summary.DegradedSources += r.Summary.DegradedSources
		f.Summary.UnusedBytes += r.Summary.UnusedBytes
		for _, d := range r.DeadDetections {
			a := rules[d.Name]
			if a == nil {
				a = &agg{severity: d.Severity}
				rules[d.Name] = a
			}
			a.dead++
		}
		for _, d := range r.ImpairedDetections {
			a := rules[d.Name]
			if a == nil {
				a = &agg{severity: d.Severity}
				rules[d.Name] = a
			}
			a.impaired++
		}
	}
	for name, a := range rules {
		f.Rollups = append(f.Rollups, FleetRollup{
			Name: name, Severity: a.severity,
			DeadIn: a.dead, ImpairedIn: a.impaired, Of: len(instances),
		})
	}
	sort.Slice(f.Rollups, func(i, j int) bool {
		a, b := f.Rollups[i], f.Rollups[j]
		if a.DeadIn != b.DeadIn {
			return a.DeadIn > b.DeadIn
		}
		if rank(a.Severity) != rank(b.Severity) {
			return rank(a.Severity) < rank(b.Severity)
		}
		return a.Name < b.Name
	})
	return f
}

// ExitCode: any failed instance is an incomplete scan (2); otherwise findings
// in any instance gate as usual.
func (f *FleetReport) ExitCode() int {
	if len(f.Errors) > 0 {
		return ExitError
	}
	for _, r := range f.Instances {
		if r.ExitCode() == ExitFindings {
			return ExitFindings
		}
	}
	return ExitHealthy
}

// Write writes the JSON fleet report to path with 0600 permissions.
func (f *FleetReport) Write(path string) error {
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding fleet report: %w", err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		return fmt.Errorf("writing fleet report: %w", err)
	}
	return nil
}

// Redact digests instance names (MSSP client identities) and everything the
// per-instance reports redact.
func (f *FleetReport) Redact() {
	if f.Redacted {
		return
	}
	f.Redacted = true
	for _, r := range f.Instances {
		r.Instance = redact("ten", r.Instance)
		r.Redact()
	}
	for i := range f.Errors {
		f.Errors[i].Instance = redact("ten", f.Errors[i].Instance)
	}
	for i := range f.Rollups {
		f.Rollups[i].Name = redact("rule", f.Rollups[i].Name)
	}
}
