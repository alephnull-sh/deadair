package report

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	redactpkg "github.com/alephnull-sh/deadair/internal/redact"
	"github.com/alephnull-sh/deadair/internal/securefile"
)

// FleetReport aggregates per-instance (per-tenant / per-SIEM) reports with
// cross-instance rollups. Instance names can be client identities (MSSPs):
// Redact pseudonymizes them like everything else.
type FleetReport struct {
	SchemaVersion string             `json:"schema_version"`
	GeneratedAt   time.Time          `json:"generated_at"`
	Producer      Producer           `json:"producer"`
	Redacted      bool               `json:"redacted,omitempty"`
	Redaction     *RedactionMetadata `json:"redaction,omitempty"`
	Summary       FleetSummary       `json:"summary"`
	Rollups       []FleetRollup      `json:"rollups,omitempty"`
	Errors        []InstanceError    `json:"errors,omitempty"`
	Instances     []*Report          `json:"instances"`
}

// InstanceError records a fleet member whose scan failed entirely.
type InstanceError struct {
	Instance string `json:"instance"`
	Error    string `json:"error"`
}

// FleetSummary rolls the per-instance summaries up.
type FleetSummary struct {
	Instances                 int                       `json:"instances"`
	InstancesFailed           int                       `json:"instances_failed,omitempty"`
	DeadDetections            int                       `json:"dead_detections"`
	ImpairedDetections        int                       `json:"impaired_detections,omitempty"`
	PartialInputs             int                       `json:"partial_inputs,omitempty"`
	DegradedSources           int                       `json:"degraded_sources"`
	UnusedBytes               int64                     `json:"unused_bytes"`
	UnusedTelemetryAssessment UnusedTelemetryAssessment `json:"unused_telemetry_assessment"`
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
	return BuildFleetWithVersion(instances, errs, "")
}

// BuildFleetWithVersion assembles a fleet report with an explicit producer
// version, including when every instance failed before producing a report.
func BuildFleetWithVersion(instances []*Report, errs []InstanceError, producerVersion string) *FleetReport {
	if len(instances) > 0 {
		if producerVersion == "" {
			producerVersion = instances[0].Producer.Version
		}
	}
	f := &FleetReport{
		SchemaVersion: FleetReportSchemaVersion,
		GeneratedAt:   time.Now().UTC(),
		Producer:      producer(producerVersion),
		Instances:     instances,
		Errors:        errs,
	}
	f.Summary.Instances = len(instances) + len(errs)
	f.Summary.InstancesFailed = len(errs)
	f.Summary.UnusedTelemetryAssessment = fleetUnusedTelemetryAssessment(instances, errs)

	type agg struct {
		severity       string
		dead, impaired int
	}
	rules := map[string]*agg{}
	for _, r := range instances {
		f.Summary.DeadDetections += r.Summary.DeadDetections
		f.Summary.ImpairedDetections += r.Summary.ImpairedDetections
		f.Summary.PartialInputs += r.Summary.PartialInputs
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

func fleetUnusedTelemetryAssessment(instances []*Report, errs []InstanceError) UnusedTelemetryAssessment {
	if len(errs) > 0 || len(instances) == 0 {
		return UnusedAssessmentUnavailable
	}
	sawAssessed, sawNotApplicable, sawLegacy := false, false, false
	for _, instance := range instances {
		switch instance.Summary.UnusedTelemetryAssessment {
		case UnusedAssessmentComplete:
			sawAssessed = true
		case UnusedAssessmentLegacy:
			sawAssessed, sawLegacy = true, true
		case UnusedAssessmentNotApplicable:
			sawNotApplicable = true
		default:
			return UnusedAssessmentUnavailable
		}
	}
	if sawNotApplicable {
		if sawAssessed {
			return UnusedAssessmentUnavailable
		}
		return UnusedAssessmentNotApplicable
	}
	if sawLegacy {
		return UnusedAssessmentLegacy
	}
	return UnusedAssessmentComplete
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

// CandidateExitCode evaluates only candidate-rule outcomes across the fleet.
// Instance errors or unassessed candidates make the gate incomplete (2);
// unrelated source-health findings do not fail it.
func (f *FleetReport) CandidateExitCode() int {
	if len(f.Errors) > 0 {
		return ExitError
	}
	result := ExitHealthy
	for _, r := range f.Instances {
		switch r.CandidateExitCode() {
		case ExitError:
			return ExitError
		case ExitFindings:
			result = ExitFindings
		}
	}
	return result
}

// Write writes the JSON fleet report to path with 0600 permissions on POSIX.
func (f *FleetReport) Write(path string) error {
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding fleet report: %w", err)
	}
	if err := securefile.Write(path, append(data, '\n')); err != nil {
		return fmt.Errorf("writing fleet report: %w", err)
	}
	return nil
}

// Redact pseudonymizes instance names (MSSP client identities) and everything the
// per-instance reports redact.
func (f *FleetReport) Redact() {
	f.RedactWith(redactpkg.Default())
}

// RedactWith applies caller-keyed HMAC pseudonyms to the fleet and removes
// backend error details that may contain hosts, paths, or response bodies.
func (f *FleetReport) RedactWith(redactor *redactpkg.Redactor) {
	if f.Redacted {
		return
	}
	f.Redacted = true
	f.Redaction = &RedactionMetadata{Algorithm: redactpkg.Algorithm, KeyID: redactor.KeyID()}
	for _, r := range f.Instances {
		r.RedactWith(redactor)
	}
	for i := range f.Errors {
		f.Errors[i].Instance = redactor.Value("ten", f.Errors[i].Instance)
		f.Errors[i].Error = SanitizeScanError(f.Errors[i].Error)
	}
	for i := range f.Rollups {
		f.Rollups[i].Name = redactor.Value("rule", f.Rollups[i].Name)
	}
}

// SanitizeScanError reduces a backend or transport failure to a fixed category
// that is safe to print with redacted output.
func SanitizeScanError(detail string) string {
	lower := strings.ToLower(detail)
	switch {
	case strings.Contains(lower, "deadline exceeded"), strings.Contains(lower, "timed out"), strings.Contains(lower, "timeout"):
		return "scan timed out"
	case strings.Contains(lower, "status 403"), strings.Contains(lower, "forbidden"), strings.Contains(lower, "permission"):
		return "authorization failed"
	case strings.Contains(lower, "status 401"), strings.Contains(lower, "unauthorized"), strings.Contains(lower, "authentication"), strings.Contains(lower, "api key"):
		return "authentication failed"
	case strings.Contains(lower, "x509"), strings.Contains(lower, "tls"), strings.Contains(lower, "certificate"):
		return "TLS verification failed"
	case strings.Contains(lower, "connection refused"), strings.Contains(lower, "no such host"), strings.Contains(lower, "network is unreachable"), strings.Contains(lower, "dial tcp"):
		return "connection failed"
	default:
		return "scan failed"
	}
}
