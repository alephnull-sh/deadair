package report

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func fleetFixture() *FleetReport {
	a := &Report{
		SchemaVersion:   ReportSchemaVersion,
		Producer:        producer("1.2.3"),
		Instance:        "tenant-a",
		Backend:         "elastic",
		BackendMetadata: backendMetadata("elastic", "8.17.4"),
	}
	a.DeadDetections = []DeadDetection{{ID: "1", Name: "Shared dead rule", Severity: "high", Reason: "disconnected"}}
	a.Summary.DeadDetections = 1
	a.Summary.UnusedTelemetryAssessment = UnusedAssessmentComplete
	b := &Report{
		SchemaVersion:   ReportSchemaVersion,
		Producer:        producer("1.2.3"),
		Instance:        "tenant-b",
		Backend:         "opensearch",
		BackendMetadata: backendMetadata("opensearch", "2.19.3"),
	}
	b.DeadDetections = []DeadDetection{{ID: "9", Name: "Shared dead rule", Severity: "high", Reason: "starved"}}
	b.ImpairedDetections = []ImpairedDetection{{ID: "7", Name: "Laggy rule", Severity: "medium", Reasons: []string{ReasonLagBlindWindow}}}
	b.Summary.DeadDetections = 1
	b.Summary.ImpairedDetections = 1
	b.Summary.UnusedTelemetryAssessment = UnusedAssessmentComplete
	return BuildFleet([]*Report{a, b}, nil)
}

func TestBuildFleetRollups(t *testing.T) {
	f := fleetFixture()
	if f.SchemaVersion != FleetReportSchemaVersion || f.Producer != (Producer{Name: "deadair", Version: "1.2.3"}) {
		t.Fatalf("fleet contract metadata = %q / %+v", f.SchemaVersion, f.Producer)
	}
	if f.Instances[0].BackendMetadata.ObservedVersion != "8.17.4" || f.Instances[1].BackendMetadata.ObservedVersion != "2.19.3" {
		t.Fatalf("fleet changed nested backend metadata: %+v", f.Instances)
	}
	if f.Summary.Instances != 2 || f.Summary.DeadDetections != 2 || f.Summary.ImpairedDetections != 1 ||
		f.Summary.UnusedTelemetryAssessment != UnusedAssessmentComplete {
		t.Fatalf("summary = %+v", f.Summary)
	}
	// IDs differ per tenant; identity is the rule name.
	if f.Rollups[0].Name != "Shared dead rule" || f.Rollups[0].DeadIn != 2 || f.Rollups[0].Of != 2 {
		t.Fatalf("top rollup = %+v, want Shared dead rule dead in 2 of 2", f.Rollups[0])
	}
	if f.ExitCode() != ExitFindings {
		t.Errorf("exit = %d, want findings", f.ExitCode())
	}
}

func TestFleetErrorsAndExit(t *testing.T) {
	healthy := &Report{Instance: "a"}
	f := BuildFleet([]*Report{healthy}, []InstanceError{{Instance: "b", Error: "boom"}})
	if f.Summary.Instances != 2 || f.Summary.InstancesFailed != 1 {
		t.Fatalf("summary = %+v", f.Summary)
	}
	if f.ExitCode() != ExitError {
		t.Errorf("a failed instance must exit %d (incomplete scan), got %d", ExitError, f.ExitCode())
	}
	if BuildFleet([]*Report{healthy}, nil).ExitCode() != ExitHealthy {
		t.Error("healthy fleet must exit 0")
	}
	allFailed := BuildFleetWithVersion(nil, []InstanceError{{Instance: "b", Error: "boom"}}, "2.4.0")
	if allFailed.Producer.Version != "2.4.0" {
		t.Fatalf("all-failed fleet producer = %+v, want version 2.4.0", allFailed.Producer)
	}
	if allFailed.Summary.UnusedTelemetryAssessment != UnusedAssessmentUnavailable {
		t.Fatalf("all-failed fleet unused assessment = %q, want unavailable", allFailed.Summary.UnusedTelemetryAssessment)
	}
}

func TestFleetUnusedTelemetryAssessment(t *testing.T) {
	reportWith := func(assessment UnusedTelemetryAssessment) *Report {
		return &Report{Summary: Summary{UnusedTelemetryAssessment: assessment}}
	}
	tests := []struct {
		name      string
		instances []*Report
		want      UnusedTelemetryAssessment
	}{
		{"complete", []*Report{reportWith(UnusedAssessmentComplete), reportWith(UnusedAssessmentComplete)}, UnusedAssessmentComplete},
		{"legacy", []*Report{reportWith(UnusedAssessmentComplete), reportWith(UnusedAssessmentLegacy)}, UnusedAssessmentLegacy},
		{"unavailable", []*Report{reportWith(UnusedAssessmentComplete), reportWith(UnusedAssessmentUnavailable)}, UnusedAssessmentUnavailable},
		{"candidate", []*Report{reportWith(UnusedAssessmentNotApplicable)}, UnusedAssessmentNotApplicable},
		{"mixed candidate", []*Report{reportWith(UnusedAssessmentComplete), reportWith(UnusedAssessmentNotApplicable)}, UnusedAssessmentUnavailable},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := BuildFleet(tt.instances, nil).Summary.UnusedTelemetryAssessment
			if got != tt.want {
				t.Fatalf("assessment = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFleetCandidateExitCodeIgnoresUnrelatedSourceFindings(t *testing.T) {
	finding := &Report{Summary: Summary{DegradedSources: 2}}
	if got := BuildFleet([]*Report{finding}, nil).CandidateExitCode(); got != ExitHealthy {
		t.Fatalf("candidate fleet exit = %d, want healthy despite source degradation", got)
	}
	finding.Summary.ImpairedDetections = 1
	if got := BuildFleet([]*Report{finding}, nil).CandidateExitCode(); got != ExitFindings {
		t.Fatalf("impaired candidate fleet exit = %d, want findings", got)
	}
	finding.Summary.UnmappedRules = 1
	if got := BuildFleet([]*Report{finding}, nil).CandidateExitCode(); got != ExitError {
		t.Fatalf("unassessed candidate fleet exit = %d, want error", got)
	}
	if got := BuildFleet(nil, []InstanceError{{Instance: "x", Error: "failed"}}).CandidateExitCode(); got != ExitError {
		t.Fatalf("failed candidate fleet exit = %d, want error", got)
	}
}

func TestFleetRedactHidesInstanceNames(t *testing.T) {
	f := fleetFixture()
	f.Errors = []InstanceError{{Instance: "client-charlie", Error: "refused"}}
	wantProducer := f.Producer
	wantMetadata := []BackendMetadata{f.Instances[0].BackendMetadata, f.Instances[1].BackendMetadata}
	f.Redact()
	if f.Producer != wantProducer || !reflect.DeepEqual(f.Instances[0].BackendMetadata, wantMetadata[0]) || !reflect.DeepEqual(f.Instances[1].BackendMetadata, wantMetadata[1]) {
		t.Fatalf("fleet redaction changed contract metadata: %+v", f)
	}
	data, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{"tenant-a", "tenant-b", "client-charlie", "Shared dead rule"} {
		if strings.Contains(string(data), leak) {
			t.Errorf("redacted fleet report leaks %q", leak)
		}
	}
}
