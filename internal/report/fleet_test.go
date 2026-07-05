package report

import (
	"encoding/json"
	"strings"
	"testing"
)

func fleetFixture() *FleetReport {
	a := &Report{Instance: "tenant-a", Backend: "elastic"}
	a.DeadDetections = []DeadDetection{{ID: "1", Name: "Shared dead rule", Severity: "high", Reason: "disconnected"}}
	a.Summary.DeadDetections = 1
	b := &Report{Instance: "tenant-b", Backend: "opensearch"}
	b.DeadDetections = []DeadDetection{{ID: "9", Name: "Shared dead rule", Severity: "high", Reason: "starved"}}
	b.ImpairedDetections = []ImpairedDetection{{ID: "7", Name: "Laggy rule", Severity: "medium", Reasons: []string{ReasonLagBlindWindow}}}
	b.Summary.DeadDetections = 1
	b.Summary.ImpairedDetections = 1
	return BuildFleet([]*Report{a, b}, nil)
}

func TestBuildFleetRollups(t *testing.T) {
	f := fleetFixture()
	if f.Summary.Instances != 2 || f.Summary.DeadDetections != 2 || f.Summary.ImpairedDetections != 1 {
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
}

func TestFleetRedactHidesInstanceNames(t *testing.T) {
	f := fleetFixture()
	f.Errors = []InstanceError{{Instance: "client-charlie", Error: "refused"}}
	f.Redact()
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
