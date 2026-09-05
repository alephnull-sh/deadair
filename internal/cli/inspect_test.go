package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/alephnull-sh/deadair/internal/backend"
	"github.com/alephnull-sh/deadair/internal/backend/elastic"
	"github.com/alephnull-sh/deadair/internal/backend/sentinel"
	"github.com/alephnull-sh/deadair/internal/report"
)

func TestInspectDoesNotPrintTerminalControls(t *testing.T) {
	var out bytes.Buffer
	printSourceImpact(&out, report.SourceImpact{Source: "x\x1b[2J", Status: "stale\x1b[2J", Freshness: []report.SourceObservation{{Basis: "event\x1b[2J", FreshnessStatus: "unknown\x1b[2J"}}}, 0, true)
	if strings.ContainsRune(out.String(), '\x1b') {
		t.Fatal("saved report can emit terminal escape sequences")
	}
}

func TestInspectRejectsTrailingDataBeforePrintingAReport(t *testing.T) {
	data, err := json.Marshal(report.Report{SchemaVersion: report.ReportSchemaVersion, Instance: "london-soc"})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(path, append(data, []byte("\n{}")...), 0600); err != nil {
		t.Fatal(err)
	}
	var out, errors bytes.Buffer
	if code := runInspect([]string{path}, &out, &errors); code != 2 || out.Len() != 0 || !strings.Contains(errors.String(), "trailing data") {
		t.Fatalf("invalid input printed a report: %d, %q, %q", code, out.String(), errors.String())
	}
}

func TestSourceInspectionUsesEvidenceAndFitsAnOrdinaryTerminal(t *testing.T) {
	var out bytes.Buffer
	printSourceImpact(&out, report.SourceImpact{Source: "endpoint-process-events-legacy", Status: "ok",
		MissingFields: []string{"process.command_line"},
		FirstCheck:    "Compare the missing fields with the source mapping and ingestion transform.",
		IngestLag:     &report.IngestLagHealth{Status: backend.EvidenceAssessed, SampleCount: 1},
		Detections:    []report.SourceConsumer{{Name: "PowerShell from legacy endpoints", Severity: "high", Status: "impaired"}},
	}, 0, false)
	text := out.String()
	for _, want := range []string{"— missing fields", "1 paired event)", "1 enabled detection reads", "process.command_line", "First check:"} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q: %s", want, text)
		}
	}
	for _, line := range strings.Split(text, "\n") {
		if utf8.RuneCountInString(line) > 80 {
			t.Errorf("inspection line exceeds 80 columns: %s", line)
		}
	}
}

func TestNativeLinksUseTheScannedFleetInstance(t *testing.T) {
	o := connOpts{backendName: "elastic", esURL: "https://wrong.example", kibanaURL: "https://wrong.example"}
	e := o.navigationFor(&elastic.Client{ESURL: "https://es.customer.example", KibanaURL: "https://soc.customer.example", Space: "ops"})
	if !strings.HasPrefix(e.sourceURL("logs"), "https://es.customer.example/") || !strings.Contains(e.ruleURL(backend.Rule{BackendObjectID: "id"}), "soc.customer.example/s/ops/") {
		t.Fatal("Elastic links used another target")
	}
	s := o.navigationFor(&sentinel.Client{SubscriptionID: "customer-sub", ResourceGroup: "customer-rg", WorkspaceName: "customer-soc"})
	if link := s.sourceURL("CommonSecurityLog"); !strings.Contains(link, "/subscriptions/customer-sub/resourceGroups/customer-rg/") || strings.Contains(link, "wrong.example") {
		t.Fatalf("Sentinel link used another target: %s", link)
	}
}

func TestInspectSavedSourceAndProducer(t *testing.T) {
	r := report.Report{SchemaVersion: report.ReportSchemaVersion, SourceImpacts: []report.SourceImpact{{Source: "CommonSecurityLog", Status: "stale", Detections: []report.SourceConsumer{{RuleID: "r", Name: "Firewall rule", Severity: "high", Status: "consumes_source"}}}}, Producers: []report.ProducerHealth{{ID: "edge-fw", Source: "CommonSecurityLog", MaxStaleSeconds: 900, Observation: report.SourceObservation{Basis: backend.FreshnessIngestionTime, Status: backend.EvidenceAssessed, FreshnessStatus: "stale"}}}}
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		args []string
		code int
		want string
	}{{[]string{"--source", "CommonSecurityLog", path}, 0, "Firewall rule"}, {[]string{"--producer", "edge-fw", path}, 0, "Expected at least once every"}, {[]string{"--source", "missing", path}, 2, ""}} {
		var out, errors bytes.Buffer
		if code := Run(append([]string{"inspect"}, tc.args...), &out, &errors); code != tc.code {
			t.Fatalf("exit=%d: %s", code, errors.String())
		}
		if !strings.Contains(out.String(), tc.want) {
			t.Fatalf("output=%s", out.String())
		}
	}
}

func TestInspectFleetRequiresAnExactSuccessfulInstance(t *testing.T) {
	fleet := report.FleetReport{SchemaVersion: report.FleetReportSchemaVersion,
		Instances: []*report.Report{{SchemaVersion: report.ReportSchemaVersion, Instance: "london-soc", Backend: "sentinel", SourceImpacts: []report.SourceImpact{{Source: "CommonSecurityLog", Status: "ok"}}}},
		Errors:    []report.InstanceError{{Instance: "offline-soc", Error: "private upstream detail"}},
	}
	data, err := json.Marshal(fleet)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "fleet.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		instance string
		code     int
		want     string
	}{
		{"", 2, "select a saved instance"}, {"offline-soc", 2, "scan failed"},
		{"london-soc", 0, "Instance: london-soc"}, {"unknown-soc", 2, "Available: london-soc"},
	} {
		var out, errors bytes.Buffer
		code := runInspect([]string{"--instance", tc.instance, "--source", "CommonSecurityLog", path}, &out, &errors)
		text := out.String() + errors.String()
		if code != tc.code || !strings.Contains(text, tc.want) || strings.Contains(text, "private upstream") {
			t.Fatalf("%s: exit %d, output %s", tc.instance, code, text)
		}
	}
}

func TestProducerWithoutSourceCardsIsStillVisible(t *testing.T) {
	r := &report.Report{Backend: "sentinel", Producers: []report.ProducerHealth{{ID: "edge-fw", Source: "CommonSecurityLog", MaxStaleSeconds: 900, Observation: report.SourceObservation{FreshnessStatus: "unknown"}}}}
	for _, render := range []func(io.Writer, *report.Report){printPlainSummary, printVisualSummary} {
		var out bytes.Buffer
		render(&out, r)
		if !strings.Contains(out.String(), "edge-fw") || !strings.Contains(out.String(), "unknown") {
			t.Fatal(out.String())
		}
	}
}

func TestNativeLinksDropCredentialsAndEscapeIdentities(t *testing.T) {
	o := connOpts{backendName: "elastic", kibanaURL: "https://user:secret@kibana.example/base?token=secret#private", esURL: "https://user:secret@es.example", kibanaSpace: "SOC team"}
	rule := o.ruleURL(backend.Rule{BackendObjectID: "one/two"})
	if rule != "https://kibana.example/base/s/SOC%20team/app/security/rules/id/one%2Ftwo" {
		t.Fatal(rule)
	}
	if strings.Contains(o.sourceURL("logs-*"), "secret") {
		t.Fatal("credentials in source link")
	}
	o.ruleFile = "candidate.ndjson"
	if o.ruleURL(backend.Rule{BackendObjectID: "id"}) != "" {
		t.Fatal("candidate linked to an installed rule")
	}
}
