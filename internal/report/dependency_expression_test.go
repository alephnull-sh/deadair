package report

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/alephnull-sh/deadair/internal/backend"
)

func TestDependencyProbeExpressionIsNeverSerialized(t *testing.T) {
	report := Report{DependencyEvidence: []DependencyEvidence{{
		RuleID: "rule-1",
		Dependency: backend.DependencyRef{
			ID:         "asim-dns",
			Name:       "_Im_Dns",
			Kind:       "sentinel_asim_parser",
			Expression: `_Im_Dns(domain_has_any=dynamic(["tenant.internal"]))`,
		},
		Status: backend.ResolutionResolved,
	}}}

	data, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "tenant.internal") || strings.Contains(string(data), "domain_has_any") {
		t.Fatalf("backend-private dependency expression leaked into report JSON: %s", data)
	}
}

func TestNegativeASIMDiagnosticBecomesDependencyEvidence(t *testing.T) {
	rules := []backend.Rule{{ID: "rule-1", Name: "DNS normalization", Severity: "medium"}}
	resolutions := []backend.InputResolution{{
		RuleID: "rule-1", Diagnostic: true, Status: backend.ResolutionUnavailable,
		ResolutionMethod: "kql_asim_native_probe+operational_insights_tables_diagnostic",
		Detail:           "ASIM parser query access is unavailable",
		ResolvedDependencies: []backend.DependencyRef{{
			ID: "sentinel_asim_parser:_im_dns", Name: "_Im_Dns", Kind: "sentinel_asim_parser", Required: true,
		}},
	}}
	evidence := buildDependencyEvidence(rules, resolutions, nil)
	if len(evidence) != 1 || evidence[0].Status != backend.ResolutionUnavailable ||
		evidence[0].Dependency.ID != "sentinel_asim_parser:_im_dns" || evidence[0].RuleName != "DNS normalization" {
		t.Fatalf("negative ASIM dependency evidence = %#v", evidence)
	}
	data, err := json.Marshal(evidence)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"status":"unavailable"`) || !strings.Contains(string(data), `"kind":"sentinel_asim_parser"`) {
		t.Fatalf("negative ASIM evidence was not retained in report JSON: %s", data)
	}
}
