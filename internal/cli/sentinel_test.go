package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	backendpkg "github.com/alephnull-sh/deadair/internal/backend"
	"github.com/alephnull-sh/deadair/internal/backend/sentinel"
	"github.com/alephnull-sh/deadair/internal/report"
)

type sentinelReportProbe struct {
	requestedFreshness []string
	freshnessErr       error
	freshness          backendpkg.FreshnessEvidence
	refreshErr         error
	refreshes          int
	ruleReads          int
	candidateReads     int
	candidateData      string
}

type policyFreshnessProbe struct {
	sentinelReportProbe
	requests []backendpkg.FreshnessRequest
}

func (p *policyFreshnessProbe) FreshnessEvidenceFor(ctx context.Context, requests []backendpkg.FreshnessRequest) (map[string]backendpkg.FreshnessEvidence, error) {
	p.requests = append([]backendpkg.FreshnessRequest(nil), requests...)
	sources := make([]backendpkg.Source, 0, len(requests))
	for _, request := range requests {
		sources = append(sources, request.Source)
	}
	return p.FreshnessEvidence(ctx, sources)
}

func TestSentinelSourcePolicyControlsFreshnessCompleteness(t *testing.T) {
	for _, ruleAware := range []bool{false, true} {
		for _, tc := range []struct {
			name       string
			global     time.Duration
			threshold  string
			lastEvent  time.Time
			wantSource string
			wantStatus backendpkg.EvidenceStatus
			wantExit   int
		}{
			{"shorter source threshold", 48 * time.Hour, "1h", time.Time{}, "stale", backendpkg.EvidenceAssessed, report.ExitFindings},
			{"threshold beyond evidence", 30 * time.Minute, "48h", time.Time{}, "unknown", backendpkg.EvidenceIncomplete, report.ExitError},
			{"threshold equals evidence", 30 * time.Minute, "24h", time.Time{}, "stale", backendpkg.EvidenceAssessed, report.ExitFindings},
			{"recent event with longer threshold", time.Hour, "48h", time.Now().UTC().Add(-time.Minute), "ok", backendpkg.EvidenceAssessed, report.ExitHealthy},
		} {
			t.Run(fmt.Sprintf("rule-aware=%t/%s", ruleAware, tc.name), func(t *testing.T) {
				dir := t.TempDir()
				policyPath, candidatePath := filepath.Join(dir, "policy.json"), filepath.Join(dir, "candidate.json")
				policy := fmt.Sprintf(`{"version":1,"gate_classes":["dead-detection"],"sources":[{"pattern":"Security*","max_stale":%q}]}`, tc.threshold)
				if err := os.WriteFile(policyPath, []byte(policy), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(candidatePath, []byte(`{"name":"candidate"}`), 0600); err != nil {
					t.Fatal(err)
				}
				probe := &policyFreshnessProbe{sentinelReportProbe: sentinelReportProbe{freshness: backendpkg.FreshnessEvidence{
					Status: backendpkg.EvidenceAssessed, Method: "bounded-max-event-time",
					ObservedAt: time.Now().UTC(), Window: 24 * time.Hour, LastEvent: tc.lastEvent,
				}}}
				var scanner backendpkg.Backend = &probe.sentinelReportProbe
				if ruleAware {
					scanner = probe
				}
				result, err := scanOnce(context.Background(), scanner, connOpts{maxStale: tc.global, policyFile: policyPath, ruleFile: candidatePath}, "prod", "target-sentinel")
				if err != nil {
					t.Fatal(err)
				}
				if ruleAware {
					threshold, _ := time.ParseDuration(tc.threshold)
					if len(probe.requests) != 1 || probe.requests[0].Window != threshold {
						t.Errorf("freshness requests = %+v, want source threshold %s", probe.requests, threshold)
					}
				}
				r := result.report
				if len(r.Sources) != 1 || r.Sources[0].Status != tc.wantSource || r.CandidateExitCode() != tc.wantExit {
					t.Errorf("sources=%+v candidate exit=%d; want %s, exit %d", r.Sources, r.CandidateExitCode(), tc.wantSource, tc.wantExit)
				}
				for _, assessment := range r.Assessments {
					if assessment.Name == report.AssessmentSourceFreshness {
						if assessment.Status != tc.wantStatus {
							t.Errorf("freshness assessment=%+v, want %s", assessment, tc.wantStatus)
						}
						return
					}
				}
				t.Fatal("source freshness assessment missing")
			})
		}
	}
}

func (*sentinelReportProbe) Name() string { return "sentinel" }

func (b *sentinelReportProbe) RefreshForScan(context.Context) error {
	b.refreshes++
	return b.refreshErr
}

func (b *sentinelReportProbe) Rules(context.Context) ([]backendpkg.Rule, error) {
	b.ruleReads++
	return []backendpkg.Rule{{
		ID: "rule-1", Name: "Rule 1", Enabled: true, Severity: "medium", Patterns: []string{"SecurityEvent"},
	}}, nil
}

func (b *sentinelReportProbe) ParseCandidates(_ context.Context, data []byte) ([]backendpkg.Rule, error) {
	b.candidateReads++
	b.candidateData = string(data)
	return []backendpkg.Rule{{
		ID: "candidate-rule", Name: "Candidate rule", Enabled: true, Severity: "medium", Patterns: []string{"SecurityEvent"},
	}}, nil
}

func TestScanRefreshesReusedBackendBeforeReadingInventory(t *testing.T) {
	probe := &sentinelReportProbe{}
	for range 2 {
		if _, err := scanOnce(context.Background(), probe, connOpts{maxStale: time.Hour}, "lab", "target-sentinel"); err != nil {
			t.Fatal(err)
		}
	}
	if probe.refreshes != 2 || probe.ruleReads != 2 {
		t.Fatalf("reused backend refreshes/rule reads = %d/%d, want 2/2", probe.refreshes, probe.ruleReads)
	}

	refreshErr := errors.New("metadata refresh failed")
	blocked := &sentinelReportProbe{refreshErr: refreshErr}
	if _, err := scanOnce(context.Background(), blocked, connOpts{maxStale: time.Hour}, "lab", "target-sentinel"); !errors.Is(err, refreshErr) || blocked.refreshes != 1 || blocked.ruleReads != 0 {
		t.Fatalf("refresh failure = %v, refreshes/rule reads = %d/%d", err, blocked.refreshes, blocked.ruleReads)
	}
}

func (*sentinelReportProbe) Sources(context.Context) ([]backendpkg.Source, error) {
	return []backendpkg.Source{
		{Name: "SecurityEvent", Docs: -1},
		{Name: "Heartbeat", Docs: -1},
	}, nil
}

func (*sentinelReportProbe) Schemas(context.Context, []backendpkg.Source) (map[string]backendpkg.Schema, error) {
	return nil, nil
}

func (*sentinelReportProbe) ResolveInputs(_ context.Context, rules []backendpkg.Rule) ([]backendpkg.InputResolution, error) {
	return []backendpkg.InputResolution{{
		RuleID: rules[0].ID, Selector: "SecurityEvent", Status: backendpkg.ResolutionResolved,
		ResolvedSources: []string{"SecurityEvent"}, ObservedAt: time.Now().UTC(),
	}}, nil
}

func (b *sentinelReportProbe) FreshnessEvidence(_ context.Context, sources []backendpkg.Source) (map[string]backendpkg.FreshnessEvidence, error) {
	if b.freshnessErr != nil {
		return nil, b.freshnessErr
	}
	out := make(map[string]backendpkg.FreshnessEvidence, len(sources))
	for _, source := range sources {
		b.requestedFreshness = append(b.requestedFreshness, source.Name)
		evidence := b.freshness
		if evidence.Status == "" {
			evidence = backendpkg.FreshnessEvidence{
				Status: backendpkg.EvidenceAssessed, Method: "bounded-max-timegenerated",
				ObservedAt: time.Now().UTC(), Window: 24 * time.Hour, LastEvent: time.Now().UTC(),
			}
		}
		out[source.Name] = evidence
	}
	return out, nil
}

func TestSentinelBackendFlagsUseEnvironmentAndDefaultCredential(t *testing.T) {
	t.Setenv("DEADAIR_BACKEND", "sentinel")
	t.Setenv("DEADAIR_AZURE_SUBSCRIPTION_ID", "subscription-a")
	t.Setenv("DEADAIR_AZURE_RESOURCE_GROUP", "detections-rg")
	t.Setenv("DEADAIR_SENTINEL_WORKSPACE", "sentinel-lab")

	var opts connOpts
	fs := flag.NewFlagSet("sentinel", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	addBackendFlags(fs, &opts)
	if err := fs.Parse(nil); err != nil {
		t.Fatal(err)
	}
	got, err := opts.client(io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	client, ok := got.(*sentinel.Client)
	if !ok {
		t.Fatalf("client = %T, want *sentinel.Client", got)
	}
	if client.SubscriptionID != "subscription-a" || client.ResourceGroup != "detections-rg" ||
		client.WorkspaceName != "sentinel-lab" || client.WorkspaceID != "" {
		t.Fatalf("Sentinel client coordinates = %+v", client)
	}
	if client.Credential == nil {
		t.Fatal("Sentinel client did not initialize DefaultAzureCredential")
	}
}

func TestSentinelTargetIDUsesStableWorkspaceCoordinates(t *testing.T) {
	a := sentinelTargetID("SUBSCRIPTION-A", "Detections-RG", "Sentinel-Lab")
	b := sentinelTargetID("subscription-a", "detections-rg", "sentinel-lab")
	if a != b {
		t.Fatalf("Azure coordinate casing changed target ID: %q != %q", a, b)
	}
	if a == sentinelTargetID("subscription-a", "detections-rg", "other-workspace") {
		t.Fatal("workspace name did not affect Sentinel target ID")
	}
}

func TestAssessmentConfigurationIDUsesResolvedSentinelRemoteMappings(t *testing.T) {
	base, err := assessmentConfigurationID(connOpts{}, &sentinel.Client{})
	if err != nil {
		t.Fatal(err)
	}
	withRemote, err := assessmentConfigurationID(connOpts{}, &sentinel.Client{RemoteWorkspaces: []sentinel.RemoteWorkspace{{
		Alias: "soc", SubscriptionID: "remote-sub", ResourceGroup: "remote-rg", WorkspaceName: "remote-law",
	}}})
	if err != nil {
		t.Fatal(err)
	}
	if base == withRemote {
		t.Fatal("resolved Sentinel remote mapping did not affect assessment identity")
	}
}

func TestAssessmentConfigurationIDIgnoresSentinelRemoteFileForOtherBackends(t *testing.T) {
	id, err := assessmentConfigurationID(connOpts{sentinelRemotesFile: filepath.Join(t.TempDir(), "missing.json")}, nil)
	if err != nil {
		t.Fatalf("non-Sentinel assessment read Sentinel remotes: %v", err)
	}
	const legacyID = "config-bda510fc298c3f9a1c65"
	if id != legacyID {
		t.Fatalf("non-Sentinel assessment ID = %q, want v0.6-compatible %q", id, legacyID)
	}
}

func TestSentinelRemoteMappingsLoadFromEnvironmentAndAffectIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "remotes.json")
	data := []byte(`[{"alias":"soc","azure_subscription_id":"remote-sub","azure_resource_group":"remote-rg","sentinel_workspace":"remote-law"}]`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DEADAIR_BACKEND", "sentinel")
	t.Setenv("DEADAIR_AZURE_SUBSCRIPTION_ID", "subscription-a")
	t.Setenv("DEADAIR_AZURE_RESOURCE_GROUP", "detections-rg")
	t.Setenv("DEADAIR_SENTINEL_WORKSPACE", "sentinel-lab")
	t.Setenv("DEADAIR_SENTINEL_REMOTES", path)
	var opts connOpts
	fs := flag.NewFlagSet("sentinel", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	addBackendFlags(fs, &opts)
	if err := fs.Parse(nil); err != nil {
		t.Fatal(err)
	}
	got, err := opts.client(io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	client := got.(*sentinel.Client)
	if len(client.RemoteWorkspaces) != 1 || client.RemoteWorkspaces[0].Alias != "soc" {
		t.Fatalf("remote workspaces = %+v", client.RemoteWorkspaces)
	}
	base := sentinelTargetID("subscription-a", "detections-rg", "sentinel-lab")
	withRemote := sentinelTargetID("subscription-a", "detections-rg", "sentinel-lab", client.RemoteWorkspaces...)
	if base == withRemote {
		t.Fatal("remote assessment scope did not affect Sentinel target identity")
	}
	reversedAliasCase := client.RemoteWorkspaces[0]
	reversedAliasCase.Alias = "SOC"
	if withRemote != sentinelTargetID("subscription-a", "detections-rg", "sentinel-lab", reversedAliasCase) {
		t.Fatal("remote mapping casing changed Sentinel target identity")
	}
	withVerifiedCustomerID := client.RemoteWorkspaces[0]
	withVerifiedCustomerID.WorkspaceID = "11111111-1111-4111-8111-111111111111"
	if withRemote != sentinelTargetID("subscription-a", "detections-rg", "sentinel-lab", withVerifiedCustomerID) {
		t.Fatal("optional verified remote customer ID changed Sentinel target identity")
	}
	second := sentinel.RemoteWorkspace{Alias: "mssp", SubscriptionID: "remote-sub-2", ResourceGroup: "remote-rg", WorkspaceName: "remote-law-2"}
	if sentinelTargetID("subscription-a", "detections-rg", "sentinel-lab", client.RemoteWorkspaces[0], second) !=
		sentinelTargetID("subscription-a", "detections-rg", "sentinel-lab", second, client.RemoteWorkspaces[0]) {
		t.Fatal("remote mapping order changed Sentinel target identity")
	}
}

func TestSentinelFleetAcceptsInlineRemoteMappings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fleet.json")
	data := []byte(`{"instances":[{"name":"sentinel-lab","backend":"sentinel","azure_subscription_id":"sub","azure_resource_group":"rg","sentinel_workspace":"law","sentinel_remote_workspaces":[{"alias":"soc","azure_subscription_id":"remote-sub","azure_resource_group":"remote-rg","sentinel_workspace":"remote-law"}]}]}`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	instances, err := (&connOpts{fleetFile: path}).resolveInstances(io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	client := instances[0].backend.(*sentinel.Client)
	if len(client.RemoteWorkspaces) != 1 || client.RemoteWorkspaces[0].WorkspaceName != "remote-law" {
		t.Fatalf("fleet remote mappings = %+v", client.RemoteWorkspaces)
	}
	if instances[0].targetID == sentinelTargetID("sub", "rg", "law") {
		t.Fatal("fleet remote mapping did not affect target identity")
	}
}

func TestSentinelCandidateRuleUsesParserWithoutReadingInstalledRules(t *testing.T) {
	path := filepath.Join(t.TempDir(), "candidate.json")
	if err := os.WriteFile(path, []byte(`{"kind":"NRT"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	probe := &sentinelReportProbe{}
	result, err := scanOnce(context.Background(), probe, connOpts{ruleFile: path, maxStale: time.Hour}, "lab", "target-sentinel")
	if err != nil {
		t.Fatal(err)
	}
	if probe.candidateReads != 1 || probe.ruleReads != 0 || probe.candidateData != `{"kind":"NRT"}` {
		t.Fatalf("candidate/installed reads = %d/%d, data %q", probe.candidateReads, probe.ruleReads, probe.candidateData)
	}
	if result.report.Summary.Rules != 1 || len(result.report.InputResolutions) == 0 || result.report.InputResolutions[0].RuleID != "candidate-rule" {
		t.Fatalf("candidate report summary/resolutions = %+v / %+v", result.report.Summary, result.report.InputResolutions)
	}
	found := false
	for _, assessment := range result.report.Assessments {
		if assessment.Name == report.AssessmentCandidateParsing {
			found = true
			if assessment.Status != backendpkg.EvidenceAssessed {
				t.Fatalf("candidate assessment = %+v", assessment)
			}
		}
	}
	if !found {
		t.Fatal("candidate report omitted candidate parsing assessment")
	}
}

func TestSentinelCandidateFleetBuildsCandidateParser(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fleet.json")
	data := []byte(`{"instances":[{"name":"sentinel-lab","backend":"sentinel","azure_subscription_id":"sub","azure_resource_group":"rg","sentinel_workspace":"law"}]}`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	opts := connOpts{fleetFile: path, ruleFile: "candidate.json"}
	instances, err := opts.resolveInstances(io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if len(instances) != 1 {
		t.Fatalf("candidate fleet instances = %+v", instances)
	}
	if _, ok := instances[0].backend.(backendpkg.CandidateParser); !ok {
		t.Fatalf("Sentinel fleet backend %T has no candidate parser", instances[0].backend)
	}
}

func TestSentinelScanDoesNotClaimUnusedTelemetryWithoutDocumentInventory(t *testing.T) {
	probe := &sentinelReportProbe{}
	result, err := scanOnce(context.Background(), probe, connOpts{maxStale: time.Hour}, "lab", "target-sentinel")
	if err != nil {
		t.Fatal(err)
	}
	if result.report.Summary.UnusedTelemetryAssessment != report.UnusedAssessmentUnavailable ||
		len(result.report.UnusedTelemetry) != 0 || result.report.Summary.UnusedSources != 0 {
		t.Fatalf("Sentinel unused telemetry = %s / %+v", result.report.Summary.UnusedTelemetryAssessment, result.report.UnusedTelemetry)
	}
	if got := result.report.Summary.UnusedTelemetryAssessmentDetail; got != sentinelUnusedTelemetryUnavailableDetail {
		t.Fatalf("Sentinel unused telemetry detail = %q, want %q", got, sentinelUnusedTelemetryUnavailableDetail)
	}
	encoded, err := json.Marshal(result.report)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"unused_telemetry_assessment_detail":"`+sentinelUnusedTelemetryUnavailableDetail+`"`) {
		t.Fatalf("Sentinel JSON omitted unused-telemetry detail: %s", encoded)
	}
	for name, render := range map[string]func(*bytes.Buffer){
		"plain":  func(output *bytes.Buffer) { printPlainSummary(output, result.report) },
		"visual": func(output *bytes.Buffer) { printVisualSummary(output, result.report) },
	} {
		t.Run(name, func(t *testing.T) {
			var output bytes.Buffer
			render(&output)
			if strings.Contains(output.String(), sentinelUnusedTelemetryUnavailableDetail) ||
				strings.Contains(output.String(), "UNUSED NOT ASSESSED") ||
				strings.Contains(output.String(), "unused telemetry: not assessed") {
				t.Fatalf("Sentinel %s terminal output promoted a non-actionable inventory limitation:\n%s", name, output.String())
			}
		})
	}
	htmlPath := filepath.Join(t.TempDir(), "sentinel.html")
	if err := result.report.WriteHTML(htmlPath); err != nil {
		t.Fatal(err)
	}
	html, err := os.ReadFile(htmlPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, unwanted := range []string{
		sentinelUnusedTelemetryUnavailableDetail,
		"enabled local rule inputs could not be resolved",
		"<th>Documents</th>",
		"<th>Stored</th>",
		"<th>Volume</th>",
		"Stored unused telemetry",
	} {
		if strings.Contains(string(html), unwanted) {
			t.Fatalf("Sentinel HTML promoted unavailable inventory as %q:\n%s", unwanted, html)
		}
	}
	if len(probe.requestedFreshness) != 1 || probe.requestedFreshness[0] != "SecurityEvent" {
		t.Fatalf("freshness requested for %v, want only the enabled rule's concrete source", probe.requestedFreshness)
	}
	if len(result.report.Sources) != 1 || result.report.Sources[0].Name != "SecurityEvent" {
		t.Fatalf("default Sentinel source listing = %+v, want only consumed sources", result.report.Sources)
	}
	foundFreshness := false
	for _, assessment := range result.report.Assessments {
		if assessment.Name == report.AssessmentSourceFreshness {
			foundFreshness = true
			if assessment.Status != backendpkg.EvidenceAssessed {
				t.Fatalf("freshness assessment = %+v, want assessed", assessment)
			}
		}
	}
	if !foundFreshness {
		t.Fatal("Sentinel report omitted source_freshness runtime assessment")
	}
}

func TestSentinelExplicitSourceScopeIsPreservedWithoutChangingVerdicts(t *testing.T) {
	probe := &sentinelReportProbe{}
	result, err := scanOnce(context.Background(), probe, connOpts{
		maxStale: time.Hour,
		include:  patternList{"Heartbeat"},
	}, "lab", "target-sentinel")
	if err != nil {
		t.Fatal(err)
	}
	if len(result.report.Sources) != 1 || result.report.Sources[0].Name != "Heartbeat" {
		t.Fatalf("explicit Sentinel scope = %+v, want Heartbeat", result.report.Sources)
	}
	if len(result.report.DeadDetections) != 0 {
		t.Fatalf("listing scope changed Sentinel verdicts: %+v", result.report.DeadDetections)
	}
	if len(probe.requestedFreshness) != 1 || probe.requestedFreshness[0] != "SecurityEvent" {
		t.Fatalf("listing filter changed freshness verdict scope: %v", probe.requestedFreshness)
	}
}

func TestSentinelFreshnessFailureStaysIncompleteWithoutFailingScan(t *testing.T) {
	probe := &sentinelReportProbe{freshnessErr: errors.New("temporary Logs failure")}
	result, err := scanOnce(context.Background(), probe, connOpts{maxStale: time.Hour}, "lab", "target-sentinel")
	if err != nil {
		t.Fatal(err)
	}
	if len(result.report.Sources) != 1 || result.report.Sources[0].Status != "unknown" {
		t.Fatalf("source health after freshness failure = %+v", result.report.Sources)
	}
	for _, assessment := range result.report.Assessments {
		if assessment.Name == report.AssessmentSourceFreshness {
			if assessment.Status != backendpkg.EvidenceIncomplete || strings.Contains(assessment.Detail, "temporary Logs failure") {
				t.Fatalf("freshness failure assessment = %+v", assessment)
			}
			return
		}
	}
	t.Fatal("Sentinel report omitted failed source_freshness assessment")
}

func TestSentinelBoundedEmptyFreshnessUsesProvedWindow(t *testing.T) {
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	for _, tt := range []struct {
		name     string
		maxStale time.Duration
		want     string
	}{
		{name: "threshold within proved window", maxStale: time.Hour, want: "stale"},
		{name: "threshold beyond proved window", maxStale: 25 * time.Hour, want: "unknown"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			probe := &sentinelReportProbe{freshness: backendpkg.FreshnessEvidence{
				Status: backendpkg.EvidenceAssessed, Method: "bounded-max-timegenerated",
				ObservedAt: now, Window: 24 * time.Hour,
			}}
			result, err := scanOnce(context.Background(), probe, connOpts{maxStale: tt.maxStale}, "lab", "target-sentinel")
			if err != nil {
				t.Fatal(err)
			}
			if len(result.report.Sources) != 1 || result.report.Sources[0].Status != tt.want {
				t.Fatalf("bounded-empty source health = %+v, want %s", result.report.Sources, tt.want)
			}
		})
	}
}

type predicateFreshnessProbe struct {
	sentinelReportProbe
	requests          []backendpkg.RulePredicateFreshnessRequest
	err               error
	predicateEvidence backendpkg.FreshnessEvidence
}

func (p *predicateFreshnessProbe) Rules(context.Context) ([]backendpkg.Rule, error) {
	p.ruleReads++
	return []backendpkg.Rule{{
		ID: "rule-1", Name: "Rule 1", Enabled: true, Severity: "medium", Patterns: []string{"SecurityEvent"},
		PredicateFreshness: []backendpkg.PredicateFreshnessSelector{{
			Source: "SecurityEvent", Expression: `DeviceVendor == "private-vendor"`, Fields: []string{"DeviceVendor"},
		}},
	}}, nil
}

func (p *predicateFreshnessProbe) RulePredicateFreshnessEvidenceFor(_ context.Context, requests []backendpkg.RulePredicateFreshnessRequest) ([]backendpkg.RulePredicateFreshnessEvidence, error) {
	p.requests = append([]backendpkg.RulePredicateFreshnessRequest(nil), requests...)
	if p.err != nil {
		return nil, p.err
	}
	items := make([]backendpkg.RulePredicateFreshnessEvidence, 0, len(requests))
	for _, request := range requests {
		freshness := p.predicateEvidence
		if freshness.Status == "" {
			freshness = backendpkg.FreshnessEvidence{
				Status: backendpkg.EvidenceAssessed, Method: "bounded-predicate-max-timegenerated",
				ObservedAt: time.Now().UTC(), Window: 24 * time.Hour, LastEvent: time.Now().UTC().Add(-2 * time.Hour),
			}
		}
		items = append(items, backendpkg.RulePredicateFreshnessEvidence{
			RuleID: request.RuleID, BackendObjectID: request.BackendObjectID,
			Source: request.Source.Name, Fields: append([]string(nil), request.Selector.Fields...),
			Freshness: freshness,
		})
	}
	return items, nil
}

func TestSentinelPredicateFreshnessIsReportedWithoutCreatingFinding(t *testing.T) {
	probe := &predicateFreshnessProbe{}
	result, err := scanOnce(context.Background(), probe, connOpts{maxStale: time.Hour}, "lab", "target-sentinel")
	if err != nil {
		t.Fatal(err)
	}
	if len(probe.requests) != 1 || probe.requests[0].Source.Name != "SecurityEvent" || probe.requests[0].Basis != backendpkg.FreshnessEventTime {
		t.Fatalf("predicate freshness requests = %+v", probe.requests)
	}
	if len(result.report.RuleSourceFreshness) != 1 || result.report.RuleSourceFreshness[0].FreshnessStatus != "stale" {
		t.Fatalf("rule-specific freshness = %+v", result.report.RuleSourceFreshness)
	}
	if len(result.report.DeadDetections) != 0 || len(result.report.ImpairedDetections) != 0 {
		t.Fatalf("predicate-only observation changed findings: dead %+v, impaired %+v", result.report.DeadDetections, result.report.ImpairedDetections)
	}
	encoded, err := json.Marshal(result.report)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "private-vendor") {
		t.Fatalf("predicate literal leaked into report: %s", encoded)
	}
	for name, render := range map[string]func(*bytes.Buffer){
		"plain":  func(output *bytes.Buffer) { printPlainSummary(output, result.report) },
		"visual": func(output *bytes.Buffer) { printVisualSummary(output, result.report) },
	} {
		t.Run(name, func(t *testing.T) {
			var output bytes.Buffer
			render(&output)
			if !strings.Contains(strings.ToLower(output.String()), "filtered data") || strings.Contains(output.String(), "private-vendor") {
				t.Fatalf("%s predicate freshness output = %q", name, output.String())
			}
		})
	}
}

func TestSentinelPredicateFreshnessFailureIsNonfatalAndIncomplete(t *testing.T) {
	probe := &predicateFreshnessProbe{err: errors.New("private query error")}
	result, err := scanOnce(context.Background(), probe, connOpts{maxStale: time.Hour}, "lab", "target-sentinel")
	if err != nil {
		t.Fatal(err)
	}
	if len(result.report.RuleSourceFreshness) != 0 {
		t.Fatalf("failed predicate query produced evidence: %+v", result.report.RuleSourceFreshness)
	}
	for _, assessment := range result.report.Assessments {
		if assessment.Name == report.AssessmentPredicateFreshness {
			if assessment.Status != backendpkg.EvidenceIncomplete || strings.Contains(assessment.Detail, "private query error") {
				t.Fatalf("predicate freshness failure assessment = %+v", assessment)
			}
			return
		}
	}
	t.Fatal("Sentinel report omitted predicate_freshness assessment")
}

func TestSentinelPredicateFreshnessUsesPolicyThresholdForEvidenceCompleteness(t *testing.T) {
	policyPath := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(policyPath, []byte(`{
  "version": 1,
  "gate_classes": ["dead-detection"],
  "sources": [{"pattern": "SecurityEvent", "max_stale": "48h"}]
}`), 0o600); err != nil {
		t.Fatal(err)
	}
	probe := &predicateFreshnessProbe{predicateEvidence: backendpkg.FreshnessEvidence{
		Status: backendpkg.EvidenceAssessed, Method: "bounded-predicate-max-timegenerated",
		ObservedAt: time.Now().UTC(), Window: 24 * time.Hour,
	}}
	result, err := scanOnce(context.Background(), probe, connOpts{maxStale: time.Hour, policyFile: policyPath}, "lab", "target-sentinel")
	if err != nil {
		t.Fatal(err)
	}
	if len(probe.requests) != 1 || probe.requests[0].Window != 48*time.Hour {
		t.Fatalf("policy-aware predicate request = %+v", probe.requests)
	}
	if len(result.report.RuleSourceFreshness) != 1 || result.report.RuleSourceFreshness[0].Status != backendpkg.EvidenceIncomplete ||
		result.report.RuleSourceFreshness[0].FreshnessStatus != "unknown" {
		t.Fatalf("policy-aware predicate evidence = %+v", result.report.RuleSourceFreshness)
	}
	for _, assessment := range result.report.Assessments {
		if assessment.Name == report.AssessmentPredicateFreshness {
			if assessment.Status != backendpkg.EvidenceIncomplete {
				t.Fatalf("policy-aware predicate assessment = %+v", assessment)
			}
			return
		}
	}
	t.Fatal("predicate freshness assessment missing")
}

func TestSentinelHelpAndSetupKeepOnboardingFocused(t *testing.T) {
	for _, command := range []string{"scan", "check", "serve"} {
		var stdout, stderr bytes.Buffer
		if code := Run([]string{command, "-h"}, &stdout, &stderr); code != report.ExitHealthy {
			t.Fatalf("%s -h exit = %d", command, code)
		}
		for _, want := range []string{"sentinel", "--azure-subscription", "--azure-resource-group", "--sentinel-workspace", "DefaultAzureCredential"} {
			if !strings.Contains(stderr.String(), want) {
				t.Errorf("%s help missing %q:\n%s", command, want, stderr.String())
			}
		}
		if command != "check" {
			for _, unwanted := range []string{
				"Tenant boundaries are not detected separately",
				"references another subscription",
				"filtered data that has gone quiet",
			} {
				if strings.Contains(stderr.String(), unwanted) {
					t.Errorf("%s help includes Sentinel reference prose %q:\n%s", command, unwanted, stderr.String())
				}
			}
		}
	}

	var stdout, stderr bytes.Buffer
	if code := Run([]string{"setup", "sentinel"}, &stdout, &stderr); code != report.ExitHealthy {
		t.Fatalf("setup sentinel exit = %d, stderr: %s", code, stderr.String())
	}
	for _, want := range []string{
		"az login", "Microsoft Sentinel Reader", "Log Analytics Reader",
		"DEADAIR_AZURE_SUBSCRIPTION_ID", "DEADAIR_SENTINEL_WORKSPACE",
		"DEADAIR_SENTINEL_REMOTES", "docs/credentials/sentinel.md",
		"docs/usage.md#microsoft-sentinel",
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("setup sentinel output missing %q:\n%s", want, stdout.String())
		}
	}
	if strings.Contains(stdout.String(), "candidate rule files remain") {
		t.Fatalf("setup still says Sentinel candidate rules are unavailable:\n%s", stdout.String())
	}
	if strings.Contains(stdout.String(), "Cross-subscription or cross-tenant") {
		t.Fatalf("setup overclaims cross-tenant boundary detection:\n%s", stdout.String())
	}
	if strings.Contains(stdout.String(), "Current limits:") || strings.Contains(stdout.String(), "source document totals remain unassessed") {
		t.Fatalf("setup pasted reference caveats into onboarding:\n%s", stdout.String())
	}
}
