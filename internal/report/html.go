package report

import (
	"bytes"
	"fmt"
	"html/template"
	"strings"
	"time"

	"github.com/alephnull-sh/deadair/internal/securefile"
)

func htmlCount(n int, singular, plural string) string {
	if n == 1 {
		return "1 " + singular
	}
	return fmt.Sprintf("%d %s", n, plural)
}

func htmlExitCode(r *Report) int {
	if r.Scope.Mode == "candidate" {
		return r.CandidateExitCode()
	}
	return r.ExitCode()
}

func htmlHeadline(r *Report) string {
	if r.Scope.Mode == "candidate" {
		switch htmlExitCode(r) {
		case ExitError:
			return "Candidate assessment is incomplete"
		case ExitFindings:
			switch {
			case r.Summary.DeadDetections > 0:
				return htmlCount(r.Summary.DeadDetections, "candidate detection can't fire", "candidate detections can't fire")
			case r.Summary.ImpairedDetections > 0:
				return htmlCount(r.Summary.ImpairedDetections, "candidate detection has reduced visibility", "candidate detections have reduced visibility")
			default:
				return "Candidate rule failed the gate"
			}
		default:
			return "Candidate rule passed"
		}
	}
	switch {
	case r.Summary.DeadDetections > 0:
		return htmlCount(r.Summary.DeadDetections, "detection can't fire", "detections can't fire")
	case r.Summary.ImpairedDetections > 0:
		return htmlCount(r.Summary.ImpairedDetections, "detection has reduced visibility", "detections have reduced visibility")
	case r.Summary.DegradedSources > 0:
		return htmlCount(r.Summary.DegradedSources, "source needs attention", "sources need attention")
	case r.ExitCode() == ExitFindings:
		return "The scan found a live blind spot"
	case htmlAdvisoryCount(r) > 0:
		return htmlCount(htmlAdvisoryCount(r), "advisory signal needs review", "advisory signals need review")
	case len(r.UnmappedRules)+len(r.RemoteRules) > 0:
		return "No confirmed failures, but coverage has gaps"
	default:
		return "No blind spots found"
	}
}

func htmlGateLabel(r *Report) string {
	switch htmlExitCode(r) {
	case ExitError:
		return "Scan incomplete"
	case ExitFindings:
		return "Gate failed"
	default:
		return "Gate passed"
	}
}

func htmlGateClass(r *Report) string {
	switch htmlExitCode(r) {
	case ExitError:
		return "incomplete"
	case ExitFindings:
		return "failed"
	default:
		return "passed"
	}
}

func htmlFreshnessWarnings(r *Report) []RuleSourceFreshness {
	items := make([]RuleSourceFreshness, 0, len(r.RuleSourceFreshness))
	for _, item := range r.RuleSourceFreshness {
		if item.FreshnessStatus == "ok" || item.FreshnessStatus == "maintenance" {
			continue
		}
		items = append(items, item)
	}
	return items
}

func htmlSummaryWarnings(r *Report) []SummaryRuleRun {
	items := make([]SummaryRuleRun, 0, len(r.SummaryRuleRuns))
	for _, item := range r.SummaryRuleRuns {
		if item.Status == "assessed" && strings.EqualFold(item.RunStatus, "Succeeded") {
			continue
		}
		items = append(items, item)
	}
	return items
}

func htmlAdvisoryCount(r *Report) int {
	return len(htmlFreshnessWarnings(r)) + len(htmlSummaryWarnings(r))
}

func htmlGateNote(r *Report) string {
	if r.Scope.Mode == "candidate" {
		switch htmlExitCode(r) {
		case ExitError:
			return "deadair could not prove every input needed to assess this candidate."
		case ExitFindings:
			if r.Policy != nil && r.Summary.GatedFindings > 0 {
				return htmlCount(r.Summary.GatedFindings, "finding is configured to fail this candidate.", "findings are configured to fail this candidate.")
			}
			return "Review the candidate rule and its sources below."
		default:
			if count := htmlAdvisoryCount(r); count > 0 {
				return fmt.Sprintf("No gated candidate findings. Review %s below.", htmlCount(count, "advisory signal", "advisory signals"))
			}
			return "No candidate findings or incomplete inputs."
		}
	}
	if htmlExitCode(r) == ExitFindings {
		if r.Policy != nil && r.Summary.GatedFindings > 0 {
			return htmlCount(r.Summary.GatedFindings, "finding is configured to fail this scan.", "findings are configured to fail this scan.")
		}
		return "Review the affected rules and sources below."
	}
	if count := htmlAdvisoryCount(r); count > 0 {
		return fmt.Sprintf("No gated findings. Review %s below.", htmlCount(count, "advisory signal", "advisory signals"))
	}
	if count := len(r.UnmappedRules) + len(r.RemoteRules); count > 0 {
		return fmt.Sprintf("No gated findings. %s could not be fully assessed.", htmlCount(count, "rule", "rules"))
	}
	return "No gated findings or incomplete rule inputs."
}

func htmlHumanLabel(raw any) string {
	value := fmt.Sprint(raw)
	labels := map[string]string{
		"rule_inventory":                    "Rule inventory",
		"source_resolution":                 "Source resolution",
		"freshness":                         "Source freshness",
		"docs_storage":                      "Document inventory",
		"schema":                            "Field schema",
		"source_freshness":                  "Source freshness",
		"predicate_freshness":               "Filtered source activity",
		"required_fields":                   "Required fields",
		"ingest_lag":                        "Ingest lag",
		"schema_drift":                      "Schema drift",
		"candidate_parsing":                 "Candidate rule",
		"remote":                            "Remote inputs",
		"dependency_resolution":             "Dependency resolution",
		"cross_workspace":                   "Cross-workspace inputs",
		"source_lineage":                    "Source lineage",
		"rule_provenance":                   "Rule provenance",
		"supported":                         "Supported",
		"partial":                           "Partial",
		"unavailable":                       "Unavailable",
		"listed-only":                       "Listed only",
		"sentinel_rule_execution_identity":  "Cross-subscription execution",
		"sentinel_summary_rule":             "Summary rule",
		"telemetry_table":                   "Telemetry table",
		"log_analytics_table":               "Log Analytics table",
		"kql_query":                         "KQL query",
		"sentinel_alert_rule_template":      "Sentinel rule template",
		"sentinel_content_hub_solution":     "Content Hub solution",
		"operational_insights_saved_search": "Workspace function",
	}
	if label, ok := labels[value]; ok {
		return label
	}
	return strings.ReplaceAll(strings.ReplaceAll(value, "_", " "), "-", " ")
}

func htmlTime(value *time.Time) string {
	if value == nil || value.IsZero() {
		return "Not observed"
	}
	return value.UTC().Format("2 Jan 2006, 15:04 UTC")
}

func htmlDuration(seconds float64) string {
	if seconds <= 0 {
		return "Not observed"
	}
	d := time.Duration(seconds) * time.Second
	if d >= 24*time.Hour && d%(24*time.Hour) == 0 {
		return fmt.Sprintf("%dd", d/(24*time.Hour))
	}
	if d >= time.Hour && d%time.Hour == 0 {
		return fmt.Sprintf("%dh", d/time.Hour)
	}
	if d >= time.Minute && d%time.Minute == 0 {
		return fmt.Sprintf("%dm", d/time.Minute)
	}
	return d.String()
}

func htmlAgo(value *time.Time, now time.Time) string {
	if value == nil || value.IsZero() {
		return "not observed"
	}
	d := now.Sub(value.UTC())
	if d < 0 {
		return "in the future"
	}
	if d < time.Minute {
		return "less than a minute ago"
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm ago", int(d/time.Minute))
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%dh ago", int(d/time.Hour))
	}
	return fmt.Sprintf("%dd ago", int(d/(24*time.Hour)))
}

func htmlPredicateState(item RuleSourceFreshness) string {
	switch item.FreshnessStatus {
	case "stale":
		return "Filtered data stale"
	case "empty":
		return "No matching data"
	case "maintenance":
		return "Expected downtime"
	case "ok":
		return "Active"
	default:
		return "Not assessed"
	}
}

func htmlPredicateAction(item RuleSourceFreshness) string {
	switch item.FreshnessStatus {
	case "stale", "empty":
		return "Review this rule's filter and the matching connector."
	default:
		return "Review scan coverage, then rescan."
	}
}

func htmlSummaryState(item SummaryRuleRun) string {
	if strings.EqualFold(item.RunStatus, "Failed") {
		return "Summary pipeline failed"
	}
	if item.Status == "incomplete" && strings.EqualFold(item.RunStatus, "Succeeded") {
		return "Summary pipeline overdue"
	}
	if item.RunAt == nil {
		return "Summary run not observed"
	}
	if item.Status != "assessed" {
		return "Summary run not assessed"
	}
	return "Summary pipeline healthy"
}

func htmlSummaryAction(item SummaryRuleRun) string {
	if strings.EqualFold(item.RunStatus, "Failed") {
		return "Open the summary rule run history in Sentinel."
	}
	if item.Status == "incomplete" && strings.EqualFold(item.RunStatus, "Succeeded") {
		return "Check the summary rule schedule and recent run history."
	}
	return "Enable summary-rule diagnostics or review scan coverage, then rescan."
}

func htmlDependencyConclusion(item DependencyEvidence) string {
	if item.Dependency.Kind != "sentinel_rule_execution_identity" {
		return item.Detail
	}
	if item.Status == "resolved" {
		return "Successful rule run observed after the latest rule change."
	}
	return "No recent successful rule-health event was found after the latest rule change. Enable Analytics rule health monitoring or inspect the rule's run history, then rescan."
}

var htmlReport = template.Must(template.New("report").Funcs(template.FuncMap{
	"bytes": func(n int64) string {
		return formatBytes(n)
	},
	"zscore": func(v *float64) string {
		if v == nil {
			return "-"
		}
		return fmt.Sprintf("%.2f", *v)
	},
	"duration": htmlDuration,
	"integer": func(value *int64) string {
		if value == nil {
			return "-"
		}
		return fmt.Sprintf("%d", *value)
	},
	"reason":               DeadReasonLabel,
	"headline":             htmlHeadline,
	"gateLabel":            htmlGateLabel,
	"gateClass":            htmlGateClass,
	"gateNote":             htmlGateNote,
	"advisoryCount":        htmlAdvisoryCount,
	"freshnessWarnings":    htmlFreshnessWarnings,
	"summaryWarnings":      htmlSummaryWarnings,
	"human":                htmlHumanLabel,
	"time":                 htmlTime,
	"ago":                  htmlAgo,
	"predicateState":       htmlPredicateState,
	"predicateAction":      htmlPredicateAction,
	"summaryState":         htmlSummaryState,
	"summaryAction":        htmlSummaryAction,
	"dependencyConclusion": htmlDependencyConclusion,
	"versions":             func(items []string) string { return strings.Join(items, ", ") },
	"join":                 func(items []string) string { return strings.Join(items, ", ") },
}).Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="icon" href="data:,">
  <title>deadair report · {{.BackendMetadata.Product}}</title>
  <style>
    :root {
      color-scheme: light;
      --paper: #ffffff;
      --ink: #17191c;
      --muted: #626a73;
      --line: #d8dce1;
      --line-dark: #aeb4bc;
      --soft: #f4f5f6;
      --danger: #b42318;
      --warn: #8a5b00;
      --good: #147a45;
    }
    * { box-sizing: border-box; }
    html, body { margin: 0; background: var(--paper); color: var(--ink); }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      font-size: 15px;
      line-height: 1.45;
      -webkit-font-smoothing: antialiased;
    }
    .report {
      width: min(1080px, calc(100% - 48px));
      margin: 0 auto;
      padding: 32px 0 56px;
    }
    .hero {
      padding: 0 0 30px;
      border-bottom: 2px solid var(--ink);
    }
    .hero-top, .section-heading, .signal-top, .detail-summary {
      display: flex;
      align-items: baseline;
      justify-content: space-between;
      gap: 20px;
    }
    .brand {
      margin: 0;
      color: var(--ink);
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      font-size: 12px;
      font-weight: 600;
      letter-spacing: .055em;
      text-transform: uppercase;
    }
    .gate {
      display: inline-block;
      padding-left: 9px;
      border-left: 3px solid currentColor;
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      font-size: 12px;
      font-weight: 700;
      letter-spacing: .04em;
      line-height: 1;
      text-transform: uppercase;
    }
    .gate-failed { color: var(--danger); }
    .gate-passed { color: var(--good); }
    .gate-incomplete { color: var(--warn); }
    h1 {
      max-width: 28ch;
      margin: 30px 0 8px;
      font-size: 2rem;
      line-height: 1.12;
      letter-spacing: -.02em;
    }
    .lede { max-width: 64ch; margin: 0; color: var(--muted); font-size: 16px; }
    .meta {
      margin: 10px 0 0;
      color: var(--muted);
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      font-size: 12px;
    }
    .metrics {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
      margin-top: 28px;
      border-top: 1px solid var(--line);
      border-bottom: 1px solid var(--line);
    }
    .metric {
      min-width: 0;
      padding: 12px 14px 13px 0;
      border-right: 1px solid var(--line);
    }
    .metric + .metric { padding-left: 14px; }
    .metric:last-child { border-right: 0; }
    .metric span {
      display: block;
      color: var(--muted);
      font-size: 12px;
    }
    .metric strong {
      display: block;
      margin-top: 2px;
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      font-size: 1.35rem;
      line-height: 1.1;
      letter-spacing: -.02em;
    }
    .metric-alert strong { color: var(--danger); }
    .metric-warn strong { color: var(--warn); }
    details > summary { cursor: pointer; }
    details > summary:focus-visible, .table-wrap:focus-visible {
      outline: 2px solid var(--ink);
      outline-offset: 3px;
    }
    section { margin-top: 34px; }
    .section-heading {
      align-items: end;
      margin-bottom: 12px;
      padding-bottom: 9px;
      border-bottom: 1px solid var(--ink);
    }
    h2 { margin: 0; font-size: 1.45rem; line-height: 1.2; letter-spacing: -.02em; }
    h3 {
      margin: 28px 0 8px;
      color: var(--muted);
      font-size: 12px;
      font-weight: 700;
      letter-spacing: .055em;
      text-transform: uppercase;
    }
    .section-copy { max-width: 68ch; margin: 4px 0 0; color: var(--muted); font-size: 13px; }
    .count {
      color: var(--muted);
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      font-size: 12px;
    }
    .signal-list {
      margin: 0;
      padding: 0;
      border-top: 1px solid var(--line);
      list-style: none;
    }
    .signal {
      display: grid;
      grid-template-columns: 1fr;
      gap: 3px;
      padding: 14px 0 15px;
      border-bottom: 1px solid var(--line);
    }
    .signal-top { align-items: start; }
    .signal-title { margin: 0; font-size: 15px; font-weight: 600; }
    .signal p { margin: 0; color: var(--muted); }
    .signal .action { margin-top: 3px; color: var(--muted); font-size: 13px; }
    .badge {
      display: inline-block;
      color: var(--muted);
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      font-size: 12px;
      font-weight: 700;
      letter-spacing: .045em;
      line-height: 1.4;
      text-transform: uppercase;
      white-space: nowrap;
    }
    .status-ok, .status-assessed, .status-resolved, .status-succeeded { color: var(--good); }
    .status-stale, .status-empty, .status-failed, .status-incompatible { color: var(--danger); }
    .status-incomplete, .status-unavailable, .status-unsupported, .status-ambiguous, .status-remote, .status-unknown, .status-disabled { color: var(--warn); }
    .status-maintenance, .status-warming, .status-pending { color: var(--muted); }
    .severity-critical, .severity-high { color: var(--danger); }
    .severity-medium { color: var(--warn); }
    .severity-low { color: var(--muted); }
    .tag-row { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 5px; }
    .tag {
      display: inline-block;
      padding: 1px 5px;
      border: 1px solid var(--line);
      border-radius: 2px;
      background: var(--soft);
      color: #454b52;
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      font-size: 11px;
      overflow-wrap: anywhere;
    }
    .advisory-note {
      margin: 0;
      padding: 8px 0 8px 12px;
      border-left: 2px solid var(--warn);
      color: var(--muted);
      font-size: 13px;
    }
    .table-wrap {
      width: 100%;
      overflow-x: auto;
      border-top: 1px solid var(--line-dark);
      border-bottom: 1px solid var(--line-dark);
      -webkit-overflow-scrolling: touch;
    }
    table { width: 100%; min-width: 720px; border-collapse: collapse; }
    th, td {
      padding: 9px 11px;
      border-bottom: 1px solid var(--line);
      text-align: left;
      vertical-align: top;
    }
    th {
      position: sticky;
      top: 0;
      z-index: 1;
      background: var(--paper);
      color: var(--muted);
      font-size: 11px;
      font-weight: 700;
      letter-spacing: .045em;
      text-transform: uppercase;
    }
    tbody tr:last-child td { border-bottom: 0; }
    td { overflow-wrap: anywhere; }
    td code, .technical {
      color: #454b52;
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      font-size: 11px;
      overflow-wrap: anywhere;
    }
    .empty-note {
      margin: 0;
      padding: 10px 0;
      border-top: 1px solid var(--line);
      border-bottom: 1px solid var(--line);
      color: var(--muted);
    }
    .evidence-panel {
      border-top: 1px solid var(--line-dark);
      border-bottom: 1px solid var(--line-dark);
    }
    .evidence-panel > summary {
      list-style: none;
      padding: 12px 0;
      font-weight: 600;
    }
    .evidence-panel > summary::-webkit-details-marker { display: none; }
    .evidence-panel > summary::after {
      content: "+";
      color: var(--muted);
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    }
    .evidence-panel[open] > summary::after { content: "−"; }
    .evidence-body { padding: 0 0 20px; border-top: 1px solid var(--line); }
    .evidence-body h3 { margin-top: 24px; }
    .row-detail summary {
      width: fit-content;
      color: var(--ink);
      font-size: 12px;
      text-decoration: underline;
      text-underline-offset: 2px;
    }
    .row-detail p { margin: 5px 0 0; color: var(--muted); }
    footer {
      margin-top: 36px;
      padding-top: 12px;
      border-top: 1px solid var(--line);
      color: var(--muted);
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      font-size: 11px;
    }
    @media (max-width: 680px) {
      .report { width: min(100% - 28px, 1080px); padding: 22px 0 40px; }
      .hero-top, .section-heading, .signal-top { align-items: flex-start; }
      h1 { margin-top: 24px; font-size: 2rem; }
      .metrics { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .metric, .metric + .metric {
        padding: 10px 8px 10px 0;
        border-right: 0;
        border-bottom: 1px solid var(--line);
      }
      .metric:nth-child(even) {
        padding-left: 12px;
        border-left: 1px solid var(--line);
      }
      .metric:last-child,
      .metric:nth-last-child(2):nth-child(odd) { border-bottom: 0; }
      section { margin-top: 34px; }
      .signal-top { gap: 12px; }
    }
    @media print {
      .report { width: 100%; padding: 0; }
      details:not([open]) > *:not(summary) { display: block !important; }
      .table-wrap { overflow: visible; }
      table { min-width: 0; font-size: 10px; }
    }
  </style>
</head>
<body>
{{ $freshnessWarnings := freshnessWarnings . }}
{{ $summaryWarnings := summaryWarnings . }}
<main class="report">
  <header class="hero">
    <div class="hero-top">
      <p class="brand">deadair / {{.BackendMetadata.Product}}</p>
      <span class="gate gate-{{gateClass .}}">{{gateLabel .}}</span>
    </div>
    <h1>{{headline .}}</h1>
    <p class="lede">{{gateNote .}}</p>
    <p class="meta"><time datetime="{{.GeneratedAt.Format "2006-01-02T15:04:05Z07:00"}}">{{.GeneratedAt.Format "2 Jan 2006, 15:04 UTC"}}</time>{{if .Redacted}} · redacted{{with .Redaction}} with key {{.KeyID}}{{end}}{{end}}</p>

    <div class="metrics">
      <div class="metric"><span>Enabled detections</span><strong>{{.Summary.EnabledRules}}</strong></div>
      <div class="metric"><span>Sources checked</span><strong>{{.Summary.Sources}}</strong></div>
      {{if .Summary.DeadDetections}}<div class="metric metric-alert"><span>Can't fire</span><strong>{{.Summary.DeadDetections}}</strong></div>{{end}}
      {{if .Summary.ImpairedDetections}}<div class="metric metric-warn"><span>Reduced visibility</span><strong>{{.Summary.ImpairedDetections}}</strong></div>{{end}}
      {{if .Summary.DegradedSources}}<div class="metric metric-alert"><span>Degraded sources</span><strong>{{.Summary.DegradedSources}}</strong></div>{{end}}
      {{if .Summary.PartialInputs}}<div class="metric metric-warn"><span>Partial inputs</span><strong>{{.Summary.PartialInputs}}</strong></div>{{end}}
      {{if .Summary.VolumeLowSources}}<div class="metric metric-warn"><span>Low-volume sources</span><strong>{{.Summary.VolumeLowSources}}</strong></div>{{end}}
      {{if .Summary.SchemaDriftSources}}<div class="metric metric-warn"><span>Schema changes</span><strong>{{.Summary.SchemaDriftSources}}</strong></div>{{end}}
    </div>

  </header>

  {{if or .DeadDetections .ImpairedDetections .PartialInputCoverage .UnmappedRules .RemoteRules $freshnessWarnings $summaryWarnings}}
  <section aria-labelledby="attention-heading">
    <div class="section-heading">
      <div>
        <h2 id="attention-heading">Needs attention</h2>
        <p class="section-copy">Confirmed findings and checks that need review.</p>
      </div>
    </div>

    {{if .DeadDetections}}
    <h3>Detections that can't fire</h3>
    <ul class="signal-list">
      {{range .DeadDetections}}
      <li class="signal">
        <div class="signal-top">
          <p class="signal-title">{{.Name}}</p>
          <span class="badge severity-{{.Severity}}">{{.Severity}}</span>
        </div>
        <p>{{reason .Reason}}</p>
        {{if .Sources}}<div class="tag-row">{{range .Sources}}<span class="tag">{{.}}</span>{{end}}</div>{{end}}
      </li>
      {{end}}
    </ul>
    {{end}}

    {{if .ImpairedDetections}}
    <h3>Detections with reduced visibility</h3>
    <ul class="signal-list">
      {{range .ImpairedDetections}}
      <li class="signal">
        <div class="signal-top">
          <p class="signal-title">{{.Name}}</p>
          <span class="badge severity-{{.Severity}}">{{.Severity}}</span>
        </div>
        <p>{{range $i, $reason := .Reasons}}{{if $i}} · {{end}}{{human $reason}}{{end}}</p>
        {{if .MissingFields}}<p class="action">Missing fields: {{join .MissingFields}}</p>{{end}}
        {{if .LagSources}}<p class="action">Ingest lag exceeds the rule window in {{join .LagSources}}.</p>{{end}}
        {{if .IncompatibleSources}}<p class="action">This rule can't use: {{join .IncompatibleSources}}.</p>{{end}}
      </li>
      {{end}}
    </ul>
    {{end}}

    {{if .PartialInputCoverage}}
    <h3>Partial rule inputs</h3>
    <ul class="signal-list">
      {{range .PartialInputCoverage}}
      <li class="signal">
        <div class="signal-top">
          <p class="signal-title">{{.RuleName}}</p>
          <span class="badge severity-{{.Severity}}">{{.Severity}}</span>
        </div>
        <p>One input is missing even though the rule still has another working path.</p>
        <div class="tag-row"><span class="tag">{{if .Selector}}{{.Selector}}{{else}}{{.Expression}}{{end}}</span></div>
      </li>
      {{end}}
    </ul>
    {{end}}

    {{if or .UnmappedRules .RemoteRules}}
    <h3>Rules not fully assessed</h3>
    <ul class="signal-list">
      {{range .UnmappedRules}}
      <li class="signal">
        <div class="signal-top">
          <p class="signal-title">{{.Name}}</p>
          <span class="badge status-{{.AssessmentStatus}}">{{human .AssessmentStatus}}</span>
        </div>
        <p>{{if .Detail}}{{.Detail}}{{else}}The rule's inputs could not be mapped safely.{{end}}</p>
      </li>
      {{end}}
      {{range .RemoteRules}}
      <li class="signal">
        <div class="signal-top">
          <p class="signal-title">{{.Name}}</p>
          <span class="badge status-remote">Remote input</span>
        </div>
        <p>The remote dependency was listed but not treated as dead.</p>
      </li>
      {{end}}
    </ul>
    {{end}}

    {{if or $freshnessWarnings $summaryWarnings}}
    <h3>Sentinel advisory signals</h3>
    <p class="advisory-note">These signals add context to the confirmed findings above. They do not change the gate or exit code.</p>
    <ul class="signal-list">
      {{range $freshnessWarnings}}
      <li class="signal">
        <div class="signal-top">
          <p class="signal-title">{{if .RuleName}}{{.RuleName}}{{else}}{{.RuleID}}{{end}} · {{.Source}}</p>
          <span class="badge status-{{.FreshnessStatus}}">{{predicateState .}}</span>
        </div>
        <p>{{if .AgeSeconds}}No matching event for {{if .AgeLowerBound}}at least {{end}}{{duration .AgeSeconds}}. {{end}}Filter fields: {{if .Fields}}{{join .Fields}}{{else}}not disclosed{{end}}.</p>
        <p class="action">{{predicateAction .}}</p>
      </li>
      {{end}}
      {{range $summaryWarnings}}
      <li class="signal">
        <div class="signal-top">
          <p class="signal-title">{{if .Rule.Name}}{{.Rule.Name}}{{else}}{{.Rule.ID}}{{end}} → {{if .Output.Name}}{{.Output.Name}}{{else}}{{.Output.ID}}{{end}}</p>
          <span class="badge {{if eq .RunStatus "Failed"}}status-failed{{else}}status-incomplete{{end}}">{{summaryState .}}</span>
        </div>
        <p>{{if .RunAt}}{{.RunStatus}} {{ago .RunAt $.GeneratedAt}}{{else}}No completed run was observed in the bounded window{{end}}{{if .QueryDurationMillis}} · {{integer .QueryDurationMillis}} ms{{end}}{{if .ResultCount}} · {{integer .ResultCount}} rows{{end}}.</p>
        {{if .Error}}<p>{{.Error}}</p>{{end}}
        <p class="action">{{summaryAction .}}</p>
      </li>
      {{end}}
    </ul>
    {{end}}
  </section>
  {{end}}

  <section aria-labelledby="sources-heading">
    <div class="section-heading">
      <div>
        <h2 id="sources-heading">Sources</h2>
        <p class="section-copy">The data feeds deadair resolved for this scan and the detections that depend on them.</p>
      </div>
      <span class="count">{{.Summary.Sources}} total</span>
    </div>
    {{if .Sources}}
    <div class="table-wrap" tabindex="0" role="region" aria-label="Sources">
      <table>
        <thead><tr><th>Source</th><th>Status</th><th>Age</th><th>Detections</th><th>Documents</th><th>Stored</th><th>Volume</th><th>Schema</th><th>Ingest lag</th></tr></thead>
        <tbody>
        {{range .Sources}}
          <tr>
            <td><strong>{{.Name}}</strong></td>
            <td><span class="badge status-{{.Status}}">{{human .Status}}</span>{{if .ExpectedDowntime}}<br><span class="count">expected downtime</span>{{end}}</td>
            <td>{{if .AgeSeconds}}{{if .AgeLowerBound}}At least {{end}}{{duration .AgeSeconds}}{{else}}Not observed{{end}}</td>
            <td>{{.Consumers}}</td>
            <td>{{if lt .Docs 0}}Not available{{else}}{{.Docs}}{{end}}</td>
            <td>{{if lt .Docs 0}}Not available{{else}}{{bytes .SizeBytes}}{{end}}</td>
            <td>{{if .Volume}}<span class="badge status-{{.Volume.Status}}">{{human .Volume.Status}}</span>{{else}}Not assessed{{end}}</td>
            <td>{{if .Schema}}<span class="badge status-{{.Schema.Status}}">{{human .Schema.Status}}</span>{{else}}Not assessed{{end}}</td>
            <td>{{if .IngestLag}}{{if eq .IngestLag.Status "assessed"}}p95 {{duration .IngestLag.P95Seconds}} · max {{duration .IngestLag.MaxSeconds}}{{else}}<span class="badge status-{{.IngestLag.Status}}">{{human .IngestLag.Status}}</span>{{with .IngestLag.Detail}}<br><span class="count">{{.}}</span>{{end}}{{end}}{{else}}Not assessed{{end}}</td>
          </tr>
        {{end}}
        </tbody>
      </table>
    </div>
    {{else}}
    <p class="empty-note">No source inventory was available for this scan.</p>
    {{end}}

    <h3>Stored unused telemetry</h3>
    {{if eq .Summary.UnusedTelemetryAssessment "unavailable"}}
      <p class="empty-note">Not assessed: {{.Summary.UnusedTelemetryExplanation}}.</p>
    {{else if eq .Summary.UnusedTelemetryAssessment "not-applicable"}}
      <p class="empty-note">Not applicable to this candidate-rule report.</p>
    {{else if .UnusedTelemetry}}
      <div class="table-wrap" tabindex="0" role="region" aria-label="Stored unused telemetry">
        <table>
          <thead><tr><th>Source</th><th>Documents</th><th>Stored</th></tr></thead>
          <tbody>{{range .UnusedTelemetry}}<tr><td><strong>{{.Name}}</strong></td><td>{{.Docs}}</td><td>{{bytes .SizeBytes}}</td></tr>{{end}}</tbody>
        </table>
      </div>
    {{else}}
      <p class="empty-note">No stored source was left without an enabled detection reading it.</p>
    {{end}}
  </section>

  <section aria-labelledby="evidence-heading">
    <div class="section-heading">
      <div>
        <h2 id="evidence-heading">Evidence</h2>
        <p class="section-copy">Open this when you need to audit how deadair reached the result.</p>
      </div>
    </div>

    <details class="evidence-panel">
      <summary class="detail-summary"><span>Evidence details</span></summary>
      <div class="evidence-body">
        {{if .Assessments}}
        <h3>Scan coverage</h3>
        <div class="table-wrap" tabindex="0" role="region" aria-label="Scan coverage">
          <table>
            <thead><tr><th>Check</th><th>Status</th><th>What happened</th></tr></thead>
            <tbody>{{range .Assessments}}<tr><td><strong>{{human .Name}}</strong></td><td><span class="badge status-{{.Status}}">{{human .Status}}</span></td><td>{{.Detail}}</td></tr>{{end}}</tbody>
          </table>
        </div>
        {{end}}

        {{if .InputResolutions}}
        <h3>Input resolution</h3>
        <div class="table-wrap" tabindex="0" role="region" aria-label="Input resolution">
          <table>
            <thead><tr><th>Rule</th><th>Input</th><th>Kind</th><th>Status</th><th>Resolved sources</th><th>Technical evidence</th></tr></thead>
            <tbody>
            {{range .InputResolutions}}
              <tr>
                <td class="technical">{{.RuleID}}</td>
                <td>{{if .Expression}}{{.Expression}}{{else}}{{.Selector}}{{end}}</td>
                <td>{{human .SelectorKind}}</td>
                <td><span class="badge status-{{.Status}}">{{human .Status}}</span></td>
                <td>{{join .ResolvedSources}}</td>
                <td><details class="row-detail"><summary>Show</summary><p><code>{{.ResolutionMethod}}</code>{{with .Detail}}<br>{{.}}{{end}}</p></details></td>
              </tr>
            {{end}}
            </tbody>
          </table>
        </div>
        {{end}}

        {{if .DependencyEvidence}}
        <h3>Dependency evidence</h3>
        <div class="table-wrap" tabindex="0" role="region" aria-label="Dependency evidence">
          <table>
            <thead><tr><th>Rule</th><th>Dependency</th><th>Kind</th><th>Status</th><th>Conclusion</th><th>Technical method</th></tr></thead>
            <tbody>{{range .DependencyEvidence}}
              <tr>
                <td>{{.RuleName}}</td>
                <td>{{if .Dependency.Name}}{{.Dependency.Name}}{{else}}{{.Dependency.ID}}{{end}}</td>
                <td>{{human .Dependency.Kind}}</td>
                <td><span class="badge status-{{.Status}}">{{human .Status}}</span></td>
                <td>{{dependencyConclusion .}}</td>
                <td><code>{{.ResolutionMethod}}</code></td>
              </tr>
            {{end}}</tbody>
          </table>
        </div>
        {{end}}

        {{if .RuleProvenance}}
        <h3>Rule provenance</h3>
        <div class="table-wrap" tabindex="0" role="region" aria-label="Rule provenance">
          <table>
            <thead><tr><th>Rule</th><th>Origin</th><th>Kind</th><th>Status</th><th>Detail</th><th>Technical method</th></tr></thead>
            <tbody>{{range .RuleProvenance}}
              <tr>
                <td>{{.RuleName}}</td>
                <td>{{if .Provenance.Name}}{{.Provenance.Name}}{{else}}{{.Provenance.ID}}{{end}}</td>
                <td>{{human .Provenance.Kind}}</td>
                <td><span class="badge status-{{.Status}}">{{human .Status}}</span></td>
                <td>{{.Detail}}</td>
                <td><code>{{.Method}}</code></td>
              </tr>
            {{end}}</tbody>
          </table>
        </div>
        {{end}}

        {{if .SourceLineage}}
        <h3>Source lineage</h3>
        <p class="section-copy">Transformations are supporting evidence. Detection health still follows the concrete source a rule reads.</p>
        <div class="table-wrap" tabindex="0" role="region" aria-label="Source lineage">
          <table>
            <thead><tr><th>Transformation</th><th>Input</th><th>Output</th><th>Status</th><th>Detail</th><th>Technical method</th></tr></thead>
            <tbody>{{range .SourceLineage}}
              <tr>
                <td>{{if .Name}}{{.Name}}{{else}}{{.ID}}{{end}} <span class="count">· {{human .Kind}}</span></td>
                <td>{{if .Input.Name}}{{.Input.Name}}{{else}}{{.Input.ID}}{{end}}</td>
                <td>{{if .Output.Name}}{{.Output.Name}}{{else}}{{.Output.ID}}{{end}}</td>
                <td><span class="badge status-{{.Status}}">{{human .Status}}</span></td>
                <td>{{.Detail}}</td>
                <td><code>{{.Method}}</code></td>
              </tr>
            {{end}}</tbody>
          </table>
        </div>
        {{end}}

        {{if .RuleSourceFreshness}}
        <h3>Filtered source activity</h3>
        <p class="section-copy">Bounded checks of parser-proved literal filters. Predicate values and query text are never included.</p>
        <div class="table-wrap" tabindex="0" role="region" aria-label="Filtered source activity">
          <table>
            <thead><tr><th>Rule</th><th>Source</th><th>Fields</th><th>Evidence</th><th>Freshness</th><th>Age</th><th>Technical detail</th></tr></thead>
            <tbody>{{range .RuleSourceFreshness}}
              <tr>
                <td>{{if .RuleName}}{{.RuleName}}{{else}}{{.RuleID}}{{end}}</td>
                <td>{{.Source}}</td>
                <td>{{join .Fields}}</td>
                <td><span class="badge status-{{.Status}}">{{human .Status}}</span></td>
                <td><span class="badge status-{{.FreshnessStatus}}">{{predicateState .}}</span></td>
                <td>{{if .AgeSeconds}}{{if .AgeLowerBound}}At least {{end}}{{duration .AgeSeconds}}{{else}}Not observed{{end}}</td>
                <td><code>{{.Method}}</code>{{with .Detail}}<br>{{.}}{{end}}</td>
              </tr>
            {{end}}</tbody>
          </table>
        </div>
        {{end}}

        {{if .SummaryRuleRuns}}
        <h3>Summary pipeline runs</h3>
        <p class="section-copy">Latest completed native run observed in the bounded window. Failures and overdue successes stay advisory.</p>
        <div class="table-wrap" tabindex="0" role="region" aria-label="Summary pipeline runs">
          <table>
            <thead><tr><th>Summary rule</th><th>Output</th><th>Status</th><th>Last completed</th><th>Duration</th><th>Rows</th><th>Error</th><th>Technical detail</th></tr></thead>
            <tbody>{{range .SummaryRuleRuns}}
              <tr>
                <td>{{if .Rule.Name}}{{.Rule.Name}}{{else}}{{.Rule.ID}}{{end}}</td>
                <td>{{if .Output.Name}}{{.Output.Name}}{{else}}{{.Output.ID}}{{end}}</td>
                <td><span class="badge {{if eq .RunStatus "Failed"}}status-failed{{else}}status-{{.Status}}{{end}}">{{summaryState .}}</span></td>
                <td>{{time .RunAt}}{{if .RunAt}}<br><span class="count">{{ago .RunAt $.GeneratedAt}}</span>{{end}}</td>
                <td>{{if .QueryDurationMillis}}{{integer .QueryDurationMillis}} ms{{else}}Not observed{{end}}</td>
                <td>{{if .ResultCount}}{{integer .ResultCount}}{{else}}Not observed{{end}}</td>
                <td>{{.Error}}</td>
                <td><details class="row-detail"><summary>Show</summary><p><code>{{.Method}}</code>{{with .RuleModifiedAt}}<br>Rule changed {{time .}}{{end}}{{with .Detail}}<br>{{.}}{{end}}</p></details></td>
              </tr>
            {{end}}</tbody>
          </table>
        </div>
        {{end}}

        {{if .RequiredFieldEvidence}}
        <h3>Required-field evidence</h3>
        <div class="table-wrap" tabindex="0" role="region" aria-label="Required-field evidence">
          <table>
            <thead><tr><th>Rule</th><th>Source</th><th>Status</th><th>Present</th><th>Missing</th><th>Detail</th></tr></thead>
            <tbody>
            {{range .RequiredFieldEvidence}}{{ $rule := .RuleName }}{{range .Sources}}
              <tr><td>{{$rule}}</td><td>{{.Source}}</td><td><span class="badge status-{{.Status}}">{{human .Status}}</span></td><td>{{join .Present}}</td><td>{{join .Missing}}</td><td>{{.Detail}}</td></tr>
            {{end}}{{end}}
            </tbody>
          </table>
        </div>
        {{end}}

        <h3>About this scan</h3>
        <p class="section-copy">{{.BackendMetadata.Product}}{{with .BackendMetadata.ObservedVersion}} {{.}}{{end}} ({{.Backend}}) · {{.SchemaVersion}} · producer {{.Producer.Name}} {{.Producer.Version}}{{with .BackendMetadata.SupportedVersionLines}} · recognized versions {{versions .}}{{end}}</p>
        {{if .BackendMetadata.Capabilities}}
        <div class="table-wrap" tabindex="0" role="region" aria-label="Backend capabilities">
          <table>
            <thead><tr><th>Capability</th><th>Status</th></tr></thead>
            <tbody>{{range .BackendMetadata.Capabilities}}<tr><td>{{human .Name}}</td><td><span class="badge status-{{.Status}}">{{human .Status}}</span></td></tr>{{end}}</tbody>
          </table>
        </div>
        {{end}}
      </div>
    </details>
  </section>

  <footer>deadair / read-only assessment</footer>
</main>
</body>
</html>
`))

// WriteHTML writes a static HTML report to path with 0600 permissions on POSIX.
func (r *Report) WriteHTML(path string) error {
	var b bytes.Buffer
	if err := htmlReport.Execute(&b, r); err != nil {
		return fmt.Errorf("rendering html report: %w", err)
	}
	lines := strings.Split(b.String(), "\n")
	for i := range lines {
		lines[i] = strings.TrimRight(lines[i], " \t")
	}
	if err := securefile.Write(path, []byte(strings.Join(lines, "\n"))); err != nil {
		return fmt.Errorf("writing html report: %w", err)
	}
	return nil
}

func formatBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
