package report

import (
	"bytes"
	"fmt"
	"html/template"
	"os"
)

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
}).Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>deadair report</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 2rem; color: #17202a; }
    h1, h2 { margin-bottom: .4rem; }
    table { border-collapse: collapse; width: 100%; margin: 1rem 0 2rem; }
    th, td { border-bottom: 1px solid #d8dee4; padding: .45rem .5rem; text-align: left; }
    th { background: #f6f8fa; font-weight: 600; }
    .muted { color: #57606a; }
    .status-ok { color: #116329; }
    .status-stale, .status-empty, .status-low { color: #b42318; font-weight: 600; }
    .status-maintenance, .status-warming, .status-pending, .status-unknown { color: #8250df; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(12rem, 1fr)); gap: .75rem; margin: 1rem 0 2rem; }
    .metric { border: 1px solid #d8dee4; border-radius: 6px; padding: .75rem; }
    .metric strong { display: block; font-size: 1.5rem; }
  </style>
</head>
<body>
  <h1>deadair report</h1>
  <p class="muted">{{.Backend}} · {{.GeneratedAt.Format "2006-01-02 15:04:05 UTC"}}{{if .Redacted}} · redacted{{end}}</p>

  <div class="grid">
    <div class="metric"><span>Sources</span><strong>{{.Summary.Sources}}</strong></div>
    <div class="metric"><span>Degraded sources</span><strong>{{.Summary.DegradedSources}}</strong></div>
    <div class="metric"><span>Low-volume sources</span><strong>{{.Summary.VolumeLowSources}}</strong></div>
    <div class="metric"><span>Schema drift</span><strong>{{.Summary.SchemaDriftSources}}</strong></div>
    <div class="metric"><span>Dead detections</span><strong>{{.Summary.DeadDetections}}</strong></div>
    <div class="metric"><span>Impaired detections</span><strong>{{.Summary.ImpairedDetections}}</strong></div>
    <div class="metric"><span>Unused telemetry</span><strong>{{bytes .Summary.UnusedBytes}}</strong></div>
  </div>

  <h2>Sources</h2>
  <table>
    <thead><tr><th>Name</th><th>Status</th><th>Docs</th><th>Size</th><th>Consumers</th><th>Volume</th><th>Z-score</th><th>Schema</th></tr></thead>
    <tbody>
    {{range .Sources}}
      <tr>
        <td>{{.Name}}</td>
        <td class="status-{{.Status}}">{{.Status}}{{if .ExpectedDowntime}} (expected downtime){{end}}</td>
        <td>{{.Docs}}</td>
        <td>{{bytes .SizeBytes}}</td>
        <td>{{.Consumers}}</td>
        <td>{{if .Volume}}<span class="status-{{.Volume.Status}}">{{.Volume.Status}}</span>{{else}}-{{end}}</td>
        <td>{{if .Volume}}{{zscore .Volume.ZScore}}{{else}}-{{end}}</td>
        <td>{{if .Schema}}<span class="status-{{.Schema.Status}}">{{.Schema.Status}}</span>{{else}}-{{end}}</td>
      </tr>
    {{end}}
    </tbody>
  </table>

  <h2>Dead detections</h2>
  <table>
    <thead><tr><th>Severity</th><th>Name</th><th>Reason</th><th>Sources</th></tr></thead>
    <tbody>
    {{range .DeadDetections}}
      <tr><td>{{.Severity}}</td><td>{{.Name}}</td><td>{{.Reason}}</td><td>{{range $i, $s := .Sources}}{{if $i}}, {{end}}{{$s}}{{end}}</td></tr>
    {{else}}
      <tr><td colspan="4">None</td></tr>
    {{end}}
    </tbody>
  </table>

  <h2>Impaired detections</h2>
  <table>
    <thead><tr><th>Severity</th><th>Name</th><th>Reasons</th><th>Missing fields</th></tr></thead>
    <tbody>
    {{range .ImpairedDetections}}
      <tr><td>{{.Severity}}</td><td>{{.Name}}</td><td>{{range $i, $r := .Reasons}}{{if $i}}, {{end}}{{$r}}{{end}}</td><td>{{range $i, $f := .MissingFields}}{{if $i}}, {{end}}{{$f}}{{end}}</td></tr>
    {{else}}
      <tr><td colspan="4">None</td></tr>
    {{end}}
    </tbody>
  </table>

  <h2>Unused telemetry</h2>
  <table>
    <thead><tr><th>Name</th><th>Docs</th><th>Size</th></tr></thead>
    <tbody>
    {{range .UnusedTelemetry}}
      <tr><td>{{.Name}}</td><td>{{.Docs}}</td><td>{{bytes .SizeBytes}}</td></tr>
    {{else}}
      <tr><td colspan="3">None</td></tr>
    {{end}}
    </tbody>
  </table>
</body>
</html>
`))

// WriteHTML writes a static HTML report to path with 0600 permissions.
func (r *Report) WriteHTML(path string) error {
	var b bytes.Buffer
	if err := htmlReport.Execute(&b, r); err != nil {
		return fmt.Errorf("rendering html report: %w", err)
	}
	if err := os.WriteFile(path, b.Bytes(), 0o600); err != nil {
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
