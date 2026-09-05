package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/alephnull-sh/deadair/internal/report"
)

func runInspect(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("inspect", flag.ContinueOnError)
	fs.SetOutput(stderr)
	source := fs.String("source", "", "exact source name to investigate")
	producer := fs.String("producer", "", "expected producer ID to investigate")
	instance := fs.String("instance", "", "instance name in a saved fleet report")
	links := fs.Bool("links", false, "include native SIEM and runbook links")
	fs.Usage = func() { inspectUsage(stderr) }
	if ok, code := parseFlags(fs, args); !ok {
		return code
	}
	if fs.NArg() != 1 || (*source != "" && *producer != "") {
		fs.Usage()
		return report.ExitError
	}
	f, err := os.Open(fs.Arg(0))
	if err != nil {
		fmt.Fprintln(stderr, "deadair: report could not be opened")
		return report.ExitError
	}
	defer f.Close()
	if info, err := f.Stat(); err != nil || info.Size() > 64<<20 {
		fmt.Fprintln(stderr, "deadair: report could not be read or exceeds 64 MiB")
		return report.ExitError
	}
	var saved struct {
		report.Report
		Instances []*report.Report       `json:"instances"`
		Errors    []report.InstanceError `json:"errors"`
	}
	dec := json.NewDecoder(io.LimitReader(f, 64<<20))
	if err := dec.Decode(&saved); err != nil || (saved.SchemaVersion != report.ReportSchemaVersion && saved.SchemaVersion != report.FleetReportSchemaVersion) {
		fmt.Fprintln(stderr, "deadair: expected a deadair report JSON file")
		return report.ExitError
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		fmt.Fprintln(stderr, "deadair: report contains trailing data")
		return report.ExitError
	}
	r := &saved.Report
	if saved.SchemaVersion == report.FleetReportSchemaVersion {
		r = nil
		var names []string
		for _, member := range saved.Instances {
			if member == nil {
				continue
			}
			names = append(names, terminalText(member.Instance))
			if member.Instance == *instance && *instance != "" {
				if r != nil || member.SchemaVersion != report.ReportSchemaVersion {
					fmt.Fprintln(stderr, "deadair: fleet report contains an invalid or duplicate instance")
					return report.ExitError
				}
				r = member
			}
		}
		for _, failed := range saved.Errors {
			if failed.Instance == *instance && *instance != "" {
				fmt.Fprintln(stderr, "deadair: this instance's scan failed; no investigation report is available")
				return report.ExitError
			}
		}
		if r == nil {
			fmt.Fprintln(stderr, "deadair: select a saved instance with --instance NAME")
			printParagraph(stderr, "  ", "Available: "+strings.Join(names, ", "))
			return report.ExitError
		}
	} else if *instance != "" && *instance != r.Instance {
		fmt.Fprintln(stderr, "deadair: this report does not contain the requested instance")
		return report.ExitError
	}
	if r.Instance != "" && (saved.SchemaVersion == report.FleetReportSchemaVersion || !strings.EqualFold(r.Instance, r.Backend)) {
		fmt.Fprintf(stdout, "Instance: %s\n", terminalText(r.Instance))
	}
	if !r.GeneratedAt.IsZero() {
		fmt.Fprintf(stdout, "Saved scan · %s · %s\n", terminalText(r.Backend), r.GeneratedAt.UTC().Format("2 Jan 2006, 15:04 UTC"))
	}
	found := false
	if *producer == "" {
		for _, item := range r.SourceImpacts {
			if *source != "" && item.Source != *source {
				continue
			}
			printSourceImpact(stdout, item, 0, *links)
			found = true
		}
	}
	if *source == "" {
		for _, item := range r.Producers {
			if *producer != "" && item.ID != *producer {
				continue
			}
			printProducer(stdout, item, true, *links)
			found = true
		}
	}
	if !found {
		fmt.Fprintln(stderr, "deadair: no matching investigation record; check the name or create a new scan report")
		return report.ExitError
	}
	return 0
}

func terminalText(value string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return ' '
		}
		return r
	}, value)
}

func findingSubject(f report.Finding) string {
	if (f.Class == report.FindingProducerStale || f.Class == report.FindingSummaryPipeline) && f.Dependency != "" {
		return terminalText(f.Dependency + " · " + f.Source)
	}
	if f.Source != "" {
		return terminalText(f.Source)
	}
	return terminalText(f.RuleName)
}

func printSourceImpact(w io.Writer, s report.SourceImpact, limit int, links bool) {
	status := s.Status
	if len(s.MissingFields) > 0 {
		status = "missing fields"
	} else if s.Schema != nil && s.Schema.Status == "drift" {
		status = "schema changed"
	} else if s.Volume != nil && s.Volume.Status == "low" {
		status = "volume below baseline"
	} else if s.Status == "ok" && s.FirstCheck != "" {
		status = "delayed"
	}
	fmt.Fprintf(w, "\n%s — %s\n", color(w, "1", terminalText(s.Source)), color(w, observationColor(status), terminalText(status)))
	for _, o := range s.Freshness {
		printObservation(w, o)
	}
	if len(s.MissingFields) > 0 {
		printParagraph(w, "  ", "Missing declared fields: "+strings.Join(s.MissingFields, ", "))
	}
	if lag := s.IngestLag; lag != nil && lag.Status == "assessed" {
		fmt.Fprintf(w, "  Ingest lag: p95 %s; max %s (%s)\n", humanDuration(lag.P95Seconds), humanDuration(lag.MaxSeconds), countLabel(lag.SampleCount, "paired event", "paired events"))
	}
	if s.Volume != nil && s.Volume.Status == "low" {
		fmt.Fprintf(w, "  Volume: %.1f events/hour; baseline %.1f (%s)\n", s.Volume.RatePerHour, s.Volume.BaselineMean, countLabel(s.Volume.SampleCount, "sample", "samples"))
	}
	if s.Schema != nil && s.Schema.Status == "drift" {
		if len(s.Schema.Removed) > 0 {
			printParagraph(w, "  ", "Removed fields: "+strings.Join(s.Schema.Removed, ", "))
		}
		if len(s.Schema.Added) > 0 {
			printParagraph(w, "  ", "Added fields: "+strings.Join(s.Schema.Added, ", "))
		}
		for _, field := range s.Schema.TypeChanged {
			printParagraph(w, "  ", "Changed type: "+field.Name+" ("+strings.Join(field.Before, ", ")+" → "+strings.Join(field.After, ", ")+")")
		}
	}
	if s.Owner != "" {
		fmt.Fprintf(w, "  Owner: %s\n", terminalText(s.Owner))
	}
	fmt.Fprintf(w, "  %s:\n", countLabel(len(s.Detections), "enabled detection reads this source", "enabled detections read this source"))
	printConsumers(w, s.Detections, limit, links)
	if s.FirstCheck != "" {
		printParagraph(w, "  ", s.FirstCheck)
	}
	if links && s.Runbook != "" {
		fmt.Fprintf(w, "  Runbook: %s\n", terminalText(s.Runbook))
	}
	if links && s.URL != "" {
		fmt.Fprintf(w, "  Source: %s\n", terminalText(s.URL))
	}
}

func printObservation(w io.Writer, o report.SourceObservation) {
	basis := strings.ReplaceAll(string(o.Basis), "_", " ")
	var line strings.Builder
	fmt.Fprintf(&line, "%s: %s", terminalText(basis), terminalText(o.FreshnessStatus))
	if o.AgeSeconds > 0 {
		prefix := ""
		if o.AgeLowerBound {
			prefix = "at least "
		}
		event := "event"
		if o.Basis == "ingestion_time" {
			event = "arrival"
		}
		fmt.Fprintf(&line, ", %s%s since the last %s", prefix, humanDuration(o.AgeSeconds), event)
	}
	if o.ExpectedDowntime {
		fmt.Fprint(&line, " (maintenance; alert suppressed)")
	}
	var wrapped strings.Builder
	printParagraph(&wrapped, "  ", line.String())
	status := terminalText(o.FreshnessStatus)
	// Colour the status, not the timestamps and other evidence beside it.
	text := strings.Replace(wrapped.String(), ": "+status, ": "+color(w, observationColor(o.FreshnessStatus), status), 1)
	fmt.Fprint(w, text)
	if o.Status != "assessed" && o.Detail != "" {
		printParagraph(w, "    ", o.Detail)
	}
}

func consumerStatus(status string) string {
	switch status {
	case "cannot_fire":
		return "cannot fire"
	case "impaired":
		return "reduced visibility"
	case "unassessed":
		return "assessment incomplete"
	default:
		return "reads this source"
	}
}

func printConsumers(w io.Writer, rules []report.SourceConsumer, limit int, links bool) {
	for i, d := range rules {
		if limit > 0 && i >= limit {
			fmt.Fprintf(w, "    … %d more in the saved report\n", len(rules)-i)
			break
		}
		printParagraph(w, "    ", fmt.Sprintf("[%s] %s — %s", d.Severity, d.Name, consumerStatus(d.Status)))
		if links && d.URL != "" {
			fmt.Fprintf(w, "      %s\n", terminalText(d.URL))
		}
	}
}

func printProducer(w io.Writer, p report.ProducerHealth, detail, links bool) {
	fmt.Fprintf(w, "\n%s · %s\n", color(w, "1", terminalText(p.ID)), terminalText(p.Source))
	printObservation(w, p.Observation)
	fmt.Fprintf(w, "  Expected at least once every %s\n", humanDuration(p.MaxStaleSeconds))
	if p.Owner != "" {
		fmt.Fprintf(w, "  Owner: %s\n", terminalText(p.Owner))
	}
	fmt.Fprintf(w, "  %s:\n", countLabel(len(p.ConfirmedDetections), "detection requires this producer", "detections require this producer"))
	for _, rule := range p.ConfirmedDetections {
		fmt.Fprintf(w, "    [%s] %s\n", terminalText(rule.Severity), terminalText(rule.Name))
		if links && rule.URL != "" {
			fmt.Fprintf(w, "      %s\n", terminalText(rule.URL))
		}
	}
	if len(p.OtherTableConsumers) > 0 {
		fmt.Fprintf(w, "  %s; producer dependency not established.\n", countLabel(len(p.OtherTableConsumers), "other table consumer", "other table consumers"))
		if detail {
			printConsumers(w, p.OtherTableConsumers, 0, false)
		}
	}
	if links && p.Runbook != "" {
		fmt.Fprintf(w, "  Runbook: %s\n", terminalText(p.Runbook))
	}
}

// Wrap prose without truncating identifiers or breaking copyable native URLs.
func printParagraph(w io.Writer, indent, value string) {
	printStyledParagraph(w, indent, value, "")
}

func printStyledParagraph(w io.Writer, indent, value, code string) {
	line := indent
	for _, word := range strings.Fields(terminalText(value)) {
		if line != indent && utf8.RuneCountInString(line)+1+utf8.RuneCountInString(word) > 78 {
			fmt.Fprintln(w, color(w, code, line))
			line = indent
		}
		if line != indent {
			line += " "
		}
		line += word
	}
	fmt.Fprintln(w, color(w, code, line))
}

func observationColor(status string) string {
	switch status {
	case "ok":
		return "32"
	case "maintenance":
		return "36"
	default:
		return "33"
	}
}

func printInvestigationSummary(w io.Writer, r *report.Report) {
	shown := 0
	for _, s := range r.SourceImpacts {
		if s.FirstCheck == "" {
			continue
		}
		if shown == 5 {
			fmt.Fprintln(w, "  More sources are listed in the saved report.")
			break
		}
		if shown == 0 {
			visualHeading(w, "1", "Sources to investigate", 0)
		}
		detail := s.Status
		if len(s.MissingFields) > 0 {
			detail = "missing fields: " + strings.Join(s.MissingFields, ", ")
		} else if s.Schema != nil && s.Schema.Status == "drift" {
			detail = "field schema changed"
		} else if s.Volume != nil && s.Volume.Status == "low" {
			detail = "volume below baseline"
		} else if s.IngestLag != nil && s.IngestLag.Status == "assessed" && s.IngestLag.P95Seconds > 0 && s.Status == "ok" {
			detail = "p95 ingest lag " + humanDuration(s.IngestLag.P95Seconds)
		}
		fmt.Fprintf(w, "  %s — %s\n", color(w, "1", terminalText(s.Source)), terminalText(detail))
		shown++
	}
	for _, p := range r.Producers {
		if p.Observation.FreshnessStatus != "ok" {
			printProducer(w, p, false, false)
		}
	}
}

func printSavedReport(w io.Writer, path string, canInspect bool) {
	if path == "" {
		return
	}
	if arg, ok := commandPath(path); canInspect && ok {
		fmt.Fprintf(w, "Inspect: deadair inspect -- %s\n", arg)
		return
	}
	fmt.Fprintf(w, "Saved JSON: %s\n", terminalText(path))
}

// Only suggest commands whose arguments are safe in common Unix and Windows
// shells. Other filenames remain visible without inviting a misleading paste.
func commandPath(path string) (string, bool) {
	if path == "" {
		return "", false
	}
	for _, c := range path {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || strings.ContainsRune("/._:- ", c) {
			continue
		}
		return "", false
	}
	if strings.ContainsRune(path, ' ') {
		return `"` + path + `"`, true
	}
	return path, true
}
