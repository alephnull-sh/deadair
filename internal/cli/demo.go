package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"

	"github.com/Big-Comfy/deadair/internal/demo"
	"github.com/Big-Comfy/deadair/internal/report"
)

// runDemo renders deterministic embedded evidence without reading live
// configuration or contacting a backend.
func runDemo(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("demo", flag.ContinueOnError)
	fs.SetOutput(stderr)
	jsonOut := fs.Bool("json", false, "write the full JSON report to stdout")
	outFile := fs.String("out", "", "also write the JSON report to a file (created 0600)")
	htmlFile := fs.String("html-out", "", "write a static HTML report to a file (created 0600)")
	redactNames := fs.Bool("redact", false, "replace source/rule names with stable digests (shareable report)")
	if err := fs.Parse(args); err != nil {
		return report.ExitError
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "deadair: demo does not accept positional arguments: %q\n", fs.Arg(0))
		return report.ExitError
	}

	r, err := demo.Build()
	if err != nil {
		fmt.Fprintf(stderr, "deadair: demo failed: %v\n", err)
		return report.ExitError
	}
	r.Producer.Version = Version
	if *redactNames {
		r.Redact()
	}
	if *outFile != "" {
		if err := r.Write(*outFile); err != nil {
			fmt.Fprintf(stderr, "deadair: %v\n", err)
			return report.ExitError
		}
	}
	if *htmlFile != "" {
		if err := r.WriteHTML(*htmlFile); err != nil {
			fmt.Fprintf(stderr, "deadair: %v\n", err)
			return report.ExitError
		}
	}
	if *jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(r); err != nil {
			fmt.Fprintf(stderr, "deadair: %v\n", err)
			return report.ExitError
		}
	} else {
		printSummary(stdout, r)
		fmt.Fprint(stdout, `
This report uses embedded sample data; no SIEM connection was made.
Run the same checks on your environment:
  deadair setup     # print least-privilege credential setup
  deadair check     # verify connectivity and privileges
  deadair scan      # scan live rules and telemetry
`)
	}

	// Demo findings illustrate the report shape and must not act as a CI gate.
	return report.ExitHealthy
}
