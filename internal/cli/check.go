package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/Big-Comfy/deadair/internal/report"
)

// runCheck verifies connectivity and privileges without producing a report.
// It is the feedback step between `setup` and the first scan: each required
// capability is tried and reported individually, so a role or network problem
// points at itself instead of surfacing as a failed scan.
func runCheck(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var o connOpts
	addConnFlags(fs, &o)
	if err := fs.Parse(args); err != nil {
		return report.ExitError
	}
	insts, err := o.resolveInstances(stderr)
	if err != nil {
		fmt.Fprintf(stderr, "deadair: %v\n", err)
		return report.ExitError
	}

	ok := true
	for _, inst := range insts {
		fmt.Fprintf(stdout, "%s (%s)\n", inst.name, inst.backend.Name())
		ctx, cancel := context.WithTimeout(context.Background(), o.timeout)

		rules, err := inst.backend.Rules(ctx)
		if err != nil {
			ok = false
			fmt.Fprintf(stdout, "  %s detection rules not readable: %v\n", mark(stdout, false), err)
			authHint(stdout, err)
		} else {
			fmt.Fprintf(stdout, "  %s detection rules readable (%d rules)\n", mark(stdout, true), len(rules))
		}

		sources, err := inst.backend.Sources(ctx)
		if err != nil {
			ok = false
			fmt.Fprintf(stdout, "  %s source stats not readable: %v\n", mark(stdout, false), err)
			authHint(stdout, err)
		} else {
			fmt.Fprintf(stdout, "  %s source stats readable (%d sources)\n", mark(stdout, true), len(sources))

			// Optional capabilities: needed by specific flags, not by scan.
			if len(sources) > 0 {
				schemas, serr := inst.backend.Schemas(ctx, sources[:1])
				if serr == nil && len(schemas) > 0 {
					fmt.Fprintf(stdout, "  %s field mappings readable\n", mark(stdout, true))
				} else {
					fmt.Fprintf(stdout, "  - field mappings not readable (optional; used by --schema)\n")
				}
			}
		}
		cancel()
	}

	if ok {
		next := "deadair scan"
		if o.fleetFile != "" {
			next = "deadair scan --fleet " + o.fleetFile
		}
		fmt.Fprintf(stdout, "\n%s\n", color(stdout, "32", "ready — run `"+next+"`"))
		return report.ExitHealthy
	}
	return report.ExitError
}

func mark(w io.Writer, good bool) string {
	if good {
		return color(w, "32", "ok")
	}
	return color(w, "31", "FAIL")
}

func authHint(w io.Writer, err error) {
	s := err.Error()
	if strings.Contains(s, "401") || strings.Contains(s, "403") {
		fmt.Fprintln(w, "    the credential was rejected — `deadair setup` shows the expected role")
	}
	if strings.Contains(s, "certificate") || strings.Contains(s, "x509") {
		fmt.Fprintln(w, "    TLS trust problem — pass the signing CA with --ca-cert")
	}
}
