package cli

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	backendpkg "github.com/Big-Comfy/deadair/internal/backend"
	"github.com/Big-Comfy/deadair/internal/report"
)

// runCheck verifies connectivity and privileges without producing a report.
// It is the feedback step between `setup` and the first scan: each required
// capability is tried and reported individually, so a role or network problem
// points at itself instead of surfacing as a failed scan.
func runCheck(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { checkUsage(stderr) }
	var o connOpts
	addBackendFlags(fs, &o)
	if parsed, code := parseFlags(fs, args); !parsed {
		return code
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "deadair: check does not accept positional arguments: %q\n", fs.Arg(0))
		return report.ExitError
	}
	insts, err := o.resolveInstances(stderr)
	if err != nil {
		fmt.Fprintf(stderr, "deadair: %v\n", err)
		return report.ExitError
	}

	var details bytes.Buffer
	ready := true
	limited := false
	for _, inst := range insts {
		fmt.Fprintf(&details, "\n%s (%s)\n", inst.name, inst.backend.Name())
		ctx, cancel := context.WithTimeout(context.Background(), o.timeout)
		if provider, available := inst.backend.(backendpkg.VersionProvider); available {
			versionCtx, versionCancel := context.WithTimeout(ctx, 5*time.Second)
			version, verr := provider.Version(versionCtx)
			versionCancel()
			if verr == nil {
				assessment := report.AssessBackendVersion(inst.backend.Name(), version)
				switch assessment.Status {
				case report.BackendVersionTested:
					fmt.Fprintf(&details, "  %s backend version %s (tested)\n", mark(stdout, true), version)
				case report.BackendVersionBestEffort:
					limited = true
					fmt.Fprintf(&details, "  - backend version %s (best-effort — %s)\n", version, assessment.Detail)
				case report.BackendVersionUnsupported:
					ready = false
					fmt.Fprintf(&details, "  %s backend version %s unsupported — %s\n", mark(stdout, false), version, assessment.Detail)
				}
			} else {
				limited = true
				fmt.Fprintf(&details, "  - backend version unavailable: %v\n", verr)
			}
		}

		rules, err := inst.backend.Rules(ctx)
		ruleInputUnavailable := 0
		ruleInputDetail := ""
		if err != nil {
			ready = false
			fmt.Fprintf(&details, "  %s detection rules not readable: %v\n", mark(stdout, false), err)
			authHint(&details, err)
		} else {
			fmt.Fprintf(&details, "  %s detection rules readable (%d rules)\n", mark(stdout, true), len(rules))
			for _, rule := range rules {
				if !rule.Enabled || rule.InputStatus != backendpkg.ResolutionUnavailable {
					continue
				}
				ruleInputUnavailable++
				if ruleInputDetail == "" {
					ruleInputDetail = rule.InputDetail
				}
			}
			if ruleInputUnavailable > 0 {
				ready = false
				fmt.Fprintf(&details, "  %s rule input discovery unavailable for %d enabled rule(s)", mark(stdout, false), ruleInputUnavailable)
				if ruleInputDetail != "" {
					fmt.Fprintf(&details, ": %s", ruleInputDetail)
				}
				fmt.Fprintln(&details)
				if ruleInputDetail != "" {
					authHint(&details, fmt.Errorf("%s", ruleInputDetail))
				}
			}
		}

		sources, err := inst.backend.Sources(ctx)
		if err != nil {
			ready = false
			fmt.Fprintf(&details, "  %s source stats not readable: %v\n", mark(stdout, false), err)
			authHint(&details, err)
		} else {
			fmt.Fprintf(&details, "  %s source stats readable (%d sources)\n", mark(stdout, true), len(sources))

			// Optional capabilities: needed by specific flags, not by scan.
			if len(sources) > 0 {
				schemas, serr := inst.backend.Schemas(ctx, sources[:1])
				if serr == nil && len(schemas) > 0 {
					fmt.Fprintf(&details, "  %s field mappings readable\n", mark(stdout, true))
				} else {
					limited = true
					fmt.Fprintln(&details, "  - field mappings not readable (optional; used by --schema)")
				}
			} else {
				limited = true
				fmt.Fprintln(&details, "  - field mappings not checked because no sources were visible")
			}
		}

		resolver, available := inst.backend.(backendpkg.Resolver)
		if !available {
			ready = false
			fmt.Fprintf(&details, "  %s native input resolution unavailable\n", mark(stdout, false))
		} else {
			probe := backendpkg.Rule{ID: "deadair-resolution-probe", Patterns: []string{"deadair-resolution-probe-does-not-exist-*"}}
			resolved, rerr := resolver.ResolveInputs(ctx, []backendpkg.Rule{probe})
			if rerr != nil || len(resolved) != 1 || (resolved[0].Status != backendpkg.ResolutionResolved && resolved[0].Status != backendpkg.ResolutionEmpty) {
				ready = false
				if rerr != nil {
					fmt.Fprintf(&details, "  %s native input resolution not readable: %v\n", mark(stdout, false), rerr)
				} else if len(resolved) == 0 {
					fmt.Fprintf(&details, "  %s native input resolution returned no evidence\n", mark(stdout, false))
				} else {
					fmt.Fprintf(&details, "  %s native input resolution is %s: %s\n", mark(stdout, false), resolved[0].Status, resolved[0].Detail)
				}
			} else if ruleInputUnavailable > 0 {
				fmt.Fprintf(&details, "  - native index-pattern resolution readable (%s); rule input discovery failed above\n", resolved[0].Status)
			} else {
				fmt.Fprintf(&details, "  %s native input resolution readable (%s)\n", mark(stdout, true), resolved[0].Status)
			}
		}
		cancel()
	}

	switch {
	case !ready:
		fmt.Fprintln(stdout, color(stdout, "31;1", "BLOCKED"))
		fmt.Fprintln(stdout, "A required read path failed. Fix the failures below before scanning.")
	case limited:
		fmt.Fprintln(stdout, color(stdout, "33;1", "READY WITH LIMITS"))
		fmt.Fprintln(stdout, "Live scans can run, but an optional check is unavailable.")
	default:
		fmt.Fprintln(stdout, color(stdout, "32;1", "READY"))
		fmt.Fprintln(stdout, "The credential can read rules, sources, and native resolution evidence.")
	}
	if _, err := io.Copy(stdout, &details); err != nil {
		fmt.Fprintf(stderr, "deadair: writing check output: %v\n", err)
		return report.ExitError
	}

	if ready {
		next := "deadair scan"
		if o.fleetFile != "" {
			next = "deadair scan --fleet " + o.fleetFile
		}
		fmt.Fprintf(stdout, "\nnext: %s\n", next)
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
