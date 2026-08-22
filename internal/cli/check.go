package cli

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	backendpkg "github.com/alephnull-sh/deadair/internal/backend"
	"github.com/alephnull-sh/deadair/internal/report"
)

// runCheck verifies connectivity and privileges without producing a report.
// It is the feedback step between `setup` and the first scan: each required
// capability is tried and reported individually, so a role or network problem
// points at itself instead of surfacing as a failed scan.
func runCheck(args []string, stdout, stderr io.Writer) int {
	return runCheckWithTargets(args, stdout, stderr, (*connOpts).resolveInstances)
}

type checkTargetResolver func(*connOpts, io.Writer) ([]fleetInstance, error)

func runCheckWithTargets(args []string, stdout, stderr io.Writer, resolveTargets checkTargetResolver) int {
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
	insts, err := resolveTargets(&o, stderr)
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
				fmt.Fprintf(&details, "  %s rule input discovery unavailable for %s", mark(stdout, false), countLabel(ruleInputUnavailable, "enabled rule", "enabled rules"))
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
			fmt.Fprintf(&details, "  %s source inventory not readable: %v\n", mark(stdout, false), err)
			authHint(&details, err)
		} else {
			fmt.Fprintf(&details, "  %s source inventory readable (%d sources)\n", mark(stdout, true), len(sources))
			if provider, available := inst.backend.(backendpkg.ReadinessProvider); available {
				evidence, probeErr := provider.ReadinessEvidence(ctx, rules, sources)
				switch {
				case probeErr != nil:
					ready = false
					fmt.Fprintf(&details, "  %s runtime query path not readable: %v\n", mark(stdout, false), probeErr)
					authHint(&details, probeErr)
				case !evidence.Attempted:
					limited = true
					fmt.Fprintf(&details, "  - runtime query path not checked: %s\n", evidence.Detail)
				case evidence.Status != backendpkg.EvidenceAssessed:
					ready = false
					fmt.Fprintf(&details, "  %s runtime query path not readable: %s\n", mark(stdout, false), evidence.Detail)
					authHint(&details, fmt.Errorf("%s", evidence.Detail))
				case evidence.Limited:
					limited = true
					fmt.Fprintf(&details, "  - runtime query path readable with limits: %s\n", evidence.Detail)
				default:
					fmt.Fprintf(&details, "  %s runtime query path readable for enabled-rule sources\n", mark(stdout, true))
				}
			}

			// Optional capabilities: needed by specific flags, not by scan.
			if len(sources) > 0 {
				schemas, serr := inst.backend.Schemas(ctx, sources[:1])
				if serr == nil && len(schemas) > 0 {
					fmt.Fprintf(&details, "  %s source schemas readable\n", mark(stdout, true))
				} else {
					limited = true
					fmt.Fprintln(&details, "  - source schemas not readable (optional; used by --schema)")
				}
			} else {
				limited = true
				fmt.Fprintln(&details, "  - source schemas not checked because no sources were visible")
			}
		}

		resolver, available := inst.backend.(backendpkg.Resolver)
		if !available {
			ready = false
			fmt.Fprintf(&details, "  %s native input resolution unavailable\n", mark(stdout, false))
		} else {
			resolution, rerr := probeNativeInputResolution(ctx, resolver)
			if rerr != nil {
				ready = false
				fmt.Fprintf(&details, "  %s native input resolution not readable: %v\n", mark(stdout, false), rerr)
			} else if ruleInputUnavailable > 0 {
				fmt.Fprintf(&details, "  - native input resolution readable; rule input discovery failed above\n")
			} else if resolution.Status == backendpkg.ResolutionEmpty {
				fmt.Fprintf(&details, "  %s native input resolution readable (missing sources can be proved)\n", mark(stdout, true))
			} else {
				fmt.Fprintf(&details, "  %s native input resolution readable (%s)\n", mark(stdout, true), resolution.Status)
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
		fmt.Fprintln(stdout, "Live scans can run, but one or more checks have limits.")
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

func probeNativeInputResolution(ctx context.Context, resolver backendpkg.Resolver) (backendpkg.InputResolution, error) {
	probe := backendpkg.Rule{ID: "deadair-resolution-probe", Enabled: true, Patterns: []string{"deadair-resolution-probe-does-not-exist-*"}}
	resolved, err := resolver.ResolveInputs(ctx, []backendpkg.Rule{probe})
	if err != nil {
		return backendpkg.InputResolution{}, err
	}
	authoritative := make([]backendpkg.InputResolution, 0, 1)
	for _, resolution := range resolved {
		if !resolution.Diagnostic {
			authoritative = append(authoritative, resolution)
		}
	}
	if len(authoritative) == 0 {
		return backendpkg.InputResolution{}, fmt.Errorf("native input resolution returned no authoritative evidence")
	}
	if len(authoritative) != 1 {
		return backendpkg.InputResolution{}, fmt.Errorf("native input resolution returned %d authoritative results", len(authoritative))
	}
	resolution := authoritative[0]
	if resolution.Status != backendpkg.ResolutionResolved && resolution.Status != backendpkg.ResolutionEmpty {
		return backendpkg.InputResolution{}, fmt.Errorf("native input resolution is %s: %s", resolution.Status, resolution.Detail)
	}
	return resolution, nil
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
