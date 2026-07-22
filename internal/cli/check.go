package cli

import (
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
		observedCapabilities := map[string]report.Capability{}
		observeUnavailable := func(name, detail string) {
			observedCapabilities[name] = report.Capability{
				Name: name, Status: report.CapabilityUnavailable, Detail: detail,
			}
		}
		observedVersion := ""
		if provider, available := inst.backend.(backendpkg.VersionProvider); available {
			versionCtx, versionCancel := context.WithTimeout(ctx, 5*time.Second)
			version, verr := provider.Version(versionCtx)
			versionCancel()
			if verr == nil {
				observedVersion = version
				assessment := report.AssessBackendVersion(inst.backend.Name(), version)
				switch assessment.Status {
				case report.BackendVersionTested:
					fmt.Fprintf(stdout, "  %s backend version %s (tested)\n", mark(stdout, true), version)
				case report.BackendVersionBestEffort:
					fmt.Fprintf(stdout, "  - backend version %s (best-effort — %s)\n", version, assessment.Detail)
				case report.BackendVersionUnsupported:
					ok = false
					fmt.Fprintf(stdout, "  %s backend version %s unsupported — %s\n", mark(stdout, false), version, assessment.Detail)
				}
			} else {
				fmt.Fprintf(stdout, "  - backend version unavailable: %v\n", verr)
			}
		}

		rules, err := inst.backend.Rules(ctx)
		ruleInputUnavailable := 0
		ruleInputDetail := ""
		if err != nil {
			ok = false
			observeUnavailable(report.CapabilityRuleInventory, "runtime rule-inventory probe failed")
			observeUnavailable(report.CapabilityRequiredFields, "runtime rule-inventory probe failed")
			fmt.Fprintf(stdout, "  %s detection rules not readable: %v\n", mark(stdout, false), err)
			authHint(stdout, err)
		} else {
			fmt.Fprintf(stdout, "  %s detection rules readable (%d rules)\n", mark(stdout, true), len(rules))
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
				ok = false
				detail := fmt.Sprintf("runtime rule-input discovery failed for %d enabled rule(s)", ruleInputUnavailable)
				observeUnavailable(report.CapabilitySourceResolution, detail)
				fmt.Fprintf(stdout, "  %s rule input discovery unavailable for %d enabled rule(s)", mark(stdout, false), ruleInputUnavailable)
				if ruleInputDetail != "" {
					fmt.Fprintf(stdout, ": %s", ruleInputDetail)
				}
				fmt.Fprintln(stdout)
				if ruleInputDetail != "" {
					authHint(stdout, fmt.Errorf("%s", ruleInputDetail))
				}
			}
		}

		sources, err := inst.backend.Sources(ctx)
		if err != nil {
			ok = false
			observeUnavailable(report.CapabilityFreshness, "runtime source-stats probe failed")
			observeUnavailable(report.CapabilityDocsStorage, "runtime source-stats probe failed")
			observeUnavailable(report.CapabilitySchema, "runtime source-stats probe failed before schema could be checked")
			observeUnavailable(report.CapabilityIngestLag, "runtime source-stats probe failed")
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
					observeUnavailable(report.CapabilitySchema, "runtime field-mapping probe failed")
					fmt.Fprintf(stdout, "  - field mappings not readable (optional; used by --schema)\n")
				}
			} else {
				observedCapabilities[report.CapabilitySchema] = report.Capability{
					Name: report.CapabilitySchema, Status: report.CapabilityPartial,
					Detail: "not probed because no sources were visible",
				}
			}
		}

		resolver, available := inst.backend.(backendpkg.Resolver)
		if !available {
			ok = false
			observeUnavailable(report.CapabilitySourceResolution, "backend adapter has no native resolver")
			fmt.Fprintf(stdout, "  %s native input resolution unavailable\n", mark(stdout, false))
		} else {
			probe := backendpkg.Rule{ID: "deadair-resolution-probe", Patterns: []string{"deadair-resolution-probe-does-not-exist-*"}}
			resolved, rerr := resolver.ResolveInputs(ctx, []backendpkg.Rule{probe})
			if rerr != nil || len(resolved) != 1 || (resolved[0].Status != backendpkg.ResolutionResolved && resolved[0].Status != backendpkg.ResolutionEmpty) {
				ok = false
				observeUnavailable(report.CapabilitySourceResolution, "runtime native-resolution probe failed")
				if rerr != nil {
					fmt.Fprintf(stdout, "  %s native input resolution not readable: %v\n", mark(stdout, false), rerr)
				} else if len(resolved) == 0 {
					fmt.Fprintf(stdout, "  %s native input resolution returned no evidence\n", mark(stdout, false))
				} else {
					fmt.Fprintf(stdout, "  %s native input resolution is %s: %s\n", mark(stdout, false), resolved[0].Status, resolved[0].Detail)
				}
			} else if ruleInputUnavailable > 0 {
				fmt.Fprintf(stdout, "  - native index-pattern resolution readable (%s); rule input discovery failed above\n", resolved[0].Status)
			} else {
				fmt.Fprintf(stdout, "  %s native input resolution readable (%s)\n", mark(stdout, true), resolved[0].Status)
			}
		}

		metadata := report.MetadataForBackend(inst.backend.Name(), observedVersion)
		for i := range metadata.Capabilities {
			if observed, exists := observedCapabilities[metadata.Capabilities[i].Name]; exists {
				metadata.Capabilities[i] = observed
			}
		}
		fmt.Fprintln(stdout, "  capabilities (adapter limits; runtime failures override):")
		for _, capability := range metadata.Capabilities {
			fmt.Fprintf(stdout, "    %-20s %s", capability.Name, capability.Status)
			if capability.Detail != "" {
				fmt.Fprintf(stdout, " — %s", capability.Detail)
			}
			fmt.Fprintln(stdout)
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
