package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alephnull-sh/deadair/internal/backend"
	"github.com/alephnull-sh/deadair/internal/report"
)

type candidateResolutionProbe struct {
	sentinelReportProbe
	denied bool
}

func (p *candidateResolutionProbe) ResolveInputs(ctx context.Context, rules []backend.Rule) ([]backend.InputResolution, error) {
	items, err := p.sentinelReportProbe.ResolveInputs(ctx, rules)
	if p.denied {
		items[0].Status, items[0].ResolvedSources = backend.ResolutionUnavailable, nil
	}
	return items, err
}

func TestCandidateDiffRejectsLostEvidence(t *testing.T) {
	dir := t.TempDir()
	candidate := filepath.Join(dir, "candidate.json")
	if err := os.WriteFile(candidate, []byte(`{"name":"candidate"}`), 0600); err != nil {
		t.Fatal(err)
	}
	o := connOpts{maxStale: time.Hour, ruleFile: candidate, include: patternList{"SecurityEvent"}}
	probe := &candidateResolutionProbe{}
	paths := []string{filepath.Join(dir, "before.json"), filepath.Join(dir, "after.json")}
	for i, path := range paths {
		probe.denied = i == 1
		result, err := scanOnce(context.Background(), probe, o, "prod", "target-sentinel")
		if err != nil {
			t.Fatal(err)
		}
		want := report.ExitHealthy
		if probe.denied {
			want = report.ExitError
		}
		if result.report.CandidateExitCode() != want {
			t.Fatalf("scan fixture exit=%d, want %d", result.report.CandidateExitCode(), want)
		}
		if err := result.report.Write(path); err != nil {
			t.Fatal(err)
		}
	}
	for _, jsonOutput := range []bool{false, true} {
		args := append([]string(nil), paths...)
		if jsonOutput {
			args = append([]string{"--json"}, args...)
		}
		var stdout, stderr bytes.Buffer
		if code := runDiff(args, &stdout, &stderr); code != report.ExitError || stdout.Len() != 0 || !strings.Contains(stderr.String(), "newer candidate") {
			t.Fatalf("diff code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
		}
	}
}
