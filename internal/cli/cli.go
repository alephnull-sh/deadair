// Package cli wires the deadair commands. Secrets come from the environment
// or a file, never from argv (argv leaks in process listings).
package cli

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"sort"
	"strings"
	"syscall"
	"time"

	backendpkg "github.com/alephnull-sh/deadair/internal/backend"
	"github.com/alephnull-sh/deadair/internal/backend/elastic"
	"github.com/alephnull-sh/deadair/internal/backend/opensearch"
	"github.com/alephnull-sh/deadair/internal/exporter"
	"github.com/alephnull-sh/deadair/internal/graph"
	"github.com/alephnull-sh/deadair/internal/health"
	redactpkg "github.com/alephnull-sh/deadair/internal/redact"
	"github.com/alephnull-sh/deadair/internal/report"
	"github.com/alephnull-sh/deadair/internal/state"
)

// Version is stamped at build time via -ldflags.
var Version = "dev"

func init() {
	info, ok := debug.ReadBuildInfo()
	Version = versionFromBuildInfo(Version, info, ok)
}

func versionFromBuildInfo(stamped string, info *debug.BuildInfo, ok bool) string {
	if stamped != "" && stamped != "dev" {
		return stamped
	}
	fallback := stamped
	if fallback == "" {
		fallback = "dev"
	}
	if !ok || info == nil || info.Main.Path != "github.com/alephnull-sh/deadair" {
		return fallback
	}
	if info.Main.Version == "" || info.Main.Version == "(devel)" {
		return fallback
	}
	return info.Main.Version
}

// printHelp writes the top-level help. Shown on bare invocation (exit 0, per
// CLI convention: typing the program name is a request for orientation, not
// an error).
func printHelp(w io.Writer) {
	h := func(s string) string { return color(w, "1", s) }
	fmt.Fprintf(w, "%s — telemetry health monitoring for SIEM detections\n\n", h("deadair"))
	fmt.Fprintln(w, "Maps detection rules to the log sources they read and reports which rules")
	fmt.Fprintln(w, "cannot currently detect anything. Read-only; Elastic and OpenSearch.")
	fmt.Fprintf(w, "\n%s\n", h("USAGE"))
	fmt.Fprintln(w, "  deadair <command> [flags]")
	fmt.Fprintf(w, "\n%s\n", h("COMMANDS"))
	fmt.Fprintln(w, "  setup     print least-privilege credential setup for a backend")
	fmt.Fprintln(w, "  check     verify readiness for a live scan")
	fmt.Fprintln(w, "  scan      one-shot report; exit 0 passed, 1 gated findings, 2 error")
	fmt.Fprintln(w, "  serve     Prometheus exporter with periodic scans")
	fmt.Fprintln(w, "  diff      compare two reports; exit 1 on regressions")
	fmt.Fprintln(w, "  tune      suggest baseline settings from accumulated state")
	fmt.Fprintln(w, "  version   print version")
	fmt.Fprintf(w, "\n%s\n", h("GET STARTED"))
	fmt.Fprintln(w, "  deadair setup     # print the read-only credential setup")
	fmt.Fprintln(w, "  deadair check     # confirm the credential can scan")
	fmt.Fprintln(w, "  deadair scan      # assess live rules and telemetry")
	if os.Getenv("DEADAIR_ES_URL") != "" {
		fmt.Fprintln(w, "\nconfigured: elastic")
	} else if os.Getenv("DEADAIR_OPENSEARCH_URL") != "" {
		fmt.Fprintln(w, "\nconfigured: opensearch")
	} else {
		fmt.Fprintln(w, "\nnot configured yet — start with: deadair setup")
	}
	fmt.Fprintf(w, "\nRun \"deadair <command> -h\" for flags. Guide: %s\n", usageGuideURL)
}

var commands = []string{"scan", "serve", "check", "diff", "tune", "setup", "version", "help"}

// suggest returns the closest command name, or "" if nothing is close.
func suggest(input string) string {
	best, bestDist := "", 3 // suggest only within edit distance 2
	for _, c := range commands {
		if d := editDistance(input, c); d < bestDist {
			best, bestDist = c, d
		}
	}
	return best
}

func editDistance(a, b string) int {
	prev := make([]int, len(b)+1)
	cur := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, min(cur[j-1]+1, prev[j-1]+cost))
		}
		prev, cur = cur, prev
	}
	return prev[len(b)]
}

// Run executes the CLI and returns the process exit code.
func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printHelp(stdout)
		return 0
	}
	switch args[0] {
	case "scan":
		return runScan(args[1:], stdout, stderr)
	case "serve":
		return runServe(args[1:], stderr)
	case "check":
		return runCheck(args[1:], stdout, stderr)
	case "tune":
		return runTune(args[1:], stdout, stderr)
	case "diff":
		return runDiff(args[1:], stdout, stderr)
	case "setup":
		return runSetup(args[1:], stdout, stderr)
	case "version", "-v", "--version":
		fmt.Fprintln(stdout, Version)
		return 0
	case "help", "-h", "--help":
		printHelp(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "deadair: unknown command %q\n", args[0])
		if s := suggest(args[0]); s != "" {
			fmt.Fprintf(stderr, "did you mean %q?\n", s)
		}
		fmt.Fprintln(stderr, `run "deadair" for the command list`)
		return report.ExitError
	}
}

type connOpts struct {
	backendName            string
	esURL                  string
	kibanaURL              string
	opensearchURL          string
	opensearchUsername     string
	opensearchPasswordFile string
	apiKeyFile             string
	timeout                time.Duration
	concurrency            int
	maxStale               time.Duration
	include                patternList
	exclude                patternList
	downtimeFile           string
	stateFile              string
	volumeWarmup           time.Duration
	volumeHysteresis       int
	volumeMinSamples       int
	volumeZThreshold       float64
	schemaTrack            bool
	ruleFile               string // scan-only: proposed-change (candidate rule) mode
	caCert                 string
	insecureTLS            bool
	kibanaSpace            string
	fleetFile              string
	instanceName           string
	policyFile             string
	policy                 *report.Policy
}

func addBackendFlags(fs *flag.FlagSet, o *connOpts) {
	fs.StringVar(&o.backendName, "backend", envOr("DEADAIR_BACKEND", "elastic"), "backend to scan: elastic or opensearch (env DEADAIR_BACKEND)")
	fs.StringVar(&o.esURL, "es-url", os.Getenv("DEADAIR_ES_URL"), "Elasticsearch base URL (env DEADAIR_ES_URL)")
	fs.StringVar(&o.kibanaURL, "kibana-url", os.Getenv("DEADAIR_KIBANA_URL"), "Kibana base URL (env DEADAIR_KIBANA_URL)")
	fs.StringVar(&o.opensearchURL, "opensearch-url", os.Getenv("DEADAIR_OPENSEARCH_URL"), "OpenSearch base URL (env DEADAIR_OPENSEARCH_URL)")
	fs.StringVar(&o.opensearchUsername, "opensearch-username", os.Getenv("DEADAIR_OPENSEARCH_USERNAME"), "OpenSearch username for basic auth (env DEADAIR_OPENSEARCH_USERNAME)")
	fs.StringVar(&o.opensearchPasswordFile, "opensearch-password-file", "", "file containing the OpenSearch password (default: env DEADAIR_OPENSEARCH_PASSWORD)")
	fs.StringVar(&o.apiKeyFile, "api-key-file", "", "file containing the API key (default: env DEADAIR_API_KEY)")
	fs.DurationVar(&o.timeout, "timeout", 60*time.Second, "overall timeout per scan")
	fs.IntVar(&o.concurrency, "concurrency", 4, "max parallel source-health and input-resolution queries")
	fs.StringVar(&o.caCert, "ca-cert", "", "PEM file with the CA that signed the SIEM's TLS certificate")
	fs.BoolVar(&o.insecureTLS, "insecure-skip-verify", false, "skip TLS certificate verification (testing only)")
	fs.StringVar(&o.kibanaSpace, "kibana-space", "", "Kibana space holding the detection rules (default: default space)")
	fs.StringVar(&o.fleetFile, "fleet", "", "fleet config JSON: scan multiple instances/tenants in one run")
	fs.StringVar(&o.instanceName, "instance-name", "", "instance label in reports and metrics (default: backend name)")
}

func addAssessmentFlags(fs *flag.FlagSet, o *connOpts) {
	fs.DurationVar(&o.maxStale, "max-stale", 30*time.Minute, "freshness window before a source counts as stale")
	fs.Var(&o.include, "include", "source name pattern to include; repeatable, default includes all sources")
	fs.Var(&o.exclude, "exclude", "source name pattern to exclude; repeatable, wins over --include")
	fs.StringVar(&o.downtimeFile, "downtime-file", "", "JSON file describing expected per-source downtime windows")
	fs.StringVar(&o.stateFile, "state-file", "", "state file for volume baselines, warmup, and hysteresis (created 0600 on POSIX)")
	fs.DurationVar(&o.volumeWarmup, "volume-warmup", 24*time.Hour, "time a source must be observed before volume-baseline findings can fire")
	fs.IntVar(&o.volumeHysteresis, "volume-hysteresis", 2, "consecutive low-volume scans required before a volume finding fires")
	fs.IntVar(&o.volumeMinSamples, "volume-min-samples", 4, "same weekday/hour samples required before volume baselines evaluate")
	fs.Float64Var(&o.volumeZThreshold, "volume-z-threshold", 3, "negative z-score threshold for low-volume findings")
	fs.BoolVar(&o.schemaTrack, "schema", false, "track field_caps schema drift; requires --state-file")
	fs.StringVar(&o.policyFile, "policy", "", "local JSON policy for source freshness, accepted findings, and gate classes")
}

type patternList []string

func (p *patternList) String() string {
	if p == nil {
		return ""
	}
	return strings.Join(*p, ",")
}

func (p *patternList) Set(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	*p = append(*p, value)
	return nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func readSecretFile(path, label string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("reading %s file: %w", label, err)
	}
	return strings.TrimSpace(string(data)), nil
}

// httpClient builds the HTTP client honoring --ca-cert / --insecure-skip-verify.
func (o *connOpts) httpClient(stderr io.Writer) (*http.Client, error) {
	tc := &tls.Config{InsecureSkipVerify: o.insecureTLS}
	if o.insecureTLS {
		fmt.Fprintln(stderr, "deadair: warning: TLS certificate verification disabled")
	}
	if o.caCert != "" {
		pem, err := os.ReadFile(o.caCert)
		if err != nil {
			return nil, fmt.Errorf("reading ca cert: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("no certificates parsed from %s", o.caCert)
		}
		tc.RootCAs = pool
	}
	return &http.Client{Timeout: o.timeout, Transport: &http.Transport{TLSClientConfig: tc}}, nil
}

func (o *connOpts) elasticClient(stderr io.Writer) (backendpkg.Backend, error) {
	if o.esURL == "" || o.kibanaURL == "" {
		return nil, fmt.Errorf("no deployment configured: set DEADAIR_ES_URL and DEADAIR_KIBANA_URL (or --es-url/--kibana-url) — `deadair setup` prints the full least-privilege walkthrough")
	}
	key := os.Getenv("DEADAIR_API_KEY")
	if o.apiKeyFile != "" {
		fileKey, err := readSecretFile(o.apiKeyFile, "api key")
		if err != nil {
			return nil, err
		}
		key = fileKey
	}
	if key == "" {
		fmt.Fprintln(stderr, "deadair: warning: no API key (DEADAIR_API_KEY or --api-key-file); connecting unauthenticated")
	}
	hc, err := o.httpClient(stderr)
	if err != nil {
		return nil, err
	}
	return &elastic.Client{
		ESURL:       o.esURL,
		KibanaURL:   o.kibanaURL,
		APIKey:      key,
		Space:       o.kibanaSpace,
		HTTP:        hc,
		Concurrency: o.concurrency,
	}, nil
}

func (o *connOpts) openSearchClient(stderr io.Writer) (backendpkg.Backend, error) {
	if o.opensearchURL == "" {
		return nil, fmt.Errorf("--opensearch-url is required (or DEADAIR_OPENSEARCH_URL)")
	}
	username := o.opensearchUsername
	password := os.Getenv("DEADAIR_OPENSEARCH_PASSWORD")
	if o.opensearchPasswordFile != "" {
		filePassword, err := readSecretFile(o.opensearchPasswordFile, "OpenSearch password")
		if err != nil {
			return nil, err
		}
		password = filePassword
	}
	if (username == "") != (password == "") {
		return nil, fmt.Errorf("OpenSearch basic auth requires both DEADAIR_OPENSEARCH_USERNAME/--opensearch-username and DEADAIR_OPENSEARCH_PASSWORD/--opensearch-password-file")
	}

	key := os.Getenv("DEADAIR_OPENSEARCH_API_KEY")
	if o.apiKeyFile != "" {
		fileKey, err := readSecretFile(o.apiKeyFile, "api key")
		if err != nil {
			return nil, err
		}
		key = fileKey
	}
	if key == "" && username == "" {
		key = os.Getenv("DEADAIR_API_KEY")
	}
	if key != "" && username != "" {
		return nil, fmt.Errorf("OpenSearch auth is ambiguous: use either API key auth or username/password, not both")
	}
	if key == "" && username == "" {
		fmt.Fprintln(stderr, "deadair: warning: no OpenSearch auth (DEADAIR_OPENSEARCH_API_KEY, DEADAIR_API_KEY, --api-key-file, or username/password); connecting unauthenticated")
	}
	hc, err := o.httpClient(stderr)
	if err != nil {
		return nil, err
	}
	return &opensearch.Client{
		URL:         o.opensearchURL,
		Username:    username,
		Password:    password,
		APIKey:      key,
		HTTP:        hc,
		Concurrency: o.concurrency,
	}, nil
}

func (o *connOpts) client(stderr io.Writer) (backendpkg.Backend, error) {
	switch strings.ToLower(strings.TrimSpace(o.backendName)) {
	case "", "elastic":
		return o.elasticClient(stderr)
	case "opensearch":
		return o.openSearchClient(stderr)
	default:
		return nil, fmt.Errorf("unknown backend %q (want elastic or opensearch)", o.backendName)
	}
}

func (o *connOpts) healthCheck() (health.Check, error) {
	check := health.Check{MaxStale: o.maxStale}
	if o.downtimeFile == "" {
		return check, nil
	}
	windows, err := health.LoadDowntimeFile(o.downtimeFile)
	if err != nil {
		return health.Check{}, err
	}
	check.Downtime = windows
	return check, nil
}

type stateAssessments struct {
	volume map[string]state.VolumeAssessment
	schema map[string]state.SchemaAssessment
	fields map[string]map[string]bool // source -> field set, when schemas fetched
}

func collectRequiredFieldEvidence(ctx context.Context, c backendpkg.Backend, rules []backendpkg.Rule, g *graph.Graph, inventory []backendpkg.Source) (map[string]backendpkg.FieldEvidence, report.RuntimeAssessment, error) {
	assessment := report.RuntimeAssessment{Name: report.AssessmentRequiredFields}
	provider, ok := c.(backendpkg.RequiredFieldProvider)
	if !ok {
		assessment.Status = backendpkg.EvidenceUnavailable
		assessment.Detail = "backend does not expose targeted required-field evidence"
		return nil, assessment, nil
	}
	fieldSet := map[string]bool{}
	sourceSet := map[string]bool{}
	declared := false
	for _, rule := range rules {
		if !rule.Enabled || len(rule.RequiredFields) == 0 {
			continue
		}
		declared = true
		resolved := false
		for _, source := range g.SourcesFor(rule.ID) {
			sourceSet[source] = true
			resolved = true
		}
		if resolved {
			for _, field := range rule.RequiredFields {
				fieldSet[field] = true
			}
		}
	}
	if !declared {
		assessment.Status = backendpkg.EvidenceDisabled
		assessment.Detail = "enabled rules did not declare required fields"
		return nil, assessment, nil
	}
	if len(sourceSet) == 0 {
		assessment.Status = backendpkg.EvidenceDisabled
		assessment.Detail = "enabled rules with required fields did not resolve to a local source"
		return map[string]backendpkg.FieldEvidence{}, assessment, nil
	}
	fields := make([]string, 0, len(fieldSet))
	for field := range fieldSet {
		fields = append(fields, field)
	}
	sort.Strings(fields)
	sources := make([]backendpkg.Source, 0, len(sourceSet))
	for _, source := range inventory {
		if sourceSet[source.Name] {
			sources = append(sources, source)
		}
	}
	evidence, err := provider.RequiredFieldEvidence(ctx, sources, fields)
	if err != nil {
		return nil, assessment, err
	}
	assessment.Status = backendpkg.EvidenceAssessed
	for _, source := range sources {
		item, found := evidence[source.Name]
		if !found || item.Status != backendpkg.EvidenceAssessed {
			assessment.Status = backendpkg.EvidenceIncomplete
			assessment.Detail = "one or more concrete source mappings could not be read"
			break
		}
	}
	return evidence, assessment, nil
}

func collectIngestLagEvidence(ctx context.Context, c backendpkg.Backend, rules []backendpkg.Rule, g *graph.Graph, inventory []backendpkg.Source) (map[string]backendpkg.IngestLagEvidence, report.RuntimeAssessment, error) {
	assessment := report.RuntimeAssessment{Name: report.AssessmentIngestLag}
	provider, ok := c.(backendpkg.IngestLagProvider)
	if !ok {
		assessment.Status = backendpkg.EvidenceUnavailable
		assessment.Detail = "backend does not provide paired ingest-lag evidence"
		return nil, assessment, nil
	}
	wanted := map[string]bool{}
	for _, rule := range rules {
		if !rule.Enabled || (rule.TimestampOverride != "" && rule.TimestampOverride != "@timestamp") ||
			rule.Interval <= 0 || rule.Lookback < rule.Interval {
			continue
		}
		for _, source := range g.SourcesFor(rule.ID) {
			wanted[source] = true
		}
	}
	if len(wanted) == 0 {
		assessment.Status = backendpkg.EvidenceDisabled
		assessment.Detail = "no resolved source is used by an event-time rule with a measurable window margin"
		return map[string]backendpkg.IngestLagEvidence{}, assessment, nil
	}
	sources := make([]backendpkg.Source, 0, len(wanted))
	for _, source := range inventory {
		if wanted[source.Name] {
			sources = append(sources, source)
		}
	}
	evidence, err := provider.IngestLagEvidence(ctx, sources)
	if err != nil {
		return nil, assessment, err
	}
	assessment.Status = backendpkg.EvidenceAssessed
	assessedSources := 0
	for _, source := range sources {
		item, found := evidence[source.Name]
		if found && item.Status == backendpkg.EvidenceAssessed {
			assessedSources++
		}
		if !found || (item.Status != backendpkg.EvidenceAssessed && item.Status != backendpkg.EvidenceDisabled) {
			assessment.Status = backendpkg.EvidenceIncomplete
			assessment.Detail = "one or more paired recent-event samples could not be collected"
			break
		}
	}
	if assessment.Status == backendpkg.EvidenceAssessed && assessedSources == 0 {
		assessment.Status = backendpkg.EvidenceDisabled
		assessment.Detail = "relevant sources had no documents to sample"
	} else if assessment.Status == backendpkg.EvidenceAssessed {
		assessment.Detail = fmt.Sprintf("paired recent-event samples requested for %d relevant source(s)", len(sources))
	}
	return evidence, assessment, nil
}

func runtimeAssessments(o connOpts, g *graph.Graph, scoped []backendpkg.Source, schemaEvidence map[string]state.SchemaAssessment, fields, lag report.RuntimeAssessment) []report.RuntimeAssessment {
	resolution := report.RuntimeAssessment{Name: report.AssessmentSourceResolution, Status: backendpkg.EvidenceAssessed}
	enabledRules := make(map[string]bool, len(g.Rules))
	for _, rule := range g.Rules {
		if rule.Enabled {
			enabledRules[rule.ID] = true
		}
	}
	if len(enabledRules) == 0 {
		resolution.Status = backendpkg.EvidenceDisabled
		resolution.Detail = "no enabled rules to resolve"
	} else {
		authoritative := make(map[string]bool, len(enabledRules))
		for _, item := range g.Resolutions {
			if !enabledRules[item.RuleID] {
				continue
			}
			if !item.Diagnostic {
				authoritative[item.RuleID] = true
			}
			switch item.Status {
			case backendpkg.ResolutionResolved, backendpkg.ResolutionEmpty:
			default:
				resolution.Status = backendpkg.EvidenceIncomplete
				resolution.Detail = "one or more rule inputs could not be assessed locally"
			}
		}
		for ruleID := range enabledRules {
			if !authoritative[ruleID] {
				resolution.Status = backendpkg.EvidenceIncomplete
				resolution.Detail = "one or more enabled rules have no authoritative input-resolution evidence"
				break
			}
		}
	}

	schema := report.RuntimeAssessment{Name: report.AssessmentSchemaDrift, Status: backendpkg.EvidenceDisabled, Detail: "enable with --schema and --state-file"}
	if o.ruleFile != "" && o.schemaTrack {
		schema.Detail = "candidate scans do not update installed source schema history"
	} else if o.schemaTrack {
		if len(scoped) == 0 {
			schema.Detail = "no sources are in scope"
		} else {
			schema.Status = backendpkg.EvidenceAssessed
			schema.Detail = "compared with the saved schema snapshot"
			for _, source := range scoped {
				evidence, found := schemaEvidence[source.Name]
				if !found || evidence.Status == state.SchemaUnknown {
					schema.Status = backendpkg.EvidenceIncomplete
					schema.Detail = "one or more scoped source schemas could not be read"
					break
				}
			}
		}
	}
	candidate := report.RuntimeAssessment{Name: report.AssessmentCandidateParsing, Status: backendpkg.EvidenceDisabled, Detail: "no candidate rule file was supplied"}
	if o.ruleFile != "" {
		candidate.Status = backendpkg.EvidenceAssessed
		candidate.Detail = "candidate rule file parsed without installation"
	}
	return []report.RuntimeAssessment{resolution, fields, lag, schema, candidate}
}

func (o *connOpts) stateAssessments(ctx context.Context, c backendpkg.Backend, sources []backendpkg.Source, check health.Check, targetID string) (stateAssessments, *state.Store, error) {
	if o.stateFile == "" {
		if o.schemaTrack {
			return stateAssessments{}, nil, fmt.Errorf("--schema requires --state-file")
		}
		return stateAssessments{}, nil, nil
	}
	store, err := state.Load(o.stateFile)
	if err != nil {
		return stateAssessments{}, nil, err
	}
	if err := store.BindTarget(targetID); err != nil {
		return stateAssessments{}, nil, err
	}
	// Candidate scans may retain finding lifecycle in their own scope, but
	// source history belongs to the installed assessment. Updating volume or
	// schema state here could consume a drift or alter the next installed
	// baseline even though candidate exit status ignores source findings.
	if o.ruleFile != "" {
		return stateAssessments{}, store, nil
	}
	now := time.Now().UTC()
	volume := store.AssessVolumes(sources, state.VolumeOptions{
		Now:        now,
		Warmup:     o.volumeWarmup,
		Hysteresis: o.volumeHysteresis,
		MinSamples: o.volumeMinSamples,
		ZThreshold: o.volumeZThreshold,
		InDowntime: func(name string) bool { return check.InDowntime(name, now) },
	})
	var schema map[string]state.SchemaAssessment
	var fields map[string]map[string]bool
	if o.schemaTrack {
		current, err := c.Schemas(ctx, sources)
		if err != nil {
			return stateAssessments{}, nil, err
		}
		schema = store.AssessSchemas(sources, current, now)
		fields = make(map[string]map[string]bool, len(current))
		for name, sc := range current {
			set := make(map[string]bool, len(sc.Fields))
			for _, f := range sc.Fields {
				set[f.Name] = true
			}
			fields[name] = set
		}
	}
	return stateAssessments{volume: volume, schema: schema, fields: fields}, store, nil
}

// scanResult carries the report plus the deferred state commit: the state
// file is saved only after the report has actually been delivered, so a
// failed render can never consume a one-shot drift finding or a hysteresis
// streak.
type scanResult struct {
	report            *report.Report
	store             *state.Store
	path              string
	findingsOnlyState bool
}

func (s scanResult) commitState() error {
	if s.store == nil {
		return nil
	}
	if s.findingsOnlyState {
		return s.store.SaveFindingUpdates(s.path)
	}
	return s.store.Save(s.path)
}

func scanOnce(ctx context.Context, c backendpkg.Backend, o connOpts, instance, targetID string) (scanResult, error) {
	var err error
	if o.policyFile != "" {
		o.policy, err = report.LoadPolicy(o.policyFile, time.Now().UTC())
		if err != nil {
			return scanResult{}, err
		}
	}
	configurationID, err := assessmentConfigurationID(o)
	if err != nil {
		return scanResult{}, err
	}
	observedVersion := ""
	if provider, ok := c.(backendpkg.VersionProvider); ok {
		// Product version is useful report evidence, but a restricted root API
		// must not turn an otherwise valid scan into an error.
		versionCtx, versionCancel := context.WithTimeout(ctx, 5*time.Second)
		version, verr := provider.Version(versionCtx)
		versionCancel()
		if verr == nil {
			observedVersion = version
		}
	}
	var rules []backendpkg.Rule
	if o.ruleFile != "" {
		// Candidate mode: evaluate rules from a file against the live
		// environment instead of the installed inventory.
		data, rerr := os.ReadFile(o.ruleFile)
		if rerr != nil {
			return scanResult{}, fmt.Errorf("reading rule file: %w", rerr)
		}
		parser, ok := c.(backendpkg.CandidateParser)
		if !ok {
			return scanResult{}, fmt.Errorf("candidate-rule parsing is unavailable for backend %q", c.Name())
		}
		rules, err = parser.ParseCandidates(data)
	} else {
		rules, err = c.Rules(ctx)
	}
	if err != nil {
		return scanResult{}, err
	}
	if err := backendpkg.ValidateRuleIDs(rules); err != nil {
		return scanResult{}, fmt.Errorf("invalid rule inventory: %w", err)
	}
	all, err := c.Sources(ctx)
	if err != nil {
		return scanResult{}, err
	}
	// Filters scope what the report lists and which sources get stateful
	// assessments; verdicts always see the full inventory, so scoping can
	// never manufacture a dead detection (report.BuildOptions.Scope).
	scoped := graph.FilterSources(all, o.include, o.exclude)
	var scope map[string]bool
	if len(o.include) > 0 || len(o.exclude) > 0 {
		scope = make(map[string]bool, len(scoped))
		for _, s := range scoped {
			scope[s.Name] = true
		}
	}
	check, err := o.healthCheck()
	if err != nil {
		return scanResult{}, err
	}
	stateAssess, store, err := o.stateAssessments(ctx, c, scoped, check, targetID)
	if err != nil {
		return scanResult{}, err
	}
	resolver, ok := c.(backendpkg.Resolver)
	if !ok {
		return scanResult{}, fmt.Errorf("backend %q does not provide native input resolution", c.Name())
	}
	resolutions, err := resolver.ResolveInputs(ctx, rules)
	if err != nil {
		return scanResult{}, fmt.Errorf("resolving rule inputs: %w", err)
	}
	g := graph.BuildResolved(rules, all, resolutions)
	lagEvidence, lagAssessment, err := collectIngestLagEvidence(ctx, c, rules, g, all)
	if err != nil {
		return scanResult{}, fmt.Errorf("reading ingest-lag evidence: %w", err)
	}
	for i := range all {
		if evidence, found := lagEvidence[all[i].Name]; found {
			all[i].IngestLag = evidence
		}
	}
	// Attach the measurements to the graph used by report impairment checks.
	g = graph.BuildResolved(rules, all, resolutions)
	fieldEvidence, fieldAssessment, err := collectRequiredFieldEvidence(ctx, c, rules, g, all)
	if err != nil {
		return scanResult{}, fmt.Errorf("reading required-field evidence: %w", err)
	}
	r := report.BuildWithOptions(c.Name(), g, report.BuildOptions{
		Check:                  check,
		Volume:                 stateAssess.volume,
		Schema:                 stateAssess.schema,
		Scope:                  scope,
		FieldEvidence:          fieldEvidence,
		Assessments:            runtimeAssessments(o, g, scoped, stateAssess.schema, fieldAssessment, lagAssessment),
		SkipUnused:             o.ruleFile != "",
		ProducerVersion:        Version,
		BackendObservedVersion: observedVersion,
		ScanScope: report.ScanScope{
			Mode: func() string {
				if o.ruleFile != "" {
					return "candidate"
				}
				return "installed"
			}(),
			Include: append([]string(nil), o.include...), Exclude: append([]string(nil), o.exclude...),
			SchemaTracking: o.schemaTrack, Stateful: o.stateFile != "", ConfigurationID: configurationID,
			CandidateRuleIDs: func() []string {
				if o.ruleFile == "" {
					return nil
				}
				ids := make([]string, 0, len(rules))
				for _, rule := range rules {
					ids = append(ids, rule.ID)
				}
				return ids
			}(),
		},
		Policy: o.policy, Store: store, TargetID: targetID, Instance: instance,
	})
	return scanResult{
		report: r, store: store, path: o.stateFile,
		findingsOnlyState: o.ruleFile != "" && store != nil,
	}, nil
}

func runScan(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { scanUsage(stderr) }
	var o connOpts
	addBackendFlags(fs, &o)
	addAssessmentFlags(fs, &o)
	jsonOut := fs.Bool("json", false, "print the full JSON report to stdout")
	jsonFile := fs.String("json-out", "", "write the JSON report to a file (created 0600 on POSIX)")
	legacyOutFile := fs.String("out", "", "deprecated alias for --json-out")
	htmlFile := fs.String("html-out", "", "write a static HTML report to a file (created 0600 on POSIX)")
	redactNames := fs.Bool("redact", false, "replace sensitive names with HMAC pseudonyms")
	redactKeyFile := fs.String("redact-key-file", os.Getenv("DEADAIR_REDACT_KEY_FILE"), "read the HMAC redaction key from a file")
	fs.StringVar(&o.ruleFile, "rule", "", "evaluate a backend-native candidate rule or detector file")
	if parsed, code := parseFlags(fs, args); !parsed {
		return code
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "deadair: scan does not accept positional arguments: %q\n", fs.Arg(0))
		return report.ExitError
	}
	if *jsonFile != "" && *legacyOutFile != "" {
		fmt.Fprintln(stderr, "deadair: use either --json-out or --out, not both")
		return report.ExitError
	}
	outFile := *jsonFile
	if outFile == "" {
		outFile = *legacyOutFile
	}
	if err := validateScanOptions(o, *htmlFile); err != nil {
		fmt.Fprintf(stderr, "deadair: %v\n", err)
		return report.ExitError
	}
	redactionEnabled := *redactNames || *redactKeyFile != ""
	redactor, err := loadRedactor(redactionEnabled, *redactKeyFile)
	if err != nil {
		printProtectedError(stderr, redactionEnabled, "redaction setup failed; check key file access and use a random key of at least 32 bytes", err)
		return report.ExitError
	}
	if o.policyFile != "" {
		o.policy, err = report.LoadPolicy(o.policyFile, time.Now().UTC())
		if err != nil {
			printProtectedError(stderr, redactionEnabled, "policy could not be loaded or validated", err)
			return report.ExitError
		}
	}

	insts, err := o.resolveInstances(stderr)
	if err != nil {
		printProtectedError(stderr, redactionEnabled, "scan target configuration could not be loaded", err)
		return report.ExitError
	}
	if o.ruleFile != "" {
		for _, inst := range insts {
			if _, ok := inst.backend.(backendpkg.CandidateParser); !ok {
				fmt.Fprintf(stderr, "deadair: --rule is unavailable for backend %q; it has no candidate parser\n", inst.backend.Name())
				return report.ExitError
			}
		}
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	ctx, cancelTimeout := context.WithTimeout(ctx, o.timeout*time.Duration(len(insts)))
	defer cancelTimeout()
	run := func(inst fleetInstance, io connOpts) (scanResult, error) {
		sctx, cancel := context.WithTimeout(ctx, io.timeout)
		defer cancel()
		return scanOnce(sctx, inst.backend, io, inst.name, inst.targetID)
	}

	if o.fleetFile != "" {
		f, commits := scanFleet(insts, o, run)
		if redactionEnabled {
			f.RedactWith(redactor)
		}
		if outFile != "" {
			if err := f.Write(outFile); err != nil {
				printProtectedError(stderr, redactionEnabled, "report output could not be written", err)
				return report.ExitError
			}
		}
		if *jsonOut {
			enc := json.NewEncoder(stdout)
			enc.SetIndent("", "  ")
			if err := enc.Encode(f); err != nil {
				printProtectedError(stderr, redactionEnabled, "report output failed", err)
				return report.ExitError
			}
		} else {
			printFleetSummary(stdout, f)
		}
		for _, c := range commits {
			if err := c.commitState(); err != nil {
				printProtectedError(stderr, redactionEnabled, "state could not be saved", err)
				return report.ExitError
			}
		}
		if o.ruleFile != "" {
			return f.CandidateExitCode()
		}
		return f.ExitCode()
	}

	res, err := run(insts[0], o)
	if err != nil {
		if redactionEnabled {
			fmt.Fprintf(stderr, "deadair: scan failed: %s\n", report.SanitizeScanError(err.Error()))
		} else {
			fmt.Fprintf(stderr, "deadair: scan failed: %v\n", err)
		}
		if s := err.Error(); strings.Contains(s, "401") || strings.Contains(s, "403") {
			fmt.Fprintln(stderr, "deadair: hint: the credential was rejected — check the key and its role (`deadair setup` shows the expected privileges)")
		}
		return report.ExitError
	}
	res.report.Instance = insts[0].name
	r := res.report
	if redactionEnabled {
		r.RedactWith(redactor)
	}
	if outFile != "" {
		if err := r.Write(outFile); err != nil {
			printProtectedError(stderr, redactionEnabled, "report output could not be written", err)
			return report.ExitError
		}
	}
	if *htmlFile != "" {
		if err := r.WriteHTML(*htmlFile); err != nil {
			printProtectedError(stderr, redactionEnabled, "HTML output could not be written", err)
			return report.ExitError
		}
	}
	if *jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(r); err != nil {
			printProtectedError(stderr, redactionEnabled, "report output failed", err)
			return report.ExitError
		}
	} else {
		printSummary(stdout, r)
	}
	if err := res.commitState(); err != nil {
		printProtectedError(stderr, redactionEnabled, "state could not be saved", err)
		return report.ExitError
	}
	if o.ruleFile != "" {
		return r.CandidateExitCode()
	}
	return r.ExitCode()
}

func validateScanOptions(o connOpts, htmlFile string) error {
	if o.schemaTrack && o.stateFile == "" {
		return fmt.Errorf("--schema requires --state-file")
	}
	if o.fleetFile != "" && htmlFile != "" {
		return fmt.Errorf("--html-out is available only for single-instance scans")
	}
	if o.fleetFile != "" && o.instanceName != "" {
		return fmt.Errorf("--instance-name cannot be combined with --fleet; fleet instances already have names")
	}
	return nil
}

func loadRedactor(enabled bool, keyFile string) (*redactpkg.Redactor, error) {
	if !enabled {
		return nil, nil
	}
	if keyFile == "" {
		return redactpkg.Default(), nil
	}
	redactor, err := redactpkg.Load(keyFile)
	if err != nil {
		return nil, err
	}
	return redactor, nil
}

func printProtectedError(w io.Writer, protected bool, safeMessage string, err error) {
	if protected {
		fmt.Fprintf(w, "deadair: %s\n", safeMessage)
		return
	}
	fmt.Fprintf(w, "deadair: %v\n", err)
}

func printSummary(w io.Writer, r *report.Report) {
	if interactiveOutput(w) {
		printVisualSummary(w, r)
		return
	}
	printPlainSummary(w, r)
}

func printPlainSummary(w io.Writer, r *report.Report) {
	s := r.Summary
	fmt.Fprintf(w, "deadair scan — %s — %s\n", r.Backend, r.GeneratedAt.Format(time.RFC3339))
	counts := map[string]int{}
	for _, src := range r.Sources {
		counts[src.Status]++
	}
	fmt.Fprintf(w, "sources:    %d (%d ok, %d stale, %d empty, %d unknown, %d maintenance)\n",
		s.Sources, counts["ok"], counts["stale"], counts["empty"], counts["unknown"], counts["maintenance"])
	fmt.Fprintf(w, "detections: %d enabled / %d total (%d unmapped)\n", s.EnabledRules, s.Rules, s.UnmappedRules)
	if len(r.InputResolutions) > 0 {
		resolution := s.InputResolution
		fmt.Fprintf(w, "inputs:     %d resolved, %d empty, %d unsupported, %d unavailable, %d remote, %d ambiguous\n",
			resolution.Resolved, resolution.Empty, resolution.Unsupported, resolution.Unavailable,
			resolution.Remote, resolution.Ambiguous)
	}
	if r.Policy != nil {
		fmt.Fprintf(w, "policy:     %d finding(s) gate, %d accepted, %d expired acceptance(s)\n",
			s.GatedFindings, r.Policy.AcceptedActive, r.Policy.AcceptedExpired)
	}
	if s.VolumeLowSources > 0 {
		fmt.Fprintf(w, "volume:     %d source(s) below same weekday/hour baseline\n", s.VolumeLowSources)
	}
	if s.SchemaDriftSources > 0 {
		fmt.Fprintf(w, "schema:     %d source(s) changed field_caps since previous snapshot\n", s.SchemaDriftSources)
	}
	if checks := unassessedChecks(r); len(checks) > 0 {
		fmt.Fprintf(w, "checks:     %s\n", strings.Join(checks, ", "))
	}
	if len(r.DeadDetections) > 0 {
		fmt.Fprintf(w, "\n%s\n", color(w, "31;1", fmt.Sprintf("DEAD: %d enabled detection(s) cannot fire right now", s.DeadDetections)))
		for i, d := range r.DeadDetections {
			// severity-sorted, so the cut tail is always the least severe
			if i >= 15 {
				fmt.Fprintf(w, "  … and %d more (use --json for the full list)\n", s.DeadDetections-15)
				break
			}
			fmt.Fprintf(w, "  [%s] %s — %s", d.Severity, d.Name, report.DeadReasonLabel(d.Reason))
			if len(d.Sources) > 0 {
				fmt.Fprintf(w, " (%s)", strings.Join(d.Sources, ", "))
			}
			fmt.Fprintln(w)
		}
	}
	if len(r.ImpairedDetections) > 0 {
		fmt.Fprintf(w, "\n%s\n", color(w, "33;1", fmt.Sprintf("IMPAIRED: %d enabled detection(s) run with reduced visibility", s.ImpairedDetections)))
		for i, d := range r.ImpairedDetections {
			if i >= 15 {
				fmt.Fprintf(w, "  … and %d more (use --json for the full list)\n", s.ImpairedDetections-15)
				break
			}
			fmt.Fprintf(w, "  [%s] %s — %s%s\n", d.Severity, d.Name, strings.Join(d.Reasons, ", "), impairedDetail(d))
		}
	}
	if len(r.PartialInputCoverage) > 0 {
		fmt.Fprintf(w, "\npartial input coverage: %d selector(s) are missing while their combined rule input still resolves\n",
			s.PartialInputs)
		for i, coverage := range r.PartialInputCoverage {
			if i >= 10 {
				fmt.Fprintf(w, "  … and %d more (use --json for the full list)\n", s.PartialInputs-10)
				break
			}
			dependency := coverage.Selector
			if dependency == "" {
				dependency = coverage.Expression
			}
			fmt.Fprintf(w, "  [%s] %s — missing selector: %s\n", coverage.Severity, coverage.RuleName, dependency)
		}
	}
	if len(r.UnmappedRules) > 0 || len(r.RemoteRules) > 0 {
		fmt.Fprintf(w, "\ninput assessment: %d unmapped rule(s), %d remote rule(s); neither is treated as dead\n",
			len(r.UnmappedRules), len(r.RemoteRules))
		shown := 0
		for _, rule := range r.UnmappedRules {
			if shown >= 10 {
				break
			}
			fmt.Fprintf(w, "  [%s] %s — %s", rule.Severity, rule.Name, rule.AssessmentStatus)
			if rule.Detail != "" {
				fmt.Fprintf(w, ": %s", rule.Detail)
			}
			fmt.Fprintln(w)
			shown++
		}
		for _, rule := range r.RemoteRules {
			if shown >= 10 {
				break
			}
			fmt.Fprintf(w, "  [%s] %s — remote dependency\n", rule.Severity, rule.Name)
			shown++
		}
	}
	if s.UnusedTelemetryAssessment == report.UnusedAssessmentUnavailable {
		fmt.Fprintln(w, "\nunused telemetry: not assessed because one or more enabled local rule inputs could not be resolved safely")
	} else if s.UnusedSources > 0 {
		fmt.Fprintf(w, "\nunused telemetry: %d source(s), %s stored with no enabled detection reading it\n",
			s.UnusedSources, humanBytes(s.UnusedBytes))
		for i, u := range r.UnusedTelemetry {
			if i >= 5 {
				fmt.Fprintf(w, "  … and %d more (use --json for the full list)\n", s.UnusedSources-5)
				break
			}
			fmt.Fprintf(w, "  %s (%s", u.Name, humanBytes(u.SizeBytes))
			if u.DisabledConsumers > 0 {
				fmt.Fprintf(w, ", %d disabled rule(s) reference it", u.DisabledConsumers)
			}
			fmt.Fprintln(w, ")")
		}
	}
	if r.ExitCode() == report.ExitHealthy {
		if len(r.UnmappedRules) > 0 || len(r.RemoteRules) > 0 {
			fmt.Fprintln(w, "\nno positive findings; one or more rule inputs were not assessed")
		} else {
			fmt.Fprintf(w, "\n%s\n", color(w, "32", "healthy: no dead detections, no degraded sources"))
		}
	}
}

// color wraps s in an ANSI code only when writing to an interactive
// terminal. Honors NO_COLOR; pipes and CI always get plain text.
func color(w io.Writer, code, s string) string {
	f, ok := w.(*os.File)
	if !ok || os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		return s
	}
	// Legacy Windows consoles print ANSI escapes literally. Colorize only
	// when a capable host identifies itself (Windows Terminal, ConEmu,
	// ANSICON, or an environment that sets TERM, e.g. git-bash).
	if runtime.GOOS == "windows" && os.Getenv("WT_SESSION") == "" && os.Getenv("TERM") == "" &&
		os.Getenv("ANSICON") == "" && os.Getenv("ConEmuANSI") == "" {
		return s
	}
	if info, err := f.Stat(); err != nil || info.Mode()&os.ModeCharDevice == 0 {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func impairedDetail(d report.ImpairedDetection) string {
	var parts []string
	if len(d.MissingFields) > 0 {
		parts = append(parts, "missing "+strings.Join(d.MissingFields, ", "))
	}
	if len(d.LagSources) > 0 {
		parts = append(parts, fmt.Sprintf("ingest lag p95 %s (max %s) in %s exceeds window margin",
			humanDuration(d.P95LagSeconds), humanDuration(d.MaxLagSeconds), strings.Join(d.LagSources, ", ")))
	}
	if len(parts) == 0 {
		return ""
	}
	return " (" + strings.Join(parts, "; ") + ")"
}

func humanDuration(seconds float64) string {
	d := time.Duration(seconds) * time.Second
	if d >= 24*time.Hour && d%(24*time.Hour) == 0 {
		return fmt.Sprintf("%dd", d/(24*time.Hour))
	}
	s := d.String()
	s = strings.TrimSuffix(s, "0s")
	s = strings.TrimSuffix(s, "0m")
	if s == "" {
		return "0s"
	}
	return s
}

func runDiff(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("diff", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { diffUsage(stderr) }
	jsonOut := fs.Bool("json", false, "write the diff as JSON")
	if parsed, code := parseFlags(fs, args); !parsed {
		return code
	}
	if fs.NArg() != 2 {
		diffUsage(stderr)
		return report.ExitError
	}
	load := func(path string) (*report.Report, error) {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		var r report.Report
		if err := json.Unmarshal(data, &r); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		return &r, nil
	}
	older, err := load(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(stderr, "deadair: %v\n", err)
		return report.ExitError
	}
	newer, err := load(fs.Arg(1))
	if err != nil {
		fmt.Fprintf(stderr, "deadair: %v\n", err)
		return report.ExitError
	}
	d, err := report.Diff(older, newer)
	if err != nil {
		fmt.Fprintf(stderr, "deadair: reports are not comparable: %v\n", err)
		return report.ExitError
	}
	if *jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(d); err != nil {
			fmt.Fprintf(stderr, "deadair: %v\n", err)
			return report.ExitError
		}
	} else {
		printDiff(stdout, d)
	}
	if d.Regressions() > 0 {
		return report.ExitFindings
	}
	return report.ExitHealthy
}

func printDiff(w io.Writer, d *report.DiffResult) {
	if interactiveOutput(w) {
		printVisualDiff(w, d)
		return
	}
	printPlainDiff(w, d)
}

func printPlainDiff(w io.Writer, d *report.DiffResult) {
	if len(d.NewFindings)+len(d.RecoveredFindings)+len(d.NewlyGatedFindings)+len(d.NoLongerGated)+len(d.NewSources)+len(d.RemovedSources) == 0 {
		fmt.Fprintln(w, "no changes")
		return
	}
	for _, x := range d.NewlyDead {
		fmt.Fprintf(w, "DEAD     [%s] %s — %s\n", x.Severity, x.Name, report.DeadReasonLabel(x.Reason))
	}
	for _, x := range d.NewlyImpaired {
		fmt.Fprintf(w, "IMPAIRED [%s] %s — %s\n", x.Severity, x.Name, strings.Join(x.Reasons, ", "))
	}
	for _, s := range d.NewlyDegraded {
		fmt.Fprintf(w, "DEGRADED %s — %s\n", s.Name, s.Status)
	}
	for _, u := range d.NewlyUnused {
		fmt.Fprintf(w, "UNUSED   %s (%s)\n", u.Name, humanBytes(u.SizeBytes))
	}
	for _, finding := range d.NewFindings {
		switch finding.Class {
		case report.FindingVolumeLow, report.FindingSchemaDrift, report.FindingPartialInput:
			name := finding.Source
			if name == "" {
				name = finding.RuleName
			}
			fmt.Fprintf(w, "FINDING  %s — %s (%s)\n", name, finding.Reason, finding.Class)
		}
	}
	for _, finding := range d.NewlyGatedFindings {
		name := finding.Source
		if name == "" {
			name = finding.RuleName
		}
		fmt.Fprintf(w, "NEW GATE %s — %s (%s)\n", name, finding.Reason, finding.Class)
	}
	for _, x := range d.RecoveredDead {
		fmt.Fprintf(w, "recovered detection: %s\n", x.Name)
	}
	for _, x := range d.RecoveredImpaired {
		fmt.Fprintf(w, "recovered from impairment: %s\n", x.Name)
	}
	for _, s := range d.RecoveredSources {
		fmt.Fprintf(w, "recovered source: %s\n", s.Name)
	}
	for _, finding := range d.RecoveredFindings {
		switch finding.Class {
		case report.FindingVolumeLow, report.FindingSchemaDrift, report.FindingPartialInput:
			name := finding.Source
			if name == "" {
				name = finding.RuleName
			}
			fmt.Fprintf(w, "recovered finding: %s — %s (%s)\n", name, finding.Reason, finding.Class)
		}
	}
	for _, finding := range d.NoLongerGated {
		name := finding.Source
		if name == "" {
			name = finding.RuleName
		}
		fmt.Fprintf(w, "no longer gated: %s — %s (%s)\n", name, finding.Reason, finding.Class)
	}
	for _, n := range d.NewSources {
		fmt.Fprintf(w, "new source: %s\n", n)
	}
	for _, n := range d.RemovedSources {
		fmt.Fprintf(w, "removed source: %s\n", n)
	}
}

func humanBytes(n int64) string {
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

func runTune(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("tune", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { tuneUsage(stderr) }
	stateFile := fs.String("state-file", "", "state file to summarize")
	jsonOut := fs.Bool("json", false, "write tuning summary as JSON")
	redactNames := fs.Bool("redact", false, "replace source names with HMAC pseudonyms")
	redactKeyFile := fs.String("redact-key-file", os.Getenv("DEADAIR_REDACT_KEY_FILE"), "read the HMAC redaction key from a file")
	if parsed, code := parseFlags(fs, args); !parsed {
		return code
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "deadair: tune does not accept positional arguments: %q\n", fs.Arg(0))
		return report.ExitError
	}
	if *stateFile == "" {
		fmt.Fprintln(stderr, "deadair: --state-file is required")
		return report.ExitError
	}
	redactionEnabled := *redactNames || *redactKeyFile != ""
	store, err := state.Load(*stateFile)
	if err != nil {
		printProtectedError(stderr, redactionEnabled, "state could not be loaded", err)
		return report.ExitError
	}
	tune := store.Tune()
	if redactionEnabled {
		redactor, err := loadRedactor(true, *redactKeyFile)
		if err != nil {
			printProtectedError(stderr, true, "redaction setup failed; check key file access and use a random key of at least 32 bytes", err)
			return report.ExitError
		}
		for i := range tune.SourceSummaries {
			tune.SourceSummaries[i].Name = redactor.Value("src", tune.SourceSummaries[i].Name)
		}
	}
	if *jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(tune); err != nil {
			fmt.Fprintf(stderr, "deadair: %v\n", err)
			return report.ExitError
		}
		return 0
	}
	fmt.Fprintf(stdout, "deadair tune — %d source(s), %d sample(s), %d bucket(s)\n",
		tune.Sources, tune.TotalSamples, tune.TotalBuckets)
	fmt.Fprintf(stdout, "suggested: --volume-min-samples %d --volume-hysteresis %d --volume-z-threshold %.1f\n",
		tune.Suggested.VolumeMinSamples, tune.Suggested.VolumeHysteresis, tune.Suggested.VolumeZThreshold)
	for i, src := range tune.SourceSummaries {
		if i >= 10 {
			fmt.Fprintf(stdout, "… and %d more source(s)\n", len(tune.SourceSummaries)-10)
			break
		}
		fmt.Fprintf(stdout, "%s: %d samples across %d bucket(s), mean %.1f docs/hour, stddev %.1f\n",
			src.Name, src.Samples, src.Buckets, src.MeanPerHour, src.StdPerHour)
	}
	return 0
}

func runServe(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { serveUsage(stderr) }
	var o connOpts
	addBackendFlags(fs, &o)
	addAssessmentFlags(fs, &o)
	bind := fs.String("bind", "127.0.0.1:9317", "exporter listen address; keep loopback unless the scrape path is authenticated")
	interval := fs.Duration("interval", 5*time.Minute, "time between scans")
	redactNames := fs.Bool("redact", false, "replace source names in metric labels with HMAC pseudonyms")
	redactKeyFile := fs.String("redact-key-file", os.Getenv("DEADAIR_REDACT_KEY_FILE"), "read the HMAC redaction key from a file")
	if parsed, code := parseFlags(fs, args); !parsed {
		return code
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "deadair: serve does not accept positional arguments: %q\n", fs.Arg(0))
		return report.ExitError
	}
	if err := validateScanOptions(o, ""); err != nil {
		fmt.Fprintf(stderr, "deadair: %v\n", err)
		return report.ExitError
	}
	redactionEnabled := *redactNames || *redactKeyFile != ""
	redactor, err := loadRedactor(redactionEnabled, *redactKeyFile)
	if err != nil {
		printProtectedError(stderr, redactionEnabled, "redaction setup failed; check key file access and use a random key of at least 32 bytes", err)
		return report.ExitError
	}
	if o.policyFile != "" {
		o.policy, err = report.LoadPolicy(o.policyFile, time.Now().UTC())
		if err != nil {
			printProtectedError(stderr, redactionEnabled, "policy could not be loaded or validated", err)
			return report.ExitError
		}
	}

	insts, err := o.resolveInstances(stderr)
	if err != nil {
		printProtectedError(stderr, redactionEnabled, "scan target configuration could not be loaded", err)
		return report.ExitError
	}
	if host, _, err := net.SplitHostPort(*bind); err == nil && host != "127.0.0.1" && host != "::1" && host != "localhost" {
		fmt.Fprintln(stderr, "deadair: warning: exporter bound beyond loopback — metric labels enumerate your log sources; put an authenticated proxy (mTLS/reverse proxy) in front")
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	srv := &exporter.Server{}
	httpSrv := &http.Server{Addr: *bind, Handler: srv.Handler()}

	go func() {
		scan := func() {
			run := func(inst fleetInstance, io connOpts) (scanResult, error) {
				sctx, cancel := context.WithTimeout(ctx, io.timeout)
				defer cancel()
				return scanOnce(sctx, inst.backend, io, inst.name, inst.targetID)
			}
			f, commits := scanFleet(insts, o, run)
			if redactionEnabled {
				f.RedactWith(redactor)
			}
			for _, e := range f.Errors {
				fmt.Fprintf(stderr, "deadair: scan failed (%s): %s\n", e.Instance, e.Error)
			}
			srv.Update(f)
			for _, c := range commits {
				if err := c.commitState(); err != nil {
					printProtectedError(stderr, redactionEnabled, "state could not be saved", err)
				}
			}
		}
		scan()
		t := time.NewTicker(*interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				scan()
			}
		}
	}()
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(sctx)
	}()

	fmt.Fprintf(stderr, "deadair: serving metrics on http://%s/metrics (scan interval %s)\n", *bind, *interval)
	if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		fmt.Fprintf(stderr, "deadair: %v\n", err)
		return report.ExitError
	}
	return 0
}
