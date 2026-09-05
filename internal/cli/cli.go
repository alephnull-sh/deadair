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
	"github.com/alephnull-sh/deadair/internal/backend/sentinel"
	"github.com/alephnull-sh/deadair/internal/exporter"
	"github.com/alephnull-sh/deadair/internal/graph"
	"github.com/alephnull-sh/deadair/internal/health"
	redactpkg "github.com/alephnull-sh/deadair/internal/redact"
	"github.com/alephnull-sh/deadair/internal/report"
	"github.com/alephnull-sh/deadair/internal/state"
)

// Version is stamped at build time via -ldflags.
var Version = "dev"

const sentinelUnusedTelemetryUnavailableDetail = "Sentinel lacks authoritative source storage and document-count inventory"

// Read-only provenance and lineage enrich a completed health scan. Bound each
// optional provider independently so a slow catalog cannot consume the scan's
// full deadline or turn informational evidence into a gating failure.
var readOnlyEnrichmentTimeout = 10 * time.Second

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
	fmt.Fprintln(w, "cannot currently detect anything. Read-only; Elastic, OpenSearch, and Microsoft Sentinel.")
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
	fmt.Fprintln(w, "  deadair setup <backend>  # elastic, opensearch, or sentinel")
	fmt.Fprintln(w, "  deadair check     # confirm the credential can scan")
	fmt.Fprintln(w, "  deadair scan      # assess live rules and telemetry")
	if os.Getenv("DEADAIR_ES_URL") != "" {
		fmt.Fprintln(w, "\nconfigured: elastic")
	} else if os.Getenv("DEADAIR_OPENSEARCH_URL") != "" {
		fmt.Fprintln(w, "\nconfigured: opensearch")
	} else if strings.EqualFold(os.Getenv("DEADAIR_BACKEND"), "sentinel") && os.Getenv("DEADAIR_SENTINEL_WORKSPACE") != "" {
		fmt.Fprintln(w, "\nconfigured: sentinel")
	} else {
		fmt.Fprintln(w, "\nnot configured yet — start with: deadair setup <backend>")
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
	azureSubscriptionID    string
	azureResourceGroup     string
	sentinelWorkspace      string
	sentinelWorkspaceID    string
	sentinelRemotesFile    string
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
	fs.StringVar(&o.backendName, "backend", envOr("DEADAIR_BACKEND", "elastic"), "backend to scan: elastic, opensearch, or sentinel (env DEADAIR_BACKEND)")
	fs.StringVar(&o.esURL, "es-url", os.Getenv("DEADAIR_ES_URL"), "Elasticsearch base URL (env DEADAIR_ES_URL)")
	fs.StringVar(&o.kibanaURL, "kibana-url", os.Getenv("DEADAIR_KIBANA_URL"), "Kibana base URL (env DEADAIR_KIBANA_URL)")
	fs.StringVar(&o.opensearchURL, "opensearch-url", os.Getenv("DEADAIR_OPENSEARCH_URL"), "OpenSearch base URL (env DEADAIR_OPENSEARCH_URL)")
	fs.StringVar(&o.opensearchUsername, "opensearch-username", os.Getenv("DEADAIR_OPENSEARCH_USERNAME"), "OpenSearch username for basic auth (env DEADAIR_OPENSEARCH_USERNAME)")
	fs.StringVar(&o.opensearchPasswordFile, "opensearch-password-file", "", "file containing the OpenSearch password (default: env DEADAIR_OPENSEARCH_PASSWORD)")
	fs.StringVar(&o.azureSubscriptionID, "azure-subscription", os.Getenv("DEADAIR_AZURE_SUBSCRIPTION_ID"), "Azure subscription ID (env DEADAIR_AZURE_SUBSCRIPTION_ID)")
	fs.StringVar(&o.azureResourceGroup, "azure-resource-group", os.Getenv("DEADAIR_AZURE_RESOURCE_GROUP"), "Azure resource group containing the Sentinel workspace (env DEADAIR_AZURE_RESOURCE_GROUP)")
	fs.StringVar(&o.sentinelWorkspace, "sentinel-workspace", os.Getenv("DEADAIR_SENTINEL_WORKSPACE"), "Sentinel Log Analytics workspace resource name (env DEADAIR_SENTINEL_WORKSPACE)")
	fs.StringVar(&o.sentinelWorkspaceID, "sentinel-workspace-id", os.Getenv("DEADAIR_SENTINEL_WORKSPACE_ID"), "optional Log Analytics customer ID override (env DEADAIR_SENTINEL_WORKSPACE_ID; discovered through ARM by default)")
	fs.StringVar(&o.sentinelRemotesFile, "sentinel-remotes", os.Getenv("DEADAIR_SENTINEL_REMOTES"), "JSON file explicitly mapping literal workspace() targets (env DEADAIR_SENTINEL_REMOTES)")
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
	value := strings.TrimSpace(string(data))
	if value == "" {
		return "", fmt.Errorf("%s file is empty", label)
	}
	return value, nil
}

// httpClient preserves standard proxy and connection settings, then applies
// --ca-cert / --insecure-skip-verify.
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
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tc
	return &http.Client{Timeout: o.timeout, Transport: transport}, nil
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

func validateOpenSearchAuth(username, password, key string) error {
	if (strings.TrimSpace(username) == "") != (strings.TrimSpace(password) == "") ||
		(username != "" && strings.TrimSpace(username) == "") {
		return fmt.Errorf("OpenSearch basic auth requires both username and password")
	}
	if key != "" && username != "" {
		return fmt.Errorf("OpenSearch auth is ambiguous: use either API key auth or username/password, not both")
	}
	return nil
}

func (o *connOpts) openSearchClient(stderr io.Writer) (backendpkg.Backend, error) {
	if o.opensearchURL == "" {
		return nil, fmt.Errorf("--opensearch-url is required (or DEADAIR_OPENSEARCH_URL)")
	}
	username := o.opensearchUsername
	password := os.Getenv("DEADAIR_OPENSEARCH_PASSWORD")
	if o.opensearchPasswordFile != "" {
		if password != "" {
			return nil, fmt.Errorf("choose either DEADAIR_OPENSEARCH_PASSWORD or --opensearch-password-file")
		}
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
		if key != "" || os.Getenv("DEADAIR_API_KEY") != "" {
			return nil, fmt.Errorf("choose either an API key environment variable or --api-key-file")
		}
		fileKey, err := readSecretFile(o.apiKeyFile, "api key")
		if err != nil {
			return nil, err
		}
		key = fileKey
	}
	if key == "" && username == "" {
		key = os.Getenv("DEADAIR_API_KEY")
	}
	if err := validateOpenSearchAuth(username, password, key); err != nil {
		return nil, err
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

func (o *connOpts) sentinelClient(stderr io.Writer) (backendpkg.Backend, error) {
	hc, err := o.httpClient(stderr)
	if err != nil {
		return nil, err
	}
	remotes, err := loadSentinelRemotes(o.sentinelRemotesFile)
	if err != nil {
		return nil, err
	}
	return sentinel.NewClient(sentinel.Config{
		SubscriptionID:   o.azureSubscriptionID,
		ResourceGroup:    o.azureResourceGroup,
		WorkspaceName:    o.sentinelWorkspace,
		WorkspaceID:      o.sentinelWorkspaceID,
		RemoteWorkspaces: remotes,
		HTTP:             hc,
		Concurrency:      o.concurrency,
	})
}

func loadSentinelRemotes(path string) ([]sentinel.RemoteWorkspace, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading Sentinel remote-workspace file: %w", err)
	}
	remotes, err := sentinel.ParseRemoteWorkspaces(data)
	if err != nil {
		return nil, err
	}
	return remotes, nil
}

func (o *connOpts) client(stderr io.Writer) (backendpkg.Backend, error) {
	switch strings.ToLower(strings.TrimSpace(o.backendName)) {
	case "", "elastic":
		return o.elasticClient(stderr)
	case "opensearch":
		return o.openSearchClient(stderr)
	case "sentinel":
		return o.sentinelClient(stderr)
	default:
		return nil, fmt.Errorf("unknown backend %q (want elastic, opensearch, or sentinel)", o.backendName)
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

func enabledConcreteSources(rules []backendpkg.Rule, g *graph.Graph, inventory []backendpkg.Source) []backendpkg.Source {
	wanted := make(map[string]bool)
	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		for _, source := range g.SourcesFor(rule.ID) {
			wanted[source] = true
		}
	}
	sources := make([]backendpkg.Source, 0, len(wanted))
	for _, source := range inventory {
		if wanted[source.Name] {
			sources = append(sources, source)
		}
	}
	return sources
}

func freshnessRequests(rules []backendpkg.Rule, g *graph.Graph, inventory []backendpkg.Source, maxStale time.Duration, policy *report.Policy) []backendpkg.FreshnessRequest {
	type clocks struct{ event, ingestion bool }
	wanted := make(map[string]clocks)
	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		ingestion := strings.EqualFold(strings.TrimSpace(rule.TimestampOverride), "ingestion_time()")
		for _, source := range g.SourcesFor(rule.ID) {
			use := wanted[source]
			if ingestion {
				use.ingestion = true
			} else {
				use.event = true
			}
			wanted[source] = use
		}
	}
	requests := make([]backendpkg.FreshnessRequest, 0, len(wanted))
	for _, source := range inventory {
		use, ok := wanted[source.Name]
		if !ok {
			continue
		}
		basis := backendpkg.FreshnessEventTime
		switch {
		case use.event && use.ingestion:
			basis = backendpkg.FreshnessMixed
		case use.ingestion:
			basis = backendpkg.FreshnessIngestionTime
		}
		requests = append(requests, backendpkg.FreshnessRequest{Source: source, Basis: basis, Window: policy.MaxStaleFor(source.Name, maxStale)})
	}
	return requests
}

func collectFreshnessEvidence(ctx context.Context, c backendpkg.Backend, rules []backendpkg.Rule, g *graph.Graph, inventory []backendpkg.Source, maxStale time.Duration, policy *report.Policy) (map[string]backendpkg.FreshnessEvidence, report.RuntimeAssessment, error) {
	assessment := report.RuntimeAssessment{Name: report.AssessmentSourceFreshness}
	provider, legacy := c.(backendpkg.FreshnessProvider)
	requestProvider, ruleAware := c.(backendpkg.FreshnessRequestProvider)
	if !legacy && !ruleAware {
		return nil, report.RuntimeAssessment{}, nil
	}
	requests := freshnessRequests(rules, g, inventory, maxStale, policy)
	if len(requests) == 0 {
		assessment.Status = backendpkg.EvidenceDisabled
		assessment.Detail = "no enabled rule resolved to a local source"
		return map[string]backendpkg.FreshnessEvidence{}, assessment, nil
	}
	sources := make([]backendpkg.Source, 0, len(requests))
	for _, request := range requests {
		sources = append(sources, request.Source)
	}
	var evidence map[string]backendpkg.FreshnessEvidence
	var err error
	if ruleAware {
		evidence, err = requestProvider.FreshnessEvidenceFor(ctx, requests)
	} else {
		evidence, err = provider.FreshnessEvidence(ctx, sources)
	}
	if err != nil {
		if ctx.Err() != nil {
			return nil, assessment, ctx.Err()
		}
		assessment.Status = backendpkg.EvidenceIncomplete
		assessment.Detail = "bounded freshness evidence could not be collected"
		return map[string]backendpkg.FreshnessEvidence{}, assessment, nil
	}

	assessed, unavailable, incomplete := 0, 0, 0
	for _, request := range requests {
		item, found := evidence[request.Source.Name]
		if !found {
			incomplete++
			continue
		}
		if item.Status == backendpkg.EvidenceAssessed && item.LastEvent.IsZero() && request.Window > 0 && item.Window < request.Window {
			item.Status = backendpkg.EvidenceIncomplete
			item.Detail = fmt.Sprintf("bounded freshness window %s is shorter than max-stale %s", item.Window, request.Window)
			evidence[request.Source.Name] = item
		}
		switch item.Status {
		case backendpkg.EvidenceAssessed:
			assessed++
		case backendpkg.EvidenceUnavailable:
			unavailable++
		default:
			incomplete++
		}
	}
	switch {
	case unavailable == len(sources):
		assessment.Status = backendpkg.EvidenceUnavailable
		assessment.Detail = fmt.Sprintf("freshness is unavailable for %s", countLabel(unavailable, "consumed source", "consumed sources"))
	case unavailable > 0 || incomplete > 0:
		assessment.Status = backendpkg.EvidenceIncomplete
		assessment.Detail = fmt.Sprintf("freshness evidence incomplete for %d of %s", unavailable+incomplete, countLabel(len(sources), "consumed source", "consumed sources"))
	default:
		assessment.Status = backendpkg.EvidenceAssessed
		assessment.Detail = fmt.Sprintf("bounded freshness evidence collected for %s", countLabel(assessed, "consumed source", "consumed sources"))
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
		assessment.Detail = fmt.Sprintf("paired recent-event samples requested for %s", countLabel(len(sources), "relevant source", "relevant sources"))
	}
	return evidence, assessment, nil
}

func predicateFreshnessRequests(rules []backendpkg.Rule, g *graph.Graph, inventory []backendpkg.Source, maxStale time.Duration, policy *report.Policy) []backendpkg.RulePredicateFreshnessRequest {
	sources := make(map[string]backendpkg.Source, len(inventory))
	for _, source := range inventory {
		sources[source.Name] = source
	}
	var requests []backendpkg.RulePredicateFreshnessRequest
	for _, rule := range rules {
		if !rule.Enabled || len(rule.PredicateFreshness) == 0 {
			continue
		}
		resolved := make(map[string]bool)
		for _, source := range g.SourcesFor(rule.ID) {
			resolved[source] = true
		}
		basis := backendpkg.FreshnessEventTime
		if strings.EqualFold(strings.TrimSpace(rule.TimestampOverride), "ingestion_time()") {
			basis = backendpkg.FreshnessIngestionTime
		}
		for _, selector := range rule.PredicateFreshness {
			source, ok := sources[selector.Source]
			if !ok || !resolved[selector.Source] {
				continue
			}
			window := maxStale
			if policy != nil {
				window = policy.MaxStaleFor(source.Name, maxStale)
			}
			requests = append(requests, backendpkg.RulePredicateFreshnessRequest{
				RuleID: rule.ID, BackendObjectID: rule.BackendObjectID, Source: source,
				Basis: basis, Window: window, Selector: selector,
			})
		}
	}
	sort.Slice(requests, func(i, j int) bool {
		if requests[i].RuleID != requests[j].RuleID {
			return requests[i].RuleID < requests[j].RuleID
		}
		if requests[i].Source.Name != requests[j].Source.Name {
			return requests[i].Source.Name < requests[j].Source.Name
		}
		return requests[i].Selector.Expression < requests[j].Selector.Expression
	})
	return requests
}

func collectPredicateFreshnessEvidence(ctx context.Context, c backendpkg.Backend, rules []backendpkg.Rule, g *graph.Graph, inventory []backendpkg.Source, maxStale time.Duration, policy *report.Policy) ([]backendpkg.RulePredicateFreshnessEvidence, report.RuntimeAssessment, error) {
	provider, ok := c.(backendpkg.RulePredicateFreshnessProvider)
	if !ok {
		return nil, report.RuntimeAssessment{}, nil
	}
	assessment := report.RuntimeAssessment{Name: report.AssessmentPredicateFreshness}
	requests := predicateFreshnessRequests(rules, g, inventory, maxStale, policy)
	if len(requests) == 0 {
		assessment.Status = backendpkg.EvidenceDisabled
		assessment.Detail = "no enabled, fully resolved rule exposed a supported closed source predicate"
		return nil, assessment, nil
	}
	evidence, err := provider.RulePredicateFreshnessEvidenceFor(ctx, requests)
	if err != nil {
		if ctx.Err() != nil {
			return nil, assessment, ctx.Err()
		}
		assessment.Status = backendpkg.EvidenceIncomplete
		assessment.Detail = "predicate-qualified freshness evidence could not be collected"
		return nil, assessment, nil
	}
	assessed, incomplete, unavailable := 0, 0, 0
	for i := range evidence {
		item := &evidence[i]
		effectiveMaxStale := maxStale
		if policy != nil {
			effectiveMaxStale = policy.MaxStaleFor(item.Source, maxStale)
		}
		if item.Freshness.Status == backendpkg.EvidenceAssessed && item.Freshness.LastEvent.IsZero() &&
			effectiveMaxStale > 0 && item.Freshness.Window < effectiveMaxStale {
			item.Freshness.Status = backendpkg.EvidenceIncomplete
			item.Freshness.Detail = "bounded predicate query window is shorter than the stale threshold"
		}
		switch item.Freshness.Status {
		case backendpkg.EvidenceAssessed:
			assessed++
		case backendpkg.EvidenceUnavailable:
			unavailable++
		default:
			incomplete++
		}
	}
	missing := len(requests) - len(evidence)
	if missing > 0 {
		incomplete += missing
	}
	switch {
	case unavailable == len(requests):
		assessment.Status = backendpkg.EvidenceUnavailable
		assessment.Detail = "predicate-qualified freshness is unavailable for " + countLabel(unavailable, "rule/source check", "rule/source checks")
	case unavailable > 0 || incomplete > 0:
		assessment.Status = backendpkg.EvidenceIncomplete
		assessment.Detail = fmt.Sprintf("predicate-qualified freshness is incomplete for %d of %d rule/source checks", unavailable+incomplete, len(requests))
	default:
		assessment.Status = backendpkg.EvidenceAssessed
		assessment.Detail = "bounded predicate-qualified freshness collected for " + countLabel(assessed, "rule/source check", "rule/source checks")
	}
	return evidence, assessment, nil
}

func runtimeAssessments(o connOpts, g *graph.Graph, scoped []backendpkg.Source, schemaEvidence map[string]state.SchemaAssessment, fields, lag report.RuntimeAssessment, extra ...report.RuntimeAssessment) []report.RuntimeAssessment {
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
			case backendpkg.ResolutionResolved, backendpkg.ResolutionEmpty, backendpkg.ResolutionIncompatible:
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
	assessments := []report.RuntimeAssessment{resolution}
	for _, assessment := range extra {
		if assessment.Name != "" {
			assessments = append(assessments, assessment)
		}
	}
	return append(assessments, fields, lag, schema, candidate)
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

func collectReadOnlyEnrichment(ctx context.Context, c backendpkg.Backend, rules []backendpkg.Rule, candidate bool) ([]backendpkg.ProvenanceEvidence, []backendpkg.LineageEvidence, []backendpkg.SummaryRuleRunEvidence, error) {
	if candidate {
		return nil, nil, nil, nil
	}
	var provenance []backendpkg.ProvenanceEvidence
	if provider, ok := c.(backendpkg.ProvenanceProvider); ok {
		enrichmentCtx, cancel := context.WithTimeout(ctx, readOnlyEnrichmentTimeout)
		items, err := provider.ProvenanceEvidence(enrichmentCtx, rules)
		cancel()
		if err != nil {
			if ctx.Err() != nil {
				return nil, nil, nil, ctx.Err()
			}
			observedAt := time.Now().UTC()
			items = make([]backendpkg.ProvenanceEvidence, 0, len(rules))
			for _, rule := range rules {
				items = append(items, backendpkg.ProvenanceEvidence{
					RuleID: rule.ID, BackendObjectID: rule.BackendObjectID,
					Provenance: backendpkg.ProvenanceRef{Kind: "backend_rule_provenance"},
					Status:     backendpkg.EvidenceUnavailable, Method: "backend-provenance",
					ObservedAt: observedAt, Detail: "rule provenance could not be read",
				})
			}
		}
		provenance = items
	}
	var lineage []backendpkg.LineageEvidence
	if provider, ok := c.(backendpkg.LineageProvider); ok {
		enrichmentCtx, cancel := context.WithTimeout(ctx, readOnlyEnrichmentTimeout)
		items, err := provider.LineageEvidence(enrichmentCtx, rules)
		cancel()
		if err != nil {
			if ctx.Err() != nil {
				return nil, nil, nil, ctx.Err()
			}
			items = []backendpkg.LineageEvidence{{
				Kind:   "backend_lineage_inventory",
				Input:  backendpkg.DependencyRef{Kind: "unavailable_lineage_input"},
				Output: backendpkg.DependencyRef{Kind: "unavailable_lineage_output"},
				Status: backendpkg.EvidenceUnavailable, Method: "backend-lineage",
				ObservedAt: time.Now().UTC(), Detail: "source lineage could not be read",
			}}
		}
		lineage = items
	}
	var summaryRuns []backendpkg.SummaryRuleRunEvidence
	if provider, ok := c.(backendpkg.SummaryRuleRunProvider); ok {
		enrichmentCtx, cancel := context.WithTimeout(ctx, readOnlyEnrichmentTimeout)
		items, err := provider.SummaryRuleRunEvidence(enrichmentCtx, rules)
		cancel()
		if err != nil {
			if ctx.Err() != nil {
				return nil, nil, nil, ctx.Err()
			}
			items = []backendpkg.SummaryRuleRunEvidence{{
				ID:     "backend-summary-rule-runs",
				Rule:   backendpkg.DependencyRef{Kind: "unavailable_summary_rule"},
				Output: backendpkg.DependencyRef{Kind: "unavailable_summary_output"},
				Status: backendpkg.EvidenceUnavailable, Method: "backend-summary-rule-runs",
				ObservedAt: time.Now().UTC(), Detail: "summary-rule runtime evidence could not be read",
			}}
		}
		summaryRuns = items
	}
	return provenance, lineage, summaryRuns, nil
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
	if refresher, ok := c.(backendpkg.ScanRefresher); ok {
		if err := refresher.RefreshForScan(ctx); err != nil {
			return scanResult{}, fmt.Errorf("refreshing backend scan metadata: %w", err)
		}
	}
	var err error
	if o.policyFile != "" {
		o.policy, err = report.LoadPolicy(o.policyFile, time.Now().UTC())
		if err != nil {
			return scanResult{}, err
		}
	}
	configurationID, err := assessmentConfigurationID(o, c)
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
		rules, err = parser.ParseCandidates(ctx, data)
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
	resolver, ok := c.(backendpkg.Resolver)
	if !ok {
		return scanResult{}, fmt.Errorf("backend %q does not provide native input resolution", c.Name())
	}
	resolutions, err := resolver.ResolveInputs(ctx, rules)
	if err != nil {
		return scanResult{}, fmt.Errorf("resolving rule inputs: %w", err)
	}
	g := graph.BuildResolved(rules, all, resolutions)
	freshnessEvidence, freshnessAssessment, err := collectFreshnessEvidence(ctx, c, rules, g, all, o.maxStale, o.policy)
	if err != nil {
		return scanResult{}, fmt.Errorf("reading source-freshness evidence: %w", err)
	}
	for i := range all {
		if evidence, found := freshnessEvidence[all[i].Name]; found {
			all[i].Freshness = evidence
			if evidence.Status == backendpkg.EvidenceAssessed && !evidence.LastEvent.IsZero() {
				all[i].LastEvent = evidence.LastEvent
			}
		}
	}
	// Runtime evidence is attached only after native resolution selects the
	// bounded source set. Rebuild so verdicts see it without narrowing the
	// full catalog used to prove missing tables.
	g = graph.BuildResolved(rules, all, resolutions)

	// Filters scope what the report lists and which sources get stateful
	// assessments; verdicts always see the full inventory, so scoping can
	// never manufacture a dead detection (report.BuildOptions.Scope).
	filtersSet := len(o.include) > 0 || len(o.exclude) > 0
	scoped := graph.FilterSources(all, o.include, o.exclude)
	var scope map[string]bool
	if c.Name() == "sentinel" && !filtersSet {
		scoped = enabledConcreteSources(rules, g, all)
		scope = make(map[string]bool, len(scoped))
		for _, source := range scoped {
			scope[source.Name] = true
		}
	} else if filtersSet {
		scope = make(map[string]bool, len(scoped))
		for _, source := range scoped {
			scope[source.Name] = true
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
	predicateFreshnessEvidence, predicateFreshnessAssessment, err := collectPredicateFreshnessEvidence(ctx, c, rules, g, all, o.maxStale, o.policy)
	if err != nil {
		return scanResult{}, fmt.Errorf("reading predicate-qualified freshness evidence: %w", err)
	}
	fieldEvidence, fieldAssessment, err := collectRequiredFieldEvidence(ctx, c, rules, g, all)
	if err != nil {
		return scanResult{}, fmt.Errorf("reading required-field evidence: %w", err)
	}
	provenanceEvidence, lineageEvidence, summaryRunEvidence, err := collectReadOnlyEnrichment(ctx, c, rules, o.ruleFile != "")
	if err != nil {
		return scanResult{}, fmt.Errorf("reading backend enrichment evidence: %w", err)
	}
	suppressUnused := o.ruleFile != ""
	unusedTelemetryUnavailableDetail := ""
	if c.Name() == "sentinel" && !suppressUnused {
		// The v1 unused-telemetry result requires a source document inventory.
		// Sentinel exposes bounded freshness queries, not a cheap table total,
		// so absence of a consumer is not enough to claim stored unused data.
		unusedTelemetryUnavailableDetail = sentinelUnusedTelemetryUnavailableDetail
	}
	r := report.BuildWithOptions(c.Name(), g, report.BuildOptions{
		Check:                            check,
		Volume:                           stateAssess.volume,
		Schema:                           stateAssess.schema,
		Scope:                            scope,
		FieldEvidence:                    fieldEvidence,
		PredicateFreshnessEvidence:       predicateFreshnessEvidence,
		ProvenanceEvidence:               provenanceEvidence,
		LineageEvidence:                  lineageEvidence,
		SummaryRuleRunEvidence:           summaryRunEvidence,
		Assessments:                      runtimeAssessments(o, g, scoped, stateAssess.schema, fieldAssessment, lagAssessment, freshnessAssessment, predicateFreshnessAssessment),
		SkipUnused:                       suppressUnused,
		UnusedTelemetryUnavailableDetail: unusedTelemetryUnavailableDetail,
		ProducerVersion:                  Version,
		BackendObservedVersion:           observedVersion,
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
	visibleUnmapped := r.VisibleUnmappedRules()
	fmt.Fprintf(w, "deadair scan — %s — %s\n", r.Backend, r.GeneratedAt.Format(time.RFC3339))
	printPlainGateStatus(w, r)
	counts := map[string]int{}
	for _, src := range r.Sources {
		counts[src.Status]++
	}
	fmt.Fprintf(w, "sources:    %d (%d ok, %d stale, %d empty, %d unknown, %d maintenance)\n",
		s.Sources, counts["ok"], counts["stale"], counts["empty"], counts["unknown"], counts["maintenance"])
	fmt.Fprintf(w, "detections: %d enabled / %d total", s.EnabledRules, s.Rules)
	if len(visibleUnmapped) > 0 {
		fmt.Fprintf(w, " (%d not fully assessed)", len(visibleUnmapped))
	}
	fmt.Fprintln(w)
	if len(r.InputResolutions) > 0 {
		resolution := humanInputResolution(r)
		fmt.Fprintf(w, "inputs:     %d resolved, %d empty, %d incompatible, %d unsupported, %d unavailable, %d remote, %d ambiguous\n",
			resolution.Resolved, resolution.Empty, resolution.Incompatible, resolution.Unsupported, resolution.Unavailable,
			resolution.Remote, resolution.Ambiguous)
	}
	if r.Policy != nil {
		fmt.Fprintf(w, "policy:     %d gated, %d accepted, %d expired\n",
			s.GatedFindings, r.Policy.AcceptedActive, r.Policy.AcceptedExpired)
	}
	if s.VolumeLowSources > 0 {
		fmt.Fprintf(w, "volume:     %s below same weekday/hour baseline\n", countLabel(s.VolumeLowSources, "source", "sources"))
	}
	if s.SchemaDriftSources > 0 {
		fmt.Fprintf(w, "schema:     %s changed field_caps since previous snapshot\n", countLabel(s.SchemaDriftSources, "source", "sources"))
	}
	if checks := unassessedChecks(r); len(checks) > 0 {
		fmt.Fprintln(w, "checks:")
		for _, check := range checks {
			fmt.Fprintf(w, "  %s\n", check)
		}
	}
	if len(r.DeadDetections) > 0 {
		fmt.Fprintf(w, "\n%s\n", color(w, "31;1", fmt.Sprintf("DEAD: %s cannot fire right now", countLabel(s.DeadDetections, "enabled detection", "enabled detections"))))
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
		verb := "run"
		if s.ImpairedDetections == 1 {
			verb = "runs"
		}
		fmt.Fprintf(w, "\n%s\n", color(w, "33;1", fmt.Sprintf("IMPAIRED: %s %s with reduced visibility", countLabel(s.ImpairedDetections, "enabled detection", "enabled detections"), verb)))
		for i, d := range r.ImpairedDetections {
			if i >= 15 {
				fmt.Fprintf(w, "  … and %d more (use --json for the full list)\n", s.ImpairedDetections-15)
				break
			}
			fmt.Fprintf(w, "  [%s] %s — %s%s\n", d.Severity, d.Name, strings.Join(impairedReasonLabels(d.Reasons), ", "), impairedDetail(d))
		}
	}
	printPlainSourceFindings(w, sourceAttentionItems(r))
	if len(r.PartialInputCoverage) > 0 {
		verb := "are"
		if s.PartialInputs == 1 {
			verb = "is"
		}
		fmt.Fprintf(w, "\npartial input coverage: %s %s missing while the combined rule input still resolves\n",
			countLabel(s.PartialInputs, "selector", "selectors"), verb)
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
	if len(visibleUnmapped) > 0 || len(r.RemoteRules) > 0 {
		fmt.Fprintf(w, "\ninput assessment: %s, %s; these are not treated as dead\n",
			countLabel(len(visibleUnmapped), "unmapped rule", "unmapped rules"), countLabel(len(r.RemoteRules), "remote rule", "remote rules"))
		shown := 0
		for _, rule := range visibleUnmapped {
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
	printPlainSentinelSignals(w, r)
	if s.UnusedTelemetryAssessment == report.UnusedAssessmentUnavailable && !strings.EqualFold(r.Backend, "sentinel") {
		fmt.Fprintf(w, "\nunused telemetry: not assessed because %s\n", s.UnusedTelemetryExplanation())
	} else if s.UnusedSources > 0 {
		fmt.Fprintf(w, "\nunused telemetry: %s, %s stored with no enabled detection reading it\n",
			countLabel(s.UnusedSources, "source", "sources"), humanBytes(s.UnusedBytes))
		for i, u := range r.UnusedTelemetry {
			if i >= 5 {
				fmt.Fprintf(w, "  … and %d more (use --json for the full list)\n", s.UnusedSources-5)
				break
			}
			fmt.Fprintf(w, "  %s (%s", u.Name, humanBytes(u.SizeBytes))
			if u.DisabledConsumers > 0 {
				fmt.Fprintf(w, ", %s reference it", countLabel(u.DisabledConsumers, "disabled rule", "disabled rules"))
			}
			fmt.Fprintln(w, ")")
		}
	}
}

func humanInputResolution(r *report.Report) report.InputResolutionSummary {
	resolution := r.Summary.InputResolution
	hidden := len(r.UnmappedRules) - len(r.VisibleUnmappedRules())
	if hidden > resolution.Unsupported {
		hidden = resolution.Unsupported
	}
	resolution.Unsupported -= hidden
	return resolution
}

func printPlainSourceFindings(w io.Writer, items []sourceAttention) {
	if len(items) == 0 {
		return
	}
	verb := "need"
	if len(items) == 1 {
		verb = "needs"
	}
	fmt.Fprintf(w, "\nSOURCE FINDINGS: %s %s attention\n", countLabel(len(items), "source", "sources"), verb)
	for i, item := range items {
		if i >= 15 {
			fmt.Fprintf(w, "  … and %d more (use --json for the full list)\n", len(items)-i)
			break
		}
		fmt.Fprintf(w, "  %s — %s\n", item.name, strings.Join(item.reasons, "; "))
	}
}

func printPlainGateStatus(w io.Writer, r *report.Report) {
	switch terminalGateExitCode(r) {
	case report.ExitHealthy:
		if count := sentinelSignalCount(r); count > 0 {
			fmt.Fprintf(w, "%s — no gated findings; review %s below\n", color(w, "32;1", "GATE PASSED"), countLabel(count, "Sentinel signal", "Sentinel signals"))
			return
		}
		fmt.Fprintf(w, "%s — no gated findings\n", color(w, "32;1", "GATE PASSED"))
	case report.ExitFindings:
		fmt.Fprintf(w, "%s — one or more findings require attention\n", color(w, "31;1", "GATE FAILED"))
	default:
		fmt.Fprintf(w, "%s — the gate could not be evaluated safely\n", color(w, "33;1", "SCAN INCOMPLETE"))
	}
}

func printPlainSentinelSignals(w io.Writer, r *report.Report) {
	freshness := ruleSourceFreshnessWarnings(r)
	summaryRuns := summaryRuleRunWarnings(r)
	if len(freshness)+len(summaryRuns) == 0 {
		return
	}
	count := len(freshness) + len(summaryRuns)
	verb := "need"
	if count == 1 {
		verb = "needs"
	}
	fmt.Fprintf(w, "\nSENTINEL SIGNALS: %s %s review. Advisory evidence only; gate unchanged.\n",
		countLabel(count, "signal", "signals"), verb)
	shown := 0
	for _, item := range freshness {
		if shown >= 10 {
			fmt.Fprintf(w, "  … and %d more (use --json for the full list)\n", len(freshness)+len(summaryRuns)-shown)
			return
		}
		shown++
		fmt.Fprintf(w, "  Filtered data — %s\n", ruleSourceLabel(item))
		fmt.Fprintf(w, "    %s\n", filteredFreshnessDetail(item))
		fmt.Fprintln(w, "    Review this rule's filter and matching connector.")
	}
	for _, item := range summaryRuns {
		if shown >= 10 {
			fmt.Fprintf(w, "  … and %d more (use --json for the full list)\n", len(freshness)+len(summaryRuns)-shown)
			return
		}
		shown++
		fmt.Fprintf(w, "  Summary pipeline — %s\n", summaryRuleLabel(item))
		fmt.Fprintf(w, "    %s\n", summaryRunDetail(r, item))
		fmt.Fprintln(w, "    Open the summary rule run history in Sentinel.")
	}
}

func terminalGateExitCode(r *report.Report) int {
	if r.Scope.Mode == "candidate" {
		return r.CandidateExitCode()
	}
	return r.ExitCode()
}

func sentinelSignalCount(r *report.Report) int {
	return len(ruleSourceFreshnessWarnings(r)) + len(summaryRuleRunWarnings(r))
}

func ruleSourceLabel(item report.RuleSourceFreshness) string {
	name := item.RuleName
	if name == "" {
		name = item.RuleID
	}
	return name + " → " + item.Source
}

func filteredFreshnessDetail(item report.RuleSourceFreshness) string {
	status := "Freshness: " + strings.ReplaceAll(item.FreshnessStatus, "-", " ")
	if item.AgeSeconds > 0 && (item.FreshnessStatus == "stale" || item.FreshnessStatus == "empty") {
		prefix := ""
		if item.AgeLowerBound {
			prefix = "at least "
		}
		status = "No matching data for " + prefix + humanDuration(item.AgeSeconds)
	} else if item.FreshnessStatus == "unknown" {
		status = "Freshness could not be confirmed"
	}
	if len(item.Fields) > 0 {
		status += " · Filter fields: " + strings.Join(item.Fields, ", ")
	}
	return status
}

func summaryRuleLabel(item report.SummaryRuleRun) string {
	ruleName := item.Rule.Name
	if ruleName == "" {
		ruleName = item.Rule.ID
	}
	output := item.Output.Name
	if output == "" {
		output = item.Output.ID
	}
	if output == "" {
		return ruleName
	}
	return ruleName + " → " + output
}

func summaryRunDetail(r *report.Report, item report.SummaryRuleRun) string {
	status := item.RunStatus
	if status == "" {
		status = string(item.Status)
	}
	parts := []string{status}
	if item.RunAt != nil {
		reference := r.GeneratedAt
		if reference.IsZero() {
			reference = item.ObservedAt
		}
		if !reference.IsZero() && !item.RunAt.After(reference) {
			age := reference.Sub(*item.RunAt)
			if age < time.Second {
				parts[0] += " just now"
			} else {
				parts[0] += " " + humanDuration(age.Seconds()) + " ago"
			}
		}
	}
	if item.QueryDurationMillis != nil {
		parts = append(parts, humanMilliseconds(*item.QueryDurationMillis))
	}
	if item.ResultCount != nil {
		parts = append(parts, countLabel(int(*item.ResultCount), "row", "rows"))
	}
	if item.Error != "" {
		parts = append(parts, item.Error)
	} else if item.Detail != "" {
		parts = append(parts, item.Detail)
	}
	return strings.Join(parts, " · ")
}

func humanMilliseconds(milliseconds int64) string {
	if milliseconds < 1000 {
		return fmt.Sprintf("%d ms", milliseconds)
	}
	seconds := float64(milliseconds) / 1000
	return strings.TrimRight(strings.TrimRight(fmt.Sprintf("%.1f", seconds), "0"), ".") + "s"
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
		parts = append(parts, fmt.Sprintf("p95 ingest delay %s (max %s) exceeds the rule's lookback margin in %s",
			humanDuration(d.P95LagSeconds), humanDuration(d.MaxLagSeconds), strings.Join(d.LagSources, ", ")))
	}
	if len(d.IncompatibleSources) > 0 {
		parts = append(parts, incompatibleSourceDetail(d.IncompatibleSources))
	}
	if len(parts) == 0 {
		return ""
	}
	return " (" + strings.Join(parts, "; ") + ")"
}

func impairedReasonLabels(reasons []string) []string {
	labels := make([]string, 0, len(reasons))
	for _, reason := range reasons {
		labels = append(labels, report.ImpairedReasonLabel(reason))
	}
	return labels
}

func incompatibleSourceDetail(sources []string) string {
	label := "source not usable by this rule"
	if len(sources) != 1 {
		label = "sources not usable by this rule"
	}
	return label + ": " + strings.Join(sources, ", ")
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
		fmt.Fprintf(w, "IMPAIRED [%s] %s — %s\n", x.Severity, x.Name, strings.Join(impairedReasonLabels(x.Reasons), ", "))
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
			fmt.Fprintf(w, "FINDING  %s — %s (%s)\n", name,
				report.FindingReasonLabel(finding.Class, finding.Reason), report.FindingClassLabel(finding.Class))
		}
	}
	for _, finding := range d.NewlyGatedFindings {
		name := finding.Source
		if name == "" {
			name = finding.RuleName
		}
		fmt.Fprintf(w, "NEW GATE %s — %s (%s)\n", name,
			report.FindingReasonLabel(finding.Class, finding.Reason), report.FindingClassLabel(finding.Class))
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
			fmt.Fprintf(w, "recovered finding: %s — %s (%s)\n", name,
				report.FindingReasonLabel(finding.Class, finding.Reason), report.FindingClassLabel(finding.Class))
		}
	}
	for _, finding := range d.NoLongerGated {
		name := finding.Source
		if name == "" {
			name = finding.RuleName
		}
		fmt.Fprintf(w, "no longer gated: %s — %s (%s)\n", name,
			report.FindingReasonLabel(finding.Class, finding.Reason), report.FindingClassLabel(finding.Class))
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
	fmt.Fprintf(stdout, "deadair tune — %s, %s, %s\n",
		countLabel(tune.Sources, "source", "sources"), countLabel(tune.TotalSamples, "sample", "samples"), countLabel(tune.TotalBuckets, "bucket", "buckets"))
	fmt.Fprintf(stdout, "suggested: --volume-min-samples %d --volume-hysteresis %d --volume-z-threshold %.1f\n",
		tune.Suggested.VolumeMinSamples, tune.Suggested.VolumeHysteresis, tune.Suggested.VolumeZThreshold)
	for i, src := range tune.SourceSummaries {
		if i >= 10 {
			fmt.Fprintf(stdout, "… and %s\n", countLabel(len(tune.SourceSummaries)-10, "more source", "more sources"))
			break
		}
		fmt.Fprintf(stdout, "%s: %s across %s, mean %.1f docs/hour, stddev %.1f\n",
			src.Name, countLabel(src.Samples, "sample", "samples"), countLabel(src.Buckets, "bucket", "buckets"), src.MeanPerHour, src.StdPerHour)
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
	if *interval <= 0 {
		fmt.Fprintln(stderr, "deadair: --interval must be greater than zero")
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

	listener, err := net.Listen("tcp", *bind)
	if err != nil {
		fmt.Fprintf(stderr, "deadair: cannot listen on %s: %v\n", *bind, err)
		return report.ExitError
	}
	defer listener.Close()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	srv := &exporter.Server{}
	scan := func(ctx context.Context) {
		run := func(inst fleetInstance, io connOpts) (scanResult, error) {
			sctx, cancel := context.WithTimeout(ctx, io.timeout)
			defer cancel()
			return scanOnce(sctx, inst.backend, io, inst.name, inst.targetID)
		}
		f, commits := scanFleet(insts, o, run)
		if ctx.Err() != nil {
			return
		}
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
	fmt.Fprintf(stderr, "deadair: serving metrics on http://%s/metrics (scan interval %s)\n", listener.Addr(), *interval)
	if err := serveMetrics(ctx, listener, *interval, srv.Handler(), scan); err != nil {
		fmt.Fprintf(stderr, "deadair: %v\n", err)
		return report.ExitError
	}
	return 0
}

func serveMetrics(parent context.Context, listener net.Listener, interval time.Duration, handler http.Handler, scan func(context.Context)) error {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	httpSrv := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	workerDone := make(chan struct{})
	go func() {
		defer close(workerDone)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			if ctx.Err() != nil {
				return
			}
			scan(ctx)
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	shutdownDone := make(chan struct{})
	go func() {
		defer close(shutdownDone)
		<-ctx.Done()
		shutdownCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if err := httpSrv.Shutdown(shutdownCtx); err != nil {
			_ = httpSrv.Close()
		}
	}()
	err := httpSrv.Serve(listener)
	cancel()
	<-workerDone
	<-shutdownDone
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}
