// Package cli wires the deadair commands. Secrets come from the environment
// or a file, never from argv (argv leaks in process listings).
package cli

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	backendpkg "github.com/Big-Comfy/deadair/internal/backend"
	"github.com/Big-Comfy/deadair/internal/backend/elastic"
	"github.com/Big-Comfy/deadair/internal/backend/opensearch"
	"github.com/Big-Comfy/deadair/internal/exporter"
	"github.com/Big-Comfy/deadair/internal/graph"
	"github.com/Big-Comfy/deadair/internal/health"
	"github.com/Big-Comfy/deadair/internal/report"
	"github.com/Big-Comfy/deadair/internal/state"
)

// Version is stamped at build time via -ldflags.
var Version = "dev"

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
	fmt.Fprintln(w, "  check     verify connectivity and privileges")
	fmt.Fprintln(w, "  scan      one-shot report; exit 0 healthy, 1 findings, 2 error")
	fmt.Fprintln(w, "  serve     Prometheus exporter with periodic scans")
	fmt.Fprintln(w, "  diff      compare two reports; exit 1 on regressions")
	fmt.Fprintln(w, "  tune      suggest baseline settings from accumulated state")
	fmt.Fprintln(w, "  version   print version")
	fmt.Fprintf(w, "\n%s\n", h("GET STARTED"))
	fmt.Fprintln(w, "  deadair setup     # prints the role, key command, and env exports")
	fmt.Fprintln(w, "  deadair check     # confirms the connection and privileges work")
	fmt.Fprintln(w, "  deadair scan      # first report")
	if os.Getenv("DEADAIR_ES_URL") != "" {
		fmt.Fprintf(w, "\nconfigured: elastic (%s)\n", os.Getenv("DEADAIR_ES_URL"))
	} else if os.Getenv("DEADAIR_OPENSEARCH_URL") != "" {
		fmt.Fprintf(w, "\nconfigured: opensearch (%s)\n", os.Getenv("DEADAIR_OPENSEARCH_URL"))
	} else {
		fmt.Fprintln(w, "\nnot configured yet — start with: deadair setup")
	}
	fmt.Fprintln(w, "\nRun \"deadair <command> -h\" for flags. Guides: docs/usage.md")
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
}

func addConnFlags(fs *flag.FlagSet, o *connOpts) {
	fs.StringVar(&o.backendName, "backend", envOr("DEADAIR_BACKEND", "elastic"), "backend to scan: elastic or opensearch (env DEADAIR_BACKEND)")
	fs.StringVar(&o.esURL, "es-url", os.Getenv("DEADAIR_ES_URL"), "Elasticsearch base URL (env DEADAIR_ES_URL)")
	fs.StringVar(&o.kibanaURL, "kibana-url", os.Getenv("DEADAIR_KIBANA_URL"), "Kibana base URL (env DEADAIR_KIBANA_URL)")
	fs.StringVar(&o.opensearchURL, "opensearch-url", os.Getenv("DEADAIR_OPENSEARCH_URL"), "OpenSearch base URL (env DEADAIR_OPENSEARCH_URL)")
	fs.StringVar(&o.opensearchUsername, "opensearch-username", os.Getenv("DEADAIR_OPENSEARCH_USERNAME"), "OpenSearch username for basic auth (env DEADAIR_OPENSEARCH_USERNAME)")
	fs.StringVar(&o.opensearchPasswordFile, "opensearch-password-file", "", "file containing the OpenSearch password (default: env DEADAIR_OPENSEARCH_PASSWORD)")
	fs.StringVar(&o.apiKeyFile, "api-key-file", "", "file containing the API key (default: env DEADAIR_API_KEY)")
	fs.DurationVar(&o.timeout, "timeout", 60*time.Second, "overall timeout per scan")
	fs.IntVar(&o.concurrency, "concurrency", 4, "max parallel freshness queries against the backend")
	fs.DurationVar(&o.maxStale, "max-stale", 30*time.Minute, "freshness window before a source counts as stale")
	fs.Var(&o.include, "include", "source name pattern to include; repeatable, default includes all sources")
	fs.Var(&o.exclude, "exclude", "source name pattern to exclude; repeatable, wins over --include")
	fs.StringVar(&o.downtimeFile, "downtime-file", "", "JSON file describing expected per-source downtime windows")
	fs.StringVar(&o.stateFile, "state-file", "", "state file for volume baselines, warmup, and hysteresis (created 0600)")
	fs.DurationVar(&o.volumeWarmup, "volume-warmup", 24*time.Hour, "time a source must be observed before volume-baseline findings can fire")
	fs.IntVar(&o.volumeHysteresis, "volume-hysteresis", 2, "consecutive low-volume scans required before a volume finding fires")
	fs.IntVar(&o.volumeMinSamples, "volume-min-samples", 4, "same weekday/hour samples required before volume baselines evaluate")
	fs.Float64Var(&o.volumeZThreshold, "volume-z-threshold", 3, "negative z-score threshold for low-volume findings")
	fs.BoolVar(&o.schemaTrack, "schema", false, "track field_caps schema drift; requires --state-file")
	fs.StringVar(&o.caCert, "ca-cert", "", "PEM file with the CA that signed the SIEM's TLS certificate")
	fs.BoolVar(&o.insecureTLS, "insecure-skip-verify", false, "skip TLS certificate verification (testing only)")
	fs.StringVar(&o.kibanaSpace, "kibana-space", "", "Kibana space holding the detection rules (default: default space)")
	fs.StringVar(&o.fleetFile, "fleet", "", "fleet config JSON: scan multiple instances/tenants in one run")
	fs.StringVar(&o.instanceName, "instance-name", "", "instance label in reports and metrics (default: backend name)")
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
		MeasureLag:  o.stateFile != "",
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

func (o *connOpts) stateAssessments(ctx context.Context, c backendpkg.Backend, sources []backendpkg.Source, check health.Check) (stateAssessments, *state.Store, error) {
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
	report *report.Report
	store  *state.Store
	path   string
}

func (s scanResult) commitState() error {
	if s.store == nil {
		return nil
	}
	return s.store.Save(s.path)
}

func scanOnce(ctx context.Context, c backendpkg.Backend, o connOpts) (scanResult, error) {
	var rules []backendpkg.Rule
	var err error
	if o.ruleFile != "" {
		// Candidate mode: evaluate rules from a file against the live
		// environment instead of the installed inventory.
		data, rerr := os.ReadFile(o.ruleFile)
		if rerr != nil {
			return scanResult{}, fmt.Errorf("reading rule file: %w", rerr)
		}
		rules, err = elastic.ParseRuleFile(data)
	} else {
		rules, err = c.Rules(ctx)
	}
	if err != nil {
		return scanResult{}, err
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
	stateAssess, store, err := o.stateAssessments(ctx, c, scoped, check)
	if err != nil {
		return scanResult{}, err
	}
	g := graph.Build(rules, all)
	r := report.BuildWithOptions(c.Name(), g, report.BuildOptions{
		Check:        check,
		Volume:       stateAssess.volume,
		Schema:       stateAssess.schema,
		Scope:        scope,
		SourceFields: stateAssess.fields,
		SkipUnused:   o.ruleFile != "",
	})
	return scanResult{report: r, store: store, path: o.stateFile}, nil
}

func runScan(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var o connOpts
	addConnFlags(fs, &o)
	jsonOut := fs.Bool("json", false, "write the full JSON report to stdout")
	outFile := fs.String("out", "", "also write the JSON report to a file (created 0600)")
	htmlFile := fs.String("html-out", "", "write a static HTML report to a file (created 0600)")
	redactNames := fs.Bool("redact", false, "replace source/rule names with stable digests (shareable report)")
	fs.StringVar(&o.ruleFile, "rule", "", "evaluate candidate rule file (JSON/ndjson export) against the environment instead of installed rules")
	fs.StringVar(&o.ruleFile, "change", "", "alias for --rule: generic proposed-change input")
	if err := fs.Parse(args); err != nil {
		return report.ExitError
	}

	insts, err := o.resolveInstances(stderr)
	if err != nil {
		fmt.Fprintf(stderr, "deadair: %v\n", err)
		return report.ExitError
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	ctx, cancelTimeout := context.WithTimeout(ctx, o.timeout*time.Duration(len(insts)))
	defer cancelTimeout()
	run := func(inst fleetInstance, io connOpts) (scanResult, error) {
		sctx, cancel := context.WithTimeout(ctx, io.timeout)
		defer cancel()
		return scanOnce(sctx, inst.backend, io)
	}

	if o.fleetFile != "" {
		f, commits := scanFleet(insts, o, run)
		if *redactNames {
			f.Redact()
		}
		if *htmlFile != "" {
			fmt.Fprintln(stderr, "deadair: --html-out is per-instance and not yet supported with --fleet")
			return report.ExitError
		}
		if *outFile != "" {
			if err := f.Write(*outFile); err != nil {
				fmt.Fprintf(stderr, "deadair: %v\n", err)
				return report.ExitError
			}
		}
		if *jsonOut {
			enc := json.NewEncoder(stdout)
			enc.SetIndent("", "  ")
			if err := enc.Encode(f); err != nil {
				fmt.Fprintf(stderr, "deadair: %v\n", err)
				return report.ExitError
			}
		} else {
			printFleetSummary(stdout, f)
		}
		for _, c := range commits {
			if err := c.commitState(); err != nil {
				fmt.Fprintf(stderr, "deadair: %v\n", err)
				return report.ExitError
			}
		}
		return f.ExitCode()
	}

	res, err := run(insts[0], o)
	if err != nil {
		fmt.Fprintf(stderr, "deadair: scan failed: %v\n", err)
		if s := err.Error(); strings.Contains(s, "401") || strings.Contains(s, "403") {
			fmt.Fprintln(stderr, "deadair: hint: the credential was rejected — check the key and its role (`deadair setup` shows the expected privileges)")
		}
		return report.ExitError
	}
	res.report.Instance = insts[0].name
	r := res.report
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
	}
	if err := res.commitState(); err != nil {
		fmt.Fprintf(stderr, "deadair: %v\n", err)
		return report.ExitError
	}
	if o.ruleFile != "" {
		return r.CandidateExitCode()
	}
	return r.ExitCode()
}

func printSummary(w io.Writer, r *report.Report) {
	s := r.Summary
	fmt.Fprintf(w, "deadair scan — %s — %s\n", r.Backend, r.GeneratedAt.Format(time.RFC3339))
	counts := map[string]int{}
	for _, src := range r.Sources {
		counts[src.Status]++
	}
	fmt.Fprintf(w, "sources:    %d (%d ok, %d stale, %d empty, %d unknown, %d maintenance)\n",
		s.Sources, counts["ok"], counts["stale"], counts["empty"], counts["unknown"], counts["maintenance"])
	fmt.Fprintf(w, "detections: %d enabled / %d total (%d unmapped)\n", s.EnabledRules, s.Rules, s.UnmappedRules)
	if s.VolumeLowSources > 0 {
		fmt.Fprintf(w, "volume:     %d source(s) below same weekday/hour baseline\n", s.VolumeLowSources)
	}
	if s.SchemaDriftSources > 0 {
		fmt.Fprintf(w, "schema:     %d source(s) changed field_caps since previous snapshot\n", s.SchemaDriftSources)
	}
	if len(r.DeadDetections) > 0 {
		fmt.Fprintf(w, "\n%s\n", color(w, "31;1", fmt.Sprintf("DEAD: %d enabled detection(s) cannot fire right now", s.DeadDetections)))
		for i, d := range r.DeadDetections {
			// severity-sorted, so the cut tail is always the least severe
			if i >= 15 {
				fmt.Fprintf(w, "  … and %d more (use --json for the full list)\n", s.DeadDetections-15)
				break
			}
			fmt.Fprintf(w, "  [%s] %s — %s", d.Severity, d.Name, d.Reason)
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
	if s.UnusedSources > 0 {
		fmt.Fprintf(w, "\nunused telemetry: %d source(s), %s ingested with no enabled detection reading it\n",
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
		fmt.Fprintf(w, "\n%s\n", color(w, "32", "healthy: no dead detections, no degraded sources"))
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
	if d.RetentionSeconds > 0 {
		parts = append(parts, fmt.Sprintf("lookback %s > retention %s",
			humanDuration(d.LookbackSeconds), humanDuration(d.RetentionSeconds)))
	}
	if len(d.MissingFields) > 0 {
		parts = append(parts, "missing "+strings.Join(d.MissingFields, ", "))
	}
	if d.MaxLagSeconds > 0 {
		parts = append(parts, fmt.Sprintf("ingest lag %s exceeds window margin", humanDuration(d.MaxLagSeconds)))
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
	jsonOut := fs.Bool("json", false, "write the diff as JSON")
	if err := fs.Parse(args); err != nil {
		return report.ExitError
	}
	if fs.NArg() != 2 {
		fmt.Fprintln(stderr, "usage: deadair diff [--json] <old-report.json> <new-report.json>")
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
	d := report.Diff(older, newer)
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
	if d.Regressions() == 0 && len(d.RecoveredDead)+len(d.RecoveredImpaired)+len(d.RecoveredSources)+len(d.NewSources)+len(d.RemovedSources)+len(d.NewlyUnused) == 0 {
		fmt.Fprintln(w, "no changes")
		return
	}
	for _, x := range d.NewlyDead {
		fmt.Fprintf(w, "DEAD     [%s] %s — %s\n", x.Severity, x.Name, x.Reason)
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
	for _, x := range d.RecoveredDead {
		fmt.Fprintf(w, "recovered detection: %s\n", x.Name)
	}
	for _, x := range d.RecoveredImpaired {
		fmt.Fprintf(w, "recovered from impairment: %s\n", x.Name)
	}
	for _, s := range d.RecoveredSources {
		fmt.Fprintf(w, "recovered source: %s\n", s.Name)
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
	stateFile := fs.String("state-file", "", "state file to summarize")
	jsonOut := fs.Bool("json", false, "write tuning summary as JSON")
	redactNames := fs.Bool("redact", false, "replace source names with stable digests")
	if err := fs.Parse(args); err != nil {
		return report.ExitError
	}
	if *stateFile == "" {
		fmt.Fprintln(stderr, "deadair: --state-file is required")
		return report.ExitError
	}
	store, err := state.Load(*stateFile)
	if err != nil {
		fmt.Fprintf(stderr, "deadair: %v\n", err)
		return report.ExitError
	}
	tune := store.Tune()
	if *redactNames {
		for i := range tune.SourceSummaries {
			tune.SourceSummaries[i].Name = redactTune("src", tune.SourceSummaries[i].Name)
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

func redactTune(prefix, name string) string {
	sum := sha256.Sum256([]byte(name))
	return prefix + "-" + hex.EncodeToString(sum[:])[:12]
}

func runServe(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var o connOpts
	addConnFlags(fs, &o)
	bind := fs.String("bind", "127.0.0.1:9317", "exporter listen address; keep loopback unless the scrape path is authenticated")
	interval := fs.Duration("interval", 5*time.Minute, "time between scans")
	redactNames := fs.Bool("redact", false, "replace source names in metric labels with stable digests")
	if err := fs.Parse(args); err != nil {
		return report.ExitError
	}

	insts, err := o.resolveInstances(stderr)
	if err != nil {
		fmt.Fprintf(stderr, "deadair: %v\n", err)
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
				return scanOnce(sctx, inst.backend, io)
			}
			f, commits := scanFleet(insts, o, run)
			for _, e := range f.Errors {
				fmt.Fprintf(stderr, "deadair: scan failed (%s): %s\n", e.Instance, e.Error)
			}
			if *redactNames {
				f.Redact()
			}
			srv.Update(f)
			for _, c := range commits {
				if err := c.commitState(); err != nil {
					fmt.Fprintf(stderr, "deadair: %v\n", err)
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
