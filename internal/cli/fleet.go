package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	backendpkg "github.com/Big-Comfy/deadair/internal/backend"
	"github.com/Big-Comfy/deadair/internal/backend/elastic"
	"github.com/Big-Comfy/deadair/internal/backend/opensearch"
	"github.com/Big-Comfy/deadair/internal/report"
)

// fleetConfig lists the instances (tenants / deployments) one scan covers.
// Secrets are referenced by env var or file, never inline.
type fleetConfig struct {
	Instances []instanceSpec `json:"instances"`
}

type instanceSpec struct {
	Name          string `json:"name"`
	Backend       string `json:"backend"` // elastic | opensearch
	ESURL         string `json:"es_url"`
	KibanaURL     string `json:"kibana_url"`
	OpenSearchURL string `json:"opensearch_url"`
	Username      string `json:"username"`
	APIKeyEnv     string `json:"api_key_env"`
	APIKeyFile    string `json:"api_key_file"`
	PasswordEnv   string `json:"password_env"`
	PasswordFile  string `json:"password_file"`
	Space         string `json:"space"`
	CACert        string `json:"ca_cert"`
	Insecure      bool   `json:"insecure_skip_verify"`
}

// fleetInstance is one resolved scan target.
type fleetInstance struct {
	name    string
	backend backendpkg.Backend
}

func (s instanceSpec) secret(env, file, label string) (string, error) {
	if file != "" {
		return readSecretFile(file, label)
	}
	if env != "" {
		return os.Getenv(env), nil
	}
	return "", nil
}

func (o *connOpts) buildInstance(s instanceSpec) (fleetInstance, error) {
	if s.Name == "" {
		return fleetInstance{}, fmt.Errorf("instance name is required")
	}
	io := *o
	io.caCert, io.insecureTLS = s.CACert, s.Insecure
	hc, err := io.httpClient(os.Stderr)
	if err != nil {
		return fleetInstance{}, fmt.Errorf("instance %q: %w", s.Name, err)
	}
	switch s.Backend {
	case "", "elastic":
		if s.ESURL == "" || s.KibanaURL == "" {
			return fleetInstance{}, fmt.Errorf("instance %q: es_url and kibana_url are required", s.Name)
		}
		key, err := s.secret(s.APIKeyEnv, s.APIKeyFile, "api key")
		if err != nil {
			return fleetInstance{}, fmt.Errorf("instance %q: %w", s.Name, err)
		}
		return fleetInstance{name: s.Name, backend: &elastic.Client{
			ESURL: s.ESURL, KibanaURL: s.KibanaURL, APIKey: key, Space: s.Space,
			HTTP: hc, Concurrency: o.concurrency,
			MeasureLag: o.stateFile != "",
		}}, nil
	case "opensearch":
		if s.OpenSearchURL == "" {
			return fleetInstance{}, fmt.Errorf("instance %q: opensearch_url is required", s.Name)
		}
		password, err := s.secret(s.PasswordEnv, s.PasswordFile, "password")
		if err != nil {
			return fleetInstance{}, fmt.Errorf("instance %q: %w", s.Name, err)
		}
		key, err := s.secret(s.APIKeyEnv, s.APIKeyFile, "api key")
		if err != nil {
			return fleetInstance{}, fmt.Errorf("instance %q: %w", s.Name, err)
		}
		return fleetInstance{name: s.Name, backend: &opensearch.Client{
			URL: s.OpenSearchURL, Username: s.Username, Password: password, APIKey: key,
			HTTP: hc, Concurrency: o.concurrency,
		}}, nil
	default:
		return fleetInstance{}, fmt.Errorf("instance %q: unknown backend %q", s.Name, s.Backend)
	}
}

// resolveInstances returns the scan targets: the --fleet file when given,
// otherwise the single instance described by flags/env.
func (o *connOpts) resolveInstances(stderr io.Writer) ([]fleetInstance, error) {
	if o.fleetFile == "" {
		c, err := o.client(stderr)
		if err != nil {
			return nil, err
		}
		name := o.instanceName
		if name == "" {
			name = c.Name()
		}
		return []fleetInstance{{name: name, backend: c}}, nil
	}
	data, err := os.ReadFile(o.fleetFile)
	if err != nil {
		return nil, fmt.Errorf("reading fleet file: %w", err)
	}
	var cfg fleetConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing fleet file: %w", err)
	}
	if len(cfg.Instances) == 0 {
		return nil, fmt.Errorf("fleet file lists no instances")
	}
	out := make([]fleetInstance, 0, len(cfg.Instances))
	seen := map[string]bool{}
	for _, s := range cfg.Instances {
		if seen[s.Name] {
			return nil, fmt.Errorf("duplicate instance name %q", s.Name)
		}
		seen[s.Name] = true
		inst, err := o.buildInstance(s)
		if err != nil {
			return nil, err
		}
		out = append(out, inst)
	}
	return out, nil
}

// scanFleet scans every instance sequentially (SIEM-safe: one tenant at a
// time) and tolerates per-instance failures: one dead tenant connection must
// not hide the other eleven. State files are per-instance to keep tenants'
// baselines apart.
func scanFleet(instances []fleetInstance, o connOpts, run func(fleetInstance, connOpts) (scanResult, error)) (*report.FleetReport, []scanResult) {
	var reports []*report.Report
	var errs []report.InstanceError
	var commits []scanResult
	for _, inst := range instances {
		io := o
		if o.stateFile != "" && len(instances) > 1 {
			io.stateFile = o.stateFile + "." + inst.name
		}
		res, err := run(inst, io)
		if err != nil {
			errs = append(errs, report.InstanceError{Instance: inst.name, Error: err.Error()})
			continue
		}
		res.report.Instance = inst.name
		reports = append(reports, res.report)
		commits = append(commits, res)
	}
	return report.BuildFleet(reports, errs), commits
}

func printFleetSummary(w io.Writer, f *report.FleetReport) {
	fmt.Fprintf(w, "deadair fleet — %d instance(s)", f.Summary.Instances)
	if f.Summary.InstancesFailed > 0 {
		fmt.Fprintf(w, ", %d failed", f.Summary.InstancesFailed)
	}
	fmt.Fprintln(w)
	for _, r := range f.Instances {
		fmt.Fprintf(w, "  %s (%s): %d dead, %d impaired, %d degraded source(s), %s unused\n",
			r.Instance, r.Backend, r.Summary.DeadDetections, r.Summary.ImpairedDetections,
			r.Summary.DegradedSources, humanBytes(r.Summary.UnusedBytes))
	}
	for _, e := range f.Errors {
		fmt.Fprintf(w, "  %s: scan failed: %s\n", e.Instance, e.Error)
	}
	shown := 0
	for _, ru := range f.Rollups {
		if ru.DeadIn+ru.ImpairedIn < 2 && f.Summary.Instances > 1 {
			continue // fleet section highlights cross-tenant repeats
		}
		if shown == 0 {
			fmt.Fprintln(w, "\nFLEET: findings across tenants")
		}
		if shown >= 10 {
			fmt.Fprintln(w, "  … more in --json")
			break
		}
		shown++
		fmt.Fprintf(w, "  [%s] %s —", ru.Severity, ru.Name)
		if ru.DeadIn > 0 {
			fmt.Fprintf(w, " dead in %d of %d", ru.DeadIn, ru.Of)
		}
		if ru.ImpairedIn > 0 {
			fmt.Fprintf(w, " impaired in %d of %d", ru.ImpairedIn, ru.Of)
		}
		fmt.Fprintln(w)
	}
}
