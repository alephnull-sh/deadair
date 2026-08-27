package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	backendpkg "github.com/alephnull-sh/deadair/internal/backend"
	"github.com/alephnull-sh/deadair/internal/backend/elastic"
	"github.com/alephnull-sh/deadair/internal/backend/opensearch"
	"github.com/alephnull-sh/deadair/internal/backend/sentinel"
	"github.com/alephnull-sh/deadair/internal/report"
	"golang.org/x/text/unicode/norm"
)

// fleetConfig lists the instances (tenants / deployments) one scan covers.
// Secrets are referenced by env var or file, never inline.
type fleetConfig struct {
	Instances []instanceSpec `json:"instances"`
}

type instanceSpec struct {
	Name             string                     `json:"name"`
	Backend          string                     `json:"backend"` // elastic | opensearch | sentinel
	ESURL            string                     `json:"es_url"`
	KibanaURL        string                     `json:"kibana_url"`
	OpenSearchURL    string                     `json:"opensearch_url"`
	Subscription     string                     `json:"azure_subscription_id"`
	ResourceGroup    string                     `json:"azure_resource_group"`
	Workspace        string                     `json:"sentinel_workspace"`
	WorkspaceID      string                     `json:"sentinel_workspace_id"`
	RemoteWorkspaces []sentinel.RemoteWorkspace `json:"sentinel_remote_workspaces,omitempty"`
	Username         string                     `json:"username"`
	APIKeyEnv        string                     `json:"api_key_env"`
	APIKeyFile       string                     `json:"api_key_file"`
	PasswordEnv      string                     `json:"password_env"`
	PasswordFile     string                     `json:"password_file"`
	Space            string                     `json:"space"`
	CACert           string                     `json:"ca_cert"`
	Insecure         bool                       `json:"insecure_skip_verify"`
}

// fleetInstance is one resolved scan target.
type fleetInstance struct {
	name     string
	targetID string
	backend  backendpkg.Backend
}

func backendTargetID(backendName string, parts ...string) string {
	h := sha256.New()
	h.Write([]byte(strings.ToLower(strings.TrimSpace(backendName))))
	for _, part := range parts {
		h.Write([]byte{0})
		h.Write([]byte(canonicalTargetPart(part)))
	}
	return fmt.Sprintf("target-%x", h.Sum(nil)[:10])
}

func canonicalTargetPart(part string) string {
	part = strings.TrimRight(strings.TrimSpace(part), "/")
	parsed, err := url.Parse(part)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return part
	}
	parsed.User = nil
	parsed.RawQuery = ""
	parsed.Fragment = ""
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	parsed.Host = strings.ToLower(parsed.Host)
	return strings.TrimRight(parsed.String(), "/")
}

func sentinelTargetID(subscription, resourceGroup, workspace string, remotes ...sentinel.RemoteWorkspace) string {
	parts := []string{
		strings.ToLower(strings.TrimSpace(subscription)),
		strings.ToLower(strings.TrimSpace(resourceGroup)),
		strings.ToLower(strings.TrimSpace(workspace)),
	}
	parts = append(parts, sentinel.RemoteWorkspaceIdentitySet(remotes)...)
	return backendTargetID("sentinel", parts...)
}

func assessmentConfigurationID(o connOpts, scanBackend backendpkg.Backend) (string, error) {
	h := sha256.New()
	fmt.Fprintf(h, "max-stale=%s\nstateful=%t\nschema=%t\nvolume-warmup=%s\nvolume-hysteresis=%d\nvolume-min-samples=%d\nvolume-z-threshold=%g\n",
		o.maxStale, o.stateFile != "", o.schemaTrack, o.volumeWarmup, o.volumeHysteresis, o.volumeMinSamples, o.volumeZThreshold)
	for _, item := range []struct {
		name string
		path string
	}{{"downtime", o.downtimeFile}, {"policy", o.policyFile}} {
		fmt.Fprintf(h, "%s=", item.name)
		if item.path == "" {
			h.Write([]byte("none\n"))
			continue
		}
		data, err := os.ReadFile(item.path)
		if err != nil {
			return "", fmt.Errorf("reading %s file for scan identity: %w", item.name, err)
		}
		digest := sha256.Sum256(data)
		fmt.Fprintf(h, "%x\n", digest[:])
	}
	if client, ok := scanBackend.(*sentinel.Client); ok {
		fmt.Fprintln(h, "sentinel-remotes=")
		for _, identity := range sentinel.RemoteWorkspaceIdentitySet(client.RemoteWorkspaces) {
			fmt.Fprintf(h, "%x\n", sha256.Sum256([]byte(identity)))
		}
	}
	return fmt.Sprintf("config-%x", h.Sum(nil)[:10]), nil
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

func (s instanceSpec) requiredSecret(env, file, label string) (string, error) {
	if env != "" && file != "" {
		return "", fmt.Errorf("%s must use either an environment variable or a file, not both", label)
	}
	value, err := s.secret(env, file, label)
	if err != nil {
		return "", err
	}
	if value == "" && (env != "" || file != "") {
		return "", fmt.Errorf("configured %s resolved to an empty value", label)
	}
	return value, nil
}

func validateFleetInstanceName(name string) error {
	if name == "" {
		return fmt.Errorf("instance name is required")
	}
	if strings.TrimSpace(name) != name {
		return fmt.Errorf("instance name %q must not have leading or trailing whitespace", name)
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return fmt.Errorf("instance name %q contains a control character", name)
		}
		if strings.ContainsRune(`/\<>:"|?*`, r) {
			return fmt.Errorf("instance name %q contains a character that is unsafe in state-file names", name)
		}
	}
	if strings.HasSuffix(name, ".") {
		return fmt.Errorf("instance name %q must not end with a dot", name)
	}
	return nil
}

func fleetStatePath(base, name string) (string, error) {
	if err := validateFleetInstanceName(name); err != nil {
		return "", err
	}
	path := base + "." + name
	if filepath.Clean(filepath.Dir(path)) != filepath.Clean(filepath.Dir(base)) {
		return "", fmt.Errorf("instance name %q resolves outside the state-file directory", name)
	}
	return path, nil
}

func (o *connOpts) buildInstance(s instanceSpec, stderr io.Writer) (fleetInstance, error) {
	if err := validateFleetInstanceName(s.Name); err != nil {
		return fleetInstance{}, err
	}
	io := *o
	io.caCert, io.insecureTLS = s.CACert, s.Insecure
	hc, err := io.httpClient(stderr)
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
		return fleetInstance{name: s.Name, targetID: backendTargetID("elastic", s.ESURL, s.KibanaURL, s.Space), backend: &elastic.Client{
			ESURL: s.ESURL, KibanaURL: s.KibanaURL, APIKey: key, Space: s.Space,
			HTTP: hc, Concurrency: o.concurrency,
		}}, nil
	case "opensearch":
		if s.OpenSearchURL == "" {
			return fleetInstance{}, fmt.Errorf("instance %q: opensearch_url is required", s.Name)
		}
		password, err := s.requiredSecret(s.PasswordEnv, s.PasswordFile, "OpenSearch password")
		if err != nil {
			return fleetInstance{}, fmt.Errorf("instance %q: %w", s.Name, err)
		}
		key, err := s.requiredSecret(s.APIKeyEnv, s.APIKeyFile, "OpenSearch API key")
		if err != nil {
			return fleetInstance{}, fmt.Errorf("instance %q: %w", s.Name, err)
		}
		if err := validateOpenSearchAuth(s.Username, password, key); err != nil {
			return fleetInstance{}, fmt.Errorf("instance %q: %w", s.Name, err)
		}
		if key == "" && s.Username == "" {
			fmt.Fprintf(stderr, "deadair: warning: instance %q has no OpenSearch auth; connecting unauthenticated\n", s.Name)
		}
		return fleetInstance{name: s.Name, targetID: backendTargetID("opensearch", s.OpenSearchURL), backend: &opensearch.Client{
			URL: s.OpenSearchURL, Username: s.Username, Password: password, APIKey: key,
			HTTP: hc, Concurrency: o.concurrency,
		}}, nil
	case "sentinel":
		client, err := sentinel.NewClient(sentinel.Config{
			SubscriptionID:   s.Subscription,
			ResourceGroup:    s.ResourceGroup,
			WorkspaceName:    s.Workspace,
			WorkspaceID:      s.WorkspaceID,
			RemoteWorkspaces: s.RemoteWorkspaces,
			HTTP:             hc,
			Concurrency:      o.concurrency,
		})
		if err != nil {
			return fleetInstance{}, fmt.Errorf("instance %q: %w", s.Name, err)
		}
		return fleetInstance{
			name: s.Name, targetID: sentinelTargetID(s.Subscription, s.ResourceGroup, s.Workspace, s.RemoteWorkspaces...), backend: client,
		}, nil
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
		targetID := ""
		switch c.Name() {
		case "elastic":
			targetID = backendTargetID(c.Name(), o.esURL, o.kibanaURL, o.kibanaSpace)
		case "opensearch":
			targetID = backendTargetID(c.Name(), o.opensearchURL)
		case "sentinel":
			client, ok := c.(*sentinel.Client)
			if !ok {
				return nil, fmt.Errorf("internal error: Sentinel backend has type %T", c)
			}
			targetID = sentinelTargetID(o.azureSubscriptionID, o.azureResourceGroup, o.sentinelWorkspace, client.RemoteWorkspaces...)
		}
		return []fleetInstance{{name: name, targetID: targetID, backend: c}}, nil
	}
	if o.sentinelRemotesFile != "" {
		return nil, fmt.Errorf("--sentinel-remotes applies to a single Sentinel target; put sentinel_remote_workspaces on each fleet instance")
	}
	data, err := os.ReadFile(o.fleetFile)
	if err != nil {
		return nil, fmt.Errorf("reading fleet file: %w", err)
	}
	var cfg fleetConfig
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parsing fleet file: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			err = fmt.Errorf("multiple JSON values")
		}
		return nil, fmt.Errorf("parsing fleet file: %w", err)
	}
	if len(cfg.Instances) == 0 {
		return nil, fmt.Errorf("fleet file lists no instances")
	}
	seen := make([]string, 0, len(cfg.Instances))
	for _, s := range cfg.Instances {
		if err := validateFleetInstanceName(s.Name); err != nil {
			return nil, err
		}
		nameKey := norm.NFC.String(s.Name)
		for _, prior := range seen {
			if strings.EqualFold(nameKey, norm.NFC.String(prior)) {
				return nil, fmt.Errorf("duplicate instance name %q conflicts with %q", s.Name, prior)
			}
		}
		seen = append(seen, s.Name)
	}
	if o.ruleFile != "" {
		backends := map[string]bool{}
		for _, s := range cfg.Instances {
			name := strings.ToLower(strings.TrimSpace(s.Backend))
			if name == "" {
				name = "elastic"
			}
			backends[name] = true
		}
		if len(backends) > 1 {
			return nil, fmt.Errorf("--rule cannot scan a mixed-backend fleet because candidate file formats are backend-specific")
		}
	}
	out := make([]fleetInstance, 0, len(cfg.Instances))
	for _, s := range cfg.Instances {
		inst, err := o.buildInstance(s, stderr)
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
			path, err := fleetStatePath(o.stateFile, inst.name)
			if err != nil {
				errs = append(errs, report.InstanceError{Instance: inst.name, Error: err.Error()})
				continue
			}
			io.stateFile = path
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
	return report.BuildFleetWithVersion(reports, errs, Version), commits
}

func printFleetSummary(w io.Writer, f *report.FleetReport) {
	fmt.Fprintf(w, "deadair fleet — %s", countLabel(f.Summary.Instances, "instance", "instances"))
	if f.Summary.InstancesFailed > 0 {
		fmt.Fprintf(w, ", %d failed", f.Summary.InstancesFailed)
	}
	fmt.Fprintln(w)
	for _, r := range f.Instances {
		unused := humanBytes(r.Summary.UnusedBytes) + " unused"
		showUnused := true
		switch r.Summary.UnusedTelemetryAssessment {
		case report.UnusedAssessmentUnavailable:
			if strings.EqualFold(r.Backend, "sentinel") {
				showUnused = false
			} else {
				unused = "unused not assessed"
			}
		case report.UnusedAssessmentNotApplicable:
			unused = "unused not applicable"
		}
		fmt.Fprintf(w, "  %s (%s): %d dead, %d impaired, %s",
			r.Instance, r.Backend, r.Summary.DeadDetections, r.Summary.ImpairedDetections,
			countLabel(r.Summary.DegradedSources, "degraded source", "degraded sources"))
		if showUnused {
			fmt.Fprintf(w, ", %s", unused)
		}
		fmt.Fprintln(w)
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
