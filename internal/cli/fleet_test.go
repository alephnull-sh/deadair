package cli

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/alephnull-sh/deadair/internal/backend/opensearch"
	"github.com/alephnull-sh/deadair/internal/report"
)

func TestValidateFleetInstanceName(t *testing.T) {
	for _, name := range []string{
		"acme-prod",
		"beta_corp.2",
		"München SOC @ prod (blue)",
	} {
		t.Run("valid_"+name, func(t *testing.T) {
			if err := validateFleetInstanceName(name); err != nil {
				t.Fatalf("validateFleetInstanceName(%q): %v", name, err)
			}
		})
	}

	for _, name := range []string{
		"",
		"../tenant",
		"tenant/../../../outside",
		`..\tenant`,
		"/absolute",
		`C:\absolute`,
		"tenant:stream",
		"tenant\nprod",
		"tenant\x7fprod",
		"tenant.",
		" tenant",
		"tenant ",
	} {
		t.Run("invalid_"+name, func(t *testing.T) {
			if err := validateFleetInstanceName(name); err == nil {
				t.Fatalf("validateFleetInstanceName(%q) unexpectedly succeeded", name)
			}
		})
	}
}

func TestFleetStatePathStaysWithPrefix(t *testing.T) {
	base := filepath.Join(t.TempDir(), "fleet-state.json")
	got, err := fleetStatePath(base, "München SOC @ prod (blue)")
	if err != nil {
		t.Fatal(err)
	}
	want := base + ".München SOC @ prod (blue)"
	if got != want || filepath.Dir(got) != filepath.Dir(base) {
		t.Fatalf("fleet state path = %q, want %q in %q", got, want, filepath.Dir(base))
	}
	for _, name := range []string{"../../outside", "tenant/../../../outside", `tenant\..\..\outside`} {
		if got, err := fleetStatePath(base, name); err == nil {
			t.Fatalf("fleetStatePath(%q) = %q, want rejection", name, got)
		}
	}
}

func TestScanFleetRejectsUnsafeStateNameBeforeRun(t *testing.T) {
	base := filepath.Join(t.TempDir(), "fleet-state.json")
	instances := []fleetInstance{{name: "safe"}, {name: "tenant/../../../outside"}}
	called := map[string]string{}
	fleet, _ := scanFleet(instances, connOpts{stateFile: base}, func(inst fleetInstance, opts connOpts) (scanResult, error) {
		called[inst.name] = opts.stateFile
		return scanResult{report: &report.Report{}}, nil
	})
	if called["safe"] != base+".safe" {
		t.Fatalf("safe state path = %q", called["safe"])
	}
	if _, ok := called[instances[1].name]; ok {
		t.Fatal("unsafe instance reached scan callback")
	}
	if len(fleet.Errors) != 1 || !strings.Contains(fleet.Errors[0].Error, "unsafe in state-file names") {
		t.Fatalf("unsafe instance errors = %+v", fleet.Errors)
	}
}

func TestFleetConfigJSONIsStrict(t *testing.T) {
	t.Setenv("FLEET_TEST_ES_KEY", "elastic-key")
	t.Setenv("FLEET_TEST_OS_PASSWORD", "opensearch-password")

	valid := `{"instances":[
		{"name":"acme-prod","backend":"elastic","es_url":"https://es.example","kibana_url":"https://kibana.example","api_key_env":"FLEET_TEST_ES_KEY"},
		{"name":"beta-opensearch","backend":"opensearch","opensearch_url":"https://os.example","username":"deadair","password_env":"FLEET_TEST_OS_PASSWORD"}
	]}`
	tests := []struct {
		name    string
		data    string
		wantErr string
		wantN   int
	}{
		{name: "existing valid fleet with trailing whitespace", data: valid + "\n\t ", wantN: 2},
		{name: "unknown top-level field", data: `{"instances":[],"instnaces":[]}`, wantErr: `unknown field "instnaces"`},
		{name: "unknown instance field", data: `{"instances":[{"name":"acme","backend":"elastic","es_url":"https://es.example","kibana_url":"https://kibana.example","api_key_enb":"KEY"}]}`, wantErr: `unknown field "api_key_enb"`},
		{name: "unknown remote-workspace field", data: `{"instances":[{"name":"sentinel","backend":"sentinel","azure_subscription_id":"sub","azure_resource_group":"rg","sentinel_workspace":"law","sentinel_remote_workspaces":[{"alias":"soc","azure_subscription_id":"remote-sub","azure_resource_group":"remote-rg","sentinel_workspace":"remote-law","sentinel_workpace_id":"typo"}]}]}`, wantErr: `unknown field "sentinel_workpace_id"`},
		{name: "second JSON document", data: valid + ` {"instances":[]}`, wantErr: "multiple JSON values"},
		{name: "trailing non-JSON data", data: valid + ` trailing`, wantErr: "invalid character"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "fleet.json")
			if err := os.WriteFile(path, []byte(tt.data), 0o600); err != nil {
				t.Fatal(err)
			}
			instances, err := (&connOpts{fleetFile: path}).resolveInstances(io.Discard)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("resolveInstances() error = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(instances) != tt.wantN {
				t.Fatalf("instances = %d, want %d", len(instances), tt.wantN)
			}
		})
	}
}

func TestFleetConfigValidatesAllNamesBeforeSecrets(t *testing.T) {
	data := `{"instances":[
		{"name":"Tenant-A","backend":"elastic","es_url":"https://es.example","kibana_url":"https://kibana.example","api_key_file":"/does/not/exist"},
		{"name":"tenant-a","backend":"elastic","es_url":"https://es.example","kibana_url":"https://kibana.example"}
	]}`
	path := filepath.Join(t.TempDir(), "fleet.json")
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := (&connOpts{fleetFile: path}).resolveInstances(io.Discard)
	if err == nil || !strings.Contains(err.Error(), "duplicate instance name") || strings.Contains(err.Error(), "reading api key file") {
		t.Fatalf("resolveInstances() error = %v, want duplicate before secret read", err)
	}
}

func TestFleetConfigRejectsUnicodeNormalisationAliases(t *testing.T) {
	data := `{"instances":[
		{"name":"é","backend":"opensearch","opensearch_url":"https://one.example"},
		{"name":"e\u0301","backend":"opensearch","opensearch_url":"https://two.example"}
	]}`
	path := filepath.Join(t.TempDir(), "fleet.json")
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := (&connOpts{fleetFile: path}).resolveInstances(io.Discard)
	if err == nil || !strings.Contains(err.Error(), "duplicate instance name") {
		t.Fatalf("resolveInstances() error = %v, want normalisation-alias rejection", err)
	}
}

func TestValidateOpenSearchAuthMatrix(t *testing.T) {
	tests := []struct {
		name                    string
		username, password, key string
		wantErr                 string
	}{
		{name: "unauthenticated"},
		{name: "basic", username: "user", password: "password"},
		{name: "api key", key: "key"},
		{name: "username only", username: "user", wantErr: "requires both username and password"},
		{name: "password only", password: "password", wantErr: "requires both username and password"},
		{name: "basic and api key", username: "user", password: "password", key: "key", wantErr: "ambiguous"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateOpenSearchAuth(tt.username, tt.password, tt.key)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("validateOpenSearchAuth() error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestOpenSearchAuthValidationAppliesToSingleAndFleet(t *testing.T) {
	t.Setenv("DEADAIR_OPENSEARCH_PASSWORD", "")
	t.Setenv("DEADAIR_OPENSEARCH_API_KEY", "")
	t.Setenv("DEADAIR_API_KEY", "")
	_, singleErr := (&connOpts{opensearchURL: "https://os.example", opensearchUsername: "user"}).openSearchClient(io.Discard)
	_, fleetErr := (&connOpts{}).buildInstance(instanceSpec{
		Name: "tenant", Backend: "opensearch", OpenSearchURL: "https://os.example", Username: "user",
	}, io.Discard)
	for mode, err := range map[string]error{"single": singleErr, "fleet": fleetErr} {
		if err == nil || !strings.Contains(err.Error(), "requires both username and password") {
			t.Fatalf("%s target error = %v", mode, err)
		}
	}
}

func TestFleetOpenSearchAuthModes(t *testing.T) {
	t.Setenv("FLEET_TEST_PASSWORD", "password")
	t.Setenv("FLEET_TEST_API_KEY", "api-key")
	t.Setenv("FLEET_TEST_EMPTY", "")
	tests := []struct {
		name    string
		spec    instanceSpec
		wantErr string
		warning bool
	}{
		{name: "unauthenticated", spec: instanceSpec{Name: "none", Backend: "opensearch", OpenSearchURL: "https://os.example"}, warning: true},
		{name: "basic", spec: instanceSpec{Name: "basic", Backend: "opensearch", OpenSearchURL: "https://os.example", Username: "user", PasswordEnv: "FLEET_TEST_PASSWORD"}},
		{name: "api key", spec: instanceSpec{Name: "api", Backend: "opensearch", OpenSearchURL: "https://os.example", APIKeyEnv: "FLEET_TEST_API_KEY"}},
		{name: "password only", spec: instanceSpec{Name: "password", Backend: "opensearch", OpenSearchURL: "https://os.example", PasswordEnv: "FLEET_TEST_PASSWORD"}, wantErr: "requires both username and password"},
		{name: "mixed", spec: instanceSpec{Name: "mixed", Backend: "opensearch", OpenSearchURL: "https://os.example", Username: "user", PasswordEnv: "FLEET_TEST_PASSWORD", APIKeyEnv: "FLEET_TEST_API_KEY"}, wantErr: "ambiguous"},
		{name: "empty API key reference", spec: instanceSpec{Name: "empty-api", Backend: "opensearch", OpenSearchURL: "https://os.example", APIKeyEnv: "FLEET_TEST_EMPTY"}, wantErr: "resolved to an empty value"},
		{name: "missing password variable", spec: instanceSpec{Name: "missing-password", Backend: "opensearch", OpenSearchURL: "https://os.example", Username: "user", PasswordEnv: "FLEET_TEST_MISSING"}, wantErr: "resolved to an empty value"},
		{name: "two API key references", spec: instanceSpec{Name: "two-api", Backend: "opensearch", OpenSearchURL: "https://os.example", APIKeyEnv: "FLEET_TEST_API_KEY", APIKeyFile: "/not/read"}, wantErr: "either an environment variable or a file"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stderr bytes.Buffer
			instance, err := (&connOpts{}).buildInstance(tt.spec, &stderr)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("buildInstance() error = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			client, ok := instance.backend.(*opensearch.Client)
			if !ok {
				t.Fatalf("backend = %T", instance.backend)
			}
			if tt.warning != strings.Contains(stderr.String(), "connecting unauthenticated") {
				t.Fatalf("warning = %q, want warning %t", stderr.String(), tt.warning)
			}
			if tt.name == "basic" && (client.Username != "user" || client.Password != "password" || client.APIKey != "") {
				t.Fatalf("basic credentials = %+v", client)
			}
			if tt.name == "api key" && (client.APIKey != "api-key" || client.Username != "" || client.Password != "") {
				t.Fatalf("API-key credentials = %+v", client)
			}
		})
	}
}

func TestFleetOpenSearchAuthReachesWireOrFailsBeforeRequest(t *testing.T) {
	type testCase struct {
		name       string
		configure  func(t *testing.T, spec map[string]any)
		wantHeader string
		wantErr    string
	}
	tests := []testCase{
		{
			name: "basic authentication",
			configure: func(t *testing.T, spec map[string]any) {
				t.Setenv("FLEET_WIRE_PASSWORD", "synthetic-password")
				spec["username"] = "synthetic-user"
				spec["password_env"] = "FLEET_WIRE_PASSWORD"
			},
			wantHeader: "Basic " + base64.StdEncoding.EncodeToString([]byte("synthetic-user:synthetic-password")),
		},
		{
			name: "API key authentication",
			configure: func(t *testing.T, spec map[string]any) {
				keyFile := filepath.Join(t.TempDir(), "api-key")
				if err := os.WriteFile(keyFile, []byte("synthetic-api-key\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				spec["api_key_file"] = keyFile
			},
			wantHeader: "ApiKey synthetic-api-key",
		},
		{
			name:       "intentional unauthenticated access",
			configure:  func(*testing.T, map[string]any) {},
			wantHeader: "",
		},
		{
			name: "username without password reference",
			configure: func(_ *testing.T, spec map[string]any) {
				spec["username"] = "synthetic-user"
			},
			wantErr: "requires both username and password",
		},
		{
			name: "password environment reference without username",
			configure: func(t *testing.T, spec map[string]any) {
				t.Setenv("FLEET_WIRE_PASSWORD", "synthetic-password")
				spec["password_env"] = "FLEET_WIRE_PASSWORD"
			},
			wantErr: "requires both username and password",
		},
		{
			name: "empty password environment reference",
			configure: func(t *testing.T, spec map[string]any) {
				t.Setenv("FLEET_WIRE_EMPTY_PASSWORD", "")
				spec["username"] = "synthetic-user"
				spec["password_env"] = "FLEET_WIRE_EMPTY_PASSWORD"
			},
			wantErr: "resolved to an empty value",
		},
		{
			name: "empty API key file",
			configure: func(t *testing.T, spec map[string]any) {
				keyFile := filepath.Join(t.TempDir(), "empty-api-key")
				if err := os.WriteFile(keyFile, nil, 0o600); err != nil {
					t.Fatal(err)
				}
				spec["api_key_file"] = keyFile
			},
			wantErr: "resolved to an empty value",
		},
		{
			name: "mixed basic and API key references",
			configure: func(t *testing.T, spec map[string]any) {
				t.Setenv("FLEET_WIRE_PASSWORD", "synthetic-password")
				t.Setenv("FLEET_WIRE_API_KEY", "synthetic-api-key")
				spec["username"] = "synthetic-user"
				spec["password_env"] = "FLEET_WIRE_PASSWORD"
				spec["api_key_env"] = "FLEET_WIRE_API_KEY"
			},
			wantErr: "ambiguous",
		},
		{
			name: "conflicting password environment and file references",
			configure: func(t *testing.T, spec map[string]any) {
				t.Setenv("FLEET_WIRE_PASSWORD", "synthetic-password")
				passwordFile := filepath.Join(t.TempDir(), "password")
				if err := os.WriteFile(passwordFile, []byte("synthetic-password\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				spec["username"] = "synthetic-user"
				spec["password_env"] = "FLEET_WIRE_PASSWORD"
				spec["password_file"] = passwordFile
			},
			wantErr: "either an environment variable or a file",
		},
		{
			name: "conflicting API key environment and file references",
			configure: func(t *testing.T, spec map[string]any) {
				t.Setenv("FLEET_WIRE_API_KEY", "synthetic-api-key")
				keyFile := filepath.Join(t.TempDir(), "api-key")
				if err := os.WriteFile(keyFile, []byte("synthetic-api-key\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				spec["api_key_env"] = "FLEET_WIRE_API_KEY"
				spec["api_key_file"] = keyFile
			},
			wantErr: "either an environment variable or a file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var requests atomic.Int32
			headers := make(chan string, 1)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				headers <- r.Header.Get("Authorization")
				fmt.Fprint(w, `{"version":{"number":"3.7.0"}}`)
			}))
			defer server.Close()

			spec := map[string]any{
				"name":           "wire-proof",
				"backend":        "opensearch",
				"opensearch_url": server.URL,
			}
			tt.configure(t, spec)
			data, err := json.Marshal(map[string]any{"instances": []any{spec}})
			if err != nil {
				t.Fatal(err)
			}
			fleetFile := filepath.Join(t.TempDir(), "fleet.json")
			if err := os.WriteFile(fleetFile, data, 0o600); err != nil {
				t.Fatal(err)
			}

			instances, err := (&connOpts{fleetFile: fleetFile}).resolveInstances(io.Discard)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("resolveInstances() error did not contain %q", tt.wantErr)
				}
				if requests.Load() != 0 {
					t.Fatal("invalid fleet configuration reached the HTTP server")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(instances) != 1 {
				t.Fatalf("resolved %d instances, want 1", len(instances))
			}
			client, ok := instances[0].backend.(*opensearch.Client)
			if !ok {
				t.Fatalf("backend = %T, want OpenSearch client", instances[0].backend)
			}
			if _, err := client.Version(context.Background()); err != nil {
				t.Fatal(err)
			}
			if requests.Load() != 1 {
				t.Fatalf("HTTP request count = %d, want 1", requests.Load())
			}
			if got := <-headers; got != tt.wantHeader {
				t.Fatal("Authorization header did not match the resolved fleet credential mode")
			}
		})
	}
}
