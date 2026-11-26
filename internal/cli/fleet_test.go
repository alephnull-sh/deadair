package cli

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alephnull-sh/deadair/internal/report"
)

func TestFleetNamesAndStatePaths(t *testing.T) {
	for _, name := range []string{"", "../outside", `a\b`, "a/b", "a:b", ".", "..", "prod.", "prod ", "café", "cafe\u0301", "CON", "lpt1.txt", strings.Repeat("a", 65)} {
		if _, err := fleetStatePath(filepath.Join(t.TempDir(), "state.json"), name); err == nil {
			t.Errorf("unsafe name accepted: %q", name)
		}
	}
	for _, name := range []string{"prod", "Prod-UK_1", "tenant.one", "123"} {
		dir := t.TempDir()
		path, err := fleetStatePath(filepath.Join(dir, "state.json"), name)
		if err != nil || filepath.Dir(path) != dir || filepath.Base(path) != "state.json."+name {
			t.Fatalf("state path %q %v", path, err)
		}
	}
}

func TestFleetRejectsAmbiguousJSONAndNames(t *testing.T) {
	for _, data := range []string{
		`{"instances":[],"instance":[]}`, `{"instances":[]} {}`, `null`,
		`{"instances":[{"name":"prod","typo":true}]}`,
		`{"instances":[{"name":"prod"},{"name":"PROD"}]}`,
		`{"instances":[{"name":"café"},{"name":"cafe\u0301"}]}`,
	} {
		path := filepath.Join(t.TempDir(), "fleet.json")
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		o := connOpts{fleetFile: path}
		if _, err := o.resolveInstances(io.Discard); err == nil {
			t.Fatalf("accepted %s", data)
		}
	}
}

func TestFleetOpenSearchCredentials(t *testing.T) {
	t.Setenv("DEADAIR_TEST_PASSWORD", "password")
	t.Setenv("DEADAIR_TEST_KEY", "key")
	t.Setenv("DEADAIR_TEST_EMPTY", " ")
	keyFile := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(keyFile, []byte("key"), 0600); err != nil {
		t.Fatal(err)
	}
	emptyFile := filepath.Join(t.TempDir(), "empty")
	if err := os.WriteFile(emptyFile, nil, 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		spec  instanceSpec
		valid bool
	}{
		{"anonymous", instanceSpec{}, true},
		{"key", instanceSpec{APIKeyEnv: "DEADAIR_TEST_KEY"}, true},
		{"basic", instanceSpec{Username: "scanner", PasswordEnv: "DEADAIR_TEST_PASSWORD"}, true},
		{"username only", instanceSpec{Username: "scanner"}, false},
		{"password only", instanceSpec{PasswordEnv: "DEADAIR_TEST_PASSWORD"}, false},
		{"both auth types", instanceSpec{Username: "scanner", PasswordEnv: "DEADAIR_TEST_PASSWORD", APIKeyEnv: "DEADAIR_TEST_KEY"}, false},
		{"two key sources", instanceSpec{APIKeyEnv: "DEADAIR_TEST_KEY", APIKeyFile: keyFile}, false},
		{"empty env", instanceSpec{APIKeyEnv: "DEADAIR_TEST_EMPTY"}, false},
		{"empty file", instanceSpec{APIKeyFile: emptyFile}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.spec.Name, tc.spec.Backend, tc.spec.OpenSearchURL = "prod", "opensearch", "http://unused.invalid"
			data, err := json.Marshal(fleetConfig{Instances: []instanceSpec{tc.spec}})
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "fleet.json")
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			o := connOpts{fleetFile: path}
			_, err = o.resolveInstances(io.Discard)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v error=%v", tc.valid, err)
			}
		})
	}
}

func TestSingleOpenSearchCredentials(t *testing.T) {
	secretFile := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(secretFile, []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name                            string
		username, password, key         string
		passwordFile, keyFile, fallback string
		valid                           bool
	}{
		{name: "anonymous", valid: true},
		{name: "basic", username: "scanner", password: "secret", valid: true},
		{name: "key", key: "secret", valid: true},
		{name: "key file", keyFile: secretFile, valid: true},
		{name: "generic key fallback", fallback: "secret", valid: true},
		{name: "username only", username: "scanner"},
		{name: "password only", password: "secret"},
		{name: "two auth types", username: "scanner", password: "secret", key: "secret"},
		{name: "two password sources", username: "scanner", password: "secret", passwordFile: secretFile},
		{name: "two key sources", key: "secret", keyFile: secretFile},
		{name: "file and generic key", fallback: "secret", keyFile: secretFile},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("DEADAIR_OPENSEARCH_PASSWORD", tc.password)
			t.Setenv("DEADAIR_OPENSEARCH_API_KEY", tc.key)
			t.Setenv("DEADAIR_API_KEY", tc.fallback)
			o := connOpts{opensearchURL: "http://unused.invalid", opensearchUsername: tc.username, opensearchPasswordFile: tc.passwordFile, apiKeyFile: tc.keyFile}
			_, err := o.openSearchClient(io.Discard)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v error=%v", tc.valid, err)
			}
		})
	}
}

func TestScanFleetConcurrencyPreservesDeterministicOrderAndIsolatesFailures(t *testing.T) {
	instances := []fleetInstance{
		{name: "tenant-alpha"},
		{name: "tenant-beta"},
		{name: "tenant-gamma"},
		{name: "tenant-delta"},
	}
	var active, maxActive atomic.Int32
	stateBase := filepath.Join(t.TempDir(), "state.json")
	fleetReport, commits := scanFleet(instances, connOpts{fleetConcurrency: 3, stateFile: stateBase}, func(inst fleetInstance, io connOpts) (scanResult, error) {
		cur := active.Add(1)
		for {
			prev := maxActive.Load()
			if cur <= prev || maxActive.CompareAndSwap(prev, cur) {
				break
			}
		}
		defer active.Add(-1)
		// Deliberately make earlier instances finish slower than later ones.
		if inst.name == "tenant-alpha" {
			time.Sleep(25 * time.Millisecond)
		} else {
			time.Sleep(5 * time.Millisecond)
		}
		if inst.name == "tenant-beta" {
			return scanResult{}, errors.New("connection refused")
		}
		return scanResult{
			report: &report.Report{Backend: "elastic"},
			path:   io.stateFile,
		}, nil
	})
	if maxActive.Load() < 2 || maxActive.Load() > 3 {
		t.Fatalf("max concurrent fleet workers = %d, want 2..3", maxActive.Load())
	}
	if len(fleetReport.Instances) != 3 ||
		fleetReport.Instances[0].Instance != "tenant-alpha" ||
		fleetReport.Instances[1].Instance != "tenant-gamma" ||
		fleetReport.Instances[2].Instance != "tenant-delta" {
		t.Fatalf("fleet instance order = %+v", fleetReport.Instances)
	}
	if len(fleetReport.Errors) != 1 || fleetReport.Errors[0].Instance != "tenant-beta" {
		t.Fatalf("fleet errors = %+v", fleetReport.Errors)
	}
	if len(commits) != 3 ||
		filepath.Base(commits[0].path) != "state.json.tenant-alpha" ||
		filepath.Base(commits[1].path) != "state.json.tenant-gamma" ||
		filepath.Base(commits[2].path) != "state.json.tenant-delta" {
		t.Fatalf("commits order = %+v", commits)
	}
}
