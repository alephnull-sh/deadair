package state

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/alephnull-sh/deadair/internal/backend"
)

func TestAssessVolumesWarmupAndHysteresis(t *testing.T) {
	now := time.Date(2026, 7, 8, 10, 0, 0, 0, time.UTC)
	store := New()
	store.Sources["logs-app"] = SourceState{
		FirstSeen: now.Add(-48 * time.Hour),
		LastSeen:  now.Add(-time.Hour),
		LastDocs:  1000,
		Buckets: map[string][]float64{
			"3:10": {100, 101, 99, 100},
		},
	}
	opt := VolumeOptions{Now: now, Warmup: 24 * time.Hour, Hysteresis: 2, MinSamples: 4, ZThreshold: 3}

	first := store.AssessVolumes([]backend.Source{{Name: "logs-app", Docs: 1001}}, opt)["logs-app"]
	if first.Status != VolumePending {
		t.Fatalf("first low scan status = %s, want pending", first.Status)
	}
	if first.ZScore == nil || *first.ZScore > -3 {
		t.Fatalf("zscore = %v, want a low-volume outlier", first.ZScore)
	}

	opt.Now = now.Add(time.Minute)
	second := store.AssessVolumes([]backend.Source{{Name: "logs-app", Docs: 1002}}, opt)["logs-app"]
	if second.Status != VolumeLow {
		t.Fatalf("second low scan status = %s, want low", second.Status)
	}

	opt.Now = now.Add(2 * time.Minute)
	recovered := store.AssessVolumes([]backend.Source{{Name: "logs-app", Docs: 1202}}, opt)["logs-app"]
	if recovered.Status != VolumeOK {
		t.Fatalf("recovered status = %s, want ok", recovered.Status)
	}
}

func TestAssessVolumesWarmupSuppressesLow(t *testing.T) {
	now := time.Date(2026, 7, 8, 10, 0, 0, 0, time.UTC)
	store := New()
	store.Sources["logs-new"] = SourceState{
		FirstSeen: now.Add(-time.Hour),
		LastSeen:  now.Add(-time.Hour),
		LastDocs:  1000,
		Buckets: map[string][]float64{
			"3:10": {100, 100, 100, 100},
		},
	}

	got := store.AssessVolumes(
		[]backend.Source{{Name: "logs-new", Docs: 1000}},
		VolumeOptions{Now: now, Warmup: 24 * time.Hour, Hysteresis: 1, MinSamples: 4},
	)["logs-new"]
	if got.Status != VolumeWarming || !got.Warmup {
		t.Fatalf("status = %s warmup=%v, want warming warmup=true", got.Status, got.Warmup)
	}
}

func TestLoadSavePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "deadair-state.json")
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	store := New()
	store.Sources["logs-app"] = SourceState{FirstSeen: time.Now(), LastDocs: 42}
	if err := store.Save(path); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("state permissions = %o, want 0600", info.Mode().Perm())
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Sources["logs-app"].LastDocs != 42 {
		t.Fatalf("loaded state = %+v", loaded.Sources["logs-app"])
	}
}

func TestLoadRejectsUnsupportedVersionWithoutChangingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	// A future schema can change field types. The explicit version must take
	// precedence over errors that would arise from decoding those fields as v1.
	original := []byte("{\n  \"version\": 2,\n  \"sources\": [\"future-layout\"]\n}\n")
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}

	store, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "unsupported state file version 2") ||
		!strings.Contains(err.Error(), "current version is 1") {
		t.Fatalf("Load() = (%+v, %v), want unsupported version error", store, err)
	}
	after, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !bytes.Equal(after, original) {
		t.Fatalf("unsupported state file changed:\nwant: %q\n got: %q", original, after)
	}
}

func TestLoadRejectsMalformedExplicitVersionsWithoutChangingFile(t *testing.T) {
	for _, tt := range []struct {
		name    string
		version string
	}{
		{name: "null", version: "null"},
		{name: "string", version: `"1"`},
		{name: "fractional", version: "1.5"},
		{name: "out of range", version: "18446744073709551616"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "state.json")
			original := []byte(fmt.Sprintf("{\n  \"version\": %s,\n  \"sources\": {}\n}\n", tt.version))
			if err := os.WriteFile(path, original, 0o600); err != nil {
				t.Fatal(err)
			}

			store, err := Load(path)
			if err == nil || !strings.Contains(err.Error(), "parsing state file version: expected an integer") ||
				strings.Contains(err.Error(), "unsupported state file version") {
				t.Fatalf("Load() = (%+v, %v), want malformed explicit version error", store, err)
			}
			after, readErr := os.ReadFile(path)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if !bytes.Equal(after, original) {
				t.Fatalf("malformed state file changed:\nwant: %q\n got: %q", original, after)
			}
		})
	}
}

func TestLoadRejectsNonObjectRootWithoutChangingFile(t *testing.T) {
	for _, tt := range []struct {
		name string
		data string
	}{
		{name: "null", data: " \n null \t"},
		{name: "array", data: `[]`},
		{name: "string", data: `"state"`},
		{name: "number", data: `1`},
		{name: "boolean", data: `true`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "state.json")
			original := []byte(tt.data)
			if err := os.WriteFile(path, original, 0o600); err != nil {
				t.Fatal(err)
			}

			store, err := Load(path)
			if err == nil || !strings.Contains(err.Error(), "malformed state file: top-level JSON value must be an object") {
				t.Fatalf("Load() = (%+v, %v), want non-object root error", store, err)
			}
			after, readErr := os.ReadFile(path)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if !bytes.Equal(after, original) {
				t.Fatalf("non-object state file changed:\nwant: %q\n got: %q", original, after)
			}
		})
	}
}

func TestLoadPreservesEncodingJSONBOMRejection(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	original := append([]byte{0xef, 0xbb, 0xbf}, []byte(`{}`)...)
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}

	store, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "parsing state file:") ||
		strings.Contains(err.Error(), "top-level JSON value must be an object") {
		t.Fatalf("Load() = (%+v, %v), want encoding/json parse error", store, err)
	}
	after, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !bytes.Equal(after, original) {
		t.Fatalf("BOM-prefixed state file changed:\nwant: %q\n got: %q", original, after)
	}
}

func TestLoadCurrentVersionRoundTrips(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	original := []byte(`{"version":1,"target_id":"target-a","sources":{"logs-app":{"last_docs":42}}}`)
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}

	store, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if store.Version != Version || store.TargetID != "target-a" || store.Sources["logs-app"].LastDocs != 42 {
		t.Fatalf("loaded current state = %+v", store)
	}
	if err := store.Save(path); err != nil {
		t.Fatal(err)
	}
	roundTripped, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if roundTripped.Version != Version || roundTripped.TargetID != "target-a" ||
		roundTripped.Sources["logs-app"].LastDocs != 42 {
		t.Fatalf("round-tripped current state = %+v", roundTripped)
	}
}

func TestLoadMigratesLegacyVersionZeroState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	original := []byte(`{"version":0,"sources":{"logs-legacy":{"last_docs":7}}}`)
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}

	store, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if store.Version != Version || store.Sources["logs-legacy"].LastDocs != 7 {
		t.Fatalf("loaded legacy state = %+v", store)
	}
	if err := store.Save(path); err != nil {
		t.Fatal(err)
	}
	migrated, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(migrated, []byte(`"version": 1`)) {
		t.Fatalf("migrated state has no current version:\n%s", migrated)
	}
}

func TestLoadMigratesLegacyMissingVersionState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	original := []byte(`{"sources":{"logs-legacy":{"last_docs":7}}}`)
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}

	store, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if store.Version != Version || store.Sources["logs-legacy"].LastDocs != 7 {
		t.Fatalf("loaded legacy state = %+v", store)
	}
	if err := store.Save(path); err != nil {
		t.Fatal(err)
	}
	migrated, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(migrated, []byte(`"version": 1`)) {
		t.Fatalf("migrated state has no current version:\n%s", migrated)
	}
}

func TestLoadAcceptsWhitespaceWrappedEmptyLegacyObject(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	original := []byte(" \n { } \t")
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}

	store, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if store.Version != Version || store.Sources == nil || store.Findings == nil {
		t.Fatalf("loaded empty legacy state = %+v", store)
	}
	afterLoad, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !bytes.Equal(afterLoad, original) {
		t.Fatalf("loading empty legacy state changed it:\nwant: %q\n got: %q", original, afterLoad)
	}
	if err := store.Save(path); err != nil {
		t.Fatal(err)
	}
	migrated, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(migrated, []byte(`"version": 1`)) {
		t.Fatalf("migrated empty legacy state has no current version:\n%s", migrated)
	}
}

func TestSaveRejectsUnsupportedVersionBeforeMutationOrRewrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	original := []byte("preserve this file exactly\n")
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}
	stale := SourceState{LastSeen: time.Now().UTC().Add(-60 * 24 * time.Hour)}
	store := New()
	store.Version = Version + 1
	store.Sources["logs-stale"] = stale

	err := store.Save(path)
	if err == nil || !strings.Contains(err.Error(), "unsupported state file version 2") {
		t.Fatalf("Save() error = %v, want unsupported version error", err)
	}
	got, found := store.Sources["logs-stale"]
	if store.Version != Version+1 || !found || len(store.Sources) != 1 || !got.LastSeen.Equal(stale.LastSeen) {
		t.Fatalf("unsupported store mutated before rejection: %+v", store)
	}
	after, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !bytes.Equal(after, original) {
		t.Fatalf("destination changed after rejected save:\nwant: %q\n got: %q", original, after)
	}
}

func TestBindTargetRejectsStateReuse(t *testing.T) {
	store := New()
	if err := store.BindTarget("target-a"); err != nil {
		t.Fatal(err)
	}
	if err := store.BindTarget("target-a"); err != nil {
		t.Fatalf("same target was rejected: %v", err)
	}
	if err := store.BindTarget("target-b"); err == nil {
		t.Fatal("state file accepted a different target")
	}
	if store.TargetID != "target-a" {
		t.Fatalf("target binding changed to %q", store.TargetID)
	}
}

func TestAssessSchemas(t *testing.T) {
	store := New()
	now := time.Date(2026, 7, 4, 12, 0, 0, 0, time.UTC)
	requested := []backend.Source{{Name: "logs-app"}}
	first := store.AssessSchemas(requested, map[string]backend.Schema{
		"logs-app": {
			Source: "logs-app",
			Fields: []backend.Field{
				{Name: "@timestamp", Types: []string{"date"}},
				{Name: "event.code", Types: []string{"keyword"}},
				{Name: "message", Types: []string{"text"}},
			},
		},
	}, now)["logs-app"]
	if first.Status != SchemaWarming || first.FieldCount != 3 {
		t.Fatalf("first schema = %+v, want warming with 3 fields", first)
	}

	second := store.AssessSchemas(requested, map[string]backend.Schema{
		"logs-app": {
			Source: "logs-app",
			Fields: []backend.Field{
				{Name: "@timestamp", Types: []string{"date"}},
				{Name: "event.code", Types: []string{"long"}},
				{Name: "host.name", Types: []string{"keyword"}},
			},
		},
	}, now.Add(time.Hour))["logs-app"]
	if second.Status != SchemaDrift {
		t.Fatalf("second schema status = %s, want drift", second.Status)
	}
	if len(second.Added) != 1 || second.Added[0] != "host.name" {
		t.Fatalf("added = %v, want host.name", second.Added)
	}
	if len(second.Removed) != 1 || second.Removed[0] != "message" {
		t.Fatalf("removed = %v, want message", second.Removed)
	}
	if len(second.TypeChanged) != 1 || second.TypeChanged[0].Name != "event.code" {
		t.Fatalf("type changes = %+v, want event.code", second.TypeChanged)
	}
}

func TestAssessSchemasUnknownOnFetchFailure(t *testing.T) {
	store := New()
	now := time.Date(2026, 7, 4, 12, 0, 0, 0, time.UTC)
	requested := []backend.Source{{Name: "logs-app"}}
	schema := map[string]backend.Schema{
		"logs-app": {Source: "logs-app", Fields: []backend.Field{{Name: "@timestamp", Types: []string{"date"}}}},
	}
	store.AssessSchemas(requested, schema, now)

	// Fetch failure: source requested but absent from current. The verdict is
	// unknown and the stored snapshot must survive untouched.
	got := store.AssessSchemas(requested, map[string]backend.Schema{}, now.Add(time.Hour))["logs-app"]
	if got.Status != SchemaUnknown {
		t.Fatalf("status = %s, want unknown", got.Status)
	}
	if store.Sources["logs-app"].Schema == nil || len(store.Sources["logs-app"].Schema.Fields) != 1 {
		t.Fatalf("stored snapshot must be untouched, got %+v", store.Sources["logs-app"].Schema)
	}
	// The next successful fetch diffs against the last good snapshot.
	after := store.AssessSchemas(requested, map[string]backend.Schema{
		"logs-app": {Source: "logs-app", Fields: []backend.Field{{Name: "@timestamp", Types: []string{"date"}}, {Name: "new.field", Types: []string{"keyword"}}}},
	}, now.Add(2*time.Hour))["logs-app"]
	if after.Status != SchemaDrift || len(after.Added) != 1 {
		t.Fatalf("post-failure diff = %+v, want drift with one added field", after)
	}
}

func TestVolumeMaintenanceSuppressesFindings(t *testing.T) {
	now := time.Date(2026, 7, 8, 10, 0, 0, 0, time.UTC)
	store := New()
	store.Sources["logs-app"] = SourceState{
		FirstSeen:       now.Add(-48 * time.Hour),
		LastSeen:        now.Add(-time.Hour),
		LastDocs:        1000,
		VolumeLowStreak: 1,
		Buckets:         map[string][]float64{"3:10": {100, 101, 99, 100}},
	}
	opt := VolumeOptions{
		Now: now, Warmup: 24 * time.Hour, Hysteresis: 2, MinSamples: 4, ZThreshold: 3,
		InDowntime: func(string) bool { return true },
	}
	// Docs flat during declared downtime: must not page, must not record a
	// sample, must not consume the streak.
	got := store.AssessVolumes([]backend.Source{{Name: "logs-app", Docs: 1000}}, opt)["logs-app"]
	if got.Status != VolumeMaintenance {
		t.Fatalf("status = %s, want maintenance", got.Status)
	}
	st := store.Sources["logs-app"]
	if len(st.Buckets["3:10"]) != 4 {
		t.Fatalf("samples recorded during downtime: %v", st.Buckets["3:10"])
	}
	if st.VolumeLowStreak != 1 {
		t.Fatalf("streak = %d, want 1 (unchanged)", st.VolumeLowStreak)
	}
}

func TestNormalizeOptionsMaxSamplesRespectsMinSamples(t *testing.T) {
	opt := normalizeOptions(VolumeOptions{MinSamples: 100})
	if opt.MaxSamples < opt.MinSamples {
		t.Fatalf("MaxSamples %d < MinSamples %d: the sample gate is permanently unreachable", opt.MaxSamples, opt.MinSamples)
	}
	if def := normalizeOptions(VolumeOptions{}); def.MaxSamples != 64 {
		t.Fatalf("default MaxSamples = %d, want 64", def.MaxSamples)
	}
}

func TestZeroStddevRequiresGrossDrop(t *testing.T) {
	now := time.Date(2026, 7, 8, 10, 0, 0, 0, time.UTC)
	newStore := func() *Store {
		s := New()
		s.Sources["logs-flat"] = SourceState{
			FirstSeen: now.Add(-48 * time.Hour),
			LastSeen:  now.Add(-time.Hour),
			LastDocs:  0,
			Buckets:   map[string][]float64{"3:10": {100, 100, 100, 100}},
		}
		return s
	}
	opt := VolumeOptions{Now: now, Warmup: 24 * time.Hour, Hysteresis: 1, MinSamples: 4, ZThreshold: 3}

	// 99 docs/hour against a perfectly steady 100 baseline is jitter, not an
	// outage: must stay ok.
	jitter := newStore().AssessVolumes([]backend.Source{{Name: "logs-flat", Docs: 99}}, opt)["logs-flat"]
	if jitter.Status != VolumeOK {
		t.Fatalf("0.01%% dip status = %s, want ok", jitter.Status)
	}
	// A >50%% drop against the steady baseline is a finding.
	drop := newStore().AssessVolumes([]backend.Source{{Name: "logs-flat", Docs: 40}}, opt)["logs-flat"]
	if drop.Status != VolumeLow {
		t.Fatalf("gross drop status = %s, want low", drop.Status)
	}
}

func TestPruneStale(t *testing.T) {
	now := time.Date(2026, 7, 8, 10, 0, 0, 0, time.UTC)
	store := New()
	store.Sources["rolled-2026.05"] = SourceState{FirstSeen: now.Add(-60 * 24 * time.Hour), LastSeen: now.Add(-45 * 24 * time.Hour)}
	store.Sources["logs-live"] = SourceState{FirstSeen: now.Add(-60 * 24 * time.Hour), LastSeen: now.Add(-time.Hour)}
	store.Sources["schema-only"] = SourceState{Schema: &SchemaState{LastSeen: now.Add(-time.Hour)}}

	store.PruneStale(now, 30*24*time.Hour)
	if _, ok := store.Sources["rolled-2026.05"]; ok {
		t.Fatal("stale rolled index must be pruned")
	}
	if _, ok := store.Sources["logs-live"]; !ok {
		t.Fatal("recently seen source must survive pruning")
	}
	if _, ok := store.Sources["schema-only"]; !ok {
		t.Fatal("source with recent schema activity must survive pruning")
	}
}

func TestTune(t *testing.T) {
	store := New()
	store.Sources["logs-a"] = SourceState{Buckets: map[string][]float64{"1:10": {100, 110}, "2:10": {90}}}
	store.Sources["logs-b"] = SourceState{Buckets: map[string][]float64{"1:10": {1, 100}}}

	got := store.Tune()
	if got.Sources != 2 || got.TotalSamples != 5 || got.TotalBuckets != 3 {
		t.Fatalf("tune summary = %+v", got)
	}
	if got.Suggested.VolumeHysteresis != 3 || got.Suggested.VolumeZThreshold != 4 {
		t.Fatalf("suggested = %+v, want noisier settings due high variance source", got.Suggested)
	}
	if len(got.SourceSummaries) != 2 || got.SourceSummaries[0].Name != "logs-a" {
		t.Fatalf("source summaries = %+v, want logs-a first by sample count", got.SourceSummaries)
	}
}
