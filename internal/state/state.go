// Package state stores cross-scan source and finding history. Volume
// baselines, warmup, hysteresis, and finding lifecycle cannot be derived from
// one poll. The file is as sensitive as a report because it stores source and
// rule names.
package state

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/alephnull-sh/deadair/internal/backend"
	"github.com/alephnull-sh/deadair/internal/securefile"
)

const (
	Version = 1

	VolumeOK          = "ok"
	VolumeLow         = "low"
	VolumePending     = "pending"
	VolumeWarming     = "warming"
	VolumeUnknown     = "unknown"
	VolumeMaintenance = "maintenance"

	SchemaOK      = "ok"
	SchemaDrift   = "drift"
	SchemaWarming = "warming"
	SchemaUnknown = "unknown"
)

// Store is the persisted state file.
type Store struct {
	Version  int                     `json:"version"`
	TargetID string                  `json:"target_id,omitempty"`
	Sources  map[string]SourceState  `json:"sources"`
	Findings map[string]FindingState `json:"findings,omitempty"`
}

// FindingState is the lifecycle record for one stable report finding. The
// descriptive fields let a later scan report a recovery without retaining a
// copy of the previous report.
type FindingState struct {
	FindingID       string    `json:"finding_id"`
	ScopeID         string    `json:"scope_id"`
	FirstSeen       time.Time `json:"first_seen"`
	LastSeen        time.Time `json:"last_seen"`
	Occurrences     int       `json:"occurrences"`
	Active          bool      `json:"active"`
	Class           string    `json:"class"`
	Reason          string    `json:"reason,omitempty"`
	RuleID          string    `json:"rule_id,omitempty"`
	BackendObjectID string    `json:"backend_object_id,omitempty"`
	RuleName        string    `json:"rule_name,omitempty"`
	Severity        string    `json:"severity,omitempty"`
	Source          string    `json:"source,omitempty"`
	Dependency      string    `json:"dependency,omitempty"`
	TargetID        string    `json:"target_id,omitempty"`
	Instance        string    `json:"instance,omitempty"`
	Backend         string    `json:"backend,omitempty"`
}

// SourceState is the state for one concrete source.
type SourceState struct {
	FirstSeen       time.Time            `json:"first_seen"`
	LastSeen        time.Time            `json:"last_seen"`
	LastDocs        int64                `json:"last_docs"`
	VolumeLowStreak int                  `json:"volume_low_streak,omitempty"`
	Buckets         map[string][]float64 `json:"buckets,omitempty"` // weekday-hour -> docs/hour samples
	Schema          *SchemaState         `json:"schema,omitempty"`
}

// SchemaState is the last known schema snapshot for one source.
type SchemaState struct {
	LastSeen time.Time           `json:"last_seen"`
	Fields   map[string][]string `json:"fields"`
}

// VolumeOptions controls stateful volume evaluation.
type VolumeOptions struct {
	Now        time.Time
	Warmup     time.Duration
	Hysteresis int
	MinSamples int
	MaxSamples int
	ZThreshold float64
	// InDowntime, when set, reports whether a source is inside a declared
	// downtime window right now. A quiet window must neither page nor poison
	// the baseline.
	InDowntime func(source string) bool
}

// VolumeAssessment is one source's volume-baseline verdict for this scan.
type VolumeAssessment struct {
	Status       string
	RatePerHour  float64
	BaselineMean float64
	BaselineStd  float64
	ZScore       *float64
	SampleCount  int
	Warmup       bool
}

// SchemaAssessment is one source's schema-drift verdict for this scan.
type SchemaAssessment struct {
	Status      string
	FieldCount  int
	Added       []string
	Removed     []string
	TypeChanged []FieldTypeChange
}

// FieldTypeChange records a field whose concrete backend type set changed.
type FieldTypeChange struct {
	Name   string
	Before []string
	After  []string
}

// TuningReport summarizes accumulated volume history for dogfooding.
type TuningReport struct {
	Sources         int              `json:"sources"`
	TotalBuckets    int              `json:"total_buckets"`
	TotalSamples    int              `json:"total_samples"`
	Suggested       TuningSuggestion `json:"suggested"`
	SourceSummaries []SourceTuning   `json:"sources_detail"`
}

// TuningSuggestion is a conservative global tuning recommendation from the
// available history. It is meant as a starting point, not an automatic policy.
type TuningSuggestion struct {
	VolumeMinSamples int     `json:"volume_min_samples"`
	VolumeHysteresis int     `json:"volume_hysteresis"`
	VolumeZThreshold float64 `json:"volume_z_threshold"`
}

// SourceTuning summarizes one source's accumulated baseline history.
type SourceTuning struct {
	Name        string  `json:"name"`
	Buckets     int     `json:"buckets"`
	Samples     int     `json:"samples"`
	MeanPerHour float64 `json:"mean_per_hour"`
	StdPerHour  float64 `json:"std_per_hour"`
}

// New returns an empty state store.
func New() *Store {
	return &Store{Version: Version, Sources: map[string]SourceState{}, Findings: map[string]FindingState{}}
}

// BindTarget ties a state file to one backend endpoint/namespace identity.
// Source names are not globally unique, so reusing their volume and schema
// history against another target would produce false baselines and drift.
// Legacy state files acquire their binding on their first successful scan.
func (s *Store) BindTarget(targetID string) error {
	if targetID == "" {
		return fmt.Errorf("state target identity is missing")
	}
	if s.TargetID == "" {
		s.TargetID = targetID
		return nil
	}
	if s.TargetID != targetID {
		return fmt.Errorf("state file belongs to target %q, not %q", s.TargetID, targetID)
	}
	return nil
}

// Load reads a state file. A missing file starts a new store.
func Load(path string) (*Store, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return New(), nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading state file: %w", err)
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal(data, &root); err != nil || root == nil {
		return nil, fmt.Errorf("state file must contain a JSON object")
	}
	// encoding/json accepts case-insensitive field aliases and duplicate keys.
	// Neither may override the version after the preflight check.
	decoder := json.NewDecoder(bytes.NewReader(data))
	_, _ = decoder.Token() // The complete JSON object was validated above.
	seenVersion := false
	for decoder.More() {
		key, _ := decoder.Token()
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			return nil, fmt.Errorf("parsing state file: %w", err)
		}
		name := key.(string)
		if strings.EqualFold(name, "version") {
			if name != "version" || seenVersion {
				return nil, fmt.Errorf("state version must appear once as lowercase version")
			}
			seenVersion = true
		}
	}
	version := 0
	if raw, present := root["version"]; present {
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return nil, fmt.Errorf("state version must be an integer")
		}
		if err := json.Unmarshal(raw, &version); err != nil {
			return nil, fmt.Errorf("state version must be an integer: %w", err)
		}
	}
	if version != 0 && version != Version {
		return nil, fmt.Errorf("unsupported state version %d (supported: %d)", version, Version)
	}
	var s Store
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("parsing state file: %w", err)
	}
	if s.Sources == nil {
		s.Sources = map[string]SourceState{}
	}
	if s.Findings == nil {
		s.Findings = map[string]FindingState{}
	}
	if s.Version == 0 {
		s.Version = Version
	}
	return &s, nil
}

// pruneRetention bounds state growth: entries with no activity for this long
// are dropped on Save, or rolled/dated indices would accumulate forever.
const pruneRetention = 30 * 24 * time.Hour

// PruneStale drops sources whose last recorded activity is older than
// retention.
func (s *Store) PruneStale(now time.Time, retention time.Duration) {
	for name, st := range s.Sources {
		last := st.LastSeen
		if st.Schema != nil && st.Schema.LastSeen.After(last) {
			last = st.Schema.LastSeen
		}
		if last.IsZero() {
			last = st.FirstSeen
		}
		if !last.IsZero() && now.Sub(last) > retention {
			delete(s.Sources, name)
		}
	}
	s.pruneFindings(now, retention)
}

// Save writes the state file with report-like permissions.
func (s *Store) Save(path string) error {
	return s.save(path, true)
}

// SaveFindingUpdates persists finding lifecycle changes without pruning or
// otherwise changing source history. Candidate-rule scans use this path: they
// may keep their own scoped finding lifecycle, but must not consume schema
// drift or alter an installed scan's volume baseline.
func (s *Store) SaveFindingUpdates(path string) error {
	return s.save(path, false)
}

func (s *Store) save(path string, pruneSources bool) error {
	if s.Version != 0 && s.Version != Version {
		return fmt.Errorf("unsupported state version %d (supported: %d)", s.Version, Version)
	}
	s.Version = Version
	if pruneSources {
		s.PruneStale(time.Now().UTC(), pruneRetention)
	} else {
		s.pruneFindings(time.Now().UTC(), pruneRetention)
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding state file: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("creating state directory: %w", err)
	}
	if err := securefile.Write(path, append(data, '\n')); err != nil {
		return fmt.Errorf("writing state file: %w", err)
	}
	return nil
}

func (s *Store) pruneFindings(now time.Time, retention time.Duration) {
	for id, finding := range s.Findings {
		if !finding.LastSeen.IsZero() && now.Sub(finding.LastSeen) > retention {
			delete(s.Findings, id)
		}
	}
}

// AssessVolumes updates state and returns current volume-baseline verdicts.
func (s *Store) AssessVolumes(sources []backend.Source, opt VolumeOptions) map[string]VolumeAssessment {
	opt = normalizeOptions(opt)
	out := make(map[string]VolumeAssessment, len(sources))
	for _, src := range sources {
		out[src.Name] = s.assessVolume(src, opt)
	}
	return out
}

// AssessSchemas updates schema snapshots and returns drift verdicts for the
// requested sources. A source whose schema could not be fetched this scan
// (absent from current) is reported unknown and its stored snapshot is left
// untouched, so the next successful fetch still diffs against the last good
// snapshot — a broken source must not kill the report or consume its history.
func (s *Store) AssessSchemas(sources []backend.Source, current map[string]backend.Schema, now time.Time) map[string]SchemaAssessment {
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}
	out := make(map[string]SchemaAssessment, len(sources))
	for _, src := range sources {
		schema, ok := current[src.Name]
		if !ok {
			out[src.Name] = SchemaAssessment{Status: SchemaUnknown}
			continue
		}
		out[src.Name] = s.assessSchema(src.Name, schema, now)
	}
	return out
}

func (s *Store) assessSchema(source string, schema backend.Schema, now time.Time) SchemaAssessment {
	if s.Sources == nil {
		s.Sources = map[string]SourceState{}
	}
	st := s.Sources[source]
	if st.FirstSeen.IsZero() {
		st.FirstSeen = now
	}
	next := schemaFields(schema)
	res := SchemaAssessment{Status: SchemaWarming, FieldCount: len(next)}
	if st.Schema != nil && len(st.Schema.Fields) > 0 {
		res = diffSchemas(st.Schema.Fields, next)
	}
	st.Schema = &SchemaState{LastSeen: now, Fields: next}
	s.Sources[source] = st
	return res
}

func schemaFields(schema backend.Schema) map[string][]string {
	fields := make(map[string][]string, len(schema.Fields))
	for _, f := range schema.Fields {
		types := append([]string(nil), f.Types...)
		sort.Strings(types)
		fields[f.Name] = types
	}
	return fields
}

func diffSchemas(before, after map[string][]string) SchemaAssessment {
	res := SchemaAssessment{Status: SchemaOK, FieldCount: len(after)}
	for name, afterTypes := range after {
		beforeTypes, ok := before[name]
		if !ok {
			res.Added = append(res.Added, name)
			continue
		}
		if !equalStrings(beforeTypes, afterTypes) {
			res.TypeChanged = append(res.TypeChanged, FieldTypeChange{
				Name:   name,
				Before: append([]string(nil), beforeTypes...),
				After:  append([]string(nil), afterTypes...),
			})
		}
	}
	for name := range before {
		if _, ok := after[name]; !ok {
			res.Removed = append(res.Removed, name)
		}
	}
	sort.Strings(res.Added)
	sort.Strings(res.Removed)
	sort.Slice(res.TypeChanged, func(i, j int) bool { return res.TypeChanged[i].Name < res.TypeChanged[j].Name })
	if len(res.Added) > 0 || len(res.Removed) > 0 || len(res.TypeChanged) > 0 {
		res.Status = SchemaDrift
	}
	return res
}

func normalizeOptions(opt VolumeOptions) VolumeOptions {
	if opt.Now.IsZero() {
		opt.Now = time.Now().UTC()
	} else {
		opt.Now = opt.Now.UTC()
	}
	if opt.Hysteresis < 1 {
		opt.Hysteresis = 1
	}
	if opt.MinSamples < 1 {
		opt.MinSamples = 4
	}
	if opt.MaxSamples < opt.MinSamples {
		// Never cap buckets below the sample gate, or the gate becomes
		// permanently unreachable and baselines silently stay "warming".
		opt.MaxSamples = max(64, opt.MinSamples)
	}
	if opt.ZThreshold <= 0 {
		opt.ZThreshold = 3
	}
	return opt
}

func (s *Store) assessVolume(src backend.Source, opt VolumeOptions) VolumeAssessment {
	if s.Sources == nil {
		s.Sources = map[string]SourceState{}
	}
	st := s.Sources[src.Name]
	if st.FirstSeen.IsZero() {
		st.FirstSeen = opt.Now
	}
	if st.Buckets == nil {
		st.Buckets = map[string][]float64{}
	}

	res := VolumeAssessment{Status: VolumeUnknown}
	if src.Docs < 0 || st.LastSeen.IsZero() || st.LastDocs < 0 || src.Docs < st.LastDocs {
		st.LastSeen = opt.Now
		st.LastDocs = src.Docs
		st.VolumeLowStreak = 0
		s.Sources[src.Name] = st
		return res
	}

	elapsed := opt.Now.Sub(st.LastSeen)
	if elapsed <= 0 {
		st.LastSeen = opt.Now
		st.LastDocs = src.Docs
		st.VolumeLowStreak = 0
		s.Sources[src.Name] = st
		return res
	}

	rate := float64(src.Docs-st.LastDocs) / elapsed.Hours()
	if opt.InDowntime != nil && opt.InDowntime(src.Name) {
		// Declared maintenance: keep the streak, record no sample.
		st.LastSeen = opt.Now
		st.LastDocs = src.Docs
		s.Sources[src.Name] = st
		return VolumeAssessment{Status: VolumeMaintenance, RatePerHour: rate}
	}
	bucket := volumeBucket(opt.Now)
	samples := st.Buckets[bucket]
	recordSample := true
	res = VolumeAssessment{Status: VolumeWarming, RatePerHour: rate, SampleCount: len(samples)}
	if opt.Warmup > 0 && opt.Now.Sub(st.FirstSeen) < opt.Warmup {
		res.Warmup = true
	} else if len(samples) >= opt.MinSamples {
		mean, std := meanStd(samples)
		res.BaselineMean = mean
		res.BaselineStd = std
		candidateLow := false
		if std > 0 {
			z := (rate - mean) / std
			res.ZScore = &z
			candidateLow = z <= -opt.ZThreshold
		} else if mean > 0 && rate < mean*0.5 {
			// Zero variance leaves no z-score to threshold; require a gross
			// (>50%) drop so measurement jitter can never page.
			candidateLow = true
		}
		if candidateLow {
			recordSample = false
			st.VolumeLowStreak++
			if st.VolumeLowStreak >= opt.Hysteresis {
				res.Status = VolumeLow
			} else {
				res.Status = VolumePending
			}
		} else {
			st.VolumeLowStreak = 0
			res.Status = VolumeOK
		}
	} else {
		st.VolumeLowStreak = 0
	}

	if recordSample {
		st.Buckets[bucket] = appendLimited(samples, rate, opt.MaxSamples)
	}
	st.LastSeen = opt.Now
	st.LastDocs = src.Docs
	s.Sources[src.Name] = st
	return res
}

func volumeBucket(t time.Time) string {
	return fmt.Sprintf("%d:%02d", int(t.Weekday()), t.Hour())
}

func meanStd(samples []float64) (float64, float64) {
	var sum float64
	for _, s := range samples {
		sum += s
	}
	mean := sum / float64(len(samples))
	var variance float64
	for _, s := range samples {
		d := s - mean
		variance += d * d
	}
	return mean, math.Sqrt(variance / float64(len(samples)))
}

func appendLimited(samples []float64, value float64, limit int) []float64 {
	samples = append(samples, value)
	if len(samples) <= limit {
		return samples
	}
	out := make([]float64, limit)
	copy(out, samples[len(samples)-limit:])
	return out
}

// Tune summarizes real scan history for baseline tuning.
func (s *Store) Tune() TuningReport {
	report := TuningReport{
		Sources: len(s.Sources),
		Suggested: TuningSuggestion{
			VolumeMinSamples: 4,
			VolumeHysteresis: 2,
			VolumeZThreshold: 3,
		},
	}
	for name, src := range s.Sources {
		var values []float64
		for _, samples := range src.Buckets {
			if len(samples) == 0 {
				continue
			}
			report.TotalBuckets++
			report.TotalSamples += len(samples)
			values = append(values, samples...)
		}
		if len(values) == 0 {
			continue
		}
		mean, std := meanStd(values)
		report.SourceSummaries = append(report.SourceSummaries, SourceTuning{
			Name:        name,
			Buckets:     len(src.Buckets),
			Samples:     len(values),
			MeanPerHour: mean,
			StdPerHour:  std,
		})
		if mean > 0 && std/mean > 0.75 {
			report.Suggested.VolumeHysteresis = 3
			report.Suggested.VolumeZThreshold = 4
		}
	}
	sort.Slice(report.SourceSummaries, func(i, j int) bool {
		if report.SourceSummaries[i].Samples != report.SourceSummaries[j].Samples {
			return report.SourceSummaries[i].Samples > report.SourceSummaries[j].Samples
		}
		return report.SourceSummaries[i].Name < report.SourceSummaries[j].Name
	})
	return report
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
