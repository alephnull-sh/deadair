// Package exporter exposes the latest scan as Prometheus metrics. Scrapes
// read a cached snapshot and never trigger a scan, so a scrape storm cannot
// become load on the monitored SIEMs. Metric labels enumerate instance and
// source names — the endpoint is as sensitive as the report and binds
// loopback by default (see cmd serve).
package exporter

import (
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"

	"github.com/Big-Comfy/deadair/internal/report"
)

// Server holds the snapshot rendered at /metrics.
type Server struct {
	snapshot atomic.Pointer[report.FleetReport]
	healthy  atomic.Bool
}

// Update stores a new fleet snapshot. Instances that failed this cycle keep
// last-known-good data out of the listing but flip deadair_up to 0.
func (s *Server) Update(f *report.FleetReport) {
	if f == nil {
		s.healthy.Store(false)
		return
	}
	s.snapshot.Store(f)
	s.healthy.Store(len(f.Errors) == 0 && len(f.Instances) > 0)
}

// Handler returns the /metrics handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /metrics", s.metrics)
	return mux
}

func (s *Server) metrics(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	var b strings.Builder

	up := 0
	if s.healthy.Load() {
		up = 1
	}
	fmt.Fprintf(&b, "# HELP deadair_up Whether the most recent scan cycle succeeded for every instance.\n# TYPE deadair_up gauge\ndeadair_up %d\n", up)

	f := s.snapshot.Load()
	if f != nil {
		fmt.Fprintf(&b, "# HELP deadair_last_scan_timestamp_seconds Unix time of the last scan cycle.\n# TYPE deadair_last_scan_timestamp_seconds gauge\ndeadair_last_scan_timestamp_seconds %d\n", f.GeneratedAt.Unix())

		fmt.Fprintf(&b, "# HELP deadair_instance_up Whether the last scan of this instance succeeded.\n# TYPE deadair_instance_up gauge\n")
		for _, r := range f.Instances {
			fmt.Fprintf(&b, "deadair_instance_up{instance=%s} 1\n", label(r.Instance))
		}
		for _, e := range f.Errors {
			fmt.Fprintf(&b, "deadair_instance_up{instance=%s} 0\n", label(e.Instance))
		}

		fmt.Fprintf(&b, "# HELP deadair_sources Number of sources by health status.\n# TYPE deadair_sources gauge\n")
		for _, r := range f.Instances {
			counts := map[string]int{}
			for _, src := range r.Sources {
				counts[src.Status]++
			}
			for _, st := range []string{"ok", "stale", "empty", "unknown", "maintenance"} {
				fmt.Fprintf(&b, "deadair_sources{instance=%s,status=%q} %d\n", label(r.Instance), st, counts[st])
			}
		}

		gauge := func(name, help string, val func(*report.Report) int64) {
			fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s gauge\n", name, help, name)
			for _, r := range f.Instances {
				fmt.Fprintf(&b, "%s{instance=%s} %d\n", name, label(r.Instance), val(r))
			}
		}
		gauge("deadair_detections_dead", "Enabled detections that cannot currently fire.", func(r *report.Report) int64 { return int64(r.Summary.DeadDetections) })
		gauge("deadair_detections_impaired", "Enabled detections running with reduced visibility.", func(r *report.Report) int64 { return int64(r.Summary.ImpairedDetections) })
		gauge("deadair_detections_unmapped", "Enabled detections whose inputs cannot be mapped from metadata.", func(r *report.Report) int64 { return int64(r.Summary.UnmappedRules) })
		gauge("deadair_unused_telemetry_bytes", "Store size of sources no enabled detection reads.", func(r *report.Report) int64 { return r.Summary.UnusedBytes })

		fmt.Fprintf(&b, "# HELP deadair_source_freshness_seconds Seconds since the last event arrived in the source.\n# TYPE deadair_source_freshness_seconds gauge\n")
		for _, r := range f.Instances {
			for _, src := range r.Sources {
				// maintenance carries a real age too; dropping it would trip
				// absent() alerts for every declared window.
				if src.Status == "ok" || src.Status == "stale" || src.Status == "maintenance" {
					fmt.Fprintf(&b, "deadair_source_freshness_seconds{instance=%s,source=%s} %g\n", label(r.Instance), label(src.Name), src.AgeSeconds)
				}
			}
		}
		fmt.Fprintf(&b, "# HELP deadair_source_consumers Enabled detections that read the source (blast radius).\n# TYPE deadair_source_consumers gauge\n")
		for _, r := range f.Instances {
			for _, src := range r.Sources {
				fmt.Fprintf(&b, "deadair_source_consumers{instance=%s,source=%s} %d\n", label(r.Instance), label(src.Name), src.Consumers)
			}
		}
		fmt.Fprintf(&b, "# HELP deadair_source_volume_zscore Current source volume z-score against same weekday/hour baseline.\n# TYPE deadair_source_volume_zscore gauge\n")
		for _, r := range f.Instances {
			for _, src := range r.Sources {
				if src.Volume != nil && src.Volume.ZScore != nil {
					fmt.Fprintf(&b, "deadair_source_volume_zscore{instance=%s,source=%s} %g\n", label(r.Instance), label(src.Name), *src.Volume.ZScore)
				}
			}
		}
		fmt.Fprintf(&b, "# HELP deadair_source_volume_low Sources whose volume is below baseline after warmup and hysteresis.\n# TYPE deadair_source_volume_low gauge\n")
		for _, r := range f.Instances {
			for _, src := range r.Sources {
				if src.Volume == nil {
					continue
				}
				low := 0
				if src.Volume.Status == "low" {
					low = 1
				}
				fmt.Fprintf(&b, "deadair_source_volume_low{instance=%s,source=%s} %d\n", label(r.Instance), label(src.Name), low)
			}
		}
		fmt.Fprintf(&b, "# HELP deadair_source_schema_drift Sources whose field_caps snapshot changed since the previous scan.\n# TYPE deadair_source_schema_drift gauge\n")
		for _, r := range f.Instances {
			for _, src := range r.Sources {
				if src.Schema == nil {
					continue
				}
				drift := 0
				if src.Schema.Status == "drift" {
					drift = 1
				}
				fmt.Fprintf(&b, "deadair_source_schema_drift{instance=%s,source=%s} %d\n", label(r.Instance), label(src.Name), drift)
			}
		}
	}

	_, _ = w.Write([]byte(b.String()))
}

// label renders a Prometheus label value with required escaping.
func label(v string) string {
	v = strings.ReplaceAll(v, `\`, `\\`)
	v = strings.ReplaceAll(v, `"`, `\"`)
	v = strings.ReplaceAll(v, "\n", `\n`)
	return `"` + v + `"`
}
