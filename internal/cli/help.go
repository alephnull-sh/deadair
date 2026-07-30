package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/Big-Comfy/deadair/internal/report"
)

const usageGuideURL = "https://github.com/alephnull-sh/deadair/blob/main/docs/usage.md"

// parseFlags makes help a successful command path while preserving flag
// package diagnostics for invalid input.
func parseFlags(fs *flag.FlagSet, args []string) (bool, int) {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return false, report.ExitHealthy
		}
		return false, report.ExitError
	}
	return true, report.ExitHealthy
}

func scanUsage(w io.Writer) {
	fmt.Fprintln(w, `Usage: deadair scan [options]

Run a live, read-only assessment. Exit 0 is healthy, 1 means findings, and 2
means the scan could not complete.

Connection:
  --backend NAME              elastic or opensearch (default: elastic)
  --es-url URL                Elasticsearch URL (DEADAIR_ES_URL)
  --kibana-url URL            Kibana URL (DEADAIR_KIBANA_URL)
  --opensearch-url URL        OpenSearch URL (DEADAIR_OPENSEARCH_URL)
  --api-key-file FILE         read an API key from FILE instead of the environment
  --opensearch-username NAME  OpenSearch basic-auth username
  --opensearch-password-file FILE
                              read the OpenSearch password from FILE
  --ca-cert FILE              trust the PEM certificate authority in FILE
  --insecure-skip-verify      disable TLS verification (lab use only)
  --kibana-space NAME         Kibana space containing the rules
  --timeout DURATION          overall timeout per instance (default: 1m)
  --concurrency N             parallel backend reads (default: 4)

Output:
  --json                      print JSON instead of the terminal report
  --json-out FILE             write the JSON report to FILE
  --html-out FILE             write a static HTML report to FILE
  --redact                    replace names with stable digests

Scope:
  --include PATTERN           include matching sources; repeatable
  --exclude PATTERN           exclude matching sources; repeatable
  --max-stale DURATION        source freshness window (default: 30m)
  --downtime-file FILE        expected source downtime windows
  --rule FILE                 evaluate Elastic candidate rule JSON or ndjson

Fleet:
  --fleet FILE                scan instances listed in a fleet JSON file
  --instance-name NAME        label a single instance in reports

Stateful checks:
  --state-file FILE           retain local volume, lag, and schema history
  --schema                    track field mapping drift; requires --state-file
  --volume-warmup DURATION    baseline warmup (default: 24h)
  --volume-hysteresis N       low-volume scans before a finding (default: 2)
  --volume-min-samples N      comparable samples required (default: 4)
  --volume-z-threshold N      low-volume z-score threshold (default: 3)

Guide: `+usageGuideURL)
}

func checkUsage(w io.Writer) {
	fmt.Fprintln(w, `Usage: deadair check [connection options]

Verify that the configured credential can run a trustworthy live scan.

Connection:
  --backend NAME              elastic or opensearch (default: elastic)
  --es-url URL                Elasticsearch URL (DEADAIR_ES_URL)
  --kibana-url URL            Kibana URL (DEADAIR_KIBANA_URL)
  --opensearch-url URL        OpenSearch URL (DEADAIR_OPENSEARCH_URL)
  --api-key-file FILE         read an API key from FILE instead of the environment
  --opensearch-username NAME  OpenSearch basic-auth username
  --opensearch-password-file FILE
                              read the OpenSearch password from FILE
  --ca-cert FILE              trust the PEM certificate authority in FILE
  --insecure-skip-verify      disable TLS verification (lab use only)
  --kibana-space NAME         Kibana space containing the rules
  --timeout DURATION          timeout per instance (default: 1m)
  --concurrency N             parallel backend reads (default: 4)
  --fleet FILE                check instances listed in a fleet JSON file
  --instance-name NAME        label a single instance

Guide: `+usageGuideURL)
}

func diffUsage(w io.Writer) {
	fmt.Fprintln(w, `Usage: deadair diff [--json] OLD_REPORT NEW_REPORT

Compare two JSON reports. Exit 1 means the newer report contains regressions.

  --json  print the diff as JSON

Guide: `+usageGuideURL+`#compare-two-reports`)
}

func tuneUsage(w io.Writer) {
	fmt.Fprintln(w, `Usage: deadair tune --state-file FILE [options]

Suggest volume-baseline settings from accumulated local state.

  --state-file FILE  state file to summarize
  --json             print the tuning summary as JSON
  --redact           replace source names with stable digests

Guide: `+usageGuideURL+`#tune-volume-thresholds`)
}

func serveUsage(w io.Writer) {
	fmt.Fprintln(w, `Usage: deadair serve [options]

Run periodic live scans and expose the latest result as Prometheus metrics.

Exporter:
  --bind ADDRESS              listen address (default: 127.0.0.1:9317)
  --interval DURATION         time between scans (default: 5m)
  --redact                    replace metric-label names with stable digests

Connection and scan:
  --backend NAME              elastic or opensearch (default: elastic)
  --es-url URL                Elasticsearch URL (DEADAIR_ES_URL)
  --kibana-url URL            Kibana URL (DEADAIR_KIBANA_URL)
  --opensearch-url URL        OpenSearch URL (DEADAIR_OPENSEARCH_URL)
  --api-key-file FILE         read an API key from FILE
  --ca-cert FILE              trust the PEM certificate authority in FILE
  --kibana-space NAME         Kibana space containing the rules
  --timeout DURATION          timeout per instance (default: 1m)
  --concurrency N             parallel backend reads (default: 4)
  --fleet FILE                scan instances listed in a fleet JSON file
  --include PATTERN           include matching sources; repeatable
  --exclude PATTERN           exclude matching sources; repeatable
  --max-stale DURATION        source freshness window (default: 30m)
  --downtime-file FILE        expected source downtime windows
  --state-file FILE           retain volume, lag, and schema history
  --schema                    track field mapping drift; requires --state-file

Run `+"`deadair scan -h`"+` for the full connection and state option list.
Guide: `+usageGuideURL+`#prometheus-exporter`)
}
