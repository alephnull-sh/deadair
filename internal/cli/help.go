package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/alephnull-sh/deadair/internal/report"
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

Run a live, read-only assessment. Exit 0 passes the configured gate, 1 means
gated findings, and 2 means the scan could not complete.

Connection:
  --backend NAME              elastic, opensearch, or sentinel (default: elastic)
  --es-url URL                Elasticsearch URL (DEADAIR_ES_URL)
  --kibana-url URL            Kibana URL (DEADAIR_KIBANA_URL)
  --opensearch-url URL        OpenSearch URL (DEADAIR_OPENSEARCH_URL)
  --azure-subscription ID     Azure subscription (DEADAIR_AZURE_SUBSCRIPTION_ID)
  --azure-resource-group NAME Azure resource group (DEADAIR_AZURE_RESOURCE_GROUP)
  --sentinel-workspace NAME   Log Analytics workspace name (DEADAIR_SENTINEL_WORKSPACE)
  --sentinel-workspace-id ID  optional customer ID override (normally discovered through ARM)
  --sentinel-remotes FILE     JSON mappings for literal workspace() targets
                              (DEADAIR_SENTINEL_REMOTES)
                              Sentinel authentication uses DefaultAzureCredential
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
  --redact                    replace names with HMAC pseudonyms
  --redact-key-file FILE      HMAC key for stable cross-run pseudonyms
                              (DEADAIR_REDACT_KEY_FILE)

Scope:
  --include PATTERN           include matching sources; repeatable
  --exclude PATTERN           exclude matching sources; repeatable
  --max-stale DURATION        source freshness window (default: 30m)
  --downtime-file FILE        expected source downtime windows
  --policy FILE               local freshness, acceptance, and gate policy
  --rule FILE                 evaluate one backend-native candidate file

Fleet:
  --fleet FILE                scan instances listed in a fleet JSON file
  --instance-name NAME        label a single instance in reports

Stateful checks:
  --state-file FILE           retain volume, schema, and finding history
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

Sentinel checks the core Scheduled/NRT rule, table, query, and explicitly mapped
literal workspace() paths, including required remote Sentinel onboarding.
Optional summary-lineage and Content Hub reads are scan enrichment and are not
required for readiness.

Connection:
  --backend NAME              elastic, opensearch, or sentinel (default: elastic)
  --es-url URL                Elasticsearch URL (DEADAIR_ES_URL)
  --kibana-url URL            Kibana URL (DEADAIR_KIBANA_URL)
  --opensearch-url URL        OpenSearch URL (DEADAIR_OPENSEARCH_URL)
  --azure-subscription ID     Azure subscription (DEADAIR_AZURE_SUBSCRIPTION_ID)
  --azure-resource-group NAME Azure resource group (DEADAIR_AZURE_RESOURCE_GROUP)
  --sentinel-workspace NAME   Log Analytics workspace name (DEADAIR_SENTINEL_WORKSPACE)
  --sentinel-workspace-id ID  optional customer ID override (normally discovered through ARM)
  --sentinel-remotes FILE     JSON mappings for literal workspace() targets
                              (DEADAIR_SENTINEL_REMOTES)
                              Sentinel authentication uses DefaultAzureCredential
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

Guide: `+usageGuideURL+`#gate-detection-changes`)
}

func tuneUsage(w io.Writer) {
	fmt.Fprintln(w, `Usage: deadair tune --state-file FILE [options]

Suggest volume-baseline settings from accumulated local state.

  --state-file FILE  state file to summarize
  --json             print the tuning summary as JSON
  --redact           replace source names with HMAC pseudonyms
  --redact-key-file FILE
                     HMAC key for stable cross-run pseudonyms

Guide: `+usageGuideURL+`#add-history-based-checks`)
}

func serveUsage(w io.Writer) {
	fmt.Fprintln(w, `Usage: deadair serve [options]

Run periodic live scans and expose the latest result as Prometheus metrics.

Exporter:
  --bind ADDRESS              listen address (default: 127.0.0.1:9317)
  --interval DURATION         time between scans (default: 5m)
  --redact                    replace metric-label names with HMAC pseudonyms
  --redact-key-file FILE      HMAC key for stable cross-run pseudonyms

Connection and scan:
  --backend NAME              elastic, opensearch, or sentinel (default: elastic)
  --es-url URL                Elasticsearch URL (DEADAIR_ES_URL)
  --kibana-url URL            Kibana URL (DEADAIR_KIBANA_URL)
  --opensearch-url URL        OpenSearch URL (DEADAIR_OPENSEARCH_URL)
  --azure-subscription ID     Azure subscription (DEADAIR_AZURE_SUBSCRIPTION_ID)
  --azure-resource-group NAME Azure resource group (DEADAIR_AZURE_RESOURCE_GROUP)
  --sentinel-workspace NAME   Log Analytics workspace name (DEADAIR_SENTINEL_WORKSPACE)
  --sentinel-workspace-id ID  optional customer ID override (normally discovered through ARM)
  --sentinel-remotes FILE     JSON mappings for literal workspace() targets
                              (DEADAIR_SENTINEL_REMOTES)
                              Sentinel authentication uses DefaultAzureCredential
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
  --policy FILE               local freshness, acceptance, and gate policy
  --state-file FILE           retain volume, schema, and finding history
  --schema                    track field mapping drift; requires --state-file

Run `+"`deadair scan -h`"+` for the full connection and state option list.
Guide: `+usageGuideURL+`#run-the-exporter`)
}
