package cli

import (
	"flag"
	"fmt"
	"io"

	"github.com/alephnull-sh/deadair/internal/report"
)

// runSetup prints copy-paste least-privilege onboarding for a backend: the
// role, the key mint, the env exports. It never touches the SIEM itself —
// the operator runs the commands with their own admin credentials.
func runSetup(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintln(stderr, `Usage: deadair setup [elastic|opensearch]

Print the least-privilege role, credential command, and environment variables
for a backend. This command does not contact the SIEM.

Credential guides:
  Elastic:    https://github.com/alephnull-sh/deadair/blob/main/docs/credentials/elastic.md
  OpenSearch: https://github.com/alephnull-sh/deadair/blob/main/docs/credentials/opensearch.md`)
	}
	if parsed, code := parseFlags(fs, args); !parsed {
		return code
	}
	if fs.NArg() > 1 {
		fmt.Fprintf(stderr, "deadair: setup accepts one backend, got %q\n", fs.Args())
		return report.ExitError
	}
	backend := "elastic"
	if fs.NArg() == 1 {
		backend = fs.Arg(0)
	}
	switch backend {
	case "elastic":
		fmt.Fprint(stdout, `# deadair setup — Elastic (least privilege, read-only)
# 1. Create the role and API key (run with an admin credential):
curl -u elastic -X POST "$ES_URL/_security/api_key" -H 'Content-Type: application/json' -d '{
  "name": "deadair",
  "role_descriptors": { "deadair_monitor": {
    "cluster": ["monitor"],
    "indices": [{ "names": ["*"], "privileges": ["monitor", "view_index_metadata", "read"] }],
    "applications": [{ "application": "kibana-.kibana",
	      "privileges": ["feature_siem.read", "feature_siemV2.read", "feature_indexPatterns.read"], "resources": ["space:default"] }]
  }}}'

# 2. Point deadair at the deployment (use "encoded" from the response):
export DEADAIR_ES_URL=https://your-es:9200
export DEADAIR_KIBANA_URL=https://your-kibana:5601
export DEADAIR_API_KEY=<encoded>

# 3. Verify, then scan:
deadair check
deadair scan

# Details and tighter scoping:
# https://github.com/alephnull-sh/deadair/blob/main/docs/credentials/elastic.md
`)
		return report.ExitHealthy
	case "opensearch":
		fmt.Fprint(stdout, `# deadair setup — OpenSearch (least privilege, read-only)
# 1. Create a read-only user and map it (run as admin):
#    roles: security_analytics_read_access + a role with cluster_monitor and
#    indices monitor/read on your telemetry patterns.
#    Full role JSON:
#    https://github.com/alephnull-sh/deadair/blob/main/docs/credentials/opensearch.md

# 2. Point deadair at the deployment:
export DEADAIR_BACKEND=opensearch
export DEADAIR_OPENSEARCH_URL=https://your-opensearch:9200
export DEADAIR_OPENSEARCH_USERNAME=deadair
export DEADAIR_OPENSEARCH_PASSWORD=<password>   # or --opensearch-password-file

# 3. Verify, then scan:
deadair check
deadair scan
`)
		return report.ExitHealthy
	default:
		fmt.Fprintf(stderr, "deadair: unknown backend %q (want elastic or opensearch)\n", backend)
		return report.ExitError
	}
}
