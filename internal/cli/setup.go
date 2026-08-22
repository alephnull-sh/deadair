package cli

import (
	"flag"
	"fmt"
	"io"

	"github.com/alephnull-sh/deadair/internal/report"
)

// runSetup prints copy-paste read-only onboarding for a backend: the role,
// authentication path, and environment variables. It never touches the SIEM
// itself — the operator runs the commands with their own admin credentials.
func runSetup(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintln(stderr, `Usage: deadair setup [elastic|opensearch|sentinel]

Print the read-only role, authentication path, and environment variables
for a backend. This command does not contact the SIEM.

Credential guides:
  Elastic:    https://github.com/alephnull-sh/deadair/blob/main/docs/credentials/elastic.md
  OpenSearch: https://github.com/alephnull-sh/deadair/blob/main/docs/credentials/opensearch.md
  Sentinel:   https://github.com/alephnull-sh/deadair/blob/main/docs/credentials/sentinel.md`)
	}
	if parsed, code := parseFlags(fs, args); !parsed {
		return code
	}
	if fs.NArg() > 1 {
		fmt.Fprintf(stderr, "deadair: setup accepts one backend, got %q\n", fs.Args())
		return report.ExitError
	}
	if fs.NArg() == 0 {
		fmt.Fprint(stdout, `Choose a backend:
  deadair setup elastic      Elastic Security
  deadair setup opensearch   OpenSearch Security Analytics
  deadair setup sentinel     Microsoft Sentinel
`)
		return report.ExitHealthy
	}
	backend := fs.Arg(0)
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
	case "sentinel":
		fmt.Fprint(stdout, `# deadair setup — Microsoft Sentinel (read-only)
# 1. Sign in locally and select the subscription. In CI, DefaultAzureCredential
#    also supports workload identity, managed identity, and service principals.
az login --tenant <tenant-id>
az account set --subscription <subscription-id>

# 2. For a simple setup, give that identity Microsoft Sentinel Reader and
#    Log Analytics Reader on the workspace (or an enclosing resource group).
#    These convenient built-ins are broader than the feature-specific custom-
#    role operations in the credential guide. deadair reads analytics rules and
#    table metadata, then runs bounded read-only Logs queries.

# 3. Identify the workspace. deadair discovers its Log Analytics customer ID
#    through ARM.
export DEADAIR_BACKEND=sentinel
export DEADAIR_AZURE_SUBSCRIPTION_ID=<subscription-id>
export DEADAIR_AZURE_RESOURCE_GROUP=<resource-group>
export DEADAIR_SENTINEL_WORKSPACE=<workspace-resource-name>

# Optional customer-ID override. deadair still verifies it through ARM:
# export DEADAIR_SENTINEL_WORKSPACE_ID=<log-analytics-customer-id>

# Optional literal workspace() mappings. The identity needs workspace/table ARM
# reads, Microsoft.SecurityInsights/onboardingStates/read, and Logs query access
# on each remote; it does not need remote rule inventory for this path. Save a
# JSON array with alias,
# azure_subscription_id, azure_resource_group, sentinel_workspace, and optional
# sentinel_workspace_id, then set:
# export DEADAIR_SENTINEL_REMOTES=/path/to/sentinel-remotes.json

# 4. Verify, then scan:
deadair check
deadair scan

# Least-privilege role and cross-workspace setup:
# https://github.com/alephnull-sh/deadair/blob/main/docs/credentials/sentinel.md
# Evidence boundaries and current limits:
# https://github.com/alephnull-sh/deadair/blob/main/docs/usage.md#microsoft-sentinel
`)
		return report.ExitHealthy
	default:
		fmt.Fprintf(stderr, "deadair: unknown backend %q (want elastic, opensearch, or sentinel)\n", backend)
		return report.ExitError
	}
}
