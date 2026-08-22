#!/bin/sh
set -eu

# Prepares only the disposable fixtures added by the Sentinel expansion test.
# The default mode is plan. apply and cleanup require an explicit confirmation
# value and always target the named child resources below.

mode=${1:-plan}
subscription_id=${DEADAIR_AZURE_SUBSCRIPTION_ID:-}
resource_group=${DEADAIR_AZURE_RESOURCE_GROUP:-deadair-sentinel-lab}
workspace=${DEADAIR_SENTINEL_WORKSPACE:-deadair-sentinel-lab}
remote_workspace=${DEADAIR_SENTINEL_REMOTE_WORKSPACE:-deadair-sentinel-remote}
remote_workspace_id_env=${DEADAIR_SENTINEL_REMOTE_WORKSPACE_ID:-}
confirmation=${DEADAIR_SENTINEL_LAB_CONFIRM:-}

watchlist_alias=DeadairVIPs
watchlist_source=deadair-sentinel-expansion-fixture.csv
remote_table=DeadairRemote_CL
summary_rule=deadair-basic-summary
summary_table=DeadairBasicSummary_CL
summary_display=deadair-basic-summary
summary_query='DeadairBasic_CL | summarize EventCount=count() by Marker'
fixture_marker=deadair-sentinel-expansion-validation
base_fixture_marker=deadair-sentinel-base-validation
summary_table_description="$fixture_marker:$summary_table"
nrt_rule_id=78888888-8888-4888-8888-888888888888
nrt_display='deadair lab - nrt dependency'
nrt_description='Disposable deadair Sentinel conformance rule.'
nrt_query='DeadairFresh_CL | where TimeGenerated < datetime(1900-01-01)'
nrt_suppression=PT1H
base_function=DeadairLabSource
base_function_body='DeadairFresh_CL | project TimeGenerated, EventId, Marker'
parameterized_function=DeadairLabParameterized
parameterized_function_body='DeadairFresh_CL | where Marker == marker | project TimeGenerated, EventId, Marker'
parameterized_function_parameters=marker:string

watchlist_rule_id=79911111-1111-4111-8111-111111111111
watchlist_rule_display='deadair expansion - literal watchlist dependency'
watchlist_rule_query='_GetWatchlist("DeadairVIPs") | take 0'
asim_rule_id=79922222-2222-4222-8222-222222222222
asim_rule_display='deadair expansion - native ASIM dependency'
asim_rule_query='_Im_Authentication(starttime=ago(1d),endtime=now()) | take 0'
remote_rule_id=79933333-3333-4333-8333-333333333333
remote_rule_display='deadair expansion - remote workspace dependency'
remote_rule_query="workspace(\"$remote_workspace\").$remote_table | take 0"
summary_consumer_rule_id=79944444-4444-4444-8444-444444444444
summary_consumer_rule_display='deadair expansion - summary table consumer'
summary_consumer_rule_query="$summary_table | where TimeGenerated > ago(30m) | project TimeGenerated, Marker, EventCount"

case "$mode" in
plan|verify|apply|cleanup|predicate-test) ;;
*)
	echo "usage: $0 [plan|verify|apply|cleanup|predicate-test]" >&2
	exit 2
	;;
esac

if [ "$mode" = predicate-test ] && [ -z "$subscription_id" ]; then
	subscription_id=00000000-0000-0000-0000-000000000000
fi

if [ -z "$subscription_id" ]; then
	echo "DEADAIR_AZURE_SUBSCRIPTION_ID is required" >&2
	exit 2
fi

case "$subscription_id" in
????????-????-????-????-????????????) ;;
*)
	echo "DEADAIR_AZURE_SUBSCRIPTION_ID must be a UUID" >&2
	exit 2
	;;
esac
case "$subscription_id" in
*[!0-9A-Fa-f-]*)
	echo "DEADAIR_AZURE_SUBSCRIPTION_ID must be a UUID" >&2
	exit 2
	;;
esac
case "$resource_group" in
""|*[!A-Za-z0-9_.-]*)
	echo "DEADAIR_AZURE_RESOURCE_GROUP contains unsupported characters" >&2
	exit 2
	;;
esac
if [ "$mode" != predicate-test ]; then
	for workspace_name in "$workspace" "$remote_workspace"; do
		workspace_length=${#workspace_name}
		if [ "$workspace_length" -lt 4 ] || [ "$workspace_length" -gt 63 ]; then
			echo "workspace names must contain 4 to 63 characters" >&2
			exit 2
		fi
		case "$workspace_name" in
		*[!A-Za-z0-9-]*)
			echo "workspace names must contain only letters, numbers, and hyphens" >&2
			exit 2
			;;
		esac
		case "$workspace_name" in
		[!A-Za-z0-9]*|*[!A-Za-z0-9])
			echo "workspace names must begin and end with a letter or number" >&2
			exit 2
			;;
		esac
	done
	workspace_key=$(printf '%s' "$workspace" | tr '[:upper:]' '[:lower:]')
	remote_workspace_key=$(printf '%s' "$remote_workspace" | tr '[:upper:]' '[:lower:]')
	if [ "$workspace_key" = "$remote_workspace_key" ]; then
		echo "DEADAIR_SENTINEL_REMOTE_WORKSPACE must differ from DEADAIR_SENTINEL_WORKSPACE" >&2
		exit 2
	fi
fi

workspace_path="/subscriptions/$subscription_id/resourceGroups/$resource_group/providers/Microsoft.OperationalInsights/workspaces/$workspace"
remote_path="/subscriptions/$subscription_id/resourceGroups/$resource_group/providers/Microsoft.OperationalInsights/workspaces/$remote_workspace"
remote_onboarding_path="$remote_path/providers/Microsoft.SecurityInsights/onboardingStates/default"
watchlist_path="$workspace_path/providers/Microsoft.SecurityInsights/watchlists/$watchlist_alias"
summary_path="$workspace_path/summaryLogs/$summary_rule"
summary_table_path="$workspace_path/tables/$summary_table"
remote_table_path="$remote_path/tables/$remote_table"
sentinel_path="$workspace_path/providers/Microsoft.SecurityInsights"

watchlist_uri="https://management.azure.com$watchlist_path?api-version=2025-09-01"
summary_uri="https://management.azure.com$summary_path?api-version=2025-07-01"
summary_table_uri="https://management.azure.com$summary_table_path?api-version=2025-07-01"
remote_uri="https://management.azure.com$remote_path?api-version=2025-07-01"
remote_onboarding_uri="https://management.azure.com$remote_onboarding_path?api-version=2025-09-01"
remote_table_uri="https://management.azure.com$remote_table_path?api-version=2025-07-01"
watchlist_collection_uri="https://management.azure.com$workspace_path/providers/Microsoft.SecurityInsights/watchlists?api-version=2025-09-01"
summary_collection_uri="https://management.azure.com$workspace_path/summaryLogs?api-version=2025-07-01"
table_collection_uri="https://management.azure.com$workspace_path/tables?api-version=2025-07-01"
workspace_collection_uri="https://management.azure.com/subscriptions/$subscription_id/resourceGroups/$resource_group/providers/Microsoft.OperationalInsights/workspaces?api-version=2025-07-01"
alert_rule_collection_uri="https://management.azure.com$workspace_path/providers/Microsoft.SecurityInsights/alertRules?api-version=2025-09-01"
alert_rule_preview_collection_uri="https://management.azure.com$workspace_path/providers/Microsoft.SecurityInsights/alertRules?api-version=2025-10-01-preview"

remote_onboarding_matches() {
	printf '%s' "$1" | jq -e --arg id "$remote_onboarding_path" '
		(.name == "default") and
		(((.id // "") | ascii_downcase) == ($id | ascii_downcase)) and
		(((.type // "") | ascii_downcase) == "microsoft.securityinsights/onboardingstates") and
		(if (.properties | type) == "object" then
			(((.properties | has("customerManagedKey")) | not) or
				.properties.customerManagedKey == false)
		else false end)' >/dev/null
}

watchlist_matches() {
	printf '%s' "$1" | jq -e \
		--arg id "$watchlist_path" --arg alias "$watchlist_alias" \
		--arg marker "$fixture_marker" --arg source "$watchlist_source" '
		(((.id // "") | ascii_downcase) == ($id | ascii_downcase)) and
		(.name == $alias) and
		(((.type // "") | ascii_downcase) == "microsoft.securityinsights/watchlists") and
		(if (.properties | type) == "object" then
			(.properties.watchlistAlias == $alias) and
			(.properties.displayName == "deadair expansion validation VIPs") and
			(.properties.provider == "deadair") and
			(.properties.source == $source) and
			(.properties.sourceType == "Local") and
			(.properties.description == $marker) and
			(.properties.itemsSearchKey == "FixtureID") and
			(((.properties | has("contentType")) | not) or
				.properties.contentType == "text/csv") and
			(.properties.isDeleted == false)
		else false end)' >/dev/null
}

summary_table_matches() {
	printf '%s' "$1" | jq -e \
		--arg id "$summary_table_path" --arg table "$summary_table" \
		--arg description "$summary_table_description" '
		(((.id // "") | ascii_downcase) == ($id | ascii_downcase)) and
		(.name == $table) and
		(.properties.plan == "Analytics") and
		(.properties.schema.name == $table) and
		(.properties.schema.description == $description) and
		([.properties.schema.columns[]?] | length) == 3 and
		(any(.properties.schema.columns[]?; .name == "TimeGenerated" and (.type | ascii_downcase) == "datetime")) and
		(any(.properties.schema.columns[]?; .name == "EventCount" and .type == "long")) and
		(any(.properties.schema.columns[]?; .name == "Marker" and .type == "string"))' >/dev/null
}

expect_predicate_accepts() {
	label=$1
	predicate=$2
	resource=$3
	if ! "$predicate" "$resource"; then
		echo "predicate regression: $label was rejected" >&2
		return 1
	fi
}

expect_predicate_rejects() {
	label=$1
	predicate=$2
	resource=$3
	if "$predicate" "$resource"; then
		echo "predicate regression: $label was accepted" >&2
		return 1
	fi
}

run_predicate_tests() {
	onboarding=$(jq -cn --arg id "$remote_onboarding_path" '{
		id: $id, name: "default", type: "Microsoft.SecurityInsights/onboardingStates", properties: {}
	}')
	expect_predicate_accepts "onboarding state with omitted CMK" remote_onboarding_matches "$onboarding"
	expect_predicate_accepts "onboarding state with false CMK" remote_onboarding_matches \
		"$(printf '%s' "$onboarding" | jq -c '.properties.customerManagedKey = false')"
	expect_predicate_rejects "onboarding state with true CMK" remote_onboarding_matches \
		"$(printf '%s' "$onboarding" | jq -c '.properties.customerManagedKey = true')"
	expect_predicate_rejects "onboarding state with null CMK" remote_onboarding_matches \
		"$(printf '%s' "$onboarding" | jq -c '.properties.customerManagedKey = null')"
	expect_predicate_rejects "onboarding state without properties" remote_onboarding_matches \
		"$(printf '%s' "$onboarding" | jq -c 'del(.properties)')"
	expect_predicate_rejects "onboarding state with null properties" remote_onboarding_matches \
		"$(printf '%s' "$onboarding" | jq -c '.properties = null')"

	watchlist=$(jq -cn \
		--arg id "$watchlist_path" --arg alias "$watchlist_alias" \
		--arg marker "$fixture_marker" --arg source "$watchlist_source" '{
		id: $id, name: $alias, type: "Microsoft.SecurityInsights/watchlists",
		properties: {
			watchlistAlias: $alias, displayName: "deadair expansion validation VIPs",
			provider: "deadair", source: $source, sourceType: "Local", description: $marker,
			itemsSearchKey: "FixtureID", isDeleted: false
		}
	}')
	expect_predicate_accepts "watchlist with omitted contentType" watchlist_matches "$watchlist"
	expect_predicate_accepts "watchlist with exact contentType" watchlist_matches \
		"$(printf '%s' "$watchlist" | jq -c '.properties.contentType = "text/csv"')"
	expect_predicate_rejects "watchlist with null contentType" watchlist_matches \
		"$(printf '%s' "$watchlist" | jq -c '.properties.contentType = null')"
	expect_predicate_rejects "watchlist with false contentType" watchlist_matches \
		"$(printf '%s' "$watchlist" | jq -c '.properties.contentType = false')"
	expect_predicate_rejects "watchlist with wrong contentType" watchlist_matches \
		"$(printf '%s' "$watchlist" | jq -c '.properties.contentType = "application/json"')"

	summary=$(jq -cn \
		--arg id "$summary_table_path" --arg table "$summary_table" \
		--arg description "$summary_table_description" '{
		id: $id, name: $table,
		properties: {
			plan: "Analytics",
			schema: {
				name: $table, description: $description,
				columns: [
					{name: "TimeGenerated", type: "dateTime"},
					{name: "EventCount", type: "long"},
					{name: "Marker", type: "string"}
				]
			}
		}
	}')
	expect_predicate_accepts "summary table with exact schema" summary_table_matches "$summary"
	expect_predicate_rejects "summary table with an extra column" summary_table_matches \
		"$(printf '%s' "$summary" | jq -c '.properties.schema.columns += [{name: "Extra", type: "string"}]')"
	expect_predicate_rejects "summary table with a wrong column type" summary_table_matches \
		"$(printf '%s' "$summary" | jq -c '(.properties.schema.columns[] | select(.name == "EventCount")).type = "string"')"

	echo "Sentinel expansion ownership predicate tests passed"
}

if [ "$mode" = predicate-test ]; then
	if ! command -v jq >/dev/null 2>&1; then
		echo "jq is required" >&2
		exit 2
	fi
	run_predicate_tests
	exit 0
fi

print_plan() {
	test_remote_id=
	if [ -n "$remote_workspace_id_env" ]; then
		test_remote_id=" DEADAIR_SENTINEL_REMOTE_WORKSPACE_ID=$remote_workspace_id_env"
	fi
	echo "Sentinel expansion fixture plan (no Azure changes):"
	echo "  subscription: $subscription_id"
	echo "  home workspace: $workspace_path"
	echo "  PUT/DELETE watchlist: $watchlist_path"
	echo "  PUT/DELETE remote workspace: $remote_path"
	echo "  PUT remote Sentinel onboarding state: $remote_onboarding_path"
	echo "  PUT remote table: $remote_table_path"
	echo "  VERIFY ONLY existing disabled NRT rule: $nrt_rule_id"
	echo "  PUT/DELETE summary rule: $summary_path"
	echo "  PUT/DELETE owned summary destination: $summary_table_path"
	echo "  PUT/DELETE four disabled expansion analytics rules under: $sentinel_path/alertRules"
	echo "  confirmation for apply/cleanup: DEADAIR_SENTINEL_LAB_CONFIRM=$fixture_marker"
	echo
	echo "Run the read-only test with:"
	echo "  require certificate EnvironmentCredential variables and matching DEADAIR_SENTINEL_SCANNER_CLIENT_ID"
	echo "  DEADAIR_IT_SENTINEL=1 DEADAIR_AZURE_SUBSCRIPTION_ID=$subscription_id DEADAIR_AZURE_RESOURCE_GROUP=$resource_group DEADAIR_SENTINEL_WORKSPACE=$workspace DEADAIR_SENTINEL_REMOTE_WORKSPACE=$remote_workspace$test_remote_id go test -tags=integration ./integration -run '^TestSentinelReadOnlyLab$' -v"
	echo "  DEADAIR_IT_SENTINEL_WRITE_DENIALS=1 DEADAIR_AZURE_SUBSCRIPTION_ID=$subscription_id DEADAIR_AZURE_RESOURCE_GROUP=$resource_group DEADAIR_SENTINEL_WORKSPACE=$workspace go test -tags=integration ./integration -run '^TestSentinelWriteDenials$' -v"
	echo "  apply prints DEADAIR_SENTINEL_REMOTE_WORKSPACE_ID after Azure assigns it"
}

if { [ "$mode" = apply ] || [ "$mode" = cleanup ]; } && [ "$confirmation" != "$fixture_marker" ]; then
	echo "refusing $mode: set DEADAIR_SENTINEL_LAB_CONFIRM=$fixture_marker" >&2
	exit 2
fi

for command_name in az jq; do
	if ! command -v "$command_name" >/dev/null 2>&1; then
		echo "$command_name is required" >&2
		exit 2
	fi
done

active_subscription=$(az account show --query id --output tsv)
if [ "$active_subscription" != "$subscription_id" ]; then
	echo "active Azure subscription $active_subscription does not match $subscription_id" >&2
	exit 2
fi

collection_resource() {
	label=$1
	target=$2
	resource_name=$3
	page=0
	found=
	while [ -n "$target" ]; do
		case "$target" in
		https://management.azure.com/*) ;;
		*)
			echo "$label inventory returned an unexpected nextLink" >&2
			return 2
			;;
		esac
		if ! response=$(az rest --only-show-errors --method get --uri "$target" --output json); then
			echo "$label inventory could not be read" >&2
			return 2
		fi
		count=$(printf '%s' "$response" |
			jq --arg name "$resource_name" '[.value[] | select(((.name // "") | ascii_downcase) == ($name | ascii_downcase))] | length')
		if [ "$count" -gt 1 ] || { [ "$count" -eq 1 ] && [ -n "$found" ]; }; then
			echo "$label inventory returned duplicate resources" >&2
			return 2
		fi
		if [ "$count" -eq 1 ]; then
			found=$(printf '%s' "$response" |
				jq -c --arg name "$resource_name" '.value[] | select(((.name // "") | ascii_downcase) == ($name | ascii_downcase))')
		fi
		target=$(printf '%s' "$response" | jq -r '.nextLink // empty')
		page=$((page + 1))
		if [ "$page" -gt 1000 ]; then
			echo "$label inventory exceeded 1000 pages" >&2
			return 2
		fi
	done
	printf '%s' "$found"
}

require_collection_absent() {
	label=$1
	target=$2
	resource_name=$3
	resource=$(collection_resource "$label" "$target" "$resource_name")
	if [ -n "$resource" ]; then
		echo "refusing apply: $label already exists" >&2
		echo "If this is an interrupted owned run, inspect it and run cleanup with the explicit confirmation before retrying apply." >&2
		exit 2
	fi
}

expansion_rule_uri() {
	printf 'https://management.azure.com%s/alertRules/%s?api-version=2025-09-01' "$sentinel_path" "$1"
}

expansion_rule_matches() {
	rule_resource=$1
	rule_id=$2
	rule_display=$3
	rule_query=$4
	printf '%s' "$rule_resource" | jq -e \
		--arg id "$sentinel_path/alertRules/$rule_id" --arg name "$rule_id" \
		--arg marker "$fixture_marker" --arg display "$rule_display" --arg query "$rule_query" '
		(((.id // "") | ascii_downcase) == ($id | ascii_downcase)) and
		(.name == $name) and .kind == "Scheduled" and
		.properties.displayName == $display and .properties.description == $marker and
		.properties.enabled == false and .properties.severity == "Low" and
		.properties.query == $query and .properties.queryFrequency == "PT5M" and
		.properties.queryPeriod == "PT30M" and
		.properties.triggerOperator == "GreaterThan" and .properties.triggerThreshold == 10000 and
		.properties.suppressionDuration == "PT1H" and .properties.suppressionEnabled == false and
		.properties.incidentConfiguration.createIncident == false and
		((.properties.provisioningState // "Succeeded") == "Succeeded")' >/dev/null
}

wait_for_expansion_rule() {
	rule_id=$1
	rule_display=$2
	rule_query=$3
	rule_target=$(expansion_rule_uri "$rule_id")
	rule_attempt=0
	while [ "$rule_attempt" -lt 60 ]; do
		if rule_resource=$(az rest --only-show-errors --method get --uri "$rule_target" --output json 2>/dev/null) && \
			expansion_rule_matches "$rule_resource" "$rule_id" "$rule_display" "$rule_query"; then
			return 0
		fi
		rule_attempt=$((rule_attempt + 1))
		sleep 5
	done
	echo "disabled expansion rule $rule_id did not become readable with its exact definition" >&2
	return 1
}

create_expansion_rule() {
	rule_id=$1
	rule_display=$2
	rule_query=$3
	jq -n --arg display "$rule_display" --arg description "$fixture_marker" --arg query "$rule_query" '{
		kind: "Scheduled",
		properties: {
			displayName: $display, description: $description, enabled: false, severity: "Low",
			query: $query, queryFrequency: "PT5M", queryPeriod: "PT30M",
			triggerOperator: "GreaterThan", triggerThreshold: 10000,
			suppressionDuration: "PT1H", suppressionEnabled: false,
			incidentConfiguration: {createIncident: false},
			eventGroupingSettings: {aggregationKind: "SingleAlert"}
		}
	}' >"$tmp_dir/rule-$rule_id.json"
	az rest --only-show-errors --method put --uri "$(expansion_rule_uri "$rule_id")" \
		--body "@$tmp_dir/rule-$rule_id.json" --output none
	wait_for_expansion_rule "$rule_id" "$rule_display" "$rule_query"
}

wait_for_value() {
	uri=$1
	query=$2
	want=$3
	label=$4
	attempt=0
	while [ "$attempt" -lt 60 ]; do
		value=$(az rest --only-show-errors --method get --uri "$uri" --query "$query" --output tsv 2>/dev/null || true)
		if [ "$value" = "$want" ]; then
			return 0
		fi
		attempt=$((attempt + 1))
		sleep 5
	done
	echo "$label did not reach $query=$want" >&2
	return 1
}

wait_for_nonempty() {
	uri=$1
	query=$2
	label=$3
	attempt=0
	while [ "$attempt" -lt 60 ]; do
		value=$(az rest --only-show-errors --method get --uri "$uri" --query "$query" --output tsv 2>/dev/null || true)
		if [ -n "$value" ]; then
			return 0
		fi
		attempt=$((attempt + 1))
		sleep 5
	done
	echo "$label did not expose $query" >&2
	return 1
}

wait_for_collection_absence() {
	collection_uri=$1
	resource_name=$2
	label=$3
	attempt=0
	while [ "$attempt" -lt 60 ]; do
		resource=$(collection_resource "$label" "$collection_uri" "$resource_name")
		if [ -z "$resource" ]; then
			return 0
		fi
		attempt=$((attempt + 1))
		sleep 5
	done
	echo "$label was not deleted" >&2
	return 1
}

wait_for_watchlist_ready() {
	uri=$1
	label=$2
	attempt=0
	last_provisioning=
	last_upload=
	while [ "$attempt" -lt 60 ]; do
		if ! resource=$(az rest --only-show-errors --method get --uri "$uri" --output json); then
			echo "$label could not be read while waiting for lifecycle completion" >&2
			return 1
		fi
		last_provisioning=$(printf '%s' "$resource" | jq -r '.properties.provisioningState // empty')
		last_upload=$(printf '%s' "$resource" | jq -r '.properties.uploadStatus // empty')
		case "$last_provisioning" in
		""|Succeeded) provisioning_ready=true ;;
		Failed|Canceled)
			echo "$label reached provisioningState=$last_provisioning" >&2
			return 1
			;;
		*) provisioning_ready=false ;;
		esac
		case "$last_upload" in
		""|Complete|Succeeded) upload_ready=true ;;
		Failed|Canceled)
			echo "$label reached uploadStatus=$last_upload" >&2
			return 1
			;;
		*) upload_ready=false ;;
		esac
		if [ "$provisioning_ready" = true ] && [ "$upload_ready" = true ]; then
			return 0
		fi
		attempt=$((attempt + 1))
		sleep 5
	done
	echo "$label lifecycle did not settle (provisioningState=${last_provisioning:-omitted}, uploadStatus=${last_upload:-omitted})" >&2
	return 1
}

require_watchlist_settled() {
	resource=$1
	label=$2
	provisioning=$(printf '%s' "$resource" | jq -r '.properties.provisioningState // empty')
	upload=$(printf '%s' "$resource" | jq -r '.properties.uploadStatus // empty')
	case "$provisioning" in
	""|Succeeded|Failed|Canceled) ;;
	*)
		echo "refusing cleanup: $label has provisioningState=$provisioning" >&2
		exit 2
		;;
	esac
	case "$upload" in
	""|Complete|Succeeded|Failed|Canceled) ;;
	*)
		echo "refusing cleanup: $label has uploadStatus=$upload" >&2
		exit 2
		;;
	esac
}

prerequisite_issues=
base_tables_ready=true

add_prerequisite_issue() {
	prerequisite_issues="$prerequisite_issues
  - $1"
}

verify_base_table() {
	name=$1
	want_plan=$2
	want_shape=$3
	resource=$(collection_resource "base table $name" "$table_collection_uri" "$name")
	if [ -z "$resource" ]; then
		add_prerequisite_issue "missing base table $name (plan $want_plan, $want_shape-column schema)"
		base_tables_ready=false
		return
	fi
	table_exact=$(printf '%s' "$resource" | jq -r \
		--arg marker "$base_fixture_marker" --arg name "$name" --arg plan "$want_plan" --arg shape "$want_shape" '
		.properties.provisioningState == "Succeeded" and
		.properties.schema.description == $marker and .properties.plan == $plan and
		((.properties.schema.name // .name) | ascii_downcase) == ($name | ascii_downcase) and
		(if $shape == "four" then
			([.properties.schema.columns[]?] | length) == 4 and
			any(.properties.schema.columns[]?; .name == "TimeGenerated" and (.type | ascii_downcase) == "datetime") and
			any(.properties.schema.columns[]?; .name == "EventId" and (.type | ascii_downcase) == "string") and
			any(.properties.schema.columns[]?; .name == "Marker" and (.type | ascii_downcase) == "string") and
			any(.properties.schema.columns[]?; .name == "ExpectedField" and (.type | ascii_downcase) == "string")
		else
			([.properties.schema.columns[]?] | length) == 2 and
			any(.properties.schema.columns[]?; .name == "TimeGenerated" and (.type | ascii_downcase) == "datetime") and
			any(.properties.schema.columns[]?; .name == "Marker" and (.type | ascii_downcase) == "string")
		end)')
	if [ "$table_exact" != true ]; then
		add_prerequisite_issue "base table $name does not match plan $want_plan and its exact owned $want_shape-column schema"
		base_tables_ready=false
	fi
}

verify_base_rule() {
	id=$1
	want_display=$2
	want_query=$3
	want_frequency=$4
	want_period=$5
	resource=$(collection_resource "base alert rule $id" "$alert_rule_collection_uri" "$id")
	if [ -z "$resource" ]; then
		add_prerequisite_issue "missing exact Scheduled base alert rule $id in the GA inventory"
		return
	fi
	exact=$(printf '%s' "$resource" | jq -r \
		--arg display "$want_display" --arg description "$nrt_description" \
		--arg query "$want_query" --arg frequency "$want_frequency" --arg period "$want_period" \
		--arg suppression "$nrt_suppression" '
		(.kind == "Scheduled") and
		(.properties.displayName == $display) and
		(.properties.description == $description) and
		(.properties.enabled == true) and
		(.properties.severity == "Low") and
		(.properties.query == $query) and
		(.properties.queryFrequency == $frequency) and
		(.properties.queryPeriod == $period) and
		(.properties.suppressionDuration == $suppression) and
		(.properties.suppressionEnabled == false) and
		(.properties.triggerOperator == "GreaterThan") and
		(.properties.triggerThreshold == 10000) and
		(.properties.incidentConfiguration.createIncident == false) and
		((.properties.provisioningState // "Succeeded") == "Succeeded")')
	if [ "$exact" != true ]; then
		add_prerequisite_issue "Scheduled base alert rule $id does not match its exact read-only fixture definition"
	fi
}

verify_base_data() {
	base_data_query='union
(DeadairFresh_CL | where ingestion_time() >= ago(24h) and TimeGenerated >= ago(24h) | extend IngestedAt=ingestion_time() | summarize RowCount=count(), arg_max(IngestedAt, TimeGenerated, EventId, Marker, ExpectedField) | project Source="Fresh", RowCount, EventIDPresent=isnotempty(EventId), MarkerPresent=isnotempty(Marker), ExpectedFieldPresent=isnotempty(ExpectedField), Paired=isnotnull(TimeGenerated) and isnotnull(IngestedAt), LagSeconds=datetime_diff("second", IngestedAt, TimeGenerated)),
(DeadairLag_CL | where ingestion_time() >= ago(24h) and TimeGenerated >= ago(24h) | extend IngestedAt=ingestion_time() | summarize RowCount=count(), arg_max(IngestedAt, TimeGenerated, EventId, Marker, ExpectedField) | project Source="Lag", RowCount, EventIDPresent=isnotempty(EventId), MarkerPresent=isnotempty(Marker), ExpectedFieldPresent=isnotempty(ExpectedField), Paired=isnotnull(TimeGenerated) and isnotnull(IngestedAt), LagSeconds=datetime_diff("second", IngestedAt, TimeGenerated)),
(DeadairStale_CL | where ingestion_time() >= ago(24h) and TimeGenerated >= ago(24h) | extend IngestedAt=ingestion_time() | summarize RowCount=count(), arg_max(IngestedAt, TimeGenerated, EventId, Marker, ExpectedField) | project Source="Stale", RowCount, EventIDPresent=isnotempty(EventId), MarkerPresent=isnotempty(Marker), ExpectedFieldPresent=isnotempty(ExpectedField), Paired=isnotnull(TimeGenerated) and isnotnull(IngestedAt), LagSeconds=datetime_diff("second", IngestedAt, TimeGenerated)),
(DeadairUnused_CL | where ingestion_time() >= ago(24h) and TimeGenerated >= ago(24h) | extend IngestedAt=ingestion_time() | summarize RowCount=count(), arg_max(IngestedAt, TimeGenerated, EventId, Marker, ExpectedField) | project Source="Unused", RowCount, EventIDPresent=isnotempty(EventId), MarkerPresent=isnotempty(Marker), ExpectedFieldPresent=isnotempty(ExpectedField), Paired=isnotnull(TimeGenerated) and isnotnull(IngestedAt), LagSeconds=datetime_diff("second", IngestedAt, TimeGenerated))'
	base_data_body=$(jq -cn --arg query "$base_data_query" '{query: $query}')
	if ! base_data_response=$(az rest --only-show-errors --method post --resource https://api.loganalytics.io \
		--uri "https://api.loganalytics.io/v1/workspaces/$home_workspace_id/query" \
		--body "$base_data_body" --output json 2>/dev/null); then
		add_prerequisite_issue "bounded base-row aggregate could not be read through the Logs API"
		return
	fi
	if ! printf '%s' "$base_data_response" | jq -e '
		.tables[0] as $table |
		([$table.columns[]?.name] == ["Source", "RowCount", "EventIDPresent", "MarkerPresent", "ExpectedFieldPresent", "Paired", "LagSeconds"]) and
		([$table.rows[]? | {key: .[0], value: {
			count: .[1], event: .[2], marker: .[3], expected: .[4], paired: .[5], lag: .[6]
		}}] | from_entries) as $rows |
		($rows | keys | sort) == (["Fresh", "Lag", "Stale", "Unused"] | sort) and
		all($rows[]; (.count | type) == "number" and .count > 0 and
			.event == true and .marker == true and .expected == true and .paired == true and
			(.lag | type) == "number" and .lag >= 0) and
		$rows.Fresh.lag < $rows.Lag.lag and $rows.Lag.lag < $rows.Stale.lag' >/dev/null; then
		add_prerequisite_issue "bounded base-row aggregate lacks complete recent rows or Fresh < Lag < Stale paired lag ordering"
	fi
}

verify_base_prerequisites() {
	prerequisite_issues=
	base_tables_ready=true
	if ! workspace_resource=$(az rest --only-show-errors --method get \
		--uri "https://management.azure.com$workspace_path?api-version=2025-07-01" --output json); then
		echo "base-lab preflight could not read the home workspace" >&2
		exit 2
	fi
	home_workspace_id=$(printf '%s' "$workspace_resource" | jq -r '.properties.customerId // empty')
	home_workspace_provisioning=$(printf '%s' "$workspace_resource" | jq -r '.properties.provisioningState // empty')
	if [ "$home_workspace_provisioning" != Succeeded ]; then
		add_prerequisite_issue "home workspace provisioningState is ${home_workspace_provisioning:-omitted}, want Succeeded"
	fi
	if [ -z "$home_workspace_id" ]; then
		add_prerequisite_issue "home workspace customer ID is missing"
	fi

	verify_base_table DeadairFresh_CL Analytics four
	verify_base_table DeadairStale_CL Analytics four
	verify_base_table DeadairLag_CL Analytics four
	verify_base_table DeadairUnused_CL Analytics four
	verify_base_table DeadairBasic_CL Basic two
	verify_base_table DeadairAuxiliary_CL Auxiliary two
	verify_base_table DeadairEmptyAnalytics_CL Analytics two
	removed=$(collection_resource "removed-table fixture DeadairRemoved_CL" "$table_collection_uri" DeadairRemoved_CL)
	if [ -n "$removed" ]; then
		add_prerequisite_issue "removed-table fixture DeadairRemoved_CL must be absent"
	fi

	verify_base_rule 11111111-1111-4111-8111-111111111111 'deadair lab - fresh direct table' \
		'DeadairFresh_CL | where TimeGenerated > ago(30m) | project TimeGenerated, EventId, Marker, ExpectedField' PT5M PT30M
	verify_base_rule 22222222-2222-4222-8222-222222222222 'deadair lab - stale direct table' \
		'DeadairStale_CL | where TimeGenerated > ago(30m) | project TimeGenerated, EventId, Marker, ExpectedField' PT5M PT30M
	verify_base_rule 33333333-3333-4333-8333-333333333333 'deadair lab - delayed direct table' \
		'DeadairLag_CL | where TimeGenerated > ago(10m) | project TimeGenerated, EventId, Marker, ExpectedField' PT5M PT10M
	verify_base_rule 44444444-4444-4444-8444-444444444444 'deadair lab - removed direct table' \
		'DeadairRemoved_CL | where TimeGenerated > ago(30m) | project TimeGenerated, EventId, Marker, ExpectedField' PT5M PT30M
	verify_base_rule 55555555-5555-4555-8555-555555555555 'deadair lab - partial union' \
		'union isfuzzy=true DeadairFresh_CL, DeadairRemoved_CL | where TimeGenerated > ago(30m) | project TimeGenerated, EventId, Marker' PT5M PT30M
	verify_base_rule 66666666-6666-4666-8666-666666666666 'deadair lab - let and join' \
		'let recentFresh = DeadairFresh_CL | where TimeGenerated > ago(30m); recentFresh | join kind=leftouter (DeadairLag_CL | where TimeGenerated > ago(30m)) on ExpectedField | project TimeGenerated, EventId, Marker' PT5M PT30M
	verify_base_rule 71111111-1111-4111-8111-111111111111 'deadair lab - saved function bare source' \
		'DeadairLabSource | where TimeGenerated > ago(30m) | project TimeGenerated, EventId, Marker' PT5M PT30M
	verify_base_rule 72222222-2222-4222-8222-222222222222 'deadair lab - saved function call' \
		'DeadairLabSource() | where TimeGenerated > ago(30m) | project TimeGenerated, EventId, Marker' PT5M PT30M
	verify_base_rule 73333333-3333-4333-8333-333333333333 'deadair lab - parameterized function' \
		'DeadairLabParameterized("fresh") | where TimeGenerated > ago(30m) | project TimeGenerated, EventId, Marker' PT5M PT30M
	verify_base_rule 74444444-4444-4444-8444-444444444444 'deadair lab - auxiliary table dependency' \
		'DeadairAuxiliary_CL | where TimeGenerated > ago(30m) | project TimeGenerated, Marker' PT5M PT30M
	verify_base_rule 76666666-6666-4666-8666-666666666666 'deadair lab - empty analytics table' \
		'DeadairEmptyAnalytics_CL | where TimeGenerated > ago(30m) | project TimeGenerated, Marker' PT5M PT30M
	fusion=$(collection_resource "BuiltInFusion provenance rule" "$alert_rule_collection_uri" BuiltInFusion)
	if [ -z "$fusion" ]; then
		add_prerequisite_issue "missing BuiltInFusion provenance rule"
	else
		fusion_exact=$(printf '%s' "$fusion" | jq -r '
			.name == "BuiltInFusion" and .kind == "Fusion" and
			.properties.displayName == "Advanced Multistage Attack Detection" and
			.properties.enabled == true')
		if [ "$fusion_exact" != true ]; then
			add_prerequisite_issue "BuiltInFusion does not match its required kind, display name, and enabled state"
		fi
	fi

	nrt_ga=$(collection_resource "NRT base alert rule $nrt_rule_id in GA" "$alert_rule_collection_uri" "$nrt_rule_id")
	if [ -n "$nrt_ga" ]; then
		add_prerequisite_issue "NRT base alert rule $nrt_rule_id unexpectedly appears in the GA inventory"
	fi
	nrt=$(collection_resource "NRT base alert rule $nrt_rule_id" "$alert_rule_preview_collection_uri" "$nrt_rule_id")
	if [ -z "$nrt" ]; then
		add_prerequisite_issue "missing disabled NRT base alert rule $nrt_rule_id in the preview inventory"
	else
		nrt_exact=$(printf '%s' "$nrt" | jq -r \
			--arg display "$nrt_display" --arg description "$nrt_description" \
			--arg query "$nrt_query" --arg suppression "$nrt_suppression" '
			(.kind == "NRT") and
			(.properties.displayName == $display) and
			(.properties.description == $description) and
			(.properties.enabled == false) and
			(.properties.severity == "Informational") and
			(.properties.query == $query) and
			(.properties.suppressionDuration == $suppression) and
			(.properties.suppressionEnabled == false) and
			(.properties.incidentConfiguration.createIncident == false) and
			((.properties.provisioningState // "Succeeded") == "Succeeded")')
		if [ "$nrt_exact" != true ]; then
			add_prerequisite_issue "NRT base alert rule $nrt_rule_id does not match its disabled, impossible-query fixture definition"
		fi
	fi

	if [ -n "$home_workspace_id" ]; then
		if ! metadata=$(az rest --only-show-errors --method get --resource https://api.loganalytics.io \
			--uri "https://api.loganalytics.io/v1/workspaces/$home_workspace_id/metadata" --output json); then
			echo "base-lab preflight could not read Log Analytics function metadata" >&2
			exit 2
		fi
		base_matches=$(printf '%s' "$metadata" | jq --arg name "$base_function" --arg body "$base_function_body" '
			[.functions[]? | select(.name == $name and .body == $body and ((.parameters // "") == "" or .parameters == "()"))] | length')
		if [ "$base_matches" -ne 1 ]; then
			add_prerequisite_issue "$base_function metadata does not match the required body and empty parameter list"
		fi
		parameterized_matches=$(printf '%s' "$metadata" | jq \
			--arg name "$parameterized_function" --arg body "$parameterized_function_body" \
			--arg parameters "$parameterized_function_parameters" '
			[.functions[]? | select(.name == $name and .body == $body and
				((.parameters // "") == $parameters or .parameters == ("(" + $parameters + ")")))] | length')
		if [ "$parameterized_matches" -ne 1 ]; then
			add_prerequisite_issue "$parameterized_function metadata does not match the required body and marker:string parameter"
		fi
	fi
	if [ "$base_tables_ready" = true ] && [ -n "$home_workspace_id" ]; then
		verify_base_data
	fi

	if [ -n "$prerequisite_issues" ]; then
		echo "base Sentinel lab prerequisites are missing or mismatched:$prerequisite_issues" >&2
		echo "No expansion fixture writes were attempted. Repair the externally owned base lab, then rerun $0 $mode." >&2
		exit 2
	fi
	echo "base Sentinel lab prerequisites verified (read only)"
}

if [ "$mode" = plan ] || [ "$mode" = verify ] || [ "$mode" = apply ]; then
	verify_base_prerequisites
fi
if [ "$mode" = plan ]; then
	print_plan
	exit 0
fi
if [ "$mode" = verify ]; then
	echo "Sentinel base-lab verification passed; no Azure changes were made"
	exit 0
fi

tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/deadair-sentinel-expansion.XXXXXX")
trap 'rm -rf "$tmp_dir"' EXIT HUP INT TERM

if [ "$mode" = apply ]; then
	require_collection_absent "watchlist $watchlist_alias" "$watchlist_collection_uri" "$watchlist_alias"
	require_collection_absent "remote workspace $remote_workspace" "$workspace_collection_uri" "$remote_workspace"
	require_collection_absent "summary rule $summary_rule" "$summary_collection_uri" "$summary_rule"
	require_collection_absent "summary destination $summary_table" "$table_collection_uri" "$summary_table"
	require_collection_absent "watchlist dependency rule $watchlist_rule_id" "$alert_rule_collection_uri" "$watchlist_rule_id"
	require_collection_absent "ASIM dependency rule $asim_rule_id" "$alert_rule_collection_uri" "$asim_rule_id"
	require_collection_absent "remote dependency rule $remote_rule_id" "$alert_rule_collection_uri" "$remote_rule_id"
	require_collection_absent "summary consumer rule $summary_consumer_rule_id" "$alert_rule_collection_uri" "$summary_consumer_rule_id"

	location=$(az rest --only-show-errors --method get \
		--uri "https://management.azure.com$workspace_path?api-version=2025-07-01" \
		--query location --output tsv)
	if [ -z "$location" ]; then
		echo "home workspace location is unavailable" >&2
		exit 2
	fi

	jq -n --arg source "$watchlist_source" --arg marker "$fixture_marker" '{
		properties: {
			displayName: "deadair expansion validation VIPs",
			source: $source,
			sourceType: "Local",
			provider: "deadair",
			description: $marker,
			numberOfLinesToSkip: 0,
			rawContent: "FixtureID,Label\nfixture-user,deadair\n",
			itemsSearchKey: "FixtureID",
			contentType: "text/csv"
		}
	}' >"$tmp_dir/watchlist.json"
	az rest --only-show-errors --method put --uri "$watchlist_uri" \
		--body "@$tmp_dir/watchlist.json" --output none
	wait_for_value "$watchlist_uri" properties.watchlistAlias "$watchlist_alias" "watchlist $watchlist_alias"
	wait_for_nonempty "$watchlist_uri" id "watchlist $watchlist_alias"
	wait_for_value "$watchlist_uri" properties.isDeleted false "watchlist $watchlist_alias"
	wait_for_watchlist_ready "$watchlist_uri" "watchlist $watchlist_alias"
	if ! watchlist_resource=$(az rest --only-show-errors --method get --uri "$watchlist_uri" --output json); then
		echo "watchlist $watchlist_alias could not be read exactly after creation" >&2
		exit 2
	fi
	if ! watchlist_matches "$watchlist_resource"; then
		echo "watchlist $watchlist_alias does not match the exact owned fixture definition" >&2
		exit 2
	fi

	jq -n --arg location "$location" --arg marker "$fixture_marker" '{
		location: $location,
		tags: {project: "deadair", purpose: $marker, disposable: "true"},
		properties: {retentionInDays: 30},
		sku: {name: "PerGB2018"}
	}' >"$tmp_dir/remote-workspace.json"
	az rest --only-show-errors --method put --uri "$remote_uri" \
		--body "@$tmp_dir/remote-workspace.json" --output none
	wait_for_value "$remote_uri" properties.provisioningState Succeeded "remote workspace $remote_workspace"

	jq -n '{properties: {customerManagedKey: false}}' >"$tmp_dir/remote-onboarding.json"
	az rest --only-show-errors --method put --uri "$remote_onboarding_uri" \
		--body "@$tmp_dir/remote-onboarding.json" --output none
	wait_for_value "$remote_onboarding_uri" name default "remote Sentinel onboarding state"
	wait_for_nonempty "$remote_onboarding_uri" id "remote Sentinel onboarding state"
	if ! remote_onboarding_resource=$(az rest --only-show-errors --method get \
		--uri "$remote_onboarding_uri" --output json); then
		echo "remote Sentinel onboarding state could not be read exactly" >&2
		exit 2
	fi
	if ! remote_onboarding_matches "$remote_onboarding_resource"; then
		echo "remote Sentinel onboarding state does not match the exact non-CMK fixture" >&2
		exit 2
	fi

	jq -n --arg table "$remote_table" '{
		properties: {
			plan: "Analytics",
			schema: {
				name: $table,
				columns: [
					{name: "TimeGenerated", type: "dateTime"},
					{name: "Marker", type: "string"}
				]
			}
		}
	}' >"$tmp_dir/remote-table.json"
	az rest --only-show-errors --method put --uri "$remote_table_uri" \
		--body "@$tmp_dir/remote-table.json" --output none
	wait_for_value "$remote_table_uri" properties.provisioningState Succeeded "remote table $remote_table"

	jq -n --arg table "$summary_table" --arg description "$summary_table_description" '{
		properties: {
			plan: "Analytics",
			schema: {
			name: $table,
			description: $description,
			columns: [
				{name: "TimeGenerated", type: "dateTime"},
				{name: "EventCount", type: "long"},
				{name: "Marker", type: "string"}
				]
			}
		}
	}' >"$tmp_dir/summary-table.json"
	az rest --only-show-errors --method put --uri "$summary_table_uri" \
		--body "@$tmp_dir/summary-table.json" --output none
	wait_for_value "$summary_table_uri" properties.provisioningState Succeeded "summary destination $summary_table"
	if ! summary_table_resource=$(az rest --only-show-errors --method get --uri "$summary_table_uri" --output json); then
		echo "owned summary destination could not be read after creation; run cleanup after Azure settles" >&2
		exit 2
	fi
	if ! summary_table_matches "$summary_table_resource"; then
		echo "owned summary destination did not preserve its exact schema marker; refusing to create the summary rule" >&2
		echo "Inspect $summary_table_path before cleanup; the script will not delete it unless that marker is readable." >&2
		exit 2
	fi

	jq -n --arg marker "$fixture_marker" --arg destination "$summary_table" \
		--arg display "$summary_display" --arg query "$summary_query" '{
		properties: {
			displayName: $display,
			description: $marker,
			ruleType: "User",
			ruleDefinition: {
				query: $query,
				binSize: 20,
				binDelay: 5,
				timeSelector: "TimeGenerated",
				destinationTable: $destination
			}
		}
	}' >"$tmp_dir/summary.json"
	az rest --only-show-errors --method put --uri "$summary_uri" \
		--body "@$tmp_dir/summary.json" --output none
	wait_for_value "$summary_uri" properties.provisioningState Succeeded "summary rule $summary_rule"
	wait_for_value "$summary_uri" properties.isActive true "summary rule $summary_rule"
	wait_for_value "$summary_table_uri" properties.provisioningState Succeeded "summary destination $summary_table"

	create_expansion_rule "$watchlist_rule_id" "$watchlist_rule_display" "$watchlist_rule_query"
	create_expansion_rule "$asim_rule_id" "$asim_rule_display" "$asim_rule_query"
	create_expansion_rule "$remote_rule_id" "$remote_rule_display" "$remote_rule_query"
	create_expansion_rule "$summary_consumer_rule_id" "$summary_consumer_rule_display" "$summary_consumer_rule_query"

	remote_workspace_id=$(az rest --only-show-errors --method get --uri "$remote_uri" \
		--query properties.customerId --output tsv)
	echo "fixtures ready"
	echo "export DEADAIR_SENTINEL_REMOTE_WORKSPACE=$remote_workspace"
	echo "export DEADAIR_SENTINEL_REMOTE_WORKSPACE_ID=$remote_workspace_id"
	exit 0
fi

# cleanup verifies ownership markers before deleting any pre-existing home
# workspace child. The remote workspace is removed only when all three tags
# still match the values written by apply.
cleanup_expansion_rule_state() {
	cleanup_rule_id=$1
	cleanup_rule_display=$2
	cleanup_rule_query=$3
	if ! cleanup_rule_resource=$(collection_resource "expansion rule $cleanup_rule_id" "$alert_rule_collection_uri" "$cleanup_rule_id"); then
		echo "refusing cleanup: expansion rule inventory could not be read" >&2
		return 2
	fi
	if [ -z "$cleanup_rule_resource" ]; then
		return 1
	fi
	if ! cleanup_rule_exact_resource=$(az rest --only-show-errors --method get \
		--uri "$(expansion_rule_uri "$cleanup_rule_id")" --output json); then
		echo "refusing cleanup: expansion rule $cleanup_rule_id could not be read exactly" >&2
		return 2
	fi
	if ! expansion_rule_matches "$cleanup_rule_exact_resource" "$cleanup_rule_id" "$cleanup_rule_display" "$cleanup_rule_query"; then
		echo "refusing cleanup: expansion rule $cleanup_rule_id lacks the exact disabled ownership definition" >&2
		return 2
	fi
	return 0
}

watchlist_rule_owned=false
if cleanup_expansion_rule_state "$watchlist_rule_id" "$watchlist_rule_display" "$watchlist_rule_query"; then
	watchlist_rule_owned=true
else
	cleanup_status=$?
	[ "$cleanup_status" -eq 1 ] || exit "$cleanup_status"
fi
asim_rule_owned=false
if cleanup_expansion_rule_state "$asim_rule_id" "$asim_rule_display" "$asim_rule_query"; then
	asim_rule_owned=true
else
	cleanup_status=$?
	[ "$cleanup_status" -eq 1 ] || exit "$cleanup_status"
fi
remote_rule_owned=false
if cleanup_expansion_rule_state "$remote_rule_id" "$remote_rule_display" "$remote_rule_query"; then
	remote_rule_owned=true
else
	cleanup_status=$?
	[ "$cleanup_status" -eq 1 ] || exit "$cleanup_status"
fi
summary_consumer_rule_owned=false
if cleanup_expansion_rule_state "$summary_consumer_rule_id" "$summary_consumer_rule_display" "$summary_consumer_rule_query"; then
	summary_consumer_rule_owned=true
else
	cleanup_status=$?
	[ "$cleanup_status" -eq 1 ] || exit "$cleanup_status"
fi

watchlist_owned=false
watchlist_resource=$(collection_resource "watchlist $watchlist_alias" "$watchlist_collection_uri" "$watchlist_alias")
if [ -n "$watchlist_resource" ]; then
	if ! watchlist_exact_resource=$(az rest --only-show-errors --method get --uri "$watchlist_uri" --output json); then
		echo "refusing cleanup: watchlist $watchlist_alias could not be read exactly" >&2
		exit 2
	fi
	require_watchlist_settled "$watchlist_exact_resource" "watchlist $watchlist_alias"
	if ! watchlist_matches "$watchlist_exact_resource"; then
		echo "refusing cleanup: watchlist ownership marker does not match" >&2
		exit 2
	fi
	watchlist_owned=true
fi

summary_owned=false
summary_resource=$(collection_resource "summary rule $summary_rule" "$summary_collection_uri" "$summary_rule")
summary_table_resource=$(collection_resource "summary destination $summary_table" "$table_collection_uri" "$summary_table")
summary_table_owned=false
if [ -n "$summary_table_resource" ]; then
	if ! summary_table_exact_resource=$(az rest --only-show-errors --method get --uri "$summary_table_uri" --output json); then
		echo "refusing cleanup: summary destination could not be read exactly" >&2
		exit 2
	fi
	if ! summary_table_matches "$summary_table_exact_resource"; then
		echo "refusing cleanup: summary destination lacks the script's exact independent schema marker" >&2
		exit 2
	fi
	summary_table_owned=true
fi
if [ -n "$summary_resource" ]; then
	if ! summary_exact_resource=$(az rest --only-show-errors --method get --uri "$summary_uri" --output json); then
		echo "refusing cleanup: summary rule could not be read exactly" >&2
		exit 2
	fi
	summary_marker=$(printf '%s' "$summary_exact_resource" | jq -r '.properties.description // empty')
	summary_actual_display=$(printf '%s' "$summary_exact_resource" | jq -r '.properties.displayName // empty')
	summary_actual_query=$(printf '%s' "$summary_exact_resource" | jq -r '.properties.ruleDefinition.query // empty')
	summary_actual_destination=$(printf '%s' "$summary_exact_resource" | jq -r '.properties.ruleDefinition.destinationTable // empty')
	summary_definition_exact=$(printf '%s' "$summary_exact_resource" | jq -r \
		--arg id "$summary_path" --arg name "$summary_rule" '
		(((.id // "") | ascii_downcase) == ($id | ascii_downcase)) and
		(.name == $name) and
		(.properties.ruleType == "User") and
		(.properties.ruleDefinition.binSize == 20) and
		(.properties.ruleDefinition.binDelay == 5) and
		(.properties.ruleDefinition.timeSelector == "TimeGenerated")')
	if [ "$summary_marker" != "$fixture_marker" ] || \
		[ "$summary_actual_display" != "$summary_display" ] || \
		[ "$summary_actual_query" != "$summary_query" ] || \
		[ "$summary_actual_destination" != "$summary_table" ] || \
		[ "$summary_definition_exact" != true ]; then
		echo "refusing cleanup: summary-rule ownership definition does not match" >&2
		exit 2
	fi
	summary_owned=true
fi

remote_owned=false
remote_resource=$(collection_resource "remote workspace $remote_workspace" "$workspace_collection_uri" "$remote_workspace")
if [ -n "$remote_resource" ]; then
	if ! remote_exact_resource=$(az rest --only-show-errors --method get --uri "$remote_uri" --output json); then
		echo "refusing cleanup: remote workspace could not be read exactly" >&2
		exit 2
	fi
	remote_project=$(printf '%s' "$remote_exact_resource" | jq -r '.tags.project // empty')
	remote_purpose=$(printf '%s' "$remote_exact_resource" | jq -r '.tags.purpose // empty')
	remote_disposable=$(printf '%s' "$remote_exact_resource" | jq -r '.tags.disposable // empty')
	remote_identity_exact=$(printf '%s' "$remote_exact_resource" | jq -r \
		--arg id "$remote_path" --arg name "$remote_workspace" '
		(((.id // "") | ascii_downcase) == ($id | ascii_downcase)) and (.name == $name)')
	if [ "$remote_project" != deadair ] || [ "$remote_purpose" != "$fixture_marker" ] || [ "$remote_disposable" != true ]; then
		echo "refusing cleanup: remote-workspace ownership tags do not match" >&2
		exit 2
	fi
	if [ "$remote_identity_exact" != true ]; then
		echo "refusing cleanup: remote-workspace identity does not match" >&2
		exit 2
	fi
	remote_owned=true
fi

if [ "$summary_consumer_rule_owned" = true ]; then
	az rest --only-show-errors --method delete --uri "$(expansion_rule_uri "$summary_consumer_rule_id")" --output none
	wait_for_collection_absence "$alert_rule_collection_uri" "$summary_consumer_rule_id" "summary consumer rule $summary_consumer_rule_id"
fi
if [ "$remote_rule_owned" = true ]; then
	az rest --only-show-errors --method delete --uri "$(expansion_rule_uri "$remote_rule_id")" --output none
	wait_for_collection_absence "$alert_rule_collection_uri" "$remote_rule_id" "remote dependency rule $remote_rule_id"
fi
if [ "$asim_rule_owned" = true ]; then
	az rest --only-show-errors --method delete --uri "$(expansion_rule_uri "$asim_rule_id")" --output none
	wait_for_collection_absence "$alert_rule_collection_uri" "$asim_rule_id" "ASIM dependency rule $asim_rule_id"
fi
if [ "$watchlist_rule_owned" = true ]; then
	az rest --only-show-errors --method delete --uri "$(expansion_rule_uri "$watchlist_rule_id")" --output none
	wait_for_collection_absence "$alert_rule_collection_uri" "$watchlist_rule_id" "watchlist dependency rule $watchlist_rule_id"
fi

if [ "$summary_owned" = true ]; then
	az rest --only-show-errors --method delete --uri "$summary_uri" --output none
	wait_for_collection_absence "$summary_collection_uri" "$summary_rule" "summary rule $summary_rule"
fi

if [ "$summary_table_owned" = true ]; then
	az rest --only-show-errors --method delete --uri "$summary_table_uri" --output none
	wait_for_collection_absence "$table_collection_uri" "$summary_table" "summary destination $summary_table"
fi

if [ "$watchlist_owned" = true ]; then
	az rest --only-show-errors --method delete --uri "$watchlist_uri" --output none
	wait_for_collection_absence "$watchlist_collection_uri" "$watchlist_alias" "watchlist $watchlist_alias"
fi

if [ "$remote_owned" = true ]; then
	az rest --only-show-errors --method delete --uri "$remote_uri" --output none
	wait_for_collection_absence "$workspace_collection_uri" "$remote_workspace" "remote workspace $remote_workspace"
fi

echo "Sentinel expansion fixtures removed"
