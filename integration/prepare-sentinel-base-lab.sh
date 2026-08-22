#!/bin/sh
set -eu

# Provisions only the named base fixtures consumed by TestSentinelReadOnlyLab.
# The resource group, workspace, Sentinel onboarding, budget, provider
# registration, and provisioner identity are external prerequisites. plan is
# offline. apply and cleanup require the exact confirmation marker below.

mode=${1:-plan}
subscription_id=${DEADAIR_AZURE_SUBSCRIPTION_ID:-}
resource_group=${DEADAIR_AZURE_RESOURCE_GROUP:-}
workspace=${DEADAIR_SENTINEL_WORKSPACE:-}
workspace_id=${DEADAIR_SENTINEL_WORKSPACE_ID:-}
confirmation=${DEADAIR_SENTINEL_BASE_LAB_CONFIRM:-}

fixture_marker=deadair-sentinel-base-validation
rule_description='Disposable deadair Sentinel conformance rule.'
function_category='deadair lab'
dcr_name=deadair-sentinel-base-dcr
dcr_destination=labWorkspace

base_function_id=7aaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa
base_function=DeadairLabSource
base_function_body='DeadairFresh_CL | project TimeGenerated, EventId, Marker'
parameterized_function_id=7bbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb
parameterized_function=DeadairLabParameterized
parameterized_function_body='DeadairFresh_CL | where Marker == marker | project TimeGenerated, EventId, Marker'
parameterized_function_parameters=marker:string

nrt_rule_id=78888888-8888-4888-8888-888888888888
nrt_display='deadair lab - nrt dependency'
nrt_query='DeadairFresh_CL | where TimeGenerated < datetime(1900-01-01)'

predicate_rule_id=77777777-7777-4777-8777-777777777777
predicate_rule_display='deadair lab - predicate freshness'
predicate_rule_query="DeadairPredicate_CL | where DeviceVendor == 'Deadair Labs' | project TimeGenerated, EventId, DeviceVendor"

case "$mode" in
plan|apply|cleanup) ;;
*)
	echo "usage: $0 [plan|apply|cleanup]" >&2
	exit 2
	;;
esac

valid_uuid() {
	case "$1" in
	????????-????-????-????-????????????) ;;
	*) return 1 ;;
	esac
	uuid_compact=$(printf '%s' "$1" | tr -d '-')
	case "$uuid_compact" in
	????????????????????????????????) ;;
	*) return 1 ;;
	esac
	case "$uuid_compact" in
	*[!0-9A-Fa-f]*) return 1 ;;
	esac
	return 0
}

if [ -z "$subscription_id" ] || [ -z "$resource_group" ] || [ -z "$workspace" ] || [ -z "$workspace_id" ]; then
	echo "DEADAIR_AZURE_SUBSCRIPTION_ID, DEADAIR_AZURE_RESOURCE_GROUP, DEADAIR_SENTINEL_WORKSPACE, and DEADAIR_SENTINEL_WORKSPACE_ID are required" >&2
	exit 2
fi
if ! valid_uuid "$subscription_id"; then
	echo "DEADAIR_AZURE_SUBSCRIPTION_ID must be a UUID" >&2
	exit 2
fi
case "$resource_group" in
""|*[!A-Za-z0-9_.-]*)
	echo "DEADAIR_AZURE_RESOURCE_GROUP contains unsupported characters" >&2
	exit 2
	;;
esac
case "$workspace" in
""|*[!A-Za-z0-9-]*)
	echo "DEADAIR_SENTINEL_WORKSPACE must contain only letters, numbers, and hyphens" >&2
	exit 2
	;;
esac
if ! valid_uuid "$workspace_id"; then
	echo "DEADAIR_SENTINEL_WORKSPACE_ID must be a UUID" >&2
	exit 2
fi

expected_confirmation="$fixture_marker:$workspace:$workspace_id"

workspace_path="/subscriptions/$subscription_id/resourceGroups/$resource_group/providers/Microsoft.OperationalInsights/workspaces/$workspace"
sentinel_path="$workspace_path/providers/Microsoft.SecurityInsights"
onboarding_path="$sentinel_path/onboardingStates/default"
dcr_path="/subscriptions/$subscription_id/resourceGroups/$resource_group/providers/Microsoft.Insights/dataCollectionRules/$dcr_name"

workspace_uri="https://management.azure.com$workspace_path?api-version=2025-07-01"
onboarding_uri="https://management.azure.com$onboarding_path?api-version=2025-09-01"
table_collection_uri="https://management.azure.com$workspace_path/tables?api-version=2025-07-01"
saved_search_collection_uri="https://management.azure.com$workspace_path/savedSearches?api-version=2025-07-01"
rule_collection_uri="https://management.azure.com$sentinel_path/alertRules?api-version=2025-09-01"
rule_preview_collection_uri="https://management.azure.com$sentinel_path/alertRules?api-version=2025-10-01-preview"
dcr_collection_uri="https://management.azure.com/subscriptions/$subscription_id/resourceGroups/$resource_group/providers/Microsoft.Insights/dataCollectionRules?api-version=2024-03-11"

print_plan() {
	echo "Sentinel base fixture plan (offline; no Azure calls or changes):"
	echo "  existing resource group: /subscriptions/$subscription_id/resourceGroups/$resource_group"
	echo "  existing Sentinel workspace: $workspace_path"
	echo "  expected workspace customer ID: $workspace_id"
	echo "  create eight final tables; create then remove DeadairRemoved_CL"
	echo "  create two saved workspace functions"
	echo "  create one tagged direct-ingestion DCR: $dcr_path"
	echo "  ingest six one-row samples (fresh, 45m lag, 90m stale, unused, predicate, Basic summary source)"
	echo "  create twelve Scheduled rules and one disabled NRT rule"
	echo "  create DeadairEmptyAnalytics_CL directly as an empty Analytics table"
	echo "  cleanup starts Azure's 15-day deleted-table recovery/name-reservation window"
	echo "  apply/cleanup confirmation: DEADAIR_SENTINEL_BASE_LAB_CONFIRM=$expected_confirmation"
}

if [ "$mode" = plan ]; then
	print_plan
	exit 0
fi
if [ "$confirmation" != "$expected_confirmation" ]; then
	echo "refusing $mode: set DEADAIR_SENTINEL_BASE_LAB_CONFIRM=$expected_confirmation" >&2
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

tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/deadair-sentinel-base.XXXXXX")
trap 'rm -rf "$tmp_dir"' EXIT HUP INT TERM

collection_resource() {
	collection_label=$1
	collection_target=$2
	collection_name=$3
	collection_page=0
	collection_found=
	while [ -n "$collection_target" ]; do
		case "$collection_target" in
		https://management.azure.com/*) ;;
		*)
			echo "$collection_label inventory returned a non-ARM nextLink" >&2
			return 2
			;;
		esac
		if ! collection_response=$(az rest --only-show-errors --method get --uri "$collection_target" --output json); then
			echo "$collection_label inventory could not be read" >&2
			return 2
		fi
		collection_count=$(printf '%s' "$collection_response" |
			jq --arg name "$collection_name" '[.value[]? | select(((.name // "") | ascii_downcase) == ($name | ascii_downcase))] | length')
		if [ "$collection_count" -gt 1 ] || { [ "$collection_count" -eq 1 ] && [ -n "$collection_found" ]; }; then
			echo "$collection_label inventory returned duplicate resources" >&2
			return 2
		fi
		if [ "$collection_count" -eq 1 ]; then
			collection_found=$(printf '%s' "$collection_response" |
				jq -c --arg name "$collection_name" '.value[] | select(((.name // "") | ascii_downcase) == ($name | ascii_downcase))')
		fi
		collection_target=$(printf '%s' "$collection_response" | jq -r '.nextLink // empty')
		collection_page=$((collection_page + 1))
		if [ "$collection_page" -gt 1000 ]; then
			echo "$collection_label inventory exceeded 1000 pages" >&2
			return 2
		fi
	done
	printf '%s' "$collection_found"
}

saved_search_identity_preflight() {
	identity_expected_id=$1
	identity_alias=$2
	identity_target=$saved_search_collection_uri
	identity_page=0
	while [ -n "$identity_target" ]; do
		case "$identity_target" in
		https://management.azure.com/*) ;;
		*)
			echo "saved-search identity inventory returned a non-ARM nextLink" >&2
			exit 2
			;;
		esac
		if ! identity_response=$(az rest --only-show-errors --method get --uri "$identity_target" --output json); then
			echo "saved-search identity inventory could not be read" >&2
			exit 2
		fi
		identity_conflicts=$(printf '%s' "$identity_response" | jq --arg id "$identity_expected_id" --arg alias "$identity_alias" '[
			.value[]? |
			select(
				((.properties.functionAlias // "") | ascii_downcase) == ($alias | ascii_downcase) or
				((.properties.displayName // "") | ascii_downcase) == ($alias | ascii_downcase)
			) |
			select(((.name // "") | ascii_downcase) != ($id | ascii_downcase))
		] | length')
		if [ "$identity_conflicts" -ne 0 ]; then
			echo "refusing $mode: saved-search functionAlias/displayName $identity_alias collides with another resource" >&2
			exit 2
		fi
		identity_target=$(printf '%s' "$identity_response" | jq -r '.nextLink // empty')
		identity_page=$((identity_page + 1))
		if [ "$identity_page" -gt 1000 ]; then
			echo "saved-search identity inventory exceeded 1000 pages" >&2
			exit 2
		fi
	done
}

stable_resource_json() {
	stable_uri=$1
	stable_label=$2
	stable_attempt=0
	while [ "$stable_attempt" -lt 60 ]; do
		if ! stable_resource=$(az rest --only-show-errors --method get --uri "$stable_uri" --output json); then
			echo "$stable_label could not be read directly" >&2
			return 2
		fi
		stable_state=$(printf '%s' "$stable_resource" | jq -r '.properties.provisioningState // empty')
		case "$stable_state" in
		""|Succeeded)
			printf '%s' "$stable_resource"
			return 0
			;;
		Creating|Updating|InProgress|Accepted|Running|Deploying)
			stable_attempt=$((stable_attempt + 1))
			sleep 5
			;;
		Failed|Canceled|Cancelled)
			echo "$stable_label has terminal provisioning state $stable_state" >&2
			return 2
			;;
		*)
			echo "$stable_label has unrecognized provisioning state $stable_state" >&2
			return 2
			;;
		esac
	done
	echo "$stable_label did not reach a stable successful provisioning state" >&2
	return 2
}

wait_for_collection_presence() {
	wait_collection_uri=$1
	wait_name=$2
	wait_label=$3
	wait_attempt=0
	while [ "$wait_attempt" -lt 60 ]; do
		wait_resource=$(collection_resource "$wait_label" "$wait_collection_uri" "$wait_name")
		if [ -n "$wait_resource" ]; then
			return 0
		fi
		wait_attempt=$((wait_attempt + 1))
		sleep 5
	done
	echo "$wait_label was not visible in its inventory" >&2
	return 1
}

wait_for_collection_absence() {
	wait_collection_uri=$1
	wait_name=$2
	wait_label=$3
	wait_attempt=0
	while [ "$wait_attempt" -lt 60 ]; do
		wait_resource=$(collection_resource "$wait_label" "$wait_collection_uri" "$wait_name")
		if [ -z "$wait_resource" ]; then
			return 0
		fi
		wait_attempt=$((wait_attempt + 1))
		sleep 5
	done
	echo "$wait_label was not removed" >&2
	return 1
}

table_uri() {
	printf 'https://management.azure.com%s/tables/%s?api-version=2025-07-01' "$workspace_path" "$1"
}

saved_search_uri() {
	printf 'https://management.azure.com%s/savedSearches/%s?api-version=2025-07-01' "$workspace_path" "$1"
}

rule_uri() {
	printf 'https://management.azure.com%s/alertRules/%s?api-version=2025-09-01' "$sentinel_path" "$1"
}

rule_preview_uri() {
	printf 'https://management.azure.com%s/alertRules/%s?api-version=2025-10-01-preview' "$sentinel_path" "$1"
}

dcr_uri="https://management.azure.com$dcr_path?api-version=2024-03-11"

table_owned() {
	printf '%s' "$1" | jq -e --arg marker "$fixture_marker" '.properties.schema.description == $marker' >/dev/null
}

table_matches() {
	table_resource=$1
	table_name=$2
	table_plan=$3
	table_shape=$4
	printf '%s' "$table_resource" | jq -e \
		--arg marker "$fixture_marker" --arg name "$table_name" --arg plan "$table_plan" --arg shape "$table_shape" \
		--arg resource "$workspace_path/tables/$table_name" '
		((.name // "") | ascii_downcase) == ($name | ascii_downcase) and
		((.id // "") | ascii_downcase) == ($resource | ascii_downcase) and
		((.type // "microsoft.operationalinsights/workspaces/tables") | ascii_downcase) == "microsoft.operationalinsights/workspaces/tables" and
		((.properties.provisioningState // "Succeeded") == "Succeeded") and
		.properties.schema.description == $marker and
		.properties.plan == $plan and
		((.properties.schema.name // .name) | ascii_downcase) == ($name | ascii_downcase) and
		(if $shape == "four" then
			([.properties.schema.columns[]? | {name, type: (.type | ascii_downcase)}] | length) == 4 and
			any(.properties.schema.columns[]?; .name == "TimeGenerated" and (.type | ascii_downcase) == "datetime") and
			any(.properties.schema.columns[]?; .name == "EventId" and (.type | ascii_downcase) == "string") and
			any(.properties.schema.columns[]?; .name == "Marker" and (.type | ascii_downcase) == "string") and
			any(.properties.schema.columns[]?; .name == "ExpectedField" and (.type | ascii_downcase) == "string")
		elif $shape == "predicate" then
			([.properties.schema.columns[]? | {name, type: (.type | ascii_downcase)}] | length) == 3 and
			any(.properties.schema.columns[]?; .name == "TimeGenerated" and (.type | ascii_downcase) == "datetime") and
			any(.properties.schema.columns[]?; .name == "EventId" and (.type | ascii_downcase) == "string") and
			any(.properties.schema.columns[]?; .name == "DeviceVendor" and (.type | ascii_downcase) == "string")
		else
			([.properties.schema.columns[]? | {name, type: (.type | ascii_downcase)}] | length) == 2 and
			any(.properties.schema.columns[]?; .name == "TimeGenerated" and (.type | ascii_downcase) == "datetime") and
			any(.properties.schema.columns[]?; .name == "Marker" and (.type | ascii_downcase) == "string")
		end)' >/dev/null
}

function_owned() {
	printf '%s' "$1" | jq -e --arg marker "$fixture_marker" '
		any(.properties.tags[]?; .name == "deadair-fixture" and .value == $marker)' >/dev/null
}

function_matches() {
	function_resource=$1
	function_id=$2
	function_alias=$3
	function_body=$4
	function_parameters=$5
	printf '%s' "$function_resource" | jq -e \
		--arg marker "$fixture_marker" --arg category "$function_category" \
		--arg id "$function_id" --arg resource "$workspace_path/savedSearches/$function_id" \
		--arg alias "$function_alias" --arg body "$function_body" --arg parameters "$function_parameters" '
		((.name // "") | ascii_downcase) == ($id | ascii_downcase) and
		((.id // "") | ascii_downcase) == ($resource | ascii_downcase) and
		((.type // "") | ascii_downcase) == "microsoft.operationalinsights/savedsearches" and
		.properties.category == $category and
		.properties.displayName == $alias and
		.properties.functionAlias == $alias and
		.properties.query == $body and
		(.properties.version == 2) and
		((.properties.functionParameters // "") == $parameters) and
		any(.properties.tags[]?; .name == "deadair-fixture" and .value == $marker)' >/dev/null
}

rule_owned() {
	printf '%s' "$1" | jq -e --arg description "$rule_description" '.properties.description == $description' >/dev/null
}

rule_inventory_identity_matches() {
	rule_resource=$1
	rule_id=$2
	rule_kind=$3
	printf '%s' "$rule_resource" | jq -e --arg id "$rule_id" \
		--arg resource "$sentinel_path/alertRules/$rule_id" --arg kind "$rule_kind" '
		((.name // "") | ascii_downcase) == ($id | ascii_downcase) and
		((.id // "") | ascii_downcase) == ($resource | ascii_downcase) and
		((.type // "") | ascii_downcase) == "microsoft.securityinsights/alertrules" and
		.kind == $kind' >/dev/null
}

scheduled_rule_matches() {
	rule_resource=$1
	rule_id=$2
	rule_display=$3
	rule_frequency=$4
	rule_period=$5
	rule_query=$6
	printf '%s' "$rule_resource" | jq -e \
		--arg id "$rule_id" --arg resource "$sentinel_path/alertRules/$rule_id" \
		--arg description "$rule_description" --arg display "$rule_display" \
		--arg frequency "$rule_frequency" --arg period "$rule_period" --arg query "$rule_query" '
		((.name // "") | ascii_downcase) == ($id | ascii_downcase) and
		((.id // "") | ascii_downcase) == ($resource | ascii_downcase) and
		((.type // "") | ascii_downcase) == "microsoft.securityinsights/alertrules" and
		.kind == "Scheduled" and .properties.displayName == $display and
		.properties.description == $description and .properties.enabled == true and
		.properties.severity == "Low" and .properties.query == $query and
		.properties.queryFrequency == $frequency and .properties.queryPeriod == $period and
		.properties.triggerOperator == "GreaterThan" and .properties.triggerThreshold == 10000 and
		.properties.suppressionDuration == "PT1H" and .properties.suppressionEnabled == false and
		.properties.incidentConfiguration.createIncident == false and
		.properties.eventGroupingSettings.aggregationKind == "SingleAlert" and
		([.properties.tactics[]?] | length) == 0 and
		([.properties.techniques[]?] | length) == 0 and
		([.properties.entityMappings[]?] | length) == 0 and
		((.properties.customDetails // {}) | length) == 0 and
		all((.properties.alertDetailsOverride // {})[]; . == null or . == "") and
		((.properties.alertRuleTemplateName // "") == "") and
		((.properties.templateVersion // "") == "")' >/dev/null
}

nrt_rule_matches() {
	printf '%s' "$1" | jq -e \
		--arg id "$nrt_rule_id" --arg resource "$sentinel_path/alertRules/$nrt_rule_id" \
		--arg description "$rule_description" --arg display "$nrt_display" --arg query "$nrt_query" '
		((.name // "") | ascii_downcase) == ($id | ascii_downcase) and
		((.id // "") | ascii_downcase) == ($resource | ascii_downcase) and
		((.type // "") | ascii_downcase) == "microsoft.securityinsights/alertrules" and
		.kind == "NRT" and .properties.displayName == $display and
		.properties.description == $description and .properties.enabled == false and
		.properties.severity == "Informational" and .properties.query == $query and
		.properties.suppressionDuration == "PT1H" and .properties.suppressionEnabled == false and
		.properties.incidentConfiguration.createIncident == false and
		([.properties.tactics[]?] | length) == 0 and
		([.properties.techniques[]?] | length) == 0 and
		([.properties.entityMappings[]?] | length) == 0 and
		((.properties.customDetails // {}) | length) == 0 and
		all((.properties.alertDetailsOverride // {})[]; . == null or . == "") and
		((.properties.alertRuleTemplateName // "") == "") and
		((.properties.templateVersion // "") == "")' >/dev/null
}

dcr_owned() {
	printf '%s' "$1" | jq -e --arg marker "$fixture_marker" '
		.tags.project == "deadair" and .tags.purpose == $marker and .tags.disposable == "true"' >/dev/null
}

dcr_matches() {
	printf '%s' "$1" | jq -e --arg marker "$fixture_marker" --arg workspace "$workspace_path" --arg destination "$dcr_destination" \
		--arg resource "$dcr_path" --arg name "$dcr_name" --arg location "$workspace_location" '
		def columns($stream):
			[.properties.streamDeclarations[$stream].columns[]? |
				{name, type: (.type | ascii_downcase)}] | sort_by(.name);
		def standard_columns:
			[{name: "TimeGenerated", type: "datetime"}, {name: "EventId", type: "string"},
			 {name: "Marker", type: "string"}, {name: "ExpectedField", type: "string"}] | sort_by(.name);
		def predicate_columns:
			[{name: "TimeGenerated", type: "datetime"}, {name: "EventId", type: "string"},
			 {name: "DeviceVendor", type: "string"}] | sort_by(.name);
		def summary_source_columns:
			[{name: "TimeGenerated", type: "datetime"}, {name: "Marker", type: "string"}] | sort_by(.name);
		((.name // "") | ascii_downcase) == ($name | ascii_downcase) and
		((.id // "") | ascii_downcase) == ($resource | ascii_downcase) and
		((.type // "") | ascii_downcase) == "microsoft.insights/datacollectionrules" and
		((.location // "") | ascii_downcase) == ($location | ascii_downcase) and
		.kind == "Direct" and
		((.properties.provisioningState // "Succeeded") == "Succeeded") and
		.tags.project == "deadair" and .tags.purpose == $marker and .tags.disposable == "true" and
		.properties.description == $marker and
		([.properties.destinations | keys[]] | length) == 1 and
		([.properties.destinations.logAnalytics[]?] | length) == 1 and
		([.properties.destinations.logAnalytics[]? |
			select(.name == $destination and ((.workspaceResourceId | ascii_downcase) == ($workspace | ascii_downcase)))] | length) == 1 and
		([.properties.streamDeclarations | keys[]] | sort) == ([
			"Custom-DeadairFresh", "Custom-DeadairStale", "Custom-DeadairLag",
			"Custom-DeadairUnused", "Custom-DeadairRemoved", "Custom-DeadairPredicate",
			"Custom-DeadairBasic"] | sort) and
		columns("Custom-DeadairFresh") == standard_columns and
		columns("Custom-DeadairStale") == standard_columns and
		columns("Custom-DeadairLag") == standard_columns and
		columns("Custom-DeadairUnused") == standard_columns and
		columns("Custom-DeadairRemoved") == standard_columns and
		columns("Custom-DeadairPredicate") == predicate_columns and
		columns("Custom-DeadairBasic") == summary_source_columns and
		([.properties.dataFlows[]? |
			select(.destinations == [$destination] and .transformKql == "source" and
				(.streams | length) == 1 and .outputStream == (.streams[0] + "_CL") and
				((.captureOverflow // false) == false) and ((.builtInTransform // "") == ""))] | length) == 7 and
		([.properties.dataFlows[]?.outputStream] | sort) == ([
			"Custom-DeadairFresh_CL", "Custom-DeadairStale_CL", "Custom-DeadairLag_CL",
			"Custom-DeadairUnused_CL", "Custom-DeadairRemoved_CL", "Custom-DeadairPredicate_CL",
			"Custom-DeadairBasic_CL"] | sort)' >/dev/null
}

verify_provider() {
	provider_namespace=$1
	provider_resource=$(az rest --only-show-errors --method get \
		--uri "https://management.azure.com/subscriptions/$subscription_id/providers/$provider_namespace?api-version=2021-04-01" \
		--output json)
	provider_state=$(printf '%s' "$provider_resource" | jq -r '.registrationState // empty')
	if [ "$provider_state" != Registered ]; then
		echo "$provider_namespace is not registered in the target subscription" >&2
		exit 2
	fi
}

verify_workspace_prerequisites() {
	verify_provider Microsoft.OperationalInsights
	verify_provider Microsoft.SecurityInsights
	verify_provider Microsoft.Insights
	if ! workspace_resource=$(az rest --only-show-errors --method get --uri "$workspace_uri" --output json); then
		echo "the dedicated Log Analytics workspace could not be read" >&2
		exit 2
	fi
	workspace_actual_customer_id=$(printf '%s' "$workspace_resource" | jq -r '.properties.customerId // empty')
	workspace_location=$(printf '%s' "$workspace_resource" | jq -r '.location // empty')
	workspace_actual_id=$(printf '%s' "$workspace_resource" | jq -r '.id // empty')
	if [ "$workspace_actual_customer_id" != "$workspace_id" ]; then
		echo "the workspace customer ID does not exactly match DEADAIR_SENTINEL_WORKSPACE_ID" >&2
		exit 2
	fi
	if [ -z "$workspace_location" ] || \
		[ "$(printf '%s' "$workspace_actual_id" | tr '[:upper:]' '[:lower:]')" != "$(printf '%s' "$workspace_path" | tr '[:upper:]' '[:lower:]')" ]; then
		echo "the workspace response does not match the requested resource or lacks its location" >&2
		exit 2
	fi

}

verify_sentinel_onboarding() {
	if ! onboarding_resource=$(az rest --only-show-errors --method get --uri "$onboarding_uri" --output json); then
		echo "Sentinel onboardingStates/default is required before base fixture writes" >&2
		exit 2
	fi
	if ! printf '%s' "$onboarding_resource" | jq -e --arg id "$onboarding_path" '
		.name == "default" and ((.id | ascii_downcase) == ($id | ascii_downcase)) and
		((.type // "") | ascii_downcase) == "microsoft.securityinsights/onboardingstates"' >/dev/null; then
		echo "Sentinel onboardingStates/default does not match the requested workspace" >&2
		exit 2
	fi
}

probe_logs_query_access() {
	jq -n '{query: "print deadair_probe=1 | take 1"}' >"$tmp_dir/logs-query-probe.json"
	if ! probe_response=$(az rest --only-show-errors --method post --resource https://api.loganalytics.io \
		--uri "https://api.loganalytics.io/v1/workspaces/$workspace_id/query" \
		--body "@$tmp_dir/logs-query-probe.json" --output json); then
		echo "the provisioner identity cannot run the required bounded Log Analytics query" >&2
		exit 2
	fi
	if ! printf '%s' "$probe_response" | jq -e '.tables[0].rows == [[1]]' >/dev/null; then
		echo "the bounded Log Analytics query returned an unexpected response" >&2
		exit 2
	fi
}

preflight_table() {
	preflight_name=$1
	preflight_plan=$2
	preflight_shape=$3
	preflight_resource=$(collection_resource "table $preflight_name" "$table_collection_uri" "$preflight_name")
	if [ -z "$preflight_resource" ]; then
		return 0
	fi
	preflight_resource=$(stable_resource_json "$(table_uri "$preflight_name")" "table $preflight_name")
	if ! table_owned "$preflight_resource"; then
		echo "refusing $mode: table $preflight_name exists without the deadair base marker" >&2
		exit 2
	fi
	if ! table_matches "$preflight_resource" "$preflight_name" "$preflight_plan" "$preflight_shape"; then
		echo "refusing $mode: owned table $preflight_name does not match its fixture definition" >&2
		exit 2
	fi
}

preflight_function() {
	preflight_id=$1
	preflight_alias=$2
	preflight_body=$3
	preflight_parameters=$4
	saved_search_identity_preflight "$preflight_id" "$preflight_alias"
	preflight_resource=$(collection_resource "saved search $preflight_id" "$saved_search_collection_uri" "$preflight_id")
	if [ -z "$preflight_resource" ]; then
		return 0
	fi
	if ! preflight_resource=$(az rest --only-show-errors --method get --uri "$(saved_search_uri "$preflight_id")" --output json); then
		echo "saved search $preflight_id disappeared or became unreadable during preflight" >&2
		exit 2
	fi
	if ! function_owned "$preflight_resource"; then
		echo "refusing $mode: saved search $preflight_id exists without the deadair base marker" >&2
		exit 2
	fi
	if ! function_matches "$preflight_resource" "$preflight_id" "$preflight_alias" "$preflight_body" "$preflight_parameters"; then
		echo "refusing $mode: owned saved search $preflight_id does not match its fixture definition" >&2
		exit 2
	fi
}

preflight_scheduled_rule() {
	preflight_id=$1
	preflight_display=$2
	preflight_frequency=$3
	preflight_period=$4
	preflight_query=$5
	preflight_resource=$(collection_resource "Scheduled rule $preflight_id in GA" "$rule_collection_uri" "$preflight_id")
	preflight_preview=$(collection_resource "Scheduled rule $preflight_id in preview" "$rule_preview_collection_uri" "$preflight_id")
	if [ -z "$preflight_resource" ] && [ -n "$preflight_preview" ]; then
		echo "refusing $mode: Scheduled fixture ID $preflight_id has a preview-only alert-rule collision" >&2
		exit 2
	fi
	if [ -z "$preflight_resource" ]; then
		return 0
	fi
	if ! preflight_resource=$(az rest --only-show-errors --method get --uri "$(rule_uri "$preflight_id")" --output json); then
		echo "Scheduled rule $preflight_id disappeared or became unreadable during preflight" >&2
		exit 2
	fi
	if ! rule_owned "$preflight_resource"; then
		echo "refusing $mode: rule $preflight_id exists without the deadair base marker" >&2
		exit 2
	fi
	if ! scheduled_rule_matches "$preflight_resource" "$preflight_id" "$preflight_display" "$preflight_frequency" "$preflight_period" "$preflight_query"; then
		echo "refusing $mode: owned rule $preflight_id does not match its fixture definition" >&2
		exit 2
	fi
	if [ -n "$preflight_preview" ] && ! rule_inventory_identity_matches "$preflight_preview" "$preflight_id" Scheduled; then
		echo "refusing $mode: preview inventory kind/identity disagrees with GA for Scheduled rule $preflight_id" >&2
		exit 2
	fi
}

preflight_nrt_rule() {
	preflight_ga=$(collection_resource "NRT ID $nrt_rule_id in GA" "$rule_collection_uri" "$nrt_rule_id")
	if [ -n "$preflight_ga" ]; then
		echo "refusing $mode: NRT fixture ID $nrt_rule_id collides with a GA alert rule" >&2
		exit 2
	fi
	preflight_resource=$(collection_resource "NRT rule $nrt_rule_id" "$rule_preview_collection_uri" "$nrt_rule_id")
	if [ -z "$preflight_resource" ]; then
		return 0
	fi
	if ! preflight_resource=$(az rest --only-show-errors --method get --uri "$(rule_preview_uri "$nrt_rule_id")" --output json); then
		echo "NRT rule $nrt_rule_id disappeared or became unreadable during preflight" >&2
		exit 2
	fi
	if ! rule_owned "$preflight_resource"; then
		echo "refusing $mode: NRT rule $nrt_rule_id exists without the deadair base marker" >&2
		exit 2
	fi
	if ! nrt_rule_matches "$preflight_resource"; then
		echo "refusing $mode: owned NRT rule $nrt_rule_id does not match its fixture definition" >&2
		exit 2
	fi
}

preflight_dcr() {
	preflight_resource=$(collection_resource "DCR $dcr_name" "$dcr_collection_uri" "$dcr_name")
	if [ -z "$preflight_resource" ]; then
		return 0
	fi
	preflight_resource=$(stable_resource_json "$dcr_uri" "DCR $dcr_name")
	if ! dcr_owned "$preflight_resource"; then
		echo "refusing $mode: DCR $dcr_name exists without the deadair base tags" >&2
		exit 2
	fi
	if ! dcr_matches "$preflight_resource"; then
		echo "refusing $mode: owned DCR $dcr_name does not match its fixture definition" >&2
		exit 2
	fi
}

run_collision_preflight() {
	preflight_table DeadairFresh_CL Analytics four
	preflight_table DeadairStale_CL Analytics four
	preflight_table DeadairLag_CL Analytics four
	preflight_table DeadairUnused_CL Analytics four
	preflight_table DeadairPredicate_CL Analytics predicate
	preflight_table DeadairBasic_CL Basic two
	preflight_table DeadairAuxiliary_CL Auxiliary two
	preflight_table DeadairEmptyAnalytics_CL Analytics two
	preflight_table DeadairRemoved_CL Analytics four
	preflight_function "$base_function_id" "$base_function" "$base_function_body" ""
	preflight_function "$parameterized_function_id" "$parameterized_function" "$parameterized_function_body" "$parameterized_function_parameters"
	preflight_dcr

	preflight_scheduled_rule 11111111-1111-4111-8111-111111111111 'deadair lab - fresh direct table' PT5M PT30M 'DeadairFresh_CL | where TimeGenerated > ago(30m) | project TimeGenerated, EventId, Marker, ExpectedField'
	preflight_scheduled_rule 22222222-2222-4222-8222-222222222222 'deadair lab - stale direct table' PT5M PT30M 'DeadairStale_CL | where TimeGenerated > ago(30m) | project TimeGenerated, EventId, Marker, ExpectedField'
	preflight_scheduled_rule 33333333-3333-4333-8333-333333333333 'deadair lab - delayed direct table' PT5M PT10M 'DeadairLag_CL | where TimeGenerated > ago(10m) | project TimeGenerated, EventId, Marker, ExpectedField'
	preflight_scheduled_rule 44444444-4444-4444-8444-444444444444 'deadair lab - removed direct table' PT5M PT30M 'DeadairRemoved_CL | where TimeGenerated > ago(30m) | project TimeGenerated, EventId, Marker, ExpectedField'
	preflight_scheduled_rule 55555555-5555-4555-8555-555555555555 'deadair lab - partial union' PT5M PT30M 'union isfuzzy=true DeadairFresh_CL, DeadairRemoved_CL | where TimeGenerated > ago(30m) | project TimeGenerated, EventId, Marker'
	preflight_scheduled_rule 66666666-6666-4666-8666-666666666666 'deadair lab - let and join' PT5M PT30M 'let recentFresh = DeadairFresh_CL | where TimeGenerated > ago(30m); recentFresh | join kind=leftouter (DeadairLag_CL | where TimeGenerated > ago(30m)) on ExpectedField | project TimeGenerated, EventId, Marker'
	preflight_scheduled_rule 71111111-1111-4111-8111-111111111111 'deadair lab - saved function bare source' PT5M PT30M 'DeadairLabSource | where TimeGenerated > ago(30m) | project TimeGenerated, EventId, Marker'
	preflight_scheduled_rule 72222222-2222-4222-8222-222222222222 'deadair lab - saved function call' PT5M PT30M 'DeadairLabSource() | where TimeGenerated > ago(30m) | project TimeGenerated, EventId, Marker'
	preflight_scheduled_rule 73333333-3333-4333-8333-333333333333 'deadair lab - parameterized function' PT5M PT30M 'DeadairLabParameterized("fresh") | where TimeGenerated > ago(30m) | project TimeGenerated, EventId, Marker'
	preflight_scheduled_rule 74444444-4444-4444-8444-444444444444 'deadair lab - auxiliary table dependency' PT5M PT30M 'DeadairAuxiliary_CL | where TimeGenerated > ago(30m) | project TimeGenerated, Marker'
	preflight_scheduled_rule 76666666-6666-4666-8666-666666666666 'deadair lab - empty analytics table' PT5M PT30M 'DeadairEmptyAnalytics_CL | where TimeGenerated > ago(30m) | project TimeGenerated, Marker'
	preflight_scheduled_rule "$predicate_rule_id" "$predicate_rule_display" PT5M PT30M "$predicate_rule_query"
	preflight_nrt_rule

	preflight_removed=$(collection_resource "table DeadairRemoved_CL" "$table_collection_uri" DeadairRemoved_CL)
	preflight_dcr_resource=$(collection_resource "DCR $dcr_name" "$dcr_collection_uri" "$dcr_name")
	preflight_missing_rule=$(collection_resource "Scheduled rule 44444444-4444-4444-8444-444444444444" "$rule_collection_uri" 44444444-4444-4444-8444-444444444444)
	preflight_partial_rule=$(collection_resource "Scheduled rule 55555555-5555-4555-8555-555555555555" "$rule_collection_uri" 55555555-5555-4555-8555-555555555555)
	base_removed_needed=true
	if [ -z "$preflight_removed" ] && [ -n "$preflight_dcr_resource" ] && \
		[ -n "$preflight_missing_rule" ] && [ -n "$preflight_partial_rule" ]; then
		base_removed_needed=false
	fi
}

create_table_body() {
	create_table_name=$1
	create_table_plan=$2
	create_table_shape=$3
	if [ "$create_table_shape" = four ]; then
		jq -n --arg name "$create_table_name" --arg plan "$create_table_plan" --arg marker "$fixture_marker" '{
			properties: {plan: $plan, schema: {name: $name, description: $marker, columns: [
				{name: "TimeGenerated", type: "dateTime"},
				{name: "EventId", type: "string"},
				{name: "Marker", type: "string"},
				{name: "ExpectedField", type: "string"}
			]}}
		}'
	elif [ "$create_table_shape" = predicate ]; then
		jq -n --arg name "$create_table_name" --arg plan "$create_table_plan" --arg marker "$fixture_marker" '{
			properties: {plan: $plan, schema: {name: $name, description: $marker, columns: [
				{name: "TimeGenerated", type: "dateTime"},
				{name: "EventId", type: "string"},
				{name: "DeviceVendor", type: "string"}
			]}}
		}'
	else
		jq -n --arg name "$create_table_name" --arg plan "$create_table_plan" --arg marker "$fixture_marker" '{
			properties: {plan: $plan, schema: {name: $name, description: $marker, columns: [
				{name: "TimeGenerated", type: "dateTime"},
				{name: "Marker", type: "string"}
			]}}
		}'
	fi
}

ensure_table() {
	ensure_name=$1
	ensure_plan=$2
	ensure_shape=$3
	preflight_table "$ensure_name" "$ensure_plan" "$ensure_shape"
	ensure_resource=$(collection_resource "table $ensure_name" "$table_collection_uri" "$ensure_name")
	if [ -n "$ensure_resource" ]; then
		return 0
	fi
	create_table_body "$ensure_name" "$ensure_plan" "$ensure_shape" >"$tmp_dir/table-$ensure_name.json"
	az rest --only-show-errors --method put --uri "$(table_uri "$ensure_name")" \
		--body "@$tmp_dir/table-$ensure_name.json" --output none
	ensure_resource=$(stable_resource_json "$(table_uri "$ensure_name")" "table $ensure_name")
	if ! table_matches "$ensure_resource" "$ensure_name" "$ensure_plan" "$ensure_shape"; then
		echo "new table $ensure_name did not stabilize at its exact fixture definition" >&2
		exit 2
	fi
}

ensure_function() {
	ensure_id=$1
	ensure_alias=$2
	ensure_body=$3
	ensure_parameters=$4
	preflight_function "$ensure_id" "$ensure_alias" "$ensure_body" "$ensure_parameters"
	ensure_resource=$(collection_resource "saved search $ensure_id" "$saved_search_collection_uri" "$ensure_id")
	if [ -n "$ensure_resource" ]; then
		return 0
	fi
	jq -n --arg category "$function_category" --arg alias "$ensure_alias" --arg query "$ensure_body" \
		--arg parameters "$ensure_parameters" --arg marker "$fixture_marker" '{
			properties: {
				category: $category, displayName: $alias, functionAlias: $alias,
				functionParameters: $parameters, query: $query, version: 2,
				tags: [{name: "deadair-fixture", value: $marker}]
			}
		} | if $parameters == "" then del(.properties.functionParameters) else . end' >"$tmp_dir/function-$ensure_id.json"
	az rest --only-show-errors --method put --uri "$(saved_search_uri "$ensure_id")" \
		--body "@$tmp_dir/function-$ensure_id.json" --output none
	wait_for_collection_presence "$saved_search_collection_uri" "$ensure_id" "saved search $ensure_id"
	preflight_function "$ensure_id" "$ensure_alias" "$ensure_body" "$ensure_parameters"
}

ensure_dcr() {
	preflight_dcr
	ensure_resource=$(collection_resource "DCR $dcr_name" "$dcr_collection_uri" "$dcr_name")
	if [ -n "$ensure_resource" ]; then
		return 0
	fi
	jq -n --arg location "$workspace_location" --arg workspace "$workspace_path" \
		--arg destination "$dcr_destination" --arg marker "$fixture_marker" '{
		location: $location,
		kind: "Direct",
		tags: {project: "deadair", purpose: $marker, disposable: "true"},
		properties: {
			description: $marker,
			streamDeclarations: {
				"Custom-DeadairFresh": {columns: [
					{name: "TimeGenerated", type: "datetime"}, {name: "EventId", type: "string"},
					{name: "Marker", type: "string"}, {name: "ExpectedField", type: "string"}]},
				"Custom-DeadairStale": {columns: [
					{name: "TimeGenerated", type: "datetime"}, {name: "EventId", type: "string"},
					{name: "Marker", type: "string"}, {name: "ExpectedField", type: "string"}]},
				"Custom-DeadairLag": {columns: [
					{name: "TimeGenerated", type: "datetime"}, {name: "EventId", type: "string"},
					{name: "Marker", type: "string"}, {name: "ExpectedField", type: "string"}]},
				"Custom-DeadairUnused": {columns: [
					{name: "TimeGenerated", type: "datetime"}, {name: "EventId", type: "string"},
					{name: "Marker", type: "string"}, {name: "ExpectedField", type: "string"}]},
				"Custom-DeadairRemoved": {columns: [
					{name: "TimeGenerated", type: "datetime"}, {name: "EventId", type: "string"},
					{name: "Marker", type: "string"}, {name: "ExpectedField", type: "string"}]},
				"Custom-DeadairPredicate": {columns: [
					{name: "TimeGenerated", type: "datetime"}, {name: "EventId", type: "string"},
					{name: "DeviceVendor", type: "string"}]},
				"Custom-DeadairBasic": {columns: [
					{name: "TimeGenerated", type: "datetime"}, {name: "Marker", type: "string"}]}
			},
			destinations: {logAnalytics: [{workspaceResourceId: $workspace, name: $destination}]},
			dataFlows: [
				{streams: ["Custom-DeadairFresh"], destinations: [$destination], transformKql: "source", outputStream: "Custom-DeadairFresh_CL"},
				{streams: ["Custom-DeadairStale"], destinations: [$destination], transformKql: "source", outputStream: "Custom-DeadairStale_CL"},
				{streams: ["Custom-DeadairLag"], destinations: [$destination], transformKql: "source", outputStream: "Custom-DeadairLag_CL"},
				{streams: ["Custom-DeadairUnused"], destinations: [$destination], transformKql: "source", outputStream: "Custom-DeadairUnused_CL"},
				{streams: ["Custom-DeadairRemoved"], destinations: [$destination], transformKql: "source", outputStream: "Custom-DeadairRemoved_CL"},
				{streams: ["Custom-DeadairPredicate"], destinations: [$destination], transformKql: "source", outputStream: "Custom-DeadairPredicate_CL"},
				{streams: ["Custom-DeadairBasic"], destinations: [$destination], transformKql: "source", outputStream: "Custom-DeadairBasic_CL"}
			]
		}
	}' >"$tmp_dir/dcr.json"
	az rest --only-show-errors --method put --uri "$dcr_uri" --body "@$tmp_dir/dcr.json" --output none
	ensure_resource=$(stable_resource_json "$dcr_uri" "DCR $dcr_name")
	if ! dcr_matches "$ensure_resource"; then
		echo "new DCR $dcr_name did not stabilize at its exact fixture definition" >&2
		exit 2
	fi
}

ensure_scheduled_rule() {
	ensure_id=$1
	ensure_display=$2
	ensure_frequency=$3
	ensure_period=$4
	ensure_query=$5
	preflight_scheduled_rule "$ensure_id" "$ensure_display" "$ensure_frequency" "$ensure_period" "$ensure_query"
	ensure_resource=$(collection_resource "Scheduled rule $ensure_id" "$rule_collection_uri" "$ensure_id")
	if [ -n "$ensure_resource" ]; then
		return 0
	fi
	jq -n --arg display "$ensure_display" --arg description "$rule_description" \
		--arg frequency "$ensure_frequency" --arg period "$ensure_period" --arg query "$ensure_query" '{
		kind: "Scheduled",
		properties: {
			displayName: $display, description: $description, enabled: true, severity: "Low",
			query: $query, queryFrequency: $frequency, queryPeriod: $period,
			triggerOperator: "GreaterThan", triggerThreshold: 10000,
			suppressionDuration: "PT1H", suppressionEnabled: false,
			incidentConfiguration: {createIncident: false},
			eventGroupingSettings: {aggregationKind: "SingleAlert"}
		}
	}' >"$tmp_dir/rule-$ensure_id.json"
	az rest --only-show-errors --method put --uri "$(rule_uri "$ensure_id")" \
		--body "@$tmp_dir/rule-$ensure_id.json" --output none
	wait_for_collection_presence "$rule_collection_uri" "$ensure_id" "Scheduled rule $ensure_id"
	preflight_scheduled_rule "$ensure_id" "$ensure_display" "$ensure_frequency" "$ensure_period" "$ensure_query"
}

ensure_nrt_rule() {
	preflight_nrt_rule
	ensure_resource=$(collection_resource "NRT rule $nrt_rule_id" "$rule_preview_collection_uri" "$nrt_rule_id")
	if [ -n "$ensure_resource" ]; then
		return 0
	fi
	jq -n --arg display "$nrt_display" --arg description "$rule_description" --arg query "$nrt_query" '{
		kind: "NRT",
		properties: {
			displayName: $display, description: $description, enabled: false,
			severity: "Informational", query: $query,
			suppressionDuration: "PT1H", suppressionEnabled: false,
			incidentConfiguration: {createIncident: false}
		}
	}' >"$tmp_dir/rule-$nrt_rule_id.json"
	az rest --only-show-errors --method put --uri "$(rule_preview_uri "$nrt_rule_id")" \
		--body "@$tmp_dir/rule-$nrt_rule_id.json" --output none
	wait_for_collection_presence "$rule_preview_collection_uri" "$nrt_rule_id" "NRT rule $nrt_rule_id"
	preflight_nrt_rule
}

utc_minutes_ago() {
	utc_minutes=$1
	if date -u -v-"$utc_minutes"M '+%Y-%m-%dT%H:%M:%S.000000Z' 2>/dev/null; then
		return 0
	fi
	date -u -d "$utc_minutes minutes ago" '+%Y-%m-%dT%H:%M:%S.000000Z'
}

wait_for_ingested_row() {
	wait_table=$1
	wait_event_id=$2
	wait_attempt=0
	jq -n --arg query "$wait_table | where EventId == '$wait_event_id' | take 1" '{query: $query}' >"$tmp_dir/query-$wait_table.json"
	# New Direct DCRs can take more than five minutes before their first rows
	# become queryable even after the ingestion requests have succeeded.
	while [ "$wait_attempt" -lt 120 ]; do
		if wait_response=$(az rest --only-show-errors --method post --resource https://api.loganalytics.io \
			--uri "https://api.loganalytics.io/v1/workspaces/$workspace_id/query" \
			--body "@$tmp_dir/query-$wait_table.json" --output json 2>/dev/null); then
			wait_rows=$(printf '%s' "$wait_response" | jq '[.tables[0].rows[]?] | length')
			if [ "$wait_rows" -gt 0 ]; then
				return 0
			fi
		fi
		wait_attempt=$((wait_attempt + 1))
		sleep 5
	done
	echo "ingested marker did not become queryable in $wait_table" >&2
	return 1
}

wait_for_basic_ingested_row() {
	wait_marker=$1
	wait_attempt=0
	jq -n --arg query "DeadairBasic_CL | where Marker == '$wait_marker' | take 1" \
		'{query: $query}' >"$tmp_dir/search-DeadairBasic_CL.json"
	while [ "$wait_attempt" -lt 120 ]; do
		if wait_response=$(az rest --only-show-errors --method post --resource https://api.loganalytics.io \
			--uri "https://api.loganalytics.io/v1/workspaces/$workspace_id/search?timespan=PT30M" \
			--body "@$tmp_dir/search-DeadairBasic_CL.json" --output json 2>/dev/null); then
			wait_rows=$(printf '%s' "$wait_response" | jq '[.tables[0].rows[]?] | length')
			if [ "$wait_rows" -gt 0 ]; then
				return 0
			fi
		fi
		wait_attempt=$((wait_attempt + 1))
		sleep 5
	done
	echo "ingested marker did not become searchable in DeadairBasic_CL" >&2
	return 1
}

ingest_base_rows() {
	dcr_resource=$(stable_resource_json "$dcr_uri" "DCR $dcr_name")
	if ! dcr_matches "$dcr_resource"; then
		echo "refusing ingestion: DCR $dcr_name no longer matches its exact fixture definition" >&2
		exit 2
	fi
	dcr_immutable_id=$(printf '%s' "$dcr_resource" | jq -r '.properties.immutableId // empty')
	dcr_ingestion_endpoint=$(printf '%s' "$dcr_resource" | jq -r '.properties.endpoints.logsIngestion // empty')
	case "$dcr_immutable_id" in
	dcr-*)
		dcr_immutable_suffix=${dcr_immutable_id#dcr-}
		case "$dcr_immutable_suffix" in
		""|*[!0-9A-Fa-f]*)
			echo "DCR $dcr_name returned a malformed immutable ID" >&2
			exit 2
			;;
		esac
		;;
	*)
		echo "DCR $dcr_name did not expose an immutable ID" >&2
		exit 2
		;;
	esac
	case "$dcr_ingestion_endpoint" in
	https://*) dcr_ingestion_authority=${dcr_ingestion_endpoint#https://} ;;
	*)
		echo "DCR $dcr_name returned an unexpected Logs Ingestion endpoint" >&2
		exit 2
		;;
	esac
	case "$dcr_ingestion_authority" in
	""|*/*|*@*|*:*|*\?*|*#*)
		echo "DCR $dcr_name returned a Logs Ingestion endpoint with an invalid HTTPS authority" >&2
		exit 2
		;;
	esac
	dcr_ingestion_host=$(printf '%s' "$dcr_ingestion_authority" | tr '[:upper:]' '[:lower:]')
	case "$dcr_ingestion_host" in
	.*|*.|*..*|*[!a-z0-9.-]*|*.ingest.monitor.azure.com.ingest.monitor.azure.com)
		echo "DCR $dcr_name returned a malformed Logs Ingestion hostname" >&2
		exit 2
		;;
	esac
	case "$dcr_ingestion_host" in
	?*.ingest.monitor.azure.com) ;;
	*)
		echo "DCR $dcr_name returned a Logs Ingestion hostname outside .ingest.monitor.azure.com" >&2
		exit 2
		;;
	esac
	dcr_ingestion_endpoint="https://$dcr_ingestion_host"

	ingest_epoch=$(date -u '+%s')
	fresh_event_id="fresh-$ingest_epoch"
	lag_event_id="lag-$ingest_epoch"
	stale_event_id="stale-$ingest_epoch"
	unused_event_id="unused-$ingest_epoch"
	predicate_event_id="predicate-$ingest_epoch"
	basic_marker="summary-source-$ingest_epoch"
	fresh_time=$(utc_minutes_ago 0)
	lag_time=$(utc_minutes_ago 45)
	stale_time=$(utc_minutes_ago 90)

	jq -n --arg time "$fresh_time" --arg id "$fresh_event_id" '[{TimeGenerated: $time, EventId: $id, Marker: "fresh", ExpectedField: "join-key"}]' >"$tmp_dir/ingest-fresh.json"
	jq -n --arg time "$lag_time" --arg id "$lag_event_id" '[{TimeGenerated: $time, EventId: $id, Marker: "lag", ExpectedField: "join-key"}]' >"$tmp_dir/ingest-lag.json"
	jq -n --arg time "$stale_time" --arg id "$stale_event_id" '[{TimeGenerated: $time, EventId: $id, Marker: "stale", ExpectedField: "join-key"}]' >"$tmp_dir/ingest-stale.json"
	jq -n --arg time "$fresh_time" --arg id "$unused_event_id" '[{TimeGenerated: $time, EventId: $id, Marker: "unused", ExpectedField: "unused"}]' >"$tmp_dir/ingest-unused.json"
	jq -n --arg time "$fresh_time" --arg id "$predicate_event_id" '[{TimeGenerated: $time, EventId: $id, DeviceVendor: "Deadair Labs"}]' >"$tmp_dir/ingest-predicate.json"
	jq -n --arg time "$fresh_time" --arg marker "$basic_marker" '[{TimeGenerated: $time, Marker: $marker}]' >"$tmp_dir/ingest-basic.json"

	for ingest_spec in \
		"DeadairFresh_CL:$tmp_dir/ingest-fresh.json" \
		"DeadairLag_CL:$tmp_dir/ingest-lag.json" \
		"DeadairStale_CL:$tmp_dir/ingest-stale.json" \
		"DeadairUnused_CL:$tmp_dir/ingest-unused.json" \
		"DeadairPredicate_CL:$tmp_dir/ingest-predicate.json" \
		"DeadairBasic_CL:$tmp_dir/ingest-basic.json"; do
		ingest_stream=${ingest_spec%%:*}
		ingest_file=${ingest_spec#*:}
		ingest_input=${ingest_stream%_CL}
		if ! az rest --only-show-errors --method post --resource https://monitor.azure.com \
			--uri "$dcr_ingestion_endpoint/dataCollectionRules/$dcr_immutable_id/streams/Custom-$ingest_input?api-version=2023-01-01" \
			--body "@$ingest_file" --output none; then
			echo "Logs Ingestion failed for $ingest_stream; the provisioner identity needs Monitoring Metrics Publisher at the DCR or resource-group scope" >&2
			exit 2
		fi
	done

	wait_for_ingested_row DeadairFresh_CL "$fresh_event_id"
	wait_for_ingested_row DeadairLag_CL "$lag_event_id"
	wait_for_ingested_row DeadairStale_CL "$stale_event_id"
	wait_for_ingested_row DeadairUnused_CL "$unused_event_id"
	wait_for_ingested_row DeadairPredicate_CL "$predicate_event_id"
	wait_for_basic_ingested_row "$basic_marker"
}

apply_fixtures() {
	ensure_table DeadairFresh_CL Analytics four
	ensure_table DeadairStale_CL Analytics four
	ensure_table DeadairLag_CL Analytics four
	ensure_table DeadairUnused_CL Analytics four
	ensure_table DeadairPredicate_CL Analytics predicate
	ensure_table DeadairBasic_CL Basic two
	ensure_table DeadairAuxiliary_CL Auxiliary two
	ensure_table DeadairEmptyAnalytics_CL Analytics two
	if [ "$base_removed_needed" = true ]; then
		ensure_table DeadairRemoved_CL Analytics four
	fi

	ensure_function "$base_function_id" "$base_function" "$base_function_body" ""
	ensure_function "$parameterized_function_id" "$parameterized_function" "$parameterized_function_body" "$parameterized_function_parameters"
	ensure_dcr
	ingest_base_rows

	ensure_scheduled_rule 11111111-1111-4111-8111-111111111111 'deadair lab - fresh direct table' PT5M PT30M 'DeadairFresh_CL | where TimeGenerated > ago(30m) | project TimeGenerated, EventId, Marker, ExpectedField'
	ensure_scheduled_rule 22222222-2222-4222-8222-222222222222 'deadair lab - stale direct table' PT5M PT30M 'DeadairStale_CL | where TimeGenerated > ago(30m) | project TimeGenerated, EventId, Marker, ExpectedField'
	ensure_scheduled_rule 33333333-3333-4333-8333-333333333333 'deadair lab - delayed direct table' PT5M PT10M 'DeadairLag_CL | where TimeGenerated > ago(10m) | project TimeGenerated, EventId, Marker, ExpectedField'
	ensure_scheduled_rule 44444444-4444-4444-8444-444444444444 'deadair lab - removed direct table' PT5M PT30M 'DeadairRemoved_CL | where TimeGenerated > ago(30m) | project TimeGenerated, EventId, Marker, ExpectedField'
	ensure_scheduled_rule 55555555-5555-4555-8555-555555555555 'deadair lab - partial union' PT5M PT30M 'union isfuzzy=true DeadairFresh_CL, DeadairRemoved_CL | where TimeGenerated > ago(30m) | project TimeGenerated, EventId, Marker'
	ensure_scheduled_rule 66666666-6666-4666-8666-666666666666 'deadair lab - let and join' PT5M PT30M 'let recentFresh = DeadairFresh_CL | where TimeGenerated > ago(30m); recentFresh | join kind=leftouter (DeadairLag_CL | where TimeGenerated > ago(30m)) on ExpectedField | project TimeGenerated, EventId, Marker'
	ensure_scheduled_rule 71111111-1111-4111-8111-111111111111 'deadair lab - saved function bare source' PT5M PT30M 'DeadairLabSource | where TimeGenerated > ago(30m) | project TimeGenerated, EventId, Marker'
	ensure_scheduled_rule 72222222-2222-4222-8222-222222222222 'deadair lab - saved function call' PT5M PT30M 'DeadairLabSource() | where TimeGenerated > ago(30m) | project TimeGenerated, EventId, Marker'
	ensure_scheduled_rule 73333333-3333-4333-8333-333333333333 'deadair lab - parameterized function' PT5M PT30M 'DeadairLabParameterized("fresh") | where TimeGenerated > ago(30m) | project TimeGenerated, EventId, Marker'
	ensure_scheduled_rule 74444444-4444-4444-8444-444444444444 'deadair lab - auxiliary table dependency' PT5M PT30M 'DeadairAuxiliary_CL | where TimeGenerated > ago(30m) | project TimeGenerated, Marker'
	ensure_scheduled_rule 76666666-6666-4666-8666-666666666666 'deadair lab - empty analytics table' PT5M PT30M 'DeadairEmptyAnalytics_CL | where TimeGenerated > ago(30m) | project TimeGenerated, Marker'
	ensure_scheduled_rule "$predicate_rule_id" "$predicate_rule_display" PT5M PT30M "$predicate_rule_query"
	ensure_nrt_rule

	removed_resource=$(collection_resource "table DeadairRemoved_CL" "$table_collection_uri" DeadairRemoved_CL)
	if [ -n "$removed_resource" ]; then
		removed_resource=$(stable_resource_json "$(table_uri DeadairRemoved_CL)" "table DeadairRemoved_CL")
		if ! table_matches "$removed_resource" DeadairRemoved_CL Analytics four; then
			echo "refusing final Removed-table deletion: the complete fixture definition changed during apply" >&2
			exit 2
		fi
		az rest --only-show-errors --method delete --uri "$(table_uri DeadairRemoved_CL)" --output none
		wait_for_collection_absence "$table_collection_uri" DeadairRemoved_CL "table DeadairRemoved_CL"
	fi

	final_empty_analytics=$(collection_resource "table DeadairEmptyAnalytics_CL" "$table_collection_uri" DeadairEmptyAnalytics_CL)
	if ! table_matches "$final_empty_analytics" DeadairEmptyAnalytics_CL Analytics two; then
		echo "base fixture apply ended without the exact empty Analytics table" >&2
		exit 2
	fi
	if [ -n "$(collection_resource "table DeadairRemoved_CL" "$table_collection_uri" DeadairRemoved_CL)" ]; then
		echo "base fixture apply ended with DeadairRemoved_CL still present" >&2
		exit 2
	fi
	echo "Sentinel base fixtures are ready"
}

cleanup_preflight() {
	# The apply collision pass is also the cleanup authorization pass: every
	# present target must retain its marker and complete fixture definition
	# before cleanup sends the first DELETE.
	run_collision_preflight
}

delete_scheduled_rule() {
	delete_id=$1
	delete_display=$2
	delete_frequency=$3
	delete_period=$4
	delete_query=$5
	delete_resource=$(collection_resource "Scheduled rule $delete_id" "$rule_collection_uri" "$delete_id")
	if [ -z "$delete_resource" ]; then
		return 0
	fi
	if ! delete_resource=$(az rest --only-show-errors --method get --uri "$(rule_uri "$delete_id")" --output json); then
		echo "refusing cleanup: Scheduled rule $delete_id could not be re-read immediately before deletion" >&2
		exit 2
	fi
	if ! scheduled_rule_matches "$delete_resource" "$delete_id" "$delete_display" "$delete_frequency" "$delete_period" "$delete_query"; then
		echo "refusing cleanup: Scheduled rule $delete_id changed after the all-resource preflight" >&2
		exit 2
	fi
	az rest --only-show-errors --method delete --uri "$(rule_uri "$delete_id")" --output none
	wait_for_collection_absence "$rule_collection_uri" "$delete_id" "Scheduled rule $delete_id"
	wait_for_collection_absence "$rule_preview_collection_uri" "$delete_id" "Scheduled rule $delete_id in preview"
}

delete_nrt_rule() {
	delete_resource=$(collection_resource "NRT rule $nrt_rule_id" "$rule_preview_collection_uri" "$nrt_rule_id")
	if [ -z "$delete_resource" ]; then
		return 0
	fi
	if ! delete_resource=$(az rest --only-show-errors --method get --uri "$(rule_preview_uri "$nrt_rule_id")" --output json); then
		echo "refusing cleanup: NRT rule $nrt_rule_id could not be re-read immediately before deletion" >&2
		exit 2
	fi
	if ! nrt_rule_matches "$delete_resource"; then
		echo "refusing cleanup: NRT rule $nrt_rule_id changed after the all-resource preflight" >&2
		exit 2
	fi
	az rest --only-show-errors --method delete --uri "$(rule_preview_uri "$nrt_rule_id")" --output none
	wait_for_collection_absence "$rule_preview_collection_uri" "$nrt_rule_id" "NRT rule $nrt_rule_id"
}

delete_dcr() {
	delete_resource=$(collection_resource "DCR $dcr_name" "$dcr_collection_uri" "$dcr_name")
	if [ -z "$delete_resource" ]; then
		return 0
	fi
	delete_resource=$(stable_resource_json "$dcr_uri" "DCR $dcr_name")
	if ! dcr_matches "$delete_resource"; then
		echo "refusing cleanup: DCR $dcr_name changed after the all-resource preflight" >&2
		exit 2
	fi
	az rest --only-show-errors --method delete --uri "$dcr_uri" --output none
	wait_for_collection_absence "$dcr_collection_uri" "$dcr_name" "DCR $dcr_name"
}

delete_function() {
	delete_id=$1
	delete_alias=$2
	delete_body=$3
	delete_parameters=$4
	delete_resource=$(collection_resource "saved search $delete_id" "$saved_search_collection_uri" "$delete_id")
	if [ -z "$delete_resource" ]; then
		return 0
	fi
	if ! delete_resource=$(az rest --only-show-errors --method get --uri "$(saved_search_uri "$delete_id")" --output json); then
		echo "refusing cleanup: saved search $delete_id could not be re-read immediately before deletion" >&2
		exit 2
	fi
	if ! function_matches "$delete_resource" "$delete_id" "$delete_alias" "$delete_body" "$delete_parameters"; then
		echo "refusing cleanup: saved search $delete_id changed after the all-resource preflight" >&2
		exit 2
	fi
	az rest --only-show-errors --method delete --uri "$(saved_search_uri "$delete_id")" --output none
	wait_for_collection_absence "$saved_search_collection_uri" "$delete_id" "saved search $delete_id"
}

delete_table() {
	delete_name=$1
	delete_plan=$2
	delete_shape=$3
	delete_resource=$(collection_resource "table $delete_name" "$table_collection_uri" "$delete_name")
	if [ -z "$delete_resource" ]; then
		return 0
	fi
	delete_resource=$(stable_resource_json "$(table_uri "$delete_name")" "table $delete_name")
	if ! table_matches "$delete_resource" "$delete_name" "$delete_plan" "$delete_shape"; then
		echo "refusing cleanup: table $delete_name changed after the all-resource preflight" >&2
		exit 2
	fi
	az rest --only-show-errors --method delete --uri "$(table_uri "$delete_name")" --output none
	wait_for_collection_absence "$table_collection_uri" "$delete_name" "table $delete_name"
}

cleanup_fixtures() {
	delete_scheduled_rule 11111111-1111-4111-8111-111111111111 'deadair lab - fresh direct table' PT5M PT30M 'DeadairFresh_CL | where TimeGenerated > ago(30m) | project TimeGenerated, EventId, Marker, ExpectedField'
	delete_scheduled_rule 22222222-2222-4222-8222-222222222222 'deadair lab - stale direct table' PT5M PT30M 'DeadairStale_CL | where TimeGenerated > ago(30m) | project TimeGenerated, EventId, Marker, ExpectedField'
	delete_scheduled_rule 33333333-3333-4333-8333-333333333333 'deadair lab - delayed direct table' PT5M PT10M 'DeadairLag_CL | where TimeGenerated > ago(10m) | project TimeGenerated, EventId, Marker, ExpectedField'
	delete_scheduled_rule 44444444-4444-4444-8444-444444444444 'deadair lab - removed direct table' PT5M PT30M 'DeadairRemoved_CL | where TimeGenerated > ago(30m) | project TimeGenerated, EventId, Marker, ExpectedField'
	delete_scheduled_rule 55555555-5555-4555-8555-555555555555 'deadair lab - partial union' PT5M PT30M 'union isfuzzy=true DeadairFresh_CL, DeadairRemoved_CL | where TimeGenerated > ago(30m) | project TimeGenerated, EventId, Marker'
	delete_scheduled_rule 66666666-6666-4666-8666-666666666666 'deadair lab - let and join' PT5M PT30M 'let recentFresh = DeadairFresh_CL | where TimeGenerated > ago(30m); recentFresh | join kind=leftouter (DeadairLag_CL | where TimeGenerated > ago(30m)) on ExpectedField | project TimeGenerated, EventId, Marker'
	delete_scheduled_rule 71111111-1111-4111-8111-111111111111 'deadair lab - saved function bare source' PT5M PT30M 'DeadairLabSource | where TimeGenerated > ago(30m) | project TimeGenerated, EventId, Marker'
	delete_scheduled_rule 72222222-2222-4222-8222-222222222222 'deadair lab - saved function call' PT5M PT30M 'DeadairLabSource() | where TimeGenerated > ago(30m) | project TimeGenerated, EventId, Marker'
	delete_scheduled_rule 73333333-3333-4333-8333-333333333333 'deadair lab - parameterized function' PT5M PT30M 'DeadairLabParameterized("fresh") | where TimeGenerated > ago(30m) | project TimeGenerated, EventId, Marker'
	delete_scheduled_rule 74444444-4444-4444-8444-444444444444 'deadair lab - auxiliary table dependency' PT5M PT30M 'DeadairAuxiliary_CL | where TimeGenerated > ago(30m) | project TimeGenerated, Marker'
	delete_scheduled_rule 76666666-6666-4666-8666-666666666666 'deadair lab - empty analytics table' PT5M PT30M 'DeadairEmptyAnalytics_CL | where TimeGenerated > ago(30m) | project TimeGenerated, Marker'
	delete_scheduled_rule "$predicate_rule_id" "$predicate_rule_display" PT5M PT30M "$predicate_rule_query"
	delete_nrt_rule
	delete_dcr
	delete_function "$base_function_id" "$base_function" "$base_function_body" ""
	delete_function "$parameterized_function_id" "$parameterized_function" "$parameterized_function_body" "$parameterized_function_parameters"
	delete_table DeadairFresh_CL Analytics four
	delete_table DeadairStale_CL Analytics four
	delete_table DeadairLag_CL Analytics four
	delete_table DeadairUnused_CL Analytics four
	delete_table DeadairPredicate_CL Analytics predicate
	delete_table DeadairBasic_CL Basic two
	delete_table DeadairAuxiliary_CL Auxiliary two
	delete_table DeadairEmptyAnalytics_CL Analytics two
	delete_table DeadairRemoved_CL Analytics four
	echo "Sentinel base fixtures removed; the resource group, workspace, Sentinel onboarding, budget, and role assignments were left intact"
}

verify_workspace_prerequisites
if [ "$mode" = apply ]; then
	verify_sentinel_onboarding
	probe_logs_query_access
	run_collision_preflight
	apply_fixtures
	exit 0
fi

cleanup_preflight
cleanup_fixtures
