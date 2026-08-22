#!/bin/sh
set -eu

# Provisions only the named base fixtures consumed by TestSentinelReadOnlyLab.
# The resource group, workspace, Sentinel onboarding, budget, provider
# registration, and provisioner identity are external prerequisites. plan is
# offline. apply, refresh-summary-proof, and cleanup require the exact
# confirmation marker below.

mode=${1:-plan}
subscription_id=${DEADAIR_AZURE_SUBSCRIPTION_ID:-}
resource_group=${DEADAIR_AZURE_RESOURCE_GROUP:-}
workspace=${DEADAIR_SENTINEL_WORKSPACE:-}
workspace_id=${DEADAIR_SENTINEL_WORKSPACE_ID:-}
confirmation=${DEADAIR_SENTINEL_BASE_LAB_CONFIRM:-}

fixture_marker=deadair-sentinel-base-validation
rule_description='Disposable Sentinel lab rule for deadair conformance testing.'
function_category='identity security lab'
dcr_name="${workspace}-dcr"
dcr_destination=labWorkspace

base_function_id=7aaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa
base_function=RecentIdentitySignIns
base_function_body='WorkforceSignIn_CL | project TimeGenerated, SignInId, UserPrincipalName, ClientIpAddress, AuthenticationResult'
parameterized_function_id=7bbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb
parameterized_function=IdentitySignInsByUser
parameterized_function_body='WorkforceSignIn_CL | where UserPrincipalName == userPrincipalName | project TimeGenerated, SignInId, UserPrincipalName, ClientIpAddress, AuthenticationResult'
parameterized_function_parameters=userPrincipalName:string

nrt_rule_id=78888888-8888-4888-8888-888888888888
nrt_display='[lab] Suspicious interactive sign-in (NRT)'
nrt_query='WorkforceSignIn_CL | where TimeGenerated < datetime(1900-01-01)'

predicate_rule_id=77777777-7777-4777-8777-777777777777
predicate_rule_display='[lab] Palo Alto firewall telemetry stopped'
predicate_rule_query="PerimeterSecurity_CL | where DeviceVendor == 'Palo Alto Networks' and DeviceProduct == 'PAN-OS' | project TimeGenerated, SessionId, DeviceVendor, DeviceProduct, SourceIpAddress, DestinationIpAddress, DestinationPort, DeviceAction"

case "$mode" in
plan|apply|refresh-summary-proof|cleanup) ;;
*)
	echo "usage: $0 [plan|apply|refresh-summary-proof|cleanup]" >&2
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
workspace_length=${#workspace}
if [ "$workspace_length" -lt 4 ] || [ "$workspace_length" -gt 26 ]; then
	echo "DEADAIR_SENTINEL_WORKSPACE must contain 4 to 26 characters so its Direct DCR name remains valid" >&2
	exit 2
fi
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
	echo "  create eight final tables; create then remove PartnerSSOAuth_CL"
	echo "  create two saved workspace functions"
	echo "  create one tagged direct-ingestion DCR: $dcr_path"
	echo "  ingest seven rows: current workforce auth, 45m SaaS lag, 90m remote-access staleness, current ADFS,"
	echo "    current FortiGate plus 90m Palo Alto network events, and one Basic firewall flow"
	echo "  create twelve Scheduled rules and one disabled NRT rule"
	echo "  create SaaSAudit_CL directly as an empty Analytics table"
	echo "  cleanup starts Azure's 15-day deleted-table recovery/name-reservation window"
	echo "  apply/refresh-summary-proof/cleanup confirmation: DEADAIR_SENTINEL_BASE_LAB_CONFIRM=$expected_confirmation"
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
trap 'rm -rf "$tmp_dir"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

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
		(if $shape == "auth" then
			([.properties.schema.columns[]? | {name, type: (.type | ascii_downcase)}] | length) == 5 and
			any(.properties.schema.columns[]?; .name == "TimeGenerated" and (.type | ascii_downcase) == "datetime") and
			any(.properties.schema.columns[]?; .name == "SignInId" and (.type | ascii_downcase) == "string") and
			any(.properties.schema.columns[]?; .name == "UserPrincipalName" and (.type | ascii_downcase) == "string") and
			any(.properties.schema.columns[]?; .name == "ClientIpAddress" and (.type | ascii_downcase) == "string") and
			any(.properties.schema.columns[]?; .name == "AuthenticationResult" and (.type | ascii_downcase) == "string")
		elif $shape == "saas_auth" then
			([.properties.schema.columns[]? | {name, type: (.type | ascii_downcase)}] | length) == 6 and
			any(.properties.schema.columns[]?; .name == "TimeGenerated" and (.type | ascii_downcase) == "datetime") and
			any(.properties.schema.columns[]?; .name == "SignInId" and (.type | ascii_downcase) == "string") and
			any(.properties.schema.columns[]?; .name == "UserPrincipalName" and (.type | ascii_downcase) == "string") and
			any(.properties.schema.columns[]?; .name == "ClientIpAddress" and (.type | ascii_downcase) == "string") and
			any(.properties.schema.columns[]?; .name == "AuthenticationResult" and (.type | ascii_downcase) == "string") and
			any(.properties.schema.columns[]?; .name == "ApplicationName" and (.type | ascii_downcase) == "string")
		elif $shape == "adfs_auth" then
			([.properties.schema.columns[]? | {name, type: (.type | ascii_downcase)}] | length) == 6 and
			any(.properties.schema.columns[]?; .name == "TimeGenerated" and (.type | ascii_downcase) == "datetime") and
			any(.properties.schema.columns[]?; .name == "SignInId" and (.type | ascii_downcase) == "string") and
			any(.properties.schema.columns[]?; .name == "UserPrincipalName" and (.type | ascii_downcase) == "string") and
			any(.properties.schema.columns[]?; .name == "ClientIpAddress" and (.type | ascii_downcase) == "string") and
			any(.properties.schema.columns[]?; .name == "AuthenticationResult" and (.type | ascii_downcase) == "string") and
			any(.properties.schema.columns[]?; .name == "RelyingParty" and (.type | ascii_downcase) == "string")
		elif $shape == "perimeter" then
			([.properties.schema.columns[]? | {name, type: (.type | ascii_downcase)}] | length) == 8 and
			any(.properties.schema.columns[]?; .name == "TimeGenerated" and (.type | ascii_downcase) == "datetime") and
			any(.properties.schema.columns[]?; .name == "SessionId" and (.type | ascii_downcase) == "string") and
			any(.properties.schema.columns[]?; .name == "DeviceVendor" and (.type | ascii_downcase) == "string") and
			any(.properties.schema.columns[]?; .name == "DeviceProduct" and (.type | ascii_downcase) == "string") and
			any(.properties.schema.columns[]?; .name == "SourceIpAddress" and (.type | ascii_downcase) == "string") and
			any(.properties.schema.columns[]?; .name == "DestinationIpAddress" and (.type | ascii_downcase) == "string") and
			any(.properties.schema.columns[]?; .name == "DestinationPort" and (.type | ascii_downcase) == "int") and
			any(.properties.schema.columns[]?; .name == "DeviceAction" and (.type | ascii_downcase) == "string")
		elif $shape == "flow" then
			([.properties.schema.columns[]? | {name, type: (.type | ascii_downcase)}] | length) == 8 and
			any(.properties.schema.columns[]?; .name == "TimeGenerated" and (.type | ascii_downcase) == "datetime") and
			any(.properties.schema.columns[]?; .name == "FlowId" and (.type | ascii_downcase) == "string") and
			any(.properties.schema.columns[]?; .name == "DeviceVendor" and (.type | ascii_downcase) == "string") and
			any(.properties.schema.columns[]?; .name == "DeviceProduct" and (.type | ascii_downcase) == "string") and
			any(.properties.schema.columns[]?; .name == "SourceIpAddress" and (.type | ascii_downcase) == "string") and
			any(.properties.schema.columns[]?; .name == "DestinationIpAddress" and (.type | ascii_downcase) == "string") and
			any(.properties.schema.columns[]?; .name == "DestinationPort" and (.type | ascii_downcase) == "int") and
			any(.properties.schema.columns[]?; .name == "DeviceAction" and (.type | ascii_downcase) == "string")
		elif $shape == "audit" then
			([.properties.schema.columns[]? | {name, type: (.type | ascii_downcase)}] | length) == 5 and
			any(.properties.schema.columns[]?; .name == "TimeGenerated" and (.type | ascii_downcase) == "datetime") and
			any(.properties.schema.columns[]?; .name == "ActivityId" and (.type | ascii_downcase) == "string") and
			any(.properties.schema.columns[]?; .name == "ActorUserPrincipalName" and (.type | ascii_downcase) == "string") and
			any(.properties.schema.columns[]?; .name == "OperationName" and (.type | ascii_downcase) == "string") and
			any(.properties.schema.columns[]?; .name == "Result" and (.type | ascii_downcase) == "string")
		elif $shape == "saas_audit" then
			([.properties.schema.columns[]? | {name, type: (.type | ascii_downcase)}] | length) == 6 and
			any(.properties.schema.columns[]?; .name == "TimeGenerated" and (.type | ascii_downcase) == "datetime") and
			any(.properties.schema.columns[]?; .name == "ActivityId" and (.type | ascii_downcase) == "string") and
			any(.properties.schema.columns[]?; .name == "ActorUserPrincipalName" and (.type | ascii_downcase) == "string") and
			any(.properties.schema.columns[]?; .name == "OperationName" and (.type | ascii_downcase) == "string") and
			any(.properties.schema.columns[]?; .name == "Result" and (.type | ascii_downcase) == "string") and
			any(.properties.schema.columns[]?; .name == "ServiceName" and (.type | ascii_downcase) == "string")
		else false end)' >/dev/null
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
		def auth_columns:
			[{name: "TimeGenerated", type: "datetime"}, {name: "SignInId", type: "string"},
			 {name: "UserPrincipalName", type: "string"}, {name: "ClientIpAddress", type: "string"},
			 {name: "AuthenticationResult", type: "string"}] | sort_by(.name);
		def saas_auth_columns:
			auth_columns + [{name: "ApplicationName", type: "string"}] | sort_by(.name);
		def adfs_auth_columns:
			auth_columns + [{name: "RelyingParty", type: "string"}] | sort_by(.name);
		def perimeter_columns:
			[{name: "TimeGenerated", type: "datetime"}, {name: "SessionId", type: "string"},
			 {name: "DeviceVendor", type: "string"}, {name: "DeviceProduct", type: "string"},
			 {name: "SourceIpAddress", type: "string"}, {name: "DestinationIpAddress", type: "string"},
			 {name: "DestinationPort", type: "int"}, {name: "DeviceAction", type: "string"}] | sort_by(.name);
		def firewall_columns:
			[{name: "TimeGenerated", type: "datetime"}, {name: "FlowId", type: "string"},
			 {name: "DeviceVendor", type: "string"}, {name: "DeviceProduct", type: "string"},
			 {name: "SourceIpAddress", type: "string"}, {name: "DestinationIpAddress", type: "string"},
			 {name: "DestinationPort", type: "int"}, {name: "DeviceAction", type: "string"}] | sort_by(.name);
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
			"Custom-WorkforceSignIn", "Custom-RemoteAccessAuth", "Custom-SaaSSignIn",
			"Custom-ADFSAuthentication", "Custom-PartnerSSOAuth", "Custom-PerimeterSecurity",
			"Custom-FirewallTrafficRaw"] | sort) and
		columns("Custom-WorkforceSignIn") == auth_columns and
		columns("Custom-RemoteAccessAuth") == auth_columns and
		columns("Custom-SaaSSignIn") == saas_auth_columns and
		columns("Custom-ADFSAuthentication") == adfs_auth_columns and
		columns("Custom-PartnerSSOAuth") == saas_auth_columns and
		columns("Custom-PerimeterSecurity") == perimeter_columns and
		columns("Custom-FirewallTrafficRaw") == firewall_columns and
		([.properties.dataFlows[]? |
			select(.destinations == [$destination] and .transformKql == "source" and
				(.streams | length) == 1 and .outputStream == (.streams[0] + "_CL") and
				((.captureOverflow // false) == false) and ((.builtInTransform // "") == ""))] | length) == 7 and
		([.properties.dataFlows[]?.outputStream] | sort) == ([
			"Custom-WorkforceSignIn_CL", "Custom-RemoteAccessAuth_CL", "Custom-SaaSSignIn_CL",
			"Custom-ADFSAuthentication_CL", "Custom-PartnerSSOAuth_CL", "Custom-PerimeterSecurity_CL",
			"Custom-FirewallTrafficRaw_CL"] | sort)' >/dev/null
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
	jq -n '{query: "print read_probe=1 | take 1"}' >"$tmp_dir/logs-query-probe.json"
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
	preflight_table WorkforceSignIn_CL Analytics auth
	preflight_table RemoteAccessAuth_CL Analytics auth
	preflight_table SaaSSignIn_CL Analytics saas_auth
	preflight_table ADFSAuthentication_CL Analytics adfs_auth
	preflight_table PerimeterSecurity_CL Analytics perimeter
	preflight_table FirewallTrafficRaw_CL Basic flow
	preflight_table IdentityAuditArchive_CL Auxiliary audit
	preflight_table SaaSAudit_CL Analytics saas_audit
	preflight_table PartnerSSOAuth_CL Analytics saas_auth
	preflight_function "$base_function_id" "$base_function" "$base_function_body" ""
	preflight_function "$parameterized_function_id" "$parameterized_function" "$parameterized_function_body" "$parameterized_function_parameters"
	preflight_dcr

	preflight_scheduled_rule 11111111-1111-4111-8111-111111111111 '[lab] Suspicious interactive sign-in' PT5M PT30M 'WorkforceSignIn_CL | where TimeGenerated > ago(30m) | project TimeGenerated, SignInId, UserPrincipalName, ClientIpAddress, AuthenticationResult'
	preflight_scheduled_rule 22222222-2222-4222-8222-222222222222 '[lab] VPN password spray' PT5M PT30M 'RemoteAccessAuth_CL | where TimeGenerated > ago(30m) | project TimeGenerated, SignInId, UserPrincipalName, ClientIpAddress, AuthenticationResult'
	preflight_scheduled_rule 33333333-3333-4333-8333-333333333333 '[lab] Cloud sign-in impossible travel' PT5M PT10M 'SaaSSignIn_CL | where TimeGenerated > ago(10m) | project TimeGenerated, SignInId, UserPrincipalName, ClientIpAddress, AuthenticationResult, ApplicationName'
	preflight_scheduled_rule 44444444-4444-4444-8444-444444444444 '[lab] Partner SSO telemetry missing' PT5M PT30M 'PartnerSSOAuth_CL | where TimeGenerated > ago(30m) | project TimeGenerated, SignInId, UserPrincipalName, ClientIpAddress, AuthenticationResult, ApplicationName'
	preflight_scheduled_rule 55555555-5555-4555-8555-555555555555 '[lab] Sign-ins across primary and partner IdPs' PT5M PT30M 'union isfuzzy=true WorkforceSignIn_CL, PartnerSSOAuth_CL | where TimeGenerated > ago(30m) | project TimeGenerated, SignInId, UserPrincipalName, ClientIpAddress, AuthenticationResult'
	preflight_scheduled_rule 66666666-6666-4666-8666-666666666666 '[lab] Interactive sign-in followed by cloud app access' PT5M PT30M 'let recentFresh = WorkforceSignIn_CL | where TimeGenerated > ago(30m); recentFresh | join kind=leftouter (SaaSSignIn_CL | where TimeGenerated > ago(30m)) on UserPrincipalName | project TimeGenerated, SignInId, UserPrincipalName, ClientIpAddress, AuthenticationResult'
	preflight_scheduled_rule 71111111-1111-4111-8111-111111111111 '[lab] Recent identity sign-ins via saved function' PT5M PT30M 'RecentIdentitySignIns | where TimeGenerated > ago(30m) | project TimeGenerated, SignInId, UserPrincipalName'
	preflight_scheduled_rule 72222222-2222-4222-8222-222222222222 '[lab] Recent identity sign-ins via function call' PT5M PT30M 'RecentIdentitySignIns() | where TimeGenerated > ago(30m) | project TimeGenerated, SignInId, UserPrincipalName'
	preflight_scheduled_rule 73333333-3333-4333-8333-333333333333 '[lab] High-risk account sign-in' PT5M PT30M 'IdentitySignInsByUser("analyst@lab.example") | where TimeGenerated > ago(30m) | project TimeGenerated, SignInId, UserPrincipalName'
	preflight_scheduled_rule 74444444-4444-4444-8444-444444444444 '[lab] Privileged identity operations in archive' PT5M PT30M 'IdentityAuditArchive_CL | where TimeGenerated > ago(30m) | project TimeGenerated, ActivityId, ActorUserPrincipalName, OperationName, Result'
	preflight_scheduled_rule 76666666-6666-4666-8666-666666666666 '[lab] Cloud audit activity stopped' PT5M PT30M 'SaaSAudit_CL | where TimeGenerated > ago(30m) | project TimeGenerated, ActivityId, ActorUserPrincipalName, OperationName, Result, ServiceName'
	preflight_scheduled_rule "$predicate_rule_id" "$predicate_rule_display" PT5M PT3H "$predicate_rule_query"
	preflight_nrt_rule

	preflight_removed=$(collection_resource "table PartnerSSOAuth_CL" "$table_collection_uri" PartnerSSOAuth_CL)
	preflight_dcr_resource=$(collection_resource "DCR $dcr_name" "$dcr_collection_uri" "$dcr_name")
	preflight_missing_rule=$(collection_resource "Scheduled rule 44444444-4444-4444-8444-444444444444" "$rule_collection_uri" 44444444-4444-4444-8444-444444444444)
	preflight_partial_rule=$(collection_resource "Scheduled rule 55555555-5555-4555-8555-555555555555" "$rule_collection_uri" 55555555-5555-4555-8555-555555555555)
	base_removed_needed=true
	if [ -z "$preflight_removed" ] && [ -n "$preflight_dcr_resource" ] && \
		[ -n "$preflight_missing_rule" ] && [ -n "$preflight_partial_rule" ]; then
		base_removed_needed=false
	fi
}

require_existing_fixture() {
	require_label=$1
	require_collection=$2
	require_name=$3
	require_resource=$(collection_resource "$require_label" "$require_collection" "$require_name")
	if [ -z "$require_resource" ]; then
		echo "refusing refresh-summary-proof: missing exact owned $require_label" >&2
		exit 2
	fi
}

strict_existing_base_preflight() {
	# The ordinary collision pass validates the complete definition of every
	# fixture that is present. This mode additionally requires the final base
	# fixture set to exist exactly; it never creates or repairs a resource.
	run_collision_preflight

	for require_table in \
		WorkforceSignIn_CL RemoteAccessAuth_CL SaaSSignIn_CL ADFSAuthentication_CL \
		PerimeterSecurity_CL FirewallTrafficRaw_CL IdentityAuditArchive_CL SaaSAudit_CL; do
		require_existing_fixture "base table $require_table" "$table_collection_uri" "$require_table"
	done
	if [ -n "$(collection_resource "removed base table PartnerSSOAuth_CL" "$table_collection_uri" PartnerSSOAuth_CL)" ]; then
		echo "refusing refresh-summary-proof: removed base table PartnerSSOAuth_CL is present" >&2
		exit 2
	fi

	require_existing_fixture "saved function $base_function" "$saved_search_collection_uri" "$base_function_id"
	require_existing_fixture "saved function $parameterized_function" "$saved_search_collection_uri" "$parameterized_function_id"
	require_existing_fixture "DCR $dcr_name" "$dcr_collection_uri" "$dcr_name"

	for require_rule_id in \
		11111111-1111-4111-8111-111111111111 \
		22222222-2222-4222-8222-222222222222 \
		33333333-3333-4333-8333-333333333333 \
		44444444-4444-4444-8444-444444444444 \
		55555555-5555-4555-8555-555555555555 \
		66666666-6666-4666-8666-666666666666 \
		71111111-1111-4111-8111-111111111111 \
		72222222-2222-4222-8222-222222222222 \
		73333333-3333-4333-8333-333333333333 \
		74444444-4444-4444-8444-444444444444 \
		76666666-6666-4666-8666-666666666666 \
		"$predicate_rule_id"; do
		require_existing_fixture "Scheduled base rule $require_rule_id" "$rule_collection_uri" "$require_rule_id"
	done
	require_existing_fixture "disabled NRT base rule $nrt_rule_id" "$rule_preview_collection_uri" "$nrt_rule_id"

	echo "existing Sentinel base fixtures verified for summary proof refresh (read only)"
}

create_table_body() {
	create_table_name=$1
	create_table_plan=$2
	create_table_shape=$3
	if [ "$create_table_shape" = auth ]; then
		jq -n --arg name "$create_table_name" --arg plan "$create_table_plan" --arg marker "$fixture_marker" '{
			properties: {plan: $plan, schema: {name: $name, description: $marker, columns: [
				{name: "TimeGenerated", type: "dateTime"},
				{name: "SignInId", type: "string"},
				{name: "UserPrincipalName", type: "string"},
				{name: "ClientIpAddress", type: "string"},
				{name: "AuthenticationResult", type: "string"}
			]}}
		}'
	elif [ "$create_table_shape" = saas_auth ]; then
		jq -n --arg name "$create_table_name" --arg plan "$create_table_plan" --arg marker "$fixture_marker" '{
			properties: {plan: $plan, schema: {name: $name, description: $marker, columns: [
				{name: "TimeGenerated", type: "dateTime"},
				{name: "SignInId", type: "string"},
				{name: "UserPrincipalName", type: "string"},
				{name: "ClientIpAddress", type: "string"},
				{name: "AuthenticationResult", type: "string"},
				{name: "ApplicationName", type: "string"}
			]}}
		}'
	elif [ "$create_table_shape" = adfs_auth ]; then
		jq -n --arg name "$create_table_name" --arg plan "$create_table_plan" --arg marker "$fixture_marker" '{
			properties: {plan: $plan, schema: {name: $name, description: $marker, columns: [
				{name: "TimeGenerated", type: "dateTime"},
				{name: "SignInId", type: "string"},
				{name: "UserPrincipalName", type: "string"},
				{name: "ClientIpAddress", type: "string"},
				{name: "AuthenticationResult", type: "string"},
				{name: "RelyingParty", type: "string"}
			]}}
		}'
	elif [ "$create_table_shape" = perimeter ]; then
		jq -n --arg name "$create_table_name" --arg plan "$create_table_plan" --arg marker "$fixture_marker" '{
			properties: {plan: $plan, schema: {name: $name, description: $marker, columns: [
				{name: "TimeGenerated", type: "dateTime"},
				{name: "SessionId", type: "string"},
				{name: "DeviceVendor", type: "string"},
				{name: "DeviceProduct", type: "string"},
				{name: "SourceIpAddress", type: "string"},
				{name: "DestinationIpAddress", type: "string"},
				{name: "DestinationPort", type: "int"},
				{name: "DeviceAction", type: "string"}
			]}}
		}'
	elif [ "$create_table_shape" = flow ]; then
		jq -n --arg name "$create_table_name" --arg plan "$create_table_plan" --arg marker "$fixture_marker" '{
			properties: {plan: $plan, schema: {name: $name, description: $marker, columns: [
				{name: "TimeGenerated", type: "dateTime"},
				{name: "FlowId", type: "string"},
				{name: "DeviceVendor", type: "string"},
				{name: "DeviceProduct", type: "string"},
				{name: "SourceIpAddress", type: "string"},
				{name: "DestinationIpAddress", type: "string"},
				{name: "DestinationPort", type: "int"},
				{name: "DeviceAction", type: "string"}
			]}}
		}'
	elif [ "$create_table_shape" = audit ]; then
		jq -n --arg name "$create_table_name" --arg plan "$create_table_plan" --arg marker "$fixture_marker" '{
			properties: {plan: $plan, schema: {name: $name, description: $marker, columns: [
				{name: "TimeGenerated", type: "dateTime"},
				{name: "ActivityId", type: "string"},
				{name: "ActorUserPrincipalName", type: "string"},
				{name: "OperationName", type: "string"},
				{name: "Result", type: "string"}
			]}}
		}'
	elif [ "$create_table_shape" = saas_audit ]; then
		jq -n --arg name "$create_table_name" --arg plan "$create_table_plan" --arg marker "$fixture_marker" '{
			properties: {plan: $plan, schema: {name: $name, description: $marker, columns: [
				{name: "TimeGenerated", type: "dateTime"},
				{name: "ActivityId", type: "string"},
				{name: "ActorUserPrincipalName", type: "string"},
				{name: "OperationName", type: "string"},
				{name: "Result", type: "string"},
				{name: "ServiceName", type: "string"}
			]}}
		}'
	else
		echo "unsupported table shape $create_table_shape" >&2
		return 2
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
				"Custom-WorkforceSignIn": {columns: [
					{name: "TimeGenerated", type: "datetime"}, {name: "SignInId", type: "string"},
					{name: "UserPrincipalName", type: "string"}, {name: "ClientIpAddress", type: "string"},
					{name: "AuthenticationResult", type: "string"}]},
				"Custom-RemoteAccessAuth": {columns: [
					{name: "TimeGenerated", type: "datetime"}, {name: "SignInId", type: "string"},
					{name: "UserPrincipalName", type: "string"}, {name: "ClientIpAddress", type: "string"},
					{name: "AuthenticationResult", type: "string"}]},
				"Custom-SaaSSignIn": {columns: [
					{name: "TimeGenerated", type: "datetime"}, {name: "SignInId", type: "string"},
					{name: "UserPrincipalName", type: "string"}, {name: "ClientIpAddress", type: "string"},
					{name: "AuthenticationResult", type: "string"}, {name: "ApplicationName", type: "string"}]},
				"Custom-ADFSAuthentication": {columns: [
					{name: "TimeGenerated", type: "datetime"}, {name: "SignInId", type: "string"},
					{name: "UserPrincipalName", type: "string"}, {name: "ClientIpAddress", type: "string"},
					{name: "AuthenticationResult", type: "string"}, {name: "RelyingParty", type: "string"}]},
				"Custom-PartnerSSOAuth": {columns: [
					{name: "TimeGenerated", type: "datetime"}, {name: "SignInId", type: "string"},
					{name: "UserPrincipalName", type: "string"}, {name: "ClientIpAddress", type: "string"},
					{name: "AuthenticationResult", type: "string"}, {name: "ApplicationName", type: "string"}]},
				"Custom-PerimeterSecurity": {columns: [
					{name: "TimeGenerated", type: "datetime"}, {name: "SessionId", type: "string"},
					{name: "DeviceVendor", type: "string"}, {name: "DeviceProduct", type: "string"},
					{name: "SourceIpAddress", type: "string"}, {name: "DestinationIpAddress", type: "string"},
					{name: "DestinationPort", type: "int"}, {name: "DeviceAction", type: "string"}]},
				"Custom-FirewallTrafficRaw": {columns: [
					{name: "TimeGenerated", type: "datetime"}, {name: "FlowId", type: "string"},
					{name: "DeviceVendor", type: "string"}, {name: "DeviceProduct", type: "string"},
					{name: "SourceIpAddress", type: "string"}, {name: "DestinationIpAddress", type: "string"},
					{name: "DestinationPort", type: "int"}, {name: "DeviceAction", type: "string"}]}
			},
			destinations: {logAnalytics: [{workspaceResourceId: $workspace, name: $destination}]},
			dataFlows: [
				{streams: ["Custom-WorkforceSignIn"], destinations: [$destination], transformKql: "source", outputStream: "Custom-WorkforceSignIn_CL"},
				{streams: ["Custom-RemoteAccessAuth"], destinations: [$destination], transformKql: "source", outputStream: "Custom-RemoteAccessAuth_CL"},
				{streams: ["Custom-SaaSSignIn"], destinations: [$destination], transformKql: "source", outputStream: "Custom-SaaSSignIn_CL"},
				{streams: ["Custom-ADFSAuthentication"], destinations: [$destination], transformKql: "source", outputStream: "Custom-ADFSAuthentication_CL"},
				{streams: ["Custom-PartnerSSOAuth"], destinations: [$destination], transformKql: "source", outputStream: "Custom-PartnerSSOAuth_CL"},
				{streams: ["Custom-PerimeterSecurity"], destinations: [$destination], transformKql: "source", outputStream: "Custom-PerimeterSecurity_CL"},
				{streams: ["Custom-FirewallTrafficRaw"], destinations: [$destination], transformKql: "source", outputStream: "Custom-FirewallTrafficRaw_CL"}
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
	wait_key=$2
	wait_value=$3
	wait_attempt=0
	jq -n --arg query "$wait_table | where $wait_key == '$wait_value' | take 1" '{query: $query}' >"$tmp_dir/query-$wait_table.json"
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
	wait_flow_id=$1
	wait_attempt=0
	jq -n --arg query "FirewallTrafficRaw_CL | where FlowId == '$wait_flow_id' and DeviceVendor == 'Fortinet' and DeviceProduct == 'FortiGate' and DeviceAction == 'Deny' | take 1" \
		'{query: $query}' >"$tmp_dir/search-FirewallTrafficRaw_CL.json"
	while [ "$wait_attempt" -lt 120 ]; do
		if wait_response=$(az rest --only-show-errors --method post --resource https://api.loganalytics.io \
			--uri "https://api.loganalytics.io/v1/workspaces/$workspace_id/search?timespan=PT30M" \
			--body "@$tmp_dir/search-FirewallTrafficRaw_CL.json" --output json 2>/dev/null); then
			wait_rows=$(printf '%s' "$wait_response" | jq '
				if ((has("error") | not) or .error == null) and
					(.tables | type) == "array" and (.tables | length) == 1 and
					(.tables[0].name == "PrimaryResult")
				then [.tables[0].rows[]?] | length else 0 end')
			if [ "$wait_rows" -gt 0 ]; then
				return 0
			fi
		fi
		wait_attempt=$((wait_attempt + 1))
		sleep 5
	done
	echo "ingested denied flow did not become searchable in FirewallTrafficRaw_CL" >&2
	return 1
}

resolve_dcr_ingestion_target() {
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
}

post_dcr_row() {
	post_stream=$1
	post_file=$2
	if ! az rest --only-show-errors --method post --resource https://monitor.azure.com \
		--uri "$dcr_ingestion_endpoint/dataCollectionRules/$dcr_immutable_id/streams/Custom-$post_stream?api-version=2023-01-01" \
		--body "@$post_file" --output none; then
		echo "Logs Ingestion failed for Custom-$post_stream; the provisioner identity needs Monitoring Metrics Publisher at the DCR or resource-group scope" >&2
		exit 2
	fi
}

ingest_base_rows() {
	resolve_dcr_ingestion_target

	ingest_epoch=$(date -u '+%s')
	fresh_event_id="fresh-$ingest_epoch"
	lag_event_id="lag-$ingest_epoch"
	stale_event_id="stale-$ingest_epoch"
	unused_event_id="unused-$ingest_epoch"
	network_current_event_id="network-current-$ingest_epoch"
	network_palo_alto_event_id="network-palo-alto-$ingest_epoch"
	flow_id="denied-flow-$ingest_epoch"
	fresh_time=$(utc_minutes_ago 0)
	lag_time=$(utc_minutes_ago 45)
	stale_time=$(utc_minutes_ago 90)

	jq -n --arg time "$fresh_time" --arg id "$fresh_event_id" \
		'[{TimeGenerated: $time, SignInId: $id, UserPrincipalName: "analyst@lab.example", ClientIpAddress: "198.51.100.10", AuthenticationResult: "Success"}]' >"$tmp_dir/ingest-fresh.json"
	jq -n --arg time "$lag_time" --arg id "$lag_event_id" \
		'[{TimeGenerated: $time, SignInId: $id, UserPrincipalName: "analyst@lab.example", ClientIpAddress: "203.0.113.20", AuthenticationResult: "Success", ApplicationName: "Microsoft 365"}]' >"$tmp_dir/ingest-lag.json"
	jq -n --arg time "$stale_time" --arg id "$stale_event_id" \
		'[{TimeGenerated: $time, SignInId: $id, UserPrincipalName: "contractor@lab.example", ClientIpAddress: "192.0.2.44", AuthenticationResult: "Failure"}]' >"$tmp_dir/ingest-stale.json"
	jq -n --arg time "$fresh_time" --arg id "$unused_event_id" \
		'[{TimeGenerated: $time, SignInId: $id, UserPrincipalName: "legacy-user@lab.example", ClientIpAddress: "192.0.2.80", AuthenticationResult: "Success", RelyingParty: "urn:example:hr"}]' >"$tmp_dir/ingest-unused.json"
	jq -n --arg current_time "$fresh_time" --arg current_id "$network_current_event_id" \
		--arg stale_time "$stale_time" --arg stale_id "$network_palo_alto_event_id" '[
			{TimeGenerated: $current_time, SessionId: $current_id, DeviceVendor: "Fortinet", DeviceProduct: "FortiGate", SourceIpAddress: "10.20.4.12", DestinationIpAddress: "198.51.100.25", DestinationPort: 443, DeviceAction: "Allow"},
			{TimeGenerated: $stale_time, SessionId: $stale_id, DeviceVendor: "Palo Alto Networks", DeviceProduct: "PAN-OS", SourceIpAddress: "10.30.8.41", DestinationIpAddress: "203.0.113.53", DestinationPort: 53, DeviceAction: "Allow"}
		]' >"$tmp_dir/ingest-predicate.json"
	jq -n --arg time "$fresh_time" --arg id "$flow_id" '[{TimeGenerated: $time, FlowId: $id, DeviceVendor: "Fortinet", DeviceProduct: "FortiGate", SourceIpAddress: "10.20.4.12", DestinationIpAddress: "198.51.100.25", DestinationPort: 22, DeviceAction: "Deny"}]' >"$tmp_dir/ingest-basic.json"

	for ingest_spec in \
		"WorkforceSignIn_CL:$tmp_dir/ingest-fresh.json" \
		"SaaSSignIn_CL:$tmp_dir/ingest-lag.json" \
		"RemoteAccessAuth_CL:$tmp_dir/ingest-stale.json" \
		"ADFSAuthentication_CL:$tmp_dir/ingest-unused.json" \
		"PerimeterSecurity_CL:$tmp_dir/ingest-predicate.json" \
		"FirewallTrafficRaw_CL:$tmp_dir/ingest-basic.json"; do
		ingest_stream=${ingest_spec%%:*}
		ingest_file=${ingest_spec#*:}
		ingest_input=${ingest_stream%_CL}
		post_dcr_row "$ingest_input" "$ingest_file"
	done

	wait_for_ingested_row WorkforceSignIn_CL SignInId "$fresh_event_id"
	wait_for_ingested_row SaaSSignIn_CL SignInId "$lag_event_id"
	wait_for_ingested_row RemoteAccessAuth_CL SignInId "$stale_event_id"
	wait_for_ingested_row ADFSAuthentication_CL SignInId "$unused_event_id"
	wait_for_ingested_row PerimeterSecurity_CL SessionId "$network_current_event_id"
	wait_for_ingested_row PerimeterSecurity_CL SessionId "$network_palo_alto_event_id"
	wait_for_basic_ingested_row "$flow_id"
}

ingest_summary_proof_row() {
	proof_table_resource=$(stable_resource_json "$(table_uri FirewallTrafficRaw_CL)" "table FirewallTrafficRaw_CL")
	if ! table_matches "$proof_table_resource" FirewallTrafficRaw_CL Basic flow; then
		echo "refusing summary proof ingestion: FirewallTrafficRaw_CL no longer matches its exact base fixture definition" >&2
		exit 2
	fi
	resolve_dcr_ingestion_target

	proof_epoch=$(date -u '+%s')
	proof_flow_id="denied-flow-$proof_epoch$$"
	proof_time=$(utc_minutes_ago 0)
	jq -n --arg time "$proof_time" --arg id "$proof_flow_id" '[{
		TimeGenerated: $time,
		FlowId: $id,
		DeviceVendor: "Fortinet",
		DeviceProduct: "FortiGate",
		SourceIpAddress: "10.20.4.12",
		DestinationIpAddress: "198.51.100.25",
		DestinationPort: 22,
		DeviceAction: "Deny"
	}]' >"$tmp_dir/ingest-summary-proof.json"

	post_dcr_row FirewallTrafficRaw "$tmp_dir/ingest-summary-proof.json"
	wait_for_basic_ingested_row "$proof_flow_id"
	echo "current summary proof row is searchable in FirewallTrafficRaw_CL (FlowId=$proof_flow_id)"
}

apply_fixtures() {
	ensure_table WorkforceSignIn_CL Analytics auth
	ensure_table RemoteAccessAuth_CL Analytics auth
	ensure_table SaaSSignIn_CL Analytics saas_auth
	ensure_table ADFSAuthentication_CL Analytics adfs_auth
	ensure_table PerimeterSecurity_CL Analytics perimeter
	ensure_table FirewallTrafficRaw_CL Basic flow
	ensure_table IdentityAuditArchive_CL Auxiliary audit
	ensure_table SaaSAudit_CL Analytics saas_audit
	if [ "$base_removed_needed" = true ]; then
		ensure_table PartnerSSOAuth_CL Analytics saas_auth
	fi

	ensure_function "$base_function_id" "$base_function" "$base_function_body" ""
	ensure_function "$parameterized_function_id" "$parameterized_function" "$parameterized_function_body" "$parameterized_function_parameters"
	ensure_dcr
	ingest_base_rows

	ensure_scheduled_rule 11111111-1111-4111-8111-111111111111 '[lab] Suspicious interactive sign-in' PT5M PT30M 'WorkforceSignIn_CL | where TimeGenerated > ago(30m) | project TimeGenerated, SignInId, UserPrincipalName, ClientIpAddress, AuthenticationResult'
	ensure_scheduled_rule 22222222-2222-4222-8222-222222222222 '[lab] VPN password spray' PT5M PT30M 'RemoteAccessAuth_CL | where TimeGenerated > ago(30m) | project TimeGenerated, SignInId, UserPrincipalName, ClientIpAddress, AuthenticationResult'
	ensure_scheduled_rule 33333333-3333-4333-8333-333333333333 '[lab] Cloud sign-in impossible travel' PT5M PT10M 'SaaSSignIn_CL | where TimeGenerated > ago(10m) | project TimeGenerated, SignInId, UserPrincipalName, ClientIpAddress, AuthenticationResult, ApplicationName'
	ensure_scheduled_rule 44444444-4444-4444-8444-444444444444 '[lab] Partner SSO telemetry missing' PT5M PT30M 'PartnerSSOAuth_CL | where TimeGenerated > ago(30m) | project TimeGenerated, SignInId, UserPrincipalName, ClientIpAddress, AuthenticationResult, ApplicationName'
	ensure_scheduled_rule 55555555-5555-4555-8555-555555555555 '[lab] Sign-ins across primary and partner IdPs' PT5M PT30M 'union isfuzzy=true WorkforceSignIn_CL, PartnerSSOAuth_CL | where TimeGenerated > ago(30m) | project TimeGenerated, SignInId, UserPrincipalName, ClientIpAddress, AuthenticationResult'
	ensure_scheduled_rule 66666666-6666-4666-8666-666666666666 '[lab] Interactive sign-in followed by cloud app access' PT5M PT30M 'let recentFresh = WorkforceSignIn_CL | where TimeGenerated > ago(30m); recentFresh | join kind=leftouter (SaaSSignIn_CL | where TimeGenerated > ago(30m)) on UserPrincipalName | project TimeGenerated, SignInId, UserPrincipalName, ClientIpAddress, AuthenticationResult'
	ensure_scheduled_rule 71111111-1111-4111-8111-111111111111 '[lab] Recent identity sign-ins via saved function' PT5M PT30M 'RecentIdentitySignIns | where TimeGenerated > ago(30m) | project TimeGenerated, SignInId, UserPrincipalName'
	ensure_scheduled_rule 72222222-2222-4222-8222-222222222222 '[lab] Recent identity sign-ins via function call' PT5M PT30M 'RecentIdentitySignIns() | where TimeGenerated > ago(30m) | project TimeGenerated, SignInId, UserPrincipalName'
	ensure_scheduled_rule 73333333-3333-4333-8333-333333333333 '[lab] High-risk account sign-in' PT5M PT30M 'IdentitySignInsByUser("analyst@lab.example") | where TimeGenerated > ago(30m) | project TimeGenerated, SignInId, UserPrincipalName'
	ensure_scheduled_rule 74444444-4444-4444-8444-444444444444 '[lab] Privileged identity operations in archive' PT5M PT30M 'IdentityAuditArchive_CL | where TimeGenerated > ago(30m) | project TimeGenerated, ActivityId, ActorUserPrincipalName, OperationName, Result'
	ensure_scheduled_rule 76666666-6666-4666-8666-666666666666 '[lab] Cloud audit activity stopped' PT5M PT30M 'SaaSAudit_CL | where TimeGenerated > ago(30m) | project TimeGenerated, ActivityId, ActorUserPrincipalName, OperationName, Result, ServiceName'
	ensure_scheduled_rule "$predicate_rule_id" "$predicate_rule_display" PT5M PT3H "$predicate_rule_query"
	ensure_nrt_rule

	removed_resource=$(collection_resource "table PartnerSSOAuth_CL" "$table_collection_uri" PartnerSSOAuth_CL)
	if [ -n "$removed_resource" ]; then
		removed_resource=$(stable_resource_json "$(table_uri PartnerSSOAuth_CL)" "table PartnerSSOAuth_CL")
		if ! table_matches "$removed_resource" PartnerSSOAuth_CL Analytics saas_auth; then
			echo "refusing final Removed-table deletion: the complete fixture definition changed during apply" >&2
			exit 2
		fi
		az rest --only-show-errors --method delete --uri "$(table_uri PartnerSSOAuth_CL)" --output none
		wait_for_collection_absence "$table_collection_uri" PartnerSSOAuth_CL "table PartnerSSOAuth_CL"
	fi

	final_empty_analytics=$(collection_resource "table SaaSAudit_CL" "$table_collection_uri" SaaSAudit_CL)
	if ! table_matches "$final_empty_analytics" SaaSAudit_CL Analytics saas_audit; then
		echo "base fixture apply ended without the exact empty Analytics table" >&2
		exit 2
	fi
	if [ -n "$(collection_resource "table PartnerSSOAuth_CL" "$table_collection_uri" PartnerSSOAuth_CL)" ]; then
		echo "base fixture apply ended with PartnerSSOAuth_CL still present" >&2
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
	delete_scheduled_rule 11111111-1111-4111-8111-111111111111 '[lab] Suspicious interactive sign-in' PT5M PT30M 'WorkforceSignIn_CL | where TimeGenerated > ago(30m) | project TimeGenerated, SignInId, UserPrincipalName, ClientIpAddress, AuthenticationResult'
	delete_scheduled_rule 22222222-2222-4222-8222-222222222222 '[lab] VPN password spray' PT5M PT30M 'RemoteAccessAuth_CL | where TimeGenerated > ago(30m) | project TimeGenerated, SignInId, UserPrincipalName, ClientIpAddress, AuthenticationResult'
	delete_scheduled_rule 33333333-3333-4333-8333-333333333333 '[lab] Cloud sign-in impossible travel' PT5M PT10M 'SaaSSignIn_CL | where TimeGenerated > ago(10m) | project TimeGenerated, SignInId, UserPrincipalName, ClientIpAddress, AuthenticationResult, ApplicationName'
	delete_scheduled_rule 44444444-4444-4444-8444-444444444444 '[lab] Partner SSO telemetry missing' PT5M PT30M 'PartnerSSOAuth_CL | where TimeGenerated > ago(30m) | project TimeGenerated, SignInId, UserPrincipalName, ClientIpAddress, AuthenticationResult, ApplicationName'
	delete_scheduled_rule 55555555-5555-4555-8555-555555555555 '[lab] Sign-ins across primary and partner IdPs' PT5M PT30M 'union isfuzzy=true WorkforceSignIn_CL, PartnerSSOAuth_CL | where TimeGenerated > ago(30m) | project TimeGenerated, SignInId, UserPrincipalName, ClientIpAddress, AuthenticationResult'
	delete_scheduled_rule 66666666-6666-4666-8666-666666666666 '[lab] Interactive sign-in followed by cloud app access' PT5M PT30M 'let recentFresh = WorkforceSignIn_CL | where TimeGenerated > ago(30m); recentFresh | join kind=leftouter (SaaSSignIn_CL | where TimeGenerated > ago(30m)) on UserPrincipalName | project TimeGenerated, SignInId, UserPrincipalName, ClientIpAddress, AuthenticationResult'
	delete_scheduled_rule 71111111-1111-4111-8111-111111111111 '[lab] Recent identity sign-ins via saved function' PT5M PT30M 'RecentIdentitySignIns | where TimeGenerated > ago(30m) | project TimeGenerated, SignInId, UserPrincipalName'
	delete_scheduled_rule 72222222-2222-4222-8222-222222222222 '[lab] Recent identity sign-ins via function call' PT5M PT30M 'RecentIdentitySignIns() | where TimeGenerated > ago(30m) | project TimeGenerated, SignInId, UserPrincipalName'
	delete_scheduled_rule 73333333-3333-4333-8333-333333333333 '[lab] High-risk account sign-in' PT5M PT30M 'IdentitySignInsByUser("analyst@lab.example") | where TimeGenerated > ago(30m) | project TimeGenerated, SignInId, UserPrincipalName'
	delete_scheduled_rule 74444444-4444-4444-8444-444444444444 '[lab] Privileged identity operations in archive' PT5M PT30M 'IdentityAuditArchive_CL | where TimeGenerated > ago(30m) | project TimeGenerated, ActivityId, ActorUserPrincipalName, OperationName, Result'
	delete_scheduled_rule 76666666-6666-4666-8666-666666666666 '[lab] Cloud audit activity stopped' PT5M PT30M 'SaaSAudit_CL | where TimeGenerated > ago(30m) | project TimeGenerated, ActivityId, ActorUserPrincipalName, OperationName, Result, ServiceName'
	delete_scheduled_rule "$predicate_rule_id" "$predicate_rule_display" PT5M PT3H "$predicate_rule_query"
	delete_nrt_rule
	delete_dcr
	delete_function "$base_function_id" "$base_function" "$base_function_body" ""
	delete_function "$parameterized_function_id" "$parameterized_function" "$parameterized_function_body" "$parameterized_function_parameters"
	delete_table WorkforceSignIn_CL Analytics auth
	delete_table RemoteAccessAuth_CL Analytics auth
	delete_table SaaSSignIn_CL Analytics saas_auth
	delete_table ADFSAuthentication_CL Analytics adfs_auth
	delete_table PerimeterSecurity_CL Analytics perimeter
	delete_table FirewallTrafficRaw_CL Basic flow
	delete_table IdentityAuditArchive_CL Auxiliary audit
	delete_table SaaSAudit_CL Analytics saas_audit
	delete_table PartnerSSOAuth_CL Analytics saas_auth
	echo "Sentinel base fixtures removed; the resource group, workspace, Sentinel onboarding, budget, and role assignments were left intact"
}

verify_workspace_prerequisites
if [ "$mode" = apply ] || [ "$mode" = refresh-summary-proof ]; then
	verify_sentinel_onboarding
	probe_logs_query_access

	if [ "$mode" = refresh-summary-proof ]; then
		strict_existing_base_preflight
		ingest_summary_proof_row
		exit 0
	fi

	run_collision_preflight
	apply_fixtures
	exit 0
fi

cleanup_preflight
cleanup_fixtures
