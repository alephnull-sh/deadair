#!/bin/sh
set -eu

# Prepares only the disposable fixtures added by the Sentinel expansion test.
# The default mode is plan. apply and cleanup require an explicit confirmation
# value and always target the named child resources below.

mode=${1:-plan}
subscription_id=${DEADAIR_AZURE_SUBSCRIPTION_ID:-}
resource_group=${DEADAIR_AZURE_RESOURCE_GROUP:-}
workspace=${DEADAIR_SENTINEL_WORKSPACE:-}
remote_workspace=${DEADAIR_SENTINEL_REMOTE_WORKSPACE:-}
remote_workspace_id_env=${DEADAIR_SENTINEL_REMOTE_WORKSPACE_ID:-}
confirmation=${DEADAIR_SENTINEL_LAB_CONFIRM:-}

watchlist_alias=DeadairVIPs
watchlist_source=deadair-sentinel-expansion-fixture.csv
remote_table=DeadairRemote_CL
summary_rule=deadair-basic-summary
summary_table=DeadairBasicSummary_CL
summary_display=deadair-basic-summary
summary_query='DeadairBasic_CL | summarize EventCount=count() | extend Marker="deadair-summary-runtime"'
summary_diagnostic_setting=deadair-summary-runtime
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

if [ "$mode" = predicate-test ]; then
	resource_group=${resource_group:-deadair-sentinel-lab}
	workspace=${workspace:-deadair-sentinel-lab}
	remote_workspace=${remote_workspace:-deadair-sentinel-remote}
fi

if [ -z "$subscription_id" ] || [ -z "$resource_group" ] || [ -z "$workspace" ] || [ -z "$remote_workspace" ]; then
	echo "DEADAIR_AZURE_SUBSCRIPTION_ID, DEADAIR_AZURE_RESOURCE_GROUP, DEADAIR_SENTINEL_WORKSPACE, and DEADAIR_SENTINEL_REMOTE_WORKSPACE are required" >&2
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
summary_diagnostic_path="$workspace_path/providers/Microsoft.Insights/diagnosticSettings/$summary_diagnostic_setting"
remote_table_path="$remote_path/tables/$remote_table"
sentinel_path="$workspace_path/providers/Microsoft.SecurityInsights"

watchlist_uri="https://management.azure.com$watchlist_path?api-version=2025-09-01"
summary_uri="https://management.azure.com$summary_path?api-version=2025-07-01"
summary_table_uri="https://management.azure.com$summary_table_path?api-version=2025-07-01"
summary_diagnostic_uri="https://management.azure.com$summary_diagnostic_path?api-version=2021-05-01-preview"
remote_uri="https://management.azure.com$remote_path?api-version=2025-07-01"
remote_onboarding_uri="https://management.azure.com$remote_onboarding_path?api-version=2025-09-01"
remote_table_uri="https://management.azure.com$remote_table_path?api-version=2025-07-01"
watchlist_collection_uri="https://management.azure.com$workspace_path/providers/Microsoft.SecurityInsights/watchlists?api-version=2025-09-01"
summary_collection_uri="https://management.azure.com$workspace_path/summaryLogs?api-version=2025-07-01"
summary_diagnostic_collection_uri="https://management.azure.com$workspace_path/providers/Microsoft.Insights/diagnosticSettings?api-version=2021-05-01-preview"
summary_diagnostic_category_uri="https://management.azure.com$workspace_path/providers/Microsoft.Insights/diagnosticSettingsCategories?api-version=2021-05-01-preview"
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
		def columns:
			[.properties.schema.columns[]? | {name, type: (.type | ascii_downcase)}] | sort_by(.name);
		def query_columns:
			[{name: "TimeGenerated", type: "datetime"}, {name: "EventCount", type: "long"},
			 {name: "Marker", type: "string"}] | sort_by(.name);
		def service_columns:
			[{name: "_RuleName", type: "string"}, {name: "_RuleLastModifiedTime", type: "datetime"},
			 {name: "_BinSize", type: "long"}, {name: "_BinStartTime", type: "datetime"}];
		(((.id // "") | ascii_downcase) == ($id | ascii_downcase)) and
		(.name == $table) and
		(((.type // "microsoft.operationalinsights/workspaces/tables") | ascii_downcase) ==
			"microsoft.operationalinsights/workspaces/tables") and
		(.properties.provisioningState == "Succeeded") and
		(.properties.plan == "Analytics") and
		(.properties.schema.name == $table) and
		(.properties.schema.description == $description) and
		(columns == query_columns or columns == ((query_columns + service_columns) | sort_by(.name)))' >/dev/null
}

summary_rule_matches() {
	printf '%s' "$1" | jq -e \
		--arg id "$summary_path" --arg name "$summary_rule" \
		--arg marker "$fixture_marker" --arg display "$summary_display" \
		--arg query "$summary_query" --arg destination "$summary_table" '
		(((.id // "") | ascii_downcase) == ($id | ascii_downcase)) and
		(.name == $name) and
		(((.type // "microsoft.operationalinsights/workspaces/summarylogs") | ascii_downcase) ==
			"microsoft.operationalinsights/workspaces/summarylogs") and
		(.properties.provisioningState == "Succeeded") and
		(.properties.isActive == true) and
		(.properties.displayName == $display) and
		(.properties.description == $marker) and
		(.properties.ruleType == "User") and
		(.properties.ruleDefinition.query == $query) and
		(.properties.ruleDefinition.destinationTable == $destination) and
		(.properties.ruleDefinition.binSize == 20) and
		(.properties.ruleDefinition.binDelay == 5) and
		(.properties.ruleDefinition.timeSelector == "TimeGenerated")' >/dev/null
}

summary_diagnostic_matches() {
	printf '%s' "$1" | jq -e \
		--arg id "$summary_diagnostic_path" --arg name "$summary_diagnostic_setting" \
		--arg workspace "$workspace_path" '
		def disabled_retention:
			(if has("retentionPolicy") then
				.retentionPolicy.enabled == false and .retentionPolicy.days == 0
			 else true end);
		def requested_logs:
			([.properties.logs[]?] | length) == 1 and
			(.properties.logs[0].category == "SummaryLogs") and
			(.properties.logs[0].enabled == true) and
			((.properties.logs[0].categoryGroup // "") == "") and
			(.properties.logs[0] | disabled_retention);
		def normalized_logs:
			([.properties.logs[]?] | length) == 3 and
			([.properties.logs[]?.category] | sort) == ["Audit", "Jobs", "SummaryLogs"] and
			all(.properties.logs[]?;
				((.categoryGroup // "") == "") and disabled_retention and
				(if .category == "SummaryLogs" then .enabled == true else .enabled == false end));
		def normalized_metrics:
			([.properties.metrics[]?] | length) == 0 or
			(([.properties.metrics[]?] | length) == 1 and
			 .properties.metrics[0].category == "AllMetrics" and
			 .properties.metrics[0].enabled == false and
			 (.properties.metrics[0] | disabled_retention));
		(((.id // "") | ascii_downcase) == ($id | ascii_downcase)) and
		(.name == $name) and
		(((.type // "") | ascii_downcase) == "microsoft.insights/diagnosticsettings") and
		(((.properties.workspaceId // "") | ascii_downcase) == ($workspace | ascii_downcase)) and
		((.properties.logAnalyticsDestinationType // "") == "" or
		 .properties.logAnalyticsDestinationType == "Dedicated") and
		(requested_logs or normalized_logs) and
		normalized_metrics and
		((.properties.storageAccountId // "") == "") and
		((.properties.eventHubAuthorizationRuleId // "") == "") and
		((.properties.eventHubName // "") == "") and
		((.properties.serviceBusRuleId // "") == "") and
		((.properties.marketplacePartnerId // "") == "")' >/dev/null
}

summary_diagnostic_category_matches() {
	printf '%s' "$1" | jq -e \
		--arg id "$workspace_path/providers/Microsoft.Insights/diagnosticSettingsCategories/SummaryLogs" '
		([.value[]? | select(.name == "SummaryLogs")] | length) == 1 and
		([.value[]? | select(.name == "SummaryLogs")][0] |
			(((.id // "") | ascii_downcase) == ($id | ascii_downcase)) and
			(((.type // "") | ascii_downcase) == "microsoft.insights/diagnosticsettingscategories") and
			(.properties.categoryType == "Logs"))' >/dev/null
}

summary_runtime_response_matches() {
	printf '%s' "$1" | jq -e --arg rule "$summary_rule" --arg revision "$2" '
		def epoch:
			try (sub("\\.[0-9]+Z$"; "Z") | fromdateiso8601) catch null;
		($revision | epoch) as $revision_epoch |
		((has("error") | not) or .error == null) and
		(.tables | type) == "array" and (.tables | length) == 1 and
		(.tables[0].name == "PrimaryResult") and
		(.tables[0].columns | type) == "array" and
		([.tables[0].columns[]? | {name, type: (.type | ascii_downcase)}] == [
			{name: "RuleName", type: "string"},
			{name: "TimeGenerated", type: "datetime"},
			{name: "Status", type: "string"},
			{name: "QueryDurationMs", type: "long"},
			{name: "ResultsRecordCount", type: "long"},
			{name: "RuleLastModifiedTime", type: "datetime"},
			{name: "Message", type: "string"}
		]) and
		([.tables[0].rows[]?] | length) == 1 and
		(.tables[0].rows[0] | length) == 7 and
		(.tables[0].rows[0] as $row |
			($revision_epoch != null) and
			($row[0] == $rule) and
			($row[1] | epoch) != null and (($row[1] | epoch) >= $revision_epoch) and
			($row[2] == "Succeeded") and
			(($row[3] | type) == "number") and $row[3] >= 0 and
			(($row[4] | type) == "number") and $row[4] == 1 and
			($row[5] | epoch) != null and (($row[5] | epoch) <= ($row[1] | epoch)) and
			(($row[5] | epoch) + 30 >= $revision_epoch) and
			($row[6] == null or (($row[6] | type) == "string" and ($row[6] | test("^\\s*$")))))' >/dev/null
}

summary_runtime_response_state() {
	printf '%s' "$1" | jq -r '
		if (.tables | type) != "array" or (.tables | length) != 1 or
			(.tables[0].rows | type) != "array" then
			"malformed Logs API response"
		elif (.tables[0].rows | length) == 0 then
			"no completed LASummaryLogs row for the owned summary rule"
		elif (.tables[0].rows | length) != 1 or (.tables[0].rows[0] | length) != 7 then
			"ambiguous or malformed LASummaryLogs rows"
		else
			.tables[0].rows[0] |
			"latest row: status=\(.[2]) result_count=\(.[4]) duration_ms=\(.[3]) run=\(.[1]) native_rule_time=\(.[5])"
		end' 2>/dev/null || printf '%s' "malformed Logs API response"
}

logs_primary_result_envelope_matches() {
	printf '%s' "$1" | jq -e '
		((has("error") | not) or .error == null) and
		(.tables | type) == "array" and (.tables | length) == 1 and
		(.tables[0].name == "PrimaryResult") and
		(.tables[0].columns | type) == "array" and
		(.tables[0].rows | type) == "array"' >/dev/null
}

basic_data_response_matches() {
	printf '%s' "$1" | jq -e '
		((has("error") | not) or .error == null) and
		(.tables | type) == "array" and (.tables | length) == 1 and
		(.tables[0].name == "PrimaryResult") and
		(.tables[0].columns | type) == "array" and
		([.tables[0].columns[]? | {name, type: (.type | ascii_downcase)}] == [
			{name: "TimeGenerated", type: "datetime"},
			{name: "Marker", type: "string"}
		]) and
		(.tables[0].rows | type) == "array" and (.tables[0].rows | length) == 1 and
		(.tables[0].rows[0] | length) == 2 and
		(.tables[0].rows[0][0] | type) == "string" and
		(.tables[0].rows[0][0] |
			try (sub("\\.[0-9]+Z$"; "Z") | fromdateiso8601) catch null) != null and
		(.tables[0].rows[0][1] | type) == "string" and
		(.tables[0].rows[0][1] | test("^summary-source-[0-9]+$"))' >/dev/null
}

summary_output_response_matches() {
	printf '%s' "$1" | jq -e --arg rule "$summary_rule" --arg marker "deadair-summary-runtime" \
		--arg revision "$2" '
		def epoch:
			try (sub("\\.[0-9]+Z$"; "Z") | fromdateiso8601) catch null;
		($revision | epoch) as $revision_epoch |
		((has("error") | not) or .error == null) and
		($revision_epoch != null) and
		(.tables | type) == "array" and (.tables | length) == 1 and
		(.tables[0].name == "PrimaryResult") and
		(.tables[0].columns | type) == "array" and
		([.tables[0].columns[]? | {name, type: (.type | ascii_downcase)}] == [
			{name: "TimeGenerated", type: "datetime"},
			{name: "EventCount", type: "long"},
			{name: "Marker", type: "string"},
			{name: "RuleName", type: "string"},
			{name: "RuleModifiedAt", type: "datetime"},
			{name: "BinSize", type: "long"},
			{name: "BinStartTime", type: "datetime"}
		]) and
		(.tables[0].rows | type) == "array" and (.tables[0].rows | length) == 1 and
		(.tables[0].rows[0] | length) == 7 and
		(.tables[0].rows[0] as $row |
			($row[0] | type) == "string" and ($row[0] | epoch) != null and
			($row[1] | type) == "number" and $row[1] > 0 and ($row[1] | floor) == $row[1] and
			($row[2] == $marker) and ($row[3] == $rule) and
			($row[4] | type) == "string" and ($row[4] | epoch) != null and
			(($row[4] | epoch) >= ($revision_epoch - 30)) and
			(($row[4] | epoch) <= ($revision_epoch + 30)) and
			($row[5] == 20) and
			($row[6] | type) == "string" and ($row[6] | epoch) != null)' >/dev/null
}

summary_source_response_matches() {
	printf '%s' "$1" | jq -e --argjson expected "$2" '
		((has("error") | not) or .error == null) and
		($expected | type) == "number" and $expected > 0 and ($expected | floor) == $expected and
		(.tables | type) == "array" and (.tables | length) == 1 and
		(.tables[0].name == "PrimaryResult") and
		(.tables[0].columns | type) == "array" and
		([.tables[0].columns[]? | {name, type: (.type | ascii_downcase)}] == [
			{name: "SourceEventCount", type: "long"},
			{name: "SourceMarker", type: "string"}
		]) and
		(.tables[0].rows | type) == "array" and (.tables[0].rows | length) == 1 and
		(.tables[0].rows[0] | length) == 2 and
		(.tables[0].rows[0][0] | type) == "number" and
		(.tables[0].rows[0][0] > 0) and (.tables[0].rows[0][0] == $expected) and
		((.tables[0].rows[0][0] | floor) == .tables[0].rows[0][0]) and
		(.tables[0].rows[0][1] | type) == "string" and
		(.tables[0].rows[0][1] | test("^summary-source-[0-9]+$"))' >/dev/null
}

expect_predicate_accepts() {
	label=$1
	predicate=$2
	resource=$3
	if [ "$#" -eq 4 ]; then
		predicate_arg=$4
		if "$predicate" "$resource" "$predicate_arg"; then
			return 0
		fi
	elif "$predicate" "$resource"; then
		return 0
	fi
	echo "predicate regression: $label was rejected" >&2
	return 1
}

expect_predicate_rejects() {
	label=$1
	predicate=$2
	resource=$3
	if [ "$#" -eq 4 ]; then
		predicate_arg=$4
		if ! "$predicate" "$resource" "$predicate_arg"; then
			return 0
		fi
	elif ! "$predicate" "$resource"; then
		return 0
	fi
	echo "predicate regression: $label was accepted" >&2
	return 1
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
		id: $id, name: $table, type: "Microsoft.OperationalInsights/workspaces/tables",
		properties: {
			provisioningState: "Succeeded",
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
	expect_predicate_accepts "summary table with Azure-omitted type" summary_table_matches \
		"$(printf '%s' "$summary" | jq -c 'del(.type)')"
	expect_predicate_rejects "summary table with another resource type" summary_table_matches \
		"$(printf '%s' "$summary" | jq -c '.type = "Microsoft.OperationalInsights/workspaces/savedSearches"')"
	expect_predicate_rejects "summary table with an unrelated extra column" summary_table_matches \
		"$(printf '%s' "$summary" | jq -c '.properties.schema.columns += [{name: "Extra", type: "string"}]')"
	expect_predicate_rejects "summary table with a wrong column type" summary_table_matches \
		"$(printf '%s' "$summary" | jq -c '(.properties.schema.columns[] | select(.name == "EventCount")).type = "string"')"
	expect_predicate_rejects "summary table that is not settled" summary_table_matches \
		"$(printf '%s' "$summary" | jq -c '.properties.provisioningState = "Updating"')"
	summary_with_service=$(printf '%s' "$summary" | jq -c '.properties.schema.columns += [
		{name: "_RuleName", type: "string"},
		{name: "_RuleLastModifiedTime", type: "dateTime"},
		{name: "_BinSize", type: "long"},
		{name: "_BinStartTime", type: "dateTime"}
	]')
	expect_predicate_accepts "summary table with documented service columns" summary_table_matches "$summary_with_service"
	expect_predicate_rejects "summary table with incomplete service columns" summary_table_matches \
		"$(printf '%s' "$summary_with_service" | jq -c 'del(.properties.schema.columns[-1])')"
	expect_predicate_rejects "summary table with wrong service-column type" summary_table_matches \
		"$(printf '%s' "$summary_with_service" | jq -c '(.properties.schema.columns[] | select(.name == "_BinSize")).type = "int"')"

	summary_rule_resource=$(jq -cn \
		--arg id "$summary_path" --arg name "$summary_rule" --arg marker "$fixture_marker" \
		--arg display "$summary_display" --arg query "$summary_query" --arg destination "$summary_table" '{
		id: $id, name: $name, type: "Microsoft.OperationalInsights/workspaces/summaryLogs",
		properties: {
			provisioningState: "Succeeded", isActive: true, displayName: $display,
			description: $marker, ruleType: "User",
			ruleDefinition: {
				query: $query, destinationTable: $destination, binSize: 20,
				binDelay: 5, timeSelector: "TimeGenerated"
			}
		}
	}')
	expect_predicate_accepts "exact active summary rule" summary_rule_matches "$summary_rule_resource"
	expect_predicate_accepts "active summary rule with Azure-omitted type" summary_rule_matches \
		"$(printf '%s' "$summary_rule_resource" | jq -c 'del(.type)')"
	expect_predicate_rejects "summary rule with another resource type" summary_rule_matches \
		"$(printf '%s' "$summary_rule_resource" | jq -c '.type = "Microsoft.OperationalInsights/workspaces/savedSearches"')"
	expect_predicate_rejects "summary rule with another query" summary_rule_matches \
		"$(printf '%s' "$summary_rule_resource" | jq -c '.properties.ruleDefinition.query = "Other_CL | count"')"
	expect_predicate_rejects "inactive summary rule" summary_rule_matches \
		"$(printf '%s' "$summary_rule_resource" | jq -c '.properties.isActive = false')"

	diagnostic=$(jq -cn --arg id "$summary_diagnostic_path" --arg name "$summary_diagnostic_setting" \
		--arg workspace "$workspace_path" '{
		id: $id, name: $name, type: "Microsoft.Insights/diagnosticSettings",
		properties: {
			workspaceId: $workspace, logAnalyticsDestinationType: "Dedicated",
			logs: [{category: "SummaryLogs", enabled: true}], metrics: []
		}
	}')
	expect_predicate_accepts "exact SummaryLogs diagnostic setting" summary_diagnostic_matches "$diagnostic"
	expect_predicate_accepts "diagnostic setting with disabled zero-day retention normalization" summary_diagnostic_matches \
		"$(printf '%s' "$diagnostic" | jq -c '.properties.logs[0].retentionPolicy = {enabled: false, days: 0}')"
	normalized_diagnostic=$(printf '%s' "$diagnostic" | jq -c '
		.properties.logAnalyticsDestinationType = null |
		.properties.logs = [
			{category: "SummaryLogs", categoryGroup: null, enabled: true, retentionPolicy: {enabled: false, days: 0}},
			{category: "Audit", categoryGroup: null, enabled: false, retentionPolicy: {enabled: false, days: 0}},
			{category: "Jobs", categoryGroup: null, enabled: false, retentionPolicy: {enabled: false, days: 0}}
		] |
		.properties.metrics = [
			{category: "AllMetrics", enabled: false, retentionPolicy: {enabled: false, days: 0}}
		]')
	expect_predicate_accepts "Azure-normalized SummaryLogs diagnostic setting" summary_diagnostic_matches "$normalized_diagnostic"
	expect_predicate_rejects "normalized diagnostic setting with enabled Audit" summary_diagnostic_matches \
		"$(printf '%s' "$normalized_diagnostic" | jq -c '(.properties.logs[] | select(.category == "Audit")).enabled = true')"
	expect_predicate_rejects "normalized diagnostic setting with an unknown disabled category" summary_diagnostic_matches \
		"$(printf '%s' "$normalized_diagnostic" | jq -c '.properties.logs += [{category: "Future", enabled: false}]')"
	expect_predicate_rejects "normalized diagnostic setting with enabled metrics" summary_diagnostic_matches \
		"$(printf '%s' "$normalized_diagnostic" | jq -c '.properties.metrics[0].enabled = true')"
	expect_predicate_rejects "diagnostic setting with another log category" summary_diagnostic_matches \
		"$(printf '%s' "$diagnostic" | jq -c '.properties.logs += [{category: "Audit", enabled: true}]')"
	expect_predicate_rejects "diagnostic setting with a category group" summary_diagnostic_matches \
		"$(printf '%s' "$diagnostic" | jq -c '.properties.logs[0].categoryGroup = "allLogs"')"
	expect_predicate_rejects "diagnostic setting with another workspace destination" summary_diagnostic_matches \
		"$(printf '%s' "$diagnostic" | jq -c '.properties.workspaceId = "/subscriptions/other/workspaces/other"')"
	expect_predicate_rejects "diagnostic setting without Dedicated mode" summary_diagnostic_matches \
		"$(printf '%s' "$diagnostic" | jq -c '.properties.logAnalyticsDestinationType = "AzureDiagnostics"')"
	expect_predicate_rejects "diagnostic setting with a metric" summary_diagnostic_matches \
		"$(printf '%s' "$diagnostic" | jq -c '.properties.metrics = [{category: "AllMetrics", enabled: true}]')"
	expect_predicate_rejects "diagnostic setting with a legacy Service Bus sink" summary_diagnostic_matches \
		"$(printf '%s' "$diagnostic" | jq -c '.properties.serviceBusRuleId = "/subscriptions/other/serviceBusRule"')"

	diagnostic_category=$(jq -cn \
		--arg id "$workspace_path/providers/Microsoft.Insights/diagnosticSettingsCategories/SummaryLogs" '{
		value: [{id: $id, name: "SummaryLogs", type: "Microsoft.Insights/diagnosticSettingsCategories",
			properties: {categoryType: "Logs"}}]
	}')
	expect_predicate_accepts "exact SummaryLogs diagnostic category" summary_diagnostic_category_matches "$diagnostic_category"
	expect_predicate_rejects "duplicate SummaryLogs diagnostic category" summary_diagnostic_category_matches \
		"$(printf '%s' "$diagnostic_category" | jq -c '.value += [.value[0]]')"
	expect_predicate_rejects "SummaryLogs metric category" summary_diagnostic_category_matches \
		"$(printf '%s' "$diagnostic_category" | jq -c '.value[0].properties.categoryType = "Metrics"')"
	expect_predicate_rejects "SummaryLogs category at another resource" summary_diagnostic_category_matches \
		"$(printf '%s' "$diagnostic_category" | jq -c '.value[0].id = "/subscriptions/other/SummaryLogs"')"

	summary_revision=2026-08-22T12:00:00.1234567Z
	summary_runtime=$(jq -cn --arg rule "$summary_rule" --arg revision "$summary_revision" '{
		tables: [{
			name: "PrimaryResult",
			columns: [
				{name: "RuleName", type: "string"},
				{name: "TimeGenerated", type: "datetime"},
				{name: "Status", type: "string"},
				{name: "QueryDurationMs", type: "long"},
				{name: "ResultsRecordCount", type: "long"},
				{name: "RuleLastModifiedTime", type: "datetime"},
				{name: "Message", type: "string"}
			],
			rows: [[$rule, "2026-08-22T12:05:00Z", "Succeeded", 12, 1, $revision, null]]
		}]
	}')
	if ! summary_runtime_response_matches "$summary_runtime" "$summary_revision"; then
		echo "predicate regression: successful execution after the ARM definition became visible was rejected" >&2
		return 1
	fi
	if ! summary_runtime_response_matches \
		"$(printf '%s' "$summary_runtime" | jq -c '.tables[0].rows[0][5] = "2026-08-22T11:59:30.1234567Z"')" "$summary_revision"; then
		echo "predicate regression: summary runtime row at the 30-second native timestamp tolerance was rejected" >&2
		return 1
	fi
	if ! summary_runtime_response_matches \
		"$(printf '%s' "$summary_runtime" | jq -c '.tables[0].rows[0][1] = "2026-08-22T12:25:00Z" | .tables[0].rows[0][5] = "2026-08-22T12:20:00Z"')" "$summary_revision"; then
		echo "predicate regression: later native rule timestamp before the run time was rejected" >&2
		return 1
	fi
	if summary_runtime_response_matches \
		"$(printf '%s' "$summary_runtime" | jq -c '.tables[0].rows[0][1] = "2026-08-22T11:59:59Z"')" "$summary_revision"; then
		echo "predicate regression: summary execution before the ARM definition became visible was accepted" >&2
		return 1
	fi
	if summary_runtime_response_matches \
		"$(printf '%s' "$summary_runtime" | jq -c '.tables[0].rows[0][5] = "2026-08-22T12:05:01Z"')" "$summary_revision"; then
		echo "predicate regression: native rule timestamp after the execution was accepted" >&2
		return 1
	fi
	if summary_runtime_response_matches \
		"$(printf '%s' "$summary_runtime" | jq -c '.tables[0].rows[0][2] = "Failed"')" "$summary_revision"; then
		echo "predicate regression: failed summary runtime row was accepted" >&2
		return 1
	fi
	if summary_runtime_response_matches \
		"$(printf '%s' "$summary_runtime" | jq -c '.tables[0].rows[0][4] = 0')" "$summary_revision"; then
		echo "predicate regression: zero-result summary runtime row was accepted" >&2
		return 1
	fi
	if summary_runtime_response_matches \
		"$(printf '%s' "$summary_runtime" | jq -c '.tables[0].rows[0][5] = "2026-08-22T11:59:29.1234567Z"')" "$summary_revision"; then
		echo "predicate regression: summary runtime row beyond the 30-second native timestamp tolerance was accepted" >&2
		return 1
	fi
	if summary_runtime_response_matches \
		"$(printf '%s' "$summary_runtime" | jq -c '.tables[0].rows += [.tables[0].rows[0]]')" "$summary_revision"; then
		echo "predicate regression: duplicate summary runtime rows were accepted" >&2
		return 1
	fi
	if summary_runtime_response_matches \
		"$(printf '%s' "$summary_runtime" | jq -c '.tables[0].rows[0][6] = "native failure"')" "$summary_revision"; then
		echo "predicate regression: successful summary runtime row with an error was accepted" >&2
		return 1
	fi
	if summary_runtime_response_matches \
		"$(printf '%s' "$summary_runtime" | jq -c '.error = {code: "PartialError"}')" "$summary_revision"; then
		echo "predicate regression: partial summary runtime response was accepted" >&2
		return 1
	fi
	if summary_runtime_response_matches \
		"$(printf '%s' "$summary_runtime" | jq -c '.tables[0].name = "OtherResult"')" "$summary_revision"; then
		echo "predicate regression: summary runtime response with another table name was accepted" >&2
		return 1
	fi

	logs_envelope=$(jq -cn '{tables: [{name: "PrimaryResult", columns: [], rows: []}]}')
	expect_predicate_accepts "exact primary Logs response envelope" logs_primary_result_envelope_matches "$logs_envelope"
	expect_predicate_accepts "primary Logs response envelope with null error" logs_primary_result_envelope_matches \
		"$(printf '%s' "$logs_envelope" | jq -c '.error = null')"
	expect_predicate_rejects "partial primary Logs response envelope" logs_primary_result_envelope_matches \
		"$(printf '%s' "$logs_envelope" | jq -c '.error = {code: "PartialError"}')"
	expect_predicate_rejects "duplicate primary Logs response tables" logs_primary_result_envelope_matches \
		"$(printf '%s' "$logs_envelope" | jq -c '.tables += [.tables[0]]')"
	expect_predicate_rejects "Logs response envelope with another table name" logs_primary_result_envelope_matches \
		"$(printf '%s' "$logs_envelope" | jq -c '.tables[0].name = "OtherResult"')"

	basic_data=$(jq -cn '{
		tables: [{
			name: "PrimaryResult",
			columns: [
				{name: "TimeGenerated", type: "datetime"},
				{name: "Marker", type: "string"}
			],
			rows: [["2026-08-22T12:05:00.1234567Z", "summary-source-1787399100"]]
		}]
	}')
	expect_predicate_accepts "current exact Basic-plan source row" basic_data_response_matches "$basic_data"
	expect_predicate_rejects "empty Basic-plan search result" basic_data_response_matches \
		"$(printf '%s' "$basic_data" | jq -c '.tables[0].rows = []')"
	expect_predicate_rejects "Basic-plan row without the exact source marker" basic_data_response_matches \
		"$(printf '%s' "$basic_data" | jq -c '.tables[0].rows[0][1] = "summary-source-current"')"
	expect_predicate_rejects "duplicate Basic-plan search rows" basic_data_response_matches \
		"$(printf '%s' "$basic_data" | jq -c '.tables[0].rows += [.tables[0].rows[0]]')"
	expect_predicate_rejects "Basic-plan search result with a wrong column type" basic_data_response_matches \
		"$(printf '%s' "$basic_data" | jq -c '.tables[0].columns[1].type = "dynamic"')"
	expect_predicate_rejects "partial Basic-plan search result" basic_data_response_matches \
		"$(printf '%s' "$basic_data" | jq -c '.error = {code: "PartialError"}')"

	output_revision=2026-08-22T12:00:00Z
	summary_output=$(jq -cn --arg rule "$summary_rule" '{
		tables: [{
			name: "PrimaryResult",
			columns: [
				{name: "TimeGenerated", type: "datetime"},
				{name: "EventCount", type: "long"},
				{name: "Marker", type: "string"},
				{name: "RuleName", type: "string"},
				{name: "RuleModifiedAt", type: "datetime"},
				{name: "BinSize", type: "long"},
				{name: "BinStartTime", type: "datetime"}
			],
			rows: [["2026-08-22T12:20:00Z", 1, "deadair-summary-runtime", $rule,
				"2026-08-22T11:59:55.1234567Z", 20, "2026-08-22T12:00:00Z"]]
		}]
	}')
	expect_predicate_accepts "exact positive owned summary output" summary_output_response_matches \
		"$summary_output" "$output_revision"
	expect_predicate_rejects "zero-count owned summary output" summary_output_response_matches \
		"$(printf '%s' "$summary_output" | jq -c '.tables[0].rows[0][1] = 0')" "$output_revision"
	expect_predicate_rejects "summary output for another rule" summary_output_response_matches \
		"$(printf '%s' "$summary_output" | jq -c '.tables[0].rows[0][3] = "other-summary"')" "$output_revision"
	expect_predicate_rejects "summary output with another bin size" summary_output_response_matches \
		"$(printf '%s' "$summary_output" | jq -c '.tables[0].rows[0][5] = 60')" "$output_revision"
	expect_predicate_rejects "summary output outside the definition timestamp tolerance" summary_output_response_matches \
		"$(printf '%s' "$summary_output" | jq -c '.tables[0].rows[0][4] = "2026-08-22T11:59:29Z"')" "$output_revision"
	expect_predicate_rejects "partial summary output" summary_output_response_matches \
		"$(printf '%s' "$summary_output" | jq -c '.error = {code: "PartialError"}')" "$output_revision"

	summary_source=$(jq -cn '{
		tables: [{
			name: "PrimaryResult",
			columns: [
				{name: "SourceEventCount", type: "long"},
				{name: "SourceMarker", type: "string"}
			],
			rows: [[1, "summary-source-1787399100"]]
		}]
	}')
	expect_predicate_accepts "exact positive source bin" summary_source_response_matches "$summary_source" 1
	expect_predicate_rejects "zero-count source bin" summary_source_response_matches \
		"$(printf '%s' "$summary_source" | jq -c '.tables[0].rows[0][0] = 0')" 1
	expect_predicate_rejects "source bin count different from summary output" summary_source_response_matches \
		"$(printf '%s' "$summary_source" | jq -c '.tables[0].rows[0][0] = 2')" 1
	expect_predicate_rejects "source bin without the owned marker" summary_source_response_matches \
		"$(printf '%s' "$summary_source" | jq -c '.tables[0].rows[0][1] = "other-source-1787399100"')" 1
	expect_predicate_rejects "partial source-bin search" summary_source_response_matches \
		"$(printf '%s' "$summary_source" | jq -c '.error = {code: "PartialError"}')" 1

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
	echo "  PUT/DELETE SummaryLogs diagnostic setting: $summary_diagnostic_path"
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

verify_summary_diagnostic_category() {
	if ! category_response=$(az rest --only-show-errors --method get \
		--uri "$summary_diagnostic_category_uri" --output json); then
		echo "refusing apply: workspace diagnostic categories could not be read" >&2
		exit 2
	fi
	if ! summary_diagnostic_category_matches "$category_response"; then
		echo "refusing apply: workspace does not expose the exact SummaryLogs diagnostic category" >&2
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

wait_for_summary_runtime() {
	runtime_rule_resource=$1
	runtime_revision=$(printf '%s' "$runtime_rule_resource" | jq -r '.systemData.lastModifiedAt // empty')
	case "$runtime_revision" in
	????-??-??T??:??:??Z|????-??-??T??:??:??.*Z) ;;
	*)
		echo "summary rule does not expose a usable current ARM revision time" >&2
		return 1
		;;
	esac
	case "$runtime_revision" in
	*[!0-9TZ:.-]*)
		echo "summary rule returned an unsafe ARM revision time" >&2
		return 1
		;;
	esac

	runtime_query="LASummaryLogs
| where TimeGenerated between (ago(7d) .. now())
| where RuleName == '$summary_rule'
| where Status in ('Succeeded', 'Failed')
| summarize arg_max(TimeGenerated, Status, QueryDurationMs, ResultsRecordCount, RuleLastModifiedTime, Message) by RuleName
| project RuleName, TimeGenerated, Status, QueryDurationMs, ResultsRecordCount, RuleLastModifiedTime, Message"
	jq -n --arg query "$runtime_query" '{query: $query}' >"$tmp_dir/summary-runtime-query.json"
	runtime_attempt=0
	# A new diagnostic route can take up to 90 minutes to start, and the
	# execution record can arrive several minutes after the summary bin runs.
	runtime_max_attempts=240
	runtime_last_state="no LASummaryLogs response observed"
	while [ "$runtime_attempt" -lt "$runtime_max_attempts" ]; do
		if runtime_response=$(az rest --only-show-errors --method post --resource https://api.loganalytics.io \
			--uri "https://api.loganalytics.io/v1/workspaces/$home_workspace_id/query" \
			--body "@$tmp_dir/summary-runtime-query.json" --output json 2>/dev/null); then
			if summary_runtime_response_matches "$runtime_response" "$runtime_revision"; then
				echo "successful LASummaryLogs execution observed after the ARM definition became visible for $summary_rule"
				return 0
			fi
			runtime_last_state=$(summary_runtime_response_state "$runtime_response")
		else
			runtime_last_state="Logs API request failed on attempt $((runtime_attempt + 1))"
		fi
		runtime_attempt=$((runtime_attempt + 1))
		if [ "$runtime_attempt" -lt "$runtime_max_attempts" ]; then
			sleep 30
		fi
	done
	echo "summary runtime readiness timed out after 120 minutes" >&2
	echo "  expected rule: $summary_rule" >&2
	echo "  ARM definition visible at: $runtime_revision" >&2
	echo "  expected latest completed run: at or after that time, Succeeded with ResultsRecordCount=1" >&2
	echo "  last observation: $runtime_last_state" >&2
	echo "The owned expansion resources remain in place; inspect them and use the confirmed cleanup path before retrying apply." >&2
	return 1
}

wait_for_summary_output_proof() {
	output_rule_resource=$1
	output_revision=$(printf '%s' "$output_rule_resource" | jq -r '.systemData.lastModifiedAt // empty')
	case "$output_revision" in
	????-??-??T??:??:??Z|????-??-??T??:??:??.*Z) ;;
	*)
		echo "summary rule does not expose a usable ARM definition time for output proof" >&2
		return 1
		;;
	esac
	case "$output_revision" in
	*[!0-9TZ:.-]*)
		echo "summary rule returned an unsafe ARM definition time for output proof" >&2
		return 1
		;;
	esac

	output_query="$summary_table
| where TimeGenerated between (ago(7d) .. now())
| where _RuleName == \"$summary_rule\" and _BinSize == 20 and Marker == \"deadair-summary-runtime\" and EventCount >= 1
| summarize arg_max(TimeGenerated, EventCount, Marker, _RuleName, _RuleLastModifiedTime, _BinSize, _BinStartTime)
| project TimeGenerated, EventCount, Marker, RuleName=_RuleName, RuleModifiedAt=_RuleLastModifiedTime, BinSize=_BinSize, BinStartTime=_BinStartTime"
	output_body=$(jq -cn --arg query "$output_query" '{query: $query}')
	output_attempt=0
	output_max_attempts=180
	output_last_state="no exact positive summary destination row observed"
	while [ "$output_attempt" -lt "$output_max_attempts" ]; do
		if output_response=$(az rest --only-show-errors --method post --resource https://api.loganalytics.io \
			--uri "https://api.loganalytics.io/v1/workspaces/$home_workspace_id/query" \
			--body "$output_body" --output json 2>/dev/null); then
			if summary_output_response_matches "$output_response" "$output_revision"; then
				output_event_count=$(printf '%s' "$output_response" | jq -r '.tables[0].rows[0][1]')
				output_bin_size=$(printf '%s' "$output_response" | jq -r '.tables[0].rows[0][5]')
				output_bin_start=$(printf '%s' "$output_response" | jq -r '.tables[0].rows[0][6]')
				output_bin_safe=false
				case "$output_bin_start" in
				????-??-??T??:??:??Z|????-??-??T??:??:??.*Z)
					case "$output_bin_start" in
					*[!0-9TZ:.-]*) ;;
					*) output_bin_safe=true ;;
					esac
					;;
				*)
					output_last_state="summary destination returned an unsafe bin start"
					;;
				esac
				case "$output_bin_size" in
				20) ;;
				*)
					output_bin_safe=false
					output_last_state="summary destination returned an unsafe bin size"
					;;
				esac
				if [ "$output_bin_safe" != true ]; then
					output_last_state="summary destination returned unsafe bin metadata"
				else
					source_query="let bin_start=datetime($output_bin_start);
DeadairBasic_CL
| where TimeGenerated >= bin_start and TimeGenerated < bin_start + ${output_bin_size}m
| where Marker matches regex \"^summary-source-[0-9]+$\"
| summarize SourceEventCount=count(), arg_max(TimeGenerated, Marker)
| project SourceEventCount, SourceMarker=Marker"
					source_body=$(jq -cn --arg query "$source_query" '{query: $query}')
					if source_response=$(az rest --only-show-errors --method post --resource https://api.loganalytics.io \
						--uri "https://api.loganalytics.io/v1/workspaces/$home_workspace_id/search?timespan=P1D" \
						--body "$source_body" --output json 2>/dev/null); then
						if summary_source_response_matches "$source_response" "$output_event_count"; then
							if ! proof_rule_resource=$(az rest --only-show-errors --method get \
								--uri "$summary_uri" --output json 2>/dev/null) ||
								! proof_table_resource=$(az rest --only-show-errors --method get \
									--uri "$summary_table_uri" --output json 2>/dev/null); then
								echo "summary output ownership could not be re-read after the bounded proof" >&2
								return 1
							fi
							proof_revision=$(printf '%s' "$proof_rule_resource" | jq -r '.systemData.lastModifiedAt // empty')
							if ! summary_rule_matches "$proof_rule_resource" ||
								! summary_table_matches "$proof_table_resource" ||
								[ "$proof_revision" != "$output_revision" ]; then
								echo "summary output ownership changed during the bounded proof; rerun expansion verify" >&2
								return 1
							fi
							echo "positive summary destination row matches its exact Basic-plan source bin"
							return 0
						fi
						output_last_state="Basic-plan source bin did not match the positive summary destination count and marker"
					else
						output_last_state="bounded Basic-plan source-bin search failed"
					fi
				fi
			else
				output_last_state="no exact positive owned summary destination row observed"
			fi
		else
			output_last_state="summary destination query failed"
		fi
		output_attempt=$((output_attempt + 1))
		if [ "$output_attempt" -lt "$output_max_attempts" ]; then
			sleep 30
		fi
	done
	echo "summary output proof timed out after 90 minutes" >&2
	echo "  expected: an exact positive $summary_table row and equal owned Basic-plan source-bin count" >&2
	echo "  last observation: $output_last_state" >&2
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
base_rows_refresh_needed=false

print_base_row_refresh_instruction() {
	echo "Refresh the rows with integration/prepare-sentinel-base-lab.sh apply, then run integration/prepare-sentinel-expansion-lab.sh verify and go test -tags=integration ./integration -run '^TestSentinelReadOnlyLab$' -v." >&2
}

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
		elif $shape == "predicate" then
			([.properties.schema.columns[]?] | length) == 3 and
			any(.properties.schema.columns[]?; .name == "TimeGenerated" and (.type | ascii_downcase) == "datetime") and
			any(.properties.schema.columns[]?; .name == "EventId" and (.type | ascii_downcase) == "string") and
			any(.properties.schema.columns[]?; .name == "DeviceVendor" and (.type | ascii_downcase) == "string")
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
	if ! logs_primary_result_envelope_matches "$base_data_response"; then
		add_prerequisite_issue "bounded base-row aggregate returned a partial or malformed Logs response"
	elif ! printf '%s' "$base_data_response" | jq -e '
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
		base_rows_refresh_needed=true
	fi

	predicate_data_query="DeadairPredicate_CL | where ingestion_time() >= ago(24h) and TimeGenerated between (ago(30m) .. now()) and DeviceVendor == 'Deadair Labs' | summarize RowCount=count(), arg_max(TimeGenerated, EventId, DeviceVendor) | project RowCount, EventIDPresent=isnotempty(EventId), VendorPresent=DeviceVendor == 'Deadair Labs'"
	predicate_data_body=$(jq -cn --arg query "$predicate_data_query" '{query: $query}')
	if ! predicate_data_response=$(az rest --only-show-errors --method post --resource https://api.loganalytics.io \
		--uri "https://api.loganalytics.io/v1/workspaces/$home_workspace_id/query" \
		--body "$predicate_data_body" --output json 2>/dev/null); then
		add_prerequisite_issue "bounded predicate-fixture aggregate could not be read through the Logs API"
		return
	fi
	if ! logs_primary_result_envelope_matches "$predicate_data_response"; then
		add_prerequisite_issue "bounded predicate fixture returned a partial or malformed Logs response"
	elif ! printf '%s' "$predicate_data_response" | jq -e '
		.tables[0] as $table |
		([$table.columns[]?.name] == ["RowCount", "EventIDPresent", "VendorPresent"]) and
		([$table.rows[]?] | length) == 1 and
		($table.rows[0][0] | type) == "number" and $table.rows[0][0] > 0 and
		$table.rows[0][1] == true and $table.rows[0][2] == true' >/dev/null; then
		add_prerequisite_issue "bounded predicate fixture lacks a complete Deadair Labs row from the previous 30 minutes"
		base_rows_refresh_needed=true
	fi

	basic_data_query='DeadairBasic_CL | where TimeGenerated between (ago(30m) .. now()) and Marker matches regex "^summary-source-[0-9]+$" | top 1 by TimeGenerated desc | project TimeGenerated, Marker'
	basic_data_body=$(jq -cn --arg query "$basic_data_query" '{query: $query}')
	if ! basic_data_response=$(az rest --only-show-errors --method post --resource https://api.loganalytics.io \
		--uri "https://api.loganalytics.io/v1/workspaces/$home_workspace_id/search?timespan=PT30M" \
		--body "$basic_data_body" --output json 2>/dev/null); then
		add_prerequisite_issue "current Basic-plan summary source could not be read through the bounded Logs search API"
		return
	fi
	if ! basic_data_response_matches "$basic_data_response"; then
		add_prerequisite_issue "DeadairBasic_CL lacks a current exact summary-source-<digits> row from the previous 30 minutes"
		base_rows_refresh_needed=true
	fi
}

verify_base_prerequisites() {
	prerequisite_issues=
	base_tables_ready=true
	base_rows_refresh_needed=false
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
	verify_base_table DeadairPredicate_CL Analytics predicate
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
	verify_base_rule 77777777-7777-4777-8777-777777777777 'deadair lab - predicate freshness' \
		"DeadairPredicate_CL | where DeviceVendor == 'Deadair Labs' | project TimeGenerated, EventId, DeviceVendor" PT5M PT30M
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
		if [ "$base_rows_refresh_needed" = true ]; then
			print_base_row_refresh_instruction
		else
			echo "No expansion fixture writes were attempted. Repair the externally owned base lab, then rerun $0 $mode." >&2
		fi
		exit 2
	fi
	echo "base Sentinel lab prerequisites verified (read only)"
}

require_current_base_data_after_output() {
	prerequisite_issues=
	base_rows_refresh_needed=false
	verify_base_data
	if [ -z "$prerequisite_issues" ]; then
		return 0
	fi
	echo "base Sentinel lab data is no longer ready after the bounded summary output proof:$prerequisite_issues" >&2
	if [ "$base_rows_refresh_needed" = true ]; then
		print_base_row_refresh_instruction
	else
		echo "Fix the base-data read failure, then run integration/prepare-sentinel-expansion-lab.sh verify and the Sentinel Go test." >&2
	fi
	return 1
}

verify_existing_summary_output_if_present() {
	verify_summary_rule=$(collection_resource "summary rule $summary_rule" "$summary_collection_uri" "$summary_rule")
	verify_summary_table=$(collection_resource "summary destination $summary_table" "$table_collection_uri" "$summary_table")
	if [ -z "$verify_summary_rule" ] && [ -z "$verify_summary_table" ]; then
		return 1
	fi
	if [ -z "$verify_summary_rule" ] || [ -z "$verify_summary_table" ]; then
		echo "existing expansion summary output is incomplete; both the owned rule and destination are required" >&2
		exit 2
	fi
	if ! summary_rule_matches "$verify_summary_rule"; then
		echo "existing expansion summary rule does not match its exact owned definition" >&2
		exit 2
	fi
	if ! summary_table_matches "$verify_summary_table"; then
		echo "existing expansion summary destination does not match its exact owned schema" >&2
		exit 2
	fi
	wait_for_summary_output_proof "$verify_summary_rule"
}

if [ "$mode" = plan ] || [ "$mode" = verify ] || [ "$mode" = apply ]; then
	verify_base_prerequisites
fi
if [ "$mode" = plan ]; then
	print_plan
	exit 0
fi
if [ "$mode" = verify ]; then
	if verify_existing_summary_output_if_present; then
		require_current_base_data_after_output
		echo "Sentinel expansion verification passed, including the bounded summary output proof; no Azure changes were made"
	else
		echo "Sentinel base-lab verification passed; no Azure changes were made"
	fi
	exit 0
fi

tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/deadair-sentinel-expansion.XXXXXX")
trap 'rm -rf "$tmp_dir"' EXIT HUP INT TERM

if [ "$mode" = apply ]; then
	require_collection_absent "watchlist $watchlist_alias" "$watchlist_collection_uri" "$watchlist_alias"
	require_collection_absent "remote workspace $remote_workspace" "$workspace_collection_uri" "$remote_workspace"
	require_collection_absent "summary rule $summary_rule" "$summary_collection_uri" "$summary_rule"
	require_collection_absent "summary destination $summary_table" "$table_collection_uri" "$summary_table"
	require_collection_absent "summary diagnostic setting $summary_diagnostic_setting" "$summary_diagnostic_collection_uri" "$summary_diagnostic_setting"
	require_collection_absent "watchlist dependency rule $watchlist_rule_id" "$alert_rule_collection_uri" "$watchlist_rule_id"
	require_collection_absent "ASIM dependency rule $asim_rule_id" "$alert_rule_collection_uri" "$asim_rule_id"
	require_collection_absent "remote dependency rule $remote_rule_id" "$alert_rule_collection_uri" "$remote_rule_id"
	require_collection_absent "summary consumer rule $summary_consumer_rule_id" "$alert_rule_collection_uri" "$summary_consumer_rule_id"
	verify_summary_diagnostic_category

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

	jq -n --arg workspace "$workspace_path" '{
		properties: {
			workspaceId: $workspace,
			logAnalyticsDestinationType: "Dedicated",
			logs: [{category: "SummaryLogs", enabled: true}],
			metrics: []
		}
	}' >"$tmp_dir/summary-diagnostic.json"
	az rest --only-show-errors --method put --uri "$summary_diagnostic_uri" \
		--body "@$tmp_dir/summary-diagnostic.json" --output none
	wait_for_value "$summary_diagnostic_uri" name "$summary_diagnostic_setting" "summary diagnostic setting $summary_diagnostic_setting"
	if ! summary_diagnostic_resource=$(az rest --only-show-errors --method get \
		--uri "$summary_diagnostic_uri" --output json); then
		echo "summary diagnostic setting could not be read exactly after creation" >&2
		exit 2
	fi
	if ! summary_diagnostic_matches "$summary_diagnostic_resource"; then
		echo "summary diagnostic setting does not match the exact SummaryLogs-only same-workspace definition" >&2
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
	if ! summary_rule_resource=$(az rest --only-show-errors --method get --uri "$summary_uri" --output json); then
		echo "summary rule could not be read exactly after creation" >&2
		exit 2
	fi
	if ! summary_rule_matches "$summary_rule_resource"; then
		echo "summary rule did not preserve its exact active runtime definition" >&2
		exit 2
	fi
	if ! summary_table_resource=$(az rest --only-show-errors --method get --uri "$summary_table_uri" --output json); then
		echo "summary destination could not be re-read after the summary rule settled" >&2
		exit 2
	fi
	if ! summary_table_matches "$summary_table_resource"; then
		echo "summary destination changed outside its exact owned schema after the summary rule settled" >&2
		exit 2
	fi

	create_expansion_rule "$watchlist_rule_id" "$watchlist_rule_display" "$watchlist_rule_query"
	create_expansion_rule "$asim_rule_id" "$asim_rule_display" "$asim_rule_query"
	create_expansion_rule "$remote_rule_id" "$remote_rule_display" "$remote_rule_query"
	create_expansion_rule "$summary_consumer_rule_id" "$summary_consumer_rule_display" "$summary_consumer_rule_query"
	wait_for_summary_runtime "$summary_rule_resource"
	wait_for_summary_output_proof "$summary_rule_resource"
	require_current_base_data_after_output

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
summary_diagnostic_resource=$(collection_resource "summary diagnostic setting $summary_diagnostic_setting" "$summary_diagnostic_collection_uri" "$summary_diagnostic_setting")
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
	if ! summary_rule_matches "$summary_exact_resource"; then
		echo "refusing cleanup: summary-rule ownership definition does not match" >&2
		exit 2
	fi
	summary_owned=true
fi

summary_diagnostic_owned=false
if [ -n "$summary_diagnostic_resource" ]; then
	if ! summary_diagnostic_exact_resource=$(az rest --only-show-errors --method get \
		--uri "$summary_diagnostic_uri" --output json); then
		echo "refusing cleanup: summary diagnostic setting could not be read exactly" >&2
		exit 2
	fi
	if ! summary_diagnostic_matches "$summary_diagnostic_exact_resource"; then
		echo "refusing cleanup: summary diagnostic setting lacks the exact SummaryLogs-only same-workspace definition" >&2
		exit 2
	fi
	summary_diagnostic_owned=true
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
	if ! cleanup_expansion_rule_state "$summary_consumer_rule_id" "$summary_consumer_rule_display" "$summary_consumer_rule_query"; then
		echo "refusing cleanup: summary consumer rule changed after the all-resource preflight" >&2
		exit 2
	fi
	az rest --only-show-errors --method delete --uri "$(expansion_rule_uri "$summary_consumer_rule_id")" --output none
	wait_for_collection_absence "$alert_rule_collection_uri" "$summary_consumer_rule_id" "summary consumer rule $summary_consumer_rule_id"
fi
if [ "$summary_owned" = true ]; then
	if ! summary_exact_resource=$(az rest --only-show-errors --method get --uri "$summary_uri" --output json) || \
		! summary_rule_matches "$summary_exact_resource"; then
		echo "refusing cleanup: summary rule changed after the all-resource preflight" >&2
		exit 2
	fi
	az rest --only-show-errors --method delete --uri "$summary_uri" --output none
	wait_for_collection_absence "$summary_collection_uri" "$summary_rule" "summary rule $summary_rule"
fi

if [ "$summary_diagnostic_owned" = true ]; then
	# Re-read immediately before deletion so a post-preflight definition change
	# cannot turn the exact name into cleanup authority.
	if ! summary_diagnostic_exact_resource=$(az rest --only-show-errors --method get \
		--uri "$summary_diagnostic_uri" --output json) || \
		! summary_diagnostic_matches "$summary_diagnostic_exact_resource"; then
		echo "refusing cleanup: summary diagnostic setting changed after the all-resource preflight" >&2
		exit 2
	fi
	az rest --only-show-errors --method delete --uri "$summary_diagnostic_uri" --output none
	wait_for_collection_absence "$summary_diagnostic_collection_uri" "$summary_diagnostic_setting" "summary diagnostic setting $summary_diagnostic_setting"
fi

if [ "$summary_table_owned" = true ]; then
	if ! summary_table_exact_resource=$(az rest --only-show-errors --method get \
		--uri "$summary_table_uri" --output json) || \
		! summary_table_matches "$summary_table_exact_resource"; then
		echo "refusing cleanup: summary destination changed after the all-resource preflight" >&2
		exit 2
	fi
	az rest --only-show-errors --method delete --uri "$summary_table_uri" --output none
	wait_for_collection_absence "$table_collection_uri" "$summary_table" "summary destination $summary_table"
fi

if [ "$remote_rule_owned" = true ]; then
	if ! cleanup_expansion_rule_state "$remote_rule_id" "$remote_rule_display" "$remote_rule_query"; then
		echo "refusing cleanup: remote dependency rule changed after the all-resource preflight" >&2
		exit 2
	fi
	az rest --only-show-errors --method delete --uri "$(expansion_rule_uri "$remote_rule_id")" --output none
	wait_for_collection_absence "$alert_rule_collection_uri" "$remote_rule_id" "remote dependency rule $remote_rule_id"
fi
if [ "$asim_rule_owned" = true ]; then
	if ! cleanup_expansion_rule_state "$asim_rule_id" "$asim_rule_display" "$asim_rule_query"; then
		echo "refusing cleanup: ASIM dependency rule changed after the all-resource preflight" >&2
		exit 2
	fi
	az rest --only-show-errors --method delete --uri "$(expansion_rule_uri "$asim_rule_id")" --output none
	wait_for_collection_absence "$alert_rule_collection_uri" "$asim_rule_id" "ASIM dependency rule $asim_rule_id"
fi
if [ "$watchlist_rule_owned" = true ]; then
	if ! cleanup_expansion_rule_state "$watchlist_rule_id" "$watchlist_rule_display" "$watchlist_rule_query"; then
		echo "refusing cleanup: watchlist dependency rule changed after the all-resource preflight" >&2
		exit 2
	fi
	az rest --only-show-errors --method delete --uri "$(expansion_rule_uri "$watchlist_rule_id")" --output none
	wait_for_collection_absence "$alert_rule_collection_uri" "$watchlist_rule_id" "watchlist dependency rule $watchlist_rule_id"
fi

if [ "$watchlist_owned" = true ]; then
	if ! watchlist_exact_resource=$(az rest --only-show-errors --method get --uri "$watchlist_uri" --output json); then
		echo "refusing cleanup: watchlist changed or disappeared after the all-resource preflight" >&2
		exit 2
	fi
	require_watchlist_settled "$watchlist_exact_resource" "watchlist $watchlist_alias"
	if ! watchlist_matches "$watchlist_exact_resource"; then
		echo "refusing cleanup: watchlist changed after the all-resource preflight" >&2
		exit 2
	fi
	az rest --only-show-errors --method delete --uri "$watchlist_uri" --output none
	wait_for_collection_absence "$watchlist_collection_uri" "$watchlist_alias" "watchlist $watchlist_alias"
fi

if [ "$remote_owned" = true ]; then
	if ! remote_exact_resource=$(az rest --only-show-errors --method get --uri "$remote_uri" --output json); then
		echo "refusing cleanup: remote workspace changed or disappeared after the all-resource preflight" >&2
		exit 2
	fi
	remote_project=$(printf '%s' "$remote_exact_resource" | jq -r '.tags.project // empty')
	remote_purpose=$(printf '%s' "$remote_exact_resource" | jq -r '.tags.purpose // empty')
	remote_disposable=$(printf '%s' "$remote_exact_resource" | jq -r '.tags.disposable // empty')
	remote_identity_exact=$(printf '%s' "$remote_exact_resource" | jq -r \
		--arg id "$remote_path" --arg name "$remote_workspace" '
		(((.id // "") | ascii_downcase) == ($id | ascii_downcase)) and (.name == $name)')
	if [ "$remote_project" != deadair ] || [ "$remote_purpose" != "$fixture_marker" ] || \
		[ "$remote_disposable" != true ] || [ "$remote_identity_exact" != true ]; then
		echo "refusing cleanup: remote workspace changed after the all-resource preflight" >&2
		exit 2
	fi
	az rest --only-show-errors --method delete --uri "$remote_uri" --output none
	wait_for_collection_absence "$workspace_collection_uri" "$remote_workspace" "remote workspace $remote_workspace"
fi

echo "Sentinel expansion fixtures removed"
