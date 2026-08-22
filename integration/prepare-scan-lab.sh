#!/bin/bash
set -eu

es_url=${DEADAIR_IT_ES_URL:-http://localhost:9200}
kibana_url=${DEADAIR_IT_KIBANA_URL:-http://localhost:5601}
admin_password=${DEADAIR_IT_PASSWORD:-changeme-deadair}
out_dir=${DEADAIR_SCAN_LAB_OUT:?set DEADAIR_SCAN_LAB_OUT}
examples_dir=${DEADAIR_SCAN_LAB_EXAMPLES:?set DEADAIR_SCAN_LAB_EXAMPLES}
binary=${DEADAIR_SCAN_LAB_BINARY:?set DEADAIR_SCAN_LAB_BINARY}

umask 077
mkdir -p "$out_dir"
rm -f \
	"$out_dir/capture-state.json" \
	"$out_dir/examples-state.json"

now=$(python3 -c 'from datetime import datetime, timezone; print(datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))')
old=$(python3 -c 'from datetime import datetime, timedelta, timezone; print((datetime.now(timezone.utc)-timedelta(hours=72)).strftime("%Y-%m-%dT%H:%M:%SZ"))')
lagged=$(python3 -c 'from datetime import datetime, timedelta, timezone; print((datetime.now(timezone.utc)-timedelta(minutes=45)).strftime("%Y-%m-%dT%H:%M:%SZ"))')

elastic() {
	curl --fail --silent --show-error \
		-u "elastic:$admin_password" \
		-H "Content-Type: application/json" \
		"$@"
}

kibana() {
	curl --fail --silent --show-error \
		-u "elastic:$admin_password" \
		-H "kbn-xsrf: deadair-scan-lab" \
		-H "Content-Type: application/json" \
		"$@"
}

for rule_id in \
	deadair-lab-live deadair-lab-missing deadair-lab-stale \
	deadair-lab-schema deadair-lab-lag; do
	kibana -X DELETE "$kibana_url/api/detection_engine/rules?rule_id=$rule_id" >/dev/null 2>&1 || true
done
for index in \
	endpoint-process-events-prod \
	okta-system-events-prod \
	endpoint-process-events-legacy \
	cloudflare-firewall-prod \
	dns-query-events-prod; do
	elastic -X DELETE "$es_url/$index?expand_wildcards=all" >/dev/null 2>&1 || true
done
elastic -X DELETE "$es_url/_security/api_key" \
	-d '{"name":"deadair-scan-lab","owner":false}' >/dev/null 2>&1 || true

create_index() {
	index=$1
	mapping=$2
	document=$3
	elastic -X PUT "$es_url/$index" -d "$mapping" >/dev/null
	elastic -X POST "$es_url/$index/_doc?refresh=true" -d "$document" >/dev/null
}

create_index endpoint-process-events-prod \
	'{"mappings":{"properties":{"@timestamp":{"type":"date"},"event":{"properties":{"category":{"type":"keyword"},"dataset":{"type":"keyword"},"ingested":{"type":"date"},"type":{"type":"keyword"}}},"host":{"properties":{"name":{"type":"keyword"}}},"process":{"properties":{"executable":{"type":"keyword"},"name":{"type":"keyword"}}},"user":{"properties":{"name":{"type":"keyword"}}}}}}' \
	"{\"@timestamp\":\"$now\",\"event\":{\"category\":\"process\",\"dataset\":\"endpoint.events.process\",\"ingested\":\"$now\",\"type\":\"start\"},\"host\":{\"name\":\"wkstn-fin-07\"},\"process\":{\"executable\":\"C:\\\\Windows\\\\System32\\\\rundll32.exe\",\"name\":\"rundll32.exe\"},\"user\":{\"name\":\"maria.chen\"}}"
create_index okta-system-events-prod \
	'{"mappings":{"properties":{"@timestamp":{"type":"date"},"event":{"properties":{"action":{"type":"keyword"},"category":{"type":"keyword"},"dataset":{"type":"keyword"},"ingested":{"type":"date"},"outcome":{"type":"keyword"}}},"okta":{"properties":{"event_type":{"type":"keyword"}}},"source":{"properties":{"ip":{"type":"ip"}}},"user":{"properties":{"email":{"type":"keyword"}}}}}}' \
	"{\"@timestamp\":\"$old\",\"event\":{\"action\":\"user.session.start\",\"category\":\"authentication\",\"dataset\":\"okta.system\",\"ingested\":\"$now\",\"outcome\":\"failure\"},\"okta\":{\"event_type\":\"user.session.start\"},\"source\":{\"ip\":\"198.51.100.24\"},\"user\":{\"email\":\"alex.morgan@example.test\"}}"
create_index endpoint-process-events-legacy \
	'{"mappings":{"properties":{"@timestamp":{"type":"date"},"event":{"properties":{"category":{"type":"keyword"},"dataset":{"type":"keyword"},"ingested":{"type":"date"},"type":{"type":"keyword"}}},"host":{"properties":{"name":{"type":"keyword"}}},"process":{"properties":{"name":{"type":"keyword"}}},"user":{"properties":{"name":{"type":"keyword"}}}}}}' \
	"{\"@timestamp\":\"$now\",\"event\":{\"category\":\"process\",\"dataset\":\"endpoint.events.process\",\"ingested\":\"$now\",\"type\":\"start\"},\"host\":{\"name\":\"srv-payroll-02\"},\"process\":{\"name\":\"powershell.exe\"},\"user\":{\"name\":\"svc_payroll\"}}"
create_index cloudflare-firewall-prod \
	'{"mappings":{"properties":{"@timestamp":{"type":"date"},"cloudflare":{"properties":{"ray_id":{"type":"keyword"},"rule":{"properties":{"id":{"type":"keyword"}}}}},"destination":{"properties":{"ip":{"type":"ip"}}},"event":{"properties":{"action":{"type":"keyword"},"dataset":{"type":"keyword"},"ingested":{"type":"date"}}},"source":{"properties":{"ip":{"type":"ip"}}}}}}' \
	"{\"@timestamp\":\"$lagged\",\"cloudflare\":{\"ray_id\":\"8a73d8e9b2c14f11\",\"rule\":{\"id\":\"100173\"}},\"destination\":{\"ip\":\"192.0.2.18\"},\"event\":{\"action\":\"block\",\"dataset\":\"cloudflare_logpush.firewall_event\",\"ingested\":\"$now\"},\"source\":{\"ip\":\"203.0.113.46\"}}"
elastic -X POST "$es_url/cloudflare-firewall-prod/_doc?refresh=true" \
	-d "{\"@timestamp\":\"$now\",\"cloudflare\":{\"ray_id\":\"8a73d8e9b2c14f12\",\"rule\":{\"id\":\"100173\"}},\"destination\":{\"ip\":\"192.0.2.18\"},\"event\":{\"action\":\"block\",\"dataset\":\"cloudflare_logpush.firewall_event\",\"ingested\":\"$now\"},\"source\":{\"ip\":\"203.0.113.47\"}}" >/dev/null
create_index dns-query-events-prod \
	'{"mappings":{"properties":{"@timestamp":{"type":"date"},"dns":{"properties":{"question":{"properties":{"name":{"type":"keyword"},"type":{"type":"keyword"}}}}},"event":{"properties":{"dataset":{"type":"keyword"},"ingested":{"type":"date"}}},"source":{"properties":{"ip":{"type":"ip"}}}}}}' \
	"{\"@timestamp\":\"$now\",\"dns\":{\"question\":{\"name\":\"updates.example.test\",\"type\":\"A\"}},\"event\":{\"dataset\":\"network_traffic.dns\",\"ingested\":\"$now\"},\"source\":{\"ip\":\"192.0.2.44\"}}"

create_rule() {
	kibana -X POST "$kibana_url/api/detection_engine/rules" -d "$1" >/dev/null
}

create_rule '{"rule_id":"deadair-lab-live","name":"Endpoint process starts","description":"Disposable deadair capture lab: current Elastic Defend process telemetry","risk_score":21,"severity":"low","type":"query","query":"event.dataset: \"endpoint.events.process\" and event.category: process and event.type: start","language":"kuery","index":["endpoint-process-events-prod"],"from":"now-6m","interval":"5m","enabled":true}'
create_rule '{"rule_id":"deadair-lab-missing","name":"Sysmon registry run-key modification","description":"Disposable deadair capture lab: expected Sysmon registry telemetry is absent","risk_score":73,"severity":"high","type":"query","query":"event.provider: \"Microsoft-Windows-Sysmon\" and event.code: \"13\"","language":"kuery","index":["winlogbeat-sysmon-*"],"from":"now-6m","interval":"5m","enabled":true}'
create_rule '{"rule_id":"deadair-lab-stale","name":"Okta authentication failures","description":"Disposable deadair capture lab: Okta system telemetry stopped 72 hours ago","risk_score":47,"severity":"medium","type":"query","query":"event.dataset: \"okta.system\" and event.category: authentication and event.outcome: failure","language":"kuery","index":["okta-system-events-prod"],"from":"now-6m","interval":"5m","enabled":true}'
create_rule '{"rule_id":"deadair-lab-schema","name":"PowerShell from legacy endpoints","description":"Disposable deadair capture lab: legacy process events omit command lines","risk_score":73,"severity":"high","type":"query","query":"event.category: process and process.name: \"powershell.exe\"","language":"kuery","index":["endpoint-process-events-legacy"],"from":"now-6m","interval":"5m","enabled":true,"required_fields":[{"name":"process.name","type":"keyword"},{"name":"process.command_line","type":"keyword"}]}'
create_rule '{"rule_id":"deadair-lab-lag","name":"Cloudflare firewall blocks","description":"Disposable deadair capture lab: one recent firewall event arrived 45 minutes late","risk_score":47,"severity":"medium","type":"query","query":"event.dataset: \"cloudflare_logpush.firewall_event\" and event.action: block","language":"kuery","index":["cloudflare-firewall-prod"],"from":"now-6m","interval":"5m","enabled":true}'

elastic -X POST "$es_url/_security/api_key" -d '{
  "name":"deadair-scan-lab",
  "role_descriptors":{"deadair_lab_reader":{
    "cluster":["monitor"],
    "indices":[{"names":["endpoint-process-events-prod","winlogbeat-sysmon-*","okta-system-events-prod","endpoint-process-events-legacy","cloudflare-firewall-prod","dns-query-events-prod"],"privileges":["monitor","view_index_metadata","read"]}],
    "applications":[{"application":"kibana-.kibana","privileges":["feature_siem.read","feature_siemV2.read","feature_indexPatterns.read"],"resources":["space:default"]}]
  }}
}' | python3 -c 'import json, sys; print(json.load(sys.stdin)["encoded"])' >"$out_dir/api-key"

export DEADAIR_ES_URL="$es_url"
export DEADAIR_KIBANA_URL="$kibana_url"
export DEADAIR_API_KEY
DEADAIR_API_KEY=$(cat "$out_dir/api-key")

"$binary" check >"$out_dir/check.txt"

status=0
"$binary" scan \
	--schema \
	--state-file "$out_dir/examples-state.json" \
	--json-out "$examples_dir/sample-report.json" \
	--html-out "$examples_dir/sample-report.html" \
	>"$examples_dir/sample-scan.txt" || status=$?
if [ "$status" -ne 1 ]; then
	echo "lab scan returned $status, expected findings exit 1" >&2
	exit 1
fi
python3 -c '
import json, sys
report = json.load(open(sys.argv[1], encoding="utf-8"))
summary = report["summary"]
expected = {"dead_detections": 2, "impaired_detections": 2, "degraded_sources": 1, "unused_sources": 1}
actual = {key: summary.get(key) for key in expected}
lag_assessed = any(item.get("name") == "ingest_lag" and item.get("status") == "assessed" for item in report.get("assessments", []))
if actual != expected or not lag_assessed:
    raise SystemExit(f"unexpected lab report: counts={actual}, ingest_lag_assessed={lag_assessed}")
' "$examples_dir/sample-report.json"
