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
late=$(python3 -c 'from datetime import datetime, timedelta, timezone; print((datetime.now(timezone.utc)+timedelta(minutes=45)).strftime("%Y-%m-%dT%H:%M:%SZ"))')

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
elastic -X DELETE "$es_url/deadair-lab-*?expand_wildcards=all" >/dev/null 2>&1 || true
elastic -X DELETE "$es_url/_security/api_key" \
	-d '{"name":"deadair-scan-lab","owner":false}' >/dev/null 2>&1 || true

create_index() {
	index=$1
	mapping=$2
	document=$3
	elastic -X PUT "$es_url/$index" -d "$mapping" >/dev/null
	elastic -X POST "$es_url/$index/_doc?refresh=true" -d "$document" >/dev/null
}

create_index deadair-lab-live \
	'{"mappings":{"properties":{"@timestamp":{"type":"date"},"host":{"properties":{"name":{"type":"keyword"}}}}}}' \
	"{\"@timestamp\":\"$now\",\"host\":{\"name\":\"lab-endpoint\"}}"
create_index deadair-lab-stale \
	'{"mappings":{"properties":{"@timestamp":{"type":"date"},"event":{"properties":{"category":{"type":"keyword"}}}}}}' \
	"{\"@timestamp\":\"$old\",\"event\":{\"category\":\"authentication\"}}"
create_index deadair-lab-schema \
	'{"mappings":{"properties":{"@timestamp":{"type":"date"},"process":{"properties":{"name":{"type":"keyword"}}}}}}' \
	"{\"@timestamp\":\"$now\",\"process\":{\"name\":\"powershell.exe\"}}"
create_index deadair-lab-lag \
	'{"mappings":{"properties":{"@timestamp":{"type":"date"},"event":{"properties":{"ingested":{"type":"date"}}}}}}' \
	"{\"@timestamp\":\"$now\",\"event\":{\"ingested\":\"$late\"}}"
create_index deadair-lab-unused \
	'{"mappings":{"properties":{"@timestamp":{"type":"date"},"metric":{"properties":{"value":{"type":"long"}}}}}}' \
	"{\"@timestamp\":\"$now\",\"metric\":{\"value\":42}}"

create_rule() {
	kibana -X POST "$kibana_url/api/detection_engine/rules" -d "$1" >/dev/null
}

create_rule '{"rule_id":"deadair-lab-live","name":"Lab process telemetry","description":"Disposable deadair screenshot lab","risk_score":21,"severity":"low","type":"query","query":"*:*","language":"kuery","index":["deadair-lab-live"],"from":"now-6m","interval":"5m","enabled":true}'
create_rule '{"rule_id":"deadair-lab-missing","name":"Lab registry persistence","description":"Disposable deadair screenshot lab","risk_score":73,"severity":"high","type":"query","query":"*:*","language":"kuery","index":["deadair-lab-registry-*"],"from":"now-6m","interval":"5m","enabled":true}'
create_rule '{"rule_id":"deadair-lab-stale","name":"Lab authentication source","description":"Disposable deadair screenshot lab","risk_score":47,"severity":"medium","type":"query","query":"*:*","language":"kuery","index":["deadair-lab-stale"],"from":"now-6m","interval":"5m","enabled":true}'
create_rule '{"rule_id":"deadair-lab-schema","name":"Lab parser field coverage","description":"Disposable deadair screenshot lab","risk_score":73,"severity":"high","type":"query","query":"*:*","language":"kuery","index":["deadair-lab-schema"],"from":"now-6m","interval":"5m","enabled":true,"required_fields":[{"name":"process.name","type":"keyword"},{"name":"process.command_line","type":"keyword"}]}'
create_rule '{"rule_id":"deadair-lab-lag","name":"Lab delayed ingest","description":"Disposable deadair screenshot lab","risk_score":47,"severity":"medium","type":"query","query":"*:*","language":"kuery","index":["deadair-lab-lag"],"from":"now-6m","interval":"5m","enabled":true}'

elastic -X POST "$es_url/_security/api_key" -d '{
  "name":"deadair-scan-lab",
  "role_descriptors":{"deadair_lab_reader":{
    "cluster":["monitor"],
    "indices":[{"names":["deadair-lab-*"],"privileges":["monitor","view_index_metadata","read"]}],
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
