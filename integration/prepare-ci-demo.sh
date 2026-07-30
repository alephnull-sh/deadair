#!/bin/bash
set -eu

es_url=${DEADAIR_IT_ES_URL:-http://localhost:9200}
admin_password=${DEADAIR_IT_PASSWORD:-changeme-deadair}
out_dir=${DEADAIR_CI_DEMO_OUT:?set DEADAIR_CI_DEMO_OUT}
binary=${DEADAIR_CI_DEMO_BINARY:?set DEADAIR_CI_DEMO_BINARY}

umask 077
mkdir -p "$out_dir"

curl_json() {
	curl --fail --silent --show-error \
		-u "elastic:$admin_password" \
		-H "Content-Type: application/json" \
		"$@"
}

curl_json -X DELETE "$es_url/deadair-ci-live?ignore_unavailable=true" >/dev/null
curl_json -X PUT "$es_url/deadair-ci-live" \
	-d '{"mappings":{"properties":{"@timestamp":{"type":"date"}}}}' >/dev/null
curl_json -X POST "$es_url/deadair-ci-live/_doc?refresh=true" \
	-d "{\"@timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\"message\":\"synthetic CI event\"}" >/dev/null

curl_json -X POST "$es_url/_security/api_key" \
	-d '{"name":"deadair-ci-demo","role_descriptors":{"deadair_ci_reader":{"cluster":["monitor"],"indices":[{"names":["deadair-ci-*","netflow-*"],"privileges":["monitor","view_index_metadata","read"]}]}}}' |
	python3 -c 'import json, sys; print(json.load(sys.stdin)["encoded"])' >"$out_dir/api-key"

printf '%s\n' \
	'{"rule_id":"candidate-netflow","name":"Candidate NetFlow rule","severity":"high","index":["deadair-ci-*"],"from":"now-6m","interval":"5m"}' \
	>"$out_dir/baseline-rule.json"
printf '%s\n' \
	'{"rule_id":"candidate-netflow","name":"Candidate NetFlow rule","severity":"high","index":["netflow-*"],"from":"now-6m","interval":"5m"}' \
	>"$out_dir/candidate-rule.json"

export DEADAIR_ES_URL="$es_url"
export DEADAIR_KIBANA_URL=http://localhost:5601
export DEADAIR_API_KEY
DEADAIR_API_KEY=$(cat "$out_dir/api-key")

"$binary" scan --rule "$out_dir/baseline-rule.json" --out "$out_dir/baseline.json" >/dev/null

status=0
"$binary" scan --rule "$out_dir/candidate-rule.json" --out "$out_dir/candidate.json" >/dev/null || status=$?
if [ "$status" -ne 1 ]; then
	echo "candidate scan returned $status, expected 1" >&2
	exit 1
fi
