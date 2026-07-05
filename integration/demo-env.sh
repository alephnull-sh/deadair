#!/bin/bash
set -e
ES=http://localhost:9200; KB=http://localhost:5601; AUTH="elastic:changeme-deadair"
NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ); OLD=$(date -u -v-72H +%Y-%m-%dT%H:%M:%SZ); LAGTS=$(date -u -v+45M +%Y-%m-%dT%H:%M:%SZ)

curl -s -u $AUTH -X POST "$KB/api/fleet/epm/packages/security_detection_engine" -H "kbn-xsrf: d" -H "Content-Type: application/json" -d '{"force":true}' --max-time 240 -o /dev/null -w "package: %{http_code}\n"
curl -s -u $AUTH -X POST "$KB/internal/detection_engine/prebuilt_rules/installation/_perform" -H "kbn-xsrf: d" -H "elastic-api-version: 1" -H "x-elastic-internal-origin: Kibana" -H "Content-Type: application/json" -d '{"mode":"ALL_RULES"}' --max-time 600 -o /dev/null -w "rules install: %{http_code}\n"
curl -s -u $AUTH -X POST "$KB/api/detection_engine/rules/_bulk_action" -H "kbn-xsrf: d" -H "Content-Type: application/json" -d '{"action":"enable","query":"alert.attributes.tags: \"OS: Windows\""}' --max-time 300 -o /dev/null -w "enable: %{http_code}\n"

bulk() { local body=""; for i in $(seq 1 $3); do body+="{\"create\":{}}\n{\"@timestamp\":\"$2\",\"message\":\"e$i\",\"host\":{\"name\":\"ft\"}}\n"; done; printf "$body" | curl -s -u $AUTH -X POST "$ES/$1/_bulk" -H "Content-Type: application/x-ndjson" --data-binary @- -o /dev/null; echo "seeded $1"; }
for s in logs-endpoint.events.process-default logs-endpoint.events.network-default logs-windows.sysmon_operational-default logs-windows.powershell-default logs-system.security-default; do bulk "$s" "$NOW" 25; done
bulk "logs-system.auth-default" "$OLD" 25
bulk "logs-myapp.custom-default" "$NOW" 200
bulk "metrics-myapp.usage-default" "$NOW" 100
curl -s -u $AUTH -X PUT "$ES/winlogbeat-2026.07.04" -H "Content-Type: application/json" -d '{"mappings":{"properties":{"@timestamp":{"type":"date"}}}}' -o /dev/null && bulk "winlogbeat-2026.07.04" "$NOW" 25

# U4: stream with 30d lifecycle retention
bulk "logs-retained.audit-default" "$NOW" 50
curl -s -u $AUTH -X PUT "$ES/_data_stream/logs-retained.audit-default/_lifecycle" -H "Content-Type: application/json" -d '{"data_retention":"30d"}' -o /dev/null -w "lifecycle: %{http_code}\n"
# U5: stream whose events arrive ~45m after their event time
body=""; for i in $(seq 1 30); do body+="{\"create\":{}}\n{\"@timestamp\":\"$NOW\",\"event\":{\"ingested\":\"$LAGTS\"},\"message\":\"b$i\"}\n"; done
printf "$body" | curl -s -u $AUTH -X POST "$ES/logs-batchy.events-default/_bulk" -H "Content-Type: application/x-ndjson" --data-binary @- -o /dev/null; echo "seeded logs-batchy.events-default"

mkrule() { curl -s -u $AUTH -X POST "$KB/api/detection_engine/rules" -H "kbn-xsrf: d" -H "Content-Type: application/json" -d "$1" -o /dev/null -w "rule: %{http_code}\n"; }
mkrule '{"rule_id":"demo-trunc","name":"Quarterly audit sweep","description":"d","risk_score":47,"severity":"medium","type":"query","query":"*:*","index":["logs-retained.audit-*"],"from":"now-90d","interval":"1h","enabled":true}'
mkrule '{"rule_id":"demo-fields","name":"Sysmon custom parser match","description":"d","risk_score":73,"severity":"high","type":"query","query":"*:*","index":["logs-windows.sysmon_operational-*"],"from":"now-6m","interval":"5m","enabled":true,"required_fields":[{"name":"winlog.event_data.CustomTelemetry","type":"keyword"},{"name":"host.name","type":"keyword"}]}'
mkrule '{"rule_id":"demo-lag","name":"Batch-fed source watcher","description":"d","risk_score":47,"severity":"medium","type":"query","query":"*:*","index":["logs-batchy.events-*"],"from":"now-6m","interval":"5m","enabled":true}'
curl -s -u $AUTH -X POST "$ES/_refresh" -o /dev/null; echo refreshed

curl -s -u $AUTH -X POST "$ES/_security/api_key" -H "Content-Type: application/json" -d '{"name":"deadair-demo2","role_descriptors":{"deadair_monitor":{"cluster":["monitor","read_ilm"],"indices":[{"names":["*"],"privileges":["monitor","view_index_metadata","read"]}],"applications":[{"application":"kibana-.kibana","privileges":["feature_siem.read","feature_siemV2.read"],"resources":["space:default"]}]}}}' | python3 -c "import json,sys; print(json.load(sys.stdin)['encoded'])" > "$(dirname "$0")/demo-key"
echo "key ready"

# Real ECS mappings: install the system integration package so seeded streams
# get genuine agent-grade templates (thousands of fields) instead of skeletal
# lab mappings — keeps missing-fields findings realistic.
curl -s -u $AUTH -X POST "$KB/api/fleet/epm/packages/system" -H "kbn-xsrf: d" -H "Content-Type: application/json" -d '{"force":true}' --max-time 240 -o /dev/null -w "system package (ECS mappings): %{http_code}\n"
