# Elastic least-privilege credentials

deadair needs read access to two things:

1. Elastic Security detection-rule metadata through Kibana
2. Elasticsearch source inventory, freshness, and optional field metadata

It does not need document writes, rule writes, index management, cluster admin, or Kibana write
privileges.

Status: proven against Elastic 8.17.4 by the integration suite. The test scans successfully with
only this role, then verifies representative writes are rejected with 403. CI repeats that proof
on every push.

## Create the role

```jsonc
// POST _security/role/deadair_monitor
{
  "cluster": ["monitor"],
  "indices": [
    {
      "names": ["*"],
      "privileges": ["monitor", "view_index_metadata", "read"]
    }
  ],
  "applications": [
    {
      "application": "kibana-.kibana",
      "privileges": ["feature_siem.read", "feature_siemV2.read"],
      "resources": ["space:default"]
    }
  ]
}
```

Privilege notes:

| Privilege | Why deadair needs it |
|---|---|
| `cluster: monitor` | read data-stream and index stats |
| `indices: monitor` | read index and data-stream metadata |
| `view_index_metadata` | read mappings and `field_caps` when `--schema` is used |
| `read` | run size-0 freshness and lag aggregations |
| `feature_siem.read`, `feature_siemV2.read` | read detection rules through Kibana |

Scope `indices.names` tighter than `"*"` if telemetry is under known patterns such as `logs-*`,
`winlogbeat-*`, or `audit-*`. deadair only reports on sources the role can see.

That visibility affects verdicts. If an enabled rule expects `winlogbeat-*` but the role can read
only `logs-*`, deadair sees no matching source even if Winlogbeat indices exist. `deadair check`
confirms that required API calls are allowed; it cannot prove that a scoped role includes every
source your rules use. After tightening the role, verify at least one known-good rule and source in
the first JSON report before triaging no-match findings.

For a non-default Kibana space, change the resource and run scans with `--kibana-space`:

```jsonc
"resources": ["space:soc"]
```

```sh
deadair scan --kibana-space soc
```

## Create an API key

```jsonc
// POST _security/api_key
{
  "name": "deadair",
  "role_descriptors": {
    "deadair_monitor": {
      /* role body from above */
    }
  }
}
```

Use the response's `encoded` value.

For an interactive scan:

```sh
export DEADAIR_ES_URL=https://es.example.internal:9200
export DEADAIR_KIBANA_URL=https://kibana.example.internal:5601
export DEADAIR_API_KEY=<encoded>

deadair check
deadair scan
```

For a daemon, prefer a file:

```sh
install -m 0600 /dev/null /etc/deadair/api-key
printf '%s' '<encoded>' > /etc/deadair/api-key

deadair serve \
  --es-url https://es.example.internal:9200 \
  --kibana-url https://kibana.example.internal:5601 \
  --api-key-file /etc/deadair/api-key
```

## Calls deadair makes

- `GET /api/detection_engine/rules/_find`
- `GET /_data_stream/_stats`
- `GET /_cat/indices`
- `POST /<index>/_search` with `size: 0` aggregations for freshness and ingest lag
- `GET /<index>/_field_caps` when `--schema` is enabled

If an audit shows deadair requesting a write API or broader privileges than this document, treat
that as a bug.
