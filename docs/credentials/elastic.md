# Elastic least-privilege credentials

deadair needs read access to three things:

1. Elastic Security detection-rule metadata through Kibana.
2. Data-view metadata through Kibana when a rule uses a data view.
3. Elasticsearch index, alias, and data-stream resolution, plus source inventory, freshness, and
   optional field metadata.

It does not need document writes, rule writes, index management, cluster admin, or Kibana write
privileges.

Live integration tests cover Elastic 8.19.19 and 9.4.4. Each version is scanned with only this role.
The tests exercise native input resolution and require representative write attempts to return
`403`.

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
      "privileges": ["feature_siem.read", "feature_siemV2.read", "feature_indexPatterns.read"],
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
| `view_index_metadata` | resolve index, alias, and data-stream selectors; read targeted `field_caps`, plus full mappings when `--schema` is used |
| `read` | run size-0 freshness aggregations and read a bounded sample of paired timestamps for lag checks |
| `feature_siem.read`, `feature_siemV2.read` | read detection rules through Kibana |
| `feature_indexPatterns.read` | read Data View Management objects referenced by detection rules |

Narrow `indices.names` from `"*"` when telemetry follows known patterns such as `logs-*`,
`winlogbeat-*`, or `audit-*`. deadair can report only on sources visible to its role.

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

For a long-running service, keep the API key in a file with `0600` permissions:

```sh
install -m 0600 /dev/null /etc/deadair/api-key
printf '%s' '<encoded>' > /etc/deadair/api-key

deadair serve \
  --es-url https://es.example.internal:9200 \
  --kibana-url https://kibana.example.internal:5601 \
  --api-key-file /etc/deadair/api-key
```

## Calls deadair makes

- `GET /` for backend version discovery
- `GET /api/detection_engine/rules/_find`
- `GET /api/data_views/data_view/<id>` for data-view-backed rules
- `GET /_resolve/index/<expression>?ignore_unavailable=true`
- `GET /_data_stream/_stats`
- `GET /_cat/indices`
- `POST /<index>/_search` with a `size: 0` aggregation for freshness
- `POST /<index>/_search` for up to 500 recent events, limited to paired `event.ingested` and `@timestamp` fields, when an enabled rule can be affected by lag
- `POST /<index>/_field_caps` for targeted declared-field checks; when `--schema` is enabled,
  deadair also reads a full `fields=*` snapshot with `GET`

If an audit shows deadair requesting a write API or broader privileges than this document, treat
that as a bug.
