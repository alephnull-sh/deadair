# Least-privilege credentials — OpenSearch

deadair needs two read paths in OpenSearch:

1. Security Analytics detector metadata, via
   `POST /_plugins/_security_analytics/detectors/_search`
2. source stats/freshness, via `_data_stream/_stats`, `_cat/indices`, and size-0
   `max(@timestamp)` searches for plain indices

> Status: **proven** against docker OpenSearch 2.19.3 on 2026-07-04 by the integration suite
> (`make opensearch-integration`): scan succeeds with a user carrying only the roles below, and
> representative writes (document/index/data-stream writes, detector create, role update) are
> rejected.

## Role shape

OpenSearch ships a built-in `security_analytics_read_access` role for read access to Security
Analytics detectors, alerts, findings, mappings, and rules. Pair that with a small index-monitor
role for the source inventory calls.

```jsonc
// PUT _plugins/_security/api/roles/deadair_index_monitor
{
  "cluster_permissions": [
    "cluster_monitor"
  ],
  "index_permissions": [
    {
      "index_patterns": ["*"],
      "allowed_actions": [
        "read",
        "indices_monitor"
      ]
    }
  ]
}
```

Assign both roles to the deadair user or backend role:

- `security_analytics_read_access`
- `deadair_index_monitor`

Scope `index_patterns` tighter than `"*"` if your telemetry lives under known patterns
(for example `logs-*`, `winlogbeat-*`, or `audit-*`). deadair only reports on what it can see.

## Authentication

Basic auth:

```sh
export DEADAIR_BACKEND=opensearch
export DEADAIR_OPENSEARCH_URL=https://opensearch.example.internal:9200
export DEADAIR_OPENSEARCH_USERNAME=deadair
export DEADAIR_OPENSEARCH_PASSWORD=<password>

deadair scan
```

For daemons, prefer a file over an environment variable:

```sh
deadair serve \
  --backend opensearch \
  --opensearch-url https://opensearch.example.internal:9200 \
  --opensearch-username deadair \
  --opensearch-password-file /etc/deadair/opensearch-password
```

API key auth is also supported when your OpenSearch deployment accepts `Authorization: ApiKey`:

```sh
export DEADAIR_BACKEND=opensearch
export DEADAIR_OPENSEARCH_URL=https://opensearch.example.internal:9200
export DEADAIR_OPENSEARCH_API_KEY=<api key>

deadair scan
```

## Calls deadair makes

- `POST /_plugins/_security_analytics/detectors/_search`
- `GET /_data_stream/_stats`
- `GET /_cat/indices?format=json&h=index,docs.count,store.size&bytes=b`
- `POST /<index>/_search` with `size: 0`, `track_total_hits: false`, and a max aggregation on
  `@timestamp` for plain indices that do not have data-stream freshness

deadair never uses detector writes, rule writes, document writes, index creation/deletion, or user
and role management APIs. If an audit shows it asking for those, that's a bug.
