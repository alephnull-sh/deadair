# OpenSearch least-privilege credentials

deadair needs read access to two things:

1. Security Analytics detector metadata
2. OpenSearch source inventory, freshness, and optional field metadata

It does not need detector writes, document writes, index management, or user/role management.

Status: proven against OpenSearch 2.19.3 by the integration suite. The test scans successfully
with only the roles below, then verifies representative writes are rejected.

## Roles

Use the built-in `security_analytics_read_access` role for Security Analytics metadata.

Add a small index-monitor role for source inventory and freshness:

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

Scope `index_patterns` tighter than `"*"` if telemetry is under known patterns such as `logs-*`,
`winlogbeat-*`, or `audit-*`. deadair only reports on sources the role can see.

## Basic auth

```sh
export DEADAIR_BACKEND=opensearch
export DEADAIR_OPENSEARCH_URL=https://opensearch.example.internal:9200
export DEADAIR_OPENSEARCH_USERNAME=deadair
export DEADAIR_OPENSEARCH_PASSWORD=<password>

deadair check
deadair scan
```

For a daemon, prefer a file:

```sh
install -m 0600 /dev/null /etc/deadair/opensearch-password
printf '%s' '<password>' > /etc/deadair/opensearch-password

deadair serve \
  --backend opensearch \
  --opensearch-url https://opensearch.example.internal:9200 \
  --opensearch-username deadair \
  --opensearch-password-file /etc/deadair/opensearch-password
```

## API key auth

API key auth is supported when your OpenSearch deployment accepts `Authorization: ApiKey`.

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
- `POST /<index>/_search` with `size: 0` aggregations for freshness and ingest lag
- `GET /<index>/_field_caps` when `--schema` is enabled

If an audit shows deadair requesting detector writes, document writes, index creation/deletion, or
user and role management APIs, treat that as a bug.
