# Redis client modes

Session storage, configuration notifications, and OAuth storage select a Redis
client from `cluster_type`. The number of configured addresses never changes the
selected mode.

| `cluster_type` | Addresses | Client |
| --- | --- | --- |
| `single` (also the default when omitted) | One Redis address | Standalone |
| `sentinel` | One or more Sentinel addresses, with `master_name` | Sentinel failover |
| `cluster` | One or more Redis Cluster seed addresses | Cluster |

Existing `addr` settings accept comma- or semicolon-separated addresses. Surrounding
whitespace and empty entries are ignored. Missing addresses, unknown modes, multiple
addresses in single mode, and a missing Sentinel master name fail initialization.
Configurations that previously relied on multiple addresses implicitly selecting
Cluster must now explicitly set `cluster_type: cluster`.

A single Cluster seed is valid: the Cluster client discovers the slot topology and
routes commands to the node owning each key. Multiple seeds improve startup
availability when a seed is unreachable. A successful `PING` only checks connectivity;
it does not prove that operations on keys in other shards work.

Standalone and Sentinel modes retain the configured DB and authentication.
Cluster mode continues to ignore `db`, because Redis Cluster uses DB 0.
Sentinel authentication and Redis data-node authentication remain separate.
YAML keys and environment-variable names are unchanged.

`internal/redisclient.New` owns mode selection and connection-option validation.
Each storage/notifier instance owns its client, connection checks, and cleanup;
failed connection checks close the newly created client. Data keys, TTLs, stream
delivery, and OAuth operations belong to their existing modules.

This contract covers client construction. It does not establish Cluster
compatibility for every operation, such as scanning all shards or multi-key commands.

## Verification

The normal `make test` suite checks explicit mode selection and each consumer's
single-seed Cluster construction using miniredis. To exercise shard routing and
session/configuration events against a disposable multi-node Redis Cluster, run:

```sh
UNLA_TEST_REDIS_CLUSTER_ADDR=127.0.0.1:17000 make test \
  TEST_PACKAGES=./internal/redisclient \
  TEST_FLAGS='-v -race -run TestSingleSeedClusterAcrossShards'
```

The test requires keys served by a node other than the seed, confirms that a plain
client receives `MOVED`, and then verifies the stores can access those keys through
the Cluster client. It also checks discovery with an unreachable seed in the list.
It creates uniquely tagged test keys and deletes those keys when finished.
