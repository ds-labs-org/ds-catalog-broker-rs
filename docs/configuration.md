# Configuration

The broker reads its runtime configuration from one Turtle file, through the
vendored [`contreforts-config`](../vendor/contreforts-config) crate's
`ConfigStore`. No setting is read from environment variables.

## Where the file lives

`ConfigStore` loads `<datadir>/config_graph.ttl` into its config graph
(`https://contreforts.ds-labs.org/data/graph/config`). The datadir is
resolved the way `contreforts-config` resolves it:

1. `CONFIG_STORE_PATH`, when set and non-empty. A file there that cannot be
   read or parsed stops the broker at startup.
2. Otherwise `<os-data-dir>/config_store` (for example
   `~/.local/share/config_store` on Linux), but only when that directory
   already holds a `config_graph.ttl`. With no file there, the broker starts
   with every setting at its default and does not create the directory.

`CONFIG_STORE_PATH` is the only environment variable in the configuration
path. `RUST_LOG` still controls log filtering.

## Shape

All settings are properties of a single `broker:BrokerConfig` resource, in
the `https://catalog-broker.ds-labs.org/ontologies/config#` namespace. The
subject IRI is up to you. Two `broker:BrokerConfig` resources, or two values
for one property, stop the broker at startup. An unknown `broker:` property
is logged as a warning and ignored.

[`examples/config_graph.ttl`](examples/config_graph.ttl) sets every
property; a test (`config::tests::reads_every_setting_from_the_example_ttl`)
keeps it in step with the code.

## Settings

Every setting is optional.

| Property | Default | Meaning | Replaces env var |
|---|---|---|---|
| `broker:httpApiAddr` | `127.0.0.1:8080` | Address the HTTP API listens on. | `HTTP_API_ADDR` |
| `broker:crawlerConfigPath` | unset | Path to the participant registry TOML. Unset serves one sample catalog from an in-memory cache, with no crawler and `/sparql` answering 501. | `CRAWLER_CONFIG_PATH` |
| `broker:oauth2JwksUri` | unset | JWKS endpoint for OAuth2 Bearer gating of `/catalog` and `/sparql`. Unset leaves both unauthenticated. See [oauth2-bearer-gating-2026-08-28.md](oauth2-bearer-gating-2026-08-28.md). | `OAUTH2_JWKS_URI` |
| `broker:oauth2Issuer` | unset | Expected `iss` claim; checked only if set. | `OAUTH2_ISSUER` |
| `broker:oauth2Audience` | unset | Expected `aud` claim; checked only if set. | `OAUTH2_AUDIENCE` |
| `broker:oauth2RequiredScope` | unset | One scope the token's `scope` claim must contain; checked only if set. | `OAUTH2_REQUIRED_SCOPE` |
| `broker:sparqlQueryTimeoutMs` | `10000` | A `/sparql` evaluation running longer is stopped with `503`. Positive integer. | `SPARQL_QUERY_TIMEOUT_MS` |
| `broker:sparqlMaxRows` | `10000` | A `/sparql` `SELECT` result with more rows is rejected with `400`. Positive integer. | `SPARQL_MAX_ROWS` |
| `broker:policyFilterUnmappableConstraintAction` | `hide_dataset` | `skip`, `drop_policy` or `hide_dataset`: what ODRL filtering does with a constraint it cannot evaluate. | `POLICY_FILTER_UNMAPPABLE_CONSTRAINT_ACTION` |
| `broker:policyFilterNoPolicyVisibility` | `open` | `open` or `closed`: whether a dataset with no permissions is visible. | `POLICY_FILTER_NO_POLICY_VISIBILITY` |
| `broker:policyFilterRunWhenOauth2Disabled` | `true` | `false` turns ODRL filtering off when OAuth2 gating is off. | `POLICY_FILTER_RUN_WHEN_OAUTH2_DISABLED` |

A value that does not parse (a non-positive integer, an unknown enum value)
is logged as a warning and the default is used. Integers and booleans can
be written as plain Turtle literals (`10000`, `true`) or as strings.

The old environment variables in the last column are no longer read.
