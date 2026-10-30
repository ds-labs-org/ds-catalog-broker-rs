# Configuration

The broker reads its runtime configuration from one Turtle file, through the
vendored [`contreforts-config`](../vendor/contreforts-config) crate's
`ConfigStore`. No setting is read from environment variables.

## Where the file lives

`CONFIG_STORE_PATH` names the config, in one of these forms:

| Value | Read as |
|---|---|
| `/etc/broker` or `file:///etc/broker` (a directory) | A `contreforts-config` datadir, opened with `ConfigStore::open`, which loads `<dir>/config_graph.ttl`. |
| `/etc/broker/broker.ttl` or `file:///etc/broker/broker.ttl` (a file) | That Turtle document. |
| `https://config.example.org/broker.ttl` (or `http://`) | A Turtle document fetched once at startup with `Accept: text/turtle`. Relative IRIs in it resolve against the URL. |

Any other URL scheme, a `file://` URL with a host, a path that can't be
read, a non-2xx HTTP answer, or Turtle that doesn't parse stops the broker
at startup. The config is read once at startup; restart the broker to pick
up a change. Fetches go through the standard `HTTP(S)_PROXY` variables, as
reqwest does by default.

With `CONFIG_STORE_PATH` unset, the location is `contreforts-config`'s
per-user default, `<os-data-dir>/config_store` (for example
`~/.local/share/config_store` on Linux). It is used only when it already
holds a `config_graph.ttl`. Otherwise the broker starts with every setting
at its default and does not create the directory.

Whichever form you use, the document's triples are read as the config
graph (`https://contreforts.ds-labs.org/data/graph/config`).

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
