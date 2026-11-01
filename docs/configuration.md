# Configuration

The broker reads its runtime configuration from one Turtle file, through the
vendored [`contreforts-config`](../vendor/contreforts-config) crate's
`ConfigStore`. No setting is read from environment variables.

## Where the file lives

`CONFIG_STORE_PATH` names the config, in one of these forms:

| Value | Read as |
|---|---|
| `/etc/broker` or `file:///etc/broker` (a directory) | A `contreforts-config` datadir: `<dir>/config_graph.ttl` is read. |
| `/etc/broker/broker.ttl` or `file:///etc/broker/broker.ttl` (a file) | That Turtle document. |
| `https://config.example.org/broker.ttl` (or `http://`) | A Turtle document fetched once at startup with `Accept: text/turtle`. Relative IRIs in it resolve against the URL. |

The broker never writes to its configuration. A datadir is read directly,
not through `ConfigStore::open`, so a missing directory is not created and a
corrupt `config_graph.ttl` is not repaired from its `.bak.N` backups; both
stop the broker instead.

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
for one setting (anything but `broker:participant`, which repeats), stop the
broker at startup. So does anything in the `broker:` namespace that the
broker would otherwise skip without a word, since a typo there would leave
a setting at its default without anyone noticing:

- an unknown `broker:` property, on this resource or on a participant or
  the holder;
- an `rdf:type` in the `broker:` namespace other than `broker:BrokerConfig`,
  `broker:Participant` or `broker:Holder` (a misspelled class);
- a `broker:` property or class on any subject that is neither the
  `broker:BrokerConfig` resource nor a participant or holder linked from
  it, including a file with `broker:` triples but no `broker:BrokerConfig`;
- a blank node as a setting's value.

Triples in other vocabularies (`rdfs:label`, comments as data) are ignored.

The crawler's participants and its holder identity are separate resources,
linked from `broker:BrokerConfig`; see [Participants and holder](#participants-and-holder).

[`examples/config_graph.ttl`](examples/config_graph.ttl) sets every
property; a test (`config::tests::reads_every_setting_from_the_example_ttl`)
keeps it in step with the code.

## Settings

Every setting is optional.

| Property | Default | Meaning |
|---|---|---|
| `broker:httpApiAddr` | `127.0.0.1:8080` | Address the HTTP API listens on. In a container, set a non-loopback address such as `0.0.0.0:8080` (see [operations.md](operations.md#container-image)). |
| `broker:participant` | none | A `broker:Participant` to crawl; repeat for each. With none, no crawler runs and every route, `/sparql` included, answers from an empty store. |
| `broker:holder` | unset | The crawler's `broker:Holder` identity. Required when a participant uses the `dcp` or `oid4vp` credential protocol. |
| `broker:crawlIntervalSecs` | `300` | Seconds between the starts of two crawl cycles. Positive integer. |
| `broker:crawlTimeoutMs` | `30000` | How long one participant's crawl may take, credential presentation and response body included, before it counts as failed. Positive integer. |
| `broker:crawlConcurrency` | `8` | How many participants are crawled at the same time. Positive integer. |
| `broker:catalogMaxAgeSecs` | `86400` | A participant's cached catalog is removed once its last successful crawl is older than this, so a participant that stays down stops being served. A failed crawl keeps the previous catalog until then. Positive integer. |
| `broker:oauth2JwksUri` | unset | JWKS endpoint for OAuth2 Bearer gating of `/catalog` and `/sparql`. Unset leaves both unauthenticated. See [oauth2-bearer-gating-2026-08-28.md](oauth2-bearer-gating-2026-08-28.md). |
| `broker:oauth2Issuer` | unset | Expected `iss` claim; checked only if set. |
| `broker:oauth2Audience` | unset | Expected `aud` claim; checked only if set. |
| `broker:oauth2RequiredScope` | unset | One scope the token's `scope` claim must contain; checked only if set. |
| `broker:sparqlQueryTimeoutMs` | `10000` | A `/sparql` evaluation running longer is stopped with `503`. Positive integer. |
| `broker:sparqlMaxRows` | `10000` | A `/sparql` `SELECT` result with more rows is rejected with `400`. Positive integer. |
| `broker:policyFilterUnmappableConstraintAction` | `hide_dataset` | `skip`, `drop_policy` or `hide_dataset`: what ODRL filtering does with a constraint it cannot evaluate. |
| `broker:policyFilterNoPolicyVisibility` | `open` | `open` or `closed`: whether a dataset with no permissions is visible. |
| `broker:policyFilterRunWhenOauth2Disabled` | `true` | Boolean. `false` turns ODRL filtering off when OAuth2 gating is off. |

A value that does not parse stops the broker at startup, with an error that
names the property and the value; the default is used only when a setting
is absent. "Positive integer" means a whole number greater than zero.
Booleans are `true`, `false`, `1` or `0`. The enum values above are matched
exactly, case included. Integers and booleans can be written as plain
Turtle literals (`10000`, `true`) or as strings.

## Participants and holder

Each participant is a resource typed `broker:Participant`, and the holder a
resource typed `broker:Holder`. Either can be an IRI or a blank node:

```turtle
<urn:ds-catalog-broker:config> a broker:BrokerConfig ;
    broker:participant <urn:participant:a>, [
        a broker:Participant ;
        broker:participantId "gated" ;
        broker:participantName "DCP-gated participant" ;
        broker:catalogRequestUrl "https://gated.example.org/dsp/catalog/request" ;
        broker:credentialProtocol "dcp" ;
        broker:providerDid "did:web:gated.example.org:dsp"
    ] ;
    broker:holder <urn:holder> .

<urn:participant:a> a broker:Participant ;
    broker:participantId "a" ;
    broker:participantName "Participant A" ;
    broker:catalogRequestUrl <https://a.example.org/dsp/catalog/request> .

<urn:holder> a broker:Holder ;
    broker:ownDidHost "broker.example.org" ;
    broker:credentialJwsFile "/run/secrets/holder.jws" ;
    broker:requiredScope "org.eclipse.dspace.dcp.vc.type:FederatedCatalogAccessCredential:read" .
```

Every value is a string literal, except that `broker:catalogRequestUrl` and
`broker:oid4vpResponseUri` may also be IRIs and `broker:credentialJwsFile`
may be a `file:` IRI.

| `broker:Participant` property | Required | Meaning |
|---|---|---|
| `broker:participantId` | yes | Unique id; it identifies the participant on its harvested catalog and in logs. |
| `broker:participantName` | yes | Display name. |
| `broker:catalogRequestUrl` | yes | The participant's DSP catalog request endpoint. |
| `broker:credentialProtocol` | no | `none` (default), `dcp` or `oid4vp`: what the crawler presents to this participant. |
| `broker:providerDid` | for `dcp` | The participant's DID, the audience of the self-issued token. |
| `broker:oid4vpResponseUri` | for `oid4vp` | The OID4VP `direct_post` endpoint the presentation is sent to. |

| `broker:Holder` property | Required | Meaning |
|---|---|---|
| `broker:ownDidHost` | yes | The crawler's own `did:web` host[:port]; its DID is `did:web:<host>:dsp:holder`. |
| `broker:insecureHttp` | no | `true` resolves `did:web` DIDs over `http://`, for local tests. Default `false`. |
| `broker:credentialJwsFile` | yes | A local file holding the crawler's Verifiable Credential (a JWS compact string). See below. |
| `broker:requiredScope` | yes | The DCP scope the credential is expected to satisfy. |

The credential is a bearer secret, so it is read from a file rather than
written in the config, which may be fetched over HTTP. The value is a path
string (relative paths resolve against the broker's working directory), a
`file:` URL string, or a `file:` IRI. A relative IRI such as `<holder.jws>`
resolves against the config's own location, so it works for a local config
but not for one fetched over HTTP, where it becomes an `https` IRI. Any IRI
that isn't `file:`, a blank node, or an empty string is rejected. The file is read
once at startup, with surrounding whitespace trimmed; a missing or empty
file stops the broker. Protect it with file permissions.

Like the settings above, these resources are read strictly. Each of the
following stops the broker at startup:

- a missing required property, two values for one property, or a value of
  the wrong kind (see above);
- a `broker:participant` or `broker:holder` value that is a literal, or a
  resource without the matching `rdf:type`;
- a `broker:Participant` or `broker:Holder` resource that no
  `broker:participant` or `broker:holder` links to;
- more than one `broker:holder`;
- an unknown `broker:credentialProtocol` or a non-boolean
  `broker:insecureHttp`;
- a blank `broker:participantId` or `broker:participantName`;
- a `broker:catalogRequestUrl` or `broker:oid4vpResponseUri` that is not an
  absolute `http` or `https` URL (a relative IRI resolves against the
  config's location, so it usually becomes a `file:` IRI and is rejected);
- a `broker:providerDid` that is not a DID (`did:<method>:<id>`);
- `broker:providerDid` on a participant whose protocol is not `dcp`, or
  `broker:oid4vpResponseUri` on one whose protocol is not `oid4vp`;
- two participants with the same `broker:participantId`;
- a `dcp` participant without `broker:providerDid`, an `oid4vp` participant
  without `broker:oid4vpResponseUri`, or either one without a
  `broker:holder`.

The holder is checked the same way even when there is no participant.
Errors name a blank-node participant by its `broker:participantId`. With no
participant the crawler stays off, and a `broker:holder` or any `broker:crawl*`
or `broker:catalogMaxAgeSecs` setting is logged as a warning, since it has no
effect.

These replace the participant registry TOML file that
`broker:crawlerConfigPath` used to name. That property is no longer read.
