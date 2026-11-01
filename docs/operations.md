# Operations

## Health and readiness

| Route | Answers | Use it for |
|---|---|---|
| `GET /health` | `200 {"status":"ok"}` as soon as the process serves. | Liveness. |
| `GET /ready` | `503` with `"status":"starting"` until the crawler has finished its first cycle, then `200` with `"status":"ready"`. With no `broker:participant`, `200` at once. | Readiness: keep traffic away from a broker that has not crawled yet. |

Neither route is gated by OAuth2, since probes carry no token.

`/ready` also reports the crawler's state. A cycle counts as finished
whatever its outcome, so a broker whose participants are all down still
becomes ready; the per-participant fields say why nothing is cached.

```json
{
  "status": "ready",
  "crawler": {
    "cycles_completed": 12,
    "participants": [
      {
        "id": "participant-a",
        "last_attempt": "2026-11-01T02:13:12Z",
        "last_success": "2026-11-01T02:13:12Z",
        "last_error": null,
        "cached": true,
        "catalog_age_secs": 41
      }
    ]
  }
}
```

- `last_attempt` and `last_success` are RFC 3339 UTC times; `null` before
  the first attempt or success.
- `last_error` is the last crawl's error, cleared by the next success. A
  participant can have both a `last_error` and a cached catalog: a failed
  crawl keeps the previous catalog until it is older than
  `broker:catalogMaxAgeSecs`.
- `cached` is false before the first success and after the catalog expires.
- `catalog_age_secs` is the age of the cached catalog, `null` when nothing
  is cached.

`crawler` is `null` when no crawler runs.

## Shutdown

On `SIGTERM` or `SIGINT` the broker stops accepting connections, lets
requests in flight finish, and stops the crawler. A crawl cycle in flight
is interrupted: its HTTP requests are dropped, and a catalog already being
written completes first. Nothing is persisted, so nothing else needs
flushing. Give the process a termination grace period longer than your
slowest request; `/sparql` evaluations are bounded by
`broker:sparqlQueryTimeoutMs`.

## Container image

The repository's [`Dockerfile`](../Dockerfile) builds a two-stage image: the
release binary on `rust:1.97-bookworm`, run on
`gcr.io/distroless/cc-debian12:nonroot` as an unprivileged user. CI builds
it on every pull request (the `image` job) without pushing it.

```bash
git submodule update --init vendor/contreforts-*
docker build -t ds-catalog-broker-rs .
docker run --rm -p 8080:8080 \
  -v "$PWD/broker.ttl:/etc/ds-catalog-broker/config.ttl:ro" \
  ds-catalog-broker-rs
```

`CONFIG_STORE_PATH` is the only input. The image sets it to
`/etc/ds-catalog-broker/config.ttl`, so a container started without that
file mounted stops at once, rather than starting with built-in defaults.
Point it elsewhere (a directory, another file, or an `http(s)://` URL) as
described in [configuration.md](configuration.md).

The config must set `broker:httpApiAddr` to a non-loopback address, for
example `"0.0.0.0:8080"`: the default, `127.0.0.1:8080`, is not reachable
from outside the container. A holder credential
(`broker:credentialJwsFile`) is mounted the same way, as a read-only file.
