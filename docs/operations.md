# Operations

## Health and readiness

| Route | Answers | Use it for |
|---|---|---|
| `GET /health` | `200 {"status":"ok"}` as soon as the process serves. | Liveness. |
| `GET /ready` | `503` with `"status":"starting"` until the crawler has finished its first cycle, then `200` with `"status":"ready"`, and `503` with `"status":"stopping"` once shutdown has begun. | Readiness: keep traffic away from a broker that has not crawled yet or is stopping. |

`/ready` does not wait for the first cycle when there is no
`broker:participant`, or when a `broker:holder` is configured. A `dcp` or
`oid4vp` crawl needs the participant to call back into this broker
(`/dsp/holder/did.json`, `/dsp/holder/presentations/query`), and a load
balancer that holds traffic until `/ready` passes would block those calls
and fail the very cycle readiness waits for.

Both routes answer without a token, since probes carry none. With
`broker:oauth2JwksUri` set, `/ready` lists `participants` only for a caller
with a valid token; everyone else gets `status` and `cycles_completed`,
since participant ids and upstream error text describe the deployment.

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

On `SIGTERM` or `SIGINT`:

1. `/ready` starts answering `503 stopping`, and the crawler stops. A crawl
   cycle in flight is interrupted: its HTTP requests are dropped, and a
   catalog already being written completes first.
2. After `broker:shutdownDelaySecs` (unset: none), the listener closes and
   requests in flight are allowed to finish. The delay gives load balancers
   time to notice `/ready` and stop routing new requests; the image is
   distroless, so a `preStop` `sleep` hook is not available.
3. The process exits with status 0.

A second `SIGTERM` or `SIGINT` exits at once with status 130, without
draining. Nothing is persisted, so nothing needs flushing. Give the
process a termination grace period longer than the delay plus your slowest
request. A `/sparql` request is answered within `broker:sparqlQueryTimeoutMs`,
but a query whose cost is in-memory work (a large `VALUES` cross product,
say) cannot be interrupted and keeps its evaluation slot until it ends; the
process waits for such evaluations before exiting. At most
`broker:sparqlMaxConcurrent` of them run at once, and further queries get
`503` until a slot frees up.

If the crawl scheduler stops on its own (a panic), the broker exits with
status 1 rather than keep serving catalogs that would no longer be
refreshed or expired, so the supervisor restarts it.

## Container image

The repository's [`Dockerfile`](../Dockerfile) builds a two-stage image: the
release binary on `rust:1-bookworm` (the stable toolchain, like CI), run on
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
