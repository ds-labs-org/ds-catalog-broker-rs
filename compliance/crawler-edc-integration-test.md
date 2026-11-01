# Proving `crawler` against real Eclipse EDC 0.18.0 connectors

**Date:** 2026-08-27

**Question:** does `crates/crawler`'s HTTP client and DSP-response parser
actually work against a real Eclipse EDC connector, not just against
`http-api` (this workspace's own DSP implementation) or in-process Rust
test fixtures?

**Answer: yes — verified end to end.** Three independent, real Eclipse EDC
0.18.0 control-plane instances were built from published Maven Central
artifacts, seeded with six distinct dataset ids across them, and crawled
in a single `crawler::crawl_once` cycle from a real Rust integration test.
The resulting cache contained all six dataset ids, aggregated correctly
across three separate `Catalog` entries.

Getting there surfaced two real bugs/gaps — one in the fixture's own EDC
wiring, one in `crawler` itself — both fixed and documented below, not
routed around.

## What was built

`compliance/crawler-edc-fixture/` — a small Gradle project (`build.gradle.kts`,
Gradle wrapper pinned to 9.5.1) depending directly on
`org.eclipse.edc:controlplane-base-bom:0.18.0` from Maven Central (no
`vendor/eclipse-edc-connector` source touched or built — same recipe the
`dataspace` study repo's
[`2026-08-27-edc-catalog-metadata-exposure-policy.md`](https://labs.deepthought-solutions.net/Deepthought-Solutions/dataspace/src/branch/main/docs/spikes/2026-08-27-edc-catalog-metadata-exposure-policy.md)
spike used and confirmed published). Two `ServiceExtension`s, discovered
via the plain `java.util.ServiceLoader` mechanism `BaseRuntime` itself
uses (`src/main/resources/META-INF/services/org.eclipse.edc.spi.system.ServiceExtension` -
confirmed by reading `core/common/boot/.../ExtensionLoader.java` in the
vendored connector before relying on it):

- **`FixtureIdentityExtension`** — binds a trivial, always-succeeds
  `IdentityService` (`FixtureNoopIdentityService`, modeled on
  eclipse-edc-connector's own
  `system-tests/tck/tck-extension/.../NoopIdentityService`) plus the
  `DefaultParticipantIdExtractionFunction`/`AudienceResolver` beans real
  EDC's DSP layer requires at boot. **Not real DCP** — deliberately out
  of scope, see "Scope: real EDC-side DCP" below.
- **`CatalogFixtureExtension`** — seeds `Asset`s (`@Inject AssetIndex`),
  one shared unconstrained `use` `PolicyDefinition`
  (`@Inject PolicyDefinitionService`), and one `ContractDefinition` with
  an empty `assetsSelector` (selects every asset in the participant
  context — `@Inject ContractDefinitionService`), all parameterized by
  the `FIXTURE_ASSET_IDS` env var. Mirrors the `@Inject
  AssetIndex`/`PolicyDefinitionService`/`ContractDefinitionService` +
  `prepare()` pattern of eclipse-edc-connector's own
  `system-tests/tck/tck-extension/.../TckSetupExtension`/`DataSeed.java`,
  read for reference before writing this.

`run-instance.sh` launches one instance, entirely env-var-driven
(`INSTANCE_NAME`, `BASE_PORT`, `FIXTURE_PARTICIPANT_ID`,
`FIXTURE_ASSET_IDS`) so the same built classpath (`build/classpath.txt`,
written by the `printClasspath` Gradle task) starts three independent
instances on three different port blocks via a plain `java -cp ...
org.eclipse.edc.boot.system.runtime.BaseRuntime`, no Gradle daemon needed
per instance.

`config_graph.ttl` — a broker config (shape per
`docs/configuration.md`) whose three `broker:Participant` resources point
at the three instances' real, versioned DSP catalog-request URLs, with no
credential protocol on any of them. (This was a `participants.toml` when
the run below was recorded; the config moved into Turtle since.)

`crates/crawler/tests/crawl_real_edc.rs` — a `#[ignore]`d integration
test (depends on the three external processes above, so it must not run
in `cargo test --workspace`'s normal path) that loads `config_graph.ttl`,
runs one real `crawler::crawl_once` cycle, and **asserts** (not eyeballs)
that the cache ends up with exactly the six expected dataset ids spread
across three `Catalog` entries.

## Two real bugs found and fixed along the way

### 1. Fixture-side: `CatalogFixtureExtension` and `ControlPlaneServicesExtension` had a genuine cyclic dependency

First version bound the no-op `IdentityService` *and* seeded data in one
`ServiceExtension` class. Boot failed immediately:

```
Exception in thread "main" org.eclipse.edc.boot.util.CyclicDependencyException: Cyclic extension dependency for [InjectionContainer{injectionTarget=spike.CatalogFixtureExtension@16610890}]
	at org.eclipse.edc.boot.util.TopologicalSort.visit(TopologicalSort.java:111)
Caused by: org.eclipse.edc.boot.util.CyclicDependencyException: Cyclic extension dependency for [InjectionContainer{injectionTarget=org.eclipse.edc.connector.controlplane.services.ControlPlaneServicesExtension@4d0f2471}]
Caused by: org.eclipse.edc.boot.util.CyclicDependencyException: Cyclic extension dependency for [InjectionContainer{injectionTarget=spike.CatalogFixtureExtension@16610890}]
```

Root cause: `ControlPlaneServicesExtension` (part of
`controlplane-base-bom`) has a hard `@Inject IdentityService` — so
whatever provides `IdentityService` must have **no** dependency on
anything `ControlPlaneServicesExtension` itself provides
(`AssetIndex`/`PolicyDefinitionService`/`ContractDefinitionService`,
which the seed logic needs) or the boot-time topological sort finds a
cycle. Fixed by splitting into `FixtureIdentityExtension` (provides
`IdentityService`, no other dependencies) and `CatalogFixtureExtension`
(seeds data, depends on services `ControlPlaneServicesExtension`
provides, provides nothing back). This is fixture wiring, not a real EDC
bug — noted here because it's a genuinely non-obvious trap for anyone
writing a from-scratch EDC extension bundle.

Also needed, discovered the same way (both first-party EDC extension
points, both required at boot once any `IdentityService` is bound):
`DefaultParticipantIdExtractionFunction` (`DspApiConfigurationV2025Extension`'s
hard `@Inject`) and `AudienceResolver` (`DspHttpCoreExtension`'s hard
`@Inject`) — real EDC's own `iam-mock` module provides both alongside its
`IdentityService`; since this fixture doesn't depend on `iam-mock`
(no real per-caller identity needed — see scope note below), it provides
trivial versions of both itself, in `FixtureIdentityExtension`.

### 2. Real bug in `crates/crawler`: no `Authorization` header sent to `requires_dcp = false` participants

Real EDC's `DspRequestHandlerImpl.getResource`/`createResource` return
`401 Unauthorized` on a **missing** `Authorization` header
unconditionally — before any `IdentityService` ever runs:

```java
var token = request.getToken();
if (token == null) {
    return unauthorized(request);
}
```

(`data-protocols/dsp/dsp-core/dsp-http-core/.../DspRequestHandlerImpl.java`,
confirmed by reading it in the vendored connector.) This is not a
new/surprising finding in isolation — the `dataspace` study repo's own
[`2026-08-27-edc-catalog-metadata-exposure-policy.md`](https://labs.deepthought-solutions.net/Deepthought-Solutions/dataspace/src/branch/main/docs/spikes/2026-08-27-edc-catalog-metadata-exposure-policy.md)
spike and this repo's own `compliance/benchmark-2026-08-27.md` ("Problems
encountered" #3) both already documented that real EDC requires *a*
bearer token even under a no-op identity service — but `crates/crawler`'s
`crawl_one` had never actually been exercised against a server enforcing
that, so it had never been fixed: for a `requires_dcp = false`
participant it sent **no** `Authorization` header at all (this
workspace's own `http-api` under `DspAuthMode::Disabled` doesn't care
either way, so this went unnoticed until now). Confirmed with a live
instance before fixing:

```
$ curl -s -w '\nHTTP_STATUS:%{http_code}\n' -X POST http://127.0.0.1:18821/api/dsp/2025-1/catalog/request \
    -H "Content-Type: application/json" \
    -d '{"@context": ["https://w3id.org/dspace/2025/1/context.jsonld"], "@type": "CatalogRequestMessage"}'
HTTP_STATUS:401
```

**Fix** (`crates/crawler/src/lib.rs`, `crawl_one`): for a
`requires_dcp = false` participant, send a fixed, non-secret placeholder
`Authorization` header (`OPEN_PARTICIPANT_PLACEHOLDER_AUTH`) instead of no
header at all — a raw header value via `.header(AUTHORIZATION, ...)`, not
`.bearer_auth(...)` (real EDC's DSP layer reads the header verbatim, no
"Bearer " stripping happens in `DspRequestHandlerImpl`, matching the
project's known `iam-mock` pitfall about raw-header parsing). Harmless to
`http-api` under `DspAuthMode::Disabled` (ignores the header outright —
`crates/http-api/src/lib.rs` line ~533), required for real EDC. Verified:
after the fix, the same request against the same live instance returns
`200 OK` with both seeded datasets.

Full workspace test suite re-run after this change
(`cargo test --workspace --no-fail-fast`): every pre-existing test still
passes, with the sole exception of the one already-known, pre-existing
failure carried over from the prior step
(`crawl_once_records_a_failure_for_an_expired_dcp_credential_and_preserves_prior_cache_data`,
bug #3 from that step's report — unrelated to this change, not touched
here).

## Commands actually run, and their real output

Build the fixture and resolve its classpath:

```
$ cd compliance/crawler-edc-fixture
$ ./gradlew --offline printClasspath
...
> Task :printClasspath
wrote .../compliance/crawler-edc-fixture/build/classpath.txt (227 entries)
BUILD SUCCESSFUL in 657ms
```

Launch all three instances (backgrounded, PID captured from `$!` per the
task's own requirement — not via a wrapper script's own PID, since
`run-instance.sh` `exec`s into `java` so the backgrounded PID *is* the
`java` process):

```
$ INSTANCE_NAME=instance-a BASE_PORT=18901 FIXTURE_PARTICIPANT_ID=EDC-A FIXTURE_ASSET_IDS="EDC-A-01,EDC-A-02" \
    nohup ./run-instance.sh > logs/instance-a-stdout.log 2>&1 &
PID_A=$!   # 290609
$ INSTANCE_NAME=instance-b BASE_PORT=19001 FIXTURE_PARTICIPANT_ID=EDC-B FIXTURE_ASSET_IDS="EDC-B-01" \
    nohup ./run-instance.sh > logs/instance-b-stdout.log 2>&1 &
PID_B=$!   # 290610
$ INSTANCE_NAME=instance-c BASE_PORT=19101 FIXTURE_PARTICIPANT_ID=EDC-C FIXTURE_ASSET_IDS="EDC-C-01,EDC-C-02,EDC-C-03" \
    nohup ./run-instance.sh > logs/instance-c-stdout.log 2>&1 &
PID_C=$!   # 290611
```

Independently confirmed via `ss -tlnp` that each PID actually owns its
expected DSP port (`18921`/`19021`/`19121`, matching `config_graph.ttl`):

```
$ ss -tlnp | grep -E "18901|18911|18921|18931|18961|19001|19011|19021|19031|19061|19101|19111|19121|19131|19161"
LISTEN 0 50 *:18901 *:*  users:(("java",pid=290609,fd=236))
LISTEN 0 50 *:18911 *:*  users:(("java",pid=290609,fd=238))
LISTEN 0 50 *:18921 *:*  users:(("java",pid=290609,fd=237))   # instance A's DSP port
LISTEN 0 50 *:18931 *:*  users:(("java",pid=290609,fd=235))
LISTEN 0 50 *:18961 *:*  users:(("java",pid=290609,fd=234))
LISTEN 0 50 *:19001 *:*  users:(("java",pid=290610,fd=237))
LISTEN 0 50 *:19011 *:*  users:(("java",pid=290610,fd=234))
LISTEN 0 50 *:19021 *:*  users:(("java",pid=290610,fd=238))   # instance B's DSP port
LISTEN 0 50 *:19031 *:*  users:(("java",pid=290610,fd=236))
LISTEN 0 50 *:19061 *:*  users:(("java",pid=290610,fd=235))
LISTEN 0 50 *:19101 *:*  users:(("java",pid=290611,fd=238))
LISTEN 0 50 *:19111 *:*  users:(("java",pid=290611,fd=235))
LISTEN 0 50 *:19121 *:*  users:(("java",pid=290611,fd=234))   # instance C's DSP port
LISTEN 0 50 *:19131 *:*  users:(("java",pid=290611,fd=237))
LISTEN 0 50 *:19161 *:*  users:(("java",pid=290611,fd=236))
```

Each instance's own log confirms real seeding (see `logs/instance-{a,b,c}.log`,
kept as evidence):

```
instance-a.log: ... catalog seed: seeded 2 asset(s) [EDC-A-01, EDC-A-02] under participantContextId='EDC-A'
instance-a.log: ... 89 service extensions started
instance-a.log: ... Runtime 3ad1e3e5-3501-4383-b00e-d6b236af3c0f ready
instance-b.log: ... catalog seed: seeded 1 asset(s) [EDC-B-01] under participantContextId='EDC-B'
instance-c.log: ... catalog seed: seeded 3 asset(s) [EDC-C-01, EDC-C-02, EDC-C-03] under participantContextId='EDC-C'
```

Direct `curl` sanity check against each instance's real, versioned DSP
endpoint (not the crawler yet — proving each server independently first):

```
$ curl -s -X POST http://127.0.0.1:19021/api/dsp/2025-1/catalog/request \
    -H "Content-Type: application/json" -H "Authorization: fixture-any-token" \
    -d '{"@context": ["https://w3id.org/dspace/2025/1/context.jsonld"], "@type": "CatalogRequestMessage"}'
{"@id":"6df3f154-384e-4bd2-9eec-0e508be73592","@type":"Catalog","dataset":[{"@id":"EDC-B-01","@type":"Dataset",
"hasPolicy":[{"@id":"...","@type":"Offer","permission":[{"action":"use"}]}],"distribution":[],"id":"EDC-B-01"}],
"service":[{"@id":"...","@type":"DataService","endpointDescription":"dspace:connector",
"endpointURL":"http://localhost:19021/api/dsp/2025-1"}],"participantId":"EDC-B",
"@context":["https://w3id.org/dspace/2025/1/context.jsonld","https://w3id.org/edc/dspace/v0.0.1"]}
```

Instance C the same way, confirming all three of its seeded ids:
`curl ... | python3 -c "..."` → `['EDC-C-03', 'EDC-C-01', 'EDC-C-02']`.

Then the actual proof — the Rust crawler, for real, against all three:

```
$ cargo test -p crawler --test crawl_real_edc -- --ignored --nocapture

running 1 test
test crawls_three_real_edc_instances_and_aggregates_all_seeded_datasets ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.48s
```

The test asserts, in code: 3 `attempted`, 3 `succeeded`, 0 `failures`
(empty `Vec`), 3 cached `Catalog` entries, and that the union of every
cached catalog's dataset ids equals exactly
`{EDC-A-01, EDC-A-02, EDC-B-01, EDC-C-01, EDC-C-02, EDC-C-03}` — all six.
It passed.

Confirmed it is correctly skipped under a normal, non-`--ignored` run
(so `cargo test --workspace` never depends on these external processes):

```
$ cargo test -p crawler --test crawl_real_edc
test crawls_three_real_edc_instances_and_aggregates_all_seeded_datasets ... ignored, requires three real Eclipse EDC 0.18.0 instances running - see compliance/crawler-edc-fixture/
test result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.00s
```

## Cleanup

```
$ for p in 290609 290610 290611; do kill $p; done
$ sleep 3
$ for p in 290609 290610 290611; do kill -0 $p 2>/dev/null && echo ALIVE || echo dead; done
dead
dead
dead
$ ss -tlnp | grep -E "18901|18911|18921|18931|18961|19001|19011|19021|19031|19061|19101|19111|19121|19131|19161"
(no output - clean)
$ ./gradlew --stop
Stopping Daemon(s)
1 Daemon stopped
$ pgrep -af "BaseRuntime|GradleDaemon"
(no output - clean)
```

**One real slip caught and fixed during cleanup, worth recording
honestly:** an earlier attempt to start all three instances hit the
known "`BindException` on `WEB_HTTP_SIGNALING_PORT`'s hardcoded default
(8182) causes the JVM to hang without exiting, not to fail fast" pitfall
(see "Problems encountered" #1 in `compliance/benchmark-2026-08-27.md`,
and the port-8182 discovery below) — that attempt's PIDs (`289456`,
`289457`) were still alive, silently, after being superseded by a
corrected relaunch under new PIDs. Caught by a broader `ps -ef | grep
java` sweep during final cleanup verification (not just checking the
three PIDs I expected), and killed. Final state, re-verified after that:
zero `BaseRuntime`/`GradleDaemon` processes, zero listeners in the
18000-19999 range.

### A third port pitfall found here, not on the known list

Beyond the four pitfalls already known to this project,
`org.eclipse.edc:data-plane-signaling-core`'s `SignalingApiConfiguration`
hardcodes `DEFAULT_SIGNALING_PORT = 8182` for the `signaling` web
context — not one of the six port settings
(`WEB_HTTP_{PORT,MANAGEMENT,PROTOCOL,CONTROL,CATALOG,VERSION}`) that
`compliance/benchmark-2026-08-27.md`'s `tck-runtime.env`-derived recipe
happened to set. Running three instances concurrently without overriding
`WEB_HTTP_SIGNALING_PORT` (`web.http.signaling.port`) meant only the
first to bind port 8182 actually started; the other two hung with a
`BindException` on `0.0.0.0:8182` and, per the pitfall above, did not
exit. Fixed in `run-instance.sh` by giving `signaling` its own
per-instance port (`BASE_PORT + 60`), same pattern as the other six.
Worth carrying forward: **any new EDC runtime config in this project
should assume there may be more fixed-default web contexts than the six
already known, and confirm via `ss -tlnp` with all instances started
concurrently — not just one at a time** (this fixture's own first
single-instance smoke test, before starting all three together, did not
surface this at all, since there was no second instance to collide
with).

## Scope: real EDC-side DCP is explicitly out of scope for this step

All three instances use `NoopIdentityService`-equivalent auth
(`FixtureNoopIdentityService`) — no `iam-mock`, no real DCP. Per this
task's own briefing: wiring EDC's real `DcpIdentityService` as a relying
party is a materially larger undertaking than this step, already
identified and deferred in `compliance/benchmark-dcp-2026-08-27.md`. The
crawler's own DCP-*holder* capability (minting a self-issued token,
resolving a provider's `did:web`, completing the presentation-query round
trip) was already proven for real against a DCP-*requiring* participant
in the prior step
(`crates/crawler/tests/multi_participant_crawl.rs`,
`crawl_once_pulls_open_and_dcp_gated_catalogs_with_real_per_caller_filtering`) —
using this project's own hand-rolled, genuinely ES256-signed DSP/DCP
implementation on both sides, not a stub. This step's job was narrower
and different: prove the crawler's HTTP client and DSP-response *parser*
against a real, independent implementation's wire format, for the
`requires_dcp = false` path. Combining "real EDC" and "real DCP as a
relying party against EDC" remains deferred, as it was before this step.

## Files

- `compliance/crawler-edc-fixture/` — the Gradle fixture project (source
  committed; `build/`, `.gradle/`, `classpath.txt` gitignored — see its
  own `.gitignore`).
- `compliance/crawler-edc-fixture/logs/instance-{a,b,c}.log` — real
  startup/seed logs from the three instances used for the passing run
  documented above, kept as evidence.
- `compliance/crawler-edc-fixture/config_graph.ttl` — the crawler config
  (originally `participants.toml`).
- `crates/crawler/tests/crawl_real_edc.rs` — the `#[ignore]`d proof test.
- `crates/crawler/src/lib.rs` — the one-line-of-behavior fix (send a
  placeholder `Authorization` header to non-DCP participants) plus its
  documenting comment.
