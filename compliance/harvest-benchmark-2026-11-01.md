# Harvesting benchmark, three-way: previous broker, current broker, Eclipse EDC 1.0.0-RC5

**Date:** 2026-11-01
**Supersedes:** [`harvest-benchmark-2026-08-27.md`](harvest-benchmark-2026-08-27.md) for current numbers. That report stays as the record of the first run.

## Question

The 2026-08-27/28 report compared the broker with Eclipse EDC 0.18.0's federated-catalog crawler. Since then the broker gained policy filtering, atomic upserts, a crawl-cycle rewrite, and about twenty audit fixes (issues #15 to #45). EDC has published 1.0.0-RC5. This run answers three questions under the original conditions:

1. How does the current broker compare with the broker that produced the last report?
2. What does ODRL policy filtering cost on the catalog read path?
3. How does the current broker compare with the latest Eclipse EDC federated catalog?

## Targets

| Label | What | Build |
|---|---|---|
| `broker-old` | Broker at `2e5d07f`, the commit that produced the last report | release, config `participants.toml` |
| `broker-main` | Broker at `91cb8bf` (head of `ds-catalog-broker-rs`, PR #57), default configuration | release, Turtle config |
| `broker-main-nofilter` | Same binary, `broker:policyFilterRunWhenOauth2Disabled false` | release |
| `edc-rc5` | `org.eclipse.edc:federatedcatalog-base-bom:1.0.0-RC5` + `iam-mock` + `dsp-catalog-transform-2025` | Maven Central |

`broker-main-nofilter` is an addition to the three requested targets. Filtering is on by default even without OAuth2, so it is part of what `broker-main` measures; the extra row isolates its cost.

EDC 1.0.0-RC5 is a pre-release (published 2026-10-21). The latest stable release is 0.18.1 (2026-09-25) and was not measured.

## Conditions

Unchanged from the first report unless listed under "Differences" below.

- Two real EDC 0.18.0 participants, HARVEST-D (3 datasets) and HARVEST-E (7 datasets), started by `compliance/crawler-edc-fixture/run-instance.sh`. Both stay up for the whole run.
- Each target crawls both participants every 5 seconds over DSP 2025-1 (`POST …/catalog/request`) with no credential presentation.
- k6, 20 constant VUs, 30 s, against the target's own read endpoint while its crawl loop keeps running: `GET /catalog` for the broker, `POST /api/management/v4/catalogs/request` for EDC.
- RSS and CPU sampled once per second from `/proc/<pid>` over 35 s. Peak RSS is the maximum sample. CPU is the mean of the samples taken 1 to 31 s after the sampler starts.
- Correctness: before and after each load window, the read endpoint must return exactly the ten dataset ids `HARVEST-D-01..03` and `HARVEST-E-01..07`.
- One host, 22 cores, 93 GB RAM, k6 and the target on the same machine. Targets run one after another, never concurrently.
- Three rounds; each round runs the four targets in the order above. Figures are medians with the min and max in brackets.

### Differences from the 2026-08-27 conditions

- Three rounds instead of one, and the participants are not restarted between targets.
- EDC's read path moved. 1.0.0-RC5 no longer serves `/api/management/v3/catalogs/request` (404); only `/v4/catalogs/request` exists, and it requires `"@type":"QuerySpec"` with an `@vocab` context instead of a full IRI type.
- EDC's crawl needed one extra module. With `federatedcatalog-base-bom:1.0.0-RC5` alone, every crawl threw `No Transformer registered that can handle class …CatalogRequestMessage -> JsonObject` on the crawler thread, nothing was logged at any level, and the catalog stayed empty. Adding `dsp-catalog-transform-2025:1.0.0-RC5` fixed it. The exception was found with Java Flight Recorder. The 0.18.0 BOM did not need this.
- CPU is averaged over a fixed window of samples rather than over the k6 run. The first report's `broker-old` CPU (~892%) and this run's (1,100%) are therefore not directly comparable; throughput and RSS are.

## Results

| Target | Throughput, req/s | Peak RSS, MB | Avg CPU, % of one core | CPU per request, ms | Latency avg, ms | Latency p95, ms | Latency max, ms | Failed requests |
|---|---|---|---|---|---|---|---|---|
| `broker-old` | 37,989 [37,472 to 38,697] | 17.7 [17.7 to 18.0] | 1,100 | 0.29 | 0.477 | 0.737 | 6.0 | 69 of 3,424,834 |
| `broker-main` | 27,791 [27,697 to 28,015] | 25.7 [25.7 to 25.8] | 1,155 | 0.42 | 0.655 | 0.972 | 5.3 | 0 of 2,505,173 |
| `broker-main-nofilter` | 30,080 [30,050 to 30,119] | 26.7 [26.5 to 27.9] | 1,132 | 0.38 | 0.603 | 0.898 | 5.3 | 0 of 2,707,524 |
| `edc-rc5` | 1,046 [1,045 to 1,067] | 1,492.6 [1,321.0 to 1,560.6] | 1,235 | 11.8 | 19.03 | 28.68 | 127.0 | 0 of 94,788 |

Correctness held at both checkpoints in all 12 target-rounds (4 targets, 3 rounds).

For reference, the first report measured EDC 0.18.0 at 811.5 req/s, 1,116 MB peak RSS and 24.5 ms average latency, and the broker at 39,319 req/s and 18.0 MB.

### Reading the numbers

- `broker-main` against `broker-old`: 27% lower throughput, 45% more peak RSS (+8 MB), 0.13 ms more CPU per request. Policy filtering explains part of it: with filtering off, throughput is 21% below `broker-old` instead of 27%, so filtering costs about 8% of `broker-main`'s throughput. The rest comes from other changes between the two commits that this run does not separate.
- `broker-old` returned 31, 23 and 15 non-200 responses in rounds 1 to 3. `broker-main` and `broker-main-nofilter` returned none in any round. The response codes and server-side cause were not captured (the old binary logged nothing). The old `OxigraphCatalogCache::upsert` cleared a participant's named graph and rewrote it in separate store writes, so a read during a crawl could see an incomplete catalog; issue #26 describes this and the fix. The correlation is consistent with that, not proven by this run.
- `broker-main` against `edc-rc5`: 26.6 times the throughput, 58 times lower peak RSS, 28 times less CPU per request, and 29 times lower average latency, while both harvest every 5 seconds.
- `edc-rc5` against the first report's EDC 0.18.0 figure: higher throughput (1,046 against 811.5 req/s), 34% more RSS (1,493 against 1,116 MB), lower average latency. These are two runs on different days with a different endpoint and request body, so the comparison is indicative only.

## What this does not show

- The two systems do different work per request. The broker returns its own JSON shape (`{"catalogs": […]}`) after policy filtering. EDC returns JSON-LD Management API objects with `hasPolicy` offers for each dataset. EDC also transforms incoming DSP catalogs on harvest; the broker parses them.
- Harvest cost is not isolated. Both systems crawl in the background during the load window, but neither crawl duration nor time-to-first-catalog was recorded.
- Ten datasets from two participants. Neither store was loaded with a realistic catalog size, so memory growth with catalog size is untested.
- Participants run EDC 0.18.0 and were not upgraded to 1.0.0-RC5. A 1.0.0-RC5 participant may answer DSP differently.
- `broker-main` keeps its catalog in memory; EDC's default store is in memory too. Neither run exercised persistence.
- No DCP or OID4VP presentation in this run (same scope decision as the first report).
- The 5-second crawl period is short by design and does not reflect a production schedule.
- EDC's default JVM settings were used with no tuning; the broker has no tunables in this run either.

## Reproducing

```bash
# build the two broker versions
cargo build --release -p ds-catalog-broker-rs                      # at 91cb8bf
git worktree add --detach /tmp/broker-old 2e5d07f
( cd /tmp/broker-old && git submodule update --init --recursive && cargo build --release -p ds-catalog-broker-rs )

# EDC runtime (default 1.0.0-RC5; pass -PedcVersion=0.18.0 to rebuild the old one)
( cd compliance/harvest-bench/edc-fedcat-runtime && ./gradlew printClasspath )

# run: 3 rounds over the four targets
cd compliance/harvest-bench
HB=$PWD BIN_OLD=/tmp/broker-old/target/release/ds-catalog-broker-rs \
  BIN_MAIN=$PWD/../../target/release/ds-catalog-broker-rs \
  OLD_TOML=/tmp/broker-old/compliance/harvest-bench/participants.toml \
  EDC_DIR=$PWD/edc-fedcat-runtime OUT=$PWD/results ROUNDS=3 \
  EDC_API=v4 \
  EDC_QUERYSPEC_BODY='{"@context":{"@vocab":"https://w3id.org/edc/v0.0.1/ns/"},"@type":"QuerySpec"}' \
  ./run-three-way.sh
```

`TARGETS="edc-rc5"` runs a subset. Prerequisites are those of `README.md` in this directory.
