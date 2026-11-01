//! Scheduled catalog crawler.
//!
//! Polls each participant in a local-config registry (see [`config`]) for
//! its DSP catalog, parses the response leniently enough to tolerate both
//! this workspace's own compact DSP shape and real Eclipse EDC's fuller
//! JSON-LD shape (see [`parse_catalog_response`]'s doc comment), and
//! upserts the result into an `rdf_store::CatalogCache` - the same trait
//! `ds-catalog-broker-rs` serves `GET /catalog` and the DSP catalog endpoints from, so
//! a successful crawl cycle is immediately visible there.
//!
//! [`crawl_once`] runs exactly one cycle over every configured
//! participant and returns a [`CrawlSummary`] - useful directly in tests,
//! and as the building block [`spawn_scheduler`] calls on a
//! `tokio::time::interval` tick.

pub mod config;
// RED STATE (docs/oid4vp-holder-2026-08-28.md TDD pass): declared so this
// module's own tests are compiled and exercised, but nothing in this file
// wires it into `crawl_one` yet - that lands in the GREEN commit.
pub mod oid4vp;
pub mod status;

pub use config::{
    ConfigError, CredentialProtocol, HolderConfig, ParticipantEntry, ParticipantsConfig,
    UnknownCredentialProtocol,
};

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use catalog_core::{
    Catalog, Constraint, DataService, Dataset, Distribution, NodeId, Policy, PolicyKind, Rule,
    UNMAPPABLE_ACTION,
};
use dcp_core::HolderIdentity;
use futures_util::future::BoxFuture;
use futures_util::{FutureExt, StreamExt, stream};
use rdf_store::CatalogCache;
use serde_json::Value;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

pub use status::{CrawlStatus, ParticipantStatus, SharedCrawlStatus};

/// `@context` for the `CatalogRequestMessage` this crawler POSTs to each
/// participant - matches what `ds-catalog-broker-rs`'s own `catalog_request` handler
/// already accepts (and, today, ignores the rest of).
const DSP_CONTEXT_URL: &str = "https://w3id.org/dspace/2025/1/context.jsonld";

/// Placeholder `Authorization` header value sent to a `credential_protocol
/// = "none"` participant. Real Eclipse EDC's DSP catalog handler
/// (`DspRequestHandlerImpl`) returns `401` on a *missing* `Authorization`
/// header unconditionally, before any `IdentityService` ever runs - even
/// when that participant's own identity service (e.g. a no-op/permissive
/// one, or none at all beyond a bare presence check) would accept anything.
/// This workspace's own `ds-catalog-broker-rs` under `DspAuthMode::Disabled` ignores
/// the header entirely either way, so sending a fixed, non-secret,
/// non-empty placeholder here is harmless to it and required for real EDC
/// interop - confirmed against a real, unmodified EDC 0.18.0 instance, see
/// `compliance/crawler-edc-integration-test.md`.
const OPEN_PARTICIPANT_PLACEHOLDER_AUTH: &str = "federated-catalog-rs-crawler-anonymous";

/// Bounds on a crawl cycle. The broker reads each one from its
/// `broker:` config (see `docs/configuration.md`); [`Default`] holds the
/// same defaults.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrawlLimits {
    /// How long one participant's whole fetch may take, credential
    /// presentation and response body included, before it counts as a
    /// failure. Default: 30 seconds.
    pub participant_timeout: Duration,
    /// How many participants are crawled at the same time. Default: 8.
    pub concurrency: usize,
    /// A cached catalog whose participant has not been crawled
    /// successfully for this long is removed from the cache, so a
    /// participant that stays down stops being served. Default: 24 hours.
    pub max_catalog_age: Duration,
}

impl Default for CrawlLimits {
    fn default() -> Self {
        Self {
            participant_timeout: Duration::from_secs(30),
            concurrency: 8,
            max_catalog_age: Duration::from_secs(24 * 60 * 60),
        }
    }
}

/// The outcome of one [`crawl_once`] cycle. Callers (tests, the scheduler
/// loop) get real counts and per-participant error messages rather than a
/// bare pass/fail bool, since "3 of 5 participants failed, here's why" is
/// the actionable signal a scheduled job needs to log or assert on.
#[derive(Debug, Default, Clone)]
pub struct CrawlSummary {
    pub attempted: usize,
    pub succeeded: usize,
    pub failed: usize,
    /// The id of every participant crawled and cached successfully this
    /// cycle, in participant order.
    pub succeeded_ids: Vec<String>,
    /// `(participant_id, error message)` for every participant that
    /// failed this cycle, in participant order.
    pub failures: Vec<(String, String)>,
    /// When each participant's crawl ended, success or failure.
    pub finished_at: std::collections::BTreeMap<String, std::time::SystemTime>,
    /// The same moments as [`Self::finished_at`], as monotonic instants,
    /// which is what catalog age is measured with.
    pub finished_instants: std::collections::BTreeMap<String, Instant>,
}

/// One participant's result with the wall-clock and monotonic time its
/// crawl ended.
type Outcome = (Result<(), String>, std::time::SystemTime, Instant);

/// Run one crawl cycle over every entry in `participants`, upserting each
/// successful result into `cache`.
///
/// Up to `limits.concurrency` participants are crawled at once, and each
/// one gets `limits.participant_timeout` to answer. A slot frees as soon as
/// its participant is done, whatever the others are doing; the summary's
/// lists are still in participant order. A failure fetching or
/// parsing one participant's catalog (network error, timeout, non-2xx
/// response, malformed JSON) is recorded in the returned [`CrawlSummary`]
/// and does not abort the rest of the cycle - one bad participant must
/// never prevent the others from being crawled.
pub async fn crawl_once(
    http: &reqwest::Client,
    participants: &[ParticipantEntry],
    holder: Option<&HolderIdentity>,
    cache: &dyn CatalogCache,
    limits: &CrawlLimits,
) -> CrawlSummary {
    // Boxed and collected up front rather than mapped lazily inside the
    // stream: a closure in the stream's type makes the future returned here
    // not provably `Send` for every lifetime, which `spawn_scheduler`'s
    // `tokio::spawn` needs.
    // Each outcome carries the time its own crawl ended, not the cycle's.
    // Outcomes are taken in completion order (`buffer_unordered`), so a slow
    // participant never keeps a free slot from the next one, and are put
    // back in participant order below by the index carried along.
    let crawls: Vec<BoxFuture<'_, (usize, Outcome)>> = participants
        .iter()
        .enumerate()
        .map(|(index, participant)| {
            crawl_and_cache(http, participant, holder, cache, limits)
                .map(move |outcome| {
                    (
                        index,
                        (outcome, std::time::SystemTime::now(), Instant::now()),
                    )
                })
                .boxed()
        })
        .collect();
    let mut outcomes: Vec<(usize, Outcome)> = stream::iter(crawls)
        .buffer_unordered(limits.concurrency.max(1))
        .collect()
        .await;
    outcomes.sort_by_key(|(index, _)| *index);

    let mut summary = CrawlSummary::default();
    for (participant, (_, (outcome, finished_at, finished_instant))) in
        participants.iter().zip(outcomes)
    {
        summary.attempted += 1;
        summary
            .finished_at
            .insert(participant.id.clone(), finished_at);
        summary
            .finished_instants
            .insert(participant.id.clone(), finished_instant);
        match outcome {
            Ok(()) => {
                summary.succeeded += 1;
                summary.succeeded_ids.push(participant.id.clone());
            }
            Err(err) => {
                summary.failed += 1;
                summary.failures.push((participant.id.clone(), err));
            }
        }
    }

    summary
}

/// Crawl one participant within `limits.participant_timeout` and cache the
/// result.
async fn crawl_and_cache(
    http: &reqwest::Client,
    participant: &ParticipantEntry,
    holder: Option<&HolderIdentity>,
    cache: &dyn CatalogCache,
    limits: &CrawlLimits,
) -> Result<(), String> {
    let catalog = tokio::time::timeout(
        limits.participant_timeout,
        crawl_one(http, participant, holder),
    )
    .await
    .unwrap_or_else(|_| {
        Err(format!(
            "crawl of {} timed out after {:?}",
            participant.catalog_request_url, limits.participant_timeout
        ))
    })?;
    cache
        .upsert(catalog)
        .await
        .map_err(|err| format!("failed to cache crawl result: {err}"))
}

/// Runs crawl cycles and removes catalogs that have gone stale. Holds the
/// time each participant was last crawled successfully, which is what
/// [`CrawlLimits::max_catalog_age`] is measured against.
pub struct Harvester {
    cache: Arc<dyn CatalogCache>,
    participants: Vec<ParticipantEntry>,
    http: reqwest::Client,
    holder: Option<Arc<HolderIdentity>>,
    limits: CrawlLimits,
    last_success: HashMap<String, Instant>,
    status: SharedCrawlStatus,
}

/// The outcome of one [`Harvester::run_cycle`].
#[derive(Debug, Default, Clone)]
pub struct CycleReport {
    pub summary: CrawlSummary,
    /// Participants whose cached catalog was removed this cycle because
    /// their last successful crawl is older than
    /// [`CrawlLimits::max_catalog_age`].
    pub expired: Vec<String>,
}

impl Harvester {
    pub fn new(
        cache: Arc<dyn CatalogCache>,
        participants: Vec<ParticipantEntry>,
        http: reqwest::Client,
        holder: Option<Arc<HolderIdentity>>,
        limits: CrawlLimits,
    ) -> Self {
        // Every configured participant is listed from the start, before its
        // first crawl, so a reader sees the whole registry.
        let status = SharedCrawlStatus::new(CrawlStatus {
            cycles_completed: 0,
            participants: participants
                .iter()
                .map(|p| (p.id.clone(), ParticipantStatus::default()))
                .collect(),
        });
        Self {
            cache,
            participants,
            http,
            holder,
            limits,
            last_success: HashMap::new(),
            status,
        }
    }

    /// The status this harvester updates at the end of every cycle.
    pub fn status(&self) -> SharedCrawlStatus {
        self.status.clone()
    }

    /// Crawl every participant once, then remove the catalog of each
    /// participant not crawled successfully within
    /// [`CrawlLimits::max_catalog_age`]. A participant that has never
    /// succeeded has nothing cached, so there is nothing to expire.
    pub async fn run_cycle(&mut self) -> CycleReport {
        let summary = crawl_once(
            &self.http,
            &self.participants,
            self.holder.as_deref(),
            &*self.cache,
            &self.limits,
        )
        .await;

        let now = Instant::now();
        // Age counts from when the participant's own crawl ended, not from
        // the end of the cycle.
        for id in &summary.succeeded_ids {
            let at = summary.finished_instants.get(id).copied().unwrap_or(now);
            self.last_success.insert(id.clone(), at);
        }

        let mut stale: Vec<String> = self
            .last_success
            .iter()
            .filter(|(_, at)| now.duration_since(**at) > self.limits.max_catalog_age)
            .map(|(id, _)| id.clone())
            .collect();
        stale.sort();
        // A catalog counts as expired only once it is really gone; a failed
        // delete keeps it in `last_success`, so the next cycle tries again.
        let mut expired = Vec::with_capacity(stale.len());
        for id in stale {
            match self.cache.delete(&NodeId::new(id.clone())).await {
                Ok(_) => {
                    self.last_success.remove(&id);
                    expired.push(id);
                }
                Err(err) => {
                    tracing::warn!(participant = %id, error = %err, "failed to remove a stale catalog; retrying next cycle");
                }
            }
        }

        self.record_status(&summary, &expired);
        CycleReport { summary, expired }
    }

    /// Fold one cycle's outcome into [`Self::status`].
    fn record_status(&self, summary: &CrawlSummary, expired: &[String]) {
        let cycle_end = std::time::SystemTime::now();
        let finished = |id: &String| summary.finished_at.get(id).copied().unwrap_or(cycle_end);
        self.status.update(|status| {
            for id in &summary.succeeded_ids {
                let entry = status.participants.entry(id.clone()).or_default();
                let at = finished(id);
                entry.last_attempt = Some(at);
                entry.last_success = Some(at);
                entry.last_error = None;
                entry.cached = true;
            }
            for (id, error) in &summary.failures {
                let entry = status.participants.entry(id.clone()).or_default();
                entry.last_attempt = Some(finished(id));
                entry.last_error = Some(error.clone());
            }
            for id in expired {
                status.participants.entry(id.clone()).or_default().cached = false;
            }
            status.cycles_completed += 1;
        });
    }
}

/// Fetch and parse one participant's catalog. Split out of [`crawl_once`]
/// so its `?`-heavy body can return a plain `Result` per participant
/// instead of threading failure bookkeeping through every step by hand.
async fn crawl_one(
    http: &reqwest::Client,
    participant: &ParticipantEntry,
    holder: Option<&HolderIdentity>,
) -> Result<Catalog, String> {
    let request_body = serde_json::json!({
        "@context": [DSP_CONTEXT_URL],
        "@type": "CatalogRequestMessage",
    });

    let mut request = http
        .post(&participant.catalog_request_url)
        .json(&request_body);

    match participant.credential_protocol {
        config::CredentialProtocol::None => {
            // See `OPEN_PARTICIPANT_PLACEHOLDER_AUTH`'s doc comment: real
            // DSP servers (confirmed: Eclipse EDC) require *a* header to
            // be present even when the participant enforces no real
            // authentication - not `.bearer_auth(...)` (no "Bearer "
            // prefix wanted here; a raw header value is what real EDC's
            // DSP layer reads verbatim).
            request = request.header(
                reqwest::header::AUTHORIZATION,
                OPEN_PARTICIPANT_PLACEHOLDER_AUTH,
            );
        }
        config::CredentialProtocol::Dcp => {
            // Config validation (`ParticipantsConfig::new`) already
            // guarantees a `Dcp` participant has a `provider_did` and a
            // holder is configured, so a `holder` of `None` or a
            // missing `provider_did` here means the caller built
            // `ParticipantsConfig`/`HolderIdentity` inconsistently by
            // hand rather than through that validation - still handled
            // as a per-participant failure, not a panic, since a crawl
            // cycle should never take down the process.
            let holder = holder.ok_or_else(|| {
                format!(
                    "participant '{}' requires_dcp but no holder identity is configured",
                    participant.id
                )
            })?;
            let provider_did = participant.provider_did.as_deref().ok_or_else(|| {
                format!(
                    "participant '{}' requires_dcp but has no provider_did",
                    participant.id
                )
            })?;
            let token = holder.mint_self_issued_token(provider_did);
            request = request.bearer_auth(token);
        }
        config::CredentialProtocol::Oid4Vp => {
            // Same defensive posture as the `Dcp` arm above: config
            // validation already guarantees an `Oid4Vp` participant has
            // an `oid4vp_response_uri` and a holder is configured, but this still fails per-participant, not with a
            // panic, if a hand-built config is inconsistent.
            let holder = holder.ok_or_else(|| {
                format!(
                    "participant '{}' requires oid4vp but no holder identity is configured",
                    participant.id
                )
            })?;
            let response_uri = participant.oid4vp_response_uri.as_deref().ok_or_else(|| {
                format!(
                    "participant '{}' requires oid4vp but has no oid4vp_response_uri",
                    participant.id
                )
            })?;
            let access_token =
                oid4vp::present(http, &holder.key_pair, &holder.credential_jws, response_uri)
                    .await
                    .map_err(|e| {
                        format!(
                            "participant '{}' OID4VP presentation to {response_uri} failed: {e}",
                            participant.id
                        )
                    })?;
            request = request.bearer_auth(access_token);
        }
    }

    let response = request
        .send()
        .await
        .map_err(|e| format!("request to {} failed: {e}", participant.catalog_request_url))?;

    if !response.status().is_success() {
        return Err(format!(
            "{} returned HTTP {}",
            participant.catalog_request_url,
            response.status()
        ));
    }

    let body: Value = response.json().await.map_err(|e| {
        format!(
            "malformed JSON response from {}: {e}",
            participant.catalog_request_url
        )
    })?;

    Ok(parse_catalog_response(&body, participant))
}

/// Parse a DSP catalog-request response body into a `catalog_core::Catalog`,
/// leniently enough to accept either this workspace's own compact DSP
/// shape or real Eclipse EDC's fuller one. Notably: EDC's `accessService`
/// is a full nested `DataService` object (with its own `@id`/`endpointURL`),
/// while this workspace's own DSP responses use a compact string id for
/// the same field - both are accepted here via `serde_json::Value`-based
/// extraction rather than a rigid typed struct that would only match one
/// shape.
///
/// A response missing `dataset` and/or `service` entirely is not an error
/// - it produces a `Catalog` with empty `datasets`/`data_services`.
///
/// A dataset object's optional descriptive keys - `title`, `description`,
/// `version`, `creatorName` (a flat string; the real target wire shape's
/// nested `creator.name` isn't accepted here, since `catalog_core::Dataset`
/// has no nested creator concept), `thumbnail`, and `keywords` (kept as one
/// comma-separated string, unsplit) - are folded verbatim into the parsed
/// `Dataset.properties` bag under those exact keys when present, and simply
/// left absent from it when not. See `collect_datasets_and_services`.
///
/// A dataset object's `odrl:hasPolicy` entries (any spelling: `hasPolicy`,
/// `odrl:hasPolicy`, or the expanded IRI real EDC/DSP JSON-LD uses,
/// `http://www.w3.org/ns/odrl/2/hasPolicy`) are parsed into
/// `Dataset.policies: Vec<catalog_core::Policy>` - real harvested policy
/// data, not the placeholder the now-removed http-api DSP layer used to
/// emit (gap analysis §3.4). `hasPolicy` may be a single JSON-LD object or
/// an array of them (ODRL/JSON-LD's "one-or-many" convention); each
/// `permission`/`prohibition`/`obligation` under a policy follows the same
/// convention. See `parse_policies` for the field-by-field mapping.
///
/// Every ODRL key is read through one helper, [`get_aliased`], in its bare,
/// `odrl:`-prefixed or full-IRI spelling. Scalar values go through one
/// helper, [`json_ld_scalar`], which accepts plain strings, numbers,
/// booleans, `{"@value": ...}` value objects and `{"@id": ...}` references.
///
/// Both *atomic* ODRL constraints (`leftOperand`/`operator`/`rightOperand`)
/// and *logical* groups (`and`/`or`/`xone`/`andSequence`, nesting further
/// constraints, recursively) are modeled; see [`parse_constraint`] and
/// [`MAX_CONSTRAINT_DEPTH`].
///
/// Content that cannot be parsed is never dropped, because dropping a
/// restriction loosens the policy before the broker sees it. It is kept as
/// an unmappable marker ([`Constraint::unmappable`]) and the broker's
/// `policyFilterUnmappableConstraintAction` decides what happens to it. This
/// covers an incomplete or unreadable constraint (also inside a group), a
/// logical group nested past [`MAX_CONSTRAINT_DEPTH`], a rule with no
/// readable `action` (kept under [`UNMAPPABLE_ACTION`]), a rule or policy
/// entry that is not a JSON-LD node, and an unreadable `assignee` (a marker
/// rule is added to the policy). An unreadable `assigner` is ignored, as it
/// scopes nothing. One limit remains: `response.json()` stops at
/// serde_json's 128-level recursion limit, so a body nested deeper than
/// that fails the whole catalog fetch (the previous cache entry is kept
/// until it expires) rather than being marked per entry.
///
/// Datasets are deduplicated by id within one response, as services are:
/// the first occurrence wins and later ones are skipped with a
/// `tracing::warn!`. rdf-store derives resource IRIs from the dataset id,
/// so keeping both would merge their triples into one mixed policy.
///
/// Also tolerates a "federation of federations" response - one where the
/// crawled participant is itself a multi-participant aggregator (e.g.
/// another instance of this workspace's own `ds-catalog-broker-rs`, once it has 2+
/// origin nodes cached: see `ds-catalog-broker-rs`'s `catalog_request`) and so nests
/// its real content under a top-level `catalog` array instead of top-level
/// `dataset`/`service`. This crate's own data model is one `Catalog` per
/// configured target participant, not per nested sub-participant, so any
/// nested `catalog[]` entries found are flattened into the *same* returned
/// `Catalog` right alongside the top-level entries (recursively, in case a
/// nested entry is itself nested) - which participant a dataset nested
/// several levels down originally came from is not preserved, only that it
/// isn't silently dropped. Without this, a crawl target returning a purely
/// nested response (empty top-level `dataset`/`service`, matching what
/// `catalog_request` now does for 2+ cached origin nodes) would parse as
/// an apparently-empty catalog.
fn parse_catalog_response(value: &Value, participant: &ParticipantEntry) -> Catalog {
    let id = value
        .get("@id")
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| format!("urn:uuid:{}", uuid::Uuid::new_v4()));

    let mut catalog = Catalog::new(id, NodeId::new(participant.id.clone()));
    catalog.participant_id = value
        .get("participantId")
        .and_then(Value::as_str)
        .map(str::to_string);

    collect_datasets_and_services(value, &mut catalog, &mut SeenIds::default());

    catalog
}

/// Ids already collected from one response, across all nesting levels.
/// Sets keep the dedup linear; scanning the `Catalog` vectors per entry
/// is quadratic on a large hostile body.
#[derive(Default)]
struct SeenIds {
    datasets: std::collections::HashSet<String>,
    services: std::collections::HashSet<String>,
}

/// Extract `value`'s own `service`/`dataset` entries into `catalog`, then
/// recurse into any nested `catalog[]` entries doing the same - see
/// `parse_catalog_response`'s doc comment for why. `value` is either the
/// top-level response body or one nested `catalog[]` entry; both share the
/// same `service`/`dataset`/`catalog` shape.
fn collect_datasets_and_services(value: &Value, catalog: &mut Catalog, seen: &mut SeenIds) {
    // `service` entries first, so a dataset's nested `accessService`
    // object (parsed below) can be folded in without duplicating one
    // already listed here.
    if let Some(services) = value.get("service").and_then(Value::as_array) {
        for service_value in services {
            if let Some(service) = parse_data_service(service_value)
                && seen.services.insert(service.id.clone())
            {
                catalog.data_services.push(service);
            }
        }
    }

    if let Some(datasets) = value.get("dataset").and_then(Value::as_array) {
        for dataset_value in datasets {
            let Some(dataset_id) = dataset_value
                .get("@id")
                .or_else(|| dataset_value.get("id"))
                .and_then(Value::as_str)
            else {
                continue;
            };

            // The store derives resource IRIs from the dataset id, so two
            // datasets with one id would merge their triples into a mixed
            // policy. Keep the first, as for services.
            if !seen.datasets.insert(dataset_id.to_string()) {
                tracing::warn!(
                    dataset_id,
                    "skipping a crawled dataset whose id was already seen in this response (first one wins)"
                );
                continue;
            }

            let mut dataset = Dataset {
                id: dataset_id.to_string(),
                properties: Default::default(),
                distributions: Vec::new(),
                policies: parse_policies(dataset_value),
            };

            // Optional descriptive fields, folded verbatim into the
            // properties bag under these exact keys when present in the
            // source JSON - absent entirely when the key is missing, never
            // defaulted. `keywords` is a single comma-separated string on
            // the wire (e.g. "soil,moisture,sensors") and is kept that way
            // here too: splitting it is `ds-catalog-broker-rs::dataset_to_offer`'s
            // job, not this crawler's (see that function's own doc
            // comment).
            for key in [
                "title",
                "description",
                "version",
                "creatorName",
                "thumbnail",
                "keywords",
            ] {
                if let Some(value) = dataset_value.get(key).and_then(Value::as_str) {
                    dataset
                        .properties
                        .insert(key.to_string(), value.to_string());
                }
            }

            if let Some(distributions) = dataset_value.get("distribution").and_then(Value::as_array)
            {
                for distribution_value in distributions {
                    let format = distribution_value
                        .get("format")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string();

                    let access_service = match distribution_value.get("accessService") {
                        Some(Value::String(id)) => id.clone(),
                        Some(access_service_value @ Value::Object(_)) => {
                            let id = access_service_value
                                .get("@id")
                                .or_else(|| access_service_value.get("id"))
                                .and_then(Value::as_str)
                                .unwrap_or_default()
                                .to_string();
                            if let Some(service) = parse_data_service(access_service_value)
                                && seen.services.insert(service.id.clone())
                            {
                                catalog.data_services.push(service);
                            }
                            id
                        }
                        _ => String::new(),
                    };

                    dataset.distributions.push(Distribution {
                        format,
                        access_service,
                    });
                }
            }

            catalog.datasets.push(dataset);
        }
    }

    if let Some(nested_catalogs) = value.get("catalog").and_then(Value::as_array) {
        for nested_value in nested_catalogs {
            collect_datasets_and_services(nested_value, catalog, seen);
        }
    }
}

/// Extract a `DataService` from either a top-level `service` array entry
/// or a nested `accessService` object - both share the same
/// `@id`/`id` + `endpointURL` (+ optional `endpointDescription`) shape.
fn parse_data_service(value: &Value) -> Option<DataService> {
    let id = value
        .get("@id")
        .or_else(|| value.get("id"))
        .and_then(Value::as_str)?
        .to_string();
    let endpoint_url = value
        .get("endpointURL")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let endpoint_description = value
        .get("endpointDescription")
        .and_then(Value::as_str)
        .map(str::to_string);
    Some(DataService {
        id,
        endpoint_url,
        endpoint_description,
    })
}

/// The ODRL namespace. `<ODRL_NS>hasPolicy` is the expanded-IRI form real
/// EDC/DSP JSON-LD uses in place of the compact `hasPolicy` key (see
/// `edc_federated_catalog_client::models::Dataset::has_policy`'s own
/// `#[serde(rename = ...)]`); [`get_aliased`] accepts every key in that form.
const ODRL_NS: &str = "http://www.w3.org/ns/odrl/2/";

/// ODRL/JSON-LD's "one-or-many" convention: a value that is normally an
/// array may legally appear as a single bare object instead when there is
/// exactly one entry. Returns an empty `Vec` for a missing key, the single
/// value wrapped for a bare object, or the array's own entries otherwise.
fn one_or_many(value: Option<&Value>) -> Vec<&Value> {
    match value {
        None => Vec::new(),
        Some(Value::Array(items)) => items.iter().collect(),
        Some(other) => vec![other],
    }
}

/// Look `name` up in a JSON-LD node under any of its spellings: bare
/// (`permission`), `odrl:`-prefixed (`odrl:permission`) or the full ODRL IRI
/// (`http://www.w3.org/ns/odrl/2/permission`). The bare form wins when more
/// than one is present. Every ODRL key this parser reads goes through here,
/// so no key is accepted in one spelling and silently ignored in another
/// (a skipped `odrl:prohibition` would loosen the policy).
fn get_aliased<'a>(value: &'a Value, name: &str) -> Option<&'a Value> {
    value
        .get(name)
        .or_else(|| value.get(format!("odrl:{name}")))
        .or_else(|| value.get(format!("{ODRL_NS}{name}")))
}

/// Reduce a JSON-LD scalar to a string: a plain string, a number or boolean
/// (rendered as JSON does), a value object (`{"@value": ...}`, language and
/// datatype tags ignored), a node reference (`{"@id": ...}`), or a
/// one-element array of any of those. Anything else (null, a nested node, a
/// multi-element array) has no single string reading and yields `None`.
fn json_ld_scalar(value: &Value) -> Option<String> {
    match value {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        Value::Object(map) => match map.get("@value") {
            Some(inner @ (Value::String(_) | Value::Number(_) | Value::Bool(_))) => {
                json_ld_scalar(inner)
            }
            Some(_) => None,
            None => map.get("@id").and_then(Value::as_str).map(str::to_string),
        },
        Value::Array(items) if items.len() == 1 => json_ld_scalar(&items[0]),
        _ => None,
    }
}

/// What reading one scalar ODRL field produced.
enum Field {
    /// The key is not there.
    Absent,
    Value(String),
    /// The key is there but holds something with no single string reading.
    Unreadable,
}

impl Field {
    fn value(self) -> Option<String> {
        match self {
            Field::Value(v) => Some(v),
            _ => None,
        }
    }
}

/// Read the scalar field `name` of `value`, under any alias.
fn get_field(value: &Value, name: &str) -> Field {
    match get_aliased(value, name) {
        None => Field::Absent,
        Some(raw) => json_ld_scalar(raw).map_or(Field::Unreadable, Field::Value),
    }
}

/// A rule that carries only an unmappable marker, standing in for policy
/// content that could not be read (see [`Constraint::unmappable`]).
fn unmappable_rule(raw: &Value) -> Rule {
    tracing::warn!(entry = %raw, "keeping unreadable crawled ODRL content as an unmappable marker");
    Rule {
        action: UNMAPPABLE_ACTION.to_string(),
        constraints: vec![Constraint::unmappable(raw.to_string())],
    }
}

/// Parse a dataset object's `hasPolicy` entries (see `parse_catalog_response`'s
/// doc comment for the accepted key forms and the "one-or-many" shape) into
/// `catalog_core::Policy` values. Absent entirely -> an empty `Vec`, exactly
/// like every other optional dataset descriptor this crawler handles.
fn parse_policies(dataset_value: &Value) -> Vec<Policy> {
    one_or_many(get_aliased(dataset_value, "hasPolicy"))
        .into_iter()
        .map(|entry| {
            if entry.is_object() {
                parse_policy(entry)
            } else {
                // A bare string (a policy reference) or other non-node: the
                // broker cannot evaluate it, so it must not read as "no
                // policy".
                Policy {
                    id: None,
                    kind: PolicyKind::default(),
                    assigner: None,
                    assignee: None,
                    permissions: Vec::new(),
                    prohibitions: Vec::new(),
                    obligations: vec![unmappable_rule(entry)],
                }
            }
        })
        .collect()
}

/// Parse one `hasPolicy` entry into a `Policy`. Every field is optional
/// (matching `catalog_core::Policy`'s own `#[serde(default)]` shape): a
/// missing `@id` leaves `Policy::id` `None`, and an unrecognized or absent
/// `@type` leniently falls back to `PolicyKind::default()` (`Set`) rather
/// than failing this policy or the enclosing dataset - a crawled
/// participant advertising an ODRL vocabulary term this crate doesn't
/// recognize must not take down harvesting over it.
fn parse_policy(value: &Value) -> Policy {
    let id = value.get("@id").and_then(Value::as_str).map(str::to_string);
    let kind = value
        .get("@type")
        .and_then(Value::as_str)
        .map(|type_str| match type_str {
            "Set" => PolicyKind::Set,
            "Offer" => PolicyKind::Offer,
            "Agreement" => PolicyKind::Agreement,
            _ => PolicyKind::default(),
        })
        .unwrap_or_default();
    let assigner = get_field(value, "assigner").value();
    let mut obligations = parse_rules(value, "obligation");
    // An assignee scopes the policy to one party. Reading it as absent would
    // widen the policy to everyone, so an unreadable one adds a marker rule.
    let assignee = match get_field(value, "assignee") {
        Field::Value(v) => Some(v),
        Field::Absent => None,
        Field::Unreadable => {
            if let Some(raw) = get_aliased(value, "assignee") {
                obligations.push(unmappable_rule(raw));
            }
            None
        }
    };

    Policy {
        id,
        kind,
        assigner,
        assignee,
        permissions: parse_rules(value, "permission"),
        prohibitions: parse_rules(value, "prohibition"),
        obligations,
    }
}

/// Parse a policy object's `key` entries (`"permission"`, `"prohibition"`,
/// or `"obligation"`, one-or-many, any alias) into `Rule`s. An entry that
/// is not a node is kept as an unmappable marker rule rather than dropped.
fn parse_rules(policy_value: &Value, key: &str) -> Vec<Rule> {
    one_or_many(get_aliased(policy_value, key))
        .into_iter()
        .map(parse_rule)
        .collect()
}

/// Parse one `permission`/`prohibition`/`obligation` entry into a `Rule`.
/// An `action` that is missing or unreadable keeps the rule's constraints
/// under [`UNMAPPABLE_ACTION`] plus an unmappable marker: dropping the rule
/// would loosen the policy when it is a prohibition.
fn parse_rule(value: &Value) -> Rule {
    if !value.is_object() {
        return unmappable_rule(value);
    }
    let mut constraints = Vec::new();
    let action = match get_field(value, "action") {
        Field::Value(action) => action,
        Field::Absent | Field::Unreadable => {
            tracing::warn!(
                entry = %value,
                "crawled ODRL rule has no readable 'action'; keeping it as an unmappable marker"
            );
            constraints.push(Constraint::unmappable(value.to_string()));
            UNMAPPABLE_ACTION.to_string()
        }
    };
    constraints.extend(parse_constraints(get_aliased(value, "constraint")));
    Rule {
        action,
        constraints,
    }
}

/// Bounds how many nested `odrl:and`/`odrl:or`/`odrl:xone`/`odrl:andSequence`
/// levels [`parse_constraint`] will recurse into when parsing one crawled
/// constraint tree, so a pathologically deep (or adversarial) crawled
/// payload cannot grow this parser's call stack unboundedly. Deliberately
/// set to the exact same value as `ds-odrl-engine-rs`'s own
/// `engine::constraint::MAX_CONSTRAINT_DEPTH` (see that constant's doc
/// comment for the full rationale, including why 64 specifically) rather
/// than picking an independent number here: this crawler and that engine
/// parse/evaluate the same wire shape into structurally the same tree, and
/// a policy this crawler harvests but the engine would then refuse to
/// evaluate (or vice versa) would be a confusing, hard-to-diagnose mismatch
/// between "harvested" and "enforceable" for the exact same input.
const MAX_CONSTRAINT_DEPTH: usize = 64;

/// Constructor signature shared by [`Constraint::and`], [`Constraint::or`],
/// [`Constraint::xone`], and [`Constraint::and_sequence`] - factored into a
/// named alias purely so [`LOGICAL_CONSTRAINT_KEYS`]'s own type stays
/// readable (a bare `[(&str, fn(Vec<Constraint>) -> Constraint); 4]` is a
/// clippy `type_complexity` warning).
type LogicalConstraintBuilder = fn(Vec<Constraint>) -> Constraint;

/// The JSON-LD keys (read under any alias, see [`get_aliased`]) a logical
/// constraint group may use,
/// each paired with the `catalog_core::Constraint` constructor for that
/// combinator, in the same fixed precedence order
/// `ds-odrl-engine-rs::engine::Constraint::evaluate` applies when more than
/// one such key is present on a single node: `xone`, then `or`, then `and`,
/// then `andSequence`. A crawled constraint node is expected to carry at
/// most one of these, but keeping the same precedence as the engine (rather
/// than an arbitrary one) means a hand-authored node setting more than one
/// key - malformed, but not rejected outright, matching this parser's
/// generally lenient stance - is at least interpreted identically by both
/// this crawler and the engine that will later evaluate it.
const LOGICAL_CONSTRAINT_KEYS: [(&str, LogicalConstraintBuilder); 4] = [
    ("xone", Constraint::xone),
    ("or", Constraint::or),
    ("and", Constraint::and),
    ("andSequence", Constraint::and_sequence),
];

/// Parse a rule's `constraint` entries (one-or-many) into `Constraint`s -
/// see [`parse_constraint`] for the per-entry (recursive) parse.
fn parse_constraints(value: Option<&Value>) -> Vec<Constraint> {
    one_or_many(value)
        .into_iter()
        .map(|entry| parse_constraint(entry, 0))
        .collect()
}

/// Parse one `constraint` entry into a `Constraint`, recursively: either the
/// atomic `leftOperand`/`operator`/`rightOperand` shape, or a logical group
/// under one of [`LOGICAL_CONSTRAINT_KEYS`], whose child entries
/// (one-or-many) are parsed by recursing at `depth + 1`.
///
/// This never drops an entry. Content that cannot be read becomes a
/// [`Constraint::unmappable`] marker, so the broker's
/// `unmappableConstraintAction` decides what happens to it. A dropped
/// constraint would loosen the policy before the broker sees it. Marked
/// cases: an incomplete or unreadable atomic triple, an unrecognized shape,
/// a non-object entry, and a logical group whose children would sit past
/// [`MAX_CONSTRAINT_DEPTH`] (the group itself is replaced by the marker, at a
/// depth the store accepts).
fn parse_constraint(value: &Value, depth: usize) -> Constraint {
    if depth > MAX_CONSTRAINT_DEPTH {
        return Constraint::unmappable(value.to_string());
    }

    if let (Field::Value(left), Field::Value(operator), Field::Value(right)) = (
        get_field(value, "leftOperand"),
        get_field(value, "operator"),
        get_field(value, "rightOperand"),
    ) {
        return Constraint::atomic(left, operator, right);
    }

    for (key, build) in LOGICAL_CONSTRAINT_KEYS {
        if let Some(children_value) = get_aliased(value, key) {
            if depth >= MAX_CONSTRAINT_DEPTH {
                tracing::warn!(
                    depth,
                    max_depth = MAX_CONSTRAINT_DEPTH,
                    "crawled ODRL logical constraint nested past MAX_CONSTRAINT_DEPTH; \
                     keeping it as an unmappable marker"
                );
                return Constraint::unmappable(value.to_string());
            }
            let children: Vec<Constraint> = one_or_many(Some(children_value))
                .into_iter()
                .map(|child| parse_constraint(child, depth + 1))
                .collect();
            return build(children);
        }
    }

    tracing::warn!(
        entry = %value,
        "crawled ODRL constraint is neither a complete atomic triple nor a recognized logical \
         group; keeping it as an unmappable marker"
    );
    Constraint::unmappable(value.to_string())
}

/// Spawn a background task that runs [`Harvester::run_cycle`] every
/// `config.interval_secs` seconds (starting immediately, per
/// `tokio::time::interval`'s default first-tick behavior), logging each
/// cycle's [`CrawlSummary`] and any expired catalogs via `tracing`.
///
/// Runs until `shutdown` is cancelled, which also interrupts a cycle in
/// flight; the returned [`Scheduler::handle`] then completes. A cycle that
/// outlasts the interval delays the next tick rather than overlapping it.
pub fn spawn_scheduler(
    cache: Arc<dyn CatalogCache>,
    config: ParticipantsConfig,
    http: reqwest::Client,
    holder: Option<Arc<HolderIdentity>>,
    limits: CrawlLimits,
    shutdown: CancellationToken,
) -> Scheduler {
    let mut harvester = Harvester::new(cache, config.participants, http, holder, limits);
    let status = harvester.status();
    let handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(config.interval_secs.max(1)));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            // On shutdown, drop the cycle in flight: its HTTP requests are
            // cancelled. A catalog write already handed to the blocking pool is
            // not cancelled and may finish after the scheduler has stopped; it is
            // a single transaction, so the store never holds a half-written
            // catalog. A write not yet started can be dropped at runtime shutdown.
            let CycleReport { summary, expired } = tokio::select! {
                biased;
                () = shutdown.cancelled() => break,
                report = async {
                    interval.tick().await;
                    harvester.run_cycle().await
                } => report,
            };
            if summary.failed > 0 {
                tracing::warn!(
                    attempted = summary.attempted,
                    succeeded = summary.succeeded,
                    failed = summary.failed,
                    failures = ?summary.failures,
                    "crawl cycle completed with failures"
                );
            } else {
                tracing::info!(
                    attempted = summary.attempted,
                    succeeded = summary.succeeded,
                    "crawl cycle completed"
                );
            }
            if !expired.is_empty() {
                tracing::warn!(
                    participants = ?expired,
                    "removed catalogs not crawled successfully within catalogMaxAgeSecs"
                );
            }
        }
        tracing::info!("crawl scheduler stopped");
    });
    Scheduler { handle, status }
}

/// A running crawl scheduler, from [`spawn_scheduler`].
pub struct Scheduler {
    /// Ends once the shutdown token is cancelled.
    pub handle: tokio::task::JoinHandle<()>,
    /// What the scheduler's harvester reports.
    pub status: SharedCrawlStatus,
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::response::IntoResponse;
    use rdf_store::CatalogQuery;
    use rdf_store::oxigraph_backend::OxigraphCatalogCache;
    use serde_json::json;

    fn participant(id: &str) -> ParticipantEntry {
        ParticipantEntry {
            id: id.to_string(),
            name: id.to_string(),
            catalog_request_url: "http://127.0.0.1:0/dsp/catalog/request".to_string(),
            credential_protocol: CredentialProtocol::None,
            provider_did: None,
            oid4vp_response_uri: None,
        }
    }

    /// The real-EDC-shaped sample response from this task's own briefing
    /// (`compliance/benchmark-2026-08-27.md`'s "Fidelity comparison"
    /// section): a full nested `accessService` object, not a compact
    /// string id.
    fn real_edc_shaped_response() -> Value {
        json!({
            "@id": "6d3d7a0c-bf06-4160-839f-853350446179",
            "@type": "Catalog",
            "dataset": [
                {
                    "@id": "CAT0101",
                    "@type": "Dataset",
                    "hasPolicy": [{"@id": "offer-1", "@type": "Offer", "permission": [{"action": "use"}]}],
                    "distribution": [{
                        "@type": "Distribution",
                        "format": "HttpData-PULL",
                        "accessService": {
                            "@id": "5ee7e0fa-a2bc-4251-bab3-d3a1454dcfc8",
                            "@type": "DataService",
                            "endpointDescription": "dspace:connector",
                            "endpointURL": "http://localhost:8082/api/dsp/2025-1"
                        }
                    }],
                    "id": "CAT0101"
                }
            ],
            "service": [{
                "@id": "5ee7e0fa-a2bc-4251-bab3-d3a1454dcfc8",
                "@type": "DataService",
                "endpointDescription": "dspace:connector",
                "endpointURL": "http://localhost:8082/api/dsp/2025-1"
            }],
            "participantId": "CONNECTOR_UNDER_TEST",
            "@context": ["https://w3id.org/dspace/2025/1/context.jsonld", "https://w3id.org/edc/dspace/v0.0.1"]
        })
    }

    #[test]
    fn parses_real_edc_shaped_response_with_nested_access_service_object() {
        let participant = participant("edc-participant");
        let catalog = parse_catalog_response(&real_edc_shaped_response(), &participant);

        assert_eq!(catalog.id, "6d3d7a0c-bf06-4160-839f-853350446179");
        assert_eq!(catalog.origin_node, NodeId::new("edc-participant"));
        assert_eq!(
            catalog.participant_id.as_deref(),
            Some("CONNECTOR_UNDER_TEST")
        );

        assert_eq!(catalog.datasets.len(), 1);
        let dataset = &catalog.datasets[0];
        assert_eq!(dataset.id, "CAT0101");
        assert_eq!(dataset.distributions.len(), 1);
        assert_eq!(dataset.distributions[0].format, "HttpData-PULL");
        assert_eq!(
            dataset.distributions[0].access_service,
            "5ee7e0fa-a2bc-4251-bab3-d3a1454dcfc8"
        );

        // The nested accessService object's endpointURL isn't lost: it's
        // folded into data_services (deduplicated against the top-level
        // `service` array entry sharing the same id).
        assert_eq!(catalog.data_services.len(), 1);
        assert_eq!(
            catalog.data_services[0].id,
            "5ee7e0fa-a2bc-4251-bab3-d3a1454dcfc8"
        );
        assert_eq!(
            catalog.data_services[0].endpoint_url,
            "http://localhost:8082/api/dsp/2025-1"
        );
        assert_eq!(
            catalog.data_services[0].endpoint_description.as_deref(),
            Some("dspace:connector")
        );
    }

    #[test]
    fn parses_compact_string_access_service() {
        let body = json!({
            "@id": "cat-1",
            "dataset": [{
                "@id": "CAT0101",
                "distribution": [{"format": "application/json", "accessService": "sample-data-service"}]
            }],
            "service": [{"@id": "sample-data-service", "endpointURL": "https://example.org/dsp"}]
        });
        let participant = participant("compact-participant");
        let catalog = parse_catalog_response(&body, &participant);

        assert_eq!(catalog.datasets.len(), 1);
        assert_eq!(
            catalog.datasets[0].distributions[0].access_service,
            "sample-data-service"
        );
        assert_eq!(catalog.data_services.len(), 1);
        assert_eq!(
            catalog.data_services[0].endpoint_url,
            "https://example.org/dsp"
        );
    }

    #[test]
    fn missing_dataset_and_service_arrays_produce_an_empty_but_valid_catalog() {
        let body = json!({"@id": "empty-cat"});
        let participant = participant("empty-participant");
        let catalog = parse_catalog_response(&body, &participant);

        assert_eq!(catalog.id, "empty-cat");
        assert!(catalog.datasets.is_empty());
        assert!(catalog.data_services.is_empty());
    }

    #[test]
    fn missing_id_falls_back_to_a_fresh_uuid() {
        let body = json!({"dataset": []});
        let participant = participant("no-id-participant");
        let catalog = parse_catalog_response(&body, &participant);
        assert!(catalog.id.starts_with("urn:uuid:"));
    }

    #[test]
    fn dataset_id_falls_back_to_plain_id_field_when_at_id_is_absent() {
        let body = json!({"dataset": [{"id": "CAT0102"}]});
        let participant = participant("plain-id-participant");
        let catalog = parse_catalog_response(&body, &participant);
        assert_eq!(catalog.datasets.len(), 1);
        assert_eq!(catalog.datasets[0].id, "CAT0102");
    }

    /// Two sub-catalogs advertise the same dataset id with opposite
    /// policies. Both would land under the same store IRIs and merge into
    /// one mixed policy, so only the first is kept (as with services), and
    /// the dropped duplicate's nested access service is not folded in.
    #[test]
    fn duplicate_dataset_ids_keep_the_first_and_drop_the_rest() {
        let policy = |op: &str| {
            json!([{"permission": [{"action": "use", "constraint": [
                {"leftOperand": "role", "operator": op, "rightOperand": "admin"}
            ]}]}])
        };
        let body = json!({
            "@id": "urn:uuid:outer",
            "catalog": [
                {"dataset": [{
                    "@id": "ds-1", "title": "first", "hasPolicy": policy("eq"),
                    "distribution": [{"format": "json", "accessService": "svc-a"}]
                }], "service": [{"@id": "svc-a", "endpointURL": "https://a.example.org"}]},
                {"dataset": [{
                    "@id": "ds-1", "title": "second", "hasPolicy": policy("neq"),
                    "distribution": [{"format": "json", "accessService": {"@id": "svc-b", "endpointURL": "https://b.example.org"}}]
                }]}
            ]
        });
        let catalog = parse_catalog_response(&body, &participant("agg"));
        assert_eq!(catalog.datasets.len(), 1);
        let ds = &catalog.datasets[0];
        assert_eq!(
            ds.properties.get("title").map(String::as_str),
            Some("first")
        );
        assert_eq!(ds.distributions.len(), 1);
        assert_eq!(ds.distributions[0].access_service, "svc-a");
        assert_eq!(
            ds.policies[0].permissions[0].constraints,
            vec![Constraint::atomic("role", "eq", "admin")]
        );
        assert!(catalog.data_services.iter().all(|s| s.id != "svc-b"));
    }

    /// Dedup must stay linear in the number of entries: a crawled body of a
    /// few MB with unique ids is parsed synchronously inside the async task,
    /// where the per-participant timeout cannot interrupt it. A quadratic
    /// scan took tens of seconds at this size in a debug build.
    #[test]
    fn parsing_many_unique_datasets_and_services_stays_linear() {
        let n = 60_000;
        let datasets: Vec<Value> = (0..n).map(|i| json!({"@id": format!("ds-{i}")})).collect();
        let services: Vec<Value> = (0..n)
            .map(|i| json!({"@id": format!("svc-{i}"), "endpointURL": "https://x.example.org"}))
            .collect();
        let body = json!({"dataset": datasets, "service": services});
        let start = std::time::Instant::now();
        let catalog = parse_catalog_response(&body, &participant("big"));
        let elapsed = start.elapsed();
        assert_eq!(catalog.datasets.len(), n);
        assert_eq!(catalog.data_services.len(), n);
        assert!(
            elapsed < Duration::from_secs(3),
            "parsing {n} datasets and services took {elapsed:?}, expected linear time"
        );
    }

    /// "Federation of federations": the crawled participant is itself a
    /// multi-participant aggregator (another instance of this workspace's
    /// own `ds-catalog-broker-rs`, once it has 2+ origin nodes cached - see
    /// `ds_catalog_broker_rs::catalog_request`'s doc comment), so its response has
    /// empty top-level `dataset`/`service` and nests everything under
    /// `catalog[]` instead, one entry per sub-participant. Without
    /// flattening those nested entries, this would silently parse as an
    /// empty catalog even though the crawled node advertised 10 datasets.
    #[test]
    fn flattens_nested_catalog_entries_from_a_federation_of_federations_response() {
        let body = json!({
            "@id": "urn:uuid:outer-wrapper",
            "@type": "Catalog",
            "participantId": "urn:connector:upstream-aggregator",
            "dataset": [],
            "service": [],
            "catalog": [
                {
                    "@id": "urn:uuid:node-a-catalog",
                    "@type": "Catalog",
                    "participantId": "did:example:node-a",
                    "dataset": [
                        {
                            "@id": "A1",
                            "distribution": [{"format": "application/json", "accessService": "node-a-data-service"}]
                        }
                    ],
                    "service": [{"@id": "node-a-data-service", "endpointURL": "https://node-a.example.org/dsp"}]
                },
                {
                    "@id": "urn:uuid:node-b-catalog",
                    "@type": "Catalog",
                    "participantId": "did:example:node-b",
                    "dataset": [
                        {
                            "@id": "B1",
                            "distribution": [{"format": "application/json", "accessService": "node-b-data-service"}]
                        }
                    ],
                    "service": [{"@id": "node-b-data-service", "endpointURL": "https://node-b.example.org/dsp"}]
                }
            ]
        });
        let participant = participant("upstream-aggregator-participant");
        let catalog = parse_catalog_response(&body, &participant);

        // One Catalog per configured target participant is this crate's
        // own model - nested sub-participant identity isn't preserved,
        // only that the data isn't dropped. The outer wrapper's own
        // participantId is what's kept.
        assert_eq!(
            catalog.origin_node,
            NodeId::new("upstream-aggregator-participant")
        );
        assert_eq!(
            catalog.participant_id.as_deref(),
            Some("urn:connector:upstream-aggregator")
        );

        let mut dataset_ids: Vec<&str> = catalog.datasets.iter().map(|d| d.id.as_str()).collect();
        dataset_ids.sort();
        assert_eq!(dataset_ids, vec!["A1", "B1"]);

        let mut service_ids: Vec<&str> = catalog
            .data_services
            .iter()
            .map(|s| s.id.as_str())
            .collect();
        service_ids.sort();
        assert_eq!(
            service_ids,
            vec!["node-a-data-service", "node-b-data-service"]
        );
    }

    /// A dataset JSON object carrying every optional descriptive key this
    /// crawler is expected to fold into `Dataset.properties`
    /// (`title`/`description`/`version`/`creatorName`/`thumbnail`/
    /// `keywords`) round-trips into that bag verbatim, under exactly those
    /// keys - `keywords` stays a single comma-separated string, unsplit
    /// (splitting is `ds-catalog-broker-rs::dataset_to_offer`'s job, not the
    /// crawler's).
    #[test]
    fn dataset_optional_descriptive_properties_round_trip_into_properties_bag() {
        let body = json!({
            "@id": "cat-1",
            "dataset": [{
                "@id": "DATASET-A",
                "title": "Soil Moisture Readings",
                "description": "Hourly soil moisture readings from field sensors.",
                "version": "1.2.0",
                "creatorName": "Acme Sensors Inc.",
                "thumbnail": "https://example.org/thumbnails/soil-moisture.png",
                "keywords": "soil,moisture,sensors",
                "distribution": [{"format": "application/json", "accessService": "svc-1"}]
            }],
            "service": [{"@id": "svc-1", "endpointURL": "https://example.org/dsp"}]
        });
        let participant = participant("descriptive-participant");
        let catalog = parse_catalog_response(&body, &participant);

        assert_eq!(catalog.datasets.len(), 1);
        let props = &catalog.datasets[0].properties;
        assert_eq!(
            props.get("title").map(String::as_str),
            Some("Soil Moisture Readings")
        );
        assert_eq!(
            props.get("description").map(String::as_str),
            Some("Hourly soil moisture readings from field sensors.")
        );
        assert_eq!(props.get("version").map(String::as_str), Some("1.2.0"));
        assert_eq!(
            props.get("creatorName").map(String::as_str),
            Some("Acme Sensors Inc.")
        );
        assert_eq!(
            props.get("thumbnail").map(String::as_str),
            Some("https://example.org/thumbnails/soil-moisture.png")
        );
        assert_eq!(
            props.get("keywords").map(String::as_str),
            Some("soil,moisture,sensors"),
            "keywords must be stored verbatim as one comma-separated string, not pre-split"
        );
    }

    /// The backward-compatible half of the property above: a dataset JSON
    /// object with none of the optional descriptive keys must still parse
    /// exactly as before, with every one of those `properties` entries
    /// simply absent (never a fabricated default).
    #[test]
    fn dataset_without_optional_descriptive_properties_leaves_them_absent_from_the_bag() {
        let body = json!({
            "@id": "cat-1",
            "dataset": [{
                "@id": "DATASET-A",
                "distribution": [{"format": "application/json", "accessService": "svc-1"}]
            }],
            "service": [{"@id": "svc-1", "endpointURL": "https://example.org/dsp"}]
        });
        let participant = participant("no-descriptive-participant");
        let catalog = parse_catalog_response(&body, &participant);

        assert_eq!(catalog.datasets.len(), 1);
        let props = &catalog.datasets[0].properties;
        for key in [
            "title",
            "description",
            "version",
            "creatorName",
            "thumbnail",
            "keywords",
        ] {
            assert!(
                !props.contains_key(key),
                "expected no '{key}' property, found {:?}",
                props.get(key)
            );
        }
    }

    /// (a) A dataset with no `hasPolicy` key at all parses to an empty
    /// `policies` Vec - never a fabricated default, exactly like every
    /// other optional descriptor this function handles.
    #[test]
    fn dataset_without_has_policy_leaves_policies_empty() {
        let body = json!({
            "@id": "cat-1",
            "dataset": [{
                "@id": "DATASET-A",
                "distribution": [{"format": "application/json", "accessService": "svc-1"}]
            }],
            "service": [{"@id": "svc-1", "endpointURL": "https://example.org/dsp"}]
        });
        let participant = participant("no-policy-participant");
        let catalog = parse_catalog_response(&body, &participant);

        assert_eq!(catalog.datasets.len(), 1);
        assert!(catalog.datasets[0].policies.is_empty());
    }

    /// (b) A realistic policy - one `permission` (action + one constraint)
    /// and one `prohibition` (action only, no constraint) - parses to the
    /// exact expected `Policy`/`Rule`/`Constraint` values, including
    /// `@id`, `@type`, and the `odrl:assigner`/`odrl:assignee` aliases.
    #[test]
    fn dataset_has_policy_with_permission_and_prohibition_parses_exact_values() {
        let body = json!({
            "@id": "cat-1",
            "dataset": [{
                "@id": "DATASET-A",
                "hasPolicy": [{
                    "@id": "offer-1",
                    "@type": "Offer",
                    "odrl:assigner": "did:example:provider",
                    "odrl:assignee": "did:example:consumer",
                    "permission": [{
                        "action": "use",
                        "constraint": [{
                            "leftOperand": "dateTime",
                            "operator": "lteq",
                            "rightOperand": "2027-01-01T00:00:00Z"
                        }]
                    }],
                    "prohibition": [{"action": "distribute"}]
                }],
                "distribution": [{"format": "application/json", "accessService": "svc-1"}]
            }],
            "service": [{"@id": "svc-1", "endpointURL": "https://example.org/dsp"}]
        });
        let participant = participant("policy-participant");
        let catalog = parse_catalog_response(&body, &participant);

        assert_eq!(catalog.datasets.len(), 1);
        let policies = &catalog.datasets[0].policies;
        assert_eq!(policies.len(), 1);
        let policy = &policies[0];
        assert_eq!(policy.id.as_deref(), Some("offer-1"));
        assert_eq!(policy.kind, PolicyKind::Offer);
        assert_eq!(policy.assigner.as_deref(), Some("did:example:provider"));
        assert_eq!(policy.assignee.as_deref(), Some("did:example:consumer"));

        assert_eq!(policy.permissions.len(), 1);
        assert_eq!(policy.permissions[0].action, "use");
        assert_eq!(
            policy.permissions[0].constraints,
            vec![Constraint::atomic(
                "dateTime",
                "lteq",
                "2027-01-01T00:00:00Z"
            )]
        );

        assert_eq!(policy.prohibitions.len(), 1);
        assert_eq!(policy.prohibitions[0].action, "distribute");
        assert!(policy.prohibitions[0].constraints.is_empty());

        assert!(policy.obligations.is_empty());
    }

    /// (c) `hasPolicy` given as a single JSON object (not wrapped in an
    /// array) still parses correctly - ODRL/JSON-LD's "one-or-many"
    /// convention. Also exercises the real EDC/DSP expanded-IRI key
    /// `http://www.w3.org/ns/odrl/2/hasPolicy` instead of the compact
    /// `hasPolicy` alias.
    #[test]
    fn dataset_has_policy_as_a_single_object_via_expanded_iri_key_parses() {
        let body = json!({
            "@id": "cat-1",
            "dataset": [{
                "@id": "DATASET-A",
                "http://www.w3.org/ns/odrl/2/hasPolicy": {
                    "@type": "Set",
                    "permission": {"action": "use"}
                },
                "distribution": [{"format": "application/json", "accessService": "svc-1"}]
            }],
            "service": [{"@id": "svc-1", "endpointURL": "https://example.org/dsp"}]
        });
        let participant = participant("expanded-iri-participant");
        let catalog = parse_catalog_response(&body, &participant);

        assert_eq!(catalog.datasets.len(), 1);
        let policies = &catalog.datasets[0].policies;
        assert_eq!(policies.len(), 1);
        assert_eq!(policies[0].kind, PolicyKind::Set);
        assert_eq!(policies[0].permissions.len(), 1);
        assert_eq!(policies[0].permissions[0].action, "use");
    }

    /// (d) A permission carrying one well-formed atomic constraint
    /// alongside one genuinely malformed one (neither a complete atomic
    /// `leftOperand`/`operator`/`rightOperand` triple - `rightOperand` is
    /// missing here - nor a recognized `odrl:and`/`odrl:or`/`odrl:xone`/
    /// `odrl:andSequence` logical key) keeps the malformed one as an
    /// unmappable marker - the well-formed constraint and the rest of the
    /// permission/policy survive intact, and the whole crawl does not panic. Note this is
    /// *not* an `odrl:and`/etc. node: those are real, well-formed ODRL and
    /// are now parsed into `Constraint::Logical` (see
    /// `logical_and_constraint_is_parsed_not_skipped`), not treated as
    /// malformed.
    #[test]
    fn malformed_nested_constraint_is_kept_as_a_marker_beside_the_rest_of_the_policy() {
        let body = json!({
            "@id": "cat-1",
            "dataset": [{
                "@id": "DATASET-A",
                "hasPolicy": [{
                    "@type": "Offer",
                    "permission": [{
                        "action": "use",
                        "constraint": [
                            {
                                "leftOperand": "count",
                                "operator": "lteq",
                                "rightOperand": "10"
                            },
                            {
                                "leftOperand": "dateTime",
                                "operator": "gt"
                            }
                        ]
                    }]
                }],
                "distribution": [{"format": "application/json", "accessService": "svc-1"}]
            }],
            "service": [{"@id": "svc-1", "endpointURL": "https://example.org/dsp"}]
        });
        let participant = participant("nested-constraint-participant");
        let catalog = parse_catalog_response(&body, &participant);

        assert_eq!(catalog.datasets.len(), 1);
        let policies = &catalog.datasets[0].policies;
        assert_eq!(policies.len(), 1);
        assert_eq!(policies[0].permissions.len(), 1);
        let constraints = &policies[0].permissions[0].constraints;
        assert_eq!(constraints.len(), 2);
        assert_eq!(constraints[0], Constraint::atomic("count", "lteq", "10"));
        assert!(
            constraints[1].is_unmappable(),
            "the constraint missing rightOperand must be kept as an unmappable marker, not dropped"
        );
    }

    /// A genuine `odrl:and` logical-group constraint node (real ODRL, not
    /// malformed) must now be parsed into `Constraint::Logical`, preserving
    /// nested child order - not skipped/dropped as gap analysis §3.4 used
    /// to document. Once `catalog_core::Constraint` gained logical-grouping
    /// support, treating this shape as "malformed because it has no flat
    /// `leftOperand`" is outdated: it is well-formed ODRL that this parser
    /// was choosing not to model.
    #[test]
    fn logical_and_constraint_is_parsed_not_skipped() {
        let body = json!({
            "@id": "cat-1",
            "dataset": [{
                "@id": "DATASET-A",
                "hasPolicy": [{
                    "@type": "Offer",
                    "permission": [{
                        "action": "use",
                        "constraint": [{
                            "odrl:and": [
                                {"leftOperand": "dateTime", "operator": "gt", "rightOperand": "2026-01-01"},
                                {"leftOperand": "dateTime", "operator": "lt", "rightOperand": "2027-01-01"}
                            ]
                        }]
                    }]
                }],
                "distribution": [{"format": "application/json", "accessService": "svc-1"}]
            }],
            "service": [{"@id": "svc-1", "endpointURL": "https://example.org/dsp"}]
        });
        let participant = participant("logical-constraint-participant");
        let catalog = parse_catalog_response(&body, &participant);

        assert_eq!(catalog.datasets.len(), 1);
        let policies = &catalog.datasets[0].policies;
        assert_eq!(policies.len(), 1);
        assert_eq!(
            policies[0].permissions.len(),
            1,
            "the permission itself must survive even though its constraint is a logical group"
        );
        assert_eq!(
            policies[0].permissions[0].constraints,
            vec![Constraint::and(vec![
                Constraint::atomic("dateTime", "gt", "2026-01-01"),
                Constraint::atomic("dateTime", "lt", "2027-01-01"),
            ])],
            "a genuine odrl:and logical-group constraint must be parsed into Constraint::Logical \
             with its children in source order, not skipped/dropped"
        );
    }

    /// A `permission`/`prohibition`/`obligation` entry missing its
    /// required `action` is kept as a marker rule under `UNMAPPABLE_ACTION`
    /// (dropping it would loosen the policy when it is a prohibition), and
    /// the rest of the policy is unaffected.
    #[test]
    fn rule_entry_missing_action_is_kept_as_a_marker_rule() {
        let body = json!({
            "@id": "cat-1",
            "dataset": [{
                "@id": "DATASET-A",
                "hasPolicy": [{
                    "@type": "Offer",
                    "permission": [
                        {"constraint": [{"leftOperand": "count", "operator": "lteq", "rightOperand": "10"}]},
                        {"action": "use"}
                    ]
                }],
                "distribution": [{"format": "application/json", "accessService": "svc-1"}]
            }],
            "service": [{"@id": "svc-1", "endpointURL": "https://example.org/dsp"}]
        });
        let participant = participant("missing-action-participant");
        let catalog = parse_catalog_response(&body, &participant);

        let policies = &catalog.datasets[0].policies;
        assert_eq!(policies.len(), 1);
        let permissions = &policies[0].permissions;
        assert_eq!(permissions.len(), 2, "no rule is dropped");
        assert_eq!(permissions[0].action, UNMAPPABLE_ACTION);
        assert!(
            permissions[0]
                .constraints
                .iter()
                .any(Constraint::is_unmappable)
        );
        assert_eq!(permissions[1].action, "use");
    }

    /// An unrecognized `@type` value degrades leniently to the default
    /// `PolicyKind` (`Set`) rather than failing the whole dataset.
    #[test]
    fn unrecognized_policy_type_falls_back_to_default_kind() {
        let body = json!({
            "@id": "cat-1",
            "dataset": [{
                "@id": "DATASET-A",
                "hasPolicy": [{"@type": "SomethingUnknown", "permission": [{"action": "use"}]}],
                "distribution": [{"format": "application/json", "accessService": "svc-1"}]
            }],
            "service": [{"@id": "svc-1", "endpointURL": "https://example.org/dsp"}]
        });
        let participant = participant("unknown-type-participant");
        let catalog = parse_catalog_response(&body, &participant);

        let policies = &catalog.datasets[0].policies;
        assert_eq!(policies.len(), 1);
        assert_eq!(policies[0].kind, PolicyKind::Set);
    }

    #[tokio::test]
    async fn crawl_once_records_a_failure_for_an_unreachable_participant_and_continues() {
        // Port 0 never accepts connections, so this participant's request
        // is guaranteed to fail at the transport level without needing a
        // real server.
        let participants = vec![participant("unreachable-participant")];
        let cache = OxigraphCatalogCache::in_memory().unwrap();
        let http = reqwest::Client::new();

        let summary = crawl_once(&http, &participants, None, &cache, &CrawlLimits::default()).await;

        assert_eq!(summary.attempted, 1);
        assert_eq!(summary.succeeded, 0);
        assert_eq!(summary.failed, 1);
        assert_eq!(summary.failures.len(), 1);
        assert_eq!(summary.failures[0].0, "unreachable-participant");

        let stored = cache.query(CatalogQuery::all()).await.unwrap();
        assert!(stored.is_empty());
    }

    #[tokio::test]
    async fn crawl_one_requires_a_holder_identity_for_a_dcp_participant() {
        let mut gated = participant("gated-participant");
        gated.credential_protocol = CredentialProtocol::Dcp;
        gated.provider_did = Some("did:web:localhost%3A19002:dsp".to_string());
        let http = reqwest::Client::new();

        let err = crawl_one(&http, &gated, None)
            .await
            .expect_err("should fail without a holder");
        assert!(
            err.contains("no holder identity is configured"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn crawl_one_requires_a_holder_identity_for_an_oid4vp_participant() {
        let mut gated = participant("oid4vp-participant");
        gated.credential_protocol = CredentialProtocol::Oid4Vp;
        gated.oid4vp_response_uri = Some("http://127.0.0.1:0/oid4vp/response".to_string());
        let http = reqwest::Client::new();

        let err = crawl_one(&http, &gated, None)
            .await
            .expect_err("should fail without a holder, not panic");
        assert!(
            err.contains("no holder identity is configured"),
            "unexpected error: {err}"
        );
    }

    // --- OID4VP end-to-end wiring (docs/oid4vp-holder-2026-08-28.md) ---
    //
    // Real local mock servers for both the `oid4vp_response_uri` (the
    // OID4VP verifier's `direct_post` endpoint) and the
    // `catalog_request_url` (the real DSP catalog fetch this crawler makes
    // once it holds an access token) - proving the full chain
    // `oid4vp::present` -> access_token -> `request.bearer_auth` -> the
    // actual catalog fetch, not just that `oid4vp::present` works in
    // isolation.

    async fn bind_localhost() -> (tokio::net::TcpListener, std::net::SocketAddr) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind 127.0.0.1:0");
        let addr = listener.local_addr().expect("local_addr");
        (listener, addr)
    }

    fn spawn_server(listener: tokio::net::TcpListener, app: axum::Router) {
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("axum::serve");
        });
    }

    /// A mock `oid4vp_response_uri` server: always answers `200` with a
    /// fixed access token, regardless of what it was sent - this test's
    /// concern is what happens *after* a token is obtained (does it reach
    /// the catalog request as `Authorization: Bearer <token>`), not
    /// re-proving `oid4vp::present`'s own request-building, which
    /// `oid4vp.rs`'s own unit tests already cover.
    async fn spawn_oid4vp_response_server(access_token: &'static str) -> String {
        let (listener, addr) = bind_localhost().await;
        let app = axum::Router::new().route(
            "/oid4vp/response",
            axum::routing::post(move || async move {
                axum::Json(json!({"access_token": access_token}))
            }),
        );
        spawn_server(listener, app);
        format!("http://{addr}/oid4vp/response")
    }

    /// A mock `oid4vp_response_uri` server that always answers `401` - for
    /// the failure-path test below.
    async fn spawn_failing_oid4vp_response_server() -> String {
        let (listener, addr) = bind_localhost().await;
        let app = axum::Router::new().route(
            "/oid4vp/response",
            axum::routing::post(|| async {
                (axum::http::StatusCode::UNAUTHORIZED, "invalid_request")
            }),
        );
        spawn_server(listener, app);
        format!("http://{addr}/oid4vp/response")
    }

    /// A mock `catalog_request_url` server that asserts it received
    /// exactly `Authorization: Bearer <expected_access_token>` - proving
    /// the access token `oid4vp::present` returned is the one actually
    /// attached to the real catalog request, not just discarded/ignored.
    /// Answers with a real catalog body only when the header matches;
    /// `401` otherwise (so a wiring bug shows up as a crawl failure in the
    /// test, not a silent false-positive pass).
    async fn spawn_catalog_server_expecting_bearer(expected_access_token: &'static str) -> String {
        let (listener, addr) = bind_localhost().await;
        let app = axum::Router::new().route(
            "/dsp/catalog/request",
            axum::routing::post(move |headers: axum::http::HeaderMap| async move {
                let ok = headers
                    .get(axum::http::header::AUTHORIZATION)
                    .and_then(|v| v.to_str().ok())
                    .is_some_and(|v| v == format!("Bearer {expected_access_token}"));
                if ok {
                    axum::Json(json!({
                        "@id": "oid4vp-catalog",
                        "dataset": [{"@id": "OID4VP-01", "id": "OID4VP-01"}],
                        "service": [],
                    }))
                    .into_response()
                } else {
                    (
                        axum::http::StatusCode::UNAUTHORIZED,
                        "missing or wrong bearer token",
                    )
                        .into_response()
                }
            }),
        );
        spawn_server(listener, app);
        format!("http://{addr}/dsp/catalog/request")
    }

    #[tokio::test]
    async fn crawl_once_presents_oid4vp_and_uses_the_returned_access_token_on_the_catalog_request()
    {
        const ACCESS_TOKEN: &str = "mock-oid4vp-access-token-xyz";
        let oid4vp_response_uri = spawn_oid4vp_response_server(ACCESS_TOKEN).await;
        let catalog_request_url = spawn_catalog_server_expecting_bearer(ACCESS_TOKEN).await;

        let mut oid4vp_participant = participant("oid4vp-participant");
        oid4vp_participant.credential_protocol = CredentialProtocol::Oid4Vp;
        oid4vp_participant.catalog_request_url = catalog_request_url;
        oid4vp_participant.oid4vp_response_uri = Some(oid4vp_response_uri);

        let holder = HolderIdentity::new(
            "localhost:19100".to_string(),
            true,
            "fake.credential.jws".to_string(),
            "org.eclipse.dspace.dcp.vc.type:FederatedCatalogAccessCredential:read".to_string(),
        );

        let participants = vec![oid4vp_participant];
        let http = reqwest::Client::new();
        let cache = OxigraphCatalogCache::in_memory().unwrap();

        let summary = crawl_once(
            &http,
            &participants,
            Some(&holder),
            &cache,
            &CrawlLimits::default(),
        )
        .await;

        assert_eq!(summary.attempted, 1, "summary: {summary:?}");
        assert_eq!(summary.failed, 0, "summary: {summary:?}");
        assert_eq!(summary.succeeded, 1, "summary: {summary:?}");

        let stored = cache
            .query(CatalogQuery::for_node(NodeId::new("oid4vp-participant")))
            .await
            .unwrap();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].id, "oid4vp-catalog");
        assert_eq!(stored[0].datasets.len(), 1);
        assert_eq!(stored[0].datasets[0].id, "OID4VP-01");
    }

    #[tokio::test]
    async fn crawl_once_records_a_failure_when_the_oid4vp_response_uri_rejects_the_presentation() {
        let oid4vp_response_uri = spawn_failing_oid4vp_response_server().await;

        let mut oid4vp_participant = participant("oid4vp-participant");
        oid4vp_participant.credential_protocol = CredentialProtocol::Oid4Vp;
        // Never actually reached: `oid4vp::present` must fail before any
        // catalog request is attempted.
        oid4vp_participant.catalog_request_url =
            "http://127.0.0.1:0/dsp/catalog/request".to_string();
        oid4vp_participant.oid4vp_response_uri = Some(oid4vp_response_uri);

        let holder = HolderIdentity::new(
            "localhost:19100".to_string(),
            true,
            "fake.credential.jws".to_string(),
            "org.eclipse.dspace.dcp.vc.type:FederatedCatalogAccessCredential:read".to_string(),
        );

        let participants = vec![oid4vp_participant];
        let http = reqwest::Client::new();
        let cache = OxigraphCatalogCache::in_memory().unwrap();

        let summary = crawl_once(
            &http,
            &participants,
            Some(&holder),
            &cache,
            &CrawlLimits::default(),
        )
        .await;

        assert_eq!(summary.attempted, 1, "summary: {summary:?}");
        assert_eq!(summary.succeeded, 0, "summary: {summary:?}");
        assert_eq!(summary.failed, 1, "summary: {summary:?}");
        assert_eq!(summary.failures[0].0, "oid4vp-participant");

        let stored = cache.query(CatalogQuery::all()).await.unwrap();
        assert!(
            stored.is_empty(),
            "a rejected presentation must not cache anything for this participant"
        );
    }

    /// A catalog server that answers every request after `delay`, counting
    /// how many requests it is serving at once. Returns its request URL and
    /// the highest concurrency it saw.
    async fn spawn_slow_catalog_server(
        delay: Duration,
    ) -> (String, Arc<std::sync::atomic::AtomicUsize>) {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let in_flight = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let (listener, addr) = bind_localhost().await;
        let app = axum::Router::new().route(
            "/dsp/catalog/request",
            axum::routing::post({
                let in_flight = in_flight.clone();
                let peak = peak.clone();
                move || async move {
                    let now = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                    peak.fetch_max(now, Ordering::SeqCst);
                    tokio::time::sleep(delay).await;
                    in_flight.fetch_sub(1, Ordering::SeqCst);
                    axum::Json(json!({"@id": "slow-catalog", "dataset": [], "service": []}))
                }
            }),
        );
        spawn_server(listener, app);
        (format!("http://{addr}/dsp/catalog/request"), peak)
    }

    /// A catalog server that answers `200` while `up` is true and `503`
    /// otherwise.
    async fn spawn_switchable_catalog_server(up: Arc<std::sync::atomic::AtomicBool>) -> String {
        let (listener, addr) = bind_localhost().await;
        let app = axum::Router::new().route(
            "/dsp/catalog/request",
            axum::routing::post(move || async move {
                if up.load(std::sync::atomic::Ordering::SeqCst) {
                    axum::Json(json!({"@id": "switchable-catalog", "dataset": [], "service": []}))
                        .into_response()
                } else {
                    axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response()
                }
            }),
        );
        spawn_server(listener, app);
        format!("http://{addr}/dsp/catalog/request")
    }

    #[tokio::test]
    async fn crawl_once_crawls_up_to_the_concurrency_limit_at_once() {
        let (url, peak) = spawn_slow_catalog_server(Duration::from_millis(200)).await;
        let participants: Vec<_> = (0..6)
            .map(|i| {
                let mut entry = participant(&format!("p{i}"));
                entry.catalog_request_url = url.clone();
                entry
            })
            .collect();
        let limits = CrawlLimits {
            concurrency: 3,
            ..CrawlLimits::default()
        };
        let cache = OxigraphCatalogCache::in_memory().unwrap();

        let summary = crawl_once(
            &reqwest::Client::new(),
            &participants,
            None,
            &cache,
            &limits,
        )
        .await;

        assert_eq!(summary.succeeded, 6, "summary: {summary:?}");
        assert_eq!(
            summary.succeeded_ids,
            vec!["p0", "p1", "p2", "p3", "p4", "p5"],
            "results stay in participant order"
        );
        assert_eq!(peak.load(std::sync::atomic::Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn crawl_once_fails_a_participant_that_outlasts_the_timeout_without_blocking_others() {
        let (slow_url, _) = spawn_slow_catalog_server(Duration::from_secs(30)).await;
        let (fast_url, _) = spawn_slow_catalog_server(Duration::ZERO).await;
        let mut slow = participant("slow");
        slow.catalog_request_url = slow_url;
        let mut fast = participant("fast");
        fast.catalog_request_url = fast_url;
        let limits = CrawlLimits {
            participant_timeout: Duration::from_millis(200),
            ..CrawlLimits::default()
        };
        let cache = OxigraphCatalogCache::in_memory().unwrap();

        let started = std::time::Instant::now();
        let summary = crawl_once(
            &reqwest::Client::new(),
            &[slow, fast],
            None,
            &cache,
            &limits,
        )
        .await;

        assert!(started.elapsed() < Duration::from_secs(5));
        assert_eq!(summary.succeeded_ids, vec!["fast"]);
        assert_eq!(summary.failures.len(), 1);
        assert_eq!(summary.failures[0].0, "slow");
        assert!(
            summary.failures[0].1.contains("timed out"),
            "unexpected error: {}",
            summary.failures[0].1
        );
    }

    #[tokio::test]
    async fn harvester_keeps_a_failed_participants_catalog_until_it_is_older_than_the_max_age() {
        let up = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let mut entry = participant("flaky");
        entry.catalog_request_url = spawn_switchable_catalog_server(up.clone()).await;
        let cache: Arc<dyn CatalogCache> = Arc::new(OxigraphCatalogCache::in_memory().unwrap());
        let limits = CrawlLimits {
            max_catalog_age: Duration::from_millis(300),
            ..CrawlLimits::default()
        };
        let mut harvester = Harvester::new(
            cache.clone(),
            vec![entry],
            reqwest::Client::new(),
            None,
            limits,
        );
        let cached = || async {
            cache
                .query(CatalogQuery::for_node(NodeId::new("flaky")))
                .await
                .unwrap()
                .len()
        };

        let report = harvester.run_cycle().await;
        assert_eq!(report.summary.succeeded, 1);
        assert_eq!(cached().await, 1);

        up.store(false, std::sync::atomic::Ordering::SeqCst);
        let report = harvester.run_cycle().await;
        assert_eq!(report.summary.failed, 1);
        assert!(report.expired.is_empty());
        assert_eq!(
            cached().await,
            1,
            "a recent catalog survives a failed crawl"
        );

        tokio::time::sleep(Duration::from_millis(400)).await;
        let report = harvester.run_cycle().await;
        assert_eq!(report.expired, vec!["flaky"]);
        assert_eq!(cached().await, 0, "a stale catalog is removed");

        let report = harvester.run_cycle().await;
        assert!(
            report.expired.is_empty(),
            "an expired catalog is removed once"
        );
    }

    #[tokio::test]
    async fn harvester_reports_each_participants_crawl_status() {
        let up = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let mut ok = participant("ok");
        ok.catalog_request_url = spawn_switchable_catalog_server(up.clone()).await;
        let mut down = participant("down");
        down.catalog_request_url = "http://127.0.0.1:1/dsp/catalog/request".to_string();
        let cache: Arc<dyn CatalogCache> = Arc::new(OxigraphCatalogCache::in_memory().unwrap());
        let mut harvester = Harvester::new(
            cache,
            vec![ok, down],
            reqwest::Client::new(),
            None,
            CrawlLimits::default(),
        );
        let status = harvester.status();
        assert_eq!(status.snapshot().cycles_completed, 0);

        harvester.run_cycle().await;
        let first = status.snapshot();
        assert_eq!(first.cycles_completed, 1);
        let ok_status = &first.participants["ok"];
        assert!(ok_status.last_attempt.is_some());
        assert!(ok_status.last_success.is_some());
        assert_eq!(ok_status.last_error, None);
        assert!(ok_status.cached);
        let down_status = &first.participants["down"];
        assert!(down_status.last_attempt.is_some());
        assert_eq!(down_status.last_success, None);
        assert!(down_status.last_error.is_some());
        assert!(!down_status.cached);

        up.store(false, std::sync::atomic::Ordering::SeqCst);
        harvester.run_cycle().await;
        let second = status.snapshot();
        assert_eq!(second.cycles_completed, 2);
        let ok_status = &second.participants["ok"];
        assert_eq!(
            ok_status.last_success,
            first.participants["ok"].last_success
        );
        assert!(ok_status.last_error.is_some(), "a failure is recorded");
        assert!(ok_status.cached, "the previous catalog is still served");
    }

    #[tokio::test]
    async fn harvester_status_marks_an_expired_catalog_as_not_cached() {
        let up = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let mut entry = participant("flaky");
        entry.catalog_request_url = spawn_switchable_catalog_server(up.clone()).await;
        let cache: Arc<dyn CatalogCache> = Arc::new(OxigraphCatalogCache::in_memory().unwrap());
        let mut harvester = Harvester::new(
            cache,
            vec![entry],
            reqwest::Client::new(),
            None,
            CrawlLimits {
                max_catalog_age: Duration::from_millis(100),
                ..CrawlLimits::default()
            },
        );
        harvester.run_cycle().await;
        up.store(false, std::sync::atomic::Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(200)).await;
        let report = harvester.run_cycle().await;
        assert_eq!(report.expired, vec!["flaky"]);
        assert!(!harvester.status().snapshot().participants["flaky"].cached);
    }

    #[tokio::test]
    async fn the_scheduler_stops_mid_cycle_when_shutdown_is_cancelled() {
        let (slow_url, in_flight_peak) = spawn_slow_catalog_server(Duration::from_secs(30)).await;
        let mut slow = participant("slow");
        slow.catalog_request_url = slow_url;
        let shutdown = CancellationToken::new();
        let scheduler = spawn_scheduler(
            Arc::new(OxigraphCatalogCache::in_memory().unwrap()),
            ParticipantsConfig::new(300, vec![slow], None).unwrap(),
            reqwest::Client::new(),
            None,
            CrawlLimits {
                participant_timeout: Duration::from_secs(60),
                ..CrawlLimits::default()
            },
            shutdown.clone(),
        );
        // Cancel only once the crawl is actually waiting on the slow server.
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while in_flight_peak.load(std::sync::atomic::Ordering::SeqCst) == 0 {
            assert!(
                std::time::Instant::now() < deadline,
                "the crawl never started"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        shutdown.cancel();
        let stopped = tokio::time::timeout(Duration::from_secs(2), scheduler.handle).await;
        assert!(
            matches!(stopped, Ok(Ok(()))),
            "the scheduler did not stop: {stopped:?}"
        );
        assert_eq!(
            scheduler.status.snapshot().cycles_completed,
            0,
            "the interrupted cycle is not counted"
        );
    }

    #[tokio::test]
    async fn each_participant_is_stamped_with_its_own_finish_time() {
        let (slow_url, _) = spawn_slow_catalog_server(Duration::from_millis(500)).await;
        let (fast_url, _) = spawn_slow_catalog_server(Duration::ZERO).await;
        let mut slow = participant("slow");
        slow.catalog_request_url = slow_url;
        let mut fast = participant("fast");
        fast.catalog_request_url = fast_url;
        let cache: Arc<dyn CatalogCache> = Arc::new(OxigraphCatalogCache::in_memory().unwrap());
        let mut harvester = Harvester::new(
            cache,
            vec![slow, fast],
            reqwest::Client::new(),
            None,
            CrawlLimits::default(),
        );
        let report = harvester.run_cycle().await;
        let fast_at = report.summary.finished_at["fast"];
        let slow_at = report.summary.finished_at["slow"];
        assert!(
            slow_at.duration_since(fast_at).unwrap() >= Duration::from_millis(400),
            "the fast participant is not stamped with the slow one's time"
        );
        let status = harvester.status().snapshot();
        assert_eq!(status.participants["fast"].last_success, Some(fast_at));
        assert_eq!(status.participants["fast"].last_attempt, Some(fast_at));
        assert_eq!(status.participants["slow"].last_success, Some(slow_at));
    }

    #[tokio::test]
    async fn a_slow_participant_does_not_hold_back_the_ones_after_it() {
        let (slow_url, _) = spawn_slow_catalog_server(Duration::from_millis(600)).await;
        let (fast_url, _) = spawn_slow_catalog_server(Duration::ZERO).await;
        let mut participants = Vec::new();
        for id in ["slow", "a", "b", "c", "d"] {
            let mut p = participant(id);
            p.catalog_request_url = if id == "slow" { &slow_url } else { &fast_url }.clone();
            participants.push(p);
        }
        let cache = OxigraphCatalogCache::in_memory().unwrap();
        let limits = CrawlLimits {
            concurrency: 2,
            ..CrawlLimits::default()
        };
        let summary = crawl_once(
            &reqwest::Client::new(),
            &participants,
            None,
            &cache,
            &limits,
        )
        .await;
        assert_eq!(summary.succeeded, 5);
        assert!(
            summary.finished_at["d"] < summary.finished_at["slow"],
            "the last participant waited for the slow first one"
        );
        assert_eq!(
            summary.succeeded_ids,
            vec!["slow", "a", "b", "c", "d"],
            "results stay in participant order"
        );
    }

    #[tokio::test]
    async fn catalog_age_counts_from_the_participants_own_finish() {
        let (slow_url, _) = spawn_slow_catalog_server(Duration::from_millis(500)).await;
        let (fast_url, _) = spawn_slow_catalog_server(Duration::ZERO).await;
        let mut slow = participant("slow");
        slow.catalog_request_url = slow_url;
        let mut fast = participant("fast");
        fast.catalog_request_url = fast_url;
        let cache: Arc<dyn CatalogCache> = Arc::new(OxigraphCatalogCache::in_memory().unwrap());
        let mut harvester = Harvester::new(
            cache,
            vec![slow, fast],
            reqwest::Client::new(),
            None,
            CrawlLimits {
                max_catalog_age: Duration::from_millis(300),
                ..CrawlLimits::default()
            },
        );
        let report = harvester.run_cycle().await;
        assert_eq!(
            report.expired,
            vec!["fast"],
            "the fast catalog was already older than the limit when the cycle ended"
        );
    }

    /// A cache whose `delete` fails until `allow` is set.
    struct FailingDelete {
        inner: OxigraphCatalogCache,
        allow: std::sync::atomic::AtomicBool,
    }

    #[async_trait::async_trait]
    impl CatalogCache for FailingDelete {
        async fn upsert(&self, catalog: Catalog) -> rdf_store::StoreResult<()> {
            self.inner.upsert(catalog).await
        }
        async fn query(&self, query: CatalogQuery) -> rdf_store::StoreResult<Vec<Catalog>> {
            self.inner.query(query).await
        }
        async fn delete(&self, node: &NodeId) -> rdf_store::StoreResult<bool> {
            if self.allow.load(std::sync::atomic::Ordering::SeqCst) {
                self.inner.delete(node).await
            } else {
                Err(rdf_store::StoreError::Backend("delete refused".to_string()))
            }
        }
    }

    #[tokio::test]
    async fn a_failed_expiry_delete_is_retried_and_not_reported_as_removed() {
        let up = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let mut entry = participant("flaky");
        entry.catalog_request_url = spawn_switchable_catalog_server(up.clone()).await;
        let cache = Arc::new(FailingDelete {
            inner: OxigraphCatalogCache::in_memory().unwrap(),
            allow: std::sync::atomic::AtomicBool::new(false),
        });
        let mut harvester = Harvester::new(
            cache.clone(),
            vec![entry],
            reqwest::Client::new(),
            None,
            CrawlLimits {
                max_catalog_age: Duration::from_millis(100),
                ..CrawlLimits::default()
            },
        );
        harvester.run_cycle().await;
        up.store(false, std::sync::atomic::Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(200)).await;

        let report = harvester.run_cycle().await;
        assert!(report.expired.is_empty(), "a failed delete removed nothing");
        assert!(
            harvester.status().snapshot().participants["flaky"].cached,
            "the catalog is still served"
        );

        cache.allow.store(true, std::sync::atomic::Ordering::SeqCst);
        let report = harvester.run_cycle().await;
        assert_eq!(report.expired, vec!["flaky"], "the delete is retried");
        assert!(!harvester.status().snapshot().participants["flaky"].cached);
    }

    // --- #40: unparseable policy content is kept as an unmappable marker ---

    fn parse_one_policy(policy: Value) -> Policy {
        let body = json!({"@id": "cat-1", "dataset": [{"@id": "D", "hasPolicy": [policy]}]});
        let catalog = parse_catalog_response(&body, &participant("p40"));
        catalog.datasets[0].policies[0].clone()
    }

    fn is_marker(c: &Constraint) -> bool {
        c.is_unmappable()
    }

    #[test]
    fn incomplete_atomic_constraint_becomes_an_unmappable_marker() {
        let policy = parse_one_policy(json!({"permission": [{
            "action": "use",
            "constraint": [{"leftOperand": "purpose", "operator": "eq"}]
        }]}));
        let constraints = &policy.permissions[0].constraints;
        assert_eq!(constraints.len(), 1);
        assert!(is_marker(&constraints[0]), "{constraints:?}");
    }

    #[test]
    fn unrecognized_constraint_shape_becomes_an_unmappable_marker() {
        let policy = parse_one_policy(json!({"permission": [{
            "action": "use",
            "constraint": [{"foo": "bar"}, "not-an-object"]
        }]}));
        let constraints = &policy.permissions[0].constraints;
        assert_eq!(constraints.len(), 2);
        assert!(constraints.iter().all(is_marker));
    }

    #[test]
    fn over_deep_group_child_is_marked_not_dropped() {
        let mut deep = json!({"leftOperand": "a", "operator": "eq", "rightOperand": "b"});
        for _ in 0..(MAX_CONSTRAINT_DEPTH + 5) {
            deep = json!({"odrl:and": [deep]});
        }
        let leaf = json!({"leftOperand": "x", "operator": "eq", "rightOperand": "y"});
        let policy = parse_one_policy(json!({"permission": [{
            "action": "use",
            "constraint": [{"odrl:and": [leaf, deep]}]
        }]}));
        let Constraint::Logical(catalog_core::LogicalConstraint::And(children)) =
            &policy.permissions[0].constraints[0]
        else {
            panic!("expected an and group");
        };
        assert_eq!(children.len(), 2, "the deep child must not be dropped");
        // Walk down the deep child: it must end in a marker within the
        // depth bound the store accepts.
        let mut node = &children[1];
        let mut depth = 1;
        loop {
            match node {
                Constraint::Logical(catalog_core::LogicalConstraint::And(c)) => {
                    node = &c[0];
                    depth += 1;
                }
                other => {
                    assert!(is_marker(other), "{other:?}");
                    break;
                }
            }
        }
        assert!(depth <= MAX_CONSTRAINT_DEPTH, "depth {depth}");
    }

    #[test]
    fn bare_and_prefixed_aliases_are_read_everywhere() {
        let policy = parse_one_policy(json!({
            "odrl:assignee": "did:web:a",
            "odrl:prohibition": [{
                "odrl:action": "odrl:distribute",
                "odrl:constraint": [{"and": [
                    {"odrl:leftOperand": "count", "odrl:operator": "lt", "odrl:rightOperand": "3"}
                ]}]
            }],
            "http://www.w3.org/ns/odrl/2/permission": {"action": "use"},
            "obligation": {"action": "delete"}
        }));
        assert_eq!(policy.assignee.as_deref(), Some("did:web:a"));
        assert_eq!(policy.prohibitions.len(), 1);
        assert_eq!(
            policy.prohibitions[0].constraints,
            vec![Constraint::and(vec![Constraint::atomic(
                "count", "lt", "3"
            )])]
        );
        assert_eq!(policy.permissions.len(), 1);
        assert_eq!(policy.obligations.len(), 1);
    }

    #[test]
    fn odrl_prefixed_has_policy_is_read() {
        let body = json!({"@id": "c", "dataset": [{
            "@id": "D",
            "odrl:hasPolicy": {"permission": {"action": "use"}}
        }]});
        let catalog = parse_catalog_response(&body, &participant("p40"));
        assert_eq!(catalog.datasets[0].policies.len(), 1);
    }

    #[test]
    fn json_ld_value_objects_are_normalized() {
        let policy = parse_one_policy(json!({
            "assignee": {"@id": "did:web:a"},
            "permission": [{
                "action": {"@id": "odrl:use"},
                "constraint": [
                    {"leftOperand": {"@id": "odrl:purpose"}, "operator": {"@id": "odrl:eq"},
                     "rightOperand": {"@value": "research", "@type": "xsd:string"}},
                    {"leftOperand": "count", "operator": "lteq", "rightOperand": 10},
                    {"leftOperand": "flag", "operator": "eq", "rightOperand": true}
                ]
            }]
        }));
        assert_eq!(policy.assignee.as_deref(), Some("did:web:a"));
        assert_eq!(policy.permissions[0].action, "odrl:use");
        assert_eq!(
            policy.permissions[0].constraints,
            vec![
                Constraint::atomic("odrl:purpose", "odrl:eq", "research"),
                Constraint::atomic("count", "lteq", "10"),
                Constraint::atomic("flag", "eq", "true"),
            ]
        );
    }

    #[test]
    fn unparseable_right_operand_is_marked() {
        let policy = parse_one_policy(json!({"permission": [{
            "action": "use",
            "constraint": [{"leftOperand": "x", "operator": "isAnyOf", "rightOperand": ["a", "b"]}]
        }]}));
        assert!(is_marker(&policy.permissions[0].constraints[0]));
    }

    #[test]
    fn rule_without_a_readable_action_is_kept_with_a_marker() {
        let policy = parse_one_policy(json!({"prohibition": [
            {"constraint": [{"leftOperand": "a", "operator": "eq", "rightOperand": "b"}]},
            {"action": [1, 2]}
        ]}));
        assert_eq!(policy.prohibitions.len(), 2);
        for rule in &policy.prohibitions {
            assert!(rule.constraints.iter().any(is_marker), "{rule:?}");
        }
    }

    #[test]
    fn unreadable_assignee_is_kept_as_a_marker_rule() {
        let policy = parse_one_policy(json!({
            "assignee": {"unexpected": true},
            "permission": {"action": "use"}
        }));
        let marked = policy
            .permissions
            .iter()
            .chain(&policy.prohibitions)
            .chain(&policy.obligations)
            .any(|r| r.constraints.iter().any(is_marker));
        assert!(marked, "{policy:?}");
    }
}
