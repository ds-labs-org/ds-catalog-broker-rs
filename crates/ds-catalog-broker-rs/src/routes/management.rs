//! `POST /api/management/v4/catalogs/request`.
//!
//! This product's own federated catalog Management API surface. Its wire
//! format is not this project's to invent: it must match what the real,
//! already-published `edc-federated-catalog-client` crate
//! (<https://github.com/dataspace-rs/edc-federated-catalog-client>, pinned at
//! 0.2.5 as a *dev*-dependency below - see this crate's own Cargo.toml for
//! why not a normal one) actually sends and parses -
//! `FederatedCatalogClient::list_offers`/`get_offer_by_dataset_id` both
//! `POST {endpoint}/api/management/v4/catalogs/request` with a
//! `QuerySpec`-shaped body and expect a `Vec<FederatedCatalogOffer>` back
//! (see that crate's `src/lib.rs`). The response types just below
//! (`CatalogRequestOffer` and friends) are hand-written, field-for-field,
//! against that crate's `src/models/federated_catalog_offer.rs`,
//! `dataset.rs`, `service.rs`, and `participant_id.rs` - not derived from
//! them, since production code here doesn't depend on that crate at all
//! (only this crate's tests do, in `src/tests/management.rs`) - but proven wire-identical by those
//! same tests, which deserialize a real response body from this route with
//! the real client crate's own `FederatedCatalogOffer` type.

use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use catalog_core::{Catalog, Dataset, Policy, PolicyKind, Rule};
use rdf_store::CatalogQuery;
use serde::{Deserialize, Serialize};

use super::ErrorResponse;
use super::auth::check_oauth2_bearer;
use super::policy::{ServiceFiltering, filter_catalogs_by_policy};
use crate::AppState;

/// One offer, matching `edc-federated-catalog-client`'s
/// `models::FederatedCatalogOffer` exactly: `@id`/`@type` JSON-LD framing,
/// a `dcat:dataset` array (omitted, not emitted empty, when there are no
/// datasets - the real struct defaults it on deserialize either way), a
/// single required `dcat:service` (see `catalog_to_offer`'s doc comment
/// for why a catalog with no data services can't produce one of these at
/// all), a required `participantId` object, and a required `originator`
/// string.
#[derive(Debug, Serialize)]
pub(super) struct CatalogRequestOffer {
    #[serde(rename = "@id")]
    id: String,
    #[serde(rename = "@type")]
    r#type: String,
    #[serde(
        rename = "http://www.w3.org/ns/dcat#dataset",
        skip_serializing_if = "Vec::is_empty"
    )]
    dataset: Vec<CatalogRequestDataset>,
    #[serde(rename = "http://www.w3.org/ns/dcat#service")]
    service: CatalogRequestService,
    #[serde(rename = "participantId")]
    participant_id: CatalogRequestParticipantId,
    originator: String,
}

/// Matches `models::Dataset`. `has_policy` is always present (the real
/// struct has no `#[serde(default)]` on that field, so it's required on
/// the wire) and now carries this dataset's real, harvested
/// `catalog_core::Policy` entries, built by `dataset_to_offer` from
/// `catalog_core::Dataset.policies` - genuine ODRL data preserved from
/// what a crawled participant actually advertised, not the placeholder
/// this route used to emit unconditionally (`docs/gap-analysis-2026-08-27.md`
/// §3.4). It's an empty array, never omitted, when the harvested dataset
/// had no policies at all.
///
/// `title`/`description`/`version`/`creator`/`thumbnail`/`keywords` are the
/// optional descriptive fields sourced from `catalog_core::Dataset.properties`
/// (see `dataset_to_offer`) - each is omitted from the wire, not emitted
/// `null`/empty, when the source data doesn't have it, matching the real
/// struct's own `#[serde(default)]` on every one of these fields (so a
/// caller reading with that struct sees exactly `None`/`vec![]`, not a
/// spurious explicit null).
#[derive(Debug, Serialize)]
pub(super) struct CatalogRequestDataset {
    #[serde(rename = "@id")]
    id: String,
    #[serde(rename = "@type")]
    r#type: String,
    /// One `serde_json::Value` per `catalog_core::Policy`, built by
    /// `dataset_to_offer` via `policy_to_json` - hand-built JSON rather
    /// than the real `edc_connector_client::types::policy::Policy` type
    /// (see this struct's own doc comment for why: this route
    /// deliberately doesn't depend on that crate in production code) but
    /// shaped to satisfy every one of that type's required-field rules,
    /// so a real client deserializes it into a genuine `Policy`, not an
    /// approximation of one.
    #[serde(rename = "http://www.w3.org/ns/odrl/2/hasPolicy")]
    has_policy: Vec<serde_json::Value>,
    name: String,
    #[serde(rename = "contenttype")]
    content_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    creator: Option<CatalogRequestCreator>,
    #[serde(skip_serializing_if = "Option::is_none")]
    thumbnail: Option<CatalogRequestThumbnail>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    keywords: Vec<String>,
}

/// Matches `models::Creator` - both fields are required on the real struct
/// (no `#[serde(default)]` on either), so a `CatalogRequestCreator` is only
/// ever constructed with both filled in. See `dataset_to_offer`'s doc
/// comment for how `thumbnail` gets filled when the source data has no
/// creator-specific one of its own.
#[derive(Debug, Serialize)]
pub(super) struct CatalogRequestCreator {
    name: String,
    thumbnail: CatalogRequestThumbnail,
}

/// Matches `models::Thumbnail` - its one field, `resource`, is required
/// there (no `#[serde(default)]`).
#[derive(Debug, Serialize)]
pub(super) struct CatalogRequestThumbnail {
    resource: String,
}

/// Matches `models::Service` - all four fields required (`endpoint_description`
/// is a plain `String` there, not `Option<String>` like
/// `catalog_core::DataService::endpoint_description`, hence the
/// `unwrap_or_default` in `catalog_to_offer`).
#[derive(Debug, Serialize)]
pub(super) struct CatalogRequestService {
    #[serde(rename = "@id")]
    id: String,
    #[serde(rename = "@type")]
    r#type: String,
    #[serde(rename = "http://www.w3.org/ns/dcat#endpointDescription")]
    endpoint_description: String,
    #[serde(rename = "http://www.w3.org/ns/dcat#endpointURL")]
    endpoint_url: String,
}

/// Matches `models::ParticipantId`.
#[derive(Debug, Serialize)]
pub(super) struct CatalogRequestParticipantId {
    #[serde(rename = "@id")]
    id: String,
}

/// Converts one cached `catalog_core::Catalog` into the wire shape above -
/// `None` when `catalog.data_services` is empty. A `FederatedCatalogOffer`'s
/// `service` field is a single required `Service`, not `Option`/`Vec`, so
/// a catalog with zero data services simply cannot produce a valid offer;
/// `catalog_request_route` skips these and logs how many, rather than
/// fabricating a placeholder service. When one or more data services do
/// exist, the first (`data_services[0]`) is used.
///
/// Field mapping notes (everything not explicitly called out is a direct
/// copy):
/// - `participantId`/`originator`: `catalog.participant_id` when the crawl
///   recorded one (a DID, typically), else `catalog.origin_node`'s id - the
///   best identifier this product actually has for who this catalog came
///   from.
/// - dataset `name`/`contenttype`: `catalog_core::Dataset` has no separate
///   "name" or "content type" field, so `name` is `dataset.id` (the best
///   available stand-in) and `contenttype` is the first distribution's
///   format string, or an empty string when the dataset has none.
/// - dataset `title`/`description`/`version`/`creator`/`thumbnail`/
///   `keywords`: read back out of `dataset.properties` under the same keys
///   `crawler::collect_datasets_and_services` writes them under - see
///   `dataset_to_offer`'s own doc comment for the exact mapping, including
///   how `creator`/`keywords` are built up from flatter string properties.
pub(super) fn catalog_to_offer(catalog: &Catalog) -> Option<CatalogRequestOffer> {
    let data_service = catalog.data_services.first()?;
    let participant_id = catalog
        .participant_id
        .clone()
        .unwrap_or_else(|| catalog.origin_node.0.clone());

    Some(CatalogRequestOffer {
        id: catalog.id.clone(),
        r#type: "Catalog".to_string(),
        dataset: catalog.datasets.iter().map(dataset_to_offer).collect(),
        service: CatalogRequestService {
            id: data_service.id.clone(),
            r#type: "DataService".to_string(),
            endpoint_description: data_service
                .endpoint_description
                .clone()
                .unwrap_or_default(),
            endpoint_url: data_service.endpoint_url.clone(),
        },
        participant_id: CatalogRequestParticipantId {
            id: participant_id.clone(),
        },
        originator: participant_id,
    })
}

/// Builds one `hasPolicy` entry from a harvested `catalog_core::Policy`,
/// as a raw `serde_json::Value` (see `CatalogRequestDataset::has_policy`'s
/// doc comment for why this is hand-built JSON rather than the real
/// `edc_connector_client::types::policy::Policy` type).
///
/// Every key emitted here exists because the real struct requires it with
/// no `#[serde(default)]` (verified against
/// `edc-connector-client-next` 0.6.8's `src/types/policy.rs`); every key
/// omitted exists because the real struct marks it optional
/// (`Option` with `skip_serializing_if`, or a `Vec` with `#[serde(default)]`)
/// and this route follows its own established convention elsewhere in this
/// file of omitting rather than emitting empty/null placeholders:
///
/// - `@type` is always present - `Policy.kind` has no `#[serde(default)]`,
///   so it's required on the wire even though `PolicyKind` itself derives
///   `Default`.
/// - `@id` only when `Policy.id` is `Some`.
/// - `odrl:assigner`/`odrl:assignee` only when `Some` - and under exactly
///   those prefixed keys, not the plain `assigner`/`assignee` names, since
///   the real struct's `assigner`/`assignee` fields carry no plain
///   `#[serde(rename)]`, only `alias`es for the prefixed and full-IRI forms
///   (aliases apply only on *read*; emitting the plain name would silently
///   fail to round-trip through the real type).
/// - `permission`/`prohibition`/`obligation` arrays only when non-empty.
/// - each `Rule` -> `{"action": ..., "constraint": [...]}`, `action` always
///   present (required on the real `Permission`/`Prohibition`/`Obligation`
///   types), `constraint` only when non-empty.
/// - each atomic `Constraint` -> `{"leftOperand": ..., "operator": ...,
///   "rightOperand": ...}`, all three always present - the real
///   `AtomicConstraint` requires all three with no defaults. A `Logical`
///   `catalog_core::Constraint` (gap analysis §3.4 - `Constraint` now
///   models both shapes, see its own doc comment) is skipped here rather
///   than mis-emitted as if it were atomic: mapping a logical group to the
///   real client's own `MultiplicityConstraint` wire shape is separate,
///   not-yet-done work this route does not perform yet, and no current
///   producer constructs a `Logical` constraint in the first place.
pub(super) fn policy_to_json(policy: &Policy) -> serde_json::Value {
    let kind = match policy.kind {
        PolicyKind::Set => "Set",
        PolicyKind::Offer => "Offer",
        PolicyKind::Agreement => "Agreement",
    };
    let mut value = serde_json::json!({ "@type": kind });
    let object = value.as_object_mut().expect("built as a JSON object above");

    if let Some(id) = &policy.id {
        object.insert("@id".to_string(), serde_json::Value::String(id.clone()));
    }
    if let Some(assigner) = &policy.assigner {
        object.insert(
            "odrl:assigner".to_string(),
            serde_json::Value::String(assigner.clone()),
        );
    }
    if let Some(assignee) = &policy.assignee {
        object.insert(
            "odrl:assignee".to_string(),
            serde_json::Value::String(assignee.clone()),
        );
    }
    if !policy.permissions.is_empty() {
        object.insert(
            "permission".to_string(),
            serde_json::Value::Array(policy.permissions.iter().map(rule_to_json).collect()),
        );
    }
    if !policy.prohibitions.is_empty() {
        object.insert(
            "prohibition".to_string(),
            serde_json::Value::Array(policy.prohibitions.iter().map(rule_to_json).collect()),
        );
    }
    if !policy.obligations.is_empty() {
        object.insert(
            "obligation".to_string(),
            serde_json::Value::Array(policy.obligations.iter().map(rule_to_json).collect()),
        );
    }

    value
}

/// Builds one `permission`/`prohibition`/`obligation` entry from a
/// harvested `catalog_core::Rule` - see `policy_to_json`'s doc comment for
/// which keys are required vs. optional on the real side.
pub(super) fn rule_to_json(rule: &Rule) -> serde_json::Value {
    let mut value = serde_json::json!({ "action": rule.action });
    if !rule.constraints.is_empty() {
        value["constraint"] = serde_json::Value::Array(
            rule.constraints
                .iter()
                .filter_map(|constraint| match constraint {
                    catalog_core::Constraint::Atomic(atomic) => Some(serde_json::json!({
                        "leftOperand": atomic.left_operand,
                        "operator": atomic.operator,
                        "rightOperand": atomic.right_operand,
                    })),
                    catalog_core::Constraint::Logical(_) => None,
                })
                .collect(),
        );
    }
    value
}

/// Reads the optional descriptive properties `crawler::collect_datasets_and_services`
/// wrote into `dataset.properties` (`title`, `description`, `version`,
/// `creatorName`, `thumbnail`, `keywords`) back out and populates the
/// matching wire fields. Every one of them stays properly absent
/// (`None`/`vec![]`) when the source data doesn't have it - nothing here
/// invents a placeholder.
///
/// - `creator`: built only when a `creatorName` property is present. A
///   `Creator` requires both a `name` and a `thumbnail`
///   (`edc_federated_catalog_client::models::dataset::Creator`), but
///   `catalog_core::Dataset.properties` carries only one dataset-level
///   `thumbnail`, not a separate creator-specific one - so the creator's
///   `thumbnail` reuses the dataset's own `thumbnail` property value
///   (empty string when that's also absent, since `Creator::thumbnail` is
///   itself required and there is nothing else to put there). A defensible
///   simplification: real crawled data rarely distinguishes a dataset's
///   thumbnail from its creator's.
/// - `keywords`: the single comma-separated `keywords` property, split on
///   `,` with each entry trimmed; absent or empty -> an empty `Vec`,
///   matching the real struct's own `#[serde(default)]` on that field.
pub(super) fn dataset_to_offer(dataset: &Dataset) -> CatalogRequestDataset {
    let thumbnail_value = dataset.properties.get("thumbnail").cloned();
    let creator =
        dataset
            .properties
            .get("creatorName")
            .cloned()
            .map(|name| CatalogRequestCreator {
                name,
                thumbnail: CatalogRequestThumbnail {
                    resource: thumbnail_value.clone().unwrap_or_default(),
                },
            });
    let keywords = dataset
        .properties
        .get("keywords")
        .map(|raw| {
            raw.split(',')
                .map(str::trim)
                .filter(|entry| !entry.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();

    CatalogRequestDataset {
        id: dataset.id.clone(),
        r#type: "Dataset".to_string(),
        has_policy: dataset.policies.iter().map(policy_to_json).collect(),
        name: dataset.id.clone(),
        content_type: dataset
            .distributions
            .first()
            .map(|d| d.format.clone())
            .unwrap_or_default(),
        title: dataset.properties.get("title").cloned(),
        description: dataset.properties.get("description").cloned(),
        version: dataset.properties.get("version").cloned(),
        creator,
        thumbnail: thumbnail_value.map(|resource| CatalogRequestThumbnail { resource }),
        keywords,
    }
}

/// The `QuerySpec`-shaped request body `POST /api/management/v4/catalogs/request`
/// accepts, matching the real client's `ListOfferBody`
/// (`edc-federated-catalog-client::ListOfferBody`) closely enough to parse
/// what it sends - `@context`/`@type` are accepted but ignored (this route
/// has nothing to validate them against), and only `filterExpression` is
/// acted on. Deserialized leniently: a missing, empty, or entirely
/// malformed body all fall back to `Default` (no filter) rather than a 400
/// - see `catalog_request_route`'s doc comment for why.
#[derive(Debug, Deserialize, Default)]
pub(super) struct CatalogRequestBody {
    #[serde(rename = "filterExpression", default)]
    filter_expression: Vec<CatalogRequestConstraint>,
}

/// One `filterExpression` entry, matching the real client's private
/// `Constraint` shape (`{operandLeft, operator, operandRight}`) closely
/// enough to read it back - this route only ever recognizes one exact
/// shape of it, see `catalog_request_route`.
#[derive(Debug, Deserialize, Default)]
pub(super) struct CatalogRequestConstraint {
    #[serde(rename = "operandLeft", default)]
    operand_left: String,
    #[serde(default)]
    operator: String,
    #[serde(rename = "operandRight", default)]
    operand_right: String,
}

/// `POST /api/management/v4/catalogs/request` - see this section's module-
/// level comment above for the wire-compatibility contract this route
/// exists to satisfy.
///
/// Response: one offer per catalog currently in `state.cache`
/// (`state.cache.query(CatalogQuery::all())`, the same call `GET /catalog`
/// already uses), built by `catalog_to_offer` - catalogs with no data
/// services are skipped (logged once as a `tracing::warn!` with the
/// skipped count, not per-catalog) rather than erroring or fabricating a
/// service.
///
/// Request body: a `QuerySpec`-shaped JSON body (`CatalogRequestBody`) that
/// may carry a `filterExpression` array. The only constraint shape honored
/// is `operandLeft == "datasets.id"` with `operator == "="` - the exact
/// filter `get_offer_by_dataset_id` sends client-side - which narrows the
/// response to offers containing a dataset with that id. Any other/
/// unrecognized constraint, and a missing, empty, or malformed body
/// entirely, all mean the same thing: the full unfiltered offer list comes
/// back. A real client always sends *some* `QuerySpec` body, so being
/// lenient here matters more than being strict.
///
/// Gated by the same OAuth2 Bearer mechanism as `GET /catalog` and
/// `GET`/`POST /sparql` (`check_oauth2_bearer`) - this is another
/// catalog-listing surface, so gating it the same way is the consistent
/// choice. Unchanged/open when `state.oauth2` is `None`, exactly like
/// those two routes.
///
/// Also applies the same ODRL policy-based dataset-visibility filtering
/// as `GET /catalog` (`filter_catalogs_by_policy`, gap analysis §3.4),
/// *before* the `filterExpression` handling below - a caller not entitled
/// to a dataset under its harvested policy must not be able to retrieve
/// it merely by asking for it by id via `datasets.id`/`=`. An offer left
/// with zero visible datasets after policy filtering is kept, with an
/// empty `dataset` array, not omitted - consistent with this route's
/// existing "empty, not omitted" convention for `hasPolicy` on a
/// policy-free dataset.
pub(super) async fn catalog_request_route(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    let claims = match check_oauth2_bearer(&state, &headers) {
        Ok(claims) => claims,
        Err(response) => return *response,
    };

    let mut catalogs = match state.cache.query(CatalogQuery::all()).await {
        Ok(catalogs) => catalogs,
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: err.to_string(),
                }),
            )
                .into_response();
        }
    };
    filter_catalogs_by_policy(
        &mut catalogs,
        claims.as_ref(),
        &state,
        ServiceFiltering::KeepAll,
    );

    let mut skipped = 0usize;
    let mut offers: Vec<CatalogRequestOffer> = Vec::with_capacity(catalogs.len());
    for catalog in &catalogs {
        match catalog_to_offer(catalog) {
            Some(offer) => offers.push(offer),
            None => skipped += 1,
        }
    }
    if skipped > 0 {
        tracing::warn!(
            skipped,
            "skipped {skipped} catalog(s) with no data services in POST \
             /api/management/v4/catalogs/request: a FederatedCatalogOffer's 'service' field is \
             a single required Service, not Option/Vec, so a catalog with zero data services \
             cannot produce a valid offer"
        );
    }

    let filter = serde_json::from_slice::<CatalogRequestBody>(&body).unwrap_or_default();
    let dataset_id_filter = filter.filter_expression.iter().find_map(|constraint| {
        (constraint.operand_left == "datasets.id" && constraint.operator == "=")
            .then(|| constraint.operand_right.clone())
    });
    if let Some(dataset_id) = dataset_id_filter {
        offers.retain(|offer| offer.dataset.iter().any(|dataset| dataset.id == dataset_id));
    }

    Json(offers).into_response()
}
