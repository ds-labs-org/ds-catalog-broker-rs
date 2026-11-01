//! Runtime configuration, read from a Turtle file through `contreforts-config`'s
//! [`ConfigStore`] - see `docs/configuration.md` for the operator-facing reference and
//! `docs/examples/config_graph.ttl` for a complete example.
//!
//! # Where the settings live
//!
//! Every setting is one property on a single `broker:BrokerConfig` resource in the config
//! graph ([`CONFIG_GRAPH`]). `CONFIG_STORE_PATH` - the only environment variable in the
//! configuration path, since something has to say where the Turtle is - names it as one of:
//!
//! - **a plain path or a `file:///` URL to a directory**: a `contreforts-config` datadir, of
//!   which only `<dir>/config_graph.ttl` is read;
//! - **a plain path or a `file:///` URL to a file**: that Turtle document itself;
//! - **an `http://` or `https://` URL**: a Turtle document fetched once at startup. A non-2xx
//!   answer is an error, not an empty config. Relative IRIs in it resolve against the URL.
//!
//! Unset, the location is `contreforts-config`'s per-user default, `<os-data-dir>/config_store`.
//! No setting is read from the environment.
//!
//! # The crawler's participants and holder
//!
//! The participant registry and the crawler's holder identity are separate resources in the
//! same graph, linked from `broker:BrokerConfig` with `broker:participant` (any number) and
//! `broker:holder` (at most one); see [`BrokerSettings::crawler`]. They are read strictly: a
//! missing required property, a value that doesn't parse, or a link to a resource of the wrong
//! type stops the broker, unlike a bad scalar setting, which falls back to its default.
//!
//! # No config store at all is not an error
//!
//! When `CONFIG_STORE_PATH` is unset and the per-user default datadir holds no
//! `config_graph.ttl`, the broker starts with every setting unset (built-in defaults) - without
//! creating that directory. An explicit `CONFIG_STORE_PATH` that cannot be read *is* an error:
//! the operator asked for that file.
//!
//! # Read-only
//!
//! The broker never writes to its configuration. A datadir is read directly rather than
//! through [`ConfigStore::open`], which would create a missing directory and repair a corrupt
//! `config_graph.ttl` from its `.bak.N` backups - both writes - see
//! [`BrokerSettings::from_location`].

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;

use contreforts_config::{ConfigStore, ConfigStoreConfig, ConfigStoreError};
use contreforts_core::namespaces::CONFIG_GRAPH;
use crawler::{CredentialProtocol, HolderConfig, ParticipantEntry, ParticipantsConfig};
use oxigraph::io::{RdfFormat, RdfParser};
use oxigraph::model::vocab::rdf;
use oxigraph::model::{GraphName, GraphNameRef, NamedNode, NamedOrBlankNode, Term};
use oxigraph::store::Store;
use reqwest::Url;

/// This broker's configuration vocabulary. Every [`Setting::property`] is a local name in it.
pub const BROKER_NS: &str = "https://catalog-broker.ds-labs.org/ontologies/config#";

/// The file a `contreforts-config` datadir keeps its config graph in.
pub const CONFIG_GRAPH_FILE: &str = "config_graph.ttl";

/// `contreforts-config`'s own datadir override (private to that crate, so spelled again here).
pub const CONFIG_STORE_PATH_ENV: &str = "CONFIG_STORE_PATH";

/// One configuration setting: a property in [`BROKER_NS`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Setting {
    pub property: &'static str,
}

impl Setting {
    const fn new(property: &'static str) -> Self {
        Self { property }
    }

    /// The property's full IRI.
    pub fn iri(&self) -> String {
        format!("{BROKER_NS}{}", self.property)
    }
}

pub const HTTP_API_ADDR: Setting = Setting::new("httpApiAddr");
pub const CRAWL_INTERVAL_SECS: Setting = Setting::new("crawlIntervalSecs");
pub const CRAWL_TIMEOUT_MS: Setting = Setting::new("crawlTimeoutMs");
pub const CRAWL_CONCURRENCY: Setting = Setting::new("crawlConcurrency");
pub const CATALOG_MAX_AGE_SECS: Setting = Setting::new("catalogMaxAgeSecs");
pub const OAUTH2_JWKS_URI: Setting = Setting::new("oauth2JwksUri");
pub const OAUTH2_ISSUER: Setting = Setting::new("oauth2Issuer");
pub const OAUTH2_AUDIENCE: Setting = Setting::new("oauth2Audience");
pub const OAUTH2_REQUIRED_SCOPE: Setting = Setting::new("oauth2RequiredScope");
pub const SPARQL_QUERY_TIMEOUT_MS: Setting = Setting::new("sparqlQueryTimeoutMs");
pub const SPARQL_MAX_ROWS: Setting = Setting::new("sparqlMaxRows");
pub const POLICY_FILTER_UNMAPPABLE_CONSTRAINT_ACTION: Setting =
    Setting::new("policyFilterUnmappableConstraintAction");
pub const POLICY_FILTER_NO_POLICY_VISIBILITY: Setting =
    Setting::new("policyFilterNoPolicyVisibility");
pub const POLICY_FILTER_RUN_WHEN_OAUTH2_DISABLED: Setting =
    Setting::new("policyFilterRunWhenOauth2Disabled");

/// Every setting this broker reads, in `docs/configuration.md`'s order.
pub const ALL_SETTINGS: &[Setting] = &[
    HTTP_API_ADDR,
    CRAWL_INTERVAL_SECS,
    CRAWL_TIMEOUT_MS,
    CRAWL_CONCURRENCY,
    CATALOG_MAX_AGE_SECS,
    OAUTH2_JWKS_URI,
    OAUTH2_ISSUER,
    OAUTH2_AUDIENCE,
    OAUTH2_REQUIRED_SCOPE,
    SPARQL_QUERY_TIMEOUT_MS,
    SPARQL_MAX_ROWS,
    POLICY_FILTER_UNMAPPABLE_CONSTRAINT_ACTION,
    POLICY_FILTER_NO_POLICY_VISIBILITY,
    POLICY_FILTER_RUN_WHEN_OAUTH2_DISABLED,
];

/// The crawl interval when `broker:crawlIntervalSecs` is unset.
pub const DEFAULT_CRAWL_INTERVAL_SECS: u64 = 300;

/// `broker:BrokerConfig` -> `broker:Participant`, any number of times.
pub const PARTICIPANT_LINK: &str = "participant";
/// `broker:BrokerConfig` -> `broker:Holder`, at most once.
pub const HOLDER_LINK: &str = "holder";

/// The properties of a `broker:Participant`.
pub const PARTICIPANT_ID: &str = "participantId";
pub const PARTICIPANT_NAME: &str = "participantName";
pub const CATALOG_REQUEST_URL: &str = "catalogRequestUrl";
pub const CREDENTIAL_PROTOCOL: &str = "credentialProtocol";
pub const PROVIDER_DID: &str = "providerDid";
pub const OID4VP_RESPONSE_URI: &str = "oid4vpResponseUri";
const PARTICIPANT_PROPERTIES: &[&str] = &[
    PARTICIPANT_ID,
    PARTICIPANT_NAME,
    CATALOG_REQUEST_URL,
    CREDENTIAL_PROTOCOL,
    PROVIDER_DID,
    OID4VP_RESPONSE_URI,
];

/// The properties of the `broker:Holder`.
pub const OWN_DID_HOST: &str = "ownDidHost";
pub const INSECURE_HTTP: &str = "insecureHttp";
pub const CREDENTIAL_JWS_FILE: &str = "credentialJwsFile";
pub const REQUIRED_SCOPE: &str = "requiredScope";
const HOLDER_PROPERTIES: &[&str] = &[
    OWN_DID_HOST,
    INSECURE_HTTP,
    CREDENTIAL_JWS_FILE,
    REQUIRED_SCOPE,
];

#[derive(Debug, thiserror::Error)]
pub enum BrokerConfigError {
    #[error(transparent)]
    Store(#[from] ConfigStoreError),
    #[error("the config graph holds {0} broker:BrokerConfig resources; expected at most one")]
    MultipleConfigResources(usize),
    #[error("broker:{property} has {count} values on {resource}; expected one")]
    MultipleValues {
        resource: String,
        property: String,
        count: usize,
    },
    #[error("{resource} has no broker:{property}, which is required")]
    MissingProperty { resource: String, property: String },
    #[error("broker:{property} on {resource} is {value:?}: {reason}")]
    InvalidValue {
        resource: String,
        property: String,
        value: String,
        reason: String,
    },
    #[error("broker:{property} must point to a resource (an IRI or a blank node), not {value}")]
    NotAResource { property: String, value: String },
    #[error("{resource}, linked with broker:{property}, is not a broker:{expected}")]
    WrongType {
        resource: String,
        property: String,
        expected: String,
    },
    #[error("{resource} is a broker:{class}, but no broker:{property} links to it")]
    UnlinkedResource {
        resource: String,
        class: String,
        property: String,
    },
    #[error("invalid crawler configuration: {0}")]
    Crawler(#[from] crawler::ConfigError),
    #[error("{CONFIG_STORE_PATH_ENV}={0:?} is not a valid URL: {1}")]
    InvalidUrl(String, String),
    #[error(
        "{CONFIG_STORE_PATH_ENV}={0:?} uses an unsupported URL scheme (expected file, http or https)"
    )]
    UnsupportedScheme(String),
    #[error("failed to read {location}: {source}")]
    Read {
        location: String,
        source: std::io::Error,
    },
    #[error("failed to fetch {location}: {source}")]
    Fetch {
        location: String,
        source: reqwest::Error,
    },
    #[error("failed to parse the Turtle at {location}: {reason}")]
    Parse { location: String, reason: String },
    #[error("failed to query the config graph: {0}")]
    Query(String),
}

/// Where `CONFIG_STORE_PATH` points - see the module doc.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigLocation {
    /// A local directory (a `contreforts-config` datadir) or Turtle file.
    Local(PathBuf),
    /// An `http(s)://` Turtle document.
    Remote(Url),
}

impl ConfigLocation {
    /// Parse a `CONFIG_STORE_PATH` value. Anything without `://` is a plain path; `file://`
    /// URLs become paths; `http`/`https` stay URLs; any other scheme is rejected.
    pub fn parse(raw: &str) -> Result<Self, BrokerConfigError> {
        if !raw.contains("://") {
            return Ok(Self::Local(PathBuf::from(raw)));
        }
        let url = Url::parse(raw)
            .map_err(|err| BrokerConfigError::InvalidUrl(raw.to_string(), err.to_string()))?;
        match url.scheme() {
            "http" | "https" => Ok(Self::Remote(url)),
            "file" => url.to_file_path().map(Self::Local).map_err(|()| {
                BrokerConfigError::InvalidUrl(raw.to_string(), "not a local file path".to_string())
            }),
            _ => Err(BrokerConfigError::UnsupportedScheme(raw.to_string())),
        }
    }
}

impl std::fmt::Display for ConfigLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Local(path) => write!(f, "{}", path.display()),
            Self::Remote(url) => write!(f, "{url}"),
        }
    }
}

/// The settings read from the Turtle file, keyed by [`Setting::property`].
#[derive(Debug, Clone, Default)]
pub struct BrokerSettings {
    values: HashMap<String, String>,
    /// The participant registry and holder; `None` when the config lists no participant.
    crawler: Option<ParticipantsConfig>,
    /// Where the values came from. `None` when no config was read.
    source: Option<ConfigLocation>,
}

impl BrokerSettings {
    /// Resolve `CONFIG_STORE_PATH` (see the module doc) and read the config it names, if
    /// there is one. `http` is used only for an `http(s)://` location.
    pub async fn load(http: &reqwest::Client) -> Result<Self, BrokerConfigError> {
        let raw = std::env::var(CONFIG_STORE_PATH_ENV)
            .ok()
            .filter(|v| !v.is_empty());

        let location = match raw {
            Some(raw) => ConfigLocation::parse(&raw)?,
            None => match ConfigStoreConfig::per_user_default() {
                Ok(path) if path.join(CONFIG_GRAPH_FILE).is_file() => ConfigLocation::Local(path),
                Ok(path) => {
                    tracing::info!(
                        path = %path.display(),
                        "no config_graph.ttl in the default config store and \
                         {CONFIG_STORE_PATH_ENV} is unset; using built-in defaults"
                    );
                    return Ok(Self::default());
                }
                Err(err) => {
                    tracing::info!(
                        error = %err,
                        "no default config store location and {CONFIG_STORE_PATH_ENV} is unset; \
                         using built-in defaults"
                    );
                    return Ok(Self::default());
                }
            },
        };

        let mut settings = Self::from_location(&location, http).await?;
        tracing::info!(
            location = %location,
            settings = settings.values.len(),
            "loaded broker configuration"
        );
        settings.source = Some(location);
        Ok(settings)
    }

    /// Read the config at `location`: `<dir>/config_graph.ttl` for a datadir, a local Turtle
    /// file, or a remote Turtle document. Read-only in every case: a datadir is deliberately
    /// *not* opened with [`ConfigStore::open`], which creates a missing directory and rewrites a
    /// corrupt `config_graph.ttl` from its `.bak.N` backups. A missing or unparsable file is an
    /// error instead.
    pub async fn from_location(
        location: &ConfigLocation,
        http: &reqwest::Client,
    ) -> Result<Self, BrokerConfigError> {
        match location {
            ConfigLocation::Local(path) => {
                let file = if path.is_dir() {
                    path.join(CONFIG_GRAPH_FILE)
                } else {
                    path.clone()
                };
                let turtle = std::fs::read(&file).map_err(|source| BrokerConfigError::Read {
                    location: file.display().to_string(),
                    source,
                })?;
                let base = std::path::absolute(&file)
                    .ok()
                    .and_then(|abs| Url::from_file_path(abs).ok());
                Self::from_turtle(
                    &turtle,
                    base.as_ref().map(Url::as_str),
                    &file.display().to_string(),
                )
            }
            ConfigLocation::Remote(url) => {
                let fetch = |source| BrokerConfigError::Fetch {
                    location: location.to_string(),
                    source,
                };
                let turtle = http
                    .get(url.clone())
                    .header(reqwest::header::ACCEPT, "text/turtle")
                    .send()
                    .await
                    .and_then(reqwest::Response::error_for_status)
                    .map_err(fetch)?
                    .bytes()
                    .await
                    .map_err(fetch)?;
                Self::from_turtle(&turtle, Some(url.as_str()), &location.to_string())
            }
        }
    }

    /// Read a standalone Turtle document as the config graph.
    pub fn from_turtle(
        turtle: &[u8],
        base_iri: Option<&str>,
        location: &str,
    ) -> Result<Self, BrokerConfigError> {
        let parse = |reason: String| BrokerConfigError::Parse {
            location: location.to_string(),
            reason,
        };
        let store = Store::new().map_err(|err| parse(err.to_string()))?;
        let graph = NamedNode::new(CONFIG_GRAPH).expect("CONFIG_GRAPH is a valid IRI");
        let mut parser = RdfParser::from_format(RdfFormat::Turtle)
            .with_default_graph(GraphName::NamedNode(graph));
        if let Some(base) = base_iri {
            parser = parser
                .with_base_iri(base)
                .map_err(|err| parse(err.to_string()))?;
        }
        store
            .load_from_slice(parser, turtle)
            .map_err(|err| parse(err.to_string()))?;
        Self::from_graph(&store)
    }

    /// Read the `broker:BrokerConfig` resource from a `contreforts-config` store.
    pub fn from_store(store: &ConfigStore) -> Result<Self, BrokerConfigError> {
        Self::from_graph(store.inner())
    }

    /// Read the `broker:BrokerConfig` resource, and the participants and holder it links to,
    /// from `store`'s [`CONFIG_GRAPH`].
    fn from_graph(store: &Store) -> Result<Self, BrokerConfigError> {
        let graph = ConfigGraph::new(store);
        let mut configs = graph.subjects_of_type("BrokerConfig")?;
        if configs.len() > 1 {
            return Err(BrokerConfigError::MultipleConfigResources(configs.len()));
        }
        let Some(config) = configs.pop() else {
            return Ok(Self::default());
        };

        let resource = "the broker:BrokerConfig resource".to_string();
        let mut properties = graph.properties(&config)?;
        let participants = properties.remove(PARTICIPANT_LINK).unwrap_or_default();
        let holders = properties.remove(HOLDER_LINK).unwrap_or_default();
        let values = single_values(&resource, properties)?
            .into_iter()
            .map(|(property, term)| (property, term_value(&term)));
        let mut settings = Self::from_values(values);
        settings.crawler = settings.read_crawler(&graph, &resource, participants, holders)?;
        Ok(settings)
    }

    /// Build the crawler config from the resources `broker:BrokerConfig` links to. `None` when
    /// it lists no participant: there is nothing to crawl.
    fn read_crawler(
        &self,
        graph: &ConfigGraph<'_>,
        resource: &str,
        participants: Vec<Term>,
        holders: Vec<Term>,
    ) -> Result<Option<ParticipantsConfig>, BrokerConfigError> {
        if holders.len() > 1 {
            return Err(BrokerConfigError::MultipleValues {
                resource: resource.to_string(),
                property: HOLDER_LINK.to_string(),
                count: holders.len(),
            });
        }
        if participants.is_empty() {
            if !holders.is_empty() || self.get(CRAWL_INTERVAL_SECS).is_some() {
                tracing::warn!(
                    "broker:holder or broker:crawlIntervalSecs is set but no broker:participant \
                     is; the crawler stays off"
                );
            }
            return Ok(None);
        }

        let holder = match holders.into_iter().next() {
            Some(term) => Some(read_holder(
                graph,
                &linked(graph, term, HOLDER_LINK, "Holder")?,
            )?),
            None => None,
        };
        let mut entries = participants
            .into_iter()
            .map(|term| {
                let node = linked(graph, term, PARTICIPANT_LINK, "Participant")?;
                read_participant(graph, &node)
            })
            .collect::<Result<Vec<_>, _>>()?;
        // The graph has no order; sort so logs and crawl order are stable.
        entries.sort_by(|a, b| a.id.cmp(&b.id));

        let interval_secs = self
            .positive_integer(CRAWL_INTERVAL_SECS)
            .map_or(DEFAULT_CRAWL_INTERVAL_SECS, |secs| secs as u64);
        Ok(Some(ParticipantsConfig::new(
            interval_secs,
            entries,
            holder,
        )?))
    }

    /// Build from already-read values, keyed by [`Setting::property`]. Warns about any
    /// property this broker doesn't know - a typo'd property should be visible in the logs,
    /// not silently ignored.
    pub fn from_values(values: impl IntoIterator<Item = (String, String)>) -> Self {
        let values: HashMap<String, String> = values.into_iter().collect();
        for property in values.keys() {
            if !ALL_SETTINGS.iter().any(|s| s.property == property) {
                tracing::warn!(
                    property,
                    "unknown broker:{property} in the config graph; ignored"
                );
            }
        }
        Self {
            values,
            crawler: None,
            source: None,
        }
    }

    /// The participant registry and holder identity, or `None` when the config lists no
    /// `broker:participant` - see the module doc.
    pub fn crawler(&self) -> Option<&ParticipantsConfig> {
        self.crawler.as_ref()
    }

    /// `setting`'s value, or `None` when the config graph doesn't set it.
    pub fn get(&self, setting: Setting) -> Option<String> {
        self.values.get(setting.property).cloned()
    }

    /// `setting` as a positive integer; `None` when unset, or (with a warning) when it is not
    /// one.
    pub fn positive_integer(&self, setting: Setting) -> Option<usize> {
        let value = self.get(setting)?;
        match value.trim().parse::<usize>() {
            Ok(parsed) if parsed > 0 => Some(parsed),
            _ => {
                tracing::warn!(
                    property = setting.property,
                    value,
                    "expected a positive integer; falling back to the default"
                );
                None
            }
        }
    }

    /// Where the values were read from, if anywhere.
    pub fn source(&self) -> Option<&ConfigLocation> {
        self.source.as_ref()
    }
}

/// Read access to the triples of the config graph.
struct ConfigGraph<'a> {
    store: &'a Store,
    graph: NamedNode,
}

impl<'a> ConfigGraph<'a> {
    fn new(store: &'a Store) -> Self {
        Self {
            store,
            graph: NamedNode::new(CONFIG_GRAPH).expect("CONFIG_GRAPH is a valid IRI"),
        }
    }

    fn graph_name(&self) -> GraphNameRef<'_> {
        GraphNameRef::NamedNode(self.graph.as_ref())
    }

    /// Every subject typed `broker:<class>`.
    fn subjects_of_type(&self, class: &str) -> Result<Vec<NamedOrBlankNode>, BrokerConfigError> {
        let class = broker_node(class);
        self.store
            .quads_for_pattern(
                None,
                Some(rdf::TYPE),
                Some(class.as_ref().into()),
                Some(self.graph_name()),
            )
            .map(|quad| {
                quad.map(|quad| quad.subject)
                    .map_err(|err| BrokerConfigError::Query(err.to_string()))
            })
            .collect()
    }

    fn has_type(&self, subject: &NamedOrBlankNode, class: &str) -> Result<bool, BrokerConfigError> {
        let class = broker_node(class);
        match self
            .store
            .quads_for_pattern(
                Some(subject.as_ref()),
                Some(rdf::TYPE),
                Some(class.as_ref().into()),
                Some(self.graph_name()),
            )
            .next()
        {
            Some(Err(err)) => Err(BrokerConfigError::Query(err.to_string())),
            found => Ok(found.is_some()),
        }
    }

    /// `subject`'s `broker:` properties, keyed by local name, with every value of each.
    fn properties(
        &self,
        subject: &NamedOrBlankNode,
    ) -> Result<BTreeMap<String, Vec<Term>>, BrokerConfigError> {
        let mut found: BTreeMap<String, Vec<Term>> = BTreeMap::new();
        for quad in self.store.quads_for_pattern(
            Some(subject.as_ref()),
            None,
            None,
            Some(self.graph_name()),
        ) {
            let quad = quad.map_err(|err| BrokerConfigError::Query(err.to_string()))?;
            if let Some(local) = quad.predicate.as_str().strip_prefix(BROKER_NS) {
                found
                    .entry(local.to_string())
                    .or_default()
                    .push(quad.object);
            }
        }
        Ok(found)
    }
}

fn broker_node(local: &str) -> NamedNode {
    NamedNode::new(format!("{BROKER_NS}{local}")).expect("broker: IRIs are valid")
}

/// A term's value as a setting string: a literal's lexical form, an IRI's text.
fn term_value(term: &Term) -> String {
    match term {
        Term::Literal(literal) => literal.value().to_string(),
        Term::NamedNode(node) => node.as_str().to_string(),
        other => other.to_string(),
    }
}

/// How a resource is named in an error message.
fn describe(node: &NamedOrBlankNode) -> String {
    match node {
        NamedOrBlankNode::NamedNode(node) => format!("<{}>", node.as_str()),
        NamedOrBlankNode::BlankNode(_) => "a blank node".to_string(),
    }
}

/// Reject any property with more than one value.
fn single_values(
    resource: &str,
    properties: BTreeMap<String, Vec<Term>>,
) -> Result<BTreeMap<String, Term>, BrokerConfigError> {
    properties
        .into_iter()
        .map(|(property, mut terms)| {
            if terms.len() > 1 {
                return Err(BrokerConfigError::MultipleValues {
                    resource: resource.to_string(),
                    property,
                    count: terms.len(),
                });
            }
            Ok((property, terms.pop().expect("one value")))
        })
        .collect()
}

/// The resource a `broker:<property>` link points to, checked to be a `broker:<class>`.
fn linked(
    graph: &ConfigGraph<'_>,
    term: Term,
    property: &str,
    class: &str,
) -> Result<NamedOrBlankNode, BrokerConfigError> {
    let node = match term {
        Term::NamedNode(node) => NamedOrBlankNode::NamedNode(node),
        Term::BlankNode(node) => NamedOrBlankNode::BlankNode(node),
        other => {
            return Err(BrokerConfigError::NotAResource {
                property: property.to_string(),
                value: other.to_string(),
            });
        }
    };
    if !graph.has_type(&node, class)? {
        return Err(BrokerConfigError::WrongType {
            resource: describe(&node),
            property: property.to_string(),
            expected: class.to_string(),
        });
    }
    Ok(node)
}

/// A resource's single-valued `broker:` properties as strings, warning about unknown ones.
struct Properties {
    resource: String,
    values: BTreeMap<String, String>,
}

impl Properties {
    fn read(
        graph: &ConfigGraph<'_>,
        node: &NamedOrBlankNode,
        class: &str,
        known: &[&str],
    ) -> Result<Self, BrokerConfigError> {
        let resource = format!("broker:{class} {}", describe(node));
        let values: BTreeMap<String, String> = single_values(&resource, graph.properties(node)?)?
            .into_iter()
            .map(|(property, term)| (property, term_value(&term)))
            .collect();
        for property in values.keys() {
            if !known.contains(&property.as_str()) {
                tracing::warn!(
                    property,
                    resource,
                    "unknown broker:{property} on {resource}; ignored"
                );
            }
        }
        Ok(Self { resource, values })
    }

    fn optional(&self, property: &str) -> Option<String> {
        self.values.get(property).cloned()
    }

    fn required(&self, property: &str) -> Result<String, BrokerConfigError> {
        self.optional(property)
            .ok_or_else(|| BrokerConfigError::MissingProperty {
                resource: self.resource.clone(),
                property: property.to_string(),
            })
    }

    fn invalid(&self, property: &str, value: String, reason: String) -> BrokerConfigError {
        BrokerConfigError::InvalidValue {
            resource: self.resource.clone(),
            property: property.to_string(),
            value,
            reason,
        }
    }
}

fn read_participant(
    graph: &ConfigGraph<'_>,
    node: &NamedOrBlankNode,
) -> Result<ParticipantEntry, BrokerConfigError> {
    let props = Properties::read(graph, node, "Participant", PARTICIPANT_PROPERTIES)?;
    let credential_protocol = match props.optional(CREDENTIAL_PROTOCOL) {
        Some(raw) => raw
            .parse::<CredentialProtocol>()
            .map_err(|err| props.invalid(CREDENTIAL_PROTOCOL, raw, err.to_string()))?,
        None => CredentialProtocol::None,
    };
    Ok(ParticipantEntry {
        id: props.required(PARTICIPANT_ID)?,
        name: props.required(PARTICIPANT_NAME)?,
        catalog_request_url: props.required(CATALOG_REQUEST_URL)?,
        credential_protocol,
        provider_did: props.optional(PROVIDER_DID),
        oid4vp_response_uri: props.optional(OID4VP_RESPONSE_URI),
    })
}

fn read_holder(
    graph: &ConfigGraph<'_>,
    node: &NamedOrBlankNode,
) -> Result<HolderConfig, BrokerConfigError> {
    let props = Properties::read(graph, node, "Holder", HOLDER_PROPERTIES)?;
    let insecure_http = match props.optional(INSECURE_HTTP) {
        None => false,
        Some(raw) => match raw.trim() {
            "true" | "1" => true,
            "false" | "0" => false,
            _ => return Err(props.invalid(INSECURE_HTTP, raw, "expected a boolean".to_string())),
        },
    };
    // A `<file:...>` IRI (which a relative `<holder.jws>` resolves to, against the config
    // file's own location) or a plain path string.
    let raw_file = props.required(CREDENTIAL_JWS_FILE)?;
    let credential_jws_file = if raw_file.starts_with("file:") {
        Url::parse(&raw_file)
            .ok()
            .and_then(|url| url.to_file_path().ok())
            .ok_or_else(|| {
                props.invalid(
                    CREDENTIAL_JWS_FILE,
                    raw_file.clone(),
                    "not a local file path".to_string(),
                )
            })?
    } else if raw_file.contains("://") {
        return Err(props.invalid(
            CREDENTIAL_JWS_FILE,
            raw_file,
            "the credential must be a local file".to_string(),
        ));
    } else {
        PathBuf::from(raw_file)
    };
    Ok(HolderConfig {
        own_did_host: props.required(OWN_DID_HOST)?,
        insecure_http,
        credential_jws_file,
        required_scope: props.required(REQUIRED_SCOPE)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store_with(ttl: &str) -> (tempfile::TempDir, ConfigStore) {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("config_graph.ttl"), ttl).unwrap();
        let store = ConfigStore::open(dir.path()).unwrap();
        (dir, store)
    }

    #[test]
    fn reads_every_setting_from_the_example_ttl() {
        let example = include_str!("../../../docs/examples/config_graph.ttl");
        let (_dir, store) = store_with(example);
        let settings = BrokerSettings::from_store(&store).unwrap();
        for setting in ALL_SETTINGS {
            assert!(
                settings.get(*setting).is_some(),
                "docs/examples/config_graph.ttl is missing broker:{}",
                setting.property
            );
        }
        assert_eq!(
            settings.get(HTTP_API_ADDR).as_deref(),
            Some("127.0.0.1:8080")
        );
        assert_eq!(settings.positive_integer(SPARQL_MAX_ROWS), Some(10_000));
        assert_eq!(settings.positive_integer(CRAWL_CONCURRENCY), Some(8));
        assert_eq!(
            settings
                .get(POLICY_FILTER_RUN_WHEN_OAUTH2_DISABLED)
                .as_deref(),
            Some("true")
        );

        let crawler = settings.crawler().expect("the example lists participants");
        assert_eq!(crawler.interval_secs, 300);
        let ids: Vec<_> = crawler.participants.iter().map(|p| p.id.as_str()).collect();
        assert_eq!(
            ids,
            [
                "gated-participant",
                "oid4vp-gated-participant",
                "participant-a"
            ]
        );
        let dcp = &crawler.participants[0];
        assert_eq!(dcp.credential_protocol, CredentialProtocol::Dcp);
        assert_eq!(
            dcp.provider_did.as_deref(),
            Some("did:web:localhost%3A19002:dsp")
        );
        let oid4vp = &crawler.participants[1];
        assert_eq!(oid4vp.credential_protocol, CredentialProtocol::Oid4Vp);
        assert_eq!(
            oid4vp.oid4vp_response_uri.as_deref(),
            Some("http://127.0.0.1:19003/oid4vp/response")
        );
        let open = &crawler.participants[2];
        assert_eq!(open.name, "Participant A");
        assert_eq!(open.credential_protocol, CredentialProtocol::None);
        let holder = crawler.holder.as_ref().expect("the example has a holder");
        assert_eq!(holder.own_did_host, "localhost:19100");
        assert!(holder.insecure_http);
        assert_eq!(
            holder.credential_jws_file,
            PathBuf::from("/etc/ds-catalog-broker/holder-credential.jws")
        );
    }

    const PREFIX: &str =
        "@prefix broker: <https://catalog-broker.ds-labs.org/ontologies/config#> .\n";

    fn crawler_from(ttl: &str) -> Result<Option<ParticipantsConfig>, BrokerConfigError> {
        BrokerSettings::from_turtle(format!("{PREFIX}{ttl}").as_bytes(), None, "test")
            .map(|settings| settings.crawler().cloned())
    }

    const OPEN_PARTICIPANT: &str = "<urn:p> a broker:Participant ; broker:participantId \"p\" ; \
         broker:participantName \"P\" ; broker:catalogRequestUrl \"http://127.0.0.1:1/c\" .\n";

    #[test]
    fn no_participant_means_no_crawler() {
        let crawler =
            crawler_from("<urn:c> a broker:BrokerConfig ; broker:crawlIntervalSecs 5 .\n").unwrap();
        assert!(crawler.is_none());
    }

    #[test]
    fn reads_a_participant_with_the_default_interval_and_no_holder() {
        let crawler = crawler_from(&format!(
            "<urn:c> a broker:BrokerConfig ; broker:participant <urn:p> .\n{OPEN_PARTICIPANT}"
        ))
        .unwrap()
        .unwrap();
        assert_eq!(crawler.interval_secs, DEFAULT_CRAWL_INTERVAL_SECS);
        assert_eq!(crawler.participants.len(), 1);
        assert_eq!(crawler.participants[0].id, "p");
        assert!(crawler.holder.is_none());
    }

    #[test]
    fn reads_blank_node_participants_and_holder() {
        let crawler = crawler_from(
            "<urn:c> a broker:BrokerConfig ; broker:crawlIntervalSecs 5 ;\n\
             broker:participant [ a broker:Participant ; broker:participantId \"p\" ;\n\
               broker:participantName \"P\" ; broker:catalogRequestUrl \"http://h/c\" ;\n\
               broker:credentialProtocol \"dcp\" ; broker:providerDid \"did:web:h\" ] ;\n\
             broker:holder [ a broker:Holder ; broker:ownDidHost \"h\" ;\n\
               broker:credentialJwsFile <file:///run/secrets/holder.jws> ;\n\
               broker:requiredScope \"s\" ] .\n",
        )
        .unwrap()
        .unwrap();
        assert_eq!(crawler.interval_secs, 5);
        assert_eq!(
            crawler.participants[0].credential_protocol,
            CredentialProtocol::Dcp
        );
        let holder = crawler.holder.unwrap();
        assert!(!holder.insecure_http);
        assert_eq!(
            holder.credential_jws_file,
            PathBuf::from("/run/secrets/holder.jws")
        );
    }

    #[test]
    fn a_missing_required_participant_property_is_an_error() {
        let err = crawler_from(
            "<urn:c> a broker:BrokerConfig ; broker:participant <urn:p> .\n\
             <urn:p> a broker:Participant ; broker:participantId \"p\" ;\n\
               broker:participantName \"P\" .\n",
        )
        .unwrap_err();
        assert!(
            matches!(&err, BrokerConfigError::MissingProperty { property, .. } if property == CATALOG_REQUEST_URL),
            "{err}"
        );
    }

    #[test]
    fn a_link_to_an_untyped_resource_is_an_error() {
        let err = crawler_from(
            "<urn:c> a broker:BrokerConfig ; broker:participant <urn:p> .\n\
             <urn:p> broker:participantId \"p\" .\n",
        )
        .unwrap_err();
        assert!(matches!(err, BrokerConfigError::WrongType { .. }), "{err}");
    }

    #[test]
    fn a_literal_participant_link_is_an_error() {
        let err = crawler_from("<urn:c> a broker:BrokerConfig ; broker:participant \"p\" .\n")
            .unwrap_err();
        assert!(
            matches!(err, BrokerConfigError::NotAResource { .. }),
            "{err}"
        );
    }

    #[test]
    fn an_unknown_credential_protocol_is_an_error() {
        let err = crawler_from(
            "<urn:c> a broker:BrokerConfig ; broker:participant <urn:p> .\n\
             <urn:p> a broker:Participant ; broker:participantId \"p\" ;\n\
               broker:participantName \"P\" ; broker:catalogRequestUrl \"http://h/c\" ;\n\
               broker:credentialProtocol \"oauth\" .\n",
        )
        .unwrap_err();
        assert!(
            matches!(&err, BrokerConfigError::InvalidValue { property, .. } if property == CREDENTIAL_PROTOCOL),
            "{err}"
        );
    }

    #[test]
    fn a_gated_participant_without_a_holder_is_an_error() {
        let err = crawler_from(
            "<urn:c> a broker:BrokerConfig ; broker:participant <urn:p> .\n\
             <urn:p> a broker:Participant ; broker:participantId \"p\" ;\n\
               broker:participantName \"P\" ; broker:catalogRequestUrl \"http://h/c\" ;\n\
               broker:credentialProtocol \"dcp\" ; broker:providerDid \"did:web:h\" .\n",
        )
        .unwrap_err();
        assert!(
            matches!(
                err,
                BrokerConfigError::Crawler(crawler::ConfigError::MissingHolder { .. })
            ),
            "{err}"
        );
    }

    #[test]
    fn two_holders_are_an_error() {
        let err = crawler_from(&format!(
            "<urn:c> a broker:BrokerConfig ; broker:participant <urn:p> ;\n\
               broker:holder <urn:h1>, <urn:h2> .\n{OPEN_PARTICIPANT}"
        ))
        .unwrap_err();
        assert!(
            matches!(&err, BrokerConfigError::MultipleValues { property, .. } if property == HOLDER_LINK),
            "{err}"
        );
    }

    #[test]
    fn a_remote_credential_file_is_an_error() {
        let err = crawler_from(&format!(
            "<urn:c> a broker:BrokerConfig ; broker:participant <urn:p> ; broker:holder <urn:h> .\n\
             <urn:h> a broker:Holder ; broker:ownDidHost \"h\" ; broker:requiredScope \"s\" ;\n\
               broker:credentialJwsFile <https://example.org/holder.jws> .\n{OPEN_PARTICIPANT}"
        ))
        .unwrap_err();
        assert!(
            matches!(&err, BrokerConfigError::InvalidValue { property, .. } if property == CREDENTIAL_JWS_FILE),
            "{err}"
        );
    }

    #[test]
    fn a_relative_credential_file_iri_resolves_against_the_config_location() {
        let ttl = format!(
            "{PREFIX}<urn:c> a broker:BrokerConfig ; broker:participant <urn:p> ; broker:holder <urn:h> .\n\
             <urn:h> a broker:Holder ; broker:ownDidHost \"h\" ; broker:requiredScope \"s\" ;\n\
               broker:credentialJwsFile <holder.jws> .\n{OPEN_PARTICIPANT}"
        );
        let settings = BrokerSettings::from_turtle(
            ttl.as_bytes(),
            Some("file:///etc/broker/broker.ttl"),
            "test",
        )
        .unwrap();
        let holder = settings.crawler().unwrap().holder.as_ref().unwrap();
        assert_eq!(
            holder.credential_jws_file,
            PathBuf::from("/etc/broker/holder.jws")
        );
    }

    fn holder_with_file(file: &str) -> String {
        format!(
            "<urn:c> a broker:BrokerConfig ; broker:participant <urn:p> ; broker:holder <urn:h> .\n\
             <urn:h> a broker:Holder ; broker:ownDidHost \"h\" ; broker:requiredScope \"s\" ;\n\
               broker:credentialJwsFile {file} .\n{OPEN_PARTICIPANT}"
        )
    }

    #[test]
    fn an_unlinked_participant_is_an_error() {
        let err = crawler_from(&format!(
            "<urn:c> a broker:BrokerConfig ; broker:httpApiAddr \"x\" .\n{OPEN_PARTICIPANT}"
        ))
        .unwrap_err();
        assert!(
            matches!(&err, BrokerConfigError::UnlinkedResource { class, .. } if class == "Participant"),
            "{err}"
        );
    }

    #[test]
    fn an_unlinked_holder_is_an_error() {
        let err = crawler_from(&format!(
            "<urn:c> a broker:BrokerConfig ; broker:participant <urn:p> .\n\
             <urn:h> a broker:Holder ; broker:ownDidHost \"h\" .\n{OPEN_PARTICIPANT}"
        ))
        .unwrap_err();
        assert!(
            matches!(&err, BrokerConfigError::UnlinkedResource { class, .. } if class == "Holder"),
            "{err}"
        );
    }

    #[test]
    fn errors_on_a_blank_node_participant_name_its_id() {
        let err = crawler_from(
            "<urn:c> a broker:BrokerConfig ; broker:participant [ a broker:Participant ;\n\
               broker:participantId \"second\" ; broker:participantName \"P\" ] .\n",
        )
        .unwrap_err();
        assert!(err.to_string().contains("\"second\""), "{err}");
    }

    #[test]
    fn a_credential_file_that_is_not_a_path_is_an_error() {
        for file in ["<urn:secret>", "[]", "\"\""] {
            let ttl = holder_with_file(file);
            let err = crawler_from(&ttl).unwrap_err();
            assert!(
                matches!(&err, BrokerConfigError::InvalidValue { property, .. } if property == CREDENTIAL_JWS_FILE),
                "{file}: {err}"
            );
        }
    }

    #[test]
    fn a_credential_file_url_literal_is_read_whatever_its_case() {
        let crawler = crawler_from(&holder_with_file("\"FILE:///etc/h.jws\""))
            .unwrap()
            .unwrap();
        assert_eq!(
            crawler.holder.unwrap().credential_jws_file,
            PathBuf::from("/etc/h.jws")
        );
    }

    #[test]
    fn a_non_literal_string_property_is_an_error() {
        let err = crawler_from(
            "<urn:c> a broker:BrokerConfig ; broker:participant <urn:p> .\n\
             <urn:p> a broker:Participant ; broker:participantId [] ;\n\
               broker:participantName \"P\" ; broker:catalogRequestUrl \"http://h/c\" .\n",
        )
        .unwrap_err();
        assert!(
            matches!(&err, BrokerConfigError::InvalidValue { property, .. } if property == PARTICIPANT_ID),
            "{err}"
        );
    }

    #[test]
    fn endpoint_urls_may_be_iris() {
        let crawler = crawler_from(
            "<urn:c> a broker:BrokerConfig ; broker:participant <urn:p> .\n\
             <urn:p> a broker:Participant ; broker:participantId \"p\" ;\n\
               broker:participantName \"P\" ; broker:catalogRequestUrl <http://h/c> .\n",
        )
        .unwrap()
        .unwrap();
        assert_eq!(crawler.participants[0].catalog_request_url, "http://h/c");
    }

    #[test]
    fn unknown_properties_are_ignored_even_with_several_values() {
        let crawler = crawler_from(
            "<urn:c> a broker:BrokerConfig ; broker:tag \"a\", \"b\" ; broker:participant <urn:p> .\n\
             <urn:p> a broker:Participant ; broker:participantId \"p\" ; broker:tag \"a\", \"b\" ;\n\
               broker:participantName \"P\" ; broker:catalogRequestUrl \"http://h/c\" .\n",
        )
        .unwrap()
        .unwrap();
        assert_eq!(crawler.participants[0].id, "p");
    }

    #[test]
    fn unset_properties_are_none() {
        let (_dir, store) = store_with(&format!(
            "@prefix broker: <{BROKER_NS}> .\n\
             <urn:broker> a broker:BrokerConfig ; broker:httpApiAddr \"0.0.0.0:9000\" .\n"
        ));
        let settings = BrokerSettings::from_store(&store).unwrap();
        assert_eq!(settings.get(HTTP_API_ADDR).as_deref(), Some("0.0.0.0:9000"));
        assert_eq!(settings.get(OAUTH2_JWKS_URI), None);
    }

    #[test]
    fn an_empty_store_sets_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let store = ConfigStore::open(dir.path()).unwrap();
        let settings = BrokerSettings::from_store(&store).unwrap();
        assert!(ALL_SETTINGS.iter().all(|s| settings.get(*s).is_none()));
    }

    #[test]
    fn triples_on_other_subjects_are_ignored() {
        let (_dir, store) = store_with(&format!(
            "@prefix broker: <{BROKER_NS}> .\n\
             <urn:not-a-config> broker:httpApiAddr \"0.0.0.0:9000\" .\n"
        ));
        let settings = BrokerSettings::from_store(&store).unwrap();
        assert_eq!(settings.get(HTTP_API_ADDR), None);
    }

    #[test]
    fn two_config_resources_are_rejected() {
        let (_dir, store) = store_with(&format!(
            "@prefix broker: <{BROKER_NS}> .\n\
             <urn:a> a broker:BrokerConfig ; broker:httpApiAddr \"a\" .\n\
             <urn:b> a broker:BrokerConfig ; broker:httpApiAddr \"b\" .\n"
        ));
        assert!(matches!(
            BrokerSettings::from_store(&store),
            Err(BrokerConfigError::MultipleConfigResources(2))
        ));
    }

    #[test]
    fn two_values_for_one_property_are_rejected() {
        let (_dir, store) = store_with(&format!(
            "@prefix broker: <{BROKER_NS}> .\n\
             <urn:a> a broker:BrokerConfig ; broker:sparqlMaxRows 1, 2 .\n"
        ));
        assert!(matches!(
            BrokerSettings::from_store(&store),
            Err(BrokerConfigError::MultipleValues { .. })
        ));
    }

    #[test]
    fn non_positive_integers_fall_back() {
        let settings = BrokerSettings::from_values([
            ("sparqlMaxRows".to_string(), "0".to_string()),
            ("sparqlQueryTimeoutMs".to_string(), "soon".to_string()),
        ]);
        assert_eq!(settings.positive_integer(SPARQL_MAX_ROWS), None);
        assert_eq!(settings.positive_integer(SPARQL_QUERY_TIMEOUT_MS), None);
    }

    const ONE_SETTING: &str = "@prefix broker: <https://catalog-broker.ds-labs.org/ontologies/config#> .\n\
         <urn:broker> a broker:BrokerConfig ; broker:httpApiAddr \"0.0.0.0:9000\" .\n";

    #[test]
    fn parses_paths_and_urls() {
        assert_eq!(
            ConfigLocation::parse("/etc/broker").unwrap(),
            ConfigLocation::Local(PathBuf::from("/etc/broker"))
        );
        assert_eq!(
            ConfigLocation::parse("file:///etc/broker/config.ttl").unwrap(),
            ConfigLocation::Local(PathBuf::from("/etc/broker/config.ttl"))
        );
        assert!(matches!(
            ConfigLocation::parse("https://config.example.org/broker.ttl").unwrap(),
            ConfigLocation::Remote(url) if url.as_str() == "https://config.example.org/broker.ttl"
        ));
        assert!(matches!(
            ConfigLocation::parse("ftp://config.example.org/broker.ttl"),
            Err(BrokerConfigError::UnsupportedScheme(_))
        ));
        assert!(matches!(
            ConfigLocation::parse("file://remote-host/broker.ttl"),
            Err(BrokerConfigError::InvalidUrl(..))
        ));
    }

    #[tokio::test]
    async fn reads_a_datadir_via_a_file_url() {
        let (dir, _store) = store_with(ONE_SETTING);
        let url = Url::from_directory_path(dir.path()).unwrap();
        let location = ConfigLocation::parse(url.as_str()).unwrap();
        let settings = BrokerSettings::from_location(&location, &reqwest::Client::new())
            .await
            .unwrap();
        assert_eq!(settings.get(HTTP_API_ADDR).as_deref(), Some("0.0.0.0:9000"));
    }

    #[tokio::test]
    async fn reads_a_standalone_turtle_file() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("broker.ttl");
        std::fs::write(&file, ONE_SETTING).unwrap();
        for raw in [
            file.to_str().unwrap().to_string(),
            Url::from_file_path(&file).unwrap().to_string(),
        ] {
            let location = ConfigLocation::parse(&raw).unwrap();
            let settings = BrokerSettings::from_location(&location, &reqwest::Client::new())
                .await
                .unwrap();
            assert_eq!(settings.get(HTTP_API_ADDR).as_deref(), Some("0.0.0.0:9000"));
        }
    }

    #[test]
    fn malformed_turtle_is_an_error() {
        assert!(matches!(
            BrokerSettings::from_turtle(b"this is not turtle", None, "test"),
            Err(BrokerConfigError::Parse { .. })
        ));
    }

    /// Serves `ONE_SETTING` at `/broker.ttl` and 404 everywhere else.
    async fn serve_turtle() -> String {
        use axum::{Router, routing::get};
        let app = Router::new().route("/broker.ttl", get(|| async { ONE_SETTING }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn fetches_turtle_over_http() {
        let base = serve_turtle().await;
        let location = ConfigLocation::parse(&format!("{base}/broker.ttl")).unwrap();
        let settings = BrokerSettings::from_location(&location, &reqwest::Client::new())
            .await
            .unwrap();
        assert_eq!(settings.get(HTTP_API_ADDR).as_deref(), Some("0.0.0.0:9000"));
    }

    #[tokio::test]
    async fn an_http_error_status_is_an_error() {
        let base = serve_turtle().await;
        let location = ConfigLocation::parse(&format!("{base}/missing.ttl")).unwrap();
        assert!(matches!(
            BrokerSettings::from_location(&location, &reqwest::Client::new()).await,
            Err(BrokerConfigError::Fetch { .. })
        ));
    }

    #[tokio::test]
    async fn a_missing_datadir_is_an_error_and_is_not_created() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("nope");
        let location = ConfigLocation::Local(missing.clone());
        assert!(matches!(
            BrokerSettings::from_location(&location, &reqwest::Client::new()).await,
            Err(BrokerConfigError::Read { .. })
        ));
        assert!(!missing.exists());
    }

    #[tokio::test]
    async fn a_corrupt_datadir_file_is_an_error_and_is_left_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join(CONFIG_GRAPH_FILE);
        std::fs::write(&file, "not turtle").unwrap();
        std::fs::write(dir.path().join("config_graph.ttl.bak.1"), ONE_SETTING).unwrap();
        let location = ConfigLocation::Local(dir.path().to_path_buf());
        assert!(matches!(
            BrokerSettings::from_location(&location, &reqwest::Client::new()).await,
            Err(BrokerConfigError::Parse { .. })
        ));
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "not turtle");
    }
}
