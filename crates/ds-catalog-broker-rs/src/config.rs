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

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::PathBuf;

use contreforts_config::{ConfigStore, ConfigStoreConfig, ConfigStoreError};
use contreforts_core::namespaces::CONFIG_GRAPH;
use oxigraph::io::{RdfFormat, RdfParser};
use oxigraph::model::{GraphName, NamedNode, Term};
use oxigraph::sparql::{QueryResults, SparqlEvaluator};
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
pub const CRAWLER_CONFIG_PATH: Setting = Setting::new("crawlerConfigPath");
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
    CRAWLER_CONFIG_PATH,
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

#[derive(Debug, thiserror::Error)]
pub enum BrokerConfigError {
    #[error(transparent)]
    Store(#[from] ConfigStoreError),
    #[error("the config graph holds {0} broker:BrokerConfig resources; expected at most one")]
    MultipleConfigResources(usize),
    #[error(
        "broker:{property} has {count} values on the broker:BrokerConfig resource; expected one"
    )]
    MultipleValues { property: String, count: usize },
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

    /// Read the `broker:BrokerConfig` resource from `store`'s [`CONFIG_GRAPH`].
    fn from_graph(store: &Store) -> Result<Self, BrokerConfigError> {
        let query_err = |err: &dyn std::fmt::Display| BrokerConfigError::Query(err.to_string());
        let sparql = format!(
            "SELECT ?s ?p ?o WHERE {{ GRAPH <{CONFIG_GRAPH}> {{ \
             ?s a <{BROKER_NS}BrokerConfig> ; ?p ?o \
             FILTER(STRSTARTS(STR(?p), \"{BROKER_NS}\")) }} }}"
        );
        let prepared = SparqlEvaluator::new()
            .parse_query(&sparql)
            .map_err(|err| query_err(&err))?;
        let QueryResults::Solutions(solutions) = prepared
            .on_store(store)
            .execute()
            .map_err(|err| query_err(&err))?
        else {
            return Err(BrokerConfigError::Query("expected solutions".to_string()));
        };

        let mut subjects = BTreeSet::new();
        let mut found: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for solution in solutions {
            let solution = solution.map_err(|err| query_err(&err))?;
            let (Some(s), Some(Term::NamedNode(p)), Some(o)) =
                (solution.get("s"), solution.get("p"), solution.get("o"))
            else {
                continue;
            };
            let value = match o {
                Term::Literal(literal) => literal.value().to_string(),
                Term::NamedNode(node) => node.as_str().to_string(),
                other => other.to_string(),
            };
            subjects.insert(s.to_string());
            found
                .entry(p.as_str()[BROKER_NS.len()..].to_string())
                .or_default()
                .push(value);
        }
        if subjects.len() > 1 {
            return Err(BrokerConfigError::MultipleConfigResources(subjects.len()));
        }

        let mut values = BTreeMap::new();
        for (property, mut objects) in found {
            if objects.len() > 1 {
                return Err(BrokerConfigError::MultipleValues {
                    property,
                    count: objects.len(),
                });
            }
            values.insert(property, objects.pop().expect("one value"));
        }
        Ok(Self::from_values(values))
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
            source: None,
        }
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
        assert_eq!(
            settings
                .get(POLICY_FILTER_RUN_WHEN_OAUTH2_DISABLED)
                .as_deref(),
            Some("true")
        );
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
