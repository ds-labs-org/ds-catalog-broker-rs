//! Runtime configuration, read from a Turtle file through `contreforts-config`'s
//! [`ConfigStore`] - see `docs/configuration.md` for the operator-facing reference and
//! `docs/examples/config_graph.ttl` for a complete example.
//!
//! # Where the settings live
//!
//! Every setting is one property on a single `broker:BrokerConfig` resource in the config
//! store's [`CONFIG_GRAPH`], which `ConfigStore::open` loads from `<datadir>/config_graph.ttl`.
//! The datadir is the one `contreforts-config` itself resolves: `CONFIG_STORE_PATH` when set
//! (the only environment variable in the configuration path - something has to say where the
//! Turtle file is), otherwise `<os-data-dir>/config_store`. No setting is read from the
//! environment.
//!
//! # No config store at all is not an error
//!
//! When `CONFIG_STORE_PATH` is unset and the per-user default datadir holds no
//! `config_graph.ttl`, the broker starts with every setting unset (built-in defaults) - without
//! creating that directory, which `ConfigStore::open` would otherwise do. An explicit
//! `CONFIG_STORE_PATH` that cannot be opened *is* an error: the operator asked for that file.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};

use contreforts_config::{ConfigStore, ConfigStoreConfig, ConfigStoreError};
use contreforts_core::namespaces::CONFIG_GRAPH;

/// This broker's configuration vocabulary. Every [`Setting::property`] is a local name in it.
pub const BROKER_NS: &str = "https://catalog-broker.ds-labs.org/ontologies/config#";

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
}

/// The settings read from the Turtle file, keyed by [`Setting::property`].
#[derive(Debug, Clone, Default)]
pub struct BrokerSettings {
    values: HashMap<String, String>,
    /// The config store directory the values came from. `None` when no store was opened.
    source: Option<PathBuf>,
}

impl BrokerSettings {
    /// Resolve the config store's datadir (see the module doc) and read it, if there is one.
    pub fn load() -> Result<Self, BrokerConfigError> {
        let explicit = std::env::var_os(CONFIG_STORE_PATH_ENV).is_some_and(|v| !v.is_empty());

        let path = if explicit {
            PathBuf::from(ConfigStoreConfig::from_env()?.config_store_path)
        } else {
            match ConfigStoreConfig::per_user_default() {
                Ok(path) if path.join("config_graph.ttl").is_file() => path,
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
            }
        };

        let store = ConfigStore::open(&path)?;
        let mut settings = Self::from_store(&store)?;
        tracing::info!(
            path = %path.display(),
            settings = settings.values.len(),
            "loaded broker configuration from the config store"
        );
        settings.source = Some(path);
        Ok(settings)
    }

    /// Read the `broker:BrokerConfig` resource from `store`'s [`CONFIG_GRAPH`].
    pub fn from_store(store: &ConfigStore) -> Result<Self, BrokerConfigError> {
        let sparql = format!(
            "SELECT ?s ?p ?o WHERE {{ GRAPH <{CONFIG_GRAPH}> {{ \
             ?s a <{BROKER_NS}BrokerConfig> ; ?p ?o \
             FILTER(STRSTARTS(STR(?p), \"{BROKER_NS}\")) }} }}"
        );
        let mut subjects = BTreeSet::new();
        let mut found: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for row in store.select(&sparql)? {
            let field = |name: &str| {
                row.iter()
                    .find(|(var, _)| var == name)
                    .map(|(_, value)| value.clone())
            };
            let (Some(s), Some(p), Some(o)) = (field("s"), field("p"), field("o")) else {
                continue;
            };
            subjects.insert(s);
            found
                .entry(p[BROKER_NS.len()..].to_string())
                .or_default()
                .push(o);
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

    /// The config store directory the values were read from, if any.
    pub fn source(&self) -> Option<&Path> {
        self.source.as_deref()
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
}
