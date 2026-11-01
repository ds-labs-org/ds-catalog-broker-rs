//! The crawler's participant registry and holder identity.
//!
//! This stands in for a real dataspace participant directory (a
//! catalog-of-catalogs, or a registry service queried at runtime): for
//! now, "which DSP catalog endpoints does this connector poll" is a
//! hand-maintained list in the broker's Turtle config - `broker:Participant`
//! and `broker:Holder` resources linked from `broker:BrokerConfig`, read by
//! `ds_catalog_broker_rs::config` and documented in `docs/configuration.md`.
//! See the `dataspace` study repo's `docs/adr/` for whether/when this gets
//! replaced by something dynamic - that is a governance-adjacent decision
//! (who gets to add a participant) out of scope for this crate.
//!
//! This module only holds the types and their invariants; it does not parse
//! anything. Build a [`ParticipantsConfig`] with [`ParticipantsConfig::new`],
//! which enforces the `credential_protocol` invariants documented on
//! [`ParticipantEntry`].

use std::path::PathBuf;
use std::str::FromStr;

/// The validated crawler configuration. Construct via
/// [`ParticipantsConfig::new`] - it enforces the `credential_protocol`
/// invariants documented on [`ParticipantEntry`], so a value of this type
/// is internally consistent by the time crawl code sees it.
#[derive(Debug, Clone)]
pub struct ParticipantsConfig {
    /// How often to run a full crawl cycle over every configured
    /// participant.
    pub interval_secs: u64,
    pub participants: Vec<ParticipantEntry>,
    /// This crawler's own DCP holder identity. Required exactly when at
    /// least one participant's `credential_protocol` is `Dcp` or `Oid4Vp` -
    /// see [`ParticipantsConfig::new`]. Both protocols present the same
    /// underlying holder identity (key pair + credential), just wrapped in
    /// a different wire message.
    pub holder: Option<HolderConfig>,
}

/// Which credential-presentation protocol a participant's catalog
/// endpoint requires, if any. See `docs/oid4vp-holder-2026-08-28.md` for
/// why this is an enum rather than a second parallel bool alongside the
/// old `requires_dcp`. Written in the config as `"none"`, `"dcp"` or
/// `"oid4vp"` (see [`FromStr`]).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum CredentialProtocol {
    /// No credential presented - the unauthenticated case (still a real,
    /// non-empty `Authorization` header on the wire, see
    /// `OPEN_PARTICIPANT_PLACEHOLDER_AUTH` in `crawler::lib`, but no
    /// credential-backed identity).
    #[default]
    None,
    /// A DCP self-issued token (`Authorization: Bearer <token>`) minted
    /// via `dcp_core::HolderIdentity::mint_self_issued_token`. Requires
    /// `provider_did` on the entry and a holder on the config.
    Dcp,
    /// An OID4VP `vp_token` + `presentation_submission`, POSTed to
    /// `oid4vp_response_uri` to obtain a short-lived access token that is
    /// then attached as `Authorization: Bearer <access_token>` on the
    /// same catalog request - see `crawler::oid4vp::present`. Requires
    /// `oid4vp_response_uri` on the entry and a holder on the config (same
    /// holder identity DCP uses, different presentation wire shape).
    Oid4Vp,
}

/// A `credential_protocol` value other than `none`, `dcp` or `oid4vp`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown credential protocol {0:?} (expected none, dcp or oid4vp)")]
pub struct UnknownCredentialProtocol(pub String);

impl FromStr for CredentialProtocol {
    type Err = UnknownCredentialProtocol;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        match raw {
            "none" => Ok(Self::None),
            "dcp" => Ok(Self::Dcp),
            "oid4vp" => Ok(Self::Oid4Vp),
            other => Err(UnknownCredentialProtocol(other.to_string())),
        }
    }
}

/// One participant this crawler polls.
#[derive(Debug, Clone)]
pub struct ParticipantEntry {
    pub id: String,
    pub name: String,
    pub catalog_request_url: String,
    /// Which credential-presentation protocol this participant's catalog
    /// endpoint requires - see [`CredentialProtocol`].
    pub credential_protocol: CredentialProtocol,
    /// Required when `credential_protocol` is `Dcp`: this participant's
    /// own DID - the audience of the self-issued token the crawler sends
    /// it.
    pub provider_did: Option<String>,
    /// Required when `credential_protocol` is `Oid4Vp`: the OID4VP
    /// `direct_post` endpoint the crawler POSTs its `vp_token` +
    /// `presentation_submission` to, in exchange for a short-lived access
    /// token - see `crawler::oid4vp::present`.
    pub oid4vp_response_uri: Option<String>,
}

/// This crawler's own DCP holder identity configuration.
#[derive(Debug, Clone)]
pub struct HolderConfig {
    /// This crawler's own `did:web` host\[:port\] -
    /// `did:web:<own_did_host>:dsp:holder` is derived from it (see
    /// `dcp_core::HolderIdentity::new`).
    pub own_did_host: String,
    /// Resolve `did:web` DIDs over plain `http://` instead of `https://` -
    /// for local/test environments.
    pub insecure_http: bool,
    /// A local file holding the pre-issued Verifiable Credential (JWS
    /// compact string) this connector presents as itself.
    ///
    /// A VC is a *bearer credential* - whoever holds the JWS can present
    /// it - so it is kept out of the config document itself, which may be
    /// fetched from another machine. The flip side is that the config picks
    /// which local file is sent as the credential, so
    /// [`Self::read_credential_jws`] only accepts a file that is a VC in
    /// compact JWS form. The file is still plain, unencrypted text: this
    /// project has no secret-management story yet (see the `dataspace`
    /// study repo's `authority/` placeholder), so protecting it is left to
    /// the file's permissions.
    pub credential_jws_file: PathBuf,
    /// The DCP scope this holder's credential is expected to satisfy.
    pub required_scope: String,
}

impl HolderConfig {
    /// Read the credential from [`Self::credential_jws_file`], with
    /// surrounding whitespace (a trailing newline, say) trimmed.
    pub fn read_credential_jws(&self) -> Result<String, ConfigError> {
        let raw = std::fs::read_to_string(&self.credential_jws_file).map_err(|source| {
            ConfigError::CredentialFile {
                path: self.credential_jws_file.display().to_string(),
                source,
            }
        })?;
        let jws = raw.trim();
        if jws.is_empty() {
            return Err(ConfigError::EmptyCredentialFile {
                path: self.credential_jws_file.display().to_string(),
            });
        }
        check_compact_jws(jws).map_err(|reason| ConfigError::InvalidCredentialJws {
            path: self.credential_jws_file.display().to_string(),
            reason,
        })?;
        Ok(jws.to_string())
    }
}

/// Whether `jws` looks like a Verifiable Credential in compact JWS form
/// (RFC 7515 section 7.1): three non-empty, canonical base64url segments,
/// a JSON header naming a signing `alg`, and a JSON payload that is a
/// `VerifiableCredential` - VC-JWT's `vc` claim, or a VC 2.0 JOSE payload
/// that is the credential itself. The signature is the verifier's business;
/// this only stops a file that is plainly something else (an environment
/// dump, a key, another kind of bearer token) from being sent as the
/// crawler's credential.
fn check_compact_jws(jws: &str) -> Result<(), &'static str> {
    use serde_json::Value;
    let segments: Vec<&str> = jws.split('.').collect();
    let [_, _, signature] = segments[..] else {
        return Err("expected three dot-separated segments");
    };
    if segments.iter().any(|segment| segment.is_empty()) {
        return Err("a segment is empty");
    }
    dcp_core::b64_decode(signature).map_err(|_| "the signature is not base64url")?;
    let (_, header, payload) = dcp_core::decode_jws_unverified(jws)
        .map_err(|_| "the header or payload is not base64url-encoded JSON")?;
    let alg = header
        .get("alg")
        .and_then(Value::as_str)
        .ok_or("the header names no alg")?;
    if alg.is_empty() || alg.trim() != alg || alg.eq_ignore_ascii_case("none") {
        return Err("the header's alg is empty or none");
    }
    let credential = payload.get("vc").unwrap_or(&payload);
    let is_credential = match credential.get("type") {
        Some(Value::String(kind)) => kind == "VerifiableCredential",
        Some(Value::Array(kinds)) => kinds.iter().any(|kind| kind == "VerifiableCredential"),
        _ => false,
    };
    if !is_credential {
        return Err("the payload is not a VerifiableCredential");
    }
    Ok(())
}

/// A crawler configuration that violates one of the invariants
/// [`ParticipantsConfig::new`] enforces, or a holder credential file that
/// can't be read. Returned rather than panicking, so a bad config fails
/// fast and legibly at startup instead of surfacing deep inside a crawl
/// loop.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("two participants have the id '{id}'")]
    DuplicateParticipantId { id: String },
    #[error("participant '{id}' has credential protocol dcp but no provider DID is set")]
    MissingProviderDid { id: String },
    #[error("participant '{id}' has credential protocol oid4vp but no OID4VP response URI is set")]
    MissingOid4VpResponseUri { id: String },
    #[error(
        "participant '{id}' has a credential protocol that requires a holder identity, but no holder is configured"
    )]
    MissingHolder { id: String },
    #[error("failed to read the holder credential file {path}: {source}")]
    CredentialFile {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("the holder credential file {path} is empty")]
    EmptyCredentialFile { path: String },
    /// The file holds something other than a compact JWS. Its content is
    /// deliberately not echoed: the file may be anything a config names.
    #[error("the holder credential file {path} does not hold a compact JWS: {reason}")]
    InvalidCredentialJws { path: String, reason: &'static str },
}

impl ParticipantsConfig {
    /// Build a config, checking that participant ids are unique, that a
    /// `Dcp` participant carries a `provider_did`, that an `Oid4Vp`
    /// participant carries an `oid4vp_response_uri`, and that either way a
    /// holder is configured for the crawler to authenticate as.
    pub fn new(
        interval_secs: u64,
        participants: Vec<ParticipantEntry>,
        holder: Option<HolderConfig>,
    ) -> Result<Self, ConfigError> {
        let mut ids = std::collections::BTreeSet::new();
        for participant in &participants {
            if !ids.insert(participant.id.as_str()) {
                return Err(ConfigError::DuplicateParticipantId {
                    id: participant.id.clone(),
                });
            }
            match participant.credential_protocol {
                CredentialProtocol::None => continue,
                CredentialProtocol::Dcp => {
                    if participant.provider_did.is_none() {
                        return Err(ConfigError::MissingProviderDid {
                            id: participant.id.clone(),
                        });
                    }
                }
                CredentialProtocol::Oid4Vp => {
                    if participant.oid4vp_response_uri.is_none() {
                        return Err(ConfigError::MissingOid4VpResponseUri {
                            id: participant.id.clone(),
                        });
                    }
                }
            }
            if holder.is_none() {
                return Err(ConfigError::MissingHolder {
                    id: participant.id.clone(),
                });
            }
        }
        Ok(Self {
            interval_secs,
            participants,
            holder,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open(id: &str) -> ParticipantEntry {
        ParticipantEntry {
            id: id.to_string(),
            name: id.to_string(),
            catalog_request_url: "http://127.0.0.1:19001/dsp/catalog/request".to_string(),
            credential_protocol: CredentialProtocol::None,
            provider_did: None,
            oid4vp_response_uri: None,
        }
    }

    fn holder() -> HolderConfig {
        HolderConfig {
            own_did_host: "localhost:19100".to_string(),
            insecure_http: true,
            credential_jws_file: PathBuf::from("/nonexistent/holder.jws"),
            required_scope: "some-scope".to_string(),
        }
    }

    #[test]
    fn credential_protocols_parse_from_their_config_spelling() {
        assert_eq!("none".parse(), Ok(CredentialProtocol::None));
        assert_eq!("dcp".parse(), Ok(CredentialProtocol::Dcp));
        assert_eq!("oid4vp".parse(), Ok(CredentialProtocol::Oid4Vp));
        assert!("oid4_vp".parse::<CredentialProtocol>().is_err());
    }

    #[test]
    fn open_participants_need_no_holder() {
        let config = ParticipantsConfig::new(60, vec![open("a"), open("b")], None).unwrap();
        assert_eq!(config.participants.len(), 2);
    }

    #[test]
    fn rejects_duplicate_participant_ids() {
        let err = ParticipantsConfig::new(60, vec![open("a"), open("a")], None).unwrap_err();
        assert!(matches!(err, ConfigError::DuplicateParticipantId { id } if id == "a"));
    }

    #[test]
    fn accepts_dcp_with_provider_did_and_holder() {
        let mut gated = open("gated");
        gated.credential_protocol = CredentialProtocol::Dcp;
        gated.provider_did = Some("did:web:localhost%3A19002:dsp".to_string());
        ParticipantsConfig::new(60, vec![gated], Some(holder())).unwrap();
    }

    #[test]
    fn rejects_dcp_without_provider_did() {
        let mut gated = open("gated");
        gated.credential_protocol = CredentialProtocol::Dcp;
        let err = ParticipantsConfig::new(60, vec![gated], Some(holder())).unwrap_err();
        assert!(matches!(err, ConfigError::MissingProviderDid { id } if id == "gated"));
    }

    #[test]
    fn rejects_dcp_without_holder() {
        let mut gated = open("gated");
        gated.credential_protocol = CredentialProtocol::Dcp;
        gated.provider_did = Some("did:web:localhost%3A19002:dsp".to_string());
        let err = ParticipantsConfig::new(60, vec![gated], None).unwrap_err();
        assert!(matches!(err, ConfigError::MissingHolder { id } if id == "gated"));
    }

    #[test]
    fn accepts_oid4vp_with_response_uri_and_holder() {
        let mut gated = open("gated");
        gated.credential_protocol = CredentialProtocol::Oid4Vp;
        gated.oid4vp_response_uri = Some("http://127.0.0.1:19003/oid4vp/response".to_string());
        ParticipantsConfig::new(60, vec![gated], Some(holder())).unwrap();
    }

    #[test]
    fn rejects_oid4vp_without_response_uri() {
        let mut gated = open("gated");
        gated.credential_protocol = CredentialProtocol::Oid4Vp;
        let err = ParticipantsConfig::new(60, vec![gated], Some(holder())).unwrap_err();
        assert!(matches!(err, ConfigError::MissingOid4VpResponseUri { id } if id == "gated"));
    }

    #[test]
    fn rejects_oid4vp_without_holder() {
        let mut gated = open("gated");
        gated.credential_protocol = CredentialProtocol::Oid4Vp;
        gated.oid4vp_response_uri = Some("http://127.0.0.1:19003/oid4vp/response".to_string());
        let err = ParticipantsConfig::new(60, vec![gated], None).unwrap_err();
        assert!(matches!(err, ConfigError::MissingHolder { id } if id == "gated"));
    }

    /// Encode `json` as one base64url JWS segment.
    fn segment(json: &str) -> String {
        dcp_core::b64_encode(json)
    }

    /// A compact JWS: `header` and `payload` are JSON, the signature is
    /// arbitrary (its check is the verifier's business).
    fn jws(header: &str, payload: &str) -> String {
        format!("{}.{}.c2lnbmF0dXJl", segment(header), segment(payload))
    }

    /// A VC-JWT whose header names ES256.
    fn valid_jws() -> String {
        jws(
            r#"{"alg":"ES256","typ":"JWT"}"#,
            r#"{"vc":{"type":["VerifiableCredential","FederatedCatalogAccessCredential"]}}"#,
        )
    }

    /// Write `content` to a fresh credential file and read it back.
    fn read_credential(content: &str) -> Result<String, ConfigError> {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("holder.jws");
        std::fs::write(&file, content).unwrap();
        let mut config = holder();
        config.credential_jws_file = file;
        config.read_credential_jws()
    }

    #[test]
    fn reads_and_trims_the_credential_file() {
        let valid = valid_jws();
        assert_eq!(read_credential(&format!("{valid}\n")).unwrap(), valid);
        assert!(matches!(
            read_credential("  \n"),
            Err(ConfigError::EmptyCredentialFile { .. })
        ));
    }

    /// Whatever file the config names is sent as the credential, so only a
    /// compact JWS is accepted: not environment variables, a key, or a
    /// JSON credential.
    #[test]
    fn rejects_a_credential_file_that_is_not_a_compact_jws() {
        // A VC 2.0 JOSE credential (the payload is the credential) passes.
        let vc2 = jws(r#"{"alg":"ES256"}"#, r#"{"type":["VerifiableCredential"]}"#);
        assert_eq!(read_credential(&vc2).unwrap(), vc2);

        let header = "eyJhbGciOiJFUzI1NiJ9"; // {"alg":"ES256"}
        let cases = [
            ("environment", "PATH=/usr/bin\0HOME=/root\0".to_string()),
            (
                "PEM key",
                "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMG\n-----END PRIVATE KEY-----".to_string(),
            ),
            (
                "JSON credential",
                r#"{"@context":[],"type":["VerifiableCredential"]}"#.to_string(),
            ),
            ("two segments", format!("{header}.eyJ2YyI6e319")),
            ("four segments", format!("{header}.e30.c2ln.c2ln")),
            ("empty signature", format!("{header}.e30.")),
            ("empty payload", format!("{header}..c2ln")),
            ("not base64url", format!("{header}.e30.c2ln+/==")),
            ("header not JSON", "aGVsbG8.e30.c2ln".to_string()), // "hello"
            (
                "header without alg",
                "eyJ0eXAiOiJKV1QifQ.e30.c2ln".to_string(),
            ), // {"typ":"JWT"}
            ("alg none", "eyJhbGciOiJub25lIn0.e30.c2ln".to_string()), // {"alg":"none"}
            ("inner whitespace", format!("{header}.e30 .c2ln")),
            (
                "empty alg",
                jws(
                    r#"{"alg":""}"#,
                    r#"{"vc":{"type":["VerifiableCredential"]}}"#,
                ),
            ),
            (
                "padded none",
                jws(
                    r#"{"alg":" none"}"#,
                    r#"{"vc":{"type":["VerifiableCredential"]}}"#,
                ),
            ),
            // A bearer token of another kind, such as a service-account JWT.
            (
                "not a credential",
                jws(r#"{"alg":"RS256"}"#, r#"{"sub":"system:serviceaccount"}"#),
            ),
            ("payload not JSON", format!("{header}.aGVsbG8.c2ln")),
            // `l` leaves non-zero trailing bits: dcp_core's strict decoder
            // refuses them (`c2k` would be canonical).
            (
                "non-canonical base64url",
                format!("{}.c2l", valid_jws().rsplit_once('.').unwrap().0),
            ),
        ];
        for (name, content) in cases {
            assert!(
                matches!(
                    read_credential(&content),
                    Err(ConfigError::InvalidCredentialJws { .. })
                ),
                "{name} was accepted"
            );
        }
    }

    #[test]
    fn the_error_does_not_echo_the_file_content() {
        let err = read_credential("SECRET_TOKEN=hunter2").unwrap_err();
        assert!(!err.to_string().contains("hunter2"), "{err}");
    }

    #[test]
    fn a_missing_credential_file_is_an_error() {
        assert!(matches!(
            holder().read_credential_jws(),
            Err(ConfigError::CredentialFile { .. })
        ));
    }
}
