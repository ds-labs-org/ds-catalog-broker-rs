//! The OAuth2 Bearer gate shared by the catalog, SPARQL and management
//! routes.

use axum::{
    Json,
    http::{
        HeaderMap, StatusCode,
        header::{AUTHORIZATION, WWW_AUTHENTICATE},
    },
    response::IntoResponse,
};

use super::ErrorResponse;
use crate::AppState;
use crate::oauth2::VerifyError;

/// Enforces the OAuth2 Bearer gate (see `AppState::oauth2`'s doc comment
/// and `docs/oauth2-bearer-gating-2026-08-28.md`'s "Response shape") for
/// `GET /catalog`, `GET`/`POST /sparql`, and
/// `POST /api/management/v4/catalogs/request` - the three routes this
/// mechanism gates. `Ok(claims)` means the caller may proceed:
/// `Ok(None)` when gating is off (`state.oauth2` is `None`, so there is no
/// verified token and therefore no claims at all), `Ok(Some(claims))` when
/// the caller presented a valid, sufficiently-scoped token - `claims` is
/// exactly `OAuth2Verifier::verify`'s own decoded JWT claims object, meant
/// to be fed to `odrl_filter::jwt_claims_to_engine_claims` by callers that
/// go on to do ODRL policy-based dataset filtering (gap analysis §3.4).
/// `Err(response)` is the exact response the caller should get instead of
/// running the route's own handler.
///
/// - No/malformed `Authorization: Bearer` header, or a token that fails
///   verification for any reason other than scope (unknown `kid`, bad
///   signature, expired, wrong `iss`/`aud`): `401` with a
///   `WWW-Authenticate: Bearer` header (RFC 6750).
/// - Valid token, missing the configured required scope: `403` (no
///   `WWW-Authenticate` header - the caller authenticated fine, it's an
///   authorization failure, not an authentication one).
pub(super) fn check_oauth2_bearer(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<Option<serde_json::Value>, Box<axum::response::Response>> {
    let Some(verifier) = &state.oauth2 else {
        return Ok(None);
    };

    let Some(token) = bearer_token(headers) else {
        return Err(Box::new(unauthorized_bearer_response()));
    };

    match verifier.verify(token) {
        Ok(claims) => Ok(Some(claims)),
        Err(VerifyError::InsufficientScope(scope)) => Err(Box::new(
            (
                StatusCode::FORBIDDEN,
                Json(ErrorResponse {
                    error: format!("token is missing required scope '{scope}'"),
                }),
            )
                .into_response(),
        )),
        Err(err) => {
            tracing::warn!(error = %err, "oauth2 bearer token verification failed");
            Err(Box::new(unauthorized_bearer_response()))
        }
    }
}

/// The token of an `Authorization: Bearer <token>` header. The scheme is
/// matched case-insensitively (RFC 7235 section 2.1). `None` for a missing
/// header, another scheme, or an empty token.
pub(super) fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("Bearer") {
        return None;
    }
    Some(token.trim()).filter(|token| !token.is_empty())
}

pub(super) fn unauthorized_bearer_response() -> axum::response::Response {
    (
        StatusCode::UNAUTHORIZED,
        [(WWW_AUTHENTICATE, "Bearer")],
        Json(ErrorResponse {
            error: "missing or invalid bearer token".to_string(),
        }),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, value.parse().unwrap());
        headers
    }

    #[test]
    fn the_bearer_scheme_is_case_insensitive() {
        for value in ["Bearer abc", "bearer abc", "BEARER abc", "bEaReR  abc "] {
            assert_eq!(bearer_token(&headers(value)), Some("abc"), "{value}");
        }
    }

    #[test]
    fn other_schemes_and_empty_tokens_give_no_token() {
        for value in ["Basic abc", "Bearer", "Bearer ", "Bearerabc", "abc"] {
            assert_eq!(bearer_token(&headers(value)), None, "{value}");
        }
        assert_eq!(bearer_token(&HeaderMap::new()), None);
    }
}
