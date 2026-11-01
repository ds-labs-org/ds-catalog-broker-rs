use super::*;

use dcp_core::{DcpKeyPair, now_secs, sign_jws};

/// A stranger's own did:web, correctly signed with `aud` set to this holder,
/// gets 401 and no credential: the broker never issued it a token.
#[tokio::test]
async fn presentation_query_from_a_caller_the_holder_never_issued_a_token_to_is_401() {
    let holder = Arc::new(crate::HolderIdentity::new(
        "broker.example".to_string(),
        false,
        "header.payload.signature".to_string(),
        "scope".to_string(),
    ));
    let attacker = DcpKeyPair::generate("did:web:evil.example".to_string());
    let token = sign_jws(
        &serde_json::json!({
            "iss": attacker.own_did,
            "aud": holder.key_pair.own_did,
            "exp": now_secs() + 60,
        }),
        &attacker.signing_key(),
        &attacker.own_key_id,
    );
    let state = test_state().with_holder(Some(holder));
    let response = build_router(state)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/dsp/holder/presentations/query")
                .header("Authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
