use super::*;

use dcp_core::{DcpKeyPair, now_secs, sign_jws};

/// A stranger's own did:web, correctly signed with `aud` set to this holder
/// and a nested token it signed itself, gets 401 and no credential: the
/// broker never issued that token. The stranger's server publishes a valid
/// DID document, so a resolver that ran first would fetch it; it must see
/// zero requests.
#[tokio::test]
async fn presentation_query_from_a_caller_the_holder_never_issued_a_token_to_is_401() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let attacker_did = format!(
        "did:web:127.0.0.1%3A{}",
        listener.local_addr().unwrap().port()
    );
    let attacker = DcpKeyPair::generate(attacker_did);
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = hits.clone();
    let did_doc = attacker.did_document(&[]).to_string();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            counter.fetch_add(1, Ordering::SeqCst);
            let mut request = [0u8; 2048];
            let _ = sock.read(&mut request).await;
            let _ = sock
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{did_doc}",
                        did_doc.len()
                    )
                    .as_bytes(),
                )
                .await;
        }
    });

    let holder = Arc::new(crate::HolderIdentity::new(
        "broker.example".to_string(),
        true,
        "header.payload.signature".to_string(),
        "scope".to_string(),
    ));
    let now = now_secs();
    let forged_t2 = sign_jws(
        &serde_json::json!({
            "iss": attacker.own_did, "sub": attacker.own_did, "aud": holder.key_pair.own_did,
            "iat": now, "nbf": now, "exp": now + 300, "jti": "never-issued",
        }),
        &attacker.signing_key(),
        &attacker.own_key_id,
    );
    let token = sign_jws(
        &serde_json::json!({
            "iss": attacker.own_did,
            "sub": attacker.own_did,
            "aud": holder.key_pair.own_did,
            "token": forged_t2,
            "iat": now, "nbf": now, "exp": now + 60,
            "jti": "attacker-jti",
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
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "the attacker's server was contacted"
    );
}
