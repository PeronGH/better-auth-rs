#![expect(
    clippy::expect_used,
    reason = "test code — panicking on failures is the correct behavior"
)]
#![expect(
    clippy::panic,
    reason = "test code — panicking on failures is the correct behavior"
)]

mod compat;

use compat::dual_server::*;
use compat::helpers::*;
use serde_json::Value;

fn response_token(body: &Value) -> String {
    body.get("token")
        .and_then(|token| token.as_str())
        .unwrap_or("")
        .to_string()
}

fn session_token_from_get_session(body: &Value) -> String {
    body.get("session")
        .and_then(|session| session.get("token"))
        .and_then(|token| token.as_str())
        .unwrap_or("")
        .to_string()
}

fn other_session_token(body: &Value, current_token: &str) -> String {
    body.as_array()
        .and_then(|sessions| {
            sessions.iter().find_map(|session| {
                let token = session.get("token")?.as_str()?;
                (token != current_token).then(|| token.to_string())
            })
        })
        .unwrap_or_default()
}

#[tokio::test]
async fn phase1_request_password_reset_cases() {
    let _lock = serial_lock().await;
    if !ensure_reference_server_or_skip().await {
        return;
    }

    reset_reference_state()
        .await
        .unwrap_or_else(|error| panic!("reference state reset should succeed: {error}"));

    let auth = create_default_test_auth().await;
    let mut ref_client = RefClient::new();
    let (email, _rust_token, _rust_user_id) =
        signup_on_both(&auth, &mut ref_client, "p1_request_reset").await;
    let mut reports = Vec::new();

    for (name, body) in [
        (
            "existing user",
            serde_json::json!({
                "email": email,
                "redirectTo": "/reset",
            }),
        ),
        (
            "non-existent user",
            serde_json::json!({
                "email": unique_email("p1_request_reset_missing"),
                "redirectTo": "/reset",
            }),
        ),
        (
            "missing email",
            serde_json::json!({
                "redirectTo": "/reset",
            }),
        ),
        (
            "invalid email",
            serde_json::json!({
                "email": "not-an-email",
                "redirectTo": "/reset",
            }),
        ),
    ] {
        let rust = rust_send(&auth, post_json("/request-password-reset", body.clone())).await;
        let reference = ref_client
            .post_full("/request-password-reset", &body)
            .await
            .unwrap_or_else(ref_error_response);
        reports.push(compare_full(
            &format!("POST /request-password-reset ({name})"),
            &rust,
            &reference,
        ));
    }

    set_reference_reset_password_mode(ControlMode::Fail)
        .await
        .unwrap_or_else(|error| panic!("reference reset password mode should set: {error}"));
    let failing_auth = create_test_auth_with_reset_sender(ResetSenderMode::Fail).await;
    let failing_body = serde_json::json!({
        "email": email,
        "redirectTo": "/reset",
    });
    let rust = rust_send(
        &failing_auth,
        post_json("/request-password-reset", failing_body.clone()),
    )
    .await;
    let reference = ref_client
        .post_full("/request-password-reset", &failing_body)
        .await
        .unwrap_or_else(ref_error_response);
    reports.push(compare_full(
        "POST /request-password-reset (sender failure)",
        &rust,
        &reference,
    ));

    print_report("Phase 1", &reports);
    log_alignment_gaps(&reports);

    reset_reference_state()
        .await
        .unwrap_or_else(|error| panic!("reference state reset should succeed: {error}"));
}

#[tokio::test]
async fn phase1_reset_password_cases() {
    let _lock = serial_lock().await;
    if !ensure_reference_server_or_skip().await {
        return;
    }

    reset_reference_state()
        .await
        .unwrap_or_else(|error| panic!("reference state reset should succeed: {error}"));

    let auth = create_default_test_auth().await;
    let mut ref_client = RefClient::new();
    let (email, _rust_token, _rust_user_id) =
        signup_on_both(&auth, &mut ref_client, "p1_reset_password").await;
    let (rust_reset_token, reference_reset_token) =
        request_reset_on_both(&auth, &mut ref_client, &email).await;

    let mut reports = Vec::new();

    let happy_rust = rust_send(
        &auth,
        post_json(
            "/reset-password",
            serde_json::json!({
                "newPassword": "newPassword123!",
                "token": rust_reset_token,
            }),
        ),
    )
    .await;
    let happy_reference = ref_client
        .post_full(
            "/reset-password",
            &serde_json::json!({
                "newPassword": "newPassword123!",
                "token": reference_reset_token,
            }),
        )
        .await
        .unwrap_or_else(ref_error_response);
    reports.push(compare_full(
        "POST /reset-password (happy path)",
        &happy_rust,
        &happy_reference,
    ));

    for (name, rust_body, reference_body) in [
        (
            "missing token",
            serde_json::json!({
                "newPassword": "newPassword123!",
            }),
            serde_json::json!({
                "newPassword": "newPassword123!",
            }),
        ),
        (
            "invalid token",
            serde_json::json!({
                "newPassword": "newPassword123!",
                "token": "invalid-reset-token",
            }),
            serde_json::json!({
                "newPassword": "newPassword123!",
                "token": "invalid-reset-token",
            }),
        ),
        (
            "short password",
            serde_json::json!({
                "newPassword": "short",
                "token": "short-rust",
            }),
            serde_json::json!({
                "newPassword": "short",
                "token": "short-ref",
            }),
        ),
    ] {
        if name == "short password" {
            let expires_at = future_at(1);
            seed_rust_reset_password_token(&auth, &email, "short-rust", expires_at).await;
            seed_reference_reset_password_token(&email, "short-ref", expires_at)
                .await
                .unwrap_or_else(|error| {
                    panic!("reference reset token seed should succeed: {error}")
                });
        }

        let rust = rust_send(&auth, post_json("/reset-password", rust_body)).await;
        let reference = ref_client
            .post_full("/reset-password", &reference_body)
            .await
            .unwrap_or_else(ref_error_response);
        reports.push(compare_full(
            &format!("POST /reset-password ({name})"),
            &rust,
            &reference,
        ));
    }

    let expired_token = "expired-reset-token";
    let expired_at = expired_at(5);
    seed_rust_reset_password_token(&auth, &email, expired_token, expired_at).await;
    seed_reference_reset_password_token(&email, expired_token, expired_at)
        .await
        .unwrap_or_else(|error| {
            panic!("reference expired reset token seed should succeed: {error}")
        });
    let rust = rust_send(
        &auth,
        post_json(
            "/reset-password",
            serde_json::json!({
                "newPassword": "newPassword123!",
                "token": expired_token,
            }),
        ),
    )
    .await;
    let reference = ref_client
        .post_full(
            "/reset-password",
            &serde_json::json!({
                "newPassword": "newPassword123!",
                "token": expired_token,
            }),
        )
        .await
        .unwrap_or_else(ref_error_response);
    reports.push(compare_full(
        "POST /reset-password (expired token)",
        &rust,
        &reference,
    ));

    let rust = rust_send(
        &auth,
        post_json(
            "/reset-password",
            serde_json::json!({
                "newPassword": "newPassword123!",
                "token": rust_reset_token,
            }),
        ),
    )
    .await;
    let reference = ref_client
        .post_full(
            "/reset-password",
            &serde_json::json!({
                "newPassword": "newPassword123!",
                "token": reference_reset_token,
            }),
        )
        .await
        .unwrap_or_else(ref_error_response);
    reports.push(compare_full(
        "POST /reset-password (token reuse)",
        &rust,
        &reference,
    ));

    print_report("Phase 1", &reports);
    log_alignment_gaps(&reports);
}

#[tokio::test]
async fn phase1_change_password_cases() {
    let _lock = serial_lock().await;
    if !ensure_reference_server_or_skip().await {
        return;
    }

    let auth = create_default_test_auth().await;
    let mut ref_client = RefClient::new();
    let (_email, rust_token, _rust_user_id) =
        signup_on_both(&auth, &mut ref_client, "p1_change_password").await;
    let mut reports = Vec::new();

    for (name, body) in [
        (
            "success no revocation",
            serde_json::json!({
                "currentPassword": "password123",
                "newPassword": "newPassword123!",
                "revokeOtherSessions": false,
            }),
        ),
        (
            "wrong current password",
            serde_json::json!({
                "currentPassword": "wrong-password",
                "newPassword": "newPassword123!",
                "revokeOtherSessions": false,
            }),
        ),
        (
            "short password",
            serde_json::json!({
                "currentPassword": "password123",
                "newPassword": "short",
                "revokeOtherSessions": false,
            }),
        ),
    ] {
        let rust = rust_send(
            &auth,
            post_json_with_auth("/change-password", body.clone(), &rust_token),
        )
        .await;
        let reference = ref_client
            .post_full("/change-password", &body)
            .await
            .unwrap_or_else(ref_error_response);
        reports.push(compare_full(
            &format!("POST /change-password ({name})"),
            &rust,
            &reference,
        ));
    }

    let auth_revoke = create_default_test_auth().await;
    let mut ref_revoke = RefClient::new();
    let (_email, rust_token, _rust_user_id) =
        signup_on_both(&auth_revoke, &mut ref_revoke, "p1_change_password_revoke").await;
    let body = serde_json::json!({
        "currentPassword": "password123",
        "newPassword": "newPassword123!",
        "revokeOtherSessions": true,
    });
    let rust = rust_send(
        &auth_revoke,
        post_json_with_auth("/change-password", body.clone(), &rust_token),
    )
    .await;
    let reference = ref_revoke
        .post_full("/change-password", &body)
        .await
        .unwrap_or_else(ref_error_response);
    reports.push(compare_full(
        "POST /change-password (revoke other sessions)",
        &rust,
        &reference,
    ));

    let unauth_rust = rust_send(
        &auth_revoke,
        post_json(
            "/change-password",
            serde_json::json!({
                "currentPassword": "password123",
                "newPassword": "newPassword123!",
            }),
        ),
    )
    .await;
    let mut unauth_ref = RefClient::new();
    let unauth_reference = unauth_ref
        .post_full(
            "/change-password",
            &serde_json::json!({
                "currentPassword": "password123",
                "newPassword": "newPassword123!",
            }),
        )
        .await
        .unwrap_or_else(ref_error_response);
    reports.push(compare_full(
        "POST /change-password (no auth)",
        &unauth_rust,
        &unauth_reference,
    ));

    print_report("Phase 1", &reports);
    log_alignment_gaps(&reports);
}

#[tokio::test]
async fn phase1_list_sessions_cases() {
    let _lock = serial_lock().await;
    if !ensure_reference_server_or_skip().await {
        return;
    }

    let auth = create_default_test_auth().await;
    let mut ref_client = RefClient::new();
    let (email, _rust_token, _rust_user_id) =
        signup_on_both(&auth, &mut ref_client, "p1_list_sessions").await;

    let mut reports = Vec::new();
    let rust = rust_send(&auth, get_request("/list-sessions")).await;
    let mut no_auth_ref = RefClient::new();
    let reference = no_auth_ref
        .get_full("/list-sessions")
        .await
        .unwrap_or_else(ref_error_response);
    reports.push(compare_full(
        "GET /list-sessions (no auth)",
        &rust,
        &reference,
    ));

    let signin_body = serde_json::json!({
        "email": email,
        "password": "password123",
    });
    let rust_signin = rust_send(&auth, post_json("/sign-in/email", signin_body.clone())).await;
    let _ = ref_client
        .post_full("/sign-in/email", &signin_body)
        .await
        .unwrap_or_else(ref_error_response);
    let rust_token = response_token(&rust_signin.body);

    let rust = rust_send(&auth, get_with_auth("/list-sessions", &rust_token)).await;
    let reference = ref_client
        .get_full("/list-sessions")
        .await
        .unwrap_or_else(ref_error_response);
    reports.push(compare_full(
        "GET /list-sessions (multiple sessions)",
        &rust,
        &reference,
    ));

    print_report("Phase 1", &reports);
    log_alignment_gaps(&reports);
}

#[tokio::test]
async fn phase1_revoke_session_cases() {
    let _lock = serial_lock().await;
    if !ensure_reference_server_or_skip().await {
        return;
    }

    let auth = create_default_test_auth().await;
    let mut ref_client = RefClient::new();
    let (email, _rust_token, _rust_user_id) =
        signup_on_both(&auth, &mut ref_client, "p1_revoke_session").await;

    let signin_body = serde_json::json!({
        "email": email,
        "password": "password123",
    });
    let rust_signin = rust_send(&auth, post_json("/sign-in/email", signin_body.clone())).await;
    let _ = ref_client
        .post_full("/sign-in/email", &signin_body)
        .await
        .unwrap_or_else(ref_error_response);
    let rust_token = response_token(&rust_signin.body);

    let _rust_sessions = rust_send(&auth, get_with_auth("/list-sessions", &rust_token)).await;
    let _ref_sessions = ref_client
        .get_full("/list-sessions")
        .await
        .unwrap_or_else(ref_error_response);
    let rust_current = rust_send(&auth, get_with_auth("/get-session", &rust_token)).await;
    let ref_current = ref_client
        .get_full("/get-session")
        .await
        .unwrap_or_else(ref_error_response);
    let rust_current_token = session_token_from_get_session(&rust_current.body);
    let ref_current_token = session_token_from_get_session(&ref_current.body);

    let mut reports = Vec::new();

    let rust = rust_send(
        &auth,
        post_json_with_auth(
            "/revoke-session",
            serde_json::json!({ "token": rust_current_token }),
            &rust_token,
        ),
    )
    .await;
    let reference = ref_client
        .post_full(
            "/revoke-session",
            &serde_json::json!({ "token": ref_current_token }),
        )
        .await
        .unwrap_or_else(ref_error_response);
    reports.push(compare_full(
        "POST /revoke-session (current session)",
        &rust,
        &reference,
    ));

    let auth_other = create_default_test_auth().await;
    let mut ref_other_client = RefClient::new();
    let (email, _rust_token, _rust_user_id) = signup_on_both(
        &auth_other,
        &mut ref_other_client,
        "p1_revoke_session_other",
    )
    .await;
    let other_signin_body = serde_json::json!({
        "email": email,
        "password": "password123",
    });
    let rust_signin = rust_send(
        &auth_other,
        post_json("/sign-in/email", other_signin_body.clone()),
    )
    .await;
    let _ = ref_other_client
        .post_full("/sign-in/email", &other_signin_body)
        .await
        .unwrap_or_else(ref_error_response);
    let rust_token = response_token(&rust_signin.body);
    let rust_sessions = rust_send(&auth_other, get_with_auth("/list-sessions", &rust_token)).await;
    let ref_sessions = ref_other_client
        .get_full("/list-sessions")
        .await
        .unwrap_or_else(ref_error_response);
    let rust_current = rust_send(&auth_other, get_with_auth("/get-session", &rust_token)).await;
    let ref_current = ref_other_client
        .get_full("/get-session")
        .await
        .unwrap_or_else(ref_error_response);
    let rust_target = other_session_token(
        &rust_sessions.body,
        &session_token_from_get_session(&rust_current.body),
    );
    let ref_target = other_session_token(
        &ref_sessions.body,
        &session_token_from_get_session(&ref_current.body),
    );
    let rust = rust_send(
        &auth_other,
        post_json_with_auth(
            "/revoke-session",
            serde_json::json!({ "token": rust_target }),
            &rust_token,
        ),
    )
    .await;
    let reference = ref_other_client
        .post_full(
            "/revoke-session",
            &serde_json::json!({ "token": ref_target }),
        )
        .await
        .unwrap_or_else(ref_error_response);
    reports.push(compare_full(
        "POST /revoke-session (other session)",
        &rust,
        &reference,
    ));

    let rust = rust_send(
        &auth_other,
        post_json_with_auth("/revoke-session", serde_json::json!({}), &rust_token),
    )
    .await;
    let reference = ref_other_client
        .post_full("/revoke-session", &serde_json::json!({}))
        .await
        .unwrap_or_else(ref_error_response);
    reports.push(compare_full(
        "POST /revoke-session (missing token)",
        &rust,
        &reference,
    ));

    let rust = rust_send(
        &auth_other,
        post_json(
            "/revoke-session",
            serde_json::json!({ "token": "missing-auth-token" }),
        ),
    )
    .await;
    let mut unauth_ref = RefClient::new();
    let reference = unauth_ref
        .post_full(
            "/revoke-session",
            &serde_json::json!({ "token": "missing-auth-token" }),
        )
        .await
        .unwrap_or_else(ref_error_response);
    reports.push(compare_full(
        "POST /revoke-session (no auth)",
        &rust,
        &reference,
    ));

    let user_one_auth = create_default_test_auth().await;
    let mut user_one_ref = RefClient::new();
    let (_email_one, user_one_token, _user_one_id) = signup_on_both(
        &user_one_auth,
        &mut user_one_ref,
        "p1_revoke_session_user_one",
    )
    .await;
    let mut user_two_ref = RefClient::new();
    let (_email_two, user_two_token, _user_two_id) = signup_on_both(
        &user_one_auth,
        &mut user_two_ref,
        "p1_revoke_session_user_two",
    )
    .await;
    let user_two_reference_session = user_two_ref
        .get_full("/get-session")
        .await
        .unwrap_or_else(ref_error_response);
    let user_two_reference_token = session_token_from_get_session(&user_two_reference_session.body);
    let rust = rust_send(
        &user_one_auth,
        post_json_with_auth(
            "/revoke-session",
            serde_json::json!({ "token": user_two_token }),
            &user_one_token,
        ),
    )
    .await;
    let reference = user_one_ref
        .post_full(
            "/revoke-session",
            &serde_json::json!({ "token": user_two_reference_token }),
        )
        .await
        .unwrap_or_else(ref_error_response);
    reports.push(compare_full(
        "POST /revoke-session (foreign session token)",
        &rust,
        &reference,
    ));

    print_report("Phase 1", &reports);
    log_alignment_gaps(&reports);
}

#[tokio::test]
async fn phase1_revoke_sessions_cases() {
    let _lock = serial_lock().await;
    if !ensure_reference_server_or_skip().await {
        return;
    }

    let auth = create_default_test_auth().await;
    let mut ref_client = RefClient::new();
    let (email, _rust_token, _rust_user_id) =
        signup_on_both(&auth, &mut ref_client, "p1_revoke_sessions").await;
    let signin_body = serde_json::json!({
        "email": email,
        "password": "password123",
    });
    let rust_signin = rust_send(&auth, post_json("/sign-in/email", signin_body.clone())).await;
    let _ = ref_client
        .post_full("/sign-in/email", &signin_body)
        .await
        .unwrap_or_else(ref_error_response);
    let rust_token = response_token(&rust_signin.body);

    let mut reports = Vec::new();
    let rust = rust_send(&auth, post_with_auth("/revoke-sessions", &rust_token)).await;
    let reference = ref_client
        .post_full("/revoke-sessions", &serde_json::json!({}))
        .await
        .unwrap_or_else(ref_error_response);
    reports.push(compare_full(
        "POST /revoke-sessions (happy path)",
        &rust,
        &reference,
    ));

    let rust = rust_send(&auth, post_json("/revoke-sessions", serde_json::json!({}))).await;
    let mut unauth_ref = RefClient::new();
    let reference = unauth_ref
        .post_full("/revoke-sessions", &serde_json::json!({}))
        .await
        .unwrap_or_else(ref_error_response);
    reports.push(compare_full(
        "POST /revoke-sessions (no auth)",
        &rust,
        &reference,
    ));

    print_report("Phase 1", &reports);
    log_alignment_gaps(&reports);
}

#[tokio::test]
async fn phase1_revoke_other_sessions_cases() {
    let _lock = serial_lock().await;
    if !ensure_reference_server_or_skip().await {
        return;
    }

    let auth = create_default_test_auth().await;
    let mut ref_client = RefClient::new();
    let (email, _rust_token, _rust_user_id) =
        signup_on_both(&auth, &mut ref_client, "p1_revoke_other_sessions").await;
    let signin_body = serde_json::json!({
        "email": email,
        "password": "password123",
    });
    let rust_signin = rust_send(&auth, post_json("/sign-in/email", signin_body.clone())).await;
    let _ = ref_client
        .post_full("/sign-in/email", &signin_body)
        .await
        .unwrap_or_else(ref_error_response);
    let rust_token = response_token(&rust_signin.body);

    let mut reports = Vec::new();
    let rust = rust_send(&auth, post_with_auth("/revoke-other-sessions", &rust_token)).await;
    let reference = ref_client
        .post_full("/revoke-other-sessions", &serde_json::json!({}))
        .await
        .unwrap_or_else(ref_error_response);
    reports.push(compare_full(
        "POST /revoke-other-sessions (happy path)",
        &rust,
        &reference,
    ));

    let rust = rust_send(
        &auth,
        post_json("/revoke-other-sessions", serde_json::json!({})),
    )
    .await;
    let mut unauth_ref = RefClient::new();
    let reference = unauth_ref
        .post_full("/revoke-other-sessions", &serde_json::json!({}))
        .await
        .unwrap_or_else(ref_error_response);
    reports.push(compare_full(
        "POST /revoke-other-sessions (no auth)",
        &rust,
        &reference,
    ));

    print_report("Phase 1", &reports);
    log_alignment_gaps(&reports);
}

#[tokio::test]
async fn phase1_get_access_token_cases() {
    let _lock = serial_lock().await;
    if !ensure_reference_server_or_skip().await {
        return;
    }

    reset_reference_state()
        .await
        .unwrap_or_else(|error| panic!("reference state reset should succeed: {error}"));

    let auth = create_default_test_auth().await;
    let mut ref_client = RefClient::new();
    let (email, rust_token, rust_user_id) =
        signup_on_both(&auth, &mut ref_client, "p1_get_access_token").await;
    let mut reports = Vec::new();

    let valid_seed = OAuthSeed::valid(&email);
    seed_rust_oauth_account(&auth, &rust_user_id, &valid_seed).await;
    ref_seed_oauth_account(&valid_seed)
        .await
        .unwrap_or_else(|error| panic!("reference oauth seed should succeed: {error}"));
    let body = serde_json::json!({ "providerId": "mock" });
    let rust = rust_send(
        &auth,
        post_json_with_auth("/get-access-token", body.clone(), &rust_token),
    )
    .await;
    let reference = ref_client
        .post_full("/get-access-token", &body)
        .await
        .unwrap_or_else(ref_error_response);
    reports.push(compare_full(
        "POST /get-access-token (valid stored token)",
        &rust,
        &reference,
    ));

    let auth_refresh = create_default_test_auth().await;
    let mut ref_refresh = RefClient::new();
    let (email, rust_token, rust_user_id) = signup_on_both(
        &auth_refresh,
        &mut ref_refresh,
        "p1_get_access_token_refresh",
    )
    .await;
    let expired_seed = OAuthSeed::expired(&email);
    seed_rust_oauth_account(&auth_refresh, &rust_user_id, &expired_seed).await;
    ref_seed_oauth_account(&expired_seed)
        .await
        .unwrap_or_else(|error| panic!("reference oauth seed should succeed: {error}"));
    let rust = rust_send(
        &auth_refresh,
        post_json_with_auth("/get-access-token", body.clone(), &rust_token),
    )
    .await;
    let reference = ref_refresh
        .post_full("/get-access-token", &body)
        .await
        .unwrap_or_else(ref_error_response);
    reports.push(compare_full(
        "POST /get-access-token (refresh expired token)",
        &rust,
        &reference,
    ));

    let rust = rust_send(
        &auth_refresh,
        post_json_with_auth(
            "/get-access-token",
            serde_json::json!({ "providerId": "unknown" }),
            &rust_token,
        ),
    )
    .await;
    let reference = ref_refresh
        .post_full(
            "/get-access-token",
            &serde_json::json!({ "providerId": "unknown" }),
        )
        .await
        .unwrap_or_else(ref_error_response);
    reports.push(compare_full(
        "POST /get-access-token (unsupported provider)",
        &rust,
        &reference,
    ));

    let rust = rust_send(
        &auth_refresh,
        post_json_with_auth(
            "/get-access-token",
            serde_json::json!({
                "providerId": "mock",
                "accountId": "missing-account",
            }),
            &rust_token,
        ),
    )
    .await;
    let reference = ref_refresh
        .post_full(
            "/get-access-token",
            &serde_json::json!({
                "providerId": "mock",
                "accountId": "missing-account",
            }),
        )
        .await
        .unwrap_or_else(ref_error_response);
    reports.push(compare_full(
        "POST /get-access-token (account not found)",
        &rust,
        &reference,
    ));

    let rust = rust_send(&auth_refresh, post_json("/get-access-token", body.clone())).await;
    let mut unauth_ref = RefClient::new();
    let reference = unauth_ref
        .post_full("/get-access-token", &body)
        .await
        .unwrap_or_else(ref_error_response);
    reports.push(compare_full(
        "POST /get-access-token (no auth)",
        &rust,
        &reference,
    ));

    set_reference_oauth_refresh_mode(ControlMode::Error)
        .await
        .unwrap_or_else(|error| panic!("reference oauth refresh mode should set: {error}"));
    let auth_fail = create_default_test_auth().await;
    let mut ref_fail = RefClient::new();
    let (email, rust_token, rust_user_id) =
        signup_on_both(&auth_fail, &mut ref_fail, "p1_get_access_token_fail").await;
    let failed_seed = OAuthSeed::expired(&email);
    seed_rust_oauth_account(&auth_fail, &rust_user_id, &failed_seed).await;
    ref_seed_oauth_account(&failed_seed)
        .await
        .unwrap_or_else(|error| panic!("reference oauth seed should succeed: {error}"));
    let rust = rust_send(
        &auth_fail,
        post_json_with_auth("/get-access-token", body.clone(), &rust_token),
    )
    .await;
    let reference = ref_fail
        .post_full("/get-access-token", &body)
        .await
        .unwrap_or_else(ref_error_response);
    reports.push(compare_full(
        "POST /get-access-token (refresh failure)",
        &rust,
        &reference,
    ));

    print_report("Phase 1", &reports);
    log_alignment_gaps(&reports);

    reset_reference_state()
        .await
        .unwrap_or_else(|error| panic!("reference state reset should succeed: {error}"));
}

#[tokio::test]
async fn phase1_refresh_token_cases() {
    let _lock = serial_lock().await;
    if !ensure_reference_server_or_skip().await {
        return;
    }

    reset_reference_state()
        .await
        .unwrap_or_else(|error| panic!("reference state reset should succeed: {error}"));

    let auth = create_default_test_auth().await;
    let mut ref_client = RefClient::new();
    let (email, rust_token, rust_user_id) =
        signup_on_both(&auth, &mut ref_client, "p1_refresh_token").await;
    let valid_seed = OAuthSeed::expired(&email);
    seed_rust_oauth_account(&auth, &rust_user_id, &valid_seed).await;
    ref_seed_oauth_account(&valid_seed)
        .await
        .unwrap_or_else(|error| panic!("reference oauth seed should succeed: {error}"));

    let body = serde_json::json!({ "providerId": "mock" });
    let mut reports = Vec::new();

    let rust = rust_send(
        &auth,
        post_json_with_auth("/refresh-token", body.clone(), &rust_token),
    )
    .await;
    let reference = ref_client
        .post_full("/refresh-token", &body)
        .await
        .unwrap_or_else(ref_error_response);
    reports.push(compare_full(
        "POST /refresh-token (happy path)",
        &rust,
        &reference,
    ));

    let rust = rust_send(&auth, post_json("/refresh-token", body.clone())).await;
    let mut unauth_ref = RefClient::new();
    let reference = unauth_ref
        .post_full("/refresh-token", &body)
        .await
        .unwrap_or_else(ref_error_response);
    reports.push(compare_full(
        "POST /refresh-token (no auth)",
        &rust,
        &reference,
    ));

    let rust = rust_send(
        &auth,
        post_json_with_auth(
            "/refresh-token",
            serde_json::json!({
                "providerId": "unknown",
                "accountId": "mock-account-id",
            }),
            &rust_token,
        ),
    )
    .await;
    let reference = ref_client
        .post_full(
            "/refresh-token",
            &serde_json::json!({
                "providerId": "unknown",
                "accountId": "mock-account-id",
            }),
        )
        .await
        .unwrap_or_else(ref_error_response);
    reports.push(compare_full(
        "POST /refresh-token (unsupported provider)",
        &rust,
        &reference,
    ));

    let rust = rust_send(
        &auth,
        post_json_with_auth(
            "/refresh-token",
            serde_json::json!({
                "providerId": "mock",
                "accountId": "missing-account",
            }),
            &rust_token,
        ),
    )
    .await;
    let reference = ref_client
        .post_full(
            "/refresh-token",
            &serde_json::json!({
                "providerId": "mock",
                "accountId": "missing-account",
            }),
        )
        .await
        .unwrap_or_else(ref_error_response);
    reports.push(compare_full(
        "POST /refresh-token (account not found)",
        &rust,
        &reference,
    ));

    let auth_missing = create_default_test_auth().await;
    let mut ref_missing = RefClient::new();
    let (email, rust_token, rust_user_id) = signup_on_both(
        &auth_missing,
        &mut ref_missing,
        "p1_refresh_token_missing_refresh",
    )
    .await;
    let missing_seed = OAuthSeed {
        refresh_token: None,
        ..OAuthSeed::expired(&email)
    };
    seed_rust_oauth_account(&auth_missing, &rust_user_id, &missing_seed).await;
    ref_seed_oauth_account(&missing_seed)
        .await
        .unwrap_or_else(|error| panic!("reference oauth seed should succeed: {error}"));
    let rust = rust_send(
        &auth_missing,
        post_json_with_auth("/refresh-token", body.clone(), &rust_token),
    )
    .await;
    let reference = ref_missing
        .post_full("/refresh-token", &body)
        .await
        .unwrap_or_else(ref_error_response);
    reports.push(compare_full(
        "POST /refresh-token (missing refresh token)",
        &rust,
        &reference,
    ));

    set_reference_oauth_refresh_mode(ControlMode::Error)
        .await
        .unwrap_or_else(|error| panic!("reference oauth refresh mode should set: {error}"));
    let auth_fail = create_default_test_auth().await;
    let mut ref_fail = RefClient::new();
    let (email, rust_token, rust_user_id) =
        signup_on_both(&auth_fail, &mut ref_fail, "p1_refresh_token_fail").await;
    let failed_seed = OAuthSeed::expired(&email);
    seed_rust_oauth_account(&auth_fail, &rust_user_id, &failed_seed).await;
    ref_seed_oauth_account(&failed_seed)
        .await
        .unwrap_or_else(|error| panic!("reference oauth seed should succeed: {error}"));
    let rust = rust_send(
        &auth_fail,
        post_json_with_auth("/refresh-token", body.clone(), &rust_token),
    )
    .await;
    let reference = ref_fail
        .post_full("/refresh-token", &body)
        .await
        .unwrap_or_else(ref_error_response);
    reports.push(compare_full(
        "POST /refresh-token (refresh failure)",
        &rust,
        &reference,
    ));

    print_report("Phase 1", &reports);
    log_alignment_gaps(&reports);

    reset_reference_state()
        .await
        .unwrap_or_else(|error| panic!("reference state reset should succeed: {error}"));
}
