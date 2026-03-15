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

#[tokio::test]
async fn phase0_ok_endpoint() {
    let _lock = serial_lock().await;
    if !ensure_reference_server_or_skip().await {
        return;
    }

    let auth = create_default_test_auth().await;
    let rust = rust_send(&auth, get_request("/ok")).await;
    let mut ref_client = RefClient::new();
    let reference = ref_client
        .get_full("/ok")
        .await
        .unwrap_or_else(ref_error_response);

    let report = compare_full("GET /ok (happy path)", &rust, &reference);
    print_report("Phase 0", &[report]);
}

#[tokio::test]
async fn phase0_error_endpoint() {
    let _lock = serial_lock().await;
    if !ensure_reference_server_or_skip().await {
        return;
    }

    let auth = create_default_test_auth().await;
    let rust = rust_send(&auth, get_request("/error")).await;
    let mut ref_client = RefClient::new();
    let reference = ref_client
        .get_full("/error")
        .await
        .unwrap_or_else(ref_error_response);

    let report = compare_full("GET /error", &rust, &reference);
    print_report("Phase 0", &[report]);
}

#[tokio::test]
async fn phase0_signup_email() {
    let _lock = serial_lock().await;
    if !ensure_reference_server_or_skip().await {
        return;
    }

    let auth = create_default_test_auth().await;
    let mut ref_client = RefClient::new();
    let mut reports = Vec::new();

    for (name, body) in [
        (
            "happy path",
            serde_json::json!({
                "name": "Test User",
                "email": unique_email("p0_signup_happy"),
                "password": "password123",
            }),
        ),
        (
            "missing password",
            serde_json::json!({
                "name": "Test User",
                "email": unique_email("p0_signup_missing_password"),
            }),
        ),
        (
            "missing email",
            serde_json::json!({
                "name": "Test User",
                "password": "password123",
            }),
        ),
        (
            "invalid email",
            serde_json::json!({
                "name": "Test User",
                "email": "not-an-email",
                "password": "password123",
            }),
        ),
        ("empty body", serde_json::json!({})),
    ] {
        let rust = rust_send(&auth, post_json("/sign-up/email", body.clone())).await;
        let reference = ref_client
            .post_full("/sign-up/email", &body)
            .await
            .unwrap_or_else(ref_error_response);
        reports.push(compare_full(
            &format!("POST /sign-up/email ({name})"),
            &rust,
            &reference,
        ));
    }

    let email = unique_email("p0_signup_dup");
    let body = serde_json::json!({
        "name": "Test User",
        "email": email,
        "password": "password123",
    });
    let _ = rust_send(&auth, post_json("/sign-up/email", body.clone())).await;
    let _ = ref_client.post_full("/sign-up/email", &body).await;
    let rust = rust_send(&auth, post_json("/sign-up/email", body.clone())).await;
    let reference = ref_client
        .post_full("/sign-up/email", &body)
        .await
        .unwrap_or_else(ref_error_response);
    reports.push(compare_full(
        "POST /sign-up/email (duplicate user)",
        &rust,
        &reference,
    ));

    print_report("Phase 0", &reports);
    log_alignment_gaps(&reports);
}

#[tokio::test]
async fn phase0_signin_email() {
    let _lock = serial_lock().await;
    if !ensure_reference_server_or_skip().await {
        return;
    }

    let auth = create_default_test_auth().await;
    let mut ref_client = RefClient::new();
    let email = unique_email("p0_signin");
    let signup_body = serde_json::json!({
        "name": "Signin Test",
        "email": email,
        "password": "password123",
    });
    let _ = rust_send(&auth, post_json("/sign-up/email", signup_body.clone())).await;
    let _ = ref_client.post_full("/sign-up/email", &signup_body).await;

    let mut reports = Vec::new();
    for (name, body) in [
        (
            "happy path",
            serde_json::json!({
                "email": email,
                "password": "password123",
            }),
        ),
        (
            "wrong password",
            serde_json::json!({
                "email": email,
                "password": "wrongpassword",
            }),
        ),
        (
            "non-existent user",
            serde_json::json!({
                "email": unique_email("p0_signin_fake"),
                "password": "password123",
            }),
        ),
        (
            "missing email",
            serde_json::json!({
                "password": "password123",
            }),
        ),
        ("empty body", serde_json::json!({})),
    ] {
        let rust = rust_send(&auth, post_json("/sign-in/email", body.clone())).await;
        let reference = ref_client
            .post_full("/sign-in/email", &body)
            .await
            .unwrap_or_else(ref_error_response);
        reports.push(compare_full(
            &format!("POST /sign-in/email ({name})"),
            &rust,
            &reference,
        ));
    }

    print_report("Phase 0", &reports);
    log_alignment_gaps(&reports);
}

#[tokio::test]
async fn phase0_get_session() {
    let _lock = serial_lock().await;
    if !ensure_reference_server_or_skip().await {
        return;
    }

    let auth = create_default_test_auth().await;
    let mut ref_client = RefClient::new();
    let mut reports = Vec::new();

    let rust = rust_send(&auth, get_request("/get-session")).await;
    let reference = ref_client
        .get_full("/get-session")
        .await
        .unwrap_or_else(ref_error_response);
    reports.push(compare_full(
        "GET /get-session (no auth)",
        &rust,
        &reference,
    ));

    let email = unique_email("p0_getsess");
    let signup_body = serde_json::json!({
        "name": "Session Test",
        "email": email,
        "password": "password123",
    });
    let rust_signup = rust_send(&auth, post_json("/sign-up/email", signup_body.clone())).await;
    let _ = ref_client.post_full("/sign-up/email", &signup_body).await;
    let rust_token = rust_signup
        .body
        .get("token")
        .and_then(|token| token.as_str())
        .unwrap_or("")
        .to_string();

    let rust = rust_send(&auth, get_with_auth("/get-session", &rust_token)).await;
    let reference = ref_client
        .get_full("/get-session")
        .await
        .unwrap_or_else(ref_error_response);
    reports.push(compare_full(
        "GET /get-session (with auth)",
        &rust,
        &reference,
    ));

    let rust = rust_send(&auth, get_with_auth("/get-session", "invalid-token-xxx")).await;
    let mut bad_ref = RefClient::new();
    bad_ref.session_cookie = Some("invalid-token-xxx".to_string());
    let reference = bad_ref
        .get_full("/get-session")
        .await
        .unwrap_or_else(ref_error_response);
    reports.push(compare_full(
        "GET /get-session (invalid token)",
        &rust,
        &reference,
    ));

    print_report("Phase 0", &reports);
    log_alignment_gaps(&reports);
}

#[tokio::test]
async fn phase0_sign_out() {
    let _lock = serial_lock().await;
    if !ensure_reference_server_or_skip().await {
        return;
    }

    let auth = create_default_test_auth().await;
    let mut ref_client = RefClient::new();
    let mut reports = Vec::new();

    let rust = rust_send(&auth, post_with_auth("/sign-out", "")).await;
    let mut no_auth_ref = RefClient::new();
    let reference = no_auth_ref
        .post_full("/sign-out", &serde_json::json!({}))
        .await
        .unwrap_or_else(ref_error_response);
    reports.push(compare_full("POST /sign-out (no auth)", &rust, &reference));

    let email = unique_email("p0_signout");
    let signup_body = serde_json::json!({
        "name": "Signout Test",
        "email": email,
        "password": "password123",
    });
    let rust_signup = rust_send(&auth, post_json("/sign-up/email", signup_body.clone())).await;
    let _ = ref_client.post_full("/sign-up/email", &signup_body).await;
    let rust_token = rust_signup
        .body
        .get("token")
        .and_then(|token| token.as_str())
        .unwrap_or("")
        .to_string();

    let rust = rust_send(&auth, post_with_auth("/sign-out", &rust_token)).await;
    let reference = ref_client
        .post_full("/sign-out", &serde_json::json!({}))
        .await
        .unwrap_or_else(ref_error_response);
    reports.push(compare_full(
        "POST /sign-out (with auth)",
        &rust,
        &reference,
    ));

    print_report("Phase 0", &reports);
    log_alignment_gaps(&reports);
}

#[tokio::test]
async fn phase0_comprehensive_alignment_report() {
    let _lock = serial_lock().await;
    if !ensure_reference_server_or_skip().await {
        return;
    }

    let auth = create_default_test_auth().await;
    let mut ref_client = RefClient::new();
    let mut reports = Vec::new();

    let email = unique_email("p0_comprehensive");
    let signup_body = serde_json::json!({
        "name": "Phase0 Comprehensive",
        "email": email,
        "password": "password123",
    });
    let rust_signup = rust_send(&auth, post_json("/sign-up/email", signup_body.clone())).await;
    let ref_signup = ref_client
        .post_full("/sign-up/email", &signup_body)
        .await
        .unwrap_or_else(ref_error_response);
    reports.push(compare_full(
        "POST /sign-up/email",
        &rust_signup,
        &ref_signup,
    ));

    let signin_body = serde_json::json!({
        "email": email,
        "password": "password123",
    });
    let rust_signin = rust_send(&auth, post_json("/sign-in/email", signin_body.clone())).await;
    let ref_signin = ref_client
        .post_full("/sign-in/email", &signin_body)
        .await
        .unwrap_or_else(ref_error_response);
    reports.push(compare_full(
        "POST /sign-in/email",
        &rust_signin,
        &ref_signin,
    ));

    let rust_token = rust_signin
        .body
        .get("token")
        .and_then(|token| token.as_str())
        .unwrap_or("")
        .to_string();

    for (name, req, path) in [
        ("GET /ok", get_request("/ok"), "/ok"),
        ("GET /error", get_request("/error"), "/error"),
        (
            "GET /get-session",
            get_with_auth("/get-session", &rust_token),
            "/get-session",
        ),
    ] {
        let rust = rust_send(&auth, req).await;
        let reference = ref_client
            .get_full(path)
            .await
            .unwrap_or_else(ref_error_response);
        reports.push(compare_full(name, &rust, &reference));
    }

    let rust = rust_send(&auth, post_with_auth("/sign-out", &rust_token)).await;
    let reference = ref_client
        .post_full("/sign-out", &serde_json::json!({}))
        .await
        .unwrap_or_else(ref_error_response);
    reports.push(compare_full("POST /sign-out", &rust, &reference));

    print_report("Phase 0", &reports);
    log_alignment_gaps(&reports);
}
