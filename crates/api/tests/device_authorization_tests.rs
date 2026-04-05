use std::sync::Arc;

use better_auth_api::DeviceAuthorizationPlugin;
use better_auth_core::adapters::{MemoryDatabaseAdapter, UserOps, VerificationOps};
use better_auth_core::{
    AuthConfig, AuthContext, AuthPlugin, AuthRequest, CreateUser, HttpMethod, Session, User,
};
use serde_json::{Value, json};

const TEST_SECRET: &str = "test-secret-key-that-is-at-least-32-characters-long";

fn create_test_context() -> AuthContext<MemoryDatabaseAdapter> {
    let config = Arc::new(AuthConfig::new(TEST_SECRET));
    let database = Arc::new(MemoryDatabaseAdapter::new());
    AuthContext::new(config, database)
}

async fn create_authenticated_user(
    ctx: &AuthContext<MemoryDatabaseAdapter>,
    email: &str,
) -> (User, Session) {
    let user = ctx
        .database
        .create_user(CreateUser::new().with_email(email).with_name("Device User"))
        .await
        .unwrap();

    let session = ctx
        .session_manager()
        .create_session(&user, None, None)
        .await
        .unwrap();

    (user, session)
}

fn create_json_request(
    method: HttpMethod,
    path: &str,
    token: Option<&str>,
    body: Value,
) -> AuthRequest {
    let mut req = AuthRequest::new(method, path);
    req.body = Some(serde_json::to_vec(&body).unwrap());
    req.headers
        .insert("content-type".to_string(), "application/json".to_string());

    if let Some(token) = token {
        req.headers
            .insert("authorization".to_string(), format!("Bearer {token}"));
    }

    req
}

fn json_body(response: &better_auth_core::AuthResponse) -> Value {
    serde_json::from_slice(&response.body).unwrap()
}

fn device_code_identifier(device_code: &str) -> String {
    format!("device_code:{device_code}")
}

fn user_code_identifier(user_code: &str) -> String {
    format!("user_code:{user_code}")
}

async fn issue_device_code(
    plugin: &DeviceAuthorizationPlugin,
    ctx: &AuthContext<MemoryDatabaseAdapter>,
) -> (String, String) {
    let req = create_json_request(
        HttpMethod::Post,
        "/device/code",
        None,
        json!({
            "client_id": "living-room-tv",
            "scope": "openid profile",
        }),
    );

    let response = plugin
        .on_request(&req, ctx)
        .await
        .unwrap()
        .expect("device code response");

    assert_eq!(response.status, 200);
    let body = json_body(&response);
    (
        body["device_code"].as_str().unwrap().to_string(),
        body["user_code"].as_str().unwrap().to_string(),
    )
}

#[tokio::test]
async fn device_code_endpoint_returns_expected_payload_and_persists_codes() {
    let ctx = create_test_context();
    let plugin = DeviceAuthorizationPlugin::new()
        .enabled(true)
        .verification_uri("/activate")
        .interval(7)
        .expires_in(300);

    let req = create_json_request(
        HttpMethod::Post,
        "/device/code",
        None,
        json!({
            "client_id": "living-room-tv",
            "scope": "openid profile",
        }),
    );

    let response = plugin.on_request(&req, &ctx).await.unwrap().unwrap();
    assert_eq!(response.status, 200);

    let body = json_body(&response);
    let device_code = body["device_code"].as_str().unwrap();
    let user_code = body["user_code"].as_str().unwrap();

    assert_eq!(body["verification_uri"], "/activate");
    assert_eq!(body["expires_in"], 300);
    assert_eq!(body["interval"], 7);
    assert_eq!(device_code.len(), 40);
    assert_eq!(user_code.len(), 8);
    assert!(
        user_code
            .chars()
            .all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit())
    );

    assert!(
        ctx.database
            .get_verification_by_identifier(&device_code_identifier(device_code))
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        ctx.database
            .get_verification_by_identifier(&user_code_identifier(user_code))
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn token_endpoint_returns_authorization_pending_until_approved() {
    let ctx = create_test_context();
    let plugin = DeviceAuthorizationPlugin::new().enabled(true).interval(0);
    let (device_code, _) = issue_device_code(&plugin, &ctx).await;

    let req = create_json_request(
        HttpMethod::Post,
        "/device/token",
        None,
        json!({ "device_code": device_code }),
    );

    let err = plugin.on_request(&req, &ctx).await.unwrap_err();
    assert_eq!(err.status_code(), 400);
    assert_eq!(err.to_string(), "authorization_pending");
}

#[tokio::test]
async fn approve_flow_exchanges_device_code_for_a_single_session_token() {
    let ctx = create_test_context();
    let plugin = DeviceAuthorizationPlugin::new().enabled(true).interval(0);
    let (user, session) = create_authenticated_user(&ctx, "approve@example.com").await;
    let (device_code, user_code) = issue_device_code(&plugin, &ctx).await;

    let approve_req = create_json_request(
        HttpMethod::Post,
        "/device/approve",
        Some(&session.token),
        json!({ "userCode": user_code.clone() }),
    );

    let approve_response = plugin
        .on_request(&approve_req, &ctx)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(approve_response.status, 200);
    assert_eq!(json_body(&approve_response)["status"], true);
    assert!(
        ctx.database
            .get_verification_by_identifier(&user_code_identifier(&user_code))
            .await
            .unwrap()
            .is_none()
    );

    let token_req = create_json_request(
        HttpMethod::Post,
        "/device/token",
        None,
        json!({ "device_code": device_code.clone() }),
    );

    let token_response = plugin.on_request(&token_req, &ctx).await.unwrap().unwrap();
    assert_eq!(token_response.status, 200);

    let access_token = json_body(&token_response)["access_token"]
        .as_str()
        .unwrap()
        .to_string();
    let exchanged_session = ctx
        .session_manager()
        .get_session(&access_token)
        .await
        .unwrap()
        .expect("session created for approved device");

    assert_eq!(exchanged_session.user_id, user.id);
    assert!(
        ctx.database
            .get_verification_by_identifier(&device_code_identifier(&device_code))
            .await
            .unwrap()
            .is_none()
    );

    let second_token_req = create_json_request(
        HttpMethod::Post,
        "/device/token",
        None,
        json!({ "device_code": device_code }),
    );
    let err = plugin
        .on_request(&second_token_req, &ctx)
        .await
        .unwrap_err();
    assert_eq!(err.to_string(), "invalid_grant");
}

#[tokio::test]
async fn deny_flow_requires_authentication_and_blocks_token_exchange() {
    let ctx = create_test_context();
    let plugin = DeviceAuthorizationPlugin::new().enabled(true).interval(0);
    let (_, session) = create_authenticated_user(&ctx, "deny@example.com").await;
    let (device_code, user_code) = issue_device_code(&plugin, &ctx).await;

    let unauthenticated_deny_req = create_json_request(
        HttpMethod::Post,
        "/device/deny",
        None,
        json!({ "userCode": user_code.clone() }),
    );
    let err = plugin
        .on_request(&unauthenticated_deny_req, &ctx)
        .await
        .unwrap_err();
    assert_eq!(err.status_code(), 401);

    let deny_req = create_json_request(
        HttpMethod::Post,
        "/device/deny",
        Some(&session.token),
        json!({ "userCode": user_code }),
    );

    let deny_response = plugin.on_request(&deny_req, &ctx).await.unwrap().unwrap();
    assert_eq!(deny_response.status, 200);
    assert_eq!(json_body(&deny_response)["status"], true);

    let token_req = create_json_request(
        HttpMethod::Post,
        "/device/token",
        None,
        json!({ "device_code": device_code }),
    );
    let err = plugin.on_request(&token_req, &ctx).await.unwrap_err();
    assert_eq!(err.status_code(), 400);
    assert_eq!(err.to_string(), "access_denied");
}

#[tokio::test]
async fn disabled_plugin_returns_not_found_for_device_routes() {
    let ctx = create_test_context();
    let plugin = DeviceAuthorizationPlugin::new();

    let req = create_json_request(
        HttpMethod::Post,
        "/device/code",
        None,
        json!({ "client_id": "living-room-tv" }),
    );

    let err = plugin.on_request(&req, &ctx).await.unwrap_err();
    assert_eq!(err.status_code(), 404);
    assert_eq!(err.to_string(), "Not found");
}
