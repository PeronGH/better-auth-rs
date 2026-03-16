use axum::{
    Json, Router,
    extract::Query,
    response::IntoResponse,
    routing::{get, post},
};
use better_auth::handlers::axum::AxumIntegration;
use better_auth::plugins::{
    AccountManagementPlugin, EmailPasswordPlugin, EmailVerificationPlugin, OAuthPlugin,
    PasswordManagementPlugin, SessionManagementPlugin, UserManagementPlugin,
    email_verification::SendVerificationEmail, user_management::SendChangeEmailConfirmation,
    oauth::{OAuthProvider, OAuthUserInfo},
    password_management::SendResetPassword,
};
use better_auth::{
    AuthAccount, AuthBuilder, AuthConfig, AuthUser, CreateAccount, CreateVerification, run_migrations,
    sea_orm::Database,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::Mutex;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResetPasswordMode {
    Capture,
    Fail,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OAuthRefreshMode {
    Success,
    Error,
}

#[derive(Clone)]
struct CompatResetSender {
    outbox: Arc<Mutex<HashMap<String, String>>>,
    mode: Arc<Mutex<ResetPasswordMode>>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct EmailOutboxRecord {
    url: String,
    token: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ChangeEmailOutboxRecord {
    new_email: String,
    url: String,
    token: String,
}

#[async_trait::async_trait]
impl SendResetPassword for CompatResetSender {
    async fn send(
        &self,
        user: &serde_json::Value,
        _url: &str,
        token: &str,
    ) -> better_auth::AuthResult<()> {
        if *self.mode.lock().await == ResetPasswordMode::Fail {
            return Err(better_auth::AuthError::internal(
                "compat reset sender failure".to_string(),
            ));
        }

        if let Some(email) = user.get("email").and_then(|value| value.as_str()) {
            self.outbox
                .lock()
                .await
                .insert(email.to_string(), token.to_string());
        }
        Ok(())
    }
}

#[derive(Clone)]
struct CompatVerificationSender {
    outbox: Arc<Mutex<HashMap<String, EmailOutboxRecord>>>,
}

#[async_trait::async_trait]
impl SendVerificationEmail for CompatVerificationSender {
    async fn send(
        &self,
        user: &better_auth::User,
        url: &str,
        token: &str,
    ) -> better_auth::AuthResult<()> {
        if let Some(email) = user.email() {
            self.outbox.lock().await.insert(
                email.to_string(),
                EmailOutboxRecord {
                    url: url.to_string(),
                    token: token.to_string(),
                },
            );
        }
        Ok(())
    }
}

#[derive(Clone)]
struct CompatChangeEmailSender {
    verification_outbox: Arc<Mutex<HashMap<String, EmailOutboxRecord>>>,
    outbox: Arc<Mutex<HashMap<String, ChangeEmailOutboxRecord>>>,
}

#[async_trait::async_trait]
impl SendChangeEmailConfirmation for CompatChangeEmailSender {
    async fn send(
        &self,
        user: &better_auth::plugins::user_management::UserInfo,
        new_email: &str,
        url: &str,
        token: &str,
    ) -> better_auth::AuthResult<()> {
        if user.email_verified {
            if let Some(email) = &user.email {
                self.outbox.lock().await.insert(
                    email.clone(),
                    ChangeEmailOutboxRecord {
                        new_email: new_email.to_string(),
                        url: url.to_string(),
                        token: token.to_string(),
                    },
                );
            }
        } else {
            self.verification_outbox.lock().await.insert(
                new_email.to_string(),
                EmailOutboxRecord {
                    url: url.to_string(),
                    token: token.to_string(),
                },
            );
        }
        Ok(())
    }
}

#[derive(Deserialize)]
struct ResetTokenQuery {
    email: String,
}

#[derive(Deserialize)]
struct EmailQuery {
    email: String,
}

#[derive(Deserialize)]
struct ModeRequest {
    mode: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SeedResetPasswordRequest {
    email: String,
    token: String,
    expires_at: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SeedDeleteUserTokenRequest {
    email: String,
    token: String,
    expires_at: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RemoveCredentialAccountRequest {
    email: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SeedOAuthAccountRequest {
    email: String,
    provider_id: Option<String>,
    account_id: Option<String>,
    access_token: Option<String>,
    refresh_token: Option<String>,
    id_token: Option<String>,
    access_token_expires_at: Option<String>,
    refresh_token_expires_at: Option<String>,
    scope: Option<String>,
}

fn parse_rfc3339(value: &str) -> Result<DateTime<Utc>, chrono::ParseError> {
    DateTime::parse_from_rfc3339(value).map(|value| value.with_timezone(&Utc))
}

fn mock_oauth_plugin(port: u16) -> OAuthPlugin {
    OAuthPlugin::new().add_provider(
        "mock",
        OAuthProvider {
            client_id: "mock-client-id".to_string(),
            client_secret: "mock-client-secret".to_string(),
            auth_url: format!("http://127.0.0.1:{port}/__test/oauth/authorize"),
            token_url: format!("http://127.0.0.1:{port}/__test/oauth/token"),
            user_info_url: format!("http://127.0.0.1:{port}/__test/oauth/userinfo"),
            scopes: vec![
                "openid".to_string(),
                "email".to_string(),
                "profile".to_string(),
            ],
            map_user_info: |_value| {
                Ok(OAuthUserInfo {
                    id: "mock-account-id".to_string(),
                    email: "mock@example.com".to_string(),
                    name: Some("Mock OAuth User".to_string()),
                    image: None,
                    email_verified: true,
                })
            },
        },
    )
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(3200);

    let secret = "compat-test-only-key-not-real-minimum-32chars";
    let config = AuthConfig::new(secret)
        .base_url(format!("http://localhost:{port}"))
        .password_min_length(8);

    let database = Database::connect("sqlite::memory:").await?;
    run_migrations(&database).await?;

    let reset_outbox = Arc::new(Mutex::new(HashMap::new()));
    let verification_outbox = Arc::new(Mutex::new(HashMap::new()));
    let change_email_outbox = Arc::new(Mutex::new(HashMap::new()));
    let reset_password_mode = Arc::new(Mutex::new(ResetPasswordMode::Capture));
    let oauth_refresh_mode = Arc::new(Mutex::new(OAuthRefreshMode::Success));

    let auth = Arc::new(
        AuthBuilder::new(config)
            .database(database)
            .plugin(EmailPasswordPlugin::new().enable_signup(true))
            .plugin(SessionManagementPlugin::new())
            .plugin(AccountManagementPlugin::new())
            .plugin(
                PasswordManagementPlugin::new().send_reset_password(Arc::new(CompatResetSender {
                    outbox: reset_outbox.clone(),
                    mode: reset_password_mode.clone(),
                })),
            )
            .plugin(
                EmailVerificationPlugin::new()
                    .custom_send_verification_email(Arc::new(CompatVerificationSender {
                        outbox: verification_outbox.clone(),
                    })),
            )
            .plugin(
                UserManagementPlugin::new()
                    .change_email_enabled(true)
                    .send_change_email_confirmation(Arc::new(CompatChangeEmailSender {
                        verification_outbox: verification_outbox.clone(),
                        outbox: change_email_outbox.clone(),
                    }))
                    .delete_user_enabled(true)
                    .require_delete_verification(false),
            )
            .plugin(mock_oauth_plugin(port))
            .build()
            .await?,
    );

    let auth_router = auth.clone().axum_router();

    let reset_outbox_for_token = reset_outbox.clone();
    let reset_outbox_for_reset = reset_outbox.clone();
    let verification_outbox_for_get = verification_outbox.clone();
    let verification_outbox_for_reset = verification_outbox.clone();
    let change_email_outbox_for_get = change_email_outbox.clone();
    let change_email_outbox_for_reset = change_email_outbox.clone();
    let reset_mode_for_reset = reset_password_mode.clone();
    let reset_mode_for_set = reset_password_mode.clone();
    let oauth_mode_for_reset = oauth_refresh_mode.clone();
    let oauth_mode_for_set = oauth_refresh_mode.clone();
    let auth_for_reset_seed = auth.clone();
    let auth_for_delete_seed = auth.clone();
    let auth_for_remove_credential = auth.clone();
    let auth_for_oauth_seed = auth.clone();

    let app = Router::new()
        .route("/__health", get(health_check))
        .route(
            "/__test/verification-email",
            get(move |Query(query): Query<EmailQuery>| {
                let verification_outbox = verification_outbox_for_get.clone();
                async move {
                    let record = verification_outbox.lock().await.get(&query.email).cloned();
                    match record {
                        Some(record) => (
                            axum::http::StatusCode::OK,
                            Json(serde_json::to_value(record).unwrap()),
                        ),
                        None => (
                            axum::http::StatusCode::NOT_FOUND,
                            Json(serde_json::json!({ "message": "Not found" })),
                        ),
                    }
                }
            }),
        )
        .route(
            "/__test/change-email-confirmation",
            get(move |Query(query): Query<EmailQuery>| {
                let change_email_outbox = change_email_outbox_for_get.clone();
                async move {
                    let record = change_email_outbox.lock().await.get(&query.email).cloned();
                    match record {
                        Some(record) => (
                            axum::http::StatusCode::OK,
                            Json(serde_json::to_value(record).unwrap()),
                        ),
                        None => (
                            axum::http::StatusCode::NOT_FOUND,
                            Json(serde_json::json!({ "message": "Not found" })),
                        ),
                    }
                }
            }),
        )
        .route(
            "/__test/reset-password-token",
            get(move |Query(query): Query<ResetTokenQuery>| {
                let reset_outbox = reset_outbox_for_token.clone();
                async move {
                    let token = reset_outbox.lock().await.remove(&query.email);
                    match token {
                        Some(token) => (
                            axum::http::StatusCode::OK,
                            Json(serde_json::json!({ "token": token })),
                        ),
                        None => (
                            axum::http::StatusCode::NOT_FOUND,
                            Json(serde_json::json!({ "message": "Not found" })),
                        ),
                    }
                }
            }),
        )
        .route(
            "/__test/reset-state",
            post(move || {
                let reset_outbox = reset_outbox_for_reset.clone();
                let verification_outbox = verification_outbox_for_reset.clone();
                let change_email_outbox = change_email_outbox_for_reset.clone();
                let reset_mode = reset_mode_for_reset.clone();
                let oauth_mode = oauth_mode_for_reset.clone();
                async move {
                    reset_outbox.lock().await.clear();
                    verification_outbox.lock().await.clear();
                    change_email_outbox.lock().await.clear();
                    *reset_mode.lock().await = ResetPasswordMode::Capture;
                    *oauth_mode.lock().await = OAuthRefreshMode::Success;
                    Json(serde_json::json!({ "status": true }))
                }
            }),
        )
        .route(
            "/__test/set-reset-password-mode",
            post(move |Json(body): Json<ModeRequest>| {
                let reset_mode = reset_mode_for_set.clone();
                async move {
                    *reset_mode.lock().await = if body.mode == "throw" {
                        ResetPasswordMode::Fail
                    } else {
                        ResetPasswordMode::Capture
                    };
                    Json(serde_json::json!({ "status": true }))
                }
            }),
        )
        .route(
            "/__test/seed-reset-password-token",
            post(move |Json(body): Json<SeedResetPasswordRequest>| {
                let auth = auth_for_reset_seed.clone();
                async move {
                    let user = match auth.database().get_user_by_email(&body.email).await {
                        Ok(Some(user)) => user,
                        Ok(None) => {
                            return (
                                axum::http::StatusCode::NOT_FOUND,
                                Json(serde_json::json!({ "message": "User not found" })),
                            );
                        }
                        Err(error) => {
                            return (
                                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                                Json(serde_json::json!({ "message": error.to_string() })),
                            );
                        }
                    };

                    let expires_at = match parse_rfc3339(&body.expires_at) {
                        Ok(expires_at) => expires_at,
                        Err(error) => {
                            return (
                                axum::http::StatusCode::BAD_REQUEST,
                                Json(serde_json::json!({ "message": error.to_string() })),
                            );
                        }
                    };

                    if let Err(error) = auth.database().create_verification(CreateVerification {
                        identifier: format!("reset-password:{}", body.token),
                        value: user.id.to_string(),
                        expires_at,
                    })
                    .await
                    {
                        return (
                            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                            Json(serde_json::json!({ "message": error.to_string() })),
                        );
                    }

                    (
                        axum::http::StatusCode::OK,
                        Json(serde_json::json!({ "status": true })),
                    )
                }
            }),
        )
        .route(
            "/__test/seed-delete-user-token",
            post(move |Json(body): Json<SeedDeleteUserTokenRequest>| {
                let auth = auth_for_delete_seed.clone();
                async move {
                    let user = match auth.database().get_user_by_email(&body.email).await {
                        Ok(Some(user)) => user,
                        Ok(None) => {
                            return (
                                axum::http::StatusCode::NOT_FOUND,
                                Json(serde_json::json!({ "message": "User not found" })),
                            );
                        }
                        Err(error) => {
                            return (
                                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                                Json(serde_json::json!({ "message": error.to_string() })),
                            );
                        }
                    };

                    let expires_at = match parse_rfc3339(&body.expires_at) {
                        Ok(expires_at) => expires_at,
                        Err(error) => {
                            return (
                                axum::http::StatusCode::BAD_REQUEST,
                                Json(serde_json::json!({ "message": error.to_string() })),
                            );
                        }
                    };

                    if let Err(error) = auth.database().create_verification(CreateVerification {
                        identifier: format!("delete-account-{}", body.token),
                        value: user.id.to_string(),
                        expires_at,
                    })
                    .await
                    {
                        return (
                            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                            Json(serde_json::json!({ "message": error.to_string() })),
                        );
                    }

                    (
                        axum::http::StatusCode::OK,
                        Json(serde_json::json!({ "status": true })),
                    )
                }
            }),
        )
        .route(
            "/__test/remove-credential-account",
            post(move |Json(body): Json<RemoveCredentialAccountRequest>| {
                let auth = auth_for_remove_credential.clone();
                async move {
                    let user = match auth.database().get_user_by_email(&body.email).await {
                        Ok(Some(user)) => user,
                        Ok(None) => {
                            return (
                                axum::http::StatusCode::NOT_FOUND,
                                Json(serde_json::json!({ "message": "User not found" })),
                            );
                        }
                        Err(error) => {
                            return (
                                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                                Json(serde_json::json!({ "message": error.to_string() })),
                            );
                        }
                    };

                    let accounts = match auth.database().get_user_accounts(&user.id.to_string()).await
                    {
                        Ok(accounts) => accounts,
                        Err(error) => {
                            return (
                                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                                Json(serde_json::json!({ "message": error.to_string() })),
                            );
                        }
                    };

                    for account in accounts {
                        if account.provider_id() == "credential" {
                            if let Err(error) = auth.database().delete_account(account.id()).await
                            {
                                return (
                                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                                    Json(serde_json::json!({ "message": error.to_string() })),
                                );
                            }
                        }
                    }

                    (
                        axum::http::StatusCode::OK,
                        Json(serde_json::json!({ "status": true })),
                    )
                }
            }),
        )
        .route(
            "/__test/set-oauth-refresh-mode",
            post(move |Json(body): Json<ModeRequest>| {
                let oauth_mode = oauth_mode_for_set.clone();
                async move {
                    *oauth_mode.lock().await = if body.mode == "error" {
                        OAuthRefreshMode::Error
                    } else {
                        OAuthRefreshMode::Success
                    };
                    Json(serde_json::json!({ "status": true }))
                }
            }),
        )
        .route(
            "/__test/seed-oauth-account",
            post(move |Json(body): Json<SeedOAuthAccountRequest>| {
                let auth = auth_for_oauth_seed.clone();
                async move {
                    let user = match auth.database().get_user_by_email(&body.email).await {
                        Ok(Some(user)) => user,
                        Ok(None) => {
                            return (
                                axum::http::StatusCode::NOT_FOUND,
                                Json(serde_json::json!({ "message": "User not found" })),
                            );
                        }
                        Err(error) => {
                            return (
                                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                                Json(serde_json::json!({ "message": error.to_string() })),
                            );
                        }
                    };

                    let provider_id = body.provider_id.unwrap_or_else(|| "mock".to_string());
                    let account_id =
                        body.account_id.unwrap_or_else(|| "mock-account-id".to_string());
                    let access_token_expires_at = match body
                        .access_token_expires_at
                        .as_deref()
                        .map(parse_rfc3339)
                        .transpose()
                    {
                        Ok(value) => value,
                        Err(error) => {
                            return (
                                axum::http::StatusCode::BAD_REQUEST,
                                Json(serde_json::json!({ "message": error.to_string() })),
                            );
                        }
                    };
                    let refresh_token_expires_at = match body
                        .refresh_token_expires_at
                        .as_deref()
                        .map(parse_rfc3339)
                        .transpose()
                    {
                        Ok(value) => value,
                        Err(error) => {
                            return (
                                axum::http::StatusCode::BAD_REQUEST,
                                Json(serde_json::json!({ "message": error.to_string() })),
                            );
                        }
                    };

                    let accounts = match auth.database().get_user_accounts(&user.id.to_string()).await
                    {
                        Ok(accounts) => accounts,
                        Err(error) => {
                            return (
                                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                                Json(serde_json::json!({ "message": error.to_string() })),
                            );
                        }
                    };
                    for account in accounts {
                        if account.provider_id() == provider_id && account.account_id() == account_id
                        {
                            if let Err(error) = auth.database().delete_account(account.id()).await {
                                return (
                                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                                    Json(serde_json::json!({ "message": error.to_string() })),
                                );
                            }
                        }
                    }

                    if let Err(error) = auth.database().create_account(CreateAccount {
                        user_id: user.id.to_string(),
                        account_id,
                        provider_id,
                        access_token: body.access_token,
                        refresh_token: body.refresh_token,
                        id_token: body.id_token,
                        access_token_expires_at,
                        refresh_token_expires_at,
                        scope: body.scope,
                        password: None,
                    })
                    .await
                    {
                        return (
                            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                            Json(serde_json::json!({ "message": error.to_string() })),
                        );
                    }

                    (
                        axum::http::StatusCode::OK,
                        Json(serde_json::json!({ "status": true })),
                    )
                }
            }),
        )
        .route(
            "/__test/oauth/token",
            post(move || {
                let oauth_mode = oauth_refresh_mode.clone();
                async move {
                    if *oauth_mode.lock().await == OAuthRefreshMode::Error {
                        return (
                            axum::http::StatusCode::BAD_REQUEST,
                            Json(serde_json::json!({
                                "error": "invalid_grant",
                                "error_description": "invalid refresh token",
                            })),
                        );
                    }

                    (
                        axum::http::StatusCode::OK,
                        Json(serde_json::json!({
                            "access_token": "new-access-token",
                            "refresh_token": "new-refresh-token",
                            "id_token": "new-id-token",
                            "expires_in": 3600,
                            "refresh_token_expires_in": 7200,
                            "scope": "openid,email,profile",
                        })),
                    )
                }
            }),
        )
        .route(
            "/__test/oauth/userinfo",
            get(|| async {
                Json(serde_json::json!({
                    "sub": "mock-account-id",
                    "email": "mock@example.com",
                    "name": "Mock OAuth User",
                    "email_verified": true,
                }))
            }),
        )
        .nest("/api/auth", auth_router)
        .with_state(auth);

    let addr = format!("0.0.0.0:{port}");
    println!("[rust-server] Listening on http://localhost:{port}");
    println!("READY");

    let listener = TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn health_check() -> impl IntoResponse {
    axum::Json(serde_json::json!({ "ok": true }))
}
