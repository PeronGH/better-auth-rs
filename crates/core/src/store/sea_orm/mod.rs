//! SeaORM-backed persistence implementation for built-in auth tables.

mod account_ops;
mod api_key_ops;
mod conversions;
pub mod entities;
mod invitation_ops;
mod member_ops;
pub mod migrator;
mod organization_ops;
mod passkey_ops;
mod session_ops;
mod two_factor_ops;
mod user_ops;
mod verification_ops;

use chrono::{DateTime, Utc};
use sea_orm::{DatabaseConnection, DbErr, SqlErr};

use crate::error::{AuthError, DatabaseError};

#[derive(Clone)]
pub struct SeaOrmStore {
    db: DatabaseConnection,
}

impl SeaOrmStore {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }

    pub fn connection(&self) -> &DatabaseConnection {
        &self.db
    }

    pub async fn test_connection(&self) -> Result<(), DbErr> {
        self.db.ping().await
    }
}

fn map_db_err(err: DbErr) -> AuthError {
    match err.sql_err() {
        Some(SqlErr::UniqueConstraintViolation(message)) => {
            AuthError::Database(DatabaseError::Constraint(message))
        }
        Some(SqlErr::ForeignKeyConstraintViolation(message)) => {
            AuthError::Database(DatabaseError::Constraint(message))
        }
        Some(_) | None => AuthError::Database(DatabaseError::Query(err.to_string())),
    }
}

fn parse_rfc3339(value: &str, field: &str) -> Result<DateTime<Utc>, AuthError> {
    DateTime::parse_from_rfc3339(value)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|_| AuthError::bad_request(format!("Invalid RFC 3339 timestamp for {field}")))
}

fn parse_optional_rfc3339(
    value: Option<&str>,
    field: &str,
) -> Result<Option<DateTime<Utc>>, AuthError> {
    value.map(|inner| parse_rfc3339(inner, field)).transpose()
}

fn to_i32(value: i64, field: &str) -> Result<i32, AuthError> {
    i32::try_from(value).map_err(|_| AuthError::bad_request(format!("{field} exceeds i32 range")))
}

fn to_optional_i32(value: Option<i64>, field: &str) -> Result<Option<i32>, AuthError> {
    value.map(|inner| to_i32(inner, field)).transpose()
}
