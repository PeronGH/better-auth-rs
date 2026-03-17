//! Schema traits for binding Better Auth to app-owned SeaORM entities.

use chrono::{DateTime, Utc};
use sea_orm::{
    ActiveModelBehavior, ActiveModelTrait, ColumnTrait, EntityTrait, FromQueryResult,
    IntoActiveModel,
};

use crate::entity::{AuthAccount, AuthSession, AuthUser, AuthVerification};
use crate::types::{
    CreateAccount, CreateSession, CreateUser, CreateVerification, UpdateAccount, UpdateUser,
};

/// App-owned auth schema declaration.
pub trait AuthSchema: Send + Sync + 'static {
    type User: AuthUserModel;
    type Session: AuthSessionModel;
    type Account: AuthAccountModel;
    type Verification: AuthVerificationModel;
}

/// SeaORM binding for the auth user model.
pub trait AuthUserModel:
    AuthUser + IntoActiveModel<Self::ActiveModel> + Clone + Send + Sync + 'static + FromQueryResult
{
    type Entity: EntityTrait<Model = Self>;
    type ActiveModel: ActiveModelTrait<Entity = Self::Entity> + ActiveModelBehavior + Send;
    type Column: ColumnTrait;

    fn id_column() -> Self::Column;
    fn email_column() -> Self::Column;
    fn username_column() -> Self::Column;
    fn name_column() -> Self::Column;
    fn created_at_column() -> Self::Column;

    fn new_active(id: String, create_user: CreateUser, now: DateTime<Utc>) -> Self::ActiveModel;
    fn apply_update(active: &mut Self::ActiveModel, update: UpdateUser, now: DateTime<Utc>);
}

/// SeaORM binding for the auth session model.
pub trait AuthSessionModel:
    AuthSession + IntoActiveModel<Self::ActiveModel> + Clone + Send + Sync + 'static + FromQueryResult
{
    type Entity: EntityTrait<Model = Self>;
    type ActiveModel: ActiveModelTrait<Entity = Self::Entity> + ActiveModelBehavior + Send;
    type Column: ColumnTrait;

    fn id_column() -> Self::Column;
    fn token_column() -> Self::Column;
    fn user_id_column() -> Self::Column;
    fn active_column() -> Self::Column;
    fn expires_at_column() -> Self::Column;
    fn created_at_column() -> Self::Column;

    fn new_active(
        id: String,
        token: String,
        create_session: CreateSession,
        now: DateTime<Utc>,
    ) -> Self::ActiveModel;
    fn set_expires_at(active: &mut Self::ActiveModel, expires_at: DateTime<Utc>);
    fn set_updated_at(active: &mut Self::ActiveModel, updated_at: DateTime<Utc>);
    fn set_active_organization_id(active: &mut Self::ActiveModel, organization_id: Option<String>);
}

/// SeaORM binding for the auth account model.
pub trait AuthAccountModel:
    AuthAccount + IntoActiveModel<Self::ActiveModel> + Clone + Send + Sync + 'static + FromQueryResult
{
    type Entity: EntityTrait<Model = Self>;
    type ActiveModel: ActiveModelTrait<Entity = Self::Entity> + ActiveModelBehavior + Send;
    type Column: ColumnTrait;

    fn id_column() -> Self::Column;
    fn provider_id_column() -> Self::Column;
    fn account_id_column() -> Self::Column;
    fn user_id_column() -> Self::Column;
    fn created_at_column() -> Self::Column;

    fn new_active(
        id: String,
        create_account: CreateAccount,
        now: DateTime<Utc>,
    ) -> Self::ActiveModel;
    fn apply_update(active: &mut Self::ActiveModel, update: UpdateAccount, now: DateTime<Utc>);
}

/// SeaORM binding for the auth verification model.
pub trait AuthVerificationModel:
    AuthVerification
    + IntoActiveModel<Self::ActiveModel>
    + Clone
    + Send
    + Sync
    + 'static
    + FromQueryResult
{
    type Entity: EntityTrait<Model = Self>;
    type ActiveModel: ActiveModelTrait<Entity = Self::Entity> + ActiveModelBehavior + Send;
    type Column: ColumnTrait;

    fn id_column() -> Self::Column;
    fn identifier_column() -> Self::Column;
    fn value_column() -> Self::Column;
    fn expires_at_column() -> Self::Column;
    fn created_at_column() -> Self::Column;

    fn new_active(
        id: String,
        verification: CreateVerification,
        now: DateTime<Utc>,
    ) -> Self::ActiveModel;
}
