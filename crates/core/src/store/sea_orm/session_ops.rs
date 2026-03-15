use chrono::{DateTime, Utc};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, ExprTrait, IntoActiveModel, QueryFilter,
    QueryOrder, Set,
};
use uuid::Uuid;

use crate::error::{AuthError, AuthResult};
use crate::store::SessionOps;
use crate::types::{CreateSession, Session};

use super::entities::session::{Column, Entity};
use super::{SeaOrmStore, map_db_err};

#[async_trait::async_trait]
impl SessionOps for SeaOrmStore {
    type Session = Session;

    async fn create_session(&self, create_session: CreateSession) -> AuthResult<Self::Session> {
        let now = Utc::now();
        super::entities::session::ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            user_id: Set(create_session.user_id),
            token: Set(format!("session_{}", Uuid::new_v4())),
            expires_at: Set(create_session.expires_at),
            created_at: Set(now),
            updated_at: Set(now),
            ip_address: Set(create_session.ip_address),
            user_agent: Set(create_session.user_agent),
            impersonated_by: Set(create_session.impersonated_by),
            active_organization_id: Set(create_session.active_organization_id),
            active: Set(true),
        }
        .insert(self.connection())
        .await
        .map(Session::from)
        .map_err(map_db_err)
    }

    async fn get_session(&self, token: &str) -> AuthResult<Option<Self::Session>> {
        Entity::find()
            .filter(Column::Token.eq(token))
            .filter(Column::Active.eq(true))
            .one(self.connection())
            .await
            .map(|model| model.map(Session::from))
            .map_err(map_db_err)
    }

    async fn get_user_sessions(&self, user_id: &str) -> AuthResult<Vec<Self::Session>> {
        Entity::find()
            .filter(Column::UserId.eq(user_id))
            .filter(Column::Active.eq(true))
            .order_by_desc(Column::CreatedAt)
            .all(self.connection())
            .await
            .map(|models| models.into_iter().map(Session::from).collect())
            .map_err(map_db_err)
    }

    async fn update_session_expiry(
        &self,
        token: &str,
        expires_at: DateTime<Utc>,
    ) -> AuthResult<()> {
        let Some(model) = Entity::find()
            .filter(Column::Token.eq(token))
            .filter(Column::Active.eq(true))
            .one(self.connection())
            .await
            .map_err(map_db_err)?
        else {
            return Err(AuthError::SessionNotFound);
        };

        let mut active = model.into_active_model();
        active.expires_at = Set(expires_at);
        active.updated_at = Set(Utc::now());
        active
            .update(self.connection())
            .await
            .map(|_| ())
            .map_err(map_db_err)
    }

    async fn delete_session(&self, token: &str) -> AuthResult<()> {
        Entity::delete_many()
            .filter(Column::Token.eq(token))
            .exec(self.connection())
            .await
            .map(|_| ())
            .map_err(map_db_err)
    }

    async fn delete_user_sessions(&self, user_id: &str) -> AuthResult<()> {
        Entity::delete_many()
            .filter(Column::UserId.eq(user_id))
            .exec(self.connection())
            .await
            .map(|_| ())
            .map_err(map_db_err)
    }

    async fn delete_expired_sessions(&self) -> AuthResult<usize> {
        Entity::delete_many()
            .filter(
                Column::ExpiresAt
                    .lt(Utc::now())
                    .or(Column::Active.eq(false)),
            )
            .exec(self.connection())
            .await
            .map(|result| result.rows_affected as usize)
            .map_err(map_db_err)
    }

    async fn update_session_active_organization(
        &self,
        token: &str,
        organization_id: Option<&str>,
    ) -> AuthResult<Self::Session> {
        let Some(model) = Entity::find()
            .filter(Column::Token.eq(token))
            .filter(Column::Active.eq(true))
            .one(self.connection())
            .await
            .map_err(map_db_err)?
        else {
            return Err(AuthError::SessionNotFound);
        };

        let mut active = model.into_active_model();
        active.active_organization_id = Set(organization_id.map(str::to_owned));
        active.updated_at = Set(Utc::now());
        active
            .update(self.connection())
            .await
            .map(Session::from)
            .map_err(map_db_err)
    }
}
