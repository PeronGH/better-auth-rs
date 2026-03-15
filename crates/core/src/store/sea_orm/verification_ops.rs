use chrono::Utc;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, QueryOrder, Set};
use uuid::Uuid;

use crate::error::AuthResult;
use crate::store::VerificationOps;
use crate::types::{CreateVerification, Verification};

use super::entities::verification::{ActiveModel, Column, Entity};
use super::{SeaOrmStore, map_db_err};

#[async_trait::async_trait]
impl VerificationOps for SeaOrmStore {
    type Verification = Verification;

    async fn create_verification(
        &self,
        verification: CreateVerification,
    ) -> AuthResult<Self::Verification> {
        let now = Utc::now();
        ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            identifier: Set(verification.identifier),
            value: Set(verification.value),
            expires_at: Set(verification.expires_at),
            created_at: Set(now),
            updated_at: Set(now),
        }
        .insert(self.connection())
        .await
        .map(Verification::from)
        .map_err(map_db_err)
    }

    async fn get_verification(
        &self,
        identifier: &str,
        value: &str,
    ) -> AuthResult<Option<Self::Verification>> {
        Entity::find()
            .filter(Column::Identifier.eq(identifier))
            .filter(Column::Value.eq(value))
            .filter(Column::ExpiresAt.gt(Utc::now()))
            .one(self.connection())
            .await
            .map(|model| model.map(Verification::from))
            .map_err(map_db_err)
    }

    async fn get_verification_by_value(
        &self,
        value: &str,
    ) -> AuthResult<Option<Self::Verification>> {
        Entity::find()
            .filter(Column::Value.eq(value))
            .filter(Column::ExpiresAt.gt(Utc::now()))
            .one(self.connection())
            .await
            .map(|model| model.map(Verification::from))
            .map_err(map_db_err)
    }

    async fn get_verification_by_identifier(
        &self,
        identifier: &str,
    ) -> AuthResult<Option<Self::Verification>> {
        Entity::find()
            .filter(Column::Identifier.eq(identifier))
            .filter(Column::ExpiresAt.gt(Utc::now()))
            .one(self.connection())
            .await
            .map(|model| model.map(Verification::from))
            .map_err(map_db_err)
    }

    async fn consume_verification(
        &self,
        identifier: &str,
        value: &str,
    ) -> AuthResult<Option<Self::Verification>> {
        let Some(model) = Entity::find()
            .filter(Column::Identifier.eq(identifier))
            .filter(Column::Value.eq(value))
            .filter(Column::ExpiresAt.gt(Utc::now()))
            .order_by_desc(Column::CreatedAt)
            .one(self.connection())
            .await
            .map_err(map_db_err)?
        else {
            return Ok(None);
        };

        let _ = Entity::delete_by_id(model.id.clone())
            .exec(self.connection())
            .await
            .map_err(map_db_err)?;

        Ok(Some(model.into()))
    }

    async fn delete_verification(&self, id: &str) -> AuthResult<()> {
        Entity::delete_by_id(id.to_owned())
            .exec(self.connection())
            .await
            .map(|_| ())
            .map_err(map_db_err)
    }

    async fn delete_expired_verifications(&self) -> AuthResult<usize> {
        Entity::delete_many()
            .filter(Column::ExpiresAt.lt(Utc::now()))
            .exec(self.connection())
            .await
            .map(|result| result.rows_affected as usize)
            .map_err(map_db_err)
    }
}
