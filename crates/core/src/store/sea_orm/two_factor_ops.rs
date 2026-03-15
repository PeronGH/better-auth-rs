use chrono::Utc;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, IntoActiveModel, QueryFilter, Set};
use uuid::Uuid;

use crate::error::AuthResult;
use crate::store::TwoFactorOps;
use crate::types::{CreateTwoFactor, TwoFactor};

use super::entities::two_factor::{ActiveModel, Column, Entity};
use super::{SeaOrmStore, map_db_err};

#[async_trait::async_trait]
impl TwoFactorOps for SeaOrmStore {
    type TwoFactor = TwoFactor;

    async fn create_two_factor(&self, two_factor: CreateTwoFactor) -> AuthResult<Self::TwoFactor> {
        let now = Utc::now();
        ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            secret: Set(two_factor.secret),
            backup_codes: Set(two_factor.backup_codes),
            user_id: Set(two_factor.user_id),
            created_at: Set(now),
            updated_at: Set(now),
        }
        .insert(self.connection())
        .await
        .map(TwoFactor::from)
        .map_err(map_db_err)
    }

    async fn get_two_factor_by_user_id(
        &self,
        user_id: &str,
    ) -> AuthResult<Option<Self::TwoFactor>> {
        Entity::find()
            .filter(Column::UserId.eq(user_id))
            .one(self.connection())
            .await
            .map(|model| model.map(TwoFactor::from))
            .map_err(map_db_err)
    }

    async fn update_two_factor_backup_codes(
        &self,
        user_id: &str,
        backup_codes: &str,
    ) -> AuthResult<Self::TwoFactor> {
        let Some(model) = Entity::find()
            .filter(Column::UserId.eq(user_id))
            .one(self.connection())
            .await
            .map_err(map_db_err)?
        else {
            return Err(crate::error::AuthError::not_found(
                "Two-factor settings not found",
            ));
        };

        let mut active = model.into_active_model();
        active.backup_codes = Set(Some(backup_codes.to_owned()));
        active.updated_at = Set(Utc::now());
        active
            .update(self.connection())
            .await
            .map(TwoFactor::from)
            .map_err(map_db_err)
    }

    async fn delete_two_factor(&self, user_id: &str) -> AuthResult<()> {
        Entity::delete_many()
            .filter(Column::UserId.eq(user_id))
            .exec(self.connection())
            .await
            .map(|_| ())
            .map_err(map_db_err)
    }
}
