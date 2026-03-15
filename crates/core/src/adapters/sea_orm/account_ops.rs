use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, IntoActiveModel, QueryFilter, QueryOrder, Set,
};
use uuid::Uuid;

use crate::adapters::AccountOps;
use crate::error::AuthResult;
use crate::types::{Account, CreateAccount, UpdateAccount};

use super::entities::account::{ActiveModel, Column, Entity};
use super::{SeaOrmAdapter, map_db_err};

#[async_trait::async_trait]
impl AccountOps for SeaOrmAdapter {
    type Account = Account;

    async fn create_account(&self, create_account: CreateAccount) -> AuthResult<Self::Account> {
        let now = Utc::now();
        ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            account_id: Set(create_account.account_id),
            provider_id: Set(create_account.provider_id),
            user_id: Set(create_account.user_id),
            access_token: Set(create_account.access_token),
            refresh_token: Set(create_account.refresh_token),
            id_token: Set(create_account.id_token),
            access_token_expires_at: Set(create_account.access_token_expires_at),
            refresh_token_expires_at: Set(create_account.refresh_token_expires_at),
            scope: Set(create_account.scope),
            password: Set(create_account.password),
            created_at: Set(now),
            updated_at: Set(now),
        }
        .insert(self.connection())
        .await
        .map(Account::from)
        .map_err(map_db_err)
    }

    async fn get_account(
        &self,
        provider: &str,
        provider_account_id: &str,
    ) -> AuthResult<Option<Self::Account>> {
        Entity::find()
            .filter(Column::ProviderId.eq(provider))
            .filter(Column::AccountId.eq(provider_account_id))
            .one(self.connection())
            .await
            .map(|model| model.map(Account::from))
            .map_err(map_db_err)
    }

    async fn get_user_accounts(&self, user_id: &str) -> AuthResult<Vec<Self::Account>> {
        Entity::find()
            .filter(Column::UserId.eq(user_id))
            .order_by_desc(Column::CreatedAt)
            .all(self.connection())
            .await
            .map(|models| models.into_iter().map(Account::from).collect())
            .map_err(map_db_err)
    }

    async fn update_account(&self, id: &str, update: UpdateAccount) -> AuthResult<Self::Account> {
        let Some(model) = Entity::find_by_id(id.to_owned())
            .one(self.connection())
            .await
            .map_err(map_db_err)?
        else {
            return Err(crate::error::AuthError::not_found("Account not found"));
        };

        let mut active = model.into_active_model();
        if let Some(access_token) = update.access_token {
            active.access_token = Set(Some(access_token));
        }
        if let Some(refresh_token) = update.refresh_token {
            active.refresh_token = Set(Some(refresh_token));
        }
        if let Some(id_token) = update.id_token {
            active.id_token = Set(Some(id_token));
        }
        if let Some(expires_at) = update.access_token_expires_at {
            active.access_token_expires_at = Set(Some(expires_at));
        }
        if let Some(expires_at) = update.refresh_token_expires_at {
            active.refresh_token_expires_at = Set(Some(expires_at));
        }
        if let Some(scope) = update.scope {
            active.scope = Set(Some(scope));
        }
        if let Some(password) = update.password {
            active.password = Set(Some(password));
        }
        active.updated_at = Set(Utc::now());

        active
            .update(self.connection())
            .await
            .map(Account::from)
            .map_err(map_db_err)
    }

    async fn delete_account(&self, id: &str) -> AuthResult<()> {
        Entity::delete_by_id(id.to_owned())
            .exec(self.connection())
            .await
            .map(|_| ())
            .map_err(map_db_err)
    }
}
