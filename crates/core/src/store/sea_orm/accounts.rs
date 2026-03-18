use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DatabaseTransaction, EntityTrait,
    IntoActiveModel, QueryFilter, QueryOrder,
};
use uuid::Uuid;

use crate::error::AuthResult;
use crate::schema::{AuthAccountModel, AuthSchema};
use crate::types::{CreateAccount, UpdateAccount};

use super::{AuthStore, cancelled_by_hook, map_db_err};

impl<S: AuthSchema> AuthStore<S> {
    async fn create_account_with_connection<C>(
        &self,
        db: &C,
        tx: Option<&DatabaseTransaction>,
        mut create_account: CreateAccount,
    ) -> AuthResult<S::Account>
    where
        C: ConnectionTrait,
    {
        let hook_context = self.hook_context(tx);
        for hook in self.hooks() {
            if hook
                .before_create_account(&mut create_account, &hook_context)
                .await?
                .is_cancelled()
            {
                return Err(cancelled_by_hook("account creation"));
            }
        }
        let now = Utc::now();
        let account = S::Account::new_active(Uuid::new_v4().to_string(), create_account, now)
            .insert(db)
            .await
            .map_err(map_db_err)?;
        for hook in self.hooks() {
            hook.after_create_account(&account, &hook_context).await?;
        }
        Ok(account)
    }

    pub async fn create_account(&self, create_account: CreateAccount) -> AuthResult<S::Account> {
        self.create_account_with_connection(self.connection(), None, create_account)
            .await
    }

    /// Create an account inside an existing transaction.
    #[doc(hidden)]
    pub async fn create_account_in_tx(
        &self,
        tx: &DatabaseTransaction,
        create_account: CreateAccount,
    ) -> AuthResult<S::Account> {
        self.create_account_with_connection(tx, Some(tx), create_account)
            .await
    }

    pub async fn get_account(
        &self,
        provider: &str,
        provider_account_id: &str,
    ) -> AuthResult<Option<S::Account>> {
        <S::Account as AuthAccountModel>::Entity::find()
            .filter(<S::Account as AuthAccountModel>::provider_id_column().eq(provider))
            .filter(<S::Account as AuthAccountModel>::account_id_column().eq(provider_account_id))
            .one(self.connection())
            .await
            .map_err(map_db_err)
    }

    pub async fn get_user_accounts(&self, user_id: &str) -> AuthResult<Vec<S::Account>> {
        <S::Account as AuthAccountModel>::Entity::find()
            .filter(<S::Account as AuthAccountModel>::user_id_column().eq(user_id))
            .order_by_desc(<S::Account as AuthAccountModel>::created_at_column())
            .all(self.connection())
            .await
            .map_err(map_db_err)
    }

    pub async fn update_account(
        &self,
        id: &str,
        mut update: UpdateAccount,
    ) -> AuthResult<S::Account> {
        let hook_context = self.hook_context(None);
        for hook in self.hooks() {
            if hook
                .before_update_account(id, &mut update, &hook_context)
                .await?
                .is_cancelled()
            {
                return Err(cancelled_by_hook("account update"));
            }
        }
        let Some(model) = <S::Account as AuthAccountModel>::Entity::find()
            .filter(<S::Account as AuthAccountModel>::id_column().eq(id))
            .one(self.connection())
            .await
            .map_err(map_db_err)?
        else {
            return Err(crate::error::AuthError::not_found("Account not found"));
        };

        let mut active = model.into_active_model();
        S::Account::apply_update(&mut active, update, Utc::now());

        let account = active.update(self.connection()).await.map_err(map_db_err)?;
        for hook in self.hooks() {
            hook.after_update_account(&account, &hook_context).await?;
        }
        Ok(account)
    }

    pub async fn delete_account(&self, id: &str) -> AuthResult<()> {
        let Some(account_model) = <S::Account as AuthAccountModel>::Entity::find()
            .filter(<S::Account as AuthAccountModel>::id_column().eq(id))
            .one(self.connection())
            .await
            .map_err(map_db_err)?
        else {
            return Err(crate::error::AuthError::not_found("Account not found"));
        };
        let hook_context = self.hook_context(None);
        for hook in self.hooks() {
            if hook
                .before_delete_account(&account_model, &hook_context)
                .await?
                .is_cancelled()
            {
                return Err(cancelled_by_hook("account deletion"));
            }
        }
        let _ = <S::Account as AuthAccountModel>::Entity::delete_many()
            .filter(<S::Account as AuthAccountModel>::id_column().eq(id))
            .exec(self.connection())
            .await
            .map_err(map_db_err)?;
        for hook in self.hooks() {
            hook.after_delete_account(&account_model, &hook_context)
                .await?;
        }
        Ok(())
    }
}
