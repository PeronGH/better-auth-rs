//! SeaORM integration surface for `better-auth`.

use better_auth_core::store::sea_orm::migrator::AuthMigrator as CoreAuthMigrator;
use sea_orm::sea_query::{Alias, IntoIden};
use sea_orm::{DbErr, DynIden};
use sea_orm_migration::MigratorTraitSelf;
use sea_orm_migration::prelude::{MigrationTrait, MigratorTrait};

pub use better_auth_core::hooks::{DatabaseHookContext, DatabaseHooks, HookControl};
pub use better_auth_core::sea_orm;
pub use better_auth_core::store::AuthStore;
pub use sea_orm::{Database, DatabaseConnection};
pub use sea_orm_migration;

/// Options for running Better Auth's built-in SeaORM migrations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationOptions {
    /// Name of the SeaORM migration tracking table.
    pub table_name: String,
}

impl Default for MigrationOptions {
    fn default() -> Self {
        Self {
            table_name: "better_auth_migrations".to_string(),
        }
    }
}

/// Return the built-in auth migrations for composition with an application migrator.
pub fn auth_migrations() -> Vec<Box<dyn MigrationTrait>> {
    <CoreAuthMigrator as MigratorTrait>::migrations()
}

/// Better Auth migrator with a namespaced default migration table.
pub struct AuthMigrator;

#[async_trait::async_trait]
impl MigratorTrait for AuthMigrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        auth_migrations()
    }

    fn migration_table_name() -> DynIden {
        Alias::new(MigrationOptions::default().table_name).into_iden()
    }
}

/// Instance-based migrator for custom migration table names.
#[derive(Debug, Clone)]
pub struct ConfigurableAuthMigrator {
    options: MigrationOptions,
}

impl ConfigurableAuthMigrator {
    pub fn new(options: MigrationOptions) -> Self {
        Self { options }
    }
}

#[async_trait::async_trait]
impl MigratorTraitSelf for ConfigurableAuthMigrator {
    fn migrations(&self) -> Vec<Box<dyn MigrationTrait>> {
        auth_migrations()
    }

    fn migration_table_name(&self) -> DynIden {
        Alias::new(self.options.table_name.clone()).into_iden()
    }
}

/// Run the built-in auth migrations using the default namespaced migration table.
pub async fn run_migrations(db: &DatabaseConnection) -> Result<(), DbErr> {
    <AuthMigrator as MigratorTrait>::up(db, None).await
}

/// Run the built-in auth migrations with explicit migration table options.
pub async fn run_migrations_with(
    db: &DatabaseConnection,
    options: MigrationOptions,
) -> Result<(), DbErr> {
    ConfigurableAuthMigrator::new(options).up(db, None).await
}
