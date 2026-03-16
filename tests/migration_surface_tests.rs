#![allow(
    clippy::unwrap_used,
    reason = "migration surface tests intentionally fail fast on setup and table existence checks"
)]

use better_auth::sea_orm::sea_query::{Alias, ColumnDef, IntoIden, Table};
use better_auth::sea_orm_migration;
use better_auth::sea_orm_migration::prelude::*;
use better_auth::{
    Database, MigrationOptions, auth_migrations, run_migrations, run_migrations_with,
};

async fn sqlite_database() -> better_auth::DatabaseConnection {
    Database::connect("sqlite::memory:").await.unwrap()
}

#[derive(DeriveMigrationName)]
struct CreateTodoTable;

#[async_trait::async_trait]
impl MigrationTrait for CreateTodoTable {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Alias::new("todo_items"))
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Alias::new("id"))
                            .integer()
                            .not_null()
                            .primary_key(),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(
                Table::drop()
                    .table(Alias::new("todo_items"))
                    .if_exists()
                    .to_owned(),
            )
            .await
    }
}

struct CombinedMigrator;

#[async_trait::async_trait]
impl MigratorTrait for CombinedMigrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        let mut migrations = auth_migrations();
        migrations.push(Box::new(CreateTodoTable));
        migrations
    }

    fn migration_table_name() -> DynIden {
        Alias::new("app_auth_migrations").into_iden()
    }
}

#[tokio::test]
async fn run_migrations_uses_namespaced_default_table() {
    let db = sqlite_database().await;
    run_migrations(&db).await.unwrap();

    let manager = SchemaManager::new(&db);
    assert!(manager.has_table("better_auth_migrations").await.unwrap());
    assert!(!manager.has_table("seaql_migrations").await.unwrap());
    assert!(manager.has_table("users").await.unwrap());
}

#[tokio::test]
async fn run_migrations_with_uses_custom_table_name() {
    let db = sqlite_database().await;
    run_migrations_with(
        &db,
        MigrationOptions {
            table_name: "custom_auth_migrations".to_string(),
        },
    )
    .await
    .unwrap();

    let manager = SchemaManager::new(&db);
    assert!(manager.has_table("custom_auth_migrations").await.unwrap());
    assert!(!manager.has_table("seaql_migrations").await.unwrap());
}

#[tokio::test]
async fn auth_migrations_can_be_composed_with_app_migrations() {
    let db = sqlite_database().await;
    CombinedMigrator::up(&db, None).await.unwrap();

    let manager = SchemaManager::new(&db);
    assert!(manager.has_table("app_auth_migrations").await.unwrap());
    assert!(manager.has_table("users").await.unwrap());
    assert!(manager.has_table("todo_items").await.unwrap());
}
