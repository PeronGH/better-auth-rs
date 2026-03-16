//! Storage-related types, migrations, cache adapters, and the SeaORM integration surface.

#[cfg(feature = "redis-cache")]
pub use better_auth_core::store::RedisAdapter;
pub use better_auth_core::store::{CacheAdapter, MemoryCacheAdapter};
pub use better_auth_seaorm::{
    AuthMigrator, AuthStore, ConfigurableAuthMigrator, Database, DatabaseConnection,
    MigrationOptions, auth_migrations, run_migrations, run_migrations_with, sea_orm,
    sea_orm_migration,
};
