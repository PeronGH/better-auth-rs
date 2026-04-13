use better_auth_schema_registry::{self as registry, EntityRole, FieldDef};
use proc_macro2::TokenStream;
use quote::{format_ident, quote};

pub(crate) fn list_plugins() -> Vec<&'static str> {
    registry::plugin_schemas().iter().map(|p| p.name).collect()
}

pub(crate) fn generate_schema(plugins: &[String]) -> String {
    // Collect plugin fields for user and session
    let mut extra_user: Vec<FieldDef> = Vec::new();
    let mut extra_session: Vec<FieldDef> = Vec::new();

    for plugin_name in plugins {
        if let Some(schema) = registry::plugin_schemas()
            .iter()
            .find(|p| p.name == plugin_name.as_str())
        {
            extra_user.extend_from_slice(schema.user_fields);
            extra_session.extend_from_slice(schema.session_fields);
        }
    }

    let imports = quote! {
        use better_auth::AuthSchema;
        use better_auth::seaorm::sea_orm;
        use better_auth::seaorm::sea_orm::entity::prelude::*;
        use better_auth::seaorm::sea_orm::{ConnectionTrait, Schema};
        use better_auth::seaorm::{AuthEntity, DatabaseConnection};
    };

    let user_entity = gen_entity("user", "users", EntityRole::User, &extra_user);
    let session_entity = gen_entity("session", "sessions", EntityRole::Session, &extra_session);
    let account_entity = gen_entity("account", "accounts", EntityRole::Account, &[]);
    let verification_entity = gen_entity(
        "verification",
        "verifications",
        EntityRole::Verification,
        &[],
    );

    let schema_impl = quote! {
        pub struct AppAuthSchema;

        impl AuthSchema for AppAuthSchema {
            type User = user::Model;
            type Session = session::Model;
            type Account = account::Model;
            type Verification = verification::Model;
        }
    };

    let migration_fn = quote! {
        pub async fn run_app_migrations(
            database: &DatabaseConnection,
        ) -> Result<(), sea_orm::DbErr> {
            let schema = Schema::new(database.get_database_backend());
            for statement in [
                schema.create_table_from_entity(user::Entity).if_not_exists().to_owned(),
                schema.create_table_from_entity(session::Entity).if_not_exists().to_owned(),
                schema.create_table_from_entity(account::Entity).if_not_exists().to_owned(),
                schema.create_table_from_entity(verification::Entity).if_not_exists().to_owned(),
            ] {
                let _ = database.execute(&statement).await?;
            }
            Ok(())
        }
    };

    let tokens = quote! {
        #imports
        #user_entity
        #session_entity
        #account_entity
        #verification_entity
        #schema_impl
        #migration_fn
    };

    #[expect(
        clippy::expect_used,
        reason = "generated from hardcoded registry; parse failure is a bug"
    )]
    let file = syn::parse2(tokens).expect("generated code should be valid syntax");
    prettyplease::unparse(&file)
}

fn gen_entity(
    mod_name: &str,
    table_name: &str,
    role: EntityRole,
    plugin_fields: &[FieldDef],
) -> TokenStream {
    let mod_ident = format_ident!("{}", mod_name);
    let role_str = mod_name;

    let core = registry::core_fields(role);
    let all_fields: Vec<&FieldDef> = core.iter().chain(plugin_fields.iter()).collect();

    let field_tokens: Vec<TokenStream> = all_fields
        .iter()
        .map(|f| {
            let name = format_ident!("{}", f.name);
            #[expect(
                clippy::panic,
                reason = "type strings come from hardcoded registry; parse failure is a bug"
            )]
            let ty: syn::Type = syn::parse_str(f.ty)
                .unwrap_or_else(|e| panic!("invalid type `{}` for field `{}`: {e}", f.ty, f.name));
            if f.is_primary_key {
                quote! {
                    #[sea_orm(primary_key, auto_increment = false)]
                    pub #name: #ty,
                }
            } else {
                quote! { pub #name: #ty, }
            }
        })
        .collect();

    quote! {
        mod #mod_ident {
            use super::*;

            #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel, AuthEntity)]
            #[auth(role = #role_str)]
            #[sea_orm(table_name = #table_name)]
            pub struct Model {
                #(#field_tokens)*
            }

            #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
            pub enum Relation {}

            impl ActiveModelBehavior for ActiveModel {}
        }
    }
}
