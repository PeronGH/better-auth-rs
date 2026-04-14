//! Authoritative field registry for better-auth entity schemas.
//!
//! Shared by the `AuthEntity` proc macro (for compile-time validation)
//! and the CLI (for code generation). This is the single source of truth
//! for which fields belong to core vs which are plugin-provided.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntityRole {
    User,
    Session,
    Account,
    Verification,
}

#[derive(Clone, Copy, Debug)]
pub struct FieldDef {
    pub name: &'static str,
    /// Rust type as it appears in a SeaORM `Model` struct,
    /// e.g. `"Option<String>"`, `"bool"`, `"DateTimeUtc"`, `"Json"`.
    pub ty: &'static str,
    pub is_primary_key: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct PluginSchema {
    pub name: &'static str,
    pub user_fields: &'static [FieldDef],
    pub session_fields: &'static [FieldDef],
    pub extra_entities: &'static [ExtraEntitySchema],
}

#[derive(Clone, Copy, Debug)]
pub struct ExtraEntitySchema {
    pub mod_name: &'static str,
    pub table_name: &'static str,
    pub role: Option<EntityRole>,
    pub fields: &'static [FieldDef],
}

macro_rules! f {
    ($name:expr, $ty:expr) => {
        FieldDef {
            name: $name,
            ty: $ty,
            is_primary_key: false,
        }
    };
}

macro_rules! pk {
    ($name:expr, $ty:expr) => {
        FieldDef {
            name: $name,
            ty: $ty,
            is_primary_key: true,
        }
    };
}

// ── Core fields ──────────────────────────────────────────────────────

static USER_CORE: &[FieldDef] = &[
    pk!("id", "String"),
    f!("name", "Option<String>"),
    f!("email", "Option<String>"),
    f!("email_verified", "bool"),
    f!("image", "Option<String>"),
    f!("created_at", "DateTimeUtc"),
    f!("updated_at", "DateTimeUtc"),
];

static SESSION_CORE: &[FieldDef] = &[
    pk!("id", "String"),
    f!("expires_at", "DateTimeUtc"),
    f!("token", "String"),
    f!("created_at", "DateTimeUtc"),
    f!("updated_at", "DateTimeUtc"),
    f!("ip_address", "Option<String>"),
    f!("user_agent", "Option<String>"),
    f!("user_id", "String"),
    f!("active", "bool"),
];

static ACCOUNT_CORE: &[FieldDef] = &[
    pk!("id", "String"),
    f!("account_id", "String"),
    f!("provider_id", "String"),
    f!("user_id", "String"),
    f!("access_token", "Option<String>"),
    f!("refresh_token", "Option<String>"),
    f!("id_token", "Option<String>"),
    f!("access_token_expires_at", "Option<DateTimeUtc>"),
    f!("refresh_token_expires_at", "Option<DateTimeUtc>"),
    f!("scope", "Option<String>"),
    f!("password", "Option<String>"),
    f!("created_at", "DateTimeUtc"),
    f!("updated_at", "DateTimeUtc"),
];

static VERIFICATION_CORE: &[FieldDef] = &[
    pk!("id", "String"),
    f!("identifier", "String"),
    f!("value", "String"),
    f!("expires_at", "DateTimeUtc"),
    f!("created_at", "DateTimeUtc"),
    f!("updated_at", "DateTimeUtc"),
];

/// Core fields that are always required for a given entity role.
pub fn core_fields(role: EntityRole) -> &'static [FieldDef] {
    match role {
        EntityRole::User => USER_CORE,
        EntityRole::Session => SESSION_CORE,
        EntityRole::Account => ACCOUNT_CORE,
        EntityRole::Verification => VERIFICATION_CORE,
    }
}

// ── Plugin schemas ───────────────────────────────────────────────────

static PLUGINS: &[PluginSchema] = &[
    PluginSchema {
        name: "username",
        user_fields: &[
            f!("username", "Option<String>"),
            f!("display_username", "Option<String>"),
        ],
        session_fields: &[],
        extra_entities: &[],
    },
    PluginSchema {
        name: "two-factor",
        user_fields: &[f!("two_factor_enabled", "bool")],
        session_fields: &[],
        extra_entities: &[],
    },
    PluginSchema {
        name: "admin",
        user_fields: &[
            f!("role", "Option<String>"),
            f!("banned", "bool"),
            f!("ban_reason", "Option<String>"),
            f!("ban_expires", "Option<DateTimeUtc>"),
            f!("metadata", "Json"),
        ],
        session_fields: &[f!("impersonated_by", "Option<String>")],
        extra_entities: &[],
    },
    PluginSchema {
        name: "organization",
        user_fields: &[],
        session_fields: &[f!("active_organization_id", "Option<String>")],
        extra_entities: &[],
    },
    PluginSchema {
        name: "passkey",
        user_fields: &[],
        session_fields: &[],
        extra_entities: &[ExtraEntitySchema {
            mod_name: "passkey",
            table_name: "passkeys",
            role: None,
            fields: &[
                pk!("id", "String"),
                f!("name", "Option<String>"),
                f!("public_key", "String"),
                f!("user_id", "String"),
                f!("credential_id", "String"),
                f!("counter", "i64"),
                f!("device_type", "String"),
                f!("backed_up", "bool"),
                f!("transports", "Option<String>"),
                f!("credential", "String"),
                f!("aaguid", "Option<String>"),
                f!("created_at", "DateTimeUtc"),
                f!("updated_at", "DateTimeUtc"),
            ],
        }],
    },
];

/// Plugin schemas — each plugin can add fields to user and/or session entities.
pub fn plugin_schemas() -> &'static [PluginSchema] {
    PLUGINS
}

/// All plugin field names for a given role (convenience for the macro).
pub fn plugin_field_names(role: EntityRole) -> Vec<&'static str> {
    plugin_schemas()
        .iter()
        .flat_map(|p| match role {
            EntityRole::User => p.user_fields.iter(),
            EntityRole::Session => p.session_fields.iter(),
            EntityRole::Account | EntityRole::Verification => [].iter(),
        })
        .map(|f| f.name)
        .collect()
}

/// Core field names only (convenience for the macro).
pub fn core_field_names(role: EntityRole) -> Vec<&'static str> {
    core_fields(role).iter().map(|f| f.name).collect()
}
