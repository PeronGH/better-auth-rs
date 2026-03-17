//! Proc macros used internally by the better-auth workspace.

mod auth_entity;
mod auth_schema;
mod plugin_config;

use proc_macro::TokenStream;
use syn::{DeriveInput, parse_macro_input};

#[proc_macro_derive(AuthEntity, attributes(auth))]
pub fn derive_auth_entity(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    auth_entity::derive_auth_entity(&input).into()
}

#[proc_macro_derive(AuthSchema, attributes(auth))]
pub fn derive_auth_schema(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    auth_schema::derive_auth_schema(&input).into()
}

#[proc_macro_derive(PluginConfig, attributes(plugin, config))]
pub fn derive_plugin_config(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    plugin_config::derive_plugin_config(&input).into()
}
