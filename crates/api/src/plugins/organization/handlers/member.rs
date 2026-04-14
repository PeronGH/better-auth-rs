use better_auth_core::entity::{AuthMember, AuthOrganization, AuthSession, AuthUser};
use better_auth_core::error::{AuthError, AuthResult};
use better_auth_core::plugin::AuthContext;
use better_auth_core::types::{AuthRequest, AuthResponse};
use std::cmp::Ordering;

use super::{require_session, resolve_organization_id};
use crate::plugins::organization::OrganizationConfig;
use crate::plugins::organization::rbac::{Action, Resource, has_permission_any};
use crate::plugins::organization::types::{
    BasicMemberResponse, GetActiveMemberRoleQuery, GetActiveMemberRoleResponse, ListMembersQuery,
    ListMembersResponse, MemberResponse, RemoveMemberRequest, RemovedMemberResponse,
    UpdateMemberRoleRequest,
};

fn has_role(member: &impl AuthMember, role: &str) -> bool {
    member
        .role()
        .split(',')
        .map(str::trim)
        .any(|candidate| candidate == role)
}

fn member_field_value(member: &MemberResponse, field: &str) -> Option<String> {
    match field {
        "id" => Some(member.id.clone()),
        "organizationId" => Some(member.organization_id.clone()),
        "userId" => Some(member.user_id.clone()),
        "role" => Some(member.role.clone()),
        "createdAt" => Some(member.created_at.to_rfc3339()),
        _ => None,
    }
}

fn compare_member_field(left: &MemberResponse, right: &MemberResponse, field: &str) -> Ordering {
    match field {
        "createdAt" => left.created_at.cmp(&right.created_at),
        "role" => left.role.cmp(&right.role),
        "id" => left.id.cmp(&right.id),
        "organizationId" => left.organization_id.cmp(&right.organization_id),
        "userId" => left.user_id.cmp(&right.user_id),
        _ => Ordering::Equal,
    }
}

fn member_matches_filter(member: &MemberResponse, query: &ListMembersQuery) -> bool {
    let Some(field) = query.filter_field.as_deref() else {
        return true;
    };
    let Some(filter_value) = query.filter_value.as_deref() else {
        return true;
    };
    let operator = query.filter_operator.as_deref().unwrap_or("eq");
    let Some(actual_value) = member_field_value(member, field) else {
        return true;
    };

    match operator {
        "eq" => actual_value == filter_value,
        "ne" => actual_value != filter_value,
        "contains" => actual_value.contains(filter_value),
        "gt" | "gte" | "lt" | "lte" if field == "createdAt" => {
            let Ok(actual) = chrono::DateTime::parse_from_rfc3339(&actual_value) else {
                return false;
            };
            let Ok(expected) = chrono::DateTime::parse_from_rfc3339(filter_value) else {
                return false;
            };
            match operator {
                "gt" => actual > expected,
                "gte" => actual >= expected,
                "lt" => actual < expected,
                "lte" => actual <= expected,
                _ => false,
            }
        }
        "gt" => actual_value.as_str() > filter_value,
        "gte" => actual_value.as_str() >= filter_value,
        "lt" => actual_value.as_str() < filter_value,
        "lte" => actual_value.as_str() <= filter_value,
        _ => true,
    }
}

// ---------------------------------------------------------------------------
// Core functions
// ---------------------------------------------------------------------------

pub(crate) async fn get_active_member_core(
    user: &impl AuthUser,
    session: &impl AuthSession,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<MemberResponse> {
    let org_id = session
        .active_organization_id()
        .ok_or_else(|| AuthError::bad_request("No active organization"))?;

    let member = ctx
        .database
        .get_member(org_id, &user.id())
        .await?
        .ok_or_else(|| AuthError::bad_request("Member not found"))?;

    Ok(MemberResponse::from_member_and_user(&member, user))
}

pub(crate) async fn list_members_core(
    query: &ListMembersQuery,
    user: &impl AuthUser,
    session: &impl AuthSession,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<ListMembersResponse> {
    let org_id = if let Some(slug) = query.organization_slug.as_deref() {
        let organization = ctx
            .database
            .get_organization_by_slug(slug)
            .await?
            .ok_or_else(|| AuthError::bad_request("Organization not found"))?;
        organization.id().to_string()
    } else {
        resolve_organization_id(query.organization_id.as_deref(), None, session, ctx).await?
    };

    let _ = ctx
        .database
        .get_member(&org_id, &user.id())
        .await?
        .ok_or_else(|| AuthError::forbidden("You are not a member of this organization"))?;

    let needs_full_materialization = query.sort_by.is_some() || query.filter_field.is_some();
    let members_raw = ctx.database.list_organization_members(&org_id).await?;
    let members_page: Vec<_> = if needs_full_materialization {
        members_raw
    } else {
        let offset = query.offset.unwrap_or(0);
        let limit = query.limit.unwrap_or(50).min(100);
        members_raw.into_iter().skip(offset).take(limit).collect()
    };

    let mut members = Vec::with_capacity(members_page.len());
    for member in &members_page {
        if let Some(user_info) = ctx.database.get_user_by_id(&member.user_id()).await? {
            members.push(MemberResponse::from_member_and_user(member, &user_info));
        }
    }

    if needs_full_materialization {
        members.retain(|member| member_matches_filter(member, query));

        if let Some(sort_by) = query.sort_by.as_deref() {
            members.sort_by(|left, right| compare_member_field(left, right, sort_by));
            if matches!(query.sort_direction.as_deref(), Some("desc")) {
                members.reverse();
            }
        }

        let total = members.len();
        let offset = query.offset.unwrap_or(0);
        let limit = query.limit.unwrap_or(50).min(100);
        let members = members.into_iter().skip(offset).take(limit).collect();
        return Ok(ListMembersResponse { members, total });
    }

    let total = ctx.database.count_organization_members(&org_id).await? as usize;
    Ok(ListMembersResponse { members, total })
}

pub(crate) async fn get_active_member_role_core(
    query: &GetActiveMemberRoleQuery,
    user: &impl AuthUser,
    session: &impl AuthSession,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<GetActiveMemberRoleResponse> {
    let org_id = if let Some(slug) = query.organization_slug.as_deref() {
        let organization = ctx
            .database
            .get_organization_by_slug(slug)
            .await?
            .ok_or_else(|| AuthError::bad_request("Organization not found"))?;
        organization.id().to_string()
    } else {
        resolve_organization_id(query.organization_id.as_deref(), None, session, ctx).await?
    };

    let requester_member = ctx
        .database
        .get_member(&org_id, &user.id())
        .await?
        .ok_or_else(|| AuthError::forbidden("You are not a member of this organization"))?;

    if let Some(user_id) = query.user_id.as_deref() {
        let target_member = ctx
            .database
            .get_member(&org_id, user_id)
            .await?
            .ok_or_else(|| AuthError::forbidden("You are not a member of this organization"))?;
        return Ok(GetActiveMemberRoleResponse {
            role: target_member.role().to_string(),
        });
    }

    Ok(GetActiveMemberRoleResponse {
        role: requester_member.role().to_string(),
    })
}

pub(crate) async fn remove_member_core(
    body: &RemoveMemberRequest,
    user: &impl AuthUser,
    session: &impl AuthSession,
    config: &OrganizationConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<RemovedMemberResponse> {
    let org_id =
        resolve_organization_id(body.organization_id.as_deref(), None, session, ctx).await?;

    let requester_member = ctx
        .database
        .get_member(&org_id, &user.id())
        .await?
        .ok_or_else(|| AuthError::bad_request("Member not found"))?;

    let target_member = if body.member_id_or_email.contains('@') {
        let target_user = ctx
            .database
            .get_user_by_email(&body.member_id_or_email)
            .await?
            .ok_or_else(|| AuthError::bad_request("Member not found"))?;
        ctx.database
            .get_member(&org_id, &target_user.id())
            .await?
            .ok_or_else(|| AuthError::bad_request("Member not found"))?
    } else {
        let target_member = ctx
            .database
            .get_member_by_id(&body.member_id_or_email)
            .await?
            .ok_or_else(|| AuthError::bad_request("Member not found"))?;
        if target_member.organization_id() != org_id {
            return Err(AuthError::bad_request("Member not found"));
        }
        target_member
    };

    let target_user = ctx
        .database
        .get_user_by_id(&target_member.user_id())
        .await?
        .ok_or_else(|| AuthError::bad_request("User not found"))?;

    let is_self_removal = target_member.user_id() == user.id();

    if !is_self_removal
        && !has_permission_any(
            requester_member.role(),
            &Resource::Member,
            &Action::Delete,
            &config.roles,
        )
    {
        return Err(AuthError::forbidden(
            "You don't have permission to remove members",
        ));
    }

    if has_role(&target_member, &config.creator_role) {
        let all_members = ctx.database.list_organization_members(&org_id).await?;
        let owner_count = all_members
            .iter()
            .filter(|candidate| has_role(*candidate, &config.creator_role))
            .count();

        if owner_count <= 1 {
            return Err(AuthError::bad_request(
                "You cannot leave the organization as the only owner",
            ));
        }
    }

    let response = RemovedMemberResponse {
        member: MemberResponse::from_member_and_user(&target_member, &target_user),
    };

    ctx.database.delete_member(&target_member.id()).await?;

    if is_self_removal && session.active_organization_id() == Some(&org_id) {
        let _ = ctx
            .database
            .update_session_active_organization(session.token(), None)
            .await?;
    }

    Ok(response)
}

pub(crate) async fn update_member_role_core(
    body: &UpdateMemberRoleRequest,
    user: &impl AuthUser,
    session: &impl AuthSession,
    config: &OrganizationConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<BasicMemberResponse> {
    let org_id =
        resolve_organization_id(body.organization_id.as_deref(), None, session, ctx).await?;

    let requester_member = ctx
        .database
        .get_member(&org_id, &user.id())
        .await?
        .ok_or_else(|| AuthError::bad_request("Member not found"))?;

    if !has_permission_any(
        requester_member.role(),
        &Resource::Member,
        &Action::Update,
        &config.roles,
    ) {
        return Err(AuthError::forbidden(
            "You are not allowed to update this member",
        ));
    }

    let target_member = ctx
        .database
        .get_member_by_id(&body.member_id)
        .await?
        .ok_or_else(|| AuthError::bad_request("Member not found"))?;

    if target_member.organization_id() != org_id {
        return Err(AuthError::forbidden(
            "You are not allowed to update this member",
        ));
    }

    let requester_is_owner = has_role(&requester_member, &config.creator_role);
    let target_is_owner = has_role(&target_member, &config.creator_role);
    let new_role = body.role.joined();
    let new_role_contains_owner = new_role
        .split(',')
        .map(str::trim)
        .any(|role| role == config.creator_role);

    if (new_role_contains_owner || target_is_owner) && !requester_is_owner {
        return Err(AuthError::forbidden(
            "You are not allowed to update this member",
        ));
    }

    if target_is_owner && requester_member.id() == target_member.id() && !new_role_contains_owner {
        let all_members = ctx.database.list_organization_members(&org_id).await?;
        let owner_count = all_members
            .iter()
            .filter(|candidate| has_role(*candidate, &config.creator_role))
            .count();

        if owner_count <= 1 {
            return Err(AuthError::bad_request(
                "You cannot leave the organization without an owner",
            ));
        }
    }

    let updated = ctx
        .database
        .update_member_role(&body.member_id, &new_role)
        .await?;

    Ok(BasicMemberResponse::from_member(&updated))
}

// ---------------------------------------------------------------------------
// Old handlers (rewritten to call core)
// ---------------------------------------------------------------------------

/// Handle get active member request
pub async fn handle_get_active_member(
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<AuthResponse> {
    let (user, session) = require_session(req, ctx).await?;
    let response = get_active_member_core(&user, &session, ctx).await?;
    Ok(AuthResponse::json(200, &response)?)
}

/// Handle list members request
pub async fn handle_list_members(
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<AuthResponse> {
    let (user, session) = require_session(req, ctx).await?;
    let query = parse_query::<ListMembersQuery>(&req.query);
    let response = list_members_core(&query, &user, &session, ctx).await?;
    Ok(AuthResponse::json(200, &response)?)
}

/// Handle get active member role request
pub async fn handle_get_active_member_role(
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<AuthResponse> {
    let (user, session) = require_session(req, ctx).await?;
    let query = parse_query::<GetActiveMemberRoleQuery>(&req.query);
    let response = get_active_member_role_core(&query, &user, &session, ctx).await?;
    Ok(AuthResponse::json(200, &response)?)
}

/// Handle remove member request
pub async fn handle_remove_member(
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    config: &OrganizationConfig,
) -> AuthResult<AuthResponse> {
    let (user, session) = require_session(req, ctx).await?;
    let body: RemoveMemberRequest = match better_auth_core::validate_request_body(req) {
        Ok(v) => v,
        Err(resp) => return Ok(resp),
    };
    let response = remove_member_core(&body, &user, &session, config, ctx).await?;
    Ok(AuthResponse::json(200, &response)?)
}

/// Handle update member role request
pub async fn handle_update_member_role(
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    config: &OrganizationConfig,
) -> AuthResult<AuthResponse> {
    let (user, session) = require_session(req, ctx).await?;
    let body: UpdateMemberRoleRequest = match better_auth_core::validate_request_body(req) {
        Ok(v) => v,
        Err(resp) => return Ok(resp),
    };
    let response = update_member_role_core(&body, &user, &session, config, ctx).await?;
    Ok(AuthResponse::json(200, &response)?)
}

/// Helper function to parse query parameters into a struct
fn parse_query<T: Default + serde::de::DeserializeOwned>(
    query: &std::collections::HashMap<String, String>,
) -> T {
    let json_value =
        serde_json::to_value(query).unwrap_or(serde_json::Value::Object(Default::default()));
    serde_json::from_value(json_value).unwrap_or_default()
}
