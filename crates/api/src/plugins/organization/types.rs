use better_auth_core::entity::MemberUserView;
use better_auth_core::entity::{AuthMember, AuthOrganization};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use validator::Validate;

fn deserialize_optional_usize_from_string<'de, D>(
    deserializer: D,
) -> Result<Option<usize>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Value {
        Number(usize),
        String(String),
    }

    let value = Option::<Value>::deserialize(deserializer)?;
    match value {
        None => Ok(None),
        Some(Value::Number(number)) => Ok(Some(number)),
        Some(Value::String(string)) => string
            .parse::<usize>()
            .map(Some)
            .map_err(serde::de::Error::custom),
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum RoleInput {
    One(String),
    Many(Vec<String>),
}

impl RoleInput {
    pub fn joined(&self) -> String {
        match self {
            Self::One(role) => role.clone(),
            Self::Many(roles) => roles.join(","),
        }
    }

    pub fn roles(&self) -> Vec<&str> {
        match self {
            Self::One(role) => role
                .split(',')
                .map(str::trim)
                .filter(|role| !role.is_empty())
                .collect(),
            Self::Many(roles) => roles
                .iter()
                .flat_map(|role| role.split(','))
                .map(str::trim)
                .filter(|role| !role.is_empty())
                .collect(),
        }
    }
}

#[derive(Debug, Deserialize, Validate)]
pub struct CreateOrganizationRequest {
    #[validate(length(min = 1, message = "Name is required"))]
    pub name: String,
    #[validate(length(min = 1, max = 100, message = "Slug must be 1-100 characters"))]
    pub slug: String,
    pub logo: Option<String>,
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct UpdateOrganizationData {
    pub name: Option<String>,
    pub slug: Option<String>,
    pub logo: Option<String>,
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct UpdateOrganizationRequest {
    #[serde(rename = "organizationId")]
    pub organization_id: Option<String>,
    pub data: UpdateOrganizationData,
}

#[derive(Debug, Deserialize, Validate)]
pub struct DeleteOrganizationRequest {
    #[serde(rename = "organizationId")]
    pub organization_id: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct CheckSlugRequest {
    pub slug: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct SetActiveOrganizationRequest {
    #[serde(rename = "organizationId")]
    pub organization_id: Option<Option<String>>,
    #[serde(rename = "organizationSlug")]
    pub organization_slug: Option<String>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct LeaveOrganizationRequest {
    #[serde(rename = "organizationId")]
    pub organization_id: String,
}

#[derive(Debug, Default, Deserialize)]
pub struct GetFullOrganizationQuery {
    #[serde(rename = "organizationId")]
    pub organization_id: Option<String>,
    #[serde(rename = "organizationSlug")]
    pub organization_slug: Option<String>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct InviteMemberRequest {
    #[validate(email(message = "Invalid email address"))]
    pub email: String,
    pub role: RoleInput,
    #[serde(rename = "organizationId")]
    pub organization_id: Option<String>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct RemoveMemberRequest {
    #[serde(rename = "memberIdOrEmail")]
    pub member_id_or_email: String,
    #[serde(rename = "organizationId")]
    pub organization_id: Option<String>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct UpdateMemberRoleRequest {
    #[serde(rename = "memberId")]
    pub member_id: String,
    pub role: RoleInput,
    #[serde(rename = "organizationId")]
    pub organization_id: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub struct ListMembersQuery {
    #[serde(rename = "organizationId")]
    pub organization_id: Option<String>,
    #[serde(rename = "organizationSlug")]
    pub organization_slug: Option<String>,
    #[serde(default, deserialize_with = "deserialize_optional_usize_from_string")]
    pub limit: Option<usize>,
    #[serde(default, deserialize_with = "deserialize_optional_usize_from_string")]
    pub offset: Option<usize>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct AcceptInvitationRequest {
    #[serde(rename = "invitationId")]
    pub invitation_id: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct RejectInvitationRequest {
    #[serde(rename = "invitationId")]
    pub invitation_id: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct CancelInvitationRequest {
    #[serde(rename = "invitationId")]
    pub invitation_id: String,
}

#[derive(Debug, Default, Deserialize)]
pub struct GetInvitationQuery {
    pub id: String,
}

#[derive(Debug, Default, Deserialize)]
pub struct GetActiveMemberRoleQuery {
    #[serde(rename = "userId")]
    pub user_id: Option<String>,
    #[serde(rename = "organizationId")]
    pub organization_id: Option<String>,
    #[serde(rename = "organizationSlug")]
    pub organization_slug: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub struct ListInvitationsQuery {
    #[serde(rename = "organizationId")]
    pub organization_id: Option<String>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct HasPermissionRequest {
    pub permissions: HashMap<String, Vec<String>>,
    #[serde(rename = "organizationId")]
    pub organization_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CheckSlugResponse {
    pub status: bool,
}

#[derive(Debug, Serialize)]
pub struct SuccessResponse {
    pub success: bool,
}

#[derive(Debug, Serialize)]
pub struct HasPermissionResponse {
    pub success: bool,
    pub error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CreateOrganizationResponse<O: Serialize, M: Serialize> {
    #[serde(flatten)]
    pub organization: O,
    pub members: Vec<M>,
}

#[derive(Debug, Serialize)]
pub struct FullOrganizationResponse<O: Serialize, I: Serialize> {
    #[serde(flatten)]
    pub organization: O,
    pub members: Vec<MemberResponse>,
    pub invitations: Vec<I>,
}

#[derive(Debug, Serialize)]
pub struct InvitationResponse<I: Serialize> {
    pub invitation: I,
}

#[derive(Debug, Serialize)]
pub struct RemovedMemberResponse {
    pub member: MemberResponse,
}

#[derive(Debug, Serialize)]
pub struct BasicMemberResponse {
    pub id: String,
    #[serde(rename = "userId")]
    pub user_id: String,
    #[serde(rename = "organizationId")]
    pub organization_id: String,
    pub role: String,
    #[serde(rename = "createdAt")]
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize)]
pub struct AcceptInvitationResponse<I: Serialize, M: Serialize> {
    pub invitation: I,
    pub member: M,
}

#[derive(Debug, Serialize)]
pub struct ListMembersResponse {
    pub members: Vec<MemberResponse>,
    pub total: usize,
}

#[derive(Debug, Serialize)]
pub struct GetActiveMemberRoleResponse {
    pub role: String,
}

#[derive(Debug, Serialize)]
pub struct GetInvitationResponse<I: Serialize> {
    #[serde(flatten)]
    pub invitation: I,
    #[serde(rename = "organizationName")]
    pub organization_name: String,
    #[serde(rename = "organizationSlug")]
    pub organization_slug: String,
    #[serde(rename = "inviterEmail")]
    pub inviter_email: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct UserInvitationResponse<I: Serialize> {
    #[serde(flatten)]
    pub invitation: I,
    #[serde(rename = "organizationName")]
    pub organization_name: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CreatedOrganizationResponse {
    pub id: String,
    pub name: String,
    pub slug: String,
    pub logo: Option<String>,
    #[serde(rename = "createdAt")]
    pub created_at: chrono::DateTime<chrono::Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize)]
pub struct OrganizationResponse {
    pub id: String,
    pub name: String,
    pub slug: String,
    pub logo: Option<String>,
    #[serde(rename = "createdAt")]
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub metadata: Option<serde_json::Value>,
}

fn normalize_metadata(metadata: Option<&serde_json::Value>) -> Option<serde_json::Value> {
    match metadata {
        None => None,
        Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::Object(map)) if map.is_empty() => None,
        Some(value) => Some(value.clone()),
    }
}

impl CreatedOrganizationResponse {
    pub fn from_organization(organization: &impl AuthOrganization) -> Self {
        Self {
            id: organization.id().to_string(),
            name: organization.name().to_string(),
            slug: organization.slug().to_string(),
            logo: organization.logo().map(str::to_owned),
            created_at: organization.created_at(),
            metadata: normalize_metadata(organization.metadata()),
        }
    }
}

impl OrganizationResponse {
    pub fn from_organization(organization: &impl AuthOrganization) -> Self {
        Self {
            id: organization.id().to_string(),
            name: organization.name().to_string(),
            slug: organization.slug().to_string(),
            logo: organization.logo().map(str::to_owned),
            created_at: organization.created_at(),
            metadata: normalize_metadata(organization.metadata()),
        }
    }
}

/// Member with user details (for API responses).
///
/// Uses [`MemberUserView`] from `better_auth_core::entity` for user info,
/// keeping it compatible with the built-in auth store.
#[derive(Debug, Clone, Serialize)]
pub struct MemberResponse {
    pub id: String,
    #[serde(rename = "organizationId")]
    pub organization_id: String,
    #[serde(rename = "userId")]
    pub user_id: String,
    pub role: String,
    #[serde(rename = "createdAt")]
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub user: MemberUserView,
}

impl MemberResponse {
    /// Construct from any type implementing [`AuthMember`](better_auth_core::entity::AuthMember) and [`AuthUser`](better_auth_core::entity::AuthUser).
    pub fn from_member_and_user(
        member: &impl better_auth_core::entity::AuthMember,
        user: &impl better_auth_core::entity::AuthUser,
    ) -> Self {
        Self {
            id: member.id().to_string(),
            organization_id: member.organization_id().to_string(),
            user_id: member.user_id().to_string(),
            role: member.role().to_string(),
            created_at: member.created_at(),
            user: MemberUserView::from_user(user),
        }
    }
}

impl BasicMemberResponse {
    pub fn from_member(member: &impl AuthMember) -> Self {
        Self {
            id: member.id().to_string(),
            organization_id: member.organization_id().to_string(),
            user_id: member.user_id().to_string(),
            role: member.role().to_string(),
            created_at: member.created_at(),
        }
    }
}
