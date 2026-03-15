pub use super::traits::{
    AccountOps, ApiKeyOps, InvitationOps, MemberOps, OrganizationOps, PasskeyOps, SessionOps,
    TwoFactorOps, UserOps, VerificationOps,
};
use crate::types::{
    Account, ApiKey, Invitation, Member, Organization, Passkey, Session, TwoFactor, User,
    Verification,
};

/// Internal persistence trait that combines all auth store operations.
pub trait DatabaseAdapter:
    UserOps
    + SessionOps
    + AccountOps
    + VerificationOps
    + OrganizationOps
    + MemberOps
    + InvitationOps
    + TwoFactorOps
    + ApiKeyOps
    + PasskeyOps
{
}

impl<T> DatabaseAdapter for T where
    T: UserOps
        + SessionOps
        + AccountOps
        + VerificationOps
        + OrganizationOps
        + MemberOps
        + InvitationOps
        + TwoFactorOps
        + ApiKeyOps
        + PasskeyOps
{
}

/// Concrete auth store trait object used by the SeaORM-backed runtime.
pub type AuthDatabase = dyn DatabaseAdapter<
        User = User,
        Session = Session,
        Account = Account,
        Organization = Organization,
        Member = Member,
        Invitation = Invitation,
        Verification = Verification,
        TwoFactor = TwoFactor,
        ApiKey = ApiKey,
        Passkey = Passkey,
    >;
