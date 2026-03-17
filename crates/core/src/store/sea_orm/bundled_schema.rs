//! Internal bundled schema used by the workspace and tests.

use crate::schema::AuthSchema;

pub struct BundledSchema;

impl AuthSchema for BundledSchema {
    type User = crate::store::sea_orm::entities::user::Model;
    type Session = crate::store::sea_orm::entities::session::Model;
    type Account = crate::store::sea_orm::entities::account::Model;
    type Verification = crate::store::sea_orm::entities::verification::Model;
}
