use async_trait::async_trait;

use crate::{AuthUser, Result};

/// A trait which defines a method that allows retrieval of users from an arbitrary backend.
#[async_trait]
pub trait UserStore: std::fmt::Debug + Clone + Send + Sync + 'static {
    type User: AuthUser;

    /// Load and return a user.
    ///
    /// This provides a generic interface for loading a user from some store.
    /// For example, this might be a database or cache. It's assumed that a
    /// unique, stable identifier of the user is available. See [`AuthUser`]
    /// for expected minimal interface of the user type itself.
    #[must_use]
    async fn load_user(&self, user_id: &str) -> Result<Option<Self::User>>;
}
