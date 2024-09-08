use async_trait::async_trait;
use axum_login::{AuthUser, AuthnBackend, UserId};

use openidconnect::{
    core::CoreErrorResponseType, core::{CoreIdTokenVerifier, CoreResponseType, CoreIdTokenClaims, CoreClient }, reqwest::async_http_client, url::Url,
    ClaimsVerificationError, AuthenticationFlow, AuthorizationCode, CsrfToken, Nonce, RequestTokenError, Scope,StandardErrorResponse
};

use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
}

// Here we've implemented `Debug` manually to avoid accidentally logging the
// access token.
impl std::fmt::Debug for User {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("User")
            .field("username", &self.id)
            .finish()
    }
}

impl AuthUser for User {
    type Id = String;

    fn id(&self) -> Self::Id {
        self.id.clone()
    }

    fn session_auth_hash(&self) -> &[u8] {
        self.id.as_bytes()
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Credentials {
    pub code: AuthorizationCode,
    pub old_state: CsrfToken,
    pub new_state: CsrfToken,
    pub nonce: Nonce
}

#[derive(Debug, Deserialize)]
struct UserInfo {
    login: String,
}

#[derive(Debug, thiserror::Error)]
pub enum BackendError {
    #[error(transparent)]
    OpenIdConnect(
        RequestTokenError<
            openidconnect::reqwest::HttpClientError,
            StandardErrorResponse<CoreErrorResponseType>,
        >,
    ),
    #[error(transparent)]
    OpenIdVerification( ClaimsVerificationError )
}

#[derive(Debug, Clone)]
pub struct Backend {
   client: CoreClient,
}

impl Backend {
    pub fn new(client: CoreClient) -> Self {
        Self { client }
    }

    pub fn authorize_url(&self) -> (Url, CsrfToken, Nonce) {
        self.client
            .authorize_url(
                AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            // This example is requesting access to the the user's profile including email.
            .add_scope(Scope::new("email".to_string()))
            .add_scope(Scope::new("profile".to_string()))
            .url()
    }
}

#[async_trait]
impl AuthnBackend for Backend {
    type User = User;
    type Credentials = Credentials;
    type Error = BackendError;

    async fn authenticate(
        &self,
        creds: Self::Credentials,
    ) -> Result<Option<Self::User>, Self::Error> {
        // Ensure the CSRF state has not been tampered with.
        if creds.old_state.secret() != creds.new_state.secret() {
            return Ok(None);
        };

        // Process authorization code, expecting a token response back.
        let token_response = self
            .client
            .exchange_code(creds.code)
            .request_async(async_http_client)
            .await
            .map_err(Self::Error::OpenIdConnect)?;
            
        let id_token_verifier: CoreIdTokenVerifier = self.client.id_token_verifier();
        let id_token_claims: &CoreIdTokenClaims = token_response
            .extra_fields()
            .id_token()
            .expect("Server did not return an ID token")
            .claims(&id_token_verifier, &creds.nonce)
            .map_err(Self::Error::OpenIdVerification)?;
        println!("Gitlab returned ID token: {:?}", id_token_claims.subject());
        Ok(Some(User {
            id: id_token_claims.subject().to_string(),
        }))
        
            }

    async fn get_user(&self, user_id: &UserId<Self>) -> Result<Option<Self::User>, Self::Error> {
        Ok(Some(User {
            id: user_id.clone(),
        }))
    }
}

// We use a type alias for convenience.
//
// Note that we've supplied our concrete backend here.
pub type AuthSession = axum_login::AuthSession<Backend>;
