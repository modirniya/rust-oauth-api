use async_trait::async_trait;
use axum::{
    extract::FromRequestParts,
    headers::{authorization::Bearer, Authorization},
    http::request::Parts,
    RequestPartsExt,
    TypedHeader,
};
use uuid::Uuid;

use crate::utils::jwt::{decode_token, TokenError};

/// Represents an authenticated user's identity
#[derive(Debug, Clone)]
pub struct AuthUser {
    /// The authenticated user's ID
    pub user_id: Uuid,
}

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("Missing authorization header")]
    MissingCredentials,
    
    #[error("Invalid authorization header")]
    InvalidAuthHeader,
    
    #[error("Invalid token: {0}")]
    InvalidToken(String),
    
    #[error("Token expired")]
    TokenExpired,
}

/// Extractor for authenticated users.
/// This will extract and validate the JWT from the Authorization header,
/// and provide the user's ID to the handler.
///
/// # Example
/// ```rust,no_run
/// use axum::Router;
/// use crate::middleware::auth::AuthUser;
///
/// async fn protected_handler(auth_user: AuthUser) {
///     println!("User {} accessed protected resource", auth_user.user_id);
/// }
///
/// let app = Router::new()
///     .route("/protected", get(protected_handler));
/// ```
#[async_trait]
impl<S> FromRequestParts<S> for AuthUser
where
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        // Extract the token from the Authorization header
        let TypedHeader(Authorization(bearer)) = parts
            .extract::<TypedHeader<Authorization<Bearer>>>()
            .await
            .map_err(|_| AuthError::MissingCredentials)?;

        // Decode and validate the token
        let token_data = decode_token(bearer.token()).map_err(|e| match e {
            TokenError::TokenExpired => AuthError::TokenExpired,
            _ => AuthError::InvalidToken(e.to_string()),
        })?;

        // Parse the user ID from the token's subject claim
        let user_id = Uuid::parse_str(&token_data.claims.sub)
            .map_err(|_| AuthError::InvalidToken("Invalid user ID format".to_string()))?;

        Ok(AuthUser { user_id })
    }
}

/// Convert auth errors to responses
impl From<AuthError> for axum::http::StatusCode {
    fn from(err: AuthError) -> Self {
        match err {
            AuthError::MissingCredentials => axum::http::StatusCode::UNAUTHORIZED,
            AuthError::InvalidAuthHeader => axum::http::StatusCode::UNAUTHORIZED,
            AuthError::InvalidToken(_) => axum::http::StatusCode::UNAUTHORIZED,
            AuthError::TokenExpired => axum::http::StatusCode::UNAUTHORIZED,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
        response::Response,
        routing::get,
        Router,
    };
    use tower::ServiceExt;

    async fn test_handler(auth_user: AuthUser) -> String {
        auth_user.user_id.to_string()
    }

    #[tokio::test]
    async fn test_missing_auth_header() {
        let app = Router::new().route("/test", get(test_handler));

        let response = app
            .oneshot(Request::builder().uri("/test").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_invalid_token() {
        let app = Router::new().route("/test", get(test_handler));

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/test")
                    .header("Authorization", "Bearer invalid.token.here")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
} 