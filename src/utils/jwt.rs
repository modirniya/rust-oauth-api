use jsonwebtoken::{
    decode, encode,
    errors::Error as JwtError,
    DecodingKey, EncodingKey, Header, TokenData, Validation,
};
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::config::Config;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    /// Subject (user ID)
    pub sub: String,
    /// Expiration time (as UTC timestamp)
    pub exp: i64,
    /// Issued at (as UTC timestamp)
    pub iat: i64,
}

#[derive(Debug, thiserror::Error)]
pub enum TokenError {
    #[error("Failed to generate token: {0}")]
    TokenCreation(String),
    
    #[error("Failed to decode token: {0}")]
    TokenDecoding(String),
    
    #[error("Token has expired")]
    TokenExpired,
    
    #[error("Invalid token format")]
    InvalidToken,
    
    #[error("Failed to load configuration: {0}")]
    Configuration(String),
}

impl From<JwtError> for TokenError {
    fn from(err: JwtError) -> Self {
        match err.kind() {
            jsonwebtoken::errors::ErrorKind::ExpiredSignature => TokenError::TokenExpired,
            jsonwebtoken::errors::ErrorKind::InvalidToken => TokenError::InvalidToken,
            _ => TokenError::TokenDecoding(err.to_string()),
        }
    }
}

/// Generates a JWT for a given user ID.
/// The token includes the user ID as subject and expiration time from config.
///
/// # Arguments
/// * `user_id` - The UUID of the user to generate token for
///
/// # Returns
/// * `Result<String, TokenError>` - The JWT string or an error
///
/// # Example
/// ```rust,no_run
/// use uuid::Uuid;
/// use crate::utils::jwt::generate_token;
///
/// let user_id = Uuid::new_v4();
/// let token = generate_token(user_id)?;
/// ```
pub fn generate_token(user_id: Uuid) -> Result<String, TokenError> {
    // Load configuration
    let config = Config::load()
        .map_err(|e| TokenError::Configuration(e.to_string()))?;

    // Get current timestamp and calculate expiration
    let now = OffsetDateTime::now_utc();
    let expiration = now + Duration::hours(config.jwt.expiration_hours as i64);

    // Create the claims
    let claims = Claims {
        sub: user_id.to_string(),
        exp: expiration.unix_timestamp(),
        iat: now.unix_timestamp(),
    };

    // Create the token
    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(config.jwt.secret.as_bytes()),
    )?;

    Ok(token)
}

/// Decodes and validates a JWT token.
/// Checks the signature and expiration time.
///
/// # Arguments
/// * `token` - The JWT string to decode and validate
///
/// # Returns
/// * `Result<TokenData<Claims>, TokenError>` - The decoded token data or an error
///
/// # Example
/// ```rust,no_run
/// use crate::utils::jwt::{generate_token, decode_token};
/// use uuid::Uuid;
///
/// let user_id = Uuid::new_v4();
/// let token = generate_token(user_id)?;
/// let token_data = decode_token(&token)?;
/// assert_eq!(token_data.claims.sub, user_id.to_string());
/// ```
pub fn decode_token(token: &str) -> Result<TokenData<Claims>, TokenError> {
    // Load configuration
    let config = Config::load()
        .map_err(|e| TokenError::Configuration(e.to_string()))?;

    // Set up validation
    let mut validation = Validation::default();
    validation.validate_exp = true; // Ensure token hasn't expired
    validation.leeway = 0; // No leeway for expiration time

    // Decode and validate the token
    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(config.jwt.secret.as_bytes()),
        &validation,
    )?;

    Ok(token_data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_generation_and_decoding() {
        // Create a user ID
        let user_id = Uuid::new_v4();

        // Generate token
        let token = generate_token(user_id).expect("Failed to generate token");

        // Decode and validate token
        let decoded = decode_token(&token).expect("Failed to decode token");

        // Verify claims
        assert_eq!(decoded.claims.sub, user_id.to_string());
        assert!(decoded.claims.exp > decoded.claims.iat);
    }

    #[test]
    fn test_expired_token() {
        // Create expired claims
        let now = OffsetDateTime::now_utc();
        let claims = Claims {
            sub: Uuid::new_v4().to_string(),
            exp: (now - Duration::hours(1)).unix_timestamp(), // 1 hour ago
            iat: (now - Duration::hours(2)).unix_timestamp(), // 2 hours ago
        };

        // Load config to get secret
        let config = Config::load().expect("Failed to load config");

        // Create expired token
        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(config.jwt.secret.as_bytes()),
        )
        .expect("Failed to create expired token");

        // Attempt to decode
        let result = decode_token(&token);
        assert!(matches!(result, Err(TokenError::TokenExpired)));
    }

    #[test]
    fn test_invalid_token() {
        let result = decode_token("invalid.token.format");
        assert!(matches!(result, Err(TokenError::InvalidToken)));
    }
} 