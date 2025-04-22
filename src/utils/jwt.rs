use jsonwebtoken::{encode, EncodingKey, Header, errors::Error as JwtError};
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::config::Config;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    /// Subject (user ID)
    sub: String,
    /// Expiration time (as UTC timestamp)
    exp: i64,
    /// Issued at (as UTC timestamp)
    iat: i64,
}

#[derive(Debug, thiserror::Error)]
pub enum TokenError {
    #[error("Failed to generate token: {0}")]
    TokenCreation(String),
    
    #[error("Failed to load configuration: {0}")]
    Configuration(String),
}

impl From<JwtError> for TokenError {
    fn from(err: JwtError) -> Self {
        TokenError::TokenCreation(err.to_string())
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

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{decode, DecodingKey, Validation};

    #[test]
    fn test_token_generation() {
        // Create a user ID
        let user_id = Uuid::new_v4();

        // Generate token
        let token = generate_token(user_id).expect("Failed to generate token");

        // Load config to get secret
        let config = Config::load().expect("Failed to load config");

        // Verify token
        let decoded = decode::<Claims>(
            &token,
            &DecodingKey::from_secret(config.jwt.secret.as_bytes()),
            &Validation::default(),
        )
        .expect("Failed to decode token");

        // Verify claims
        assert_eq!(decoded.claims.sub, user_id.to_string());
        assert!(decoded.claims.exp > decoded.claims.iat);
    }
} 