use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};

#[derive(Debug, thiserror::Error)]
pub enum HashingError {
    #[error("Failed to generate password hash: {0}")]
    HashingError(String),
    #[error("Failed to verify password: {0}")]
    VerificationError(String),
}

/// Hashes a plain text password using Argon2id.
///
/// # Arguments
/// * `plain` - The plain text password to hash
///
/// # Returns
/// * `Result<String, HashingError>` - The hashed password or an error
///
/// # Example
/// ```
/// use crate::utils::hashing::hash_password;
///
/// let hash = hash_password("my_secure_password").unwrap();
/// ```
pub fn hash_password(plain: &str) -> Result<String, HashingError> {
    // Generate a random salt
    let salt = SaltString::generate(&mut OsRng);

    // Configure Argon2id hasher
    let argon2 = Argon2::default();

    // Hash the password
    argon2
        .hash_password(plain.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|e| HashingError::HashingError(e.to_string()))
}

/// Verifies a plain text password against a hash.
///
/// # Arguments
/// * `hash` - The hashed password to verify against
/// * `plain` - The plain text password to verify
///
/// # Returns
/// * `Result<bool, HashingError>` - Whether the password matches or an error
///
/// # Example
/// ```
/// use crate::utils::hashing::{hash_password, verify_password};
///
/// let hash = hash_password("my_secure_password").unwrap();
/// let is_valid = verify_password(&hash, "my_secure_password").unwrap();
/// assert!(is_valid);
/// ```
pub fn verify_password(hash: &str, plain: &str) -> Result<bool, HashingError> {
    // Parse the hash string
    let parsed_hash = PasswordHash::new(hash)
        .map_err(|e| HashingError::VerificationError(e.to_string()))?;

    // Verify the password
    Ok(Argon2::default()
        .verify_password(plain.as_bytes(), &parsed_hash)
        .is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_hashing_and_verification() {
        let password = "secure_password_123";
        
        // Test password hashing
        let hash = hash_password(password).expect("Failed to hash password");
        assert!(!hash.is_empty());
        assert!(hash.starts_with("$argon2id$"));

        // Test successful verification
        let is_valid = verify_password(&hash, password).expect("Failed to verify password");
        assert!(is_valid);

        // Test failed verification
        let is_valid = verify_password(&hash, "wrong_password").expect("Failed to verify password");
        assert!(!is_valid);
    }

    #[test]
    fn test_invalid_hash_format() {
        let result = verify_password("invalid_hash", "password");
        assert!(result.is_err());
    }
} 