use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use time::OffsetDateTime;
use uuid::Uuid;

/// Represents a user in the system
#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct User {
    /// Unique identifier for the user
    pub id: Uuid,
    
    /// User's email address (unique)
    pub email: String,
    
    /// Argon2id hashed password
    #[serde(skip_serializing)]
    pub hashed_password: String,
    
    /// Timestamp when the user was created
    pub created_at: OffsetDateTime,
}

/// Represents the data needed to create a new user
#[derive(Debug, Deserialize)]
pub struct CreateUser {
    pub email: String,
    pub password: String,
}

/// Represents the data needed to authenticate a user
#[derive(Debug, Deserialize)]
pub struct LoginUser {
    pub email: String,
    pub password: String,
} 