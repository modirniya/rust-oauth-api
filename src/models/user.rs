use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
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
    
    pub is_verified: bool,
    pub verification_token: Option<String>,
    pub verification_token_expires_at: Option<OffsetDateTime>,
    pub reset_token: Option<String>,
    pub reset_token_expires_at: Option<OffsetDateTime>,
    pub updated_at: OffsetDateTime,
}

/// Represents the data needed to create a new user
#[derive(Debug, Deserialize)]
pub struct CreateUser {
    pub email: String,
    pub password: String,
    pub verification_token: Option<String>,
}

/// Represents the data needed to authenticate a user
#[derive(Debug, Deserialize)]
pub struct LoginUser {
    pub email: String,
    pub password: String,
}

impl User {
    pub async fn create(pool: &PgPool, user: CreateUser) -> Result<Self, sqlx::Error> {
        let hashed_password = Self::hash_password(&user.password)?;
        let verification_token_expires_at = user.verification_token.as_ref().map(|_| {
            OffsetDateTime::now_utc() + time::Duration::hours(24)
        });

        let user = sqlx::query_as!(
            User,
            r#"
            INSERT INTO users (
                email,
                hashed_password,
                verification_token,
                verification_token_expires_at
            )
            VALUES ($1, $2, $3, $4)
            RETURNING *
            "#,
            user.email,
            hashed_password,
            user.verification_token,
            verification_token_expires_at,
        )
        .fetch_one(pool)
        .await?;

        Ok(user)
    }

    pub async fn find_by_email(pool: &PgPool, email: &str) -> Result<Option<Self>, sqlx::Error> {
        let user = sqlx::query_as!(
            User,
            r#"
            SELECT *
            FROM users
            WHERE email = $1
            "#,
            email
        )
        .fetch_optional(pool)
        .await?;

        Ok(user)
    }

    pub async fn verify_email(pool: &PgPool, token: &str) -> Result<bool, sqlx::Error> {
        let result = sqlx::query!(
            r#"
            UPDATE users
            SET is_verified = TRUE,
                verification_token = NULL,
                verification_token_expires_at = NULL
            WHERE verification_token = $1
                AND verification_token_expires_at > CURRENT_TIMESTAMP
                AND is_verified = FALSE
            "#,
            token
        )
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    pub async fn set_reset_token(pool: &PgPool, user_id: Uuid, token: &str) -> Result<(), sqlx::Error> {
        let expires_at = OffsetDateTime::now_utc() + time::Duration::hours(1);

        sqlx::query!(
            r#"
            UPDATE users
            SET reset_token = $1,
                reset_token_expires_at = $2
            WHERE id = $3
            "#,
            token,
            expires_at,
            user_id
        )
        .execute(pool)
        .await?;

        Ok(())
    }

    pub async fn reset_password(pool: &PgPool, token: &str, new_password: &str) -> Result<bool, sqlx::Error> {
        let hashed_password = Self::hash_password(new_password)?;

        let result = sqlx::query!(
            r#"
            UPDATE users
            SET hashed_password = $1,
                reset_token = NULL,
                reset_token_expires_at = NULL
            WHERE reset_token = $2
                AND reset_token_expires_at > CURRENT_TIMESTAMP
            "#,
            hashed_password,
            token
        )
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    pub fn verify_password(&self, password: &str) -> bool {
        let parsed_hash = match PasswordHash::new(&self.hashed_password) {
            Ok(hash) => hash,
            Err(_) => return false,
        };

        Argon2::default()
            .verify_password(password.as_bytes(), &parsed_hash)
            .is_ok()
    }

    fn hash_password(password: &str) -> Result<String, sqlx::Error> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();

        argon2
            .hash_password(password.as_bytes(), &salt)
            .map(|hash| hash.to_string())
            .map_err(|e| sqlx::Error::Protocol(e.to_string()))
    }
} 