use axum::{
    extract::State,
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use validator::Validate;

use crate::utils::{
    hashing::{hash_password, verify_password},
    jwt::generate_token,
};

use crate::{
    models::user::CreateUser,
};

#[derive(Debug, Deserialize, Validate)]
pub struct RegisterRequest {
    #[validate(email(message = "Invalid email format"))]
    pub email: String,
    #[validate(length(min = 8, message = "Password must be at least 8 characters long"))]
    pub password: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct LoginRequest {
    #[validate(email(message = "Invalid email format"))]
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct RegisterResponse {
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub token: String,
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
}

/// Handler for user registration
///
/// # Arguments
/// * `State(pool)` - Database connection pool
/// * `Json(payload)` - Registration request containing email and password
///
/// # Returns
/// * `Result<Json<RegisterResponse>, (StatusCode, Json<ErrorResponse>)>` - Success or error response
pub async fn register_handler(
    State(pool): State<PgPool>,
    Json(payload): Json<RegisterRequest>,
) -> Result<Json<RegisterResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Validate request payload
    if let Err(validation_errors) = payload.validate() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: validation_errors.to_string(),
            }),
        ));
    }

    // Hash the password
    let hashed_password = hash_password(&payload.password).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to process password".to_string(),
            }),
        )
    })?;

    // Check if user already exists
    let existing_user = sqlx::query!(
        "SELECT id FROM users WHERE email = $1",
        payload.email
    )
    .fetch_optional(&pool)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Database error".to_string(),
            }),
        )
    })?;

    if existing_user.is_some() {
        return Err((
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                error: "Email already registered".to_string(),
            }),
        ));
    }

    // Insert new user
    sqlx::query!(
        "INSERT INTO users (email, hashed_password) VALUES ($1, $2)",
        payload.email,
        hashed_password,
    )
    .execute(&pool)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to create user".to_string(),
            }),
        )
    })?;

    Ok(Json(RegisterResponse {
        message: "User registered successfully".to_string(),
    }))
}

/// Handler for user login
///
/// # Arguments
/// * `State(pool)` - Database connection pool
/// * `Json(payload)` - Login request containing email and password
///
/// # Returns
/// * `Result<Json<LoginResponse>, (StatusCode, Json<ErrorResponse>)>` - JWT token or error response
pub async fn login_handler(
    State(pool): State<PgPool>,
    Json(payload): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Validate request payload
    if let Err(validation_errors) = payload.validate() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: validation_errors.to_string(),
            }),
        ));
    }

    // Fetch user from database
    let user = sqlx::query!(
        "SELECT id, hashed_password FROM users WHERE email = $1",
        payload.email
    )
    .fetch_optional(&pool)
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Database error".to_string(),
            }),
        )
    })?;

    // Check if user exists and verify password
    let user = match user {
        Some(user) => user,
        None => {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "Invalid credentials".to_string(),
                }),
            ))
        }
    };

    // Verify password
    let is_valid = verify_password(&user.hashed_password, &payload.password).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to verify password".to_string(),
            }),
        )
    })?;

    if !is_valid {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "Invalid credentials".to_string(),
            }),
        ));
    }

    // Generate JWT token
    let token = generate_token(user.id).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to generate token".to_string(),
            }),
        )
    })?;

    Ok(Json(LoginResponse { token }))
} 