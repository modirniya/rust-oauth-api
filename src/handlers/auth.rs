use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    Json,
    debug_handler,
};
use serde::{Deserialize, Serialize};
use validator::Validate;
use uuid::Uuid;

use crate::utils::email::{send_verification_email, send_password_reset_email};

use crate::{
    models::user::{CreateUser, User},
};

use crate::AppState;

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

#[derive(Debug, Deserialize, Validate)]
pub struct VerifyEmailRequest {
    pub token: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct RequestPasswordResetRequest {
    #[validate(email(message = "Invalid email format"))]
    pub email: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct ResetPasswordRequest {
    pub token: String,
    #[validate(length(min = 8, message = "Password must be at least 8 characters long"))]
    pub new_password: String,
}

#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub message: String,
}

/// Handler for user registration
///
/// # Arguments
/// * `State(state)` - Application state containing database connection pool
/// * `Json(req)` - Registration request containing email and password
///
/// # Returns
/// * `impl IntoResponse` - Result of the operation
#[debug_handler]
pub async fn register(
    State(state): State<AppState>,
    Json(req): Json<RegisterRequest>,
) -> impl IntoResponse {
    let pool = &state.db;
    
    // Check if user already exists
    if let Ok(Some(_)) = User::find_by_email(pool, &req.email).await {
        return (
            StatusCode::CONFLICT,
            Json(AuthResponse {
                message: "User already exists".to_string(),
            }),
        );
    }

    // Generate verification token
    let verification_token = Uuid::new_v4().to_string();

    // Create user
    let create_user = CreateUser {
        email: req.email.clone(),
        password: req.password,
        verification_token: Some(verification_token.clone()),
    };

    match User::create(pool, create_user).await {
        Ok(_) => {
            // Send verification email
            if let Err(e) = send_verification_email(&req.email, &verification_token).await {
                eprintln!("Failed to send verification email: {}", e);
            }

            (
                StatusCode::CREATED,
                Json(AuthResponse {
                    message: "User registered successfully. Please check your email for verification.".to_string(),
                }),
            )
        }
        Err(e) => {
            eprintln!("Failed to create user: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(AuthResponse {
                    message: "Failed to register user".to_string(),
                }),
            )
        }
    }
}

/// Handler for user login
///
/// # Arguments
/// * `State(state)` - Application state containing database connection pool
/// * `Json(req)` - Login request containing email and password
///
/// # Returns
/// * `impl IntoResponse` - Result of the operation
#[debug_handler]
pub async fn login(
    State(state): State<AppState>,
    Json(req): Json<LoginRequest>,
) -> impl IntoResponse {
    let pool = &state.db;

    match User::find_by_email(pool, &req.email).await {
        Ok(Some(user)) => {
            if !user.is_verified {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(AuthResponse {
                        message: "Email not verified".to_string(),
                    }),
                );
            }

            if user.verify_password(&req.password) {
                (
                    StatusCode::OK,
                    Json(AuthResponse {
                        message: "Login successful".to_string(),
                    }),
                )
            } else {
                (
                    StatusCode::UNAUTHORIZED,
                    Json(AuthResponse {
                        message: "Invalid credentials".to_string(),
                    }),
                )
            }
        }
        Ok(None) => (
            StatusCode::UNAUTHORIZED,
            Json(AuthResponse {
                message: "Invalid credentials".to_string(),
            }),
        ),
        Err(e) => {
            eprintln!("Failed to find user: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(AuthResponse {
                    message: "Failed to process login".to_string(),
                }),
            )
        }
    }
}

/// Handler for email verification
///
/// # Arguments
/// * `State(state)` - Application state containing database connection pool
/// * `Json(req)` - Verify email request containing token
///
/// # Returns
/// * `impl IntoResponse` - Result of the operation
#[debug_handler]
pub async fn verify_email(
    State(state): State<AppState>,
    Json(req): Json<VerifyEmailRequest>,
) -> impl IntoResponse {
    let pool = &state.db;

    match User::verify_email(pool, &req.token).await {
        Ok(true) => (
            StatusCode::OK,
            Json(AuthResponse {
                message: "Email verified successfully".to_string(),
            }),
        ),
        Ok(false) => (
            StatusCode::BAD_REQUEST,
            Json(AuthResponse {
                message: "Invalid or expired verification token".to_string(),
            }),
        ),
        Err(e) => {
            eprintln!("Failed to verify email: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(AuthResponse {
                    message: "Failed to verify email".to_string(),
                }),
            )
        }
    }
}

/// Handler for requesting password reset
///
/// # Arguments
/// * `State(state)` - Application state containing database connection pool
/// * `Json(req)` - Request password reset request containing email
///
/// # Returns
/// * `impl IntoResponse` - Result of the operation
#[debug_handler]
pub async fn request_password_reset(
    State(state): State<AppState>,
    Json(req): Json<RequestPasswordResetRequest>,
) -> impl IntoResponse {
    let pool = &state.db;

    match User::find_by_email(pool, &req.email).await {
        Ok(Some(user)) => {
            let reset_token = Uuid::new_v4().to_string();

            match User::set_reset_token(pool, user.id, &reset_token).await {
                Ok(_) => {
                    if let Err(e) = send_password_reset_email(&req.email, &reset_token).await {
                        eprintln!("Failed to send password reset email: {}", e);
                    }

                    (
                        StatusCode::OK,
                        Json(AuthResponse {
                            message: "Password reset instructions sent to your email".to_string(),
                        }),
                    )
                }
                Err(e) => {
                    eprintln!("Failed to set reset token: {}", e);
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(AuthResponse {
                            message: "Failed to process password reset request".to_string(),
                        }),
                    )
                }
            }
        }
        Ok(None) => (
            StatusCode::OK,
            Json(AuthResponse {
                message: "If an account exists with this email, password reset instructions will be sent".to_string(),
            }),
        ),
        Err(e) => {
            eprintln!("Failed to find user: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(AuthResponse {
                    message: "Failed to process password reset request".to_string(),
                }),
            )
        }
    }
}

/// Handler for resetting password
///
/// # Arguments
/// * `State(state)` - Application state containing database connection pool
/// * `Json(req)` - Reset password request containing token and new password
///
/// # Returns
/// * `impl IntoResponse` - Result of the operation
#[debug_handler]
pub async fn reset_password(
    State(state): State<AppState>,
    Json(req): Json<ResetPasswordRequest>,
) -> impl IntoResponse {
    let pool = &state.db;

    match User::reset_password(pool, &req.token, &req.new_password).await {
        Ok(true) => (
            StatusCode::OK,
            Json(AuthResponse {
                message: "Password reset successfully".to_string(),
            }),
        ),
        Ok(false) => (
            StatusCode::BAD_REQUEST,
            Json(AuthResponse {
                message: "Invalid or expired reset token".to_string(),
            }),
        ),
        Err(e) => {
            eprintln!("Failed to reset password: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(AuthResponse {
                    message: "Failed to reset password".to_string(),
                }),
            )
        }
    }
} 