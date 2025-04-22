use axum::{
    extract::State,
    http::StatusCode,
    Json,
};
use serde::Serialize;
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::middleware::auth::AuthUser;

#[derive(Debug, Serialize)]
pub struct UserResponse {
    pub id: Uuid,
    pub email: String,
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
}

/// Handler for getting authenticated user's information
///
/// # Arguments
/// * `auth_user` - Authenticated user from JWT middleware
/// * `State(pool)` - Database connection pool
///
/// # Returns
/// * `Result<Json<UserResponse>, (StatusCode, Json<ErrorResponse>)>` - User info or error
pub async fn get_me(
    auth_user: AuthUser,
    State(pool): State<PgPool>,
) -> Result<Json<UserResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Query user information from database
    let user = sqlx::query!(
        "SELECT email, created_at FROM users WHERE id = $1",
        auth_user.user_id
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

    // Check if user exists
    let user = user.ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "User not found".to_string(),
            }),
        )
    })?;

    Ok(Json(UserResponse {
        id: auth_user.user_id,
        email: user.email,
        created_at: user.created_at,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
        routing::get,
        Router,
    };
    use tower::ServiceExt;

    #[tokio::test]
    async fn test_get_me_unauthorized() {
        let pool = PgPool::connect("postgres://postgres:postgres@localhost:5432/oauth_api")
            .await
            .unwrap();

        let app = Router::new()
            .route("/me", get(get_me))
            .with_state(pool);

        let response = app
            .oneshot(Request::builder().uri("/me").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
} 