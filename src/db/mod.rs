use sqlx::postgres::{PgPool, PgPoolOptions};
use std::time::Duration;

#[derive(Debug, thiserror::Error)]
pub enum DatabaseError {
    #[error("Failed to connect to database: {0}")]
    ConnectionError(String),
    #[error("Failed to create connection pool: {0}")]
    PoolError(String),
}

/// Creates and returns a connection pool to the PostgreSQL database.
/// The connection string is loaded from either the environment variable DATABASE_URL
/// or from the configuration file.
///
/// # Returns
/// * `Result<PgPool, DatabaseError>` - A connection pool or an error
///
/// # Example
/// ```rust,no_run
/// use crate::db::get_pool;
///
/// #[tokio::main]
/// async fn main() {
///     let pool = get_pool().await.expect("Failed to create pool");
/// }
/// ```
pub async fn get_pool() -> Result<PgPool, DatabaseError> {
    // Load .env file if it exists
    dotenvy::dotenv().ok();

    // Try to get database URL from environment first
    let database_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| {
        // If not in environment, load from config
        let config = crate::config::Config::load()
            .expect("Failed to load configuration");
        config.database.url
    });

    // Create connection pool with custom configuration
    PgPoolOptions::new()
        .max_connections(5) // Adjust based on your needs
        .acquire_timeout(Duration::from_secs(3))
        .idle_timeout(Duration::from_secs(600)) // 10 minutes
        .connect(&database_url)
        .await
        .map_err(|e| DatabaseError::PoolError(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_pool_creation() {
        // This test requires a running database
        // It will be skipped if DATABASE_URL is not set
        if std::env::var("DATABASE_URL").is_ok() {
            let pool = get_pool().await;
            assert!(pool.is_ok(), "Should create pool successfully");

            // Test that we can actually query the database
            if let Ok(pool) = pool {
                let result = sqlx::query("SELECT 1")
                    .fetch_one(&pool)
                    .await;
                assert!(result.is_ok(), "Should execute simple query successfully");
            }
        }
    }
}
