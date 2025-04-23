mod config;
mod db;
mod handlers;
mod middleware;
mod models;
mod utils;

use axum::{
    routing::{get, post},
    Router,
};
use sqlx::PgPool;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tower_http::trace::TraceLayer;
use axum::serve;

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
}

#[tokio::main]
async fn main() {
    // Initialize configuration
    let config = config::Config::load().expect("Failed to load configuration");

    // Set up database connection pool
    let pool = db::get_pool()
        .await
        .expect("Failed to create database pool");

    let state = AppState { db: pool.clone() };

    // Build application with routes
    let app = Router::new()
        // Auth routes
        .route("/register", post(handlers::auth::register))
        .route("/login", post(handlers::auth::login))
        .route("/verify-email", post(handlers::auth::verify_email))
        .route("/request-password-reset", post(handlers::auth::request_password_reset))
        .route("/reset-password", post(handlers::auth::reset_password))
        // Protected routes
        .route("/me", get(handlers::user::get_me))
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    // Start server
    let addr = SocketAddr::from(([127, 0, 0, 1], config.server.port));
    let listener = TcpListener::bind(addr).await.expect("Failed to bind to address");
    println!("Server listening on {}", addr);

    serve::serve(listener, app.into_make_service())
        .await
        .unwrap();
}
