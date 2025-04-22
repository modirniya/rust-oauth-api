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
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tower_http::trace::TraceLayer;
use axum::serve;

#[tokio::main]
async fn main() {
    // Initialize configuration
    let config = config::Config::load().expect("Failed to load configuration");

    // Set up database connection pool
    let pool = db::get_pool()
        .await
        .expect("Failed to create database pool");

    // Build application with routes
    let app = Router::new()
        // Auth routes
        .route("/register", post(handlers::auth::register_handler))
        .route("/login", post(handlers::auth::login_handler))
        // Protected routes
        .route("/me", get(handlers::user::get_me))
        .layer(TraceLayer::new_for_http())
        .with_state(pool);

    // Start server
    let addr = SocketAddr::from(([127, 0, 0, 1], config.server.port));
    let listener = TcpListener::bind(addr).await.expect("Failed to bind to address");
    println!("Server listening on {}", addr);

    serve::serve(listener, app.into_make_service())
        .await
        .unwrap();
}
