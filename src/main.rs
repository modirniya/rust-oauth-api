mod config;
mod db;
mod handlers;
mod middleware;
mod models;
mod utils;

use axum::{
    routing::post,
    Router,
};
use std::net::SocketAddr;
use tower_http::trace::TraceLayer;

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
        .route("/register", post(handlers::auth::register_handler))
        .route("/login", post(handlers::auth::login_handler))
        .layer(TraceLayer::new_for_http())
        .with_state(pool);

    // Start server
    let addr = SocketAddr::from(([127, 0, 0, 1], config.server.port));
    println!("Server listening on {}", addr);

    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}
