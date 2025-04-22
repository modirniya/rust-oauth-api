use config::{Config as ConfigBuilder, ConfigError, Environment, File};
use serde::Deserialize;
use std::env;

#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    pub port: u16,
    pub host: String,
}

#[derive(Debug, Deserialize)]
pub struct DatabaseConfig {
    pub url: String,
}

#[derive(Debug, Deserialize)]
pub struct JwtConfig {
    pub secret: String,
    pub expiration_hours: u64,
}

#[derive(Debug, Deserialize)]
pub struct OAuthConfig {
    pub access_token_expiration_minutes: u64,
    pub refresh_token_expiration_days: u64,
}

#[derive(Debug, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub jwt: JwtConfig,
    pub oauth: OAuthConfig,
}

impl Config {
    pub fn load() -> Result<Self, ConfigError> {
        // Initialize configuration
        let config_builder = ConfigBuilder::builder()
            // Start with default configuration
            .add_source(File::with_name("config/default"))
            // Add environment-specific configuration if it exists
            .add_source(
                File::with_name(&format!(
                    "config/{}",
                    env::var("RUN_ENV").unwrap_or_else(|_| "development".to_string())
                ))
                .required(false),
            )
            // Add environment variables with prefix "APP_"
            .add_source(Environment::with_prefix("APP").separator("__"));

        // Build and convert configuration
        config_builder.build()?.try_deserialize()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_default_config() {
        let config = Config::load().expect("Failed to load configuration");
        
        // Test default values
        assert_eq!(config.server.port, 8080);
        assert_eq!(config.server.host, "127.0.0.1");
        assert!(config.database.url.contains("postgres://"));
        assert!(config.jwt.expiration_hours > 0);
        assert!(config.oauth.access_token_expiration_minutes > 0);
        assert!(config.oauth.refresh_token_expiration_days > 0);
    }
}
