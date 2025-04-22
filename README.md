# Rust OAuth API

A robust OAuth2 API server built with Rust, featuring JWT authentication and PostgreSQL database integration.

## Features

- User authentication with JWT tokens
- Secure password hashing using Argon2
- PostgreSQL database with SQLx for type-safe queries
- RESTful API endpoints using Axum framework
- Environment-based configuration
- Database migrations
- Comprehensive test suite
- Postman collection for API testing

## Prerequisites

- Rust (latest stable version)
- PostgreSQL (version 12 or higher)
- Docker (optional, for containerization)

## Setup

1. Clone the repository:
```bash
git clone https://github.com/[username]/rust-oauth-api.git
cd rust-oauth-api
```

2. Create a `.env` file in the project root:
```env
DATABASE_URL=postgres://postgres:postgres@localhost:5432/oauth_api
```

3. Set up the database:
```bash
# Create the database
createdb oauth_api

# Run migrations
sqlx migrate run
```

4. Build and run the project:
```bash
cargo build
cargo run
```

The server will start at `http://127.0.0.1:8080`.

## API Endpoints

### Authentication

- `POST /register` - Register a new user
- `POST /login` - Login and receive JWT token

### Protected Routes

- `GET /me` - Get current user information (requires authentication)

## Testing

Import the provided Postman collection (`postman_collection.json`) to test the API endpoints.

### Running Tests

```bash
cargo test
```

## Configuration

The application can be configured using:
- Environment variables
- Configuration files in the `config` directory
- `.env` file for local development

## License

MIT License. See [LICENSE](LICENSE) for details. 