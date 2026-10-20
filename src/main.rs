mod auth;
mod db;
mod docker_ops;
mod handlers;
mod templates;

use std::sync::Arc;

use axum::{
    routing::{get, post},
    Router,
};
use bollard::Docker;
use rusqlite::Connection;
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct AppState {
    pub db: Arc<Mutex<Connection>>,
    pub docker: Arc<Docker>,
    pub config: Arc<Config>,
}

#[derive(Clone)]
pub struct Config {
    pub hostname_suffix: String,
    pub base_dir: String,
    pub port_min: u16,
    pub port_max: u16,
    pub image: String,
    pub cookie_domain: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let db_path = std::env::var("CS_DB")
        .unwrap_or_else(|_| "/opt/cs-manager/data.db".into());
    let conn = db::init(&db_path)?;
    let docker = Docker::connect_with_local_defaults()?;

    let domain = std::env::var("CS_DOMAIN")
        .unwrap_or_else(|_| "code.example.com".into());
    let cookie_domain = std::env::var("CS_COOKIE_DOMAIN").ok().or_else(|| {
        if domain.contains('.') {
            Some(format!(".{}", domain))
        } else {
            None
        }
    });

    let config = Config {
        hostname_suffix: domain,
        base_dir: std::env::var("CS_BASE_DIR")
            .unwrap_or_else(|_| "/opt/code-server-instances".into()),
        port_min: 8200,
        port_max: 8299,
        image: std::env::var("CS_IMAGE")
            .unwrap_or_else(|_| "codercom/code-server:latest".into()),
        cookie_domain,
    };

    auth::ensure_admin(&conn, &std::env::var("CS_ADMIN_PASSWORD").ok())?;

    let state = AppState {
        db: Arc::new(Mutex::new(conn)),
        docker: Arc::new(docker),
        config: Arc::new(config),
    };

    let app = Router::new()
        .route("/login", get(handlers::login_page).post(handlers::login_submit))
        .route("/logout", post(handlers::logout))
        .route("/", get(handlers::index))
        .route("/instances", post(handlers::create_instance))
        .route("/instances/:name/action", post(handlers::instance_action))
        .route(
            "/change-password",
            get(handlers::change_password_page).post(handlers::change_password_submit),
        )
        .route(
            "/admin/users",
            get(handlers::admin_users_page).post(handlers::admin_create_user),
        )
        .route("/admin/users/:id/reset", post(handlers::admin_reset_password))
        .route("/admin/users/:id/delete", post(handlers::admin_delete_user))
        .route("/api/auth/verify", get(handlers::auth_verify))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:8100").await?;
    tracing::info!("cs-manager listening on 127.0.0.1:8100");
    axum::serve(listener, app).await?;
    Ok(())
}