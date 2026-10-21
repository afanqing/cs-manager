mod auth;
mod db;
mod docker_ops;
mod handlers;
mod templates;

use handlers::admin;
use handlers::auth_handlers;
use handlers::auth_verify;
use handlers::instance;

use std::sync::Arc;

use axum::{
    routing::{get, post},
    Router,
};
use bollard::Docker;
use rusqlite::Connection;
use tokio::sync::Mutex;

/// 全局应用状态，通过 `State` 注入到所有 handler。
#[derive(Clone)]
pub struct AppState {
    /// SQLite 连接（Tokio Mutex 保护，跨 await 持锁）。
    pub db: Arc<Mutex<Connection>>,
    /// Bollard Docker 客户端。
    pub docker: Arc<Docker>,
    /// 面板配置。
    pub config: Arc<Config>,
}

/// 面板运行时配置，全部来自环境变量。
#[derive(Clone)]
pub struct Config {
    /// 实例子域名后缀（如 `afanai.top`），用于生成 `cs-<name>.<suffix>` 链接。
    pub hostname_suffix: String,
    /// 实例数据目录根路径（如 `/opt/code-server-instances`）。
    pub base_dir: String,
    /// 实例端口分配下限（含）。
    pub port_min: u16,
    /// 实例端口分配上限（含）。
    pub port_max: u16,
    /// code-server Docker 镜像。
    pub image: String,
    /// Cookie 的 Domain 属性（如 `.afanai.top`），None 表示 host-only。
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

    // 初始化默认镜像（从 CS_IMAGE 环境变量读取）
    let default_image = std::env::var("CS_IMAGE")
        .unwrap_or_else(|_| "codercom/code-server:latest".into());
    db::ensure_default_image(&conn, &default_image)?;

    let state = AppState {
        db: Arc::new(Mutex::new(conn)),
        docker: Arc::new(docker),
        config: Arc::new(config),
    };

    let app = Router::new()
        .route("/login", get(auth_handlers::login_page).post(auth_handlers::login_submit))
        .route("/logout", post(auth_handlers::logout))
        .route("/", get(instance::index))
        .route("/instances", post(instance::create_instance))
        .route("/instances/:name/action", post(instance::instance_action))
        .route("/instances/:name/resources", post(instance::update_instance_resources))
        .route(
            "/change-password",
            get(auth_handlers::change_password_page).post(auth_handlers::change_password_submit),
        )
        .route(
            "/admin/users",
            get(admin::admin_users_page).post(admin::admin_create_user),
        )
        .route("/admin/users/:id/reset", post(admin::admin_reset_password))
        .route("/admin/users/:id/delete", post(admin::admin_delete_user))
        .route("/admin/audit-logs", get(admin::admin_audit_logs_page))
        .route(
            "/admin/images",
            get(admin::admin_images_page).post(admin::admin_create_image),
        )
        .route("/admin/images/:id/delete", post(admin::admin_delete_image))
        .route("/admin/images/:id/set-default", post(admin::admin_set_default_image))
        .route("/admin/images/:id/pull", post(admin::admin_pull_image))
        .route("/api/auth/verify", get(auth_verify::auth_verify))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:8100").await?;
    tracing::info!("cs-manager listening on 127.0.0.1:8100");
    axum::serve(listener, app).await?;
    Ok(())
}