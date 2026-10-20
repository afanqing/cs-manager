use std::collections::HashSet;

use axum::{
    extract::{Form, Path, Query, State},
    http::{header::SET_COOKIE, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::extract::cookie::CookieJar;
use rusqlite::{params, OptionalExtension};
use serde::Deserialize;

use crate::auth::{self, User};
use crate::docker_ops::{self, CreateSpec};
use crate::templates;
use crate::AppState;

const COOKIE_NAME: &str = "cs_session";

// ---------- 表单结构 ----------

#[derive(Deserialize)]
pub struct IndexQuery {
    pub err: Option<String>,
}

#[derive(Deserialize)]
pub struct LoginQuery {
    pub err: Option<String>,
}

#[derive(Deserialize)]
pub struct LoginForm {
    pub username: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct CreateForm {
    pub name: String,
    pub mem: u32,
    pub cpus: f32,
    pub git: Option<String>,
}

#[derive(Deserialize)]
pub struct ActionForm {
    pub act: String,
}

#[derive(Deserialize)]
pub struct ChangePasswordForm {
    pub new_password: String,
    pub confirm: String,
}

#[derive(Deserialize)]
pub struct CreateUserForm {
    pub username: String,
    pub role: String,
}

#[derive(Deserialize)]
pub struct VerifyQuery {
    pub instance: String,
}

// ---------- 辅助 ----------

async fn current(state: &AppState, jar: &CookieJar) -> Option<(User, String, String)> {
    let token = jar.get(COOKIE_NAME)?.value().to_string();
    let db = state.db.lock().await;
    let res = auth::load_session(&db, &token).ok().flatten();
    res.map(|(u, k)| (u, k, token))
}

async fn load_users(state: &AppState) -> Vec<(i64, String, String, i64)> {
    let db = state.db.lock().await;
    let mut stmt = match db
        .prepare("SELECT id, username, role, must_change_password FROM users ORDER BY id")
    {
        Ok(s) => s,
        Err(_) => return vec![],
    };
    let rows = stmt.query_map([], |r| {
        Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
    });
    match rows {
        Ok(iter) => iter.filter_map(|r| r.ok()).collect(),
        Err(_) => vec![],
    }
}

fn sanitize_name(s: &str) -> String {
    let cleaned: String = s
        .trim()
        .to_lowercase()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
        .collect();
    cleaned.trim_matches('-').to_string()
}

fn set_cookie_header(resp: &mut Response, value: &str) {
    if let Ok(v) = HeaderValue::from_str(value) {
        resp.headers_mut().append(SET_COOKIE, v);
    }
}

fn session_cookie(token: &str, domain: Option<&str>) -> String {
    let mut s = format!(
        "{}={}; Path=/; HttpOnly; SameSite=Lax; Max-Age={}",
        COOKIE_NAME,
        token,
        86400 * 7
    );
    if let Some(d) = domain {
        s.push_str(&format!("; Domain={}", d));
    }
    s
}

fn clear_cookie(domain: Option<&str>) -> String {
    let mut s = format!(
        "{}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0",
        COOKIE_NAME
    );
    if let Some(d) = domain {
        s.push_str(&format!("; Domain={}", d));
    }
    s
}

// ---------- 登录 / 登出 ----------

pub async fn login_page(Query(q): Query<LoginQuery>) -> impl IntoResponse {
    templates::login_page(q.err.is_some())
}

pub async fn login_submit(
    State(state): State<AppState>,
    Form(form): Form<LoginForm>,
) -> Response {
    let db = state.db.lock().await;
    let row: Option<(i64, String, i64)> = db
        .query_row(
            "SELECT id, password_hash, must_change_password FROM users WHERE username = ?1",
            params![form.username.trim()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()
        .ok()
        .flatten();
    drop(db);

    let (id, hash, must_change) = match row {
        Some(v) => v,
        None => return Redirect::to("/login?err=1").into_response(),
    };

    let password = form.password;
    let hash_clone = hash.clone();
    let ok = tokio::task::spawn_blocking(move || auth::verify_password(&password, &hash_clone))
        .await
        .unwrap_or(false);
    if !ok {
        return Redirect::to("/login?err=1").into_response();
    }

    let kind = if must_change != 0 { "pending_reset" } else { "full" };
    let db = state.db.lock().await;
    let token = match auth::create_session(&db, id, kind) {
        Ok(t) => t,
        Err(_) => return Redirect::to("/login?err=2").into_response(),
    };
    drop(db);

    let mut resp = if kind == "pending_reset" {
        Redirect::to("/change-password").into_response()
    } else {
        Redirect::to("/").into_response()
    };
    set_cookie_header(&mut resp, &session_cookie(&token, state.config.cookie_domain.as_deref()));
    resp
}

pub async fn logout(State(state): State<AppState>, jar: CookieJar) -> Response {
    if let Some(c) = jar.get(COOKIE_NAME) {
        let db = state.db.lock().await;
        let _ = auth::delete_session(&db, c.value());
    }
    let mut resp = Redirect::to("/login").into_response();
    set_cookie_header(&mut resp, &clear_cookie(state.config.cookie_domain.as_deref()));
    resp
}

// ---------- 首页 ----------

pub async fn index(
    State(state): State<AppState>,
    jar: CookieJar,
    Query(q): Query<IndexQuery>,
) -> Response {
    let (user, kind, _) = match current(&state, &jar).await {
        Some(v) => v,
        None => return Redirect::to("/login").into_response(),
    };
    if kind == "pending_reset" {
        return Redirect::to("/change-password").into_response();
    }

    let owner = if user.role == "admin" {
        None
    } else {
        Some(user.username.as_str())
    };
    let instances = docker_ops::list_instances(&state.docker, owner)
        .await
        .unwrap_or_default();

    templates::index_page(&user, &instances, &state.config, q.err.as_deref()).into_response()
}

// ---------- 实例操作 ----------

pub async fn create_instance(
    State(state): State<AppState>,
    jar: CookieJar,
    Form(form): Form<CreateForm>,
) -> Response {
    let (user, kind, _) = match current(&state, &jar).await {
        Some(v) => v,
        None => return Redirect::to("/login").into_response(),
    };
    if kind == "pending_reset" {
        return Redirect::to("/change-password").into_response();
    }

    let name = sanitize_name(&form.name);
    if name.is_empty() {
        return Redirect::to("/?err=name").into_response();
    }
    let mem = form.mem.clamp(256, 8192);
    let cpus = form.cpus.clamp(0.1, 8.0);

    // 容器名全局唯一，先查 Docker 里是否已存在
    if state.docker.inspect_container(&name, None).await.is_ok() {
        return Redirect::to("/?err=exists").into_response();
    }

    let instances = docker_ops::list_instances(&state.docker, None)
        .await
        .unwrap_or_default();
    let used: HashSet<u16> = instances
        .iter()
        .map(|i| i.port)
        .filter(|p| *p > 0)
        .collect();
    let port = match docker_ops::pick_free_port(&used, state.config.port_min, state.config.port_max)
    {
        Some(p) => p,
        None => return Redirect::to("/?err=port").into_response(),
    };

    let git = form.git.as_deref().map(str::trim).filter(|s| !s.is_empty());

    let spec = CreateSpec {
        name: &name,
        owner: &user.username,
        mem,
        cpus,
        git,
        port,
        base_dir: &state.config.base_dir,
        image: &state.config.image,
    };

    if let Err(e) = docker_ops::create_instance(&state.docker, spec).await {
        tracing::error!("create instance failed: {e}");
        return Redirect::to("/?err=create").into_response();
    }
    Redirect::to("/").into_response()
}

pub async fn instance_action(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(name): Path<String>,
    Form(form): Form<ActionForm>,
) -> Response {
    let (user, kind, _) = match current(&state, &jar).await {
        Some(v) => v,
        None => return Redirect::to("/login").into_response(),
    };
    if kind == "pending_reset" {
        return Redirect::to("/change-password").into_response();
    }

    let instances = docker_ops::list_instances(&state.docker, None)
        .await
        .unwrap_or_default();
    let inst = match instances.iter().find(|i| i.name == name) {
        Some(i) => i,
        None => return Redirect::to("/?err=notfound").into_response(),
    };
    if user.role != "admin" && inst.owner != user.username {
        return (StatusCode::FORBIDDEN, "无权限操作该实例").into_response();
    }

    let res = match form.act.as_str() {
        "start" => docker_ops::start(&state.docker, &name).await,
        "stop" => docker_ops::stop(&state.docker, &name).await,
        "remove" => docker_ops::remove(&state.docker, &name).await,
        _ => Ok(()),
    };
    if let Err(e) = res {
        tracing::error!("action {form_act} on {name} failed: {e}", form_act = form.act);
    }
    Redirect::to("/").into_response()
}

// ---------- 改密 ----------

pub async fn change_password_page(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Response {
    let _ = match current(&state, &jar).await {
        Some(v) => v,
        None => return Redirect::to("/login").into_response(),
    };
    templates::change_password_page(None).into_response()
}

pub async fn change_password_submit(
    State(state): State<AppState>,
    jar: CookieJar,
    Form(form): Form<ChangePasswordForm>,
) -> Response {
    let (user, _, _) = match current(&state, &jar).await {
        Some(v) => v,
        None => return Redirect::to("/login").into_response(),
    };
    if form.new_password.len() < 8 {
        return templates::change_password_page(Some("密码至少 8 位")).into_response();
    }
    if form.new_password != form.confirm {
        return templates::change_password_page(Some("两次输入不一致")).into_response();
    }

    let pw = form.new_password.clone();
    let hash = match tokio::task::spawn_blocking(move || auth::hash_password(&pw)).await {
        Ok(h) => h,
        Err(_) => return templates::change_password_page(Some("哈希失败")).into_response(),
    };

    let db = state.db.lock().await;
    let _ = db.execute(
        "UPDATE users SET password_hash = ?1, must_change_password = 0 WHERE id = ?2",
        params![hash, user.id],
    );
    let _ = auth::delete_user_sessions(&db, user.id);
    let new_token = auth::create_session(&db, user.id, "full").ok();
    drop(db);

    let token = match new_token {
        Some(t) => t,
        None => return Redirect::to("/login").into_response(),
    };

    let mut resp = Redirect::to("/").into_response();
    set_cookie_header(&mut resp, &session_cookie(&token, state.config.cookie_domain.as_deref()));
    resp
}

// ---------- 管理员：用户管理 ----------

pub async fn admin_users_page(State(state): State<AppState>, jar: CookieJar) -> Response {
    let (user, kind, _) = match current(&state, &jar).await {
        Some(v) => v,
        None => return Redirect::to("/login").into_response(),
    };
    if kind == "pending_reset" {
        return Redirect::to("/change-password").into_response();
    }
    if user.role != "admin" {
        return (StatusCode::FORBIDDEN, "仅管理员可访问").into_response();
    }
    let users = load_users(&state).await;
    templates::admin_users_page(&user, &users, None).into_response()
}

pub async fn admin_create_user(
    State(state): State<AppState>,
    jar: CookieJar,
    Form(form): Form<CreateUserForm>,
) -> Response {
    let (user, kind, _) = match current(&state, &jar).await {
        Some(v) => v,
        None => return Redirect::to("/login").into_response(),
    };
    if kind == "pending_reset" {
        return Redirect::to("/change-password").into_response();
    }
    if user.role != "admin" {
        return (StatusCode::FORBIDDEN, "仅管理员可操作").into_response();
    }

    let username = form.username.trim().to_lowercase();
    if username.is_empty()
        || !username
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Redirect::to("/admin/users?err=name").into_response();
    }
    let role = if form.role == "admin" { "admin" } else { "member" };

    let temp = auth::generate_temp_password();
    let pw = temp.clone();
    let hash = match tokio::task::spawn_blocking(move || auth::hash_password(&pw)).await {
        Ok(h) => h,
        Err(_) => return Redirect::to("/admin/users?err=hash").into_response(),
    };

    let db = state.db.lock().await;
    let res = db.execute(
        "INSERT INTO users (username, password_hash, role, must_change_password, created_at)
         VALUES (?1, ?2, ?3, 1, unixepoch())",
        params![username, hash, role],
    );
    drop(db);

    match res {
        Ok(_) => {
            let msg = format!(
                "用户 {} 创建成功。临时密码：{}（仅显示一次，请立即转交，首次登录须改密）",
                username, temp
            );
            let users = load_users(&state).await;
            templates::admin_users_page(&user, &users, Some(msg.as_str())).into_response()
        }
        Err(_) => Redirect::to("/admin/users?err=dup").into_response(),
    }
}

pub async fn admin_reset_password(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<i64>,
) -> Response {
    let (user, kind, _) = match current(&state, &jar).await {
        Some(v) => v,
        None => return Redirect::to("/login").into_response(),
    };
    if kind == "pending_reset" {
        return Redirect::to("/change-password").into_response();
    }
    if user.role != "admin" {
        return (StatusCode::FORBIDDEN, "仅管理员可操作").into_response();
    }

    let temp = auth::generate_temp_password();
    let pw = temp.clone();
    let hash = match tokio::task::spawn_blocking(move || auth::hash_password(&pw)).await {
        Ok(h) => h,
        Err(_) => return Redirect::to("/admin/users?err=hash").into_response(),
    };

    let db = state.db.lock().await;
    let _ = db.execute(
        "UPDATE users SET password_hash = ?1, must_change_password = 1 WHERE id = ?2",
        params![hash, id],
    );
    let _ = auth::delete_user_sessions(&db, id);
    drop(db);

    let msg = format!(
        "用户 ID {} 密码已重置。临时密码：{}（仅显示一次，用户下次登录须改密）",
        id, temp
    );
    let users = load_users(&state).await;
    templates::admin_users_page(&user, &users, Some(msg.as_str())).into_response()
}

// ---------- Nginx auth_request 校验端点 ----------

pub async fn auth_verify(
    State(state): State<AppState>,
    Query(q): Query<VerifyQuery>,
    headers: HeaderMap,
) -> Response {
    let jar = CookieJar::from_headers(&headers);

    let (user, kind, _) = match current(&state, &jar).await {
        Some(v) => v,
        None => return StatusCode::UNAUTHORIZED.into_response(),
    };
    if kind == "pending_reset" || user.must_change_password {
        return StatusCode::PRECONDITION_REQUIRED.into_response(); // 428
    }

    let info = match state.docker.inspect_container(&q.instance, None).await {
        Ok(c) => c,
        Err(_) => return StatusCode::NOT_FOUND.into_response(),
    };
    let labels = info
        .config
        .as_ref()
        .and_then(|c| c.labels.clone())
        .unwrap_or_default();
    let owner = labels.get("cs-owner").cloned().unwrap_or_default();
    let port: u16 = match labels.get("cs-port").and_then(|v| v.parse().ok()) {
        Some(p) if p > 0 => p,
        _ => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };

    if user.role != "admin" && owner != user.username {
        return StatusCode::FORBIDDEN.into_response();
    }

    let mut resp = StatusCode::NO_CONTENT.into_response();
    if let Ok(v) = HeaderValue::from_str(&port.to_string()) {
        resp.headers_mut().insert("X-CS-Port", v);
    }
    if let Ok(v) = HeaderValue::from_str(&user.username) {
        resp.headers_mut().insert("X-CS-User", v);
    }
    resp
}

pub async fn admin_delete_user(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<i64>,
) -> Response {
    let (user, kind, _) = match current(&state, &jar).await {
        Some(v) => v,
        None => return Redirect::to("/login").into_response(),
    };
    if kind == "pending_reset" {
        return Redirect::to("/change-password").into_response();
    }
    if user.role != "admin" {
        return (StatusCode::FORBIDDEN, "仅管理员可操作").into_response();
    }

    // 1. 不能删除自己
    if user.id == id {
        return Redirect::to("/admin/users?err=self").into_response();
    }

    // 查目标用户
    let db = state.db.lock().await;
    let target: Option<(String, String)> = db
        .query_row(
            "SELECT username, role FROM users WHERE id = ?1",
            params![id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .ok()
        .flatten();
    let (username, role) = match target {
        Some(v) => v,
        None => return Redirect::to("/admin/users?err=notfound").into_response(),
    };

    // 2. 不能删除最后一个 admin
    if role == "admin" {
        let admin_count: i64 = db
            .query_row("SELECT COUNT(*) FROM users WHERE role='admin'", [], |r| r.get(0))
            .unwrap_or(0);
        if admin_count <= 1 {
            return Redirect::to("/admin/users?err=last_admin").into_response();
        }
    }
    drop(db);

    // 3. 该用户还有实例时拒绝删除
    let instances = docker_ops::list_instances(&state.docker, Some(&username))
        .await
        .unwrap_or_default();
    if !instances.is_empty() {
        let names: Vec<&str> = instances.iter().map(|i| i.name.as_str()).collect();
        let msg = format!(
            "无法删除：用户 {} 还有 {} 个实例（{}），请先在首页删除这些实例",
            username,
            names.len(),
            names.join(", ")
        );
        let users = load_users(&state).await;
        return templates::admin_users_page(&user, &users, Some(&msg)).into_response();
    }

    // 4. 执行删除，sessions 通过外键级联清理
    let db = state.db.lock().await;
    let res = db.execute("DELETE FROM users WHERE id = ?1", params![id]);
    drop(db);

    let msg = match res {
        Ok(_) => format!("用户 {} 已删除，其所有会话已失效", username),
        Err(e) => format!("删除失败：{}", e),
    };
    let users = load_users(&state).await;
    templates::admin_users_page(&user, &users, Some(&msg)).into_response()
}