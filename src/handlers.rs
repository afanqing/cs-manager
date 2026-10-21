use std::collections::HashSet;

use axum::{
    extract::{Form, Path, Query, State},
    http::{header::SET_COOKIE, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::extract::cookie::CookieJar;
use rand::RngCore;
use rusqlite::{params, OptionalExtension};
use serde::Deserialize;

use crate::auth::{self, User};
use crate::docker_ops::{self, CreateSpec};
use crate::templates;
use crate::{AppState, Config};

const COOKIE_NAME: &str = "cs_session";
const CSRF_COOKIE_NAME: &str = "cs_csrf";

#[derive(Deserialize)]
pub struct IndexQuery {
    pub err: Option<String>,
    pub ok: Option<String>,
}

#[derive(Deserialize)]
pub struct LoginQuery {
    pub err: Option<String>,
}

#[derive(Deserialize)]
pub struct LoginForm {
    pub username: String,
    pub password: String,
    pub csrf_token: Option<String>,
}

#[derive(Deserialize)]
pub struct CreateForm {
    pub name: String,
    pub mem: u32,
    pub cpus: f32,
    pub git: Option<String>,
    pub csrf_token: Option<String>,
}

#[derive(Deserialize)]
pub struct ActionForm {
    pub act: String,
    pub csrf_token: Option<String>,
}

#[derive(Deserialize)]
pub struct ResourceUpdateForm {
    pub mem: u32,
    pub cpus: f32,
    pub csrf_token: Option<String>,
}

#[derive(Deserialize)]
pub struct ChangePasswordForm {
    pub new_password: String,
    pub confirm: String,
    pub csrf_token: Option<String>,
}

#[derive(Deserialize)]
pub struct CreateUserForm {
    pub username: String,
    pub role: String,
    pub csrf_token: Option<String>,
}

#[derive(Deserialize)]
pub struct CsrfForm {
    pub csrf_token: Option<String>,
}

#[derive(Deserialize)]
pub struct VerifyQuery {
    pub instance: String,
}

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
    let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)));
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

fn set_cookie_header<B>(resp: &mut axum::http::Response<B>, value: &str) {
    if let Ok(v) = HeaderValue::from_str(value) {
        resp.headers_mut().append(SET_COOKIE, v);
    }
}

fn generate_csrf_token() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn csrf_cookie(token: &str, domain: Option<&str>) -> String {
    let mut s = format!(
        "{}={}; Path=/; HttpOnly; SameSite=Lax; Max-Age={}",
        CSRF_COOKIE_NAME,
        token,
        86400 * 7
    );
    if let Some(d) = domain {
        s.push_str(&format!("; Domain={}", d));
    }
    s
}

fn get_or_create_csrf_token<B>(
    resp: &mut axum::http::Response<B>,
    jar: &CookieJar,
    domain: Option<&str>,
) -> String {
    if let Some(cookie) = jar.get(CSRF_COOKIE_NAME) {
        return cookie.value().to_string();
    }
    let token = generate_csrf_token();
    set_cookie_header(resp, &csrf_cookie(&token, domain));
    token
}

fn validate_csrf_token(jar: &CookieJar, token: Option<&str>) -> bool {
    let expected = match jar.get(CSRF_COOKIE_NAME) {
        Some(c) => c.value().to_string(),
        None => return false,
    };
    match token.map(str::trim).filter(|s| !s.is_empty()) {
        Some(v) => v == expected,
        None => false,
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

pub async fn login_page(Query(q): Query<LoginQuery>, jar: CookieJar) -> Response {
    let mut resp = Response::new(());
    let token = get_or_create_csrf_token(&mut resp, &jar, None);
    let mut page = templates::login_page(q.err.is_some(), &token).into_response();
    for (name, value) in resp.headers().iter() {
        page.headers_mut().insert(name, value.clone());
    }
    page
}

pub async fn login_submit(
    State(state): State<AppState>,
    jar: CookieJar,
    Form(form): Form<LoginForm>,
) -> Response {
    if !validate_csrf_token(&jar, form.csrf_token.as_deref()) {
        return (StatusCode::FORBIDDEN, "CSRF 校验失败").into_response();
    }

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
    // 审计日志：登录成功
    let _ = auth::insert_audit_log(&db, id, "login", Some(form.username.trim()), None);
    drop(db);

    let mut resp = if kind == "pending_reset" {
        Redirect::to("/change-password").into_response()
    } else {
        Redirect::to("/").into_response()
    };
    set_cookie_header(&mut resp, &session_cookie(&token, state.config.cookie_domain.as_deref()));
    resp
}

pub async fn logout(
    State(state): State<AppState>,
    jar: CookieJar,
    Form(form): Form<CsrfForm>,
) -> Response {
    if !validate_csrf_token(&jar, form.csrf_token.as_deref()) {
        return (StatusCode::FORBIDDEN, "CSRF 校验失败").into_response();
    }

    if let Some(c) = jar.get(COOKIE_NAME) {
        let db = state.db.lock().await;
        let _ = auth::delete_session(&db, c.value());
    }
    let mut resp = Redirect::to("/login").into_response();
    set_cookie_header(&mut resp, &clear_cookie(state.config.cookie_domain.as_deref()));
    resp
}

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

    let mut resp = Response::new(());
    let token = get_or_create_csrf_token(&mut resp, &jar, state.config.cookie_domain.as_deref());
    let mut page = templates::index_page(
        &user,
        &instances,
        &state.config,
        q.err.as_deref(),
        q.ok.as_deref(),
        &token,
    )
    .into_response();
    for (name, value) in resp.headers().iter() {
        page.headers_mut().insert(name, value.clone());
    }
    page
}

pub async fn create_instance(
    State(state): State<AppState>,
    jar: CookieJar,
    Form(form): Form<CreateForm>,
) -> Response {
    if !validate_csrf_token(&jar, form.csrf_token.as_deref()) {
        return (StatusCode::FORBIDDEN, "CSRF 校验失败").into_response();
    }

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

    // 使用 container_name 检查是否已存在（支持跨用户同名实例）
    let cname = docker_ops::container_name(&user.username, &name);
    if state.docker.inspect_container(&cname, None).await.is_ok() {
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
    let port = match docker_ops::pick_free_port(&used, state.config.port_min, state.config.port_max) {
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

    // 审计日志：创建实例
    {
        let db = state.db.lock().await;
        let _ = auth::insert_audit_log(
            &db, user.id, "create_instance", Some(&name),
            Some(&format!("mem={}MB cpus={} port={}", mem, cpus, port)),
        );
    }

    Redirect::to("/").into_response()
}

pub async fn instance_action(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(name): Path<String>,
    Form(form): Form<ActionForm>,
) -> Response {
    if !validate_csrf_token(&jar, form.csrf_token.as_deref()) {
        return (StatusCode::FORBIDDEN, "CSRF 校验失败").into_response();
    }

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

    // 使用 container_name 获取实际容器名（支持跨用户同名实例）
    let cname = docker_ops::container_name(&inst.owner, &name);
    let act = form.act.as_str();
    let res = match act {
        "start" => docker_ops::start(&state.docker, &cname).await,
        "stop" => docker_ops::stop(&state.docker, &cname).await,
        "remove" => docker_ops::remove(&state.docker, &cname).await,
        _ => Ok(()),
    };
    if let Err(e) = res {
        tracing::error!("action {act} on {cname} failed: {e}");
    }

    // 审计日志：启停/删除实例
    {
        let db = state.db.lock().await;
        let _ = auth::insert_audit_log(
            &db, user.id, act, Some(&name),
            Some(&format!("owner={}", inst.owner)),
        );
    }

    Redirect::to("/").into_response()
}

pub async fn update_instance_resources(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(name): Path<String>,
    Form(form): Form<ResourceUpdateForm>,
) -> Response {
    if !validate_csrf_token(&jar, form.csrf_token.as_deref()) {
        return (StatusCode::FORBIDDEN, "CSRF 校验失败").into_response();
    }

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
        return (StatusCode::FORBIDDEN, "无权限调整该实例资源").into_response();
    }

    if docker_ops::validate_resource_limits(form.mem, form.cpus).is_err() {
        return Redirect::to("/?err=resource-range").into_response();
    }

    // 使用 container_name 获取实际容器名（支持跨用户同名实例）
    let cname = docker_ops::container_name(&inst.owner, &name);
    if let Err(e) = docker_ops::update_resources(&state.docker, &cname, form.mem, form.cpus).await {
        tracing::error!("update resources for {cname} failed: {e}");
        return Redirect::to("/?err=resource").into_response();
    }

    // 审计日志：更新资源
    {
        let db = state.db.lock().await;
        let _ = auth::insert_audit_log(
            &db, user.id, "update_resources", Some(&name),
            Some(&format!("mem={}MB cpus={}", form.mem, form.cpus)),
        );
    }

    Redirect::to("/?ok=resources").into_response()
}

pub async fn change_password_page(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Response {
    let _ = match current(&state, &jar).await {
        Some(v) => v,
        None => return Redirect::to("/login").into_response(),
    };
    let mut resp = Response::new(());
    let token = get_or_create_csrf_token(&mut resp, &jar, state.config.cookie_domain.as_deref());
    let mut page = templates::change_password_page(None, &token).into_response();
    for (name, value) in resp.headers().iter() {
        page.headers_mut().insert(name, value.clone());
    }
    page
}

pub async fn change_password_submit(
    State(state): State<AppState>,
    jar: CookieJar,
    Form(form): Form<ChangePasswordForm>,
) -> Response {
    if !validate_csrf_token(&jar, form.csrf_token.as_deref()) {
        return (StatusCode::FORBIDDEN, "CSRF 校验失败").into_response();
    }

    let (user, _, _) = match current(&state, &jar).await {
        Some(v) => v,
        None => return Redirect::to("/login").into_response(),
    };
    if form.new_password.len() < 8 {
        let mut resp = Response::new(());
        let token = get_or_create_csrf_token(&mut resp, &jar, state.config.cookie_domain.as_deref());
        let mut page = templates::change_password_page(Some("密码至少 8 位"), &token).into_response();
        for (name, value) in resp.headers().iter() {
            page.headers_mut().insert(name, value.clone());
        }
        return page;
    }
    if form.new_password != form.confirm {
        let mut resp = Response::new(());
        let token = get_or_create_csrf_token(&mut resp, &jar, state.config.cookie_domain.as_deref());
        let mut page = templates::change_password_page(Some("两次输入不一致"), &token).into_response();
        for (name, value) in resp.headers().iter() {
            page.headers_mut().insert(name, value.clone());
        }
        return page;
    }

    let pw = form.new_password.clone();
    let hash = match tokio::task::spawn_blocking(move || auth::hash_password(&pw)).await {
        Ok(h) => h,
        Err(_) => {
            let mut resp = Response::new(());
            let token = get_or_create_csrf_token(&mut resp, &jar, state.config.cookie_domain.as_deref());
            let mut page = templates::change_password_page(Some("哈希失败"), &token).into_response();
            for (name, value) in resp.headers().iter() {
                page.headers_mut().insert(name, value.clone());
            }
            return page;
        }
    };

    let db = state.db.lock().await;
    let _ = db.execute(
        "UPDATE users SET password_hash = ?1, must_change_password = 0 WHERE id = ?2",
        params![hash, user.id],
    );
    let _ = auth::delete_user_sessions(&db, user.id);
    let new_token = auth::create_session(&db, user.id, "full").ok();
    // 审计日志：修改密码
    let _ = auth::insert_audit_log(&db, user.id, "change_password", None, None);
    drop(db);

    let token = match new_token {
        Some(t) => t,
        None => return Redirect::to("/login").into_response(),
    };

    let mut resp = Redirect::to("/").into_response();
    set_cookie_header(&mut resp, &session_cookie(&token, state.config.cookie_domain.as_deref()));
    resp
}

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
    let mut resp = Response::new(());
    let token = get_or_create_csrf_token(&mut resp, &jar, state.config.cookie_domain.as_deref());
    let mut page = templates::admin_users_page(&user, &users, None, &token).into_response();
    for (name, value) in resp.headers().iter() {
        page.headers_mut().insert(name, value.clone());
    }
    page
}

pub async fn admin_create_user(
    State(state): State<AppState>,
    jar: CookieJar,
    Form(form): Form<CreateUserForm>,
) -> Response {
    if !validate_csrf_token(&jar, form.csrf_token.as_deref()) {
        return (StatusCode::FORBIDDEN, "CSRF 校验失败").into_response();
    }

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
    // 审计日志：创建用户
    if res.is_ok() {
        let _ = auth::insert_audit_log(
            &db, user.id, "create_user", Some(&username), Some(&format!("role={}", role)),
        );
    }
    drop(db);

    match res {
        Ok(_) => {
            let msg = format!(
                "用户 {} 创建成功。临时密码：{}（仅显示一次，请立即转交，首次登录须改密）",
                username, temp
            );
            let users = load_users(&state).await;
            let mut resp = Response::new(());
            let token = get_or_create_csrf_token(&mut resp, &jar, state.config.cookie_domain.as_deref());
            let mut page = templates::admin_users_page(&user, &users, Some(msg.as_str()), &token).into_response();
            for (name, value) in resp.headers().iter() {
                page.headers_mut().insert(name, value.clone());
            }
            page
        }
        Err(_) => Redirect::to("/admin/users?err=dup").into_response(),
    }
}

pub async fn admin_reset_password(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<i64>,
    Form(form): Form<CsrfForm>,
) -> Response {
    if !validate_csrf_token(&jar, form.csrf_token.as_deref()) {
        return (StatusCode::FORBIDDEN, "CSRF 校验失败").into_response();
    }

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
    // 审计日志：重置密码
    let _ = auth::insert_audit_log(
        &db, user.id, "reset_password", Some(&id.to_string()), None,
    );
    drop(db);

    let msg = format!(
        "用户 ID {} 密码已重置。临时密码：{}（仅显示一次，用户下次登录须改密）",
        id, temp
    );
    let users = load_users(&state).await;
    let mut resp = Response::new(());
    let token = get_or_create_csrf_token(&mut resp, &jar, state.config.cookie_domain.as_deref());
    let mut page = templates::admin_users_page(&user, &users, Some(msg.as_str()), &token).into_response();
    for (name, value) in resp.headers().iter() {
        page.headers_mut().insert(name, value.clone());
    }
    page
}

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
        return StatusCode::PRECONDITION_REQUIRED.into_response();
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
    Form(form): Form<CsrfForm>,
) -> Response {
    if !validate_csrf_token(&jar, form.csrf_token.as_deref()) {
        return (StatusCode::FORBIDDEN, "CSRF 校验失败").into_response();
    }

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

    if user.id == id {
        return Redirect::to("/admin/users?err=self").into_response();
    }

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

    if role == "admin" {
        let admin_count: i64 = db
            .query_row("SELECT COUNT(*) FROM users WHERE role='admin'", [], |r| r.get(0))
            .unwrap_or(0);
        if admin_count <= 1 {
            return Redirect::to("/admin/users?err=last_admin").into_response();
        }
    }
    drop(db);

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
        let mut resp = Response::new(());
        let token = get_or_create_csrf_token(&mut resp, &jar, state.config.cookie_domain.as_deref());
        let mut page = templates::admin_users_page(&user, &users, Some(&msg), &token).into_response();
        for (name, value) in resp.headers().iter() {
            page.headers_mut().insert(name, value.clone());
        }
        return page;
    }

    let db = state.db.lock().await;
    let res = db.execute("DELETE FROM users WHERE id = ?1", params![id]);
    // 审计日志：删除用户
    if res.is_ok() {
        let _ = auth::insert_audit_log(
            &db, user.id, "delete_user", Some(&username), None,
        );
    }
    drop(db);

    let msg = match res {
        Ok(_) => format!("用户 {} 已删除，其所有会话已失效", username),
        Err(e) => format!("删除失败：{}", e),
    };
    let users = load_users(&state).await;
    let mut resp = Response::new(());
    let token = get_or_create_csrf_token(&mut resp, &jar, state.config.cookie_domain.as_deref());
    let mut page = templates::admin_users_page(&user, &users, Some(&msg), &token).into_response();
    for (name, value) in resp.headers().iter() {
        page.headers_mut().insert(name, value.clone());
    }
    page
}

pub async fn admin_audit_logs_page(State(state): State<AppState>, jar: CookieJar) -> Response {
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

    let db = state.db.lock().await;
    let logs = auth::list_audit_logs(&db, 200).unwrap_or_default();
    drop(db);

    let mut resp = Response::new(());
    let token = get_or_create_csrf_token(&mut resp, &jar, state.config.cookie_domain.as_deref());
    let mut page = templates::admin_audit_logs_page(&user, &logs, &token).into_response();
    for (name, value) in resp.headers().iter() {
        page.headers_mut().insert(name, value.clone());
    }
    page
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum_extra::extract::cookie::Cookie;

    #[test]
    fn csrf_token_must_match_cookie_value() {
        let cookie = Cookie::build((CSRF_COOKIE_NAME, "token-123")).path("/").build();
        let jar = CookieJar::new().add(cookie);

        assert!(validate_csrf_token(&jar, Some("token-123")));
        assert!(!validate_csrf_token(&jar, Some("wrong-token")));
        assert!(!validate_csrf_token(&jar, None));
    }

    #[test]
    fn pages_include_hidden_csrf_field() {
        let html = templates::index_page(
            &User {
                id: 7,
                username: "alice".into(),
                role: "member".into(),
                must_change_password: false,
            },
            &[docker_ops::InstanceInfo {
                name: "devbox".into(),
                state: "running".into(),
                port: 8200,
                mem: 1024,
                cpus: 1.0,
                owner: "alice".into(),
            }],
            &Config {
                hostname_suffix: "example.com".into(),
                base_dir: "/tmp".into(),
                port_min: 8200,
                port_max: 8299,
                image: "codercom/code-server:latest".into(),
                cookie_domain: None,
            },
            None,
            None,
            "token-456",
        )
        .into_string();

        assert!(html.contains("name=\"csrf_token\""));
        assert!(html.contains("value=\"token-456\""));
        assert_eq!(html.matches("name=\"csrf_token\"").count(), 4);
        assert!(html.contains("<form method=\"post\" action=\"/logout\">"));
    }

    #[test]
    fn instance_card_includes_runtime_resource_update_form() {
        let html = templates::index_page(
            &User {
                id: 7,
                username: "alice".into(),
                role: "member".into(),
                must_change_password: false,
            },
            &[docker_ops::InstanceInfo {
                name: "devbox".into(),
                state: "running".into(),
                port: 8200,
                mem: 1024,
                cpus: 1.0,
                owner: "alice".into(),
            }],
            &Config {
                hostname_suffix: "example.com".into(),
                base_dir: "/tmp".into(),
                port_min: 8200,
                port_max: 8299,
                image: "codercom/code-server:latest".into(),
                cookie_domain: None,
            },
            None,
            Some("resources"),
            "token-999",
        )
        .into_string();

        assert!(html.contains("/instances/devbox/resources"));
        assert!(html.contains("资源配置已更新"));
        assert!(html.contains("无需重启容器"));
        assert!(html.contains("256–8192 MB"));
        assert!(html.contains("0.1–8 核"));
        assert!(html.contains("name=\"mem\""));
        assert!(html.contains("name=\"cpus\""));
        assert!(html.contains("value=\"1024\""));
        assert!(html.contains("value=\"1\""));
    }

    #[test]
    fn resource_update_errors_are_explained_in_the_panel() {
        let user = User {
            id: 7,
            username: "alice".into(),
            role: "member".into(),
            must_change_password: false,
        };
        let config = Config {
            hostname_suffix: "example.com".into(),
            base_dir: "/tmp".into(),
            port_min: 8200,
            port_max: 8299,
            image: "codercom/code-server:latest".into(),
            cookie_domain: None,
        };

        let range_error = templates::index_page(
            &user,
            &[],
            &config,
            Some("resource-range"),
            None,
            "token",
        )
            .into_string();
        assert!(range_error.contains("内存范围为 256–8192 MB，CPU 范围为 0.1–8 核"));

        let docker_error = templates::index_page(
            &user,
            &[],
            &config,
            Some("resource"),
            None,
            "token",
        )
            .into_string();
        assert!(docker_error.contains("降低内存时，请先确认当前使用量低于目标值"));
    }

    #[test]
    fn login_password_and_admin_pages_include_csrf_fields() {
        let user = User {
            id: 7,
            username: "alice".into(),
            role: "admin".into(),
            must_change_password: false,
        };
        let token = "token-789";
        let login = templates::login_page(false, token).into_string();
        let password = templates::change_password_page(None, token).into_string();
        let admin = templates::admin_users_page(
            &user,
            &[(8, "bob".into(), "member".into(), 0)],
            None,
            token,
        )
        .into_string();

        assert_eq!(login.matches("name=\"csrf_token\"").count(), 1);
        assert_eq!(password.matches("name=\"csrf_token\"").count(), 1);
        assert_eq!(admin.matches("name=\"csrf_token\"").count(), 4);
        assert!(admin.matches("value=\"token-789\"").count() == 4);
    }
}
