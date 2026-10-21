use axum::{
    http::{header::SET_COOKIE, HeaderValue, StatusCode},
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::extract::cookie::CookieJar;
use rand::RngCore;
use serde::Deserialize;

use crate::auth::{self, User};
use crate::AppState;

pub mod admin;
pub mod auth_handlers;
pub mod auth_verify;
pub mod instance;

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
    /// 实例归属用户名。用于在跨用户同名实例场景下精确定位容器；
    /// 非 admin 用户提交此字段无效（服务端强制使用其自身用户名）。
    pub owner: Option<String>,
}

#[derive(Deserialize)]
pub struct ResourceUpdateForm {
    pub mem: u32,
    pub cpus: f32,
    pub csrf_token: Option<String>,
    /// 实例归属用户名，语义同 [`ActionForm::owner`]。
    pub owner: Option<String>,
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
    /// Nginx 从 `cs-<owner>-<name>.<domain>` 子域名中捕获的 `cs-` 之后部分，
    /// 即 `<owner>-<name>`。加回 `cs-` 前缀即为容器名，无需再拆分 owner。
    pub instance: String,
}

/// 从 Cookie 中加载当前登录用户及其会话类型。
///
/// 返回 `(User, kind, token)`，其中 `kind` 是 `"full"` 或 `"pending_reset"`。
pub async fn current(state: &AppState, jar: &CookieJar) -> Option<(User, String, String)> {
    let token = jar.get(COOKIE_NAME)?.value().to_string();
    let db = state.db.lock().await;
    let res = auth::load_session(&db, &token).ok().flatten();
    res.map(|(u, k)| (u, k, token))
}

/// 加载所有用户列表，返回 `(id, username, role, must_change_password)` 元组。
pub async fn load_users(state: &AppState) -> Vec<(i64, String, String, i64)> {
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

/// 将用户输入的实例名清理为合法的小写 kebab-case 字符串。
///
/// 只允许 ASCII 字母、数字和连字符，并去除首尾连字符。
fn sanitize_name(s: &str) -> String {
    let cleaned: String = s
        .trim()
        .to_lowercase()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
        .collect();
    cleaned.trim_matches('-').to_string()
}

/// 在响应头中追加一个 `Set-Cookie` 头。
pub fn set_cookie_header<B>(resp: &mut axum::http::Response<B>, value: &str) {
    if let Ok(v) = HeaderValue::from_str(value) {
        resp.headers_mut().append(SET_COOKIE, v);
    }
}

/// 生成一个 64 位十六进制随机 CSRF token。
fn generate_csrf_token() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// 构造 CSRF token 的 `Set-Cookie` 字符串。
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

/// 获取或创建 CSRF token，并通过 `Set-Cookie` 写入响应。
///
/// 如果请求中已存在有效的 CSRF Cookie，则直接复用；否则生成新的 token。
pub fn get_or_create_csrf_token<B>(
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

/// 校验表单中的 CSRF token 是否与 Cookie 中一致。
pub fn validate_csrf_token(jar: &CookieJar, token: Option<&str>) -> bool {
    let expected = match jar.get(CSRF_COOKIE_NAME) {
        Some(c) => c.value().to_string(),
        None => return false,
    };
    match token.map(str::trim).filter(|s| !s.is_empty()) {
        Some(v) => v == expected,
        None => false,
    }
}

/// 构造会话 Cookie 的 `Set-Cookie` 字符串。
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

/// 构造清除会话 Cookie 的 `Set-Cookie` 字符串。
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

/// 将 CSRF Cookie 从临时响应复制到最终页面响应中。
///
/// 页面 handler 需要先创建一个临时响应来设置 CSRF Cookie，
/// 然后把该 Cookie 复制到最终渲染的页面响应里。
pub fn copy_csrf_cookie<B1, B2>(src: &axum::http::Response<B1>, dst: &mut axum::http::Response<B2>) {
    for (name, value) in src.headers().iter() {
        if name == SET_COOKIE {
            dst.headers_mut().insert(name.clone(), value.clone());
        }
    }
}

/// 验证 CSRF token，失败时返回 403 响应。
///
/// 用于 POST handler 中统一处理 CSRF 校验失败的情况。
// Err 变体是完整的 HTTP 响应，这里刻意保留以便调用方直接返回。
#[allow(clippy::result_large_err)]
pub fn require_csrf(jar: &CookieJar, token: Option<&str>) -> Result<(), Response> {
    if !validate_csrf_token(jar, token) {
        Err((StatusCode::FORBIDDEN, "CSRF 校验失败").into_response())
    } else {
        Ok(())
    }
}

/// 获取当前登录用户，并检查是否处于待改密状态。
///
/// 未登录则重定向到登录页；待改密则重定向到改密页。
/// 返回的 `kind` 为 `"full"` 或 `"pending_reset"`。
// Err 变体是完整的 HTTP 响应，这里刻意保留以便调用方直接返回。
#[allow(clippy::result_large_err)]
pub async fn require_user(state: &AppState, jar: &CookieJar) -> Result<(User, String), Response> {
    let (user, kind, _) = match current(state, jar).await {
        Some(v) => v,
        None => return Err(Redirect::to("/login").into_response()),
    };
    if kind == "pending_reset" {
        return Err(Redirect::to("/change-password").into_response());
    }
    Ok((user, kind))
}

/// 构造一个带 CSRF token 的页面响应。
///
/// 自动处理 CSRF Cookie 的设置和复制。
pub fn render_with_csrf<F>(
    jar: &CookieJar,
    domain: Option<&str>,
    render: F,
) -> Response
where
    F: FnOnce(&str) -> Response,
{
    let mut resp = Response::new(());
    let token = get_or_create_csrf_token(&mut resp, jar, domain);
    let mut page = render(&token);
    copy_csrf_cookie(&resp, &mut page);
    page
}

/// 构造会话 Cookie 的公开封装。
pub fn make_session_cookie(token: &str, domain: Option<&str>) -> String {
    session_cookie(token, domain)
}

/// 构造清除会话 Cookie 的公开封装。
pub fn make_clear_cookie(domain: Option<&str>) -> String {
    clear_cookie(domain)
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
    fn sanitize_name_removes_invalid_chars_and_trims_hyphens() {
        assert_eq!(sanitize_name("  Hello_World!! "), "helloworld");
        assert_eq!(sanitize_name("--test--"), "test");
        assert_eq!(sanitize_name(""), "");
        assert_eq!(sanitize_name("My.Project"), "myproject");
        assert_eq!(sanitize_name("---"), "");
    }
}
