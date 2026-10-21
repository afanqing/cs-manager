use axum::{
    extract::{Form, Query, State},
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::extract::cookie::CookieJar;
use rusqlite::{params, OptionalExtension};

use crate::auth;
use crate::handlers::{
    copy_csrf_cookie, get_or_create_csrf_token, make_clear_cookie, make_session_cookie,
    require_csrf, render_with_csrf, set_cookie_header, LoginForm, LoginQuery,
};
use crate::templates;
use crate::AppState;

/// 登录页面：渲染登录表单。
pub async fn login_page(Query(q): Query<LoginQuery>, jar: CookieJar) -> Response {
    render_with_csrf(&jar, None, |token| {
        templates::login_page(q.err.is_some(), token).into_response()
    })
}

/// 登录提交：校验 CSRF、验证密码、创建会话。
pub async fn login_submit(
    State(state): State<AppState>,
    jar: CookieJar,
    Form(form): Form<LoginForm>,
) -> Response {
    if let Err(resp) = require_csrf(&jar, form.csrf_token.as_deref()) {
        return resp;
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
    set_cookie_header(
        &mut resp,
        &make_session_cookie(&token, state.config.cookie_domain.as_deref()),
    );
    resp
}

/// 退出登录：清除会话 Cookie 并删除服务端会话。
pub async fn logout(
    State(state): State<AppState>,
    jar: CookieJar,
    Form(form): Form<super::CsrfForm>,
) -> Response {
    if let Err(resp) = require_csrf(&jar, form.csrf_token.as_deref()) {
        return resp;
    }

    if let Some(c) = jar.get(super::COOKIE_NAME) {
        let db = state.db.lock().await;
        let _ = auth::delete_session(&db, c.value());
    }
    let mut resp = Redirect::to("/login").into_response();
    set_cookie_header(&mut resp, &make_clear_cookie(state.config.cookie_domain.as_deref()));
    resp
}

/// 修改密码页面。
pub async fn change_password_page(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Response {
    // 只需要登录即可，改密页面本身对 pending_reset 也开放
    let _ = match super::current(&state, &jar).await {
        Some(v) => v,
        None => return Redirect::to("/login").into_response(),
    };
    render_with_csrf(&jar, state.config.cookie_domain.as_deref(), |token| {
        templates::change_password_page(None, token).into_response()
    })
}

/// 修改密码提交：校验 CSRF、复杂度、一致性，更新密码并刷新会话。
pub async fn change_password_submit(
    State(state): State<AppState>,
    jar: CookieJar,
    Form(form): Form<super::ChangePasswordForm>,
) -> Response {
    if let Err(resp) = require_csrf(&jar, form.csrf_token.as_deref()) {
        return resp;
    }

    let (user, _, _) = match super::current(&state, &jar).await {
        Some(v) => v,
        None => return Redirect::to("/login").into_response(),
    };

    if form.new_password.len() < 8 {
        return render_change_password_with_error(&state, &jar, "密码至少 8 位").await;
    }
    if form.new_password != form.confirm {
        return render_change_password_with_error(&state, &jar, "两次输入不一致").await;
    }

    let pw = form.new_password.clone();
    let hash = match tokio::task::spawn_blocking(move || auth::hash_password(&pw)).await {
        Ok(h) => h,
        Err(_) => return render_change_password_with_error(&state, &jar, "哈希失败").await,
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
    set_cookie_header(
        &mut resp,
        &make_session_cookie(&token, state.config.cookie_domain.as_deref()),
    );
    resp
}

/// 渲染带错误提示的改密页面。
async fn render_change_password_with_error(
    state: &AppState,
    jar: &CookieJar,
    err: &str,
) -> Response {
    let mut resp = Response::new(());
    let token = get_or_create_csrf_token(&mut resp, jar, state.config.cookie_domain.as_deref());
    let mut page = templates::change_password_page(Some(err), &token).into_response();
    copy_csrf_cookie(&resp, &mut page);
    page
}
