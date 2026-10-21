use axum::{
    extract::{Form, Path, State},
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::extract::cookie::CookieJar;
use rusqlite::{params, OptionalExtension};

use crate::auth;
use crate::docker_ops;
use crate::handlers::{load_users, require_csrf, require_user};
use crate::templates;
use crate::AppState;

/// 用户管理页面。
pub async fn admin_users_page(State(state): State<AppState>, jar: CookieJar) -> Response {
    let (user, _) = match require_user(&state, &jar).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    if user.role != "admin" {
        return (StatusCode::FORBIDDEN, "仅管理员可访问").into_response();
    }

    let users = load_users(&state).await;
    super::render_with_csrf(&jar, state.config.cookie_domain.as_deref(), |token| {
        templates::admin_users_page(&user, &users, None, None, token).into_response()
    })
}

/// 创建新用户。
pub async fn admin_create_user(
    State(state): State<AppState>,
    jar: CookieJar,
    Form(form): Form<super::CreateUserForm>,
) -> Response {
    if let Err(resp) = require_csrf(&jar, form.csrf_token.as_deref()) {
        return resp;
    }

    let (user, _) = match require_user(&state, &jar).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
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
            &db,
            user.id,
            "create_user",
            Some(&username),
            Some(&format!("role={}", role)),
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
            super::render_with_csrf(&jar, state.config.cookie_domain.as_deref(), |token| {
                templates::admin_users_page(&user, &users, None, Some(msg.as_str()), token).into_response()
            })
        }
        Err(_) => Redirect::to("/admin/users?err=dup").into_response(),
    }
}

/// 重置用户密码。
pub async fn admin_reset_password(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<i64>,
    Form(form): Form<super::CsrfForm>,
) -> Response {
    if let Err(resp) = require_csrf(&jar, form.csrf_token.as_deref()) {
        return resp;
    }

    let (user, _) = match require_user(&state, &jar).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
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
        &db,
        user.id,
        "reset_password",
        Some(&id.to_string()),
        None,
    );
    drop(db);

    let msg = format!(
        "用户 ID {} 密码已重置。临时密码：{}（仅显示一次，用户下次登录须改密）",
        id, temp
    );
    let users = load_users(&state).await;
    super::render_with_csrf(&jar, state.config.cookie_domain.as_deref(), |token| {
        templates::admin_users_page(&user, &users, None, Some(msg.as_str()), token).into_response()
    })
}

/// 删除用户。
pub async fn admin_delete_user(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<i64>,
    Form(form): Form<super::CsrfForm>,
) -> Response {
    if let Err(resp) = require_csrf(&jar, form.csrf_token.as_deref()) {
        return resp;
    }

    let (user, _) = match require_user(&state, &jar).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
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
        return super::render_with_csrf(&jar, state.config.cookie_domain.as_deref(), |token| {
            templates::admin_users_page(&user, &users, Some(&msg), None, token).into_response()
        });
    }

    let db = state.db.lock().await;
    let res = db.execute("DELETE FROM users WHERE id = ?1", params![id]);
    // 审计日志：删除用户
    if res.is_ok() {
        let _ = auth::insert_audit_log(
            &db,
            user.id,
            "delete_user",
            Some(&username),
            None,
        );
    }
    drop(db);

    let msg = match res {
        Ok(_) => format!("用户 {} 已删除，其所有会话已失效", username),
        Err(e) => format!("删除失败：{}", e),
    };
    let users = load_users(&state).await;
    super::render_with_csrf(&jar, state.config.cookie_domain.as_deref(), |token| {
        templates::admin_users_page(&user, &users, None, Some(&msg), token).into_response()
    })
}

/// 审计日志页面。
pub async fn admin_audit_logs_page(State(state): State<AppState>, jar: CookieJar) -> Response {
    let (user, _) = match require_user(&state, &jar).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    if user.role != "admin" {
        return (StatusCode::FORBIDDEN, "仅管理员可访问").into_response();
    }

    let db = state.db.lock().await;
    let logs = auth::list_audit_logs(&db, 200).unwrap_or_default();
    drop(db);

    super::render_with_csrf(&jar, state.config.cookie_domain.as_deref(), |token| {
        templates::admin_audit_logs_page(&user, &logs, token).into_response()
    })
}
