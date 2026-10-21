use axum::{
    extract::{Form, Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::extract::cookie::CookieJar;
use std::collections::HashSet;

use crate::auth;
use crate::docker_ops::{self, CreateSpec};
use crate::handlers::{require_csrf, require_user, sanitize_name};
use crate::templates;
use crate::AppState;

/// 首页：列出当前用户可见的实例。
pub async fn index(
    State(state): State<AppState>,
    jar: CookieJar,
    Query(q): Query<super::IndexQuery>,
) -> Response {
    let (user, _) = match require_user(&state, &jar).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    let owner = if user.role == "admin" {
        None
    } else {
        Some(user.username.as_str())
    };
    let instances = docker_ops::list_instances(&state.docker, owner)
        .await
        .unwrap_or_default();

    super::render_with_csrf(&jar, state.config.cookie_domain.as_deref(), |token| {
        templates::index_page(
            &user,
            &instances,
            &state.config,
            q.err.as_deref(),
            q.ok.as_deref(),
            token,
        )
        .into_response()
    })
}

/// 创建新实例。
pub async fn create_instance(
    State(state): State<AppState>,
    jar: CookieJar,
    Form(form): Form<super::CreateForm>,
) -> Response {
    if let Err(resp) = require_csrf(&jar, form.csrf_token.as_deref()) {
        return resp;
    }

    let (user, _) = match require_user(&state, &jar).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };

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
            &db,
            user.id,
            "create_instance",
            Some(&name),
            Some(&format!("mem={}MB cpus={} port={}", mem, cpus, port)),
        );
    }

    Redirect::to("/").into_response()
}

/// 实例启停删操作。
pub async fn instance_action(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(name): Path<String>,
    Form(form): Form<super::ActionForm>,
) -> Response {
    if let Err(resp) = require_csrf(&jar, form.csrf_token.as_deref()) {
        return resp;
    }

    let (user, _) = match require_user(&state, &jar).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };

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
            &db,
            user.id,
            act,
            Some(&name),
            Some(&format!("owner={}", inst.owner)),
        );
    }

    Redirect::to("/").into_response()
}

/// 更新实例资源限制。
pub async fn update_instance_resources(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(name): Path<String>,
    Form(form): Form<super::ResourceUpdateForm>,
) -> Response {
    if let Err(resp) = require_csrf(&jar, form.csrf_token.as_deref()) {
        return resp;
    }

    let (user, _) = match require_user(&state, &jar).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };

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
            &db,
            user.id,
            "update_resources",
            Some(&name),
            Some(&format!("mem={}MB cpus={}", form.mem, form.cpus)),
        );
    }

    Redirect::to("/?ok=resources").into_response()
}
