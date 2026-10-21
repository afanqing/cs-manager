use axum::{
    extract::{Query, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use axum_extra::extract::cookie::CookieJar;

use crate::docker_ops;
use crate::handlers::current;
use crate::AppState;

/// Nginx auth_request 鉴权端点。
///
/// 校验用户会话、强制改密状态、实例归属，并返回目标端口。
pub async fn auth_verify(
    State(state): State<AppState>,
    Query(q): Query<super::VerifyQuery>,
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

    // 使用 container_name 查找实际容器（支持跨用户同名实例）
    let cname = docker_ops::container_name(&user.username, &q.instance);
    let info = match state.docker.inspect_container(&cname, None).await {
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
