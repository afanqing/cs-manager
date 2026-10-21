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

    // Nginx 的 server_name 正则捕获 `cs-` 之后的全部内容（即 `<owner>-<name>`），
    // 与容器名 `cs-<owner>-<name>` 一一对应，因此直接加回前缀即可定位容器。
    // 用户名与实例名都可能含连字符，不做拆分以避免歧义。
    let cname = match docker_ops::container_name_from_host(&q.instance) {
        Some(n) => n,
        None => return StatusCode::BAD_REQUEST.into_response(),
    };
    let info = match state.docker.inspect_container(&cname, None).await {
        Ok(c) => c,
        Err(_) => return StatusCode::NOT_FOUND.into_response(),
    };
    let labels = info
        .config
        .as_ref()
        .and_then(|c| c.labels.clone())
        .unwrap_or_default();
    // 归属校验以容器 label 为准，不信任子域名中的 owner 段。
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
