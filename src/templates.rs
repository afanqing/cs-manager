use maud::{html, Markup, DOCTYPE};

use crate::auth::User;
use crate::docker_ops::InstanceInfo;
use crate::Config;

const STYLE: &str = r#"
* { box-sizing: border-box; }
body { font-family: -apple-system, "Segoe UI", sans-serif; margin: 0; background: #f0f2f5; color: #333; }
.container { max-width: 1000px; margin: 0 auto; padding: 1.5em; }
.card { background: #fff; padding: 1em 1.2em; margin: 1em 0; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.08); }
.running { color: #2e7d32; font-weight: bold; }
.exited, .created, .stopped, .paused, .restarting { color: #999; }
.btn {
    padding: 5px 12px;
    margin: 2px;
    border: 1px solid #ccc;
    border-radius: 5px;
    cursor: pointer;
    background: #fff;
    color: #333;
    font-size: 0.9em;
    -webkit-appearance: none;
    appearance: none;
}
.btn:hover { background: #eee; }
.btn-primary {
    background: #1677ff;
    color: #fff;
    border-color: #1677ff;
}
.btn-primary:hover { background: #0958d9; }
.btn-danger {
    background: #fff;
    color: #cf1322;
    border-color: #ffa39e;
}
form { display: inline; }
input, select { padding: 6px 8px; margin-right: 8px; border: 1px solid #ccc; border-radius: 5px; }
.meta { color: #888; font-size: 0.85em; word-break: break-word; }
.err { color: #cf1322; }
.ok { color: #2e7d32; }
a { color: #1677ff; text-decoration: none; }
a:hover { text-decoration: underline; }
.topbar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 1em; }
h2, h3 { margin-top: 0; }
table { width: 100%; border-collapse: collapse; }
th, td { text-align: left; padding: 0.5em; border-bottom: 1px solid #eee; }
.table-wrap { overflow-x: auto; -webkit-overflow-scrolling: touch; }

@media (max-width: 640px) {
    .container { padding: 0.8em; }
    .topbar { flex-direction: column; align-items: flex-start; gap: 0.4em; }
    .card { padding: 0.8em; }
    form { display: block; width: 100%; }
    form input, form select {
        display: block;
        width: 100% !important;
        margin: 0 0 8px 0 !important;
        box-sizing: border-box;
    }
    form > button, form > .btn {
        display: block;
        width: 100%;
        margin: 6px 0 0 0;
    }
    .card form { display: flex; gap: 6px; flex-wrap: wrap; margin-top: 6px; }
    .card form button {
        flex: 1 1 auto;
        width: auto !important;
        margin: 0 !important;
        min-width: 72px;
    }
    th, td { padding: 0.4em; font-size: 0.9em; }
}
"#;

pub fn layout(user: Option<&User>, body: Markup, csrf_token: &str) -> Markup {
    html! {
        (DOCTYPE)
        html {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                meta name="color-scheme" content="light";
                title { "Code Server 管理器" }
                style { (STYLE) }
            }
            body {
                div .container {
                    div .topbar {
                        h2 { "Code Server 管理器" }
                        @if let Some(u) = user {
                            div {
                                span { "用户: " (u.username) " (" (u.role) ")" }
                                " | "
                                a href="/" { "首页" }
                                " | "
                                a href="/admin/users" { "用户管理" }
                                " | "
                                form method="post" action="/logout" {
                                    input type="hidden" name="csrf_token" value=(csrf_token);
                                    button type="submit" class="btn" { "退出" }
                                }
                            }
                        }
                    }
                    (body)
                }
            }
        }
    }
}

pub fn login_page(err: bool, csrf_token: &str) -> Markup {
    layout(None, html! {
        div .card style="max-width: 400px; margin: 4em auto;" {
            h2 { "登录" }
            @if err { p .err { "用户名或密码错误" } }
            form method="post" action="/login" {
                input type="hidden" name="csrf_token" value=(csrf_token);
                p { input name="username" placeholder="用户名" required style="width:100%"; }
                p { input name="password" type="password" placeholder="密码" required style="width:100%"; }
                p { button type="submit" class="btn btn-primary" style="width:100%" { "登录" } }
            }
        }
    }, csrf_token)
}

pub fn change_password_page(err: Option<&str>, csrf_token: &str) -> Markup {
    layout(None, html! {
        div .card style="max-width: 420px; margin: 4em auto;" {
            h2 { "修改密码" }
            p { "首次登录或密码被重置，请设置新密码。" }
            @if let Some(e) = err { p .err { (e) } }
            form method="post" action="/change-password" {
                input type="hidden" name="csrf_token" value=(csrf_token);
                p { input name="new_password" type="password" placeholder="新密码（至少 8 位）" required style="width:100%"; }
                p { input name="confirm" type="password" placeholder="确认新密码" required style="width:100%"; }
                p { button type="submit" class="btn btn-primary" style="width:100%" { "提交" } }
            }
        }
    }, csrf_token)
}

pub fn index_page(
    user: &User,
    instances: &[InstanceInfo],
    config: &Config,
    err: Option<&str>,
    csrf_token: &str,
) -> Markup {
    let err_msg = match err {
        Some("exists") => Some("实例名称已被占用，请换一个名称"),
        Some("name") => Some("实例名称无效，只能包含小写字母、数字和连字符"),
        Some("port") => Some("端口范围已耗尽"),
        Some("create") => Some("创建失败，请查看面板日志"),
        Some("notfound") => Some("实例不存在"),
        _ => None,
    };
    layout(Some(user), html! {
        @if let Some(m) = err_msg {
            div .card .err { (m) }
        }
        div .card {
            h3 { "创建新实例" }
            form method="post" action="/instances" {
                input type="hidden" name="csrf_token" value=(csrf_token);
                input name="name" placeholder="实例名称（小写字母/数字/-）" required;
                input name="mem" type="number" value="1024" min="256" max="8192" style="width:90px" placeholder="内存MB";
                input name="cpus" type="number" step="0.1" value="1" min="0.1" max="8" style="width:70px" placeholder="CPU";
                input name="git" placeholder="Git 仓库（可选）" style="width:280px";
                button type="submit" class="btn btn-primary" { "创建" }
            }
        }
        h3 { "实例列表" }
        @if instances.is_empty() {
            p .meta { "还没有实例。" }
        } @else {
            @for inst in instances {
                div .card {
                    strong { (inst.name) }
                    " "
                    span class=(inst.state.as_str()) { "[" (inst.state) "]" }
                    @if inst.state == "running" {
                        " "
                        a href={ "https://cs-" (inst.name) "." (config.hostname_suffix) "/" } target="_blank" { "打开" }
                    }
                    br;
                    span .meta {
                        "Owner: " (inst.owner) " | 内存: " (inst.mem) "MB | CPU: " (inst.cpus) " | 端口: 127.0.0.1:" (inst.port)
                    }
                    br;
                    form method="post" action={ "/instances/" (inst.name) "/action" } {
                        input type="hidden" name="csrf_token" value=(csrf_token);
                        button name="act" value="start" class="btn" { "启动" }
                        button name="act" value="stop" class="btn" { "停止" }
                        button name="act" value="remove" class="btn btn-danger"
                               onclick="return confirm('确认删除容器？数据目录会保留。')" { "删除" }
                    }
                }
            }
        }
    }, csrf_token)
}

pub fn admin_users_page(
    user: &User,
    users: &[(i64, String, String, i64)],
    message: Option<&str>,
    csrf_token: &str,
) -> Markup {
    layout(Some(user), html! {
        h3 { "用户管理" }
        @if let Some(m) = message { div .card .ok { (m) } }
        div .card {
            form method="post" action="/admin/users" {
                input type="hidden" name="csrf_token" value=(csrf_token);
                input name="username" placeholder="新用户名" required;
                select name="role" {
                    option value="member" { "member" }
                    option value="admin" { "admin" }
                }
                button type="submit" class="btn btn-primary" { "创建用户（生成临时密码）" }
            }
        }
        div .table-wrap {
            table {
                thead { tr { th { "ID" } th { "用户名" } th { "角色" } th { "状态" } th { "操作" } } }
                tbody {
                    @for (id, name, role, must_change) in users {
                        tr {
                            td { (id) }
                            td { (name) }
                            td { (role) }
                            td {
                                @if *must_change != 0 { span .err { "待改密" } }
                                @else { span .ok { "正常" } }
                            }
                            td {
                                form method="post" action={ "/admin/users/" (id) "/reset" } style="display:inline"
                                    onsubmit="return confirm('确认重置该用户密码？\n\n后果：\n1. 该用户所有已登录会话立即失效，正在使用的页面会被踢下线；\n2. 生成新的临时密码，页面只显示一次，需线下转交；\n3. 用户下次登录会被强制改密。')" {
                                    input type="hidden" name="csrf_token" value=(csrf_token);
                                    button type="submit" class="btn" { "重置密码" }
                                }
                                @if *id != user.id {
                                    form method="post" action={ "/admin/users/" (id) "/delete" } style="display:inline"
                                        onsubmit="return confirm('确认删除该用户？其所有会话会立即失效，且不可恢复。')" {
                                        input type="hidden" name="csrf_token" value=(csrf_token);
                                        button type="submit" class="btn btn-danger" { "删除" }
                                    }
                                } @else {
                                    span .meta { "（当前用户）" }
                                }
                            }
                        }
                    }
                }
            }
        }
    }, csrf_token)
}
