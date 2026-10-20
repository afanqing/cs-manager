# Code Server 多用户管理平台 — Handoff 文档

> 最后更新：2026-10-20
> 维护者：（请在此填写）
> 交接对象：（请在此填写）

## 当前代码状态

- 分支：`feature/csrf-protection`
- 最近功能提交：`2c5d409`，CSRF 表单保护；已推送到 `origin/feature/csrf-protection`
- 验证：`cargo test --quiet`，3 个测试通过
- 本轮改动尚未部署到生产环境；部署后仍需验证反向代理和浏览器实际行为

---

## 1. 项目是什么

### 1.1 一句话描述

在单台 Debian 服务器上，用 **Rust 面板 + Docker 容器 + Nginx 鉴权网关** 提供多用户、多项目的隔离式 code-server 开发环境。

### 1.2 解决什么问题

传统 `code-server` 单实例部署存在三个痛点：

1. **无隔离**：所有项目共享一个进程、一个工作区，依赖冲突、误删文件风险高；
2. **无多用户**：无法区分"谁能访问哪个项目"，只能靠端口或密码，粒度粗；
3. **资源不可控**：单个项目的内存泄漏可能拖垮整台服务器。

本项目把每个项目装进独立的 Docker 容器，用 cgroup 硬限制内存/CPU，用面板统一管理生命周期，用 Nginx `auth_request` 在每次访问时强制鉴权，实现"项目间隔离、用户间隔离、资源可控"。

### 1.3 核心特性

| 特性 | 实现方式 |
|---|---|
| 每项目独立容器 | `docker run` 时绑定独立数据目录和端口 |
| 资源硬限制 | Docker `--memory` / `--cpus` / `--pids-limit`（cgroup 内核级） |
| 多用户登录 | SQLite + argon2 哈希 + HttpOnly 会话 Cookie |
| 强制首次改密 | `must_change_password` 标志 + 受限会话 |
| CSRF 防护 | 随机 Cookie token + POST 表单隐藏字段，服务端逐请求校验 |
| 实例归属隔离 | Docker label `cs-owner` + 查询时过滤 |
| 实例端口隐身 | 只绑 `127.0.0.1`，外部唯一入口是 Nginx |
| 访问鉴权 | Nginx `auth_request` 每次转发前问面板 |
| 轻量管理面 | Rust 单二进制，常驻 5–15 MB |
| 开机自恢复 | systemd `Restart=always` + Docker `restart: unless-stopped` |

### 1.4 不做什么（明确的边界）

- **不做**多机编排（Kubernetes、Swarm），单机场景够用；
- **不做**实时协同编辑；
- **不做**自助注册，所有账号由 admin 创建；
- **不做**邮件服务（预留了 `invite_token` 字段，未来可升级）；
- **不做** rootless Docker（当前 root 运行，后续可切，见 §11）。

---

## 2. 架构总览

### 2.1 请求链路

```text
用户浏览器
│ HTTPS (IPv6)
▼
┌──────────────────────────────────────────────────┐
│ Nginx (唯一公网入口, 监听 [::]:443)               │
│                                                  │
│   cs.afanai.top        → 面板 :8100              │
│   cs-<name>.afanai.top → auth_request 子请求     │
│                          ↓ 2xx 才放行            │
│   reverse_proxy 127.0.0.1:<port>                 │
└──────────────────────────────────────────────────┘
│ │
▼ ▼
┌─────────────┐ ┌──────────────────────────┐
│ Rust 面板   │ │ code-server 容器 × N     │
│ Axum+Bollard│───────▶│ 端口仅绑 127.0.0.1       │
│ SQLite      │ socket │ cgroup 硬限制            │
│ ~5-15 MB    │        │ 数据挂载 /opt/.../instances│
└─────────────┘ └──────────────────────────┘
```

### 2.2 组件职责

| 组件 | 职责 | 不负责 |
|---|---|---|
| Nginx | TLS 终止、路由分发、`auth_request` 触发、WebSocket 升级 | 不做身份判断（交给面板） |
| Rust 面板 | 用户管理、会话管理、容器 CRUD、鉴权端点 | 不做流量转发 |
| Docker daemon | 容器生命周期、cgroup 资源限制 | 不做鉴权 |
| code-server 容器 | 提供 Web IDE | 不做用户管理（`--auth none`） |
| SQLite | 用户表、会话表 | 不做容器状态存储（状态在 Docker 里） |

### 2.3 数据流：一次实例访问

```text
浏览器请求 https://cs-test1.afanai.top/

Nginx 匹配 ~^cs-(?<inst>[a-z0-9-]+).afanai.top$

触发 auth_request → 子请求 /api/auth/verify?instance=test1

面板：
a. 从 Cookie 读 cs_session
b. 查 SQLite sessions 表，校验未过期
c. 查 users 表，确认 must_change_password=0
d. inspect_container(test1)，读 label cs-owner、cs-port
e. 校验当前用户是 owner 或 admin
f. 返回 204 + X-CS-Port: 8200

Nginx 取 $upstream_http_x_cs_port = 8200

proxy_pass http://127.0.0.1:8200

code-server 返回 IDE 界面
```

**关键点**：第 4 步任何一环失败，Nginx 都不会转发，实例端口从未暴露给外部。

---

## 3. 技术选型与理由

### 3.1 为什么用 Rust 而不是 Python/Flask

| 指标 | Rust (Axum) | Python (Flask) |
|---|---|---|
| 空闲内存 | 5–15 MB | 30–50 MB |
| 启动时间 | < 5 ms | 0.3–1 s |
| 二进制/镜像体积 | 2.8 MB（strip 后） | 50–70 MB |
| 部署依赖 | 无（静态链接） | Python 运行时 + 依赖 |

在 2GB 小内存服务器上，省下的 30MB 可以多跑一个轻量实例。且 Rust 二进制无运行时依赖，`systemd` 直接启动，没有虚拟环境、没有 pip 冲突。

### 3.2 为什么用 Bollard 而不是调 `docker` CLI

- `bollard` 直接走 Docker socket 的 HTTP API，**不依赖 shell**；
- 结构化返回（强类型），不用解析 CLI 文本输出；
- 支持 async，不阻塞 Tokio 运行时；
- 避免命令注入风险（容器名、参数都经过类型系统）。

### 3.3 为什么用 SQLite 而不是 PostgreSQL

- 单文件，零额外进程，零网络开销；
- 面板并发极低（登录、鉴权子请求），SQLite 的 WAL 模式足够；
- 备份就是复制一个文件；
- 升级路径清晰：真需要时迁到 Postgres 只改 `rusqlite` 调用层。

### 3.4 为什么用 Nginx `auth_request` 而不是 Caddy `forward_auth`

- 服务器上**已有 Nginx**，复用现有实例，不引入第二个 Web 服务器；
- Caddy 空闲内存约是 Nginx 的 8 倍（实测 ~59MB vs ~7MB）；
- `auth_request` 与 `forward_auth` 功能等价，都是"子请求放行"模式。

### 3.5 为什么用 maud 而不是模板引擎

- 编译期生成 HTML，**无运行时模板解析开销**；
- Rust 类型安全，写错标签编译不过；
- 零额外依赖（对比 Tera/Askama 需要额外 crate 和配置）。

---

## 4. 目录与文件说明

```text
/opt/code/cs-manager/
├── Cargo.toml          # 依赖与 release 优化配置
├── Cargo.lock          # 锁定版本（必须提交/保留）
├── HANDOFF.md          # 本文档
├── src/
│   ├── main.rs         # 入口：配置加载、路由注册、启动监听
│   ├── db.rs           # SQLite 初始化、建表、WAL 配置
│   ├── auth.rs         # argon2 哈希、会话 CRUD、admin 初始化
│   ├── docker_ops.rs   # Bollard 封装：列表/创建/启停/删/端口分配
│   ├── handlers.rs     # 所有 HTTP handler + 鉴权端点
│   └── templates.rs    # maud 模板：登录/首页/改密/用户管理
├── data/
│   └── data.db         # SQLite 数据库（用户、会话）
├── instances/
│   └── <实例名>/        # 每个实例的数据目录
│       └── project/    # git clone 的项目（可选）
└── target/release/
    └── cs-manager      # 编译产物（2.8 MB）
```

### 4.1 每个文件的关键职责

**`main.rs`**
- 读取环境变量：`CS_DB`、`CS_DOMAIN`、`CS_BASE_DIR`、`CS_IMAGE`、`CS_COOKIE_DOMAIN`、`CS_ADMIN_PASSWORD`
- 计算 `cookie_domain`（默认 `.` + `CS_DOMAIN`）
- 调用 `auth::ensure_admin` 首次创建 admin
- 注册全部路由，绑定 `127.0.0.1:8100`

**`db.rs`**
- 建两张表：`users`、`sessions`
- 开启 WAL、外键、busy_timeout

**`auth.rs`**
- `hash_password` / `verify_password`：argon2id
- `ensure_admin`：仅当无 admin 时创建
- `create_session` / `load_session` / `delete_session` / `delete_user_sessions`
- `generate_temp_password`：24 位 hex

**`docker_ops.rs`**
- `list_instances`：按 label 过滤，可加 owner 条件
- `create_instance`：创建目录 → git clone（blocking）→ chown 1000 → 构造容器配置 → create + start
- `start` / `stop` / `remove`
- `pick_free_port`：从 8200–8299 找空闲

**`handlers.rs`**
- `login_page` / `login_submit` / `logout`
- 登录、改密、实例操作和用户管理等 POST handler 校验 CSRF token；退出使用 POST
- `index`：按角色过滤实例，显示错误
- `create_instance`：查重 → 分配端口 → 调 docker_ops
- `instance_action`：启停删，校验归属
- `change_password_page` / `change_password_submit`
- `admin_users_page` / `admin_create_user` / `admin_reset_password`
- `auth_verify`：**Nginx auth_request 的核心端点**

**`templates.rs`**
- `layout`：公共外壳（顶栏、样式）
- `login_page` / `change_password_page` / `index_page` / `admin_users_page`
- 实例卡片"打开"链接生成 `https://cs-<name>.<domain>/`

---

## 5. 完整部署步骤

> 本节是"从裸机到可用"的完整复现流程。如果接手时系统已在运行，跳到 §8 运维手册。

### 5.1 前置条件

- Debian 11/12，root 或 sudo
- 有公网 IPv6（本项目当前环境只有 IPv6）
- 域名 + 通配符证书 `*.afanai.top`
- ddns-go 已配置泛解析 AAAA
- Nginx 已安装并运行

### 5.2 安装依赖

```bash
sudo apt update
sudo apt install -y git build-essential pkg-config libssl-dev docker.io nginx

# Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
rustc --version   # >= 1.75
```

### 5.3 拉取 code-server 镜像

```bash
docker pull codercom/code-server:latest
```

**重要**：Bollard 的 `create_container` 不会自动拉镜像。首次部署必须手动 pull，否则创建实例报 404。

### 5.4 编译面板

```bash
cd /opt/code/cs-manager
cargo check          # 快速验证语法
cargo build --release
ls -lh target/release/cs-manager   # 约 2.8 MB
```

### 5.5 创建数据目录

```bash
mkdir -p /opt/code/cs-manager/data
mkdir -p /opt/code/cs-manager/instances
```

### 5.6 配置 Nginx

新建 `/etc/nginx/conf.d/cs-manager.conf`，内容见 §13.1。

```bash
sudo nginx -t && sudo systemctl reload nginx
```

### 5.7 配置 systemd

新建 `/etc/systemd/system/cs-manager.service`，内容见 §13.2。

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now cs-manager
sudo systemctl status cs-manager
```

首次启动日志会打印 admin 临时密码（如果没有设 `CS_ADMIN_PASSWORD`）：

```bash
sudo journalctl -u cs-manager -n 30 --no-pager
```

### 5.8 验证清单

| # | 验证项 | 命令 | 期望 |
|---|---|---|---|
| 1 | 面板可访问 | `curl -6 -I https://cs.afanai.top/login` | 200 |
| 2 | 登录成功 | 浏览器登录 admin | 进入首页 |
| 3 | 创建实例 | 面板创建 test1 | 卡片出现 running |
| 4 | 容器在跑 | `docker ps --filter label=cs-manager=true` | test1 Up |
| 5 | 实例直连 | `curl -I http://127.0.0.1:8200/` | 302/200 |
| 6 | 实例通过 Nginx | 浏览器 `https://cs-test1.afanai.top/` | code-server 界面 |
| 7 | 未登录拒绝 | `curl -6 -I https://cs-test1.afanai.top/` | 302 到 login |
| 8 | 他人访问拒绝 | alice 登录后访问 test1 | 403 |
| 9 | 重启自恢复 | `sudo reboot` 后重复 1–6 | 全部通过 |

---

## 6. 核心原理详解

### 6.1 鉴权链路：为什么端口不会泄露

**问题**：如果实例端口直接对外开放，绕过面板就能访问别人的 code-server。

**方案**：

1. 容器端口绑定 `127.0.0.1:<port>`，不是 `0.0.0.0`，外部无法直连；
2. Nginx 是唯一入口，每次转发前 `auth_request` 问面板；
3. 面板校验"会话有效 + 未强制改密 + 是 owner 或 admin"，返回 204 才放行；
4. 面板通过响应头 `X-CS-Port` 告诉 Nginx 该转发到哪个端口。

**为什么这个设计可靠**：三层独立校验（网络层端口绑定、Nginx 层路由、应用层鉴权），任何一层失守，下一层仍能拦住。

### 6.2 auth_request 的空 body 要求

面板的 `/api/auth/verify` **必须返回空 body**（204 No Content）。如果返回了非空 body，Nginx 会认为还有未读响应体，强制关闭 upstream 连接，导致 `auth_request` 无法复用长连接，高频请求下延迟翻倍。

配置里的 `proxy_pass_request_body off` 和 `proxy_set_header Content-Length ""` 是官方要求，不能省。

### 6.3 Cookie 域：跨子域名的关键

**问题**：用户登录 `cs.afanai.top`，访问 `cs-test1.afanai.top` 时浏览器不发送 Cookie。

**原因**：未指定 Domain 的 Cookie 是 host-only，只对设置它的域名生效。

**方案**：面板设置 Cookie 时加 `Domain=.afanai.top`（前面带点），浏览器就会在所有子域名下发送。

**代码位置**：`main.rs` 计算 `cookie_domain = "." + CS_DOMAIN`，`handlers.rs` 的 `session_cookie` 拼入 `; Domain=...`。

**安全提醒**：`.afanai.top` 意味着 Cookie 会发到 v6-codehub、v6-vscode 等所有子域名。当前可接受，未来若要隔离，可改成 `test1.cs.afanai.top` 二级结构，Cookie 设为 `.cs.afanai.top`。

### 6.4 会话状态机

```text
[创建用户] must_change_password=1
    │
    ▼
[登录] 验证密码 → 签发 kind="pending_reset" 会话
    │
    ├── 访问 /change-password → 允许
    ├── 访问其他任何页面 → 302 到 /change-password
    └── auth_request → 428 Precondition Required
    │
    ▼
[改密成功] must_change_password=0
    │ 删除该用户所有旧会话
    │ 签发 kind="full" 会话
    ▼
[正常使用] 所有页面和 auth_request 放行
```

`auth_verify` 端点里：

```rust
if kind == "pending_reset" || user.must_change_password {
    return StatusCode::PRECONDITION_REQUIRED.into_response(); // 428
}
```

Nginx 收到 428 后跳转到面板改密页。

### 6.5 容器资源隔离

创建实例时写入：

```rust
host_config: Some(HostConfig {
    memory: Some((mem as i64) * 1024 * 1024),   // 硬上限
    nano_cpus: Some((cpus * 1e9) as i64),        // CPU 配额
    pids_limit: Some(256),                       // 进程数上限
    ...
})
```

这是 **cgroup 内核级限制**，不是应用层软限制。容器内总内存触及上限时，内核 OOM Killer 终止进程，不会影响宿主机和其他容器。

曾经尝试过 `--max-memory` 参数，但当前 code-server 版本不支持，已移除。Docker cgroup 限制已经足够。

### 6.6 数据持久化

- 容器内 `/home/coder` 挂载到宿主机 `/opt/code/cs-manager/instances/<name>`；
- 删除容器不删除数据目录，项目文件仍在；
- 创建时 `chown -R 1000:1000`，因为容器内 coder 用户 UID 是 1000；
- `git clone` 以 `uid(1000)` 执行，保证容器内可读写。

---

## 7. 踩坑记录与解决方案

> 这一节是本次部署实际遇到的问题，按时间顺序。新人遇到类似现象可直接查这里。

### 7.1 文件编码：GBK 导致编译失败

**现象**：`error: couldn't read src/auth.rs: stream did not contain valid UTF-8`

**原因**：文件在 Windows 编辑器保存为 GBK 编码。

**解决**：

```bash
iconv -f GBK -t UTF-8 src/auth.rs -o src/auth.rs.utf8 && mv src/auth.rs.utf8 src/auth.rs
```

**预防**：所有 `.rs` 文件统一 UTF-8 无 BOM 保存。

### 7.2 镜像不存在：No such image: codercom/code-server:latest

**原因**：Bollard 的 `create_container` 不会自动拉镜像，CLI 的 `docker run` 会自动 pull 是 CLI 自己的逻辑。

**解决**：手动 `docker pull codercom/code-server:latest`。

**长期方案**：在 `create_instance` 里加 `inspect_image` + `create_image` 逻辑（见 §11 改进项）。

### 7.3 --max-memory 不被支持

**现象**：容器反复 Restarting，日志 `error Unknown option --max-memory`

**原因**：当前 code-server 版本的 CLI 已移除该参数。

**解决**：从 cmd 中删除 `--max-memory` 和对应值。Docker cgroup 的 `--memory` 已经提供了硬限制，不需要应用层软限制。

### 7.4 登录成功但不跳转 / 无法访问实例

**现象**：密码正确，但登录后又回到登录页；或 alice 访问 test1 跳登录页而非 403。

**原因**：Cookie 的 Domain 不对。启动时 `CS_DOMAIN=code.example.com`，导致 Cookie 域是 `.code.example.com`，浏览器在 `cs.afanai.top` 下拒绝保存。

**解决**：用 `CS_DOMAIN=afanai.top` 重启，Cookie 域变为 `.afanai.top`。

**排查方法**：

```bash
curl -6 -i -X POST https://cs.afanai.top/login -d "username=admin&password=xxx"
# 看 set-cookie 里的 Domain=
```

### 7.5 cs.afanai.top 跳转到 Gitea

**现象**：访问面板域名，返回 `i_like_gitea` Cookie 和 Gitea 页面。

**原因**：`cs-manager.conf` 里只有实例子域名块（正则 `~^cs-(?<inst>...)`），没有面板块。`cs.afanai.top` 不匹配正则，落到隐式默认 443 server（v6-codehub.afanai.top）。

**解决**：在 `cs-manager.conf` 里加面板块：

```nginx
server {
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name cs.afanai.top;
    ...
}
```

**排查方法**：

```bash
sudo nginx -T 2>/dev/null | grep -n "server_name cs.afanai.top"
# 无输出 = 面板块缺失
```

### 7.6 DNS 泛解析未生效

**现象**：`cs.afanai.top` 无法解析。

**原因**：腾讯云 DNSPod 手动逐条添加，没有泛解析记录。

**解决**：添加 `*` 的 AAAA 记录（IPv6 环境），并将 `*.afanai.top` 加入 ddns-go 的域名列表，让它自动更新。

**验证**：

```bash
dig AAAA cs.afanai.top +short
dig AAAA cs-test1.afanai.top +short
# 两者应返回同一个公网 IPv6
```

### 7.7 实例名称重复无提示

**现象**：创建同名实例，页面刷新但无任何提示。

**原因**：index handler 没有提取 Query，`?err=create` 被忽略。

**解决**：

1. `create_instance` 里先 `inspect_container` 查重，冲突返回 `?err=exists`；
2. `index` 提取 `Query<IndexQuery>`，把 err 传给模板；
3. 模板顶部显示红色提示。

### 7.8 面板"打开"链接跳到 Gitea

**现象**：点卡片"打开"，跳到 `test1.afanai.top`（Gitea）。

**原因**：模板生成的是 `https://<name>.<domain>/`，缺少 `cs-` 前缀。

**解决**：改为 `https://cs-<name>.<domain>/`。

### 7.9 IPv6 环境下的 error_page 跳转

**注意**：`error_page 401 = @login` 里 `return 302 https://cs.afanai.top/login`，要求访问者的浏览器也支持 IPv6。当前环境只有 IPv6，访问者网络不支持 IPv6 就无法访问。这是网络层限制，不是配置问题。

---

## 8. 日常运维手册

### 8.1 服务管理

```bash
# 状态
sudo systemctl status cs-manager

# 实时日志
sudo journalctl -u cs-manager -f

# 重启（改代码后）
sudo systemctl restart cs-manager

# 停止（不推荐，会导致所有实例 500）
sudo systemctl stop cs-manager
```

### 8.2 内存监控

```bash
# 面板自身内存
cat /sys/fs/cgroup/system.slice/cs-manager.service/memory.current
# 单位字节，除以 1024 是 KB

# 所有容器内存
docker stats --no-stream

# cgroup 限制是否生效
systemctl show cs-manager -p MemoryMax
# 期望 67108864（64MB）
```

### 8.3 实例管理

```bash
# 列出所有实例
docker ps -a --filter label=cs-manager=true

# 看某个实例日志
docker logs test1 --tail 50

# 看资源占用
docker stats test1 --no-stream

# 看 restart policy
docker inspect test1 --format '{{.HostConfig.RestartPolicy.Name}}'
# 期望 unless-stopped

# 看端口映射
docker port test1
# 期望 8080/tcp -> 127.0.0.1:8200
```

### 8.4 备份

只备份两个目录：

- 用户和会话数据：`/opt/code/cs-manager/data/data.db`
- 所有项目文件：`/opt/code/cs-manager/instances/`

推荐命令：

```bash
tar czf /backup/cs-manager-$(date +%F).tar.gz \
  /opt/code/cs-manager/data \
  /opt/code/cs-manager/instances
```

代码目录不需要备份，可以从仓库重新 clone + 编译。

### 8.5 升级面板

```bash
cd /opt/code/cs-manager

# 1. 备份数据（可选但推荐）
tar czf /tmp/cs-backup-$(date +%F).tar.gz data instances

# 2. 更新代码（或手动替换 src/）
#    git pull 或直接编辑文件

# 3. 编译
cargo build --release

# 4. 重启
sudo systemctl restart cs-manager

# 5. 验证
sudo systemctl status cs-manager
curl -6 -I https://cs.afanai.top/login
```

**不要删 `data/` 和 `instances/`。**

### 8.6 添加新用户

1. 浏览器登录 admin
2. 右上角"用户管理"
3. 输入用户名、选角色（member/admin）
4. 点"创建用户"
5. 记下页面显示的临时密码（**只显示一次**）
6. 线下转交给新用户
7. 新用户首次登录会被强制改密

### 8.7 重置用户密码

"用户管理"页 → 对应用户 → "重置密码" → 记下新临时密码 → 转交。

重置后该用户所有旧会话立即失效。

### 8.8 清理废弃实例

面板操作：点"删除" → 容器删除，**数据目录保留**。

彻底清理（确认项目文件不要了）：

```bash
rm -rf /opt/code/cs-manager/instances/<name>
```

---

## 9. 安全模型与边界

### 9.1 防护层次

| 层 | 措施 | 失效后果 |
|---|---|---|
| 网络 | 实例端口只绑 `127.0.0.1` | 外部无法直连实例 |
| 入口 | Nginx 唯一公网入口，TLS 终止 | 所有流量经鉴权 |
| 鉴权 | `auth_request` 每次转发前问面板 | 未授权请求被拒 |
| 会话与 CSRF | HttpOnly + SameSite=Lax 会话 Cookie；状态变更 POST 校验表单 token | 跨站请求缺少有效 token 时被拒绝 |
| 密码 | argon2id 哈希 | 数据库泄露也难爆破 |
| 归属 | Docker label `cs-owner` + 查询过滤 | 用户只能管自己的实例 |
| 资源 | cgroup 硬限制 | 单实例失控不波及宿主 |
| 进程 | systemd `NoNewPrivileges=true` | 面板无法提权 |

### 9.2 CSRF 防护

- 页面首次渲染时生成随机 CSRF token，并通过 `cs_csrf` Cookie 保存；POST 表单同时包含隐藏字段 `csrf_token`。
- 服务端对 Cookie token 和表单 token 做匹配校验；缺少或不匹配时返回 `403`。
- 登录、创建实例、实例启停/删除、修改密码、用户创建/重置/删除以及退出均受保护。
- 退出路由是 `POST /logout`，不再通过 GET 请求改变会话状态。
- CSRF token Cookie 使用 `HttpOnly` 和 `SameSite=Lax`；token 会被渲染进本站表单。该机制不替代 XSS 防护，同源脚本注入仍可读取页面内容并代表用户操作。

### 9.3 当前的安全边界（必须知道）

1. **面板以 root 运行，持有 `/var/run/docker.sock`**。Docker socket 权限等同宿主机 root。面板被攻破 = 宿主机失守。当前接受这个风险，因为：
   - 面板只监听 `127.0.0.1`，不直接暴露；
   - 公网入口是 Nginx + TLS + 鉴权；
   - 单机、受控环境。

   改进方向：rootless Docker（见 §11）。

2. **临时密码传递靠人工**。方案保证"一次性 + 强制改密 + 改密后旧会话全失效"，但传递渠道（微信/口头）的安全性由团队约定。

3. **Cookie 域是 `.afanai.top`**，会发到所有子域名，包括 v6-codehub、v6-vscode。CSRF token 校验降低了跨站伪造请求风险，但不能防止本站 XSS；共享 Cookie 域仍扩大了 Cookie 的发送范围。

4. **`--auth none`**：code-server 容器内部不做认证，完全依赖外层 Nginx + 面板鉴权。**绝对不能把实例端口暴露到公网**。

### 9.4 绝对不要做的事

- ❌ 把 8100 或 8200–8299 端口开放到公网；
- ❌ 把容器的 `host_ip` 从 `127.0.0.1` 改成 `0.0.0.0`；
- ❌ 在 Nginx 配置里移除 `auth_request`；
- ❌ 用弱密码或把 admin 密码写在公开的地方；
- ❌ 删除 `data/data.db`（所有用户和会话会丢失）。

---

## 10. 已知限制与取舍

| 限制 | 影响 | 取舍理由 |
|---|---|---|
| 实例名称全局唯一 | alice 和 bob 不能都叫 proj1 | Docker 容器名全局唯一，改造成本 > 当前收益 |
| 面板是单点 | 面板挂了，实例访问 500 | 单机场景，Restart=always 已把中断压到 2 秒级 |
| 只有 IPv6 公网 | 纯 IPv4 网络无法访问 | 服务器网络环境决定，非本项目可控 |
| 会话 7 天过期 | 需要定期重新登录 | 安全与便利的平衡 |
| 临时密码人工传递 | 传递渠道安全性依赖团队 | 引入邮件服务增加复杂度，当前团队规模不需要 |
| root 运行面板 | 面板被攻破 = 宿主机失守 | 单机受控环境可接受，rootless 留作后续 |
| 无审计日志 | 无法追溯谁做了什么 | 当前规模不需要，未来可加表 |
| 无自动 pull 镜像 | 换镜像需手动 pull | 当前只用官方镜像，频率低 |

---

## 11. 后续改进路线

按优先级排序，每项都标注了改动范围。

### 11.1 P1：创建实例时自动拉镜像

**现状**：换 `CS_IMAGE` 或首次部署需手动 `docker pull`。

**改动**：`docker_ops.rs` 的 `create_instance` 开头加：

```rust
use futures_util::StreamExt;

if docker.inspect_image(spec.image).await.is_err() {
    let mut stream = docker.create_image(
        Some(bollard::image::CreateImageOptions {
            from_image: spec.image,
            ..Default::default()
        }),
        None, None,
    );
    while let Some(item) = stream.next().await { item?; }
}
```

`Cargo.toml` 加 `futures-util = "0.3"`。

### 11.2 P1：跨用户同名实例

**现状**：容器名和数据目录都是全局唯一。

**改动**：

- 容器名改为 `cs-<owner>-<name>`；
- 数据目录改为 `instances/<owner>/<name>`；
- `list_instances`、`auth_verify`、templates 同步调整。

### 11.3 P2：rootless Docker

**现状**：面板以 root 运行，持有 root 权限的 Docker socket。

**改动**：

1. 安装 rootless Docker（`dockerd-rootless-setuptool.sh install`）；
2. 创建专用用户 `cs-manager`，加入 docker 组；
3. systemd service 的 `User=cs-manager`；
4. `Docker::connect_with_local_defaults()` 会自动找 `$XDG_RUNTIME_DIR/docker.sock`；
5. 确保 `instances/` 对该用户可读写。

**注意**：rootless 下 `--network host` 不可用，但本项目不用 host 网络。

### 11.4 P2：邮件邀请

**现状**：admin 创建用户后手动转交临时密码。

**改动**：

1. `users` 表加 `invite_token TEXT UNIQUE`、`invite_expires_at INTEGER`；
2. admin 创建用户时不设密码，生成 token；
3. 加 SMTP 发送逻辑（`lettre` crate）；
4. 加 `/register/<token>` 路由，用户自设密码。

### 11.5 P2：审计日志

**改动**：

1. 加 `audit_log` 表：`id, user_id, action, target, detail, created_at`；
2. 在创建/启停/删/改密/登录处插入记录；
3. admin 页加"审计日志"入口。

### 11.6 P3：实例模板

**需求**：创建时选"Python 项目""Node 项目"，自动装依赖。

**改动**：

- 预定义模板：自定义镜像或 `init.sh` 脚本；
- `create_instance` 接收模板参数，写入数据目录或选择镜像。

### 11.7 P3：PWA 集成

**现状**：用户可手动在浏览器安装 PWA，但面板无提示。

**改动**：卡片"打开"旁加提示文字，引导用户点地址栏安装图标。

### 11.8 P3：多节点

**需求**：容器跑在多台机器上。

**改动**：把 Docker 操作抽象成 `ContainerBackend` trait，实现本地和远程两种。改动大，非当前目标。

---

## 12. 故障排查速查表

| 现象 | 可能原因 | 排查命令 |
|---|---|---|
| 面板 502 | 面板进程没跑 | `systemctl status cs-manager` |
| 面板 404 跳到 Gitea | `server_name` 不匹配 | `nginx -T \| grep cs.afanai.top` |
| 登录不跳转 | Cookie Domain 错 | `curl -i -X POST .../login` 看 set-cookie |
| 实例访问 500 | `auth_request` 失败 | `journalctl -u cs-manager -f` |
| 实例访问 302 到 login | 未登录或 Cookie 没带上 | 浏览器开发者工具看 Cookie |
| 实例访问 403 | 不是 owner | 检查 `docker inspect <name>` 的 `cs-owner` |
| 实例 502 | 端口没映射上 | `docker port <name>`、`ss -lntp \| grep 82` |
| 容器反复 Restarting | 启动参数错 | `docker logs <name> --tail 50` |
| 创建实例报 404 | 镜像没拉 | `docker images \| grep codercom` |
| 创建实例无反应 | 名称重复或端口耗尽 | 看 URL 的 `?err=` |
| 改密后仍被拦截 | 旧会话没清 | 删浏览器 Cookie 重登 |
| 重启后实例不在 | restart policy 没生效 | `docker inspect <name> --format '{{.HostConfig.RestartPolicy.Name}}'` |
| DNS 解析不到 | 泛解析没配 | `dig AAAA cs-test1.afanai.top +short` |
| 只有 IPv6 能访问 | 访问者无 IPv6 | 网络层限制，非配置问题 |

---

## 13. 附录：关键配置全文

### 13.1 /etc/nginx/conf.d/cs-manager.conf

```nginx
# 面板入口
server {
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name cs.afanai.top;

    ssl_certificate     /etc/letsencrypt/live/afanai.top/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/afanai.top/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8100;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

# 实例子域名入口
server {
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name ~^cs-(?<inst>[a-z0-9-]+)\.afanai\.top$;

    ssl_certificate     /etc/letsencrypt/live/afanai.top/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/afanai.top/privkey.pem;

    location / {
        auth_request /_auth;
        auth_request_set $cs_port $upstream_http_x_cs_port;

        error_page 401 = @login;
        error_page 403 = @forbidden;
        error_page 428 = @change_pw;

        proxy_pass http://127.0.0.1:$cs_port;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Host $http_host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_buffering off;
        proxy_read_timeout 86400;
        proxy_send_timeout 86400;
    }

    location = /_auth {
        internal;
        proxy_pass http://127.0.0.1:8100/api/auth/verify?instance=$inst;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        proxy_set_header Cookie $http_cookie;
        proxy_set_header X-Original-URI $request_uri;
    }

    location @login {
        return 302 https://cs.afanai.top/login;
    }
    location @forbidden {
        return 403 "forbidden";
    }
    location @change_pw {
        return 302 https://cs.afanai.top/change-password;
    }
}
```

### 13.2 /etc/systemd/system/cs-manager.service

```ini
[Unit]
Description=Code Server Manager (Rust)
After=docker.service network-online.target
Requires=docker.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=/opt/code/cs-manager/target/release/cs-manager
WorkingDirectory=/opt/code/cs-manager
Restart=always
RestartSec=2
User=root

Environment=CS_DB=/opt/code/cs-manager/data/data.db
Environment=CS_DOMAIN=afanai.top
Environment=CS_BASE_DIR=/opt/code/cs-manager/instances
Environment=CS_IMAGE=codercom/code-server:latest

MemoryMax=64M
CPUQuota=50%

NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

### 13.3 环境变量说明

| 变量 | 必填 | 默认值 | 说明 |
|---|---|---|---|
| `CS_DB` | 否 | `/opt/cs-manager/data.db` | SQLite 路径 |
| `CS_DOMAIN` | 是 | `code.example.com` | 根域名，用于 Cookie 域和链接生成 |
| `CS_BASE_DIR` | 否 | `/opt/code-server-instances` | 实例数据目录 |
| `CS_IMAGE` | 否 | `codercom/code-server:latest` | code-server 镜像 |
| `CS_COOKIE_DOMAIN` | 否 | `.` + `CS_DOMAIN` | Cookie 域，通常不用改 |
| `CS_ADMIN_PASSWORD` | 否 | 随机生成 | 仅首次创建 admin 时使用 |

### 13.4 数据库表结构

```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'member',
    must_change_password INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
);

CREATE TABLE sessions (
    token TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    kind TEXT NOT NULL,          -- 'full' | 'pending_reset'
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
```

### 13.5 容器 label 约定

| Label | 值 | 用途 |
|---|---|---|
| `cs-manager` | `true` | 标识本面板创建的容器 |
| `cs-owner` | 用户名 | 归属控制 |
| `cs-mem` | 内存 MB | 面板显示 |
| `cs-cpus` | CPU 核数 | 面板显示 |
| `cs-port` | 宿主机端口 | 端口分配和显示 |

---

## 14. 交接清单

接任者第一次上手，按顺序做：

- [ ] 读完 §1–§4，理解架构和文件职责
- [ ] 跑一遍 §8.1 的服务管理命令，确认能看状态、看日志
- [ ] 跑一遍 §8.3 的实例管理命令，确认能看到所有容器
- [ ] 登录面板，创建一个测试实例，走一遍 §5.8 的验证清单
- [ ] 读 §9 安全模型，理解"绝对不能做的事"
- [ ] 确认备份策略（§8.4）已配置
- [ ] 把维护者联系方式更新到本文档顶部
- [ ] 如果要做改进，按 §11 的优先级选择，不要一次改太多

---

文档结束。有任何疑问，先查 §7 踩坑记录和 §12 故障排查，再动手。
