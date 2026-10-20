# Code Server 多用户管理平台

一个基于 Rust、Docker 和 Nginx 的轻量级 code-server 多用户管理面板。面板负责账号与权限管理，用户可以创建独立的开发容器；Nginx 通过 `auth_request` 在转发请求前向面板验证访问权限。

## 功能

- 每个开发实例运行在独立 Docker 容器中，并限制 CPU、内存和进程数。
- 使用 SQLite 保存用户和会话；密码使用 Argon2 哈希。
- 按实例归属控制访问权限，并支持管理员管理用户。
- 对状态变更表单执行 CSRF token 校验；退出通过 POST 完成。
- 实例端口仅绑定到本机，由 Nginx 作为外部访问入口。

## 环境要求

- Rust stable 工具链和 Cargo。
- 可供面板访问的 Docker Engine。
- 部署到公网时，还需要 Nginx、TLS 证书和相应的域名配置。

SQLite 使用 bundled 构建，不需要单独安装 SQLite 服务。

## 开发与验证

```bash
cargo test
cargo build --release
```

运行面板需要 Docker daemon 可用，并且数据库目录可写。默认监听地址为 `127.0.0.1:8100`；面板不会直接监听公网地址。

## 主要配置

| 环境变量 | 默认值 | 用途 |
|---|---|---|
| `CS_DB` | `/opt/cs-manager/data.db` | SQLite 数据库路径 |
| `CS_DOMAIN` | `code.example.com` | 实例子域名后缀 |
| `CS_COOKIE_DOMAIN` | 根据 `CS_DOMAIN` 推导 | Cookie 域；可显式覆盖 |
| `CS_BASE_DIR` | `/opt/code-server-instances` | 实例数据目录 |
| `CS_IMAGE` | `codercom/code-server:latest` | 新实例使用的镜像 |
| `CS_ADMIN_PASSWORD` | 未设置时自动生成 | 首次初始化管理员密码 |

端口范围当前固定为 `8200–8299`。完整部署参数及 Nginx、systemd 配置见 [HANDOFF.md](HANDOFF.md)。

## 文档

[HANDOFF.md](HANDOFF.md) 收录架构细节、完整部署步骤、日常运维、备份恢复、安全边界、故障排查和后续改进路线。README 仅作为项目入口和开发快速参考，不重复维护交接手册内容。

## 安全提示

不要将面板端口 `8100` 或实例端口 `8200–8299` 直接暴露到公网。公网部署应通过 HTTPS Nginx 入口访问，并保留实例路由上的 `auth_request` 鉴权。