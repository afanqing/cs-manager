use std::collections::{HashMap, HashSet};

use bollard::{
    container::{
        Config as ContainerConfig, CreateContainerOptions, ListContainersOptions,
        RemoveContainerOptions, StartContainerOptions, UpdateContainerOptions,
    },
    models::{HostConfig, PortBinding, RestartPolicy, RestartPolicyNameEnum},
    Docker,
};
use futures_util::StreamExt;

/// 面板首页展示的实例信息，来自 Docker label 和 inspect 结果。
pub struct InstanceInfo {
    /// 实例名（`cs-name` label，支持跨用户同名）。
    pub name: String,
    /// 容器状态（running / exited / created 等）。
    pub state: String,
    /// 宿主机端口（`cs-port` label）。
    pub port: u16,
    /// 内存上限（MB），优先取 Docker inspect 的实际值。
    pub mem: u32,
    /// CPU 上限（核数），优先取 Docker inspect 的实际值。
    pub cpus: f32,
    /// 归属用户名（`cs-owner` label）。
    pub owner: String,
}

/// 创建实例的参数。
pub struct CreateSpec<'a> {
    /// 实例名（已清理的 kebab-case）。
    pub name: &'a str,
    /// 归属用户名。
    pub owner: &'a str,
    /// 内存上限（MB）。
    pub mem: u32,
    /// CPU 上限（核数）。
    pub cpus: f32,
    /// 可选的 git 仓库 URL，创建时 clone 到 project/ 目录。
    pub git: Option<&'a str>,
    /// 分配的宿主机端口。
    pub port: u16,
    /// 实例数据目录根路径。
    pub base_dir: &'a str,
    /// code-server Docker 镜像。
    pub image: &'a str,
}

/// 内存下限（MB）。
pub const MIN_MEMORY_MB: u32 = 256;
/// 内存上限（MB）。
pub const MAX_MEMORY_MB: u32 = 8192;
/// CPU 下限（核数）。
pub const MIN_CPUS: f32 = 0.1;
/// CPU 上限（核数）。
pub const MAX_CPUS: f32 = 8.0;

pub fn validate_resource_limits(mem: u32, cpus: f32) -> anyhow::Result<()> {
    anyhow::ensure!(
        (MIN_MEMORY_MB..=MAX_MEMORY_MB).contains(&mem),
        "memory must be between {MIN_MEMORY_MB} and {MAX_MEMORY_MB} MB"
    );
    anyhow::ensure!(
        cpus.is_finite() && (MIN_CPUS..=MAX_CPUS).contains(&cpus),
        "CPU limit must be between {MIN_CPUS} and {MAX_CPUS}"
    );
    Ok(())
}

fn resource_update_options(mem: u32, cpus: f32) -> UpdateContainerOptions<String> {
    UpdateContainerOptions {
        memory: Some((mem as i64) * 1024 * 1024),
        nano_cp_us: Some((cpus as f64 * 1_000_000_000.0) as i64),
        ..Default::default()
    }
}

pub async fn list_instances(
    docker: &Docker,
    owner_filter: Option<&str>,
) -> anyhow::Result<Vec<InstanceInfo>> {
    let mut filters: HashMap<String, Vec<String>> = HashMap::new();
    let mut labels = vec!["cs-manager=true".to_string()];
    if let Some(o) = owner_filter {
        labels.push(format!("cs-owner={}", o));
    }
    filters.insert("label".to_string(), labels);

    let opts = ListContainersOptions {
        all: true,
        filters,
        ..Default::default()
    };

    let containers = docker.list_containers(Some(opts)).await?;
    let mut result = Vec::new();
    for c in containers {
        let container_name = c
            .names
            .unwrap_or_default()
            .first()
            .map(|n| n.trim_start_matches('/').to_string())
            .unwrap_or_default();
        let labels = c.labels.unwrap_or_default();
        // 优先使用 cs-name 标签作为实例名（支持跨用户同名实例）
        let name = labels
            .get("cs-name")
            .cloned()
            .unwrap_or_else(|| container_name.clone());
        let inspect = docker.inspect_container(&container_name, None).await.ok();
        let host_config = inspect.as_ref().and_then(|info| info.host_config.as_ref());
        let mem = host_config
            .and_then(|config| config.memory)
            .filter(|memory| *memory > 0)
            .map(|memory| (memory / (1024 * 1024)) as u32)
            .or_else(|| labels.get("cs-mem").and_then(|v| v.parse().ok()))
            .unwrap_or(1024);
        let cpus = host_config
            .and_then(|config| config.nano_cpus)
            .filter(|nano_cpus| *nano_cpus > 0)
            .map(|nano_cpus| nano_cpus as f64 / 1_000_000_000.0)
            .map(|cpus| cpus as f32)
            .or_else(|| labels.get("cs-cpus").and_then(|v| v.parse().ok()))
            .unwrap_or(1.0);
        result.push(InstanceInfo {
            name,
            state: c.state.unwrap_or_else(|| "unknown".into()),
            port: labels.get("cs-port").and_then(|v| v.parse().ok()).unwrap_or(0),
            mem,
            cpus,
            owner: labels.get("cs-owner").cloned().unwrap_or_default(),
        });
    }
    Ok(result)
}

/// 根据 owner 和 instance name 生成容器名（支持跨用户同名实例）
pub fn container_name(owner: &str, name: &str) -> String {
    format!("cs-{}-{}", owner, name)
}

/// 从 Nginx 子域名捕获段还原容器名。
///
/// Nginx 的 `server_name ~^cs-(?<inst>[a-z0-9_-]+)\.<domain>$` 会把 `cs-` 之后的
/// 全部内容（即 `<owner>-<name>`）捕获为 `$inst`，因此容器名就是 `cs-` + `$inst`。
/// 用户名与实例名都可能含连字符，这里刻意不做拆分以避免歧义。
///
/// 字符集包含 `_`：面板允许用户名含下划线（见 `admin_create_user`），
/// 且 Docker 容器名允许下划线，因此主机名段必须同样接受，否则这类用户的实例无法路由。
///
/// 返回 `None` 表示输入不是合法的小写 kebab-case 主机名段，调用方应拒绝请求，
/// 避免把任意字符串拼进容器名查询。
pub fn container_name_from_host(host_part: &str) -> Option<String> {
    let ok = !host_part.is_empty()
        && host_part.len() <= 128
        && !host_part.starts_with('-')
        && !host_part.starts_with('_')
        && !host_part.ends_with('-')
        && !host_part.ends_with('_')
        && host_part
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_');
    ok.then(|| format!("cs-{host_part}"))
}

pub async fn create_instance(docker: &Docker, spec: CreateSpec<'_>) -> anyhow::Result<()> {
    let cname = container_name(spec.owner, spec.name);
    let data_dir = format!("{}/{}/{}", spec.base_dir, spec.owner, spec.name);

    // 镜像不存在时自动拉取
    if docker.inspect_image(spec.image).await.is_err() {
        tracing::info!("镜像 {} 不存在，正在拉取...", spec.image);
        let mut stream = docker.create_image(
            Some(bollard::image::CreateImageOptions {
                from_image: spec.image,
                ..Default::default()
            }),
            None,
            None,
        );
        while let Some(item) = stream.next().await {
            item?;
        }
    }

    // 创建数据目录
    std::fs::create_dir_all(&data_dir)?;

    // git clone + chown 放到 blocking 线程
    let git_url = spec.git.map(|s| s.to_string());
    let project_dir = format!("{}/project", data_dir);
    let data_dir_bg = data_dir.clone();
    tokio::task::spawn_blocking(move || {
        if let Some(url) = git_url {
            if !std::path::Path::new(&project_dir).join(".git").exists() {
                let _ = std::process::Command::new("git")
                    .args(["clone", &url, &project_dir])
                    .status();
            }
        }
        let _ = std::process::Command::new("chown")
            .args(["-R", "1000:1000", &data_dir_bg])
            .status();
    })
    .await
    .ok();

    let mut labels = HashMap::new();
    labels.insert("cs-manager".to_string(), "true".to_string());
    labels.insert("cs-owner".to_string(), spec.owner.to_string());
    labels.insert("cs-mem".to_string(), spec.mem.to_string());
    labels.insert("cs-cpus".to_string(), spec.cpus.to_string());
    labels.insert("cs-port".to_string(), spec.port.to_string());
    labels.insert("cs-name".to_string(), spec.name.to_string());

    let mut port_bindings = HashMap::new();
    port_bindings.insert(
        "8080/tcp".to_string(),
        Some(vec![PortBinding {
            host_ip: Some("127.0.0.1".to_string()),
            host_port: Some(spec.port.to_string()),
        }]),
    );

    let config = ContainerConfig {
        image: Some(spec.image.to_string()),
        labels: Some(labels),
        cmd: Some(vec![
            "--bind-addr".to_string(),
            "0.0.0.0:8080".to_string(),
            "--auth".to_string(),
            "none".to_string(),
            "--disable-telemetry".to_string(),
            "--disable-workspace-trust".to_string(),
            "/home/coder".to_string(),
        ]),
        host_config: Some(HostConfig {
            memory: Some((spec.mem as i64) * 1024 * 1024),
            nano_cpus: Some((spec.cpus as f64 * 1_000_000_000.0) as i64),
            pids_limit: Some(256),
            port_bindings: Some(port_bindings),
            binds: Some(vec![format!("{}:/home/coder", data_dir)]),
            restart_policy: Some(RestartPolicy {
                name: Some(RestartPolicyNameEnum::UNLESS_STOPPED),
                maximum_retry_count: None,
            }),
            ..Default::default()
        }),
        ..Default::default()
    };

    let opts = CreateContainerOptions::<String> {
        name: cname.clone(),
        ..Default::default()
    };

    docker.create_container(Some(opts), config).await?;
    docker
        .start_container(&cname, None::<StartContainerOptions<String>>)
        .await?;
    Ok(())
}

pub async fn update_resources(
    docker: &Docker,
    name: &str,
    mem: u32,
    cpus: f32,
) -> anyhow::Result<()> {
    validate_resource_limits(mem, cpus)?;
    docker
        .update_container(name, resource_update_options(mem, cpus))
        .await?;
    Ok(())
}

pub async fn start(docker: &Docker, name: &str) -> anyhow::Result<()> {
    docker
        .start_container(name, None::<StartContainerOptions<String>>)
        .await?;
    Ok(())
}

pub async fn stop(docker: &Docker, name: &str) -> anyhow::Result<()> {
    docker.stop_container(name, None).await?;
    Ok(())
}

pub async fn remove(docker: &Docker, name: &str) -> anyhow::Result<()> {
    let _ = docker.stop_container(name, None).await;
    docker
        .remove_container(
            name,
            Some(RemoveContainerOptions {
                force: true,
                ..Default::default()
            }),
        )
        .await?;
    Ok(())
}

pub fn pick_free_port(used: &HashSet<u16>, min: u16, max: u16) -> Option<u16> {
    (min..=max).find(|p| !used.contains(p))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_limits_accept_supported_boundaries() {
        assert!(validate_resource_limits(MIN_MEMORY_MB, MIN_CPUS).is_ok());
        assert!(validate_resource_limits(MAX_MEMORY_MB, MAX_CPUS).is_ok());
    }

    #[test]
    fn resource_limits_reject_out_of_range_values() {
        assert!(validate_resource_limits(MIN_MEMORY_MB - 1, 1.0).is_err());
        assert!(validate_resource_limits(MAX_MEMORY_MB + 1, 1.0).is_err());
        assert!(validate_resource_limits(1024, MIN_CPUS - 0.01).is_err());
        assert!(validate_resource_limits(1024, MAX_CPUS + 0.1).is_err());
        assert!(validate_resource_limits(1024, f32::NAN).is_err());
    }

    #[test]
    fn resource_update_uses_docker_units() {
        let options = resource_update_options(2048, 2.5);

        assert_eq!(options.memory, Some(2 * 1024 * 1024 * 1024));
        assert_eq!(options.nano_cp_us, Some(2_500_000_000));
    }

    #[test]
    fn container_name_formats_owner_and_name() {
        assert_eq!(container_name("alice", "devbox"), "cs-alice-devbox");
        assert_eq!(container_name("bob", "my-project"), "cs-bob-my-project");
    }

    #[test]
    fn container_name_supports_same_name_different_owners() {
        let a = container_name("alice", "web");
        let b = container_name("bob", "web");
        assert_ne!(a, b);
        assert_eq!(a, "cs-alice-web");
        assert_eq!(b, "cs-bob-web");
    }

    #[test]
    fn container_name_from_host_roundtrips_container_name() {
        // Nginx 捕获 `cs-` 之后的全部内容，因此还原结果必须与 container_name 一致。
        // 这是"跨用户同名实例"能正确路由的核心不变量。
        for (owner, name) in [
            ("alice", "web"),
            ("bob", "web"),
            ("alice", "my-project"),
            ("team-lead", "dev-box"),
        ] {
            let cname = container_name(owner, name);
            let host_part = cname.strip_prefix("cs-").expect("container name has cs- prefix");
            assert_eq!(container_name_from_host(host_part).as_deref(), Some(cname.as_str()));
        }
    }

    #[test]
    fn container_name_from_host_rejects_malformed_input() {
        // 防止把任意字符串拼进容器名查询
        assert_eq!(container_name_from_host(""), None);
        assert_eq!(container_name_from_host("-leading"), None);
        assert_eq!(container_name_from_host("trailing-"), None);
        assert_eq!(container_name_from_host("_leading"), None);
        assert_eq!(container_name_from_host("trailing_"), None);
        assert_eq!(container_name_from_host("UPPER"), None);
        assert_eq!(container_name_from_host("has space"), None);
        assert_eq!(container_name_from_host("path/../etc"), None);
        assert_eq!(container_name_from_host("has.dot"), None);
        assert_eq!(container_name_from_host(&"a".repeat(129)), None);
    }

    #[test]
    fn container_name_from_host_accepts_underscores_in_username() {
        // 面板允许用户名含下划线（见 admin_create_user），主机名段必须同样接受，
        // 否则这类用户的实例永远无法路由。
        assert_eq!(
            container_name_from_host("foo_bar-web").as_deref(),
            Some("cs-foo_bar-web")
        );
        // 往返：含下划线的用户名生成的容器名能正确还原
        let cname = container_name("foo_bar", "web");
        let host_part = cname.strip_prefix("cs-").unwrap();
        assert_eq!(container_name_from_host(host_part).as_deref(), Some(cname.as_str()));
    }

    #[test]
    fn container_name_from_host_accepts_valid_kebab_case() {
        assert_eq!(
            container_name_from_host("alice-web").as_deref(),
            Some("cs-alice-web")
        );
        assert_eq!(container_name_from_host("a").as_deref(), Some("cs-a"));

        // 长度上限边界：128 字符可接受，129 字符拒绝
        let longest = "a".repeat(128);
        let expected = format!("cs-{longest}");
        assert_eq!(
            container_name_from_host(&longest).as_deref(),
            Some(expected.as_str())
        );
    }
}