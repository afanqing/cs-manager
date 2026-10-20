use std::collections::{HashMap, HashSet};

use bollard::{
    container::{
        Config as ContainerConfig, CreateContainerOptions, ListContainersOptions,
        RemoveContainerOptions, StartContainerOptions,
    },
    models::{HostConfig, PortBinding, RestartPolicy, RestartPolicyNameEnum},
    Docker,
};

pub struct InstanceInfo {
    pub name: String,
    pub state: String,
    pub port: u16,
    pub mem: u32,
    pub cpus: f32,
    pub owner: String,
}

pub struct CreateSpec<'a> {
    pub name: &'a str,
    pub owner: &'a str,
    pub mem: u32,
    pub cpus: f32,
    pub git: Option<&'a str>,
    pub port: u16,
    pub base_dir: &'a str,
    pub image: &'a str,
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
        let name = c
            .names
            .unwrap_or_default()
            .first()
            .map(|n| n.trim_start_matches('/').to_string())
            .unwrap_or_default();
        let labels = c.labels.unwrap_or_default();
        result.push(InstanceInfo {
            name,
            state: c.state.unwrap_or_else(|| "unknown".into()),
            port: labels.get("cs-port").and_then(|v| v.parse().ok()).unwrap_or(0),
            mem: labels.get("cs-mem").and_then(|v| v.parse().ok()).unwrap_or(1024),
            cpus: labels.get("cs-cpus").and_then(|v| v.parse().ok()).unwrap_or(1.0),
            owner: labels.get("cs-owner").cloned().unwrap_or_default(),
        });
    }
    Ok(result)
}

pub async fn create_instance(docker: &Docker, spec: CreateSpec<'_>) -> anyhow::Result<()> {
    let data_dir = format!("{}/{}", spec.base_dir, spec.name);
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

    let opts = CreateContainerOptions {
        name: spec.name,
        ..Default::default()
    };

    docker.create_container(Some(opts), config).await?;
    docker
        .start_container(spec.name, None::<StartContainerOptions<String>>)
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