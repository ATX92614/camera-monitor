use async_trait::async_trait;
use libunftp::auth::{AuthenticationError, Authenticator, Credentials, DefaultUser};
use libunftp::options::{ActivePassiveMode, Shutdown};
use libunftp::Server;
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::ops::RangeInclusive;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use unftp_sbe_fs::ServerExt;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FtpServerConfig {
    pub bind_host: String,
    pub port: u16,
    pub root_dir: String,
    pub username: String,
    pub password: String,
    pub passive_port_start: u16,
    pub passive_port_end: u16,
    pub passive_host: Option<String>,
    pub allow_anonymous: bool,
    pub enable_active_mode: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FtpServerStatus {
    pub running: bool,
    pub bind_addr: Option<String>,
    pub root_dir: Option<String>,
    pub username: Option<String>,
    pub allow_anonymous: bool,
    pub passive_port_start: Option<u16>,
    pub passive_port_end: Option<u16>,
    pub passive_host: Option<String>,
    pub enable_active_mode: bool,
}

#[derive(Debug, Default)]
pub struct FtpServerState {
    inner: Mutex<Option<RunningFtpServer>>,
}

#[derive(Debug)]
struct RunningFtpServer {
    status: FtpServerStatus,
    shutdown_tx: oneshot::Sender<()>,
    task: JoinHandle<Result<(), String>>,
}

#[derive(Debug)]
struct SingleUserAuthenticator {
    username: String,
    password: String,
}

#[async_trait]
impl Authenticator<DefaultUser> for SingleUserAuthenticator {
    async fn authenticate(
        &self,
        username: &str,
        creds: &Credentials,
    ) -> Result<DefaultUser, AuthenticationError> {
        if username != self.username {
            return Err(AuthenticationError::BadUser);
        }

        let Some(password) = creds.password.as_deref() else {
            return Err(AuthenticationError::BadPassword);
        };

        if password != self.password {
            return Err(AuthenticationError::BadPassword);
        }

        Ok(DefaultUser {})
    }
}

fn is_usable_ipv4_address(ip: Ipv4Addr) -> bool {
    if ip.is_loopback() {
        return false;
    }
    let octets = ip.octets();
    if octets[0] == 169 && octets[1] == 254 {
        return false;
    }
    true
}

fn validate_config(config: &FtpServerConfig) -> Result<(), String> {
    if config.bind_host.trim().is_empty() {
        return Err("Bind host is required (use 0.0.0.0 for all interfaces)".to_string());
    }
    if config.port == 0 {
        return Err("Port must be between 1 and 65535".to_string());
    }
    if config.root_dir.trim().is_empty() {
        return Err("Root directory is required".to_string());
    }
    if !config.allow_anonymous {
        if config.username.trim().is_empty() {
            return Err("Username is required (or enable anonymous)".to_string());
        }
        if config.password.is_empty() {
            return Err("Password is required (or enable anonymous)".to_string());
        }
    }
    if config.passive_port_start == 0
        || config.passive_port_end == 0
        || config.passive_port_start > config.passive_port_end
    {
        return Err("Passive port range is invalid".to_string());
    }
    Ok(())
}

fn passive_range(config: &FtpServerConfig) -> RangeInclusive<u16> {
    config.passive_port_start..=config.passive_port_end
}

fn status_from_config(config: &FtpServerConfig) -> FtpServerStatus {
    FtpServerStatus {
        running: true,
        bind_addr: Some(format!("{}:{}", config.bind_host.trim(), config.port)),
        root_dir: Some(config.root_dir.clone()),
        username: if config.allow_anonymous {
            None
        } else {
            Some(config.username.clone())
        },
        allow_anonymous: config.allow_anonymous,
        passive_port_start: Some(config.passive_port_start),
        passive_port_end: Some(config.passive_port_end),
        passive_host: config
            .passive_host
            .as_ref()
            .map(|host| host.trim().to_string())
            .filter(|host| !host.is_empty()),
        enable_active_mode: config.enable_active_mode,
    }
}

fn stopped_status() -> FtpServerStatus {
    FtpServerStatus {
        running: false,
        bind_addr: None,
        root_dir: None,
        username: None,
        allow_anonymous: false,
        passive_port_start: None,
        passive_port_end: None,
        passive_host: None,
        enable_active_mode: false,
    }
}

#[tauri::command]
pub fn get_local_ipv4_addresses() -> Result<Vec<String>, String> {
    let interfaces =
        get_if_addrs::get_if_addrs().map_err(|e| format!("Failed to enumerate interfaces: {e}"))?;
    let mut ips = Vec::new();
    for iface in interfaces {
        let get_if_addrs::IfAddr::V4(v4) = iface.addr else {
            continue;
        };
        if !is_usable_ipv4_address(v4.ip) {
            continue;
        }
        ips.push(v4.ip.to_string());
    }
    ips.sort();
    ips.dedup();
    Ok(ips)
}

#[tauri::command]
pub async fn start_ftp_server(
    state: tauri::State<'_, FtpServerState>,
    config: FtpServerConfig,
) -> Result<FtpServerStatus, String> {
    validate_config(&config)?;

    let root_dir = PathBuf::from(config.root_dir.trim());
    std::fs::create_dir_all(&root_dir).map_err(|e| {
        format!(
            "Failed to create root directory {}: {e}",
            root_dir.display()
        )
    })?;

    let mut guard = state
        .inner
        .lock()
        .map_err(|_| "FTP server state lock poisoned".to_string())?;
    if let Some(running) = guard.as_ref() {
        if !running.task.is_finished() {
            return Err("FTP server is already running".to_string());
        }
        *guard = None;
    }

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let bind_addr = format!("{}:{}", config.bind_host.trim(), config.port);
    let passive_range = passive_range(&config);

    let status = status_from_config(&config);

    let username = config.username.clone();
    let password = config.password.clone();
    let allow_anonymous = config.allow_anonymous;
    let passive_host = status.passive_host.clone();
    let enable_active_mode = config.enable_active_mode;

    let task: JoinHandle<Result<(), String>> = tokio::spawn(async move {
        let shutdown_future = async move {
            let _ = shutdown_rx.await;
            Shutdown::new().grace_period(Duration::from_secs(5))
        };

        let mut builder = Server::with_fs(root_dir)
            .passive_ports(passive_range)
            .shutdown_indicator(shutdown_future);

        if let Some(host) = passive_host {
            builder = builder.passive_host(host.as_str());
        }

        if enable_active_mode {
            builder = builder.active_passive_mode(ActivePassiveMode::ActiveAndPassive);
        }

        if allow_anonymous {
            builder = builder.authenticator(std::sync::Arc::new(
                libunftp::auth::AnonymousAuthenticator {},
            ));
        } else {
            builder = builder.authenticator(std::sync::Arc::new(SingleUserAuthenticator {
                username,
                password,
            }));
        }

        let server = builder
            .build()
            .map_err(|e| format!("Failed to build FTP server: {e}"))?;

        server
            .listen(bind_addr.as_str())
            .await
            .map_err(|e| format!("FTP server listen failed: {e}"))?;

        Ok(())
    });

    *guard = Some(RunningFtpServer {
        status: status.clone(),
        shutdown_tx,
        task,
    });

    Ok(status)
}

#[tauri::command]
pub async fn stop_ftp_server(state: tauri::State<'_, FtpServerState>) -> Result<(), String> {
    let running = {
        let mut guard = state
            .inner
            .lock()
            .map_err(|_| "FTP server state lock poisoned".to_string())?;
        guard.take()
    };

    let Some(running) = running else {
        return Ok(());
    };

    let _ = running.shutdown_tx.send(());
    match tokio::time::timeout(Duration::from_secs(6), running.task).await {
        Ok(Ok(Err(e))) => Err(e),
        Ok(Err(e)) => Err(format!("FTP server task join failed: {e}")),
        Ok(Ok(Ok(()))) | Err(_) => Ok(()),
    }
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
pub fn get_ftp_server_status(
    state: tauri::State<'_, FtpServerState>,
) -> Result<FtpServerStatus, String> {
    let mut guard = state
        .inner
        .lock()
        .map_err(|_| "FTP server state lock poisoned".to_string())?;

    if let Some(running) = guard.as_ref() {
        if running.task.is_finished() {
            *guard = None;
            return Ok(stopped_status());
        }
        return Ok(running.status.clone());
    }

    Ok(stopped_status())
}
