#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

mod ftp_server;

use reqwest::header::{HeaderValue, AUTHORIZATION, WWW_AUTHENTICATE};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error as _;
use std::hash::{Hash, Hasher};
use std::net::Ipv4Addr;
use std::sync::Mutex;
use std::time::Duration;
use tauri_plugin_updater::{Update, UpdaterExt};
use tokio::net::UdpSocket;

use ftp_server::{
    get_ftp_server_status, get_local_ipv4_addresses, start_ftp_server, stop_ftp_server,
    FtpServerState,
};

#[derive(Debug, Serialize, Deserialize)]
pub struct AlarmStatus {
    pub num: u8,
    pub status: String, // "off", "on", "error", "unknown"
    pub hex_value: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AllAlarmsStatus {
    pub alarms: Vec<AlarmStatus>,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IoLayout {
    pub inputs: Vec<u16>,
    pub relays: Vec<u16>,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IoPointStatus {
    pub id: u16,
    pub status: String, // "off", "on", "error", "unknown"
    pub hex_value: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IoStatusSnapshot {
    pub inputs: Vec<IoPointStatus>,
    pub relays: Vec<IoPointStatus>,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DiscoveredDevice {
    pub ip: String,
    pub mac: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AppUpdateInfo {
    pub current_version: String,
    pub available_version: String,
    pub date: Option<String>,
    pub notes: Option<String>,
}

struct AppState {
    clients: Mutex<HashMap<ClientKey, reqwest::Client>>,
    pending_update: Mutex<Option<Update>>,
}

#[derive(Clone, Hash, Eq, PartialEq)]
struct ClientKey {
    host: String,
    username: String,
    password_fingerprint: u64,
}

fn normalize_host(raw_host: &str) -> Result<String, String> {
    let trimmed = raw_host.trim();
    if trimmed.is_empty() {
        return Err("Host is required".to_string());
    }

    // Accept either a plain hostname/IP (e.g. `192.168.1.100`) or a full URL
    // (e.g. `https://192.168.1.100:443/rcp.xml`). We always connect using
    // `https://<host>:443/...` regardless of the input scheme/port.
    let candidate = if trimmed.contains("://") {
        trimmed.to_string()
    } else {
        format!("https://{trimmed}")
    };

    let parsed = Url::parse(&candidate).map_err(|e| format!("Invalid host: {e}"))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| "Invalid host: missing hostname/IP".to_string())?;
    Ok(host.to_string())
}

fn password_fingerprint(password: &str) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    password.hash(&mut hasher);
    hasher.finish()
}

fn get_or_create_client(
    state: &tauri::State<'_, AppState>,
    host: &str,
    username: &str,
    password: &str,
) -> Result<reqwest::Client, String> {
    let key = ClientKey {
        host: host.to_string(),
        username: username.to_string(),
        password_fingerprint: password_fingerprint(password),
    };

    let mut clients = state
        .clients
        .lock()
        .map_err(|_| "HTTP client cache lock poisoned".to_string())?;

    if let Some(client) = clients.get(&key) {
        return Ok(client.clone());
    }

    let client = build_http_client()?;
    clients.insert(key, client.clone());
    Ok(client)
}

fn format_reqwest_error(context: &str, error: &reqwest::Error) -> String {
    let mut details = vec![format!("{context}: {error}")];
    details.push(format!("is_timeout={}", error.is_timeout()));
    details.push(format!("is_connect={}", error.is_connect()));
    if let Some(status) = error.status() {
        details.push(format!("status={status}"));
    }
    if let Some(url) = error.url() {
        details.push(format!("url={url}"));
    }

    let mut depth = 0usize;
    let mut source = error.source();
    while let Some(cause) = source {
        depth += 1;
        details.push(format!("cause[{depth}]={cause}"));
        source = cause.source();
    }

    details.join(" | ")
}

fn build_http_client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .http1_only()
        .timeout(Duration::from_secs(10))
        .danger_accept_invalid_certs(true) // Accept self-signed certs
        .cookie_store(true)
        .pool_idle_timeout(Duration::from_secs(30))
        .tcp_keepalive(Duration::from_secs(30))
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {e}"))
}

fn is_usable_ipv4_address(ip: Ipv4Addr) -> bool {
    // Skip loopback and link-local (APIPA), which are not useful for device discovery.
    if ip.is_loopback() {
        return false;
    }
    let octets = ip.octets();
    if octets[0] == 169 && octets[1] == 254 {
        return false;
    }
    true
}

fn ipv4_broadcast(ip: Ipv4Addr, netmask: Ipv4Addr) -> Ipv4Addr {
    let ip_u32 = u32::from(ip);
    let mask_u32 = u32::from(netmask);
    Ipv4Addr::from(ip_u32 | !mask_u32)
}

fn format_mac(mac: &[u8]) -> String {
    let [b0, b1, b2, b3, b4, b5] = mac else {
        return "00-00-00-00-00-00".to_string();
    };

    format!("{b0:02X}-{b1:02X}-{b2:02X}-{b3:02X}-{b4:02X}-{b5:02X}")
}

fn build_autodetect_request(sequence_number: u32, reply_port: u16) -> [u8; 12] {
    let mut bytes = [0_u8; 12];
    bytes[0..4].copy_from_slice(&[0x99, 0x39, 0xA4, 0x27]);
    bytes[4..8].copy_from_slice(&sequence_number.to_be_bytes());
    bytes[8..10].copy_from_slice(&[0x00, 0x00]);
    bytes[10..12].copy_from_slice(&reply_port.to_be_bytes());
    bytes
}

fn parse_autodetect_reply(
    payload: &[u8],
    expected_sequence_number: u32,
) -> Option<DiscoveredDevice> {
    // Bosch autodetect reply packet (first reply) is at least 32 bytes:
    // magic[4], seq[4], mac[6], type[1], id[1], ip[4], mask[4], gw[4], ...
    if payload.len() < 32 {
        return None;
    }

    if payload[0..4] != [0x99, 0x39, 0xA4, 0x27] {
        return None;
    }

    let seq = u32::from_be_bytes(payload[4..8].try_into().ok()?);
    if seq != expected_sequence_number {
        return None;
    }

    let mac = format_mac(&payload[8..14]);

    // See "1st Reply Packet" in the RCP manual: device IPv4 starts at offset 16.
    let ip = Ipv4Addr::new(payload[16], payload[17], payload[18], payload[19]).to_string();

    Some(DiscoveredDevice { ip, mac })
}

#[tauri::command]
async fn discover_devices(timeout_ms: Option<u64>) -> Result<Vec<DiscoveredDevice>, String> {
    // Manual: devices respond with a random delay up to 2 seconds. Give some extra headroom.
    let timeout = Duration::from_millis(timeout_ms.unwrap_or(3000)).max(Duration::from_millis(500));

    // Bind an ephemeral UDP port and ask devices to reply back to it (via the Reply Port field).
    // This avoids port conflicts with other tools (e.g. Bosch Configuration Manager).
    let socket = UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|e| format!("Failed to bind UDP socket: {e}"))?;
    socket
        .set_broadcast(true)
        .map_err(|e| format!("Failed to enable UDP broadcast: {e}"))?;

    let local_addr = socket
        .local_addr()
        .map_err(|e| format!("Failed to read UDP local address: {e}"))?;
    let reply_port = local_addr.port();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| format!("System time error: {e}"))?;
    let seed = now.as_nanos() ^ (u128::from(now.as_secs()) << 32);
    let mixed = seed.wrapping_mul(2_654_435_761u128);
    let masked = mixed & u128::from(u32::MAX);
    let sequence_number =
        u32::try_from(masked).map_err(|e| format!("Failed to create sequence number: {e}"))?;
    let request = build_autodetect_request(sequence_number, reply_port);

    // Manual: send scan request to UDP port 1757 (static) or configurable discover port (default 1800).
    //
    // In practice, some networks/devices do not respond to limited broadcast (255.255.255.255) on Windows,
    // while they do respond to the subnet-directed broadcast (e.g. 192.168.0.255). So we send to both.
    let mut broadcast_addrs: Vec<Ipv4Addr> = vec![Ipv4Addr::BROADCAST];
    if let Ok(ifaces) = get_if_addrs::get_if_addrs() {
        for iface in ifaces {
            let get_if_addrs::IfAddr::V4(v4) = iface.addr else {
                continue;
            };
            if !is_usable_ipv4_address(v4.ip) {
                continue;
            }
            broadcast_addrs.push(ipv4_broadcast(v4.ip, v4.netmask));
        }
    } else {
        // If interface enumeration fails, we still try the limited broadcast.
    }
    broadcast_addrs.sort();
    broadcast_addrs.dedup();

    let mut destinations: Vec<String> = Vec::new();
    for bcast in broadcast_addrs {
        destinations.push(format!("{bcast}:1757"));
        destinations.push(format!("{bcast}:1800"));
    }
    for dest in destinations {
        socket
            .send_to(&request, dest.as_str())
            .await
            .map_err(|e| format!("Failed to send autodetect request to {dest}: {e}"))?;
    }

    let deadline = tokio::time::Instant::now() + timeout;
    let mut buf = vec![0_u8; 2048];
    let mut devices_by_mac: HashMap<String, DiscoveredDevice> = HashMap::new();

    loop {
        let now = tokio::time::Instant::now();
        if now >= deadline {
            break;
        }
        let remaining = deadline - now;

        match tokio::time::timeout(remaining, socket.recv_from(&mut buf)).await {
            Ok(Ok((len, _addr))) => {
                let payload = &buf[..len];
                if let Some(device) = parse_autodetect_reply(payload, sequence_number) {
                    devices_by_mac.insert(device.mac.clone(), device);
                }
            }
            Ok(Err(e)) => return Err(format!("Failed to receive autodetect reply: {e}")),
            Err(_) => break,
        }
    }

    let mut devices: Vec<DiscoveredDevice> = devices_by_mac.into_values().collect();
    devices.sort_by(|a, b| a.ip.cmp(&b.ip));
    Ok(devices)
}

async fn make_authenticated_request(
    client: &reqwest::Client,
    url: &str,
    username: &str,
    password: &str,
    request_timeout: Duration,
) -> Result<(String, u16), String> {
    // First request to get the WWW-Authenticate challenge
    let response = client
        .get(url)
        .timeout(request_timeout)
        .send()
        .await
        .map_err(|e| format_reqwest_error("Request failed", &e))?;

    if response.status() == 401 {
        // Get the WWW-Authenticate header for digest auth
        let Some(www_auth) = response.headers().get(WWW_AUTHENTICATE) else {
            return Err("401 but no WWW-Authenticate header".to_string());
        };

        let www_auth_str = www_auth
            .to_str()
            .map_err(|e| format!("Invalid WWW-Authenticate header: {e}"))?;

        // Parse the URI from the URL for digest auth
        let uri_start = url.find("/rcp.xml").unwrap_or(0);
        let uri = &url[uri_start..];

        // Parse the digest challenge
        let context = digest_auth::AuthContext::new(username, password, uri);

        let mut prompt = digest_auth::parse(www_auth_str)
            .map_err(|e| format!("Failed to parse digest challenge: {e:?}"))?;

        // Generate the authorization response
        let auth_header = prompt
            .respond(&context)
            .map_err(|e| format!("Failed to create digest response: {e:?}"))?
            .to_header_string();

        // Make the authenticated request
        let auth_response = client
            .get(url)
            .timeout(request_timeout)
            .header(
                AUTHORIZATION,
                HeaderValue::from_str(&auth_header)
                    .map_err(|e| format!("Invalid auth header: {e}"))?,
            )
            .send()
            .await
            .map_err(|e| format_reqwest_error("Authenticated request failed", &e))?;

        let status_code = auth_response.status().as_u16();
        let text = auth_response
            .text()
            .await
            .map_err(|e| format!("Failed to read response: {e}"))?;

        return Ok((text, status_code));
    }

    // If we got here without 401, return the response directly
    let status_code = response.status().as_u16();
    let text = response
        .text()
        .await
        .map_err(|e| format!("Failed to read response: {e}"))?;

    Ok((text, status_code))
}

#[tauri::command]
async fn poll_all_alarms(
    state: tauri::State<'_, AppState>,
    host: String,
    username: String,
    password: String,
) -> Result<AllAlarmsStatus, String> {
    let host = normalize_host(&host)?;
    let client = get_or_create_client(&state, &host, &username, &password)?;

    let mut alarms = Vec::new();
    let mut global_error: Option<String> = None;

    for num in 1..=16 {
        let url = format!(
            "https://{host}:443/rcp.xml?command=0x0a8b&type=F_FLAG&direction=READ&num={num}"
        );

        match make_authenticated_request(
            &client,
            &url,
            &username,
            &password,
            Duration::from_secs(10),
        )
        .await
        {
            Ok((text, status_code)) => {
                if status_code == 401 {
                    global_error =
                        Some("Authentication failed (401). Check credentials.".to_string());
                    alarms.push(AlarmStatus {
                        num,
                        status: "error".to_string(),
                        hex_value: "N/A".to_string(),
                    });
                } else if let Some(hex_value) = parse_result_hex(&text) {
                    let status = if hex_value == "0x00" {
                        "off"
                    } else if hex_value == "0x01" {
                        "on"
                    } else {
                        "unknown"
                    };
                    alarms.push(AlarmStatus {
                        num,
                        status: status.to_string(),
                        hex_value,
                    });
                } else {
                    alarms.push(AlarmStatus {
                        num,
                        status: "unknown".to_string(),
                        hex_value: "N/A".to_string(),
                    });
                }
            }
            Err(e) => {
                if global_error.is_none() {
                    global_error = Some(e);
                }
                alarms.push(AlarmStatus {
                    num,
                    status: "error".to_string(),
                    hex_value: "N/A".to_string(),
                });
            }
        }
    }

    Ok(AllAlarmsStatus {
        alarms,
        error: global_error,
    })
}

#[tauri::command]
async fn set_alarm(
    state: tauri::State<'_, AppState>,
    host: String,
    username: String,
    password: String,
    num: u8,
    turn_on: bool,
) -> Result<String, String> {
    let payload = if turn_on { "1" } else { "0" };
    let host = normalize_host(&host)?;
    let url = format!(
        "https://{host}:443/rcp.xml?command=0x0a8b&type=F_FLAG&direction=WRITE&num={num}&payload={payload}"
    );

    let client = get_or_create_client(&state, &host, &username, &password)?;

    let (text, status_code) =
        make_authenticated_request(&client, &url, &username, &password, Duration::from_secs(5))
            .await?;

    if status_code == 200 {
        let state = if turn_on { "ON" } else { "OFF" };
        Ok(format!("Alarm {num} set to {state}"))
    } else {
        Err(format!(
            "Failed to set alarm {num} (HTTP {status_code}): {text}"
        ))
    }
}

#[tauri::command]
async fn check_for_update(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<Option<AppUpdateInfo>, String> {
    let updater = app
        .updater()
        .map_err(|e| format!("Updater is not available: {e}"))?;

    let update = updater
        .check()
        .await
        .map_err(|e| format!("Update check failed: {e}"))?;

    let mut pending = state
        .pending_update
        .lock()
        .map_err(|_| "Updater cache lock poisoned".to_string())?;

    if let Some(update) = update {
        let info = AppUpdateInfo {
            current_version: app.package_info().version.to_string(),
            available_version: update.version.clone(),
            date: update.date.map(|date| date.to_string()),
            notes: update.body.clone(),
        };
        *pending = Some(update);
        Ok(Some(info))
    } else {
        *pending = None;
        Ok(None)
    }
}

#[tauri::command]
async fn install_update(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    let update = {
        let mut pending = state
            .pending_update
            .lock()
            .map_err(|_| "Updater cache lock poisoned".to_string())?;
        pending.take()
    };

    let update = if let Some(update) = update {
        update
    } else {
        let updater = app
            .updater()
            .map_err(|e| format!("Updater is not available: {e}"))?;
        updater
            .check()
            .await
            .map_err(|e| format!("Update check failed: {e}"))?
            .ok_or_else(|| "No update available.".to_string())?
    };

    update
        .download_and_install(|_chunk_length, _content_length| {}, || {})
        .await
        .map_err(|e| format!("Failed to install update: {e}"))?;

    // Some platforms require a restart. On Windows the installer may close the app.
    app.restart()
}

fn parse_result_hex(xml: &str) -> Option<String> {
    // Method 1: Look for <result><hex>value</hex>
    if let Some(result_start) = xml.find("<result>") {
        if let Some(result_end) = xml[result_start..].find("</result>") {
            let result_section = &xml[result_start..result_start + result_end];

            if let Some(hex_start) = result_section.find("<hex>") {
                let hex_content_start = hex_start + 5;
                if let Some(hex_end) = result_section[hex_content_start..].find("</hex>") {
                    let hex_value =
                        result_section[hex_content_start..hex_content_start + hex_end].trim();
                    return Some(hex_value.to_string());
                }
            }
        }
    }

    // Method 2: Look for hex pattern after "result"
    if let Some(result_idx) = xml.to_lowercase().find("result") {
        let after_result = &xml[result_idx..];
        for (i, _) in after_result.char_indices() {
            if after_result[i..].starts_with("0x") {
                let hex_start = i;
                let mut hex_end = hex_start + 2;
                while hex_end < after_result.len() {
                    let c = after_result.chars().nth(hex_end).unwrap_or(' ');
                    if c.is_ascii_hexdigit() {
                        hex_end += 1;
                    } else {
                        break;
                    }
                }
                if hex_end > hex_start + 2 {
                    return Some(after_result[hex_start..hex_end].to_string());
                }
            }
        }
    }

    None
}

fn parse_result_hex_or_str(xml: &str) -> Option<String> {
    if let Some(hex) = parse_result_hex(xml) {
        return Some(hex);
    }

    // Some commands (notably CONF_CAPABILITY_LIST / 0xff10) return their payload in <str>
    // as space-separated bytes, not in <hex>.
    if let Some(result_start) = xml.find("<result>") {
        if let Some(result_end) = xml[result_start..].find("</result>") {
            let result_section = &xml[result_start..result_start + result_end];

            if let Some(str_start) = result_section.find("<str>") {
                let str_content_start = str_start + 5;
                if let Some(str_end) = result_section[str_content_start..].find("</str>") {
                    let str_value =
                        result_section[str_content_start..str_content_start + str_end].trim();
                    if !str_value.is_empty() {
                        return Some(str_value.to_string());
                    }
                }
            }
        }
    }

    None
}

fn parse_hex_bytes(raw_hex: &str) -> Result<Vec<u8>, String> {
    let trimmed = raw_hex.trim();
    let without_prefix = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);

    let mut hex_digits = String::with_capacity(without_prefix.len());
    for ch in without_prefix.chars() {
        if ch.is_ascii_hexdigit() {
            hex_digits.push(ch);
        }
    }

    if hex_digits.is_empty() {
        return Err("Hex payload contains no hex digits".to_string());
    }

    if !hex_digits.len().is_multiple_of(2) {
        return Err(format!("Hex payload has odd length: {}", hex_digits.len()));
    }

    let mut out = Vec::with_capacity(hex_digits.len() / 2);
    for chunk in hex_digits.as_bytes().chunks(2) {
        let s = std::str::from_utf8(chunk).map_err(|e| format!("Invalid hex chunk: {e}"))?;
        let byte = u8::from_str_radix(s, 16).map_err(|e| format!("Invalid hex byte '{s}': {e}"))?;
        out.push(byte);
    }

    Ok(out)
}

fn parse_capability_list_io_ids(payload: &[u8]) -> Result<(Vec<u16>, Vec<u16>), String> {
    const MAGIC: u16 = 0xBABA;
    const SECTION_TYPE_IO: u16 = 0x0004;
    const IO_INPUT: u16 = 0x0001;
    const IO_OUTPUT: u16 = 0x0002;

    let mut offset = 0usize;
    let read_u16 = |payload: &[u8], offset: &mut usize| -> Result<u16, String> {
        let start = *offset;
        let end = start + 2;
        let bytes = payload
            .get(start..end)
            .ok_or_else(|| "Capability list truncated".to_string())?;
        *offset = end;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    };

    let magic = read_u16(payload, &mut offset)?;
    if magic != MAGIC {
        return Err(format!("Unexpected capability list magic 0x{magic:04X}"));
    }

    let _version = read_u16(payload, &mut offset)?;
    let num_sections = read_u16(payload, &mut offset)? as usize;

    let mut inputs: Vec<u16> = Vec::new();
    let mut outputs: Vec<u16> = Vec::new();

    for _ in 0..num_sections {
        let section_start = offset;
        let section_type = read_u16(payload, &mut offset)?;
        let section_size = read_u16(payload, &mut offset)? as usize;
        let num_elements = read_u16(payload, &mut offset)? as usize;

        if section_size < 6 {
            return Err(format!("Invalid capability section size: {section_size}"));
        }
        let section_end = section_start
            .checked_add(section_size)
            .ok_or_else(|| "Capability section size overflow".to_string())?;
        if section_end > payload.len() {
            return Err("Capability section exceeds payload length".to_string());
        }

        if section_type == SECTION_TYPE_IO {
            let mut element_offset = offset;
            for _ in 0..num_elements {
                if element_offset + 4 > section_end {
                    break;
                }
                let element_type =
                    u16::from_be_bytes([payload[element_offset], payload[element_offset + 1]]);
                let identifier =
                    u16::from_be_bytes([payload[element_offset + 2], payload[element_offset + 3]]);
                match element_type {
                    IO_INPUT => inputs.push(identifier),
                    IO_OUTPUT => outputs.push(identifier),
                    _ => {}
                }
                element_offset += 4;
            }
        }

        offset = section_end;
    }

    inputs.sort_unstable();
    inputs.dedup();
    outputs.sort_unstable();
    outputs.dedup();

    Ok((inputs, outputs))
}

async fn poll_f_flag_points(
    client: &reqwest::Client,
    host: &str,
    username: &str,
    password: &str,
    command: &str,
    ids: Vec<u16>,
) -> (Vec<IoPointStatus>, Option<String>) {
    let mut points = Vec::new();
    let mut global_error: Option<String> = None;

    for id in ids {
        let url = format!(
            "https://{host}:443/rcp.xml?command={command}&type=F_FLAG&direction=READ&num={id}"
        );

        match make_authenticated_request(client, &url, username, password, Duration::from_secs(10))
            .await
        {
            Ok((text, status_code)) => {
                if status_code == 401 {
                    global_error =
                        Some("Authentication failed (401). Check credentials.".to_string());
                    points.push(IoPointStatus {
                        id,
                        status: "error".to_string(),
                        hex_value: "N/A".to_string(),
                    });
                    continue;
                }

                if let Some(hex_value) = parse_result_hex(&text) {
                    let status = if hex_value == "0x00" {
                        "off"
                    } else if hex_value == "0x01" {
                        "on"
                    } else {
                        "unknown"
                    };
                    points.push(IoPointStatus {
                        id,
                        status: status.to_string(),
                        hex_value,
                    });
                    continue;
                }

                points.push(IoPointStatus {
                    id,
                    status: "unknown".to_string(),
                    hex_value: "N/A".to_string(),
                });
            }
            Err(e) => {
                if global_error.is_none() {
                    global_error = Some(e);
                }
                points.push(IoPointStatus {
                    id,
                    status: "error".to_string(),
                    hex_value: "N/A".to_string(),
                });
            }
        }
    }

    (points, global_error)
}

#[tauri::command]
async fn get_io_layout(
    state: tauri::State<'_, AppState>,
    host: String,
    username: String,
    password: String,
) -> Result<IoLayout, String> {
    let host = normalize_host(&host)?;
    let client = get_or_create_client(&state, &host, &username, &password)?;

    let url = format!("https://{host}:443/rcp.xml?command=0xff10&type=P_OCTET&direction=READ");
    let (text, status_code) =
        make_authenticated_request(&client, &url, &username, &password, Duration::from_secs(10))
            .await?;

    if status_code == 401 {
        return Ok(IoLayout {
            inputs: Vec::new(),
            relays: Vec::new(),
            error: Some("Authentication failed (401). Check credentials.".to_string()),
        });
    }

    if status_code != 200 {
        return Ok(IoLayout {
            inputs: Vec::new(),
            relays: Vec::new(),
            error: Some(format!(
                "Failed to read capability list (HTTP {status_code})."
            )),
        });
    }

    let Some(hex_or_str) = parse_result_hex_or_str(&text) else {
        return Ok(IoLayout {
            inputs: Vec::new(),
            relays: Vec::new(),
            error: Some("No <hex> or <str> result found for capability list.".to_string()),
        });
    };

    let bytes = match parse_hex_bytes(&hex_or_str) {
        Ok(bytes) => bytes,
        Err(e) => {
            return Ok(IoLayout {
                inputs: Vec::new(),
                relays: Vec::new(),
                error: Some(format!("Failed to parse capability list hex: {e}")),
            });
        }
    };

    let (inputs, outputs) = match parse_capability_list_io_ids(&bytes) {
        Ok((inputs, outputs)) => (inputs, outputs),
        Err(e) => {
            return Ok(IoLayout {
                inputs: Vec::new(),
                relays: Vec::new(),
                error: Some(format!("Failed to parse capability list: {e}")),
            });
        }
    };

    Ok(IoLayout {
        inputs,
        relays: outputs,
        error: None,
    })
}

#[tauri::command]
async fn poll_io(
    state: tauri::State<'_, AppState>,
    host: String,
    username: String,
    password: String,
    input_ids: Vec<u16>,
    relay_ids: Vec<u16>,
) -> Result<IoStatusSnapshot, String> {
    let host = normalize_host(&host)?;
    let client = get_or_create_client(&state, &host, &username, &password)?;

    let (inputs, input_error) =
        poll_f_flag_points(&client, &host, &username, &password, "0x01c0", input_ids).await;
    let (relays, relay_error) =
        poll_f_flag_points(&client, &host, &username, &password, "0x01c1", relay_ids).await;
    let global_error = input_error.or(relay_error);

    Ok(IoStatusSnapshot {
        inputs,
        relays,
        error: global_error,
    })
}

#[tauri::command]
async fn set_relay_output(
    state: tauri::State<'_, AppState>,
    host: String,
    username: String,
    password: String,
    id: u16,
    turn_on: bool,
) -> Result<String, String> {
    let payload = if turn_on { "1" } else { "0" };
    let host = normalize_host(&host)?;
    let url = format!(
        "https://{host}:443/rcp.xml?command=0x01c1&type=F_FLAG&direction=WRITE&num={id}&payload={payload}"
    );

    let client = get_or_create_client(&state, &host, &username, &password)?;

    let (text, status_code) =
        make_authenticated_request(&client, &url, &username, &password, Duration::from_secs(5))
            .await?;

    if status_code == 200 {
        let state = if turn_on { "ON" } else { "OFF" };
        Ok(format!("Relay {id} set to {state}"))
    } else {
        Err(format!(
            "Failed to set relay {id} (HTTP {status_code}): {text}"
        ))
    }
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_dialog::init())
        .manage(AppState {
            clients: Mutex::new(HashMap::new()),
            pending_update: Mutex::new(None),
        })
        .manage(FtpServerState::default())
        .invoke_handler(tauri::generate_handler![
            poll_all_alarms,
            set_alarm,
            get_io_layout,
            poll_io,
            set_relay_output,
            discover_devices,
            get_local_ipv4_addresses,
            get_ftp_server_status,
            start_ftp_server,
            stop_ftp_server,
            check_for_update,
            install_update
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[cfg(test)]
mod tests {
    use super::{parse_capability_list_io_ids, parse_hex_bytes};

    #[test]
    fn parse_hex_bytes_accepts_optional_prefix() {
        assert_eq!(parse_hex_bytes("0x0A0b").unwrap(), vec![0x0A, 0x0B]);
        assert_eq!(parse_hex_bytes("0A0B").unwrap(), vec![0x0A, 0x0B]);
    }

    #[test]
    fn parse_hex_bytes_accepts_space_separated_bytes() {
        assert_eq!(
            parse_hex_bytes("ba ba 00 01").unwrap(),
            vec![0xBA, 0xBA, 0x00, 0x01]
        );
    }

    #[test]
    fn parse_capability_list_io_ids_extracts_io_section() {
        // Magic (0xBABA), Version (0x0001), Num Sections (0x0001)
        // Section: Type IO (0x0004), Size (6 + 3*4 = 18), Num Elements (3)
        // Elements: IO_INPUT id 1, IO_OUTPUT id 2, IO_OUTPUT id 3
        let payload = vec![
            0xBA, 0xBA, 0x00, 0x01, 0x00, 0x01, 0x00, 0x04, 0x00, 0x12, 0x00, 0x03, 0x00, 0x01,
            0x00, 0x01, 0x00, 0x02, 0x00, 0x02, 0x00, 0x02, 0x00, 0x03,
        ];

        let (inputs, outputs) = parse_capability_list_io_ids(&payload).unwrap();
        assert_eq!(inputs, vec![1]);
        assert_eq!(outputs, vec![2, 3]);
    }
}
