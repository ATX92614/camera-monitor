# FTP Server Feature (Design Notes)

## Goal

Add an **embedded FTP server** to the Camera Alarm Monitor desktop app so Bosch cameras (or other devices) can upload files (snapshots/clips/logs) directly to the PC running the app.

This is intended for **local/LAN usage** (e.g. camera -> operator PC) to simplify "upload destination" setup.

---

## What "Minimum Viable" Looks Like

### User-facing requirements (minimum)

To run an FTP server that a camera can upload to, you typically need:

1. **Listen port**
   - Default recommendation: **2121** (not 21) to avoid admin/privilege and existing-service conflicts on Windows.
2. **Root directory (storage path)**
   - Required. All uploaded files land under this folder.
   - Default recommendation:
     - `%USERPROFILE%\\Documents\\Camera Alarm Monitor\\Uploads`
3. **Authentication**
   - Minimum: **username + password** (recommended).
   - Optional: allow **anonymous** mode for quick lab setups (less secure).
4. **Passive mode settings**
   - Many cameras/clients use **PASV/EPSV** (passive mode).
   - Minimum for a reliable LAN experience:
     - a **passive port range** (ex: `50000..=50100`) so firewall rules are manageable.
     - a **passive host** (the IP the server advertises back to the client). On a single LAN this can be the PC's LAN IP.

### Network requirements (minimum)

- The PC firewall must allow inbound connections:
  - the **control port** (e.g. `2121/TCP`)
  - the **passive port range** (e.g. `50000-50100/TCP`)
- If the camera and PC are on the same subnet and there is no NAT, this is usually straightforward.

> Note: FTP is plaintext (credentials and data). If this must be secure, consider FTPS if the camera supports it.

---

## Active vs Passive FTP (How to Choose)

FTP uses a control connection plus separate data connections. "Active vs passive" is about **who initiates the data connection**.

- **Passive mode (PASV/EPSV)**: the **camera (client)** opens the data connection to the **server**.
  - Recommended for most real-world LAN/NAT/firewall setups.
  - Requires the server to have a configured **passive port range** and (sometimes) an **advertised IP**.
- **Active mode (PORT)**: the **server** opens the data connection back to the **camera (client)**.
  - Often fails when the camera is behind NAT/firewall or does not accept inbound connections.

For this app's use-case (camera uploads to a PC running the embedded FTP server), the SOTA default is:

- Configure the camera to use **Passive** mode (if the camera offers a choice).
- Configure the app's FTP server with an explicit passive port range and open those ports in Windows Firewall.

Bosch ATSL note: `ATSL_6.32__Special_all_23843870091.pdf` references "FTP Posting", but does not document PASV/EPSV or how to choose active vs passive mode.

---

## Recommended Rust Implementation (Backend)

### Server library

Use:

- `libunftp` (FTP/FTPS server framework)
- `unftp-sbe-fs` (filesystem storage backend)

Why this choice:

- Mature async server, integrates cleanly with Tokio (Tauri uses Tokio already).
- Supports passive port configuration and shutdown signaling.
- Supports explicit FTPS later if needed.

### App backend architecture

Add a new "service" in `src-tauri/src/main.rs` (or a dedicated module later) with:

- **State**
  - `running: bool`
  - `bind_addr: String` (ex: `"0.0.0.0:2121"`)
  - `root_dir: PathBuf`
  - `shutdown_tx` (channel to signal stop)
  - `server_task: JoinHandle<()>`
- **Tauri commands**
  - `start_ftp_server(config)`
  - `stop_ftp_server()`
  - (optional) `get_ftp_status()`

### Shutdown/stop behavior (important)

`libunftp` supports a "shutdown indicator" future (`shutdown_indicator(...)`) which is ideal for a GUI app:

- When user clicks **Stop**, send a message to the shutdown channel.
- Server exits gracefully after a configured grace period.

### Authentication options

1. **Single-user (recommended minimal)**
   - Implement `libunftp::auth::Authenticator` that accepts only one configured username/password.
2. **Anonymous mode (optional toggle)**
   - Use `libunftp::auth::AnonymousAuthenticator`
   - Warn users that uploads are open to anyone on the LAN.

### File destination behavior

Start simple:

- The "root directory" is the FTP home.
- Allow clients to create folders under it (optional).

Later improvements (nice-to-have):

- Auto-create per-camera folders (by IP, hostname, or username).
- Add a small file index in the UI (latest uploads, timestamps).

---

## UI Integration (Recommended)

Add a new section labeled **FTP Upload Server** with:

### Configuration fields

- `Port` (default 2121)
- `Root folder` (text field + "Open folder" button)
- `Username`
- `Password`
- `Passive ports` (start/end)
- `Advertised IP` (auto-detected LAN IP + dropdown if multiple NICs)
- `Mode`:
  - `Require login` (default)
  - `Anonymous (no login)` (optional)

### Actions / status

- Button: **Start Server** / **Stop Server**
- Status text:
  - `Stopped`
  - `Running on 192.168.0.10:2121`
  - `Error: Port already in use`

### UX convenience (high value)

Show a "copy/paste block" that matches typical camera FTP config:

- Host: `PC_IP`
- Port: `2121`
- Username: `...`
- Password: `...`
- Remote dir: `/` (or a suggested folder)

Buttons:

- `Copy settings`
- `Open uploads folder`

---

## Storage of Settings (SOTA guidance)

Settings you can store plainly:

- root folder path, port, passive port range, anonymous toggle, advertised IP choice.

Secrets (username/password):

Options (best -> simplest):

1. **OS keychain / encrypted store (best)**
   - Use a secure storage plugin (e.g. Stronghold/keyring) so secrets aren't stored as plaintext on disk.
2. **Hash the password (good compromise)**
   - Store only a password hash (Argon2). The user can set/reset it, but the app never stores the plaintext password.
3. **Plaintext local config (simplest, least secure)**
   - Only acceptable for controlled lab/internal environments; document the risk clearly.

---

## Security / Scope Notes

- FTP is plaintext; on untrusted networks it is not acceptable.
- For production-grade security, evaluate:
  - **FTPS (Explicit TLS)** if camera supports it.
  - Or a different transport (SFTP) if supported by the camera (often not).

---

## Open Questions (Need answers before implementing)

1. Is the intent **server** (camera uploads to the PC) or **client** (app uploads to another FTP server)?
2. Do Bosch cameras in your environment require:
   - Passive mode only?
   - Active mode support?
   - FTPS?
3. Do you need the app to **auto-configure** camera FTP settings via RCP, or just provide the server + instructions?
4. Do uploads need to be organized per camera / per event type?
