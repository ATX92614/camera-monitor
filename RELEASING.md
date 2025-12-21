# Releasing & Auto-Updates (Tauri + GitHub Releases)

This app uses **Tauri v2’s updater plugin** to provide signed, in-app updates.

At a high level:

1. A GitHub Action builds installers and **update artifacts** for a tagged version.
2. The action signs the update artifacts using our **private signing key**.
3. The action publishes a GitHub Release and uploads:
   - the installers (NSIS `.exe`, WiX `.msi`)
   - the signature files (`.sig`)
   - a `latest.json` update manifest
4. The app checks `latest.json`, verifies the signature, downloads, and installs.

---

## Where Things Live

- **Updater endpoint (what the app checks):**
  - `https://github.com/ATX92614/camera-monitor/releases/latest/download/latest.json`
  - Configured in `src-tauri/tauri.conf.json` under `plugins.updater.endpoints`.

- **Updater keys:**
  - Public key is embedded in the app config (`src-tauri/tauri.conf.json` → `plugins.updater.pubkey`).
  - Private key must remain secret and is stored in GitHub Actions secrets.

- **Release workflow:**
  - `.github/workflows/release.yml`
  - Triggers on tags matching `v*` (example: `v0.1.2`).

---

## One-Time Setup (Already Done)

### 1) Create signing keys (one time)

On a trusted machine:

```powershell
cd camera-monitor\\src-tauri
mkdir keys
cargo tauri signer generate -w keys\\updater.key
```

- `keys/updater.key` is the **private key** (never commit it).
- `keys/updater.key.pub` is the **public key** (safe to embed in the app).

> Important: If the private key is lost, you can’t ship valid updates to existing installs.

### 2) Configure GitHub Actions secrets (one time)

GitHub repo → **Settings** → **Secrets and variables** → **Actions**:

- `TAURI_SIGNING_PRIVATE_KEY` = contents of `keys/updater.key`
- `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` = password used for the key (if any)

---

## Release Checklist (When a New Version Is Ready)

### Step 1: Update version numbers

Keep these in sync:

- `src-tauri/Cargo.toml` → `[package].version`
- `src-tauri/tauri.conf.json` → `version`

Example: set both to `0.1.3`.

### Step 2: Commit the version bump

```powershell
git add src-tauri/Cargo.toml src-tauri/tauri.conf.json
git commit -m "chore(release): v0.1.3"
git push
```

### Step 3: Create and push a tag

The workflow triggers on tags that start with `v`.

```powershell
git tag v0.1.3
git push origin v0.1.3
```

### Step 4: Verify the GitHub Action succeeded

On GitHub: **Actions** → `release` workflow.

It should publish a GitHub Release containing:

- `..._x64-setup.exe` (NSIS installer)
- `..._x64_en-US.msi` (WiX installer)
- `.sig` files for the installers
- `latest.json`

### Step 5: Verify the updater feed

Open in a browser:

`https://github.com/ATX92614/camera-monitor/releases/latest/download/latest.json`

Confirm:

- `"version"` matches the release (e.g. `0.1.3`)
- `platforms.windows-x86_64.url` points to the correct Release asset
- `platforms.windows-x86_64.signature` is present

### Step 6: Test an update end-to-end

1. Install the previous version (e.g. `0.1.2`).
2. Ensure the new Release exists (e.g. `0.1.3`).
3. Launch the app and click the **Updates** button.
4. Confirm it detects `0.1.3`, downloads, installs, and restarts.

---

## How the App Decides There’s an Update

- The app reads the `latest.json` manifest.
- If `latest.json.version` is newer than the installed version, the updater will:
  1. download the installer
  2. verify the signature (using the embedded public key)
  3. run the installer (Windows install mode is configured as **passive**)
  4. restart the app

---

## Common Failure Modes

- **Workflow fails immediately at “Build and Release”:**
  - Usually a misconfigured action version or invalid input name in `.github/workflows/release.yml`.

- **Build works but updater signatures are missing:**
  - Ensure `bundle.createUpdaterArtifacts` is enabled in `src-tauri/tauri.conf.json`.
  - Ensure GitHub secrets are set (`TAURI_SIGNING_PRIVATE_KEY` and password if used).

- **App says “Update check failed”:**
  - Verify `latest.json` is accessible publicly.
  - Verify `plugins.updater.endpoints` points to the correct URL.

- **App sees update but install fails:**
  - The downloaded installer must match the signature in `latest.json`.
  - Check the Release asset names and the manifest URLs.

---

## Security Notes / Key Rotation

- The updater’s **public key** is baked into the shipped app.
- Changing the public key later will break updates for existing installs unless you ship a special transition update.
- Treat the private key like a production secret. Restrict who can access it.

