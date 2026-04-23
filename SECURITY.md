# Security

## Reporting vulnerabilities

If you discover a security issue, please email **webmaster@pascalpagel.de** instead of opening a public issue.

## OWASP review (v1.4.2)

Full review performed 2026-04-23 against OWASP Top 10 (2021).

### Fixed

#### CRITICAL — CSRF protection + DSM session gate
**OWASP A01 Broken Access Control**

The CGI gateway (`api.cgi`) now verifies the caller's DSM session before processing any request. State-changing endpoints additionally require a valid `SynoToken` (Synology's CSRF token). Read-only endpoints (status, thumbnails, downloads, log export) require only the session.

Previously, no authentication or CSRF check was performed at the API level — any request reaching the CGI was processed unconditionally.

**Files:** `app/api.cgi`, `app/iCloudPhotoSync.js`

#### CRITICAL — Rate limiting on authentication endpoints
**OWASP A07 Identification and Authentication Failures**

Login, 2FA verification, and SMS send endpoints are now rate-limited to 5 attempts per minute per key (Apple ID or account ID). State is persisted to disk so limits survive CGI process restarts.

Previously, no rate limiting existed — an attacker could brute-force 2FA codes (1,000,000 combinations for 6 digits) or passwords without restriction.

**Files:** `lib/handlers/auth.py`

#### HIGH — Session and cookie file permissions
**OWASP A02 Cryptographic Failures**

Session JSON files are now created with `0o600` (owner-only read/write) via `os.open()` with explicit mode. Cookie jar files are `chmod`-ed to `0o600` after each save. Previously, both inherited the process umask and could be world-readable, exposing `session_token`, `trust_token`, and auth cookies.

**Files:** `lib/vendor/pyicloud_ipd/session.py`

#### HIGH — Path traversal via iCloud filenames
**OWASP A03 Injection**

All filenames and folder names received from iCloud (`photo.filename`, `album.parent_folder`) are now sanitized via `_sanitize_path_component()` which strips `../`, `/`, `\`, null bytes, and control characters. Additionally, `_safe_join()` verifies the final resolved path stays inside the target directory — any escape attempt is blocked and logged.

Previously, a malicious iCloud response could write files outside the target directory.

**Files:** `lib/sync_engine.py`

#### MEDIUM — SSRF via thumbnail/download proxy
**OWASP A10 Server-Side Request Forgery**

URL validation in proxy endpoints now uses `urlparse()` to verify the hostname actually ends with `.icloud-content.com`. Previously, a substring check (`"icloud-content.com" in url`) allowed bypass via URLs like `https://evil.com/?x=icloud-content.com`.

**Files:** `app/api.cgi`

#### MEDIUM — Symlink following in file operations
**OWASP A01 Broken Access Control**

Directory creation now uses `_makedirs_safe()` which walks each path component and refuses to follow symlinks. Hardlink deduplication explicitly rejects symlink sources. Previously, `os.makedirs()` and `os.link()` would silently follow symlinks, allowing an attacker with filesystem access to redirect writes to arbitrary locations.

**Files:** `lib/sync_engine.py`

#### HIGH — Weak encryption for temporary 2FA passwords
**OWASP A02 Cryptographic Failures**

Temporary 2FA passwords are now encrypted with PBKDF2-derived keys (100,000 iterations, random 16-byte salt) and authenticated with HMAC-SHA256. The keystream uses counter-mode SHA-256 blocks derived from the encryption key. Tampered files are detected and rejected.

Previously, passwords were XOR-encrypted with a deterministic key (SHA-256 of machine-id + account-id, no salt, no iterations), making decryption trivial if the machine-id was known.

**Files:** `lib/config_manager.py`

### Open — accepted risks

| # | Finding | Severity | OWASP | Status |
|---|---------|----------|-------|--------|
| 8 | No HTTPS enforcement at application level | MEDIUM | A02 | **Accepted** — responsibility of DSM reverse proxy config |
| 9 | TOCTOU in dedup/conflict resolution | MEDIUM | A01 | **Accepted** — per-account flock reduces window, impractical to exploit |

### Not vulnerable

| Area | OWASP | Notes |
|------|-------|-------|
| SQL injection | A03 | Parameterized queries throughout (`sync_manifest.py`) |
| Command injection | A03 | All subprocess calls use list args, no `shell=True` |
| Log injection | A09 | Python `%`-formatting, plus `PyiCloudPasswordFilter` strips passwords |
| Log export privacy | A01 | Aggressive redaction of Apple IDs, tokens, UUIDs, serial numbers |
| Authentication protocol | A02 | SRP (Secure Remote Password) — password never sent in plaintext to Apple |
| Config file integrity | A08 | Atomic writes (temp + fsync + rename) prevent corruption |
| Deserialization | A08 | No pickle, eval, or exec — JSON only |
