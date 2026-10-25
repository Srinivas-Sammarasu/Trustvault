# TrustVault

Secure document sharing where a document is reachable only by someone who was granted it, and every access, refused attempt and change is recorded in a tamper-evident log.

- Per-document grants (read or edit), owned and revoked by the document owner
- Roles: **Administrator** (manages accounts, sees activity, cannot read contents), **Document owner** (uploads and grants), **Viewer** (sees only what was granted)
- Expiring share links for people outside the company, each with a passcode and a download limit
- Hash-chained audit trail with verification, anchoring and CSV export
- Trash with restore, server-side sessions, and login lockout

See `THREATS.md` for the threat model and `docs/API.md` for who may call each endpoint.

## Requirements

- **Node.js 22.13 or newer.** The app uses Node's built-in SQLite (`node:sqlite`), so there are no third-party packages to install. Node prints an "ExperimentalWarning" for SQLite. That is expected.
- No other software is needed.

## Run it locally

```bash
npm install            # nothing to download; this only writes package-lock.json
npm run seed           # creates the three accounts and one sample document; prints the passwords once
npm start              # http://127.0.0.1:3000
```

To choose the seed passwords yourself, set them before seeding:

```bash
SEED_ADMIN_PASSWORD='a-long-admin-password' SEED_OWNER_PASSWORD='a-long-owner-password' SEED_VIEWER_PASSWORD='a-long-viewer-password' npm run seed
```

Windows PowerShell:

```powershell
$env:SEED_ADMIN_PASSWORD = "a-long-admin-password"
npm run seed
npm start
```

Seeding does nothing if any account already exists.

## Run the tests

```bash
npm test
```

The suite starts the real server on a random port with a fresh database for each test. It covers:

- cross-user access: no grant, another owner, search, the 404-versus-403 difference
- grants: read, edit, replacement, and revocation that takes effect on the next request
- deactivation and logout ending sessions immediately
- roles, admin metadata-only access, and self-protection for admins
- upload validation: file signatures, extension allow-list, size limit, random storage names
- share links: passcodes, download limits, expiry, revocation, trash, lockout, hashed secrets
- the audit trail: append-only triggers, hash-chain verification, tamper detection, CSV injection, and anonymous denied document-access attempts
- sign-in lockout, enumeration resistance, cookie flags, CSRF and origin checks, security headers

**To prove the tests test something:** in `src/app.js`, change `if (doc && perms.has(perm))` inside `requireDoc()` to `if (doc)`. Run `npm test`. Nine tests should fail. Restore the line. This check was run during development: 9 of 57 failed with the check removed, and all 57 passed with it in place.

## Deploy

TrustVault is one process with one database file and one folder of uploads. The host must keep those between restarts. Free hosts that wipe the disk on restart will lose the documents, so use a host with a persistent disk.

Render (with a persistent disk mounted at `/var/data`):

1. Build command: `npm install`
2. Start command: `npm run seed && npm start` (the first run only; later runs do nothing)
3. Environment:
   - `NODE_VERSION` = `22`
   - `NODE_ENV` = `production` (turns on the Secure cookie flag)
   - `TV_DB` = `/var/data/trustvault.db`
   - `TV_UPLOADS` = `/var/data/uploads`
   - `TV_PUBLIC_URL` = your public `https://` address
   - `TV_TRUST_PROXY` = `1` (the host is behind a proxy, so rate limits use the real client address)
   - `SEED_ADMIN_PASSWORD`, `SEED_OWNER_PASSWORD`, `SEED_VIEWER_PASSWORD` (12+ characters each)
   - `HOST` = `0.0.0.0`

Use HTTPS. Share links and session cookies must not travel over plain HTTP.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `PORT` | `3000` | Listening port |
| `HOST` | `127.0.0.1` | Listening address. Set `0.0.0.0` behind a host. |
| `TV_DB` | `data/trustvault.db` | SQLite file |
| `TV_UPLOADS` | `uploads/` | Stored files. Never served directly. |
| `TV_PUBLIC_URL` | (empty) | Public address used in share links and in the origin check |
| `TV_TRUST_PROXY` | `0` | Set to `1` to use `X-Forwarded-For` for rate limits |
| `TV_COOKIE_SECURE` | `1` if `NODE_ENV=production`, else `0` | Adds the Secure flag to the session cookie |

## Permission model in brief

Access is decided in one function, `permissionsFor()` in `src/authz.js`. Every document route calls it through `requireDoc()` in `src/app.js`.

- A document is owned by the person who uploaded it. The owner can do everything with it.
- Anyone else has no access unless they hold an active grant: **read** (view and download) or **edit** (also change title and category).
- Administrators hold no content access. They can see metadata and each document's activity. An owner can grant them content access like anyone else, and that grant is recorded.
- A user with no permission receives 404, which is the same answer as for a missing document.
- Grants, share links and deactivations take effect on the very next request, because nothing is cached.

## Audit trail

Every upload, view, download, edit, deletion, restore, grant, revocation, link creation, link view, link download, sign-in (successful or not), role refusal and account change is written to the `audit` table. Refused document access is recorded with the reason.

Each row's hash covers its content and the previous row's hash. The database triggers refuse `UPDATE` and `DELETE`. The administrator can:

- **Verify** the chain (`/api/admin/audit/verify`, or the button in the Admin → Audit tab).
- **Show the anchor**, the latest hash (`/api/admin/audit/anchor`). Copy it daily into storage the administrator cannot write to. A rewritten chain then no longer matches the copy.
- **Export** the whole log as CSV. The export is itself audited.

The chain alone cannot stop someone with full write access from rebuilding it. The external anchor is what closes that gap. The anchor is documented as not yet automated.

## Using AI in this project

AI tools (Claude) were used to design and write this code and the documents. Each suggestion was read, run, and where it was wrong, changed. The development record is in `PROMPTS.md`. Before submission, read every file, change something small yourself, and be able to explain where the authorisation decision is made.

## What is not finished

See the last section of `THREATS.md`. In short:

- No malware scanning of uploads
- No password reset, and no forced password change on first sign-in
- No file versions (editing changes details only), no ownership transfer, no automatic retention
- The audit anchor is available but not scheduled
- Rate limits are in memory and per process
- The browser interface has syntax checks and API regression coverage, but has not been fully clicked through in a real browser. Perform the manual QA checklist before the demo.
- This build was tested with Node 22.22. Earlier Node 22 releases below 22.13 do not have `node:sqlite` and will not start.

## Layout

```
server.js            entry point
seed.js              first accounts and sample data
src/app.js           every route and the request dispatcher
src/authz.js         the single access decision
src/audit.js         hash-chained log
src/db.js            schema and transactions
src/security.js      passwords, tokens, lockout
src/files.js         upload validation and download headers
src/http.js          router, body limits, security headers, static files
public/              interface (index.html, app.js, styles.css, share.html, share.js)
tests/               automated tests
docs/API.md          endpoint reference
THREATS.md           threat model
PROMPTS.md           AI prompt log
```
