# TrustVault API

All responses are JSON unless noted. Errors look like `{ "error": "message" }`.

**Who may call** is stated for each endpoint. "Any signed-in user" means an active account with a session. "Grant holder" means an active per-document grant of the stated level. Requests that the caller is not allowed to make are refused and written to the audit log, including unauthenticated attempts against document routes (recorded with an anonymous actor).

## Conventions

- **Authentication.** A session cookie `tv_session` (HttpOnly, SameSite=Strict, 8-hour lifetime, stored server-side).
- **Anti-CSRF.** Every `POST`, `PATCH` and `DELETE` must send the header `X-TrustVault: 1`. Requests whose `Origin` header does not match the host are refused.
- **Refusal codes.** `401` not signed in. `403` signed in, but the role or grant does not allow the action. `404` no permission on this document, or it does not exist (the two are indistinguishable on purpose). `409` document is in the trash. `410` share link is unusable. `413` file too large. `429` too many attempts.
- **IDs.** UUIDs. They cannot be guessed or counted.

## Health

| Method | Path | Who may call |
| --- | --- | --- |
| GET | `/api/health` | Anyone |

## Authentication

| Method | Path | Body | Who may call |
| --- | --- | --- | --- |
| POST | `/api/auth/login` | `{ email, password }` | Anyone. Five failures from one address and email lock that pair for 15 minutes. |
| POST | `/api/auth/logout` | `{}` | Signed-in user. Ends the session on the server. |
| GET | `/api/me` | | Signed-in user |

## Documents

| Method | Path | Notes | Who may call |
| --- | --- | --- | --- |
| GET | `/api/documents` | Query: `q`, `category`, `owner` (email), `from`, `to` (YYYY-MM-DD). Returns only documents the caller owns or holds a grant on. | Signed-in user |
| POST | `/api/documents?title=&category=` | Raw file bytes as the body. Header `X-File-Name` (URL-encoded). PDF, PNG, JPG or TXT, max 10 MB. Content is checked against the file signature. | Document owner |
| GET | `/api/documents/:id` | Metadata and the caller's permissions. | Read grant or owner |
| PATCH | `/api/documents/:id` | `{ title?, category? }` | Edit grant or owner |
| GET | `/api/documents/:id/download` | Returns the file as an attachment. The download is recorded before it is sent. | Read grant or owner |
| DELETE | `/api/documents/:id` | Moves the document to the trash and revokes its share links. | Owner |
| POST | `/api/documents/:id/restore` | Restores a trashed document. | Owner |
| GET | `/api/documents/:id/activity` | The audit trail for this document, including refused attempts. | Owner or administrator |

## Grants (per-document access)

| Method | Path | Body | Who may call |
| --- | --- | --- | --- |
| GET | `/api/documents/:id/grants` | | Owner |
| POST | `/api/documents/:id/grants` | `{ email, permission: "read" \| "edit" }`. Replaces any existing grant for that person. | Owner |
| DELETE | `/api/documents/:id/grants/:grantId` | | Owner. Takes effect on the next request. |

## Share links (external recipients)

| Method | Path | Body | Who may call |
| --- | --- | --- | --- |
| GET | `/api/documents/:id/links` | | Owner |
| POST | `/api/documents/:id/links` | `{ label?, expiresHours (1–168, default 24), maxDownloads (1–50, default 1), passcode? (6–64 characters) }`. A passcode is generated if omitted and returned once. | Owner |
| POST | `/api/links/:id/revoke` | | Owner of the document |

## Public share pages (no account)

| Method | Path | Body | Who may call |
| --- | --- | --- | --- |
| GET | `/share/:token` | | Anyone (HTML page) |
| GET | `/api/public/links/:token` | Returns only a generic passcode-required message; does not reveal title, filename, size, label, expiry or remaining downloads. | Anyone with the link. |
| POST | `/api/public/links/:token/download` | `{ passcode }`; on success returns the file attachment and filename in `Content-Disposition`. | Anyone with the link and the passcode. Five wrong passcodes lock the link for 30 minutes. Each download counts. |

## Administration

| Method | Path | Body | Who may call |
| --- | --- | --- | --- |
| GET | `/api/admin/users` | | Administrator |
| POST | `/api/admin/users` | `{ email, name, role, password (12+) }` | Administrator |
| PATCH | `/api/admin/users/:id` | `{ role?, active? }`. Deactivating ends the user's sessions. | Administrator. Cannot change their own role or deactivate themselves. |
| GET | `/api/admin/documents` | Metadata only, never file content. | Administrator |
| GET | `/api/admin/audit` | Query: `action`, `outcome`, `limit` (max 500) | Administrator |
| GET | `/api/admin/audit/verify` | Checks the hash chain. | Administrator |
| GET | `/api/admin/audit/anchor` | The latest hash, to be stored outside the system. | Administrator |
| GET | `/api/admin/audit/export.csv` | Full export. The export itself is audited. | Administrator |
