# THREATS.md

This document lists the ways I believe TrustVault could be broken, what I did about each one, which test covers it, and what I knowingly left open. Each test named here exists in `tests/`. To check that a test really tests its threat, remove the protection it names and run `npm test`. The test should fail.

Scope: a single organisation's workspace, running as one Node.js process with one SQLite file. Multi-server deployment, malware scanning and legal retention rules are out of scope and listed under "accepted".

## Access to documents

**T1. Someone reads a document they were not given (IDOR).**
Guessing document IDs.
*Mitigation:* IDs are random UUIDs. Every document route calls `requireDoc()`, which calls `permissionsFor()` in `src/authz.js`. Access is decided from the database on every request.
*Test:* `a user with no grant gets the same 404 for a real document and a made-up ID`; `another owner cannot touch a document they did not upload`.

**T2. Existence leak.** A user learns which document IDs exist from the difference between "not found" and "forbidden".
*Mitigation:* A user with no permission on a document gets 404, the same response as for a missing document, with an identical body. A user who can see the document but not perform the action gets 403.
*Test:* the same 404 test compares the two response bodies.

**T3. Search leaks titles.** Search results show documents the caller cannot open.
*Mitigation:* The search query is restricted in SQL to owned documents and documents with an active grant.
*Test:* `the search list never includes documents the user cannot access`.

**T4. Access survives a revocation.** A grant is removed, but the person keeps downloading.
*Mitigation:* Grants are read from the database on every request. Revocation is a single `UPDATE`, so it takes effect on the next request. There is no cached permission list.
*Test:* `revoking a grant takes effect on the very next request`.

**T5. Access survives deactivation.** A person leaves the company but still has a valid session.
*Mitigation:* Sessions are stored server-side. `sessionUser()` requires `users.active = 1` on every request. Deactivation also deletes the user's session rows.
*Test:* `deactivating a user ends their existing session on the next request`.

**T6. Logout does not end the session.** A copied cookie stays valid.
*Mitigation:* Logout deletes the session row. Only a SHA-256 of the token is stored, so a stolen database does not contain usable tokens.
*Test:* `a logged-out session cannot be reused`.

**T7. An administrator reads everything.**
*Mitigation:* Administrators hold only `ACTIVITY` permission on documents. They see metadata and the audit trail. They cannot download, and they cannot read content unless an owner grants it.
*Test:* `an administrator cannot read document contents by default`.

**T8. A viewer uploads or changes things.**
*Mitigation:* Role checks happen before any work. Refused role attempts are audited with `access.role_denied`.
*Test:* `a viewer cannot upload`; `non-admins cannot reach admin routes, and the attempt is audited`.

**T9. An owner loses control of their own file.**
*Mitigation:* Ownership is recorded on the document. The owner always holds read, edit, delete, share and activity, regardless of their global role.
*Accepted:* if an owner is demoted to viewer, they keep control of their own documents. This is a design choice. An administrator who wants them removed deactivates the account, which ends access immediately.

## Share links

**T10. A share link is used by someone who has it.**
Links are bearer secrets, and they can be forwarded.
*Mitigation:* Each link also needs a passcode, which the owner gives out of band. The link has an expiry, a download limit, and a revoke control. The download counter is updated in one atomic statement, so two requests cannot both use the last download. The pre-download metadata endpoint reveals only that a passcode is required; title, filename, size, label, expiry and remaining download count are withheld until the protected download succeeds.
*Test:* `refuses the link without the passcode, even when the link itself is correct`; `does not reveal the owner's email or the document ID to the recipient` (also asserts sensitive metadata is withheld); `stops after the maximum number of downloads`; `stops working as soon as the owner revokes it`; `stops working after it expires`.
*Residual risk:* If someone has both the link and the passcode, they can download. The owner decides who gets both.

**T11. The recipient's email is used as a check.**
The first version of this application compared a typed email with the stored recipient, and returned that email to anyone with the link. Both problems are removed. The link no longer stores or returns any recipient email.
*Test:* `does not reveal the owner's email or the document ID to the recipient`.

**T12. Passcode guessing.**
*Mitigation:* Five wrong passcodes lock the link for 30 minutes. Wrong passcodes do not use up downloads. Passcodes are hashed with scrypt.
*Test:* `locks a link after repeated wrong passcodes, even when the right one is then sent`.
*Residual risk:* the limiter is in memory. A restart clears it, and it does not coordinate across several servers.

**T13. The link token leaks through the Referer header.**
*Mitigation:* `Referrer-Policy: no-referrer` on every response.
*Test:* `sends a strict Content-Security-Policy and no-referrer policy on pages`.

**T14. Link tokens are readable from the database.**
*Mitigation:* Tokens and passcodes are stored only as hashes.
*Test:* `stores the token and passcode only as hashes`.

## Authentication

Unauthenticated requests to protected document routes are also audit-recorded with an anonymous actor, the requested document identifier and a denial reason. This preserves evidence of refused access attempts without treating the requester as a known user.

**T15. Password guessing.**
*Mitigation:* Five failures from one address for one email lock that pair for 15 minutes. Passwords are hashed with scrypt. Admin-created passwords must be at least 12 characters.
*Test:* `locks an account after five failures from the same address`; `enforces the password minimum for new admin-created accounts`.
*Residual risk:* the limiter is per process and in memory. An attacker using many addresses is not stopped. Production should add rate limiting at the proxy.

**T16. User enumeration.** Login reveals which emails exist.
*Mitigation:* An unknown email runs the same scrypt check against a dummy hash, so the response time and the message are the same.
*Test:* `gives the same answer for an unknown email and a wrong password`.

**T17. Session cookie theft.**
*Mitigation:* HttpOnly, SameSite=Strict, and Secure in production.
*Test:* `serves the session cookie as HttpOnly and SameSite=Strict`.
*Residual risk:* the Secure flag depends on `TV_COOKIE_SECURE` or `NODE_ENV=production`. Set one of them in production.

**T18. Default secrets.** The first version fell back to a public signing secret.
*Mitigation:* This version has no signing secret at all. Sessions are random tokens stored in the database.

## Cross-site and injection

**T19. Cross-site request forgery.**
*Mitigation:* Every unsafe request must carry `X-TrustVault: 1`. A cross-site form cannot set this header. Requests whose `Origin` differs from the host are refused. SameSite=Strict also applies.
*Test:* `refuses unsafe requests that lack the anti-CSRF header`; `refuses requests from another origin`.

**T20. Stored script injection through titles or file names.**
*Mitigation:* The interface builds all content with `textContent`. There is no `innerHTML`. A strict Content-Security-Policy with `script-src 'self'` blocks inline scripts. File names are cleaned to letters, digits and a few symbols.
*Residual risk:* I checked the code by reading it. I did not run a browser test, so this needs a manual check before submission.

**T21. A malicious file runs in the browser.**
*Mitigation:* Every download is sent as an attachment with `X-Content-Type-Options: nosniff`. The MIME type is chosen by the server from the validated extension, not from the client.
*Test:* `the owner uploads a document and downloads the exact bytes` (checks the headers).
*Accepted:* files are not scanned for malware. Add a scanner before production.

**T22. A fake file type passes validation.**
*Mitigation:* Each type must start with its file signature (`%PDF-`, PNG, JPEG). TXT files must be valid UTF-8 with no NUL bytes.
*Test:* `rejects a file whose content does not match its extension`; `accepts a real PDF signature`; `rejects binary data disguised as text`.

**T23. Path traversal in uploads.** A file name such as `../../etc/passwd` escapes the upload folder.
*Mitigation:* Files are stored under random 48-character names. The user's name is kept only as a display string, with path characters removed. Static file serving resolves paths and refuses anything outside `public/`.
*Test:* `stores files under random names, never the user's file name`; `does not serve files outside the public folder`.

**T24. Spreadsheet formula injection in the audit export.**
*Mitigation:* CSV cells that start with `=`, `+`, `-`, `@` or a tab are prefixed with an apostrophe.
*Test:* `exports CSV that spreadsheet software cannot run as formulas`.

**T25. Oversized uploads exhaust memory or disk.**
*Mitigation:* 10 MB limit, enforced while the body streams in. Nothing is written to disk until the file is complete and valid.
*Test:* `rejects files over 10 MB and leaves nothing on disk`.

**T26. Oversized JSON bodies.**
*Mitigation:* 64 KB limit on JSON bodies.

## Audit trail

**T27. The audit trail is edited through the application.**
*Mitigation:* Database triggers refuse `UPDATE` and `DELETE` on the audit table.
*Test:* `refuses to let the application update or delete audit rows (database triggers)`.

**T28. Someone with file access rewrites the trail.**
*Mitigation:* Each row's hash covers its content and the previous row's hash. `GET /api/admin/audit/verify` recomputes the chain. The administrator can export the latest hash with `/api/admin/audit/anchor` and store it outside the system.
*Test:* `detects a rewritten row even when someone with file access removes the triggers`; `detects a deleted row in the middle of the chain`.
*Residual risk:* someone who controls the database can rewrite the whole chain and recompute every hash. The defence against that is the external copy of the latest hash. Without it, the chain shows tampering only for a partial edit. Storing the anchor daily in a system the administrator cannot write to is the next step.

**T29. Refused attempts are not recorded.**
*Mitigation:* Every refused document action, role refusal, failed sign-in, and refused link is recorded with the actor, the document, and the reason.
*Test:* `records allowed and refused access with the actor and the document`; `records failed sign-ins, including unknown emails`.

**T30. Audit records reveal passcodes or tokens.**
*Mitigation:* Audit details hold IDs, file names and counts. They never hold tokens, passcodes or file contents.

## Denial of service

**T31. Brute-forcing login or link tokens.**
Covered by T12 and T15. Link tokens are 256-bit random values, so guessing them is not practical.

**T32. Very large search or activity queries.**
*Mitigation:* Search returns at most 200 documents. Activity returns at most 500 events. The audit list is capped at 500.

## Accepted and not yet done

- **Malware scanning** of uploads.
- **Rate limiting** outside the application (proxy or gateway). In-app limits are per process and reset on restart.
- **External anchoring** of the audit hash. The endpoint exists; the scheduled copy does not.
- **Password reset and forced change on first sign-in.** Administrators set temporary passwords.
- **File versions.** Editing changes metadata only. Replacing file content is not built.
- **Ownership transfer.**
- **Retention and purge.** Trashed documents stay until someone restores them. There is no automatic deletion.
- **Single-process storage.** SQLite and the in-memory limiters assume one server. Scaling out needs a shared database and a shared limiter.
- **Sessions are not renewed.** A session ends after eight hours whether or not the user is active.
- **No browser test suite.** The interface was checked for syntax and element IDs, not clicked through.
