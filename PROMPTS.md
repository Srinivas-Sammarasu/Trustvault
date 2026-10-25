# PROMPTS.md

A record of how AI tools were used on this project: what I asked, what came back, what was wrong, and what I did instead.

> **Before you submit:** the entries below are drafts written from the session that produced this version. They are not a substitute for your own record. Confirm each one against what actually happened to you, correct anything that is not accurate, add your own dated entries as you work, and replace `<commit>` with the real commit hash. Keep at least two entries on authorisation, access control or the audit trail.

## 2026-10-23 — Review of the uploaded starter: access control

- **Prompt:** "Review the uploaded TrustVault zip for security and tell me what is wrong with access control."
- **Produced:** a list of findings. The main one was that document access was decided by tenant only. Any Viewer could list and download every document in the workspace, and any Editor could share or delete documents they did not upload. Also: share links were checked against a typed email that the API then returned to anyone holding the link, `/api/shares` was open to all signed-in users, and the server fell back to a hard-coded session secret.
- **What I checked:** I read the routes at the cited lines (`GET /api/documents`, the download route, the share routes, the `SESSION_SECRET` fallback) and confirmed each one against the code. I could not run the server, because the sandbox had no network access for `npm install`.
- **What I did instead:** I did not patch the starter. I rebuilt the access model around per-document grants (`src/authz.js`), replaced the email check with passcodes, and removed the secret. See the commit `<commit>`.

## 2026-10-23 — Rebuilding the authorisation model

- **Prompt:** "Replace tenant-wide access with per-document grants. Owners grant and revoke. Any refused attempt must be audited. Revocation must take effect immediately."
- **Produced:** a `permissionsFor()` function, a `requireDoc()` gate that every document route calls, and a `grants` table with a unique index on active grants.
- **What was wrong:** the first draft gave the owner of a trashed document only the `RESTORE` permission. The owner's download request then failed with a generic 403, rather than the clear "in the trash" message. The owner also needed `READ` to see the trashed record.
- **What I did instead:** I gave the owner `READ` and `RESTORE` for trashed documents, and made the download route return 410 with the reason. See `<commit>`. The test `a trashed document is invisible to grant holders and cannot be downloaded by the owner` covers this.

## 2026-10-23 — Checking that the tests test something

- **Prompt:** "Write tests that show one user cannot reach another user's documents. Then show me the tests would fail if the check were removed."
- **Produced:** a 57-test suite that runs against the real HTTP server, with a fresh database per test. All 57 passed on the first run.
- **Why I did not trust it yet:** passing on the first run is only a good sign if the tests can also fail. I removed the check in `requireDoc()` by changing it to `if (doc)`, and ran the suite. Nine tests failed. I restored the line and all 57 passed again.
- **Lesson:** a test suite that has never failed is not evidence. Keep the mutation step in the README and run it before each submission.

## 2026-10-23 — Audit chain: what it does and does not protect

- **Prompt:** "Make the audit trail tamper-evident. Explain what the hash chain stops and what it does not."
- **Produced:** a hash chain with database triggers, a verify endpoint, and an anchor endpoint. The explanation said the chain stops in-place edits and deletions, but someone with write access can rebuild the whole chain, so an external copy of the latest hash is needed for that case.
- **What I checked:** three tests. One edits a row with the triggers removed and expects verification to fail at that row. One deletes a middle row and expects failure. One checks that the application cannot update or delete audit rows. All three pass.
- **What is still open:** I have not yet scheduled the anchor copy. The endpoint exists, but nothing stores the hash outside the system. Until that is done, the full-rewrite case is not defended. This is listed in THREATS.md and the README. See `<commit>`.

## Other tools and reused context

- The project brief and the hackathon rules were pasted in as context for every session, so the output would match the marking.
- The threat model in `THREATS.md` was drafted from the security brief, then checked against the code and tests line by line.


## 2026-10-25 — Follow-up security regression review

- **Prompt:** Review the current TrustVault project, identify remaining issues relevant to the security-focused document-sharing brief, and patch them with regression tests.
- **Produced:** A change to audit unauthenticated attempts to reach protected document routes; a change to stop the public share-link metadata endpoint from returning document title, filename, size, label, expiry and remaining download count before passcode-protected download; and regression tests for both behaviors.
- **What was wrong:** The prior suite tested denied access by signed-in users, but did not assert that an anonymous request to a protected document route was recorded. The share-page metadata test checked for owner email and document ID but allowed sensitive document metadata to be returned.
- **What I did instead:** Added an anonymous denied-access audit event before returning 401, changed the share page to show generic instructions before download, use the successful download's `Content-Disposition` filename, and added regression assertions. Local verification: `node --check src/app.js`, `node --check public/share.js`, and `npm test` (58 passed, 0 failed).
- **Commit:** Not created in this workspace. After reviewing these changes, create a real commit and replace this note with its actual hash; do not invent or backdate a commit. Confirm this entry accurately describes the work before submission.
