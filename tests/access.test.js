"use strict";

const { describe, it, beforeEach, afterEach } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { startTestApp, upload, PASSWORD } = require("./helpers");

let t;
beforeEach(async () => { t = await startTestApp(); });
afterEach(() => t.close());

async function ownerDoc(title = "Salary letter") {
  const owner = await t.as("owner");
  const res = await upload(owner, { title });
  assert.equal(res.status, 201, JSON.stringify(res.data));
  return { owner, id: res.data.id };
}

async function grant(owner, docId, email, permission) {
  return owner.post(`/api/documents/${docId}/grants`, { json: { email, permission } });
}

describe("ownership and the default answer", () => {
  it("the owner uploads a document and downloads the exact bytes", async () => {
    const content = Buffer.from("exact bytes \u00e9\n", "utf8");
    const owner = await t.as("owner");
    const up = await upload(owner, { content, name: "note.txt" });
    assert.equal(up.status, 201);
    const dl = await owner.get(`/api/documents/${up.data.id}/download`);
    assert.equal(dl.status, 200);
    assert.ok(dl.buffer.equals(content));
    assert.equal(dl.headers.get("x-content-type-options"), "nosniff");
    assert.match(dl.headers.get("content-disposition"), /attachment/);
  });

  it("a user with no grant gets the same 404 for a real document and a made-up ID", async () => {
    const { id } = await ownerDoc();
    const alice = await t.as("alice");
    const real = await alice.get(`/api/documents/${id}`);
    const fake = await alice.get(`/api/documents/00000000-0000-4000-8000-000000000000`);
    assert.equal(real.status, 404);
    assert.equal(fake.status, 404);
    assert.deepEqual(real.data, fake.data, "responses must not reveal whether the document exists");
    const dl = await alice.get(`/api/documents/${id}/download`);
    assert.equal(dl.status, 404);
    assert.ok(!dl.buffer.toString().includes("Confidential"), "no file content may leak");
  });

  it("another owner cannot touch a document they did not upload", async () => {
    const { id } = await ownerDoc();
    const owner2 = await t.as("owner2");
    assert.equal((await owner2.get(`/api/documents/${id}/download`)).status, 404);
    assert.equal((await owner2.patch(`/api/documents/${id}`, { json: { title: "x" } })).status, 404);
    assert.equal((await owner2.del(`/api/documents/${id}`)).status, 404);
    assert.equal((await owner2.post(`/api/documents/${id}/grants`, { json: { email: "bob@test.local", permission: "read" } })).status, 404);
  });

  it("the search list never includes documents the user cannot access", async () => {
    await ownerDoc("Board minutes secret");
    const bob = await t.as("bob");
    const res = await bob.get("/api/documents?q=Board");
    assert.equal(res.status, 200);
    assert.deepEqual(res.data.documents, []);
  });
});

describe("per-document grants", () => {
  it("a read grant allows download but not edit, delete or sharing", async () => {
    const { owner, id } = await ownerDoc();
    assert.equal((await grant(owner, id, "alice@test.local", "read")).status, 201);
    const alice = await t.as("alice");
    assert.equal((await alice.get(`/api/documents/${id}/download`)).status, 200);
    assert.equal((await alice.patch(`/api/documents/${id}`, { json: { title: "renamed" } })).status, 403);
    assert.equal((await alice.del(`/api/documents/${id}`)).status, 403);
    assert.equal((await alice.post(`/api/documents/${id}/links`, { json: { label: "x" } })).status, 403);
    assert.equal((await alice.post(`/api/documents/${id}/grants`, { json: { email: "bob@test.local", permission: "read" } })).status, 403);
  });

  it("an edit grant allows changing details but not deleting", async () => {
    const { owner, id } = await ownerDoc();
    await grant(owner, id, "alice@test.local", "edit");
    const alice = await t.as("alice");
    const edit = await alice.patch(`/api/documents/${id}`, { json: { title: "Renamed by Alice", category: "Legal" } });
    assert.equal(edit.status, 200);
    assert.equal(edit.data.document.title, "Renamed by Alice");
    assert.equal((await alice.del(`/api/documents/${id}`)).status, 403);
  });

  it("revoking a grant takes effect on the very next request", async () => {
    const { owner, id } = await ownerDoc();
    const granted = await grant(owner, id, "alice@test.local", "read");
    const alice = await t.as("alice");
    assert.equal((await alice.get(`/api/documents/${id}/download`)).status, 200);

    const rev = await owner.del(`/api/documents/${id}/grants/${granted.data.grant.id}`);
    assert.equal(rev.status, 200);
    assert.equal((await alice.get(`/api/documents/${id}/download`)).status, 404);
    assert.equal((await alice.get(`/api/documents?q=Salary`)).data.documents.length, 0);
  });

  it("a second grant replaces the first instead of stacking", async () => {
    const { owner, id } = await ownerDoc();
    await grant(owner, id, "alice@test.local", "read");
    await grant(owner, id, "alice@test.local", "edit");
    const rows = t.db.prepare("SELECT permission FROM grants WHERE document_id = ? AND revoked_at IS NULL").all(id);
    assert.deepEqual(rows.map((r) => r.permission), ["edit"]);
  });

  it("only the owner can manage grants, and the owner cannot grant to themselves", async () => {
    const { owner, id } = await ownerDoc();
    assert.equal((await owner.post(`/api/documents/${id}/grants`, { json: { email: "owner@test.local", permission: "read" } })).status, 400);
    assert.equal((await owner.post(`/api/documents/${id}/grants`, { json: { email: "nobody@test.local", permission: "read" } })).status, 404);
    assert.equal((await owner.post(`/api/documents/${id}/grants`, { json: { email: "bob@test.local", permission: "root" } })).status, 400);
  });
});

describe("taking access away", () => {
  it("deactivating a user ends their existing session on the next request", async () => {
    const { owner, id } = await ownerDoc();
    await grant(owner, id, "alice@test.local", "read");
    const alice = await t.as("alice");
    assert.equal((await alice.get(`/api/documents/${id}/download`)).status, 200);

    const admin = await t.as("admin");
    const off = await admin.patch(`/api/admin/users/${t.ids.alice}`, { json: { active: false } });
    assert.equal(off.status, 200);
    assert.equal((await alice.get(`/api/documents/${id}/download`)).status, 401);
    const left = t.db.prepare("SELECT COUNT(*) AS n FROM sessions WHERE user_id = ?").get(t.ids.alice).n;
    assert.equal(left, 0, "deactivation must delete the user's sessions");
  });

  it("a logged-out session cannot be reused", async () => {
    const alice = await t.as("alice");
    const token = alice.cookie;
    await alice.post("/api/auth/logout", { json: {} });
    const replay = t.client();
    replay.cookie = token;
    assert.equal((await replay.get("/api/me")).status, 401);
  });

  it("a trashed document is invisible to grant holders and cannot be downloaded by the owner", async () => {
    const { owner, id } = await ownerDoc();
    await grant(owner, id, "alice@test.local", "read");
    assert.equal((await owner.del(`/api/documents/${id}`)).status, 200);

    const alice = await t.as("alice");
    assert.equal((await alice.get(`/api/documents/${id}/download`)).status, 404);
    assert.equal((await owner.get(`/api/documents/${id}/download`)).status, 410);
    assert.equal((await owner.post(`/api/documents/${id}/restore`, { json: {} })).status, 200);
    assert.equal((await alice.get(`/api/documents/${id}/download`)).status, 200);
  });
});

describe("roles", () => {
  it("a viewer cannot upload", async () => {
    const alice = await t.as("alice");
    const res = await upload(alice);
    assert.equal(res.status, 403);
  });

  it("an administrator cannot read document contents by default", async () => {
    const { id } = await ownerDoc();
    const admin = await t.as("admin");
    assert.equal((await admin.get(`/api/documents/${id}/download`)).status, 403);
    assert.equal((await admin.get(`/api/documents/${id}`)).status, 403);
    const list = await admin.get("/api/admin/documents");
    assert.equal(list.status, 200);
    assert.equal(list.data.documents.length, 1, "admins see document metadata");
    assert.equal("content" in list.data.documents[0], false);
  });

  it("an administrator can see the activity on a document without reading it", async () => {
    const { id } = await ownerDoc();
    const admin = await t.as("admin");
    const activity = await admin.get(`/api/documents/${id}/activity`);
    assert.equal(activity.status, 200);
    assert.ok(activity.data.events.some((e) => e.action === "document.upload"));
  });

  it("non-admins cannot reach admin routes, and the attempt is audited", async () => {
    const bob = await t.as("bob");
    assert.equal((await bob.get("/api/admin/users")).status, 403);
    assert.equal((await bob.get("/api/admin/audit")).status, 403);
    const denied = t.db.prepare("SELECT COUNT(*) AS n FROM audit WHERE action = 'access.role_denied' AND outcome = 'denied'").get().n;
    assert.ok(denied >= 2);
  });

  it("an admin cannot demote or deactivate their own account", async () => {
    const admin = await t.as("admin");
    const self = t.ids.admin;
    assert.equal((await admin.patch(`/api/admin/users/${self}`, { json: { role: "viewer" } })).status, 400);
    assert.equal((await admin.patch(`/api/admin/users/${self}`, { json: { active: false } })).status, 400);
  });
});

describe("upload validation", () => {
  it("rejects a file whose content does not match its extension", async () => {
    const owner = await t.as("owner");
    const res = await upload(owner, { name: "fake.pdf", content: Buffer.from("not really a pdf") });
    assert.equal(res.status, 400);
  });

  it("accepts a real PDF signature", async () => {
    const owner = await t.as("owner");
    const res = await upload(owner, { name: "real.pdf", content: Buffer.from("%PDF-1.4\n%%EOF\n") });
    assert.equal(res.status, 201);
  });

  it("rejects disallowed extensions", async () => {
    const owner = await t.as("owner");
    const res = await upload(owner, { name: "run.exe", content: Buffer.from("MZ") });
    assert.equal(res.status, 400);
  });

  it("rejects binary data disguised as text", async () => {
    const owner = await t.as("owner");
    const res = await upload(owner, { name: "notes.txt", content: Buffer.from([0x41, 0x00, 0x42]) });
    assert.equal(res.status, 400);
  });

  it("rejects files over 10 MB and leaves nothing on disk", async () => {
    const owner = await t.as("owner");
    const before = fs.readdirSync(t.dir + "/uploads").length;
    const res = await upload(owner, { name: "big.txt", content: Buffer.alloc(11 * 1024 * 1024, 0x61) });
    assert.equal(res.status, 413);
    assert.equal(fs.readdirSync(t.dir + "/uploads").length, before);
  });

  it("stores files under random names, never the user's file name", async () => {
    const owner = await t.as("owner");
    const res = await upload(owner, { name: "../../etc/passwd.txt" });
    assert.equal(res.status, 201);
    const row = t.db.prepare("SELECT stored_name, original_name FROM documents WHERE id = ?").get(res.data.id);
    assert.match(row.stored_name, /^[0-9a-f]{48}$/);
    assert.ok(!row.original_name.includes("/"), "display name must not contain path separators");
    assert.ok(fs.existsSync(path.join(t.dir, "uploads", row.stored_name)));
  });
});

describe("search", () => {
  it("filters by category, owner and date", async () => {
    const owner = await t.as("owner");
    await upload(owner, { title: "Offer letter", category: "HR" });
    await upload(owner, { title: "Vendor contract", category: "Contracts" });

    const res = await owner.get("/api/documents?category=Contracts");
    assert.deepEqual(res.data.documents.map((d) => d.title), ["Vendor contract"]);
    const byOwner = await owner.get("/api/documents?owner=owner@test.local");
    assert.equal(byOwner.data.documents.length, 2);
    const today = new Date().toISOString().slice(0, 10);
    const dated = await owner.get(`/api/documents?from=${today}&to=${today}`);
    assert.equal(dated.data.documents.length, 2);
    const future = await owner.get("/api/documents?from=2999-01-01");
    assert.equal(future.data.documents.length, 0);
  });

  it("treats LIKE wildcards in the search box as plain text", async () => {
    const owner = await t.as("owner");
    await upload(owner, { title: "100% final" });
    await upload(owner, { title: "1000 final" });
    const res = await owner.get(`/api/documents?q=${encodeURIComponent("100%")}`);
    assert.deepEqual(res.data.documents.map((d) => d.title), ["100% final"]);
  });

  it("rejects malformed dates", async () => {
    const owner = await t.as("owner");
    assert.equal((await owner.get("/api/documents?from=yesterday")).status, 400);
  });
});

describe("editing", () => {
  it("writes an audit entry with the before and after values", async () => {
    const { owner, id } = await ownerDoc();
    await owner.patch(`/api/documents/${id}`, { json: { title: "Renamed" } });
    const row = t.db.prepare("SELECT details FROM audit WHERE action = 'document.edit' AND entity_id = ?").get(id);
    const details = JSON.parse(row.details);
    assert.deepEqual(details.title, { from: "Salary letter", to: "Renamed" });
  });
});

describe("request handling", () => {
  it("refuses unsafe requests that lack the anti-CSRF header", async () => {
    const alice = await t.as("alice");
    const res = await fetch(`${t.base}/api/auth/logout`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Cookie: alice.cookie },
      body: "{}",
    });
    assert.equal(res.status, 403);
  });

  it("refuses requests from another origin", async () => {
    const alice = await t.as("alice");
    const res = await fetch(`${t.base}/api/auth/logout`, {
      method: "POST",
      headers: { "X-TrustVault": "1", Origin: "https://evil.example", Cookie: alice.cookie },
      body: "{}",
    });
    assert.equal(res.status, 403);
  });

  it("serves the session cookie as HttpOnly and SameSite=Strict", async () => {
    const c = t.client();
    const res = await c.post("/api/auth/login", { json: { email: "alice@test.local", password: PASSWORD } });
    const cookie = res.headers.get("set-cookie");
    assert.match(cookie, /HttpOnly/);
    assert.match(cookie, /SameSite=Strict/);
  });

  it("sends a strict Content-Security-Policy and no-referrer policy on pages", async () => {
    const page = await t.client().get("/");
    assert.equal(page.status, 200);
    assert.match(page.headers.get("content-security-policy"), /script-src 'self'/);
    assert.equal(page.headers.get("referrer-policy"), "no-referrer");
    assert.equal(page.headers.get("x-frame-options"), "DENY");
  });

  it("does not serve files outside the public folder", async () => {
    const res = await t.client().get("/..%2fserver.js");
    assert.equal(res.status, 404);
    const res2 = await t.client().get("/../src/app.js");
    assert.equal(res2.status, 404);
  });
});
