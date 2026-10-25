"use strict";

const { describe, it, beforeEach, afterEach } = require("node:test");
const assert = require("node:assert/strict");
const { startTestApp, upload, PASSWORD } = require("./helpers");
const audit = require("../src/audit");

let t;
beforeEach(async () => { t = await startTestApp(); });
afterEach(() => t.close());

async function sharedDoc(options = {}) {
  const owner = await t.as("owner");
  const up = await upload(owner, { title: "Board pack", name: "board.pdf", content: Buffer.from("%PDF-1.7\nboard\n") });
  const link = await owner.post(`/api/documents/${up.data.id}/links`, {
    json: { label: "Board review", expiresHours: 24, maxDownloads: options.maxDownloads ?? 2, passcode: options.passcode ?? "open-sesame" },
  });
  assert.equal(link.status, 201, JSON.stringify(link.data));
  const token = link.data.link.url.split("/share/")[1];
  return { owner, docId: up.data.id, linkId: link.data.link.id, token, passcode: options.passcode ?? "open-sesame", generated: link.data.passcode };
}

describe("share links", () => {
  it("downloads with the right passcode and counts the download", async () => {
    const s = await sharedDoc();
    const c = t.client();
    const info = await c.get(`/api/public/links/${s.token}`);
    assert.equal(info.status, 200);
    const dl = await c.post(`/api/public/links/${s.token}/download`, { json: { passcode: s.passcode } });
    assert.equal(dl.status, 200);
    assert.match(dl.buffer.toString("utf8"), /%PDF-1.7/);
    assert.equal(dl.headers.get("content-disposition").startsWith("attachment"), true);
    const row = t.db.prepare("SELECT download_count FROM share_links WHERE id = ?").get(s.linkId);
    assert.equal(row.download_count, 1);
  });

  it("refuses the link without the passcode, even when the link itself is correct", async () => {
    const s = await sharedDoc();
    const res = await t.client().post(`/api/public/links/${s.token}/download`, { json: { passcode: "wrong-one" } });
    assert.equal(res.status, 403);
    const row = t.db.prepare("SELECT download_count FROM share_links WHERE id = ?").get(s.linkId);
    assert.equal(row.download_count, 0, "a wrong passcode must not use up a download");
  });

  it("locks a link after repeated wrong passcodes, even when the right one is then sent", async () => {
    const s = await sharedDoc();
    const c = t.client();
    for (let i = 0; i < 5; i += 1) {
      assert.equal((await c.post(`/api/public/links/${s.token}/download`, { json: { passcode: `nope-${i}` } })).status, 403);
    }
    const locked = await c.post(`/api/public/links/${s.token}/download`, { json: { passcode: s.passcode } });
    assert.equal(locked.status, 429);
  });

  it("stops after the maximum number of downloads", async () => {
    const s = await sharedDoc({ maxDownloads: 2 });
    const c = t.client();
    assert.equal((await c.post(`/api/public/links/${s.token}/download`, { json: { passcode: s.passcode } })).status, 200);
    assert.equal((await c.post(`/api/public/links/${s.token}/download`, { json: { passcode: s.passcode } })).status, 200);
    assert.equal((await c.post(`/api/public/links/${s.token}/download`, { json: { passcode: s.passcode } })).status, 410);
  });

  it("stops working as soon as the owner revokes it", async () => {
    const s = await sharedDoc();
    const c = t.client();
    assert.equal((await c.get(`/api/public/links/${s.token}`)).status, 200);
    assert.equal((await s.owner.post(`/api/links/${s.linkId}/revoke`, { json: {} })).status, 200);
    assert.equal((await c.get(`/api/public/links/${s.token}`)).status, 410);
    assert.equal((await c.post(`/api/public/links/${s.token}/download`, { json: { passcode: s.passcode } })).status, 410);
  });

  it("stops working after it expires", async () => {
    const s = await sharedDoc();
    t.db.prepare("UPDATE share_links SET expires_at = ? WHERE id = ?").run("2000-01-01T00:00:00.000Z", s.linkId);
    assert.equal((await t.client().get(`/api/public/links/${s.token}`)).status, 410);
  });

  it("stops working when the document is moved to the trash", async () => {
    const s = await sharedDoc();
    await s.owner.del(`/api/documents/${s.docId}`);
    assert.equal((await t.client().get(`/api/public/links/${s.token}`)).status, 410);
  });

  it("does not reveal the owner's email or the document ID to the recipient", async () => {
    const s = await sharedDoc();
    const info = await t.client().get(`/api/public/links/${s.token}`);
    const text = JSON.stringify(info.data);
    assert.ok(!text.includes("owner@test.local"));
    assert.ok(!text.includes(s.docId));
    assert.ok(!text.includes("Board pack"));
    assert.ok(!text.includes("board.pdf"));
    assert.deepEqual(Object.keys(info.data).sort(), ["message", "requiresPasscode"]);
    assert.equal(info.data.requiresPasscode, true);
  });

  it("generates a passcode when none is given and returns it only once", async () => {
    const owner = await t.as("owner");
    const up = await upload(owner, { name: "a.txt" });
    const res = await owner.post(`/api/documents/${up.data.id}/links`, { json: { label: "auto" } });
    assert.ok(res.data.passcode && res.data.passcode.length === 10);
    const listed = await owner.get(`/api/documents/${up.data.id}/links`);
    assert.equal("passcode" in listed.data.links[0], false);
    assert.equal(t.db.prepare("SELECT passcode_hash FROM share_links").get().passcode_hash.includes(res.data.passcode), false);
  });

  it("stores the token and passcode only as hashes", async () => {
    const s = await sharedDoc();
    const row = t.db.prepare("SELECT token_hash, passcode_hash FROM share_links WHERE id = ?").get(s.linkId);
    assert.ok(!row.token_hash.includes(s.token));
    assert.ok(!row.passcode_hash.includes(s.passcode));
    assert.match(row.passcode_hash, /^scrypt\$/);
  });

  it("only the owner can create or list links", async () => {
    const s = await sharedDoc();
    const alice = await t.as("alice");
    await s.owner.post(`/api/documents/${s.docId}/grants`, { json: { email: "alice@test.local", permission: "edit" } });
    assert.equal((await alice.post(`/api/documents/${s.docId}/links`, { json: { label: "x" } })).status, 403);
    assert.equal((await alice.get(`/api/documents/${s.docId}/links`)).status, 403);
    assert.equal((await alice.post(`/api/links/${s.linkId}/revoke`, { json: {} })).status, 403);
  });
});

describe("the audit trail", () => {
  it("records unauthenticated attempts to access a document", async () => {
    const owner = await t.as("owner");
    const up = await upload(owner, { name: "private.txt" });
    const anonymous = t.client();
    const denied = await anonymous.get(`/api/documents/${up.data.id}/download`);
    assert.equal(denied.status, 401);
    const row = t.db.prepare(
      "SELECT actor_id, actor_email, action, entity_id, outcome, details FROM audit WHERE entity_id = ? ORDER BY seq DESC LIMIT 1"
    ).get(up.data.id);
    assert.equal(row.actor_id, null);
    assert.equal(row.actor_email, "anonymous");
    assert.equal(row.action, "document.download");
    assert.equal(row.outcome, "denied");
    assert.equal(JSON.parse(row.details).reason, "unauthenticated");
  });
  it("records allowed and refused access with the actor and the document", async () => {
    const s = await sharedDoc();
    const bob = await t.as("bob");
    await bob.get(`/api/documents/${s.docId}/download`);
    const denied = t.db.prepare(
      "SELECT actor_email, action, outcome, entity_id FROM audit WHERE actor_email = 'bob@test.local' AND outcome = 'denied'"
    ).all();
    assert.ok(denied.some((r) => r.action === "document.download" && r.entity_id === s.docId));
    const owned = t.db.prepare("SELECT COUNT(*) AS n FROM audit WHERE action = 'document.upload' AND entity_id = ?").get(s.docId).n;
    assert.equal(owned, 1);
  });

  it("records failed sign-ins, including unknown emails", async () => {
    await t.client().post("/api/auth/login", { json: { email: "ghost@test.local", password: "nothing-here-1" } });
    const row = t.db.prepare("SELECT outcome, actor_email FROM audit WHERE action = 'auth.login' AND actor_email = 'ghost@test.local'").get();
    assert.equal(row.outcome, "failed");
  });

  it("records each link download as anonymous, with the link ID", async () => {
    const s = await sharedDoc();
    await t.client().post(`/api/public/links/${s.token}/download`, { json: { passcode: s.passcode } });
    const row = t.db.prepare("SELECT actor_email, entity_id, outcome FROM audit WHERE action = 'link.download' AND outcome = 'allowed'").get();
    assert.equal(row.actor_email, "anonymous");
    assert.equal(row.entity_id, s.linkId);
  });

  it("refuses to let the application update or delete audit rows (database triggers)", async () => {
    await sharedDoc();
    assert.throws(() => t.db.exec("UPDATE audit SET outcome = 'allowed' WHERE seq = 1"), /append-only/);
    assert.throws(() => t.db.exec("DELETE FROM audit WHERE seq = 1"), /append-only/);
  });

  it("verifies an intact chain", async () => {
    await sharedDoc();
    const result = audit.verify(t.db);
    assert.equal(result.valid, true);
    assert.ok(result.checked > 0);
  });

  it("detects a rewritten row even when someone with file access removes the triggers", async () => {
    await sharedDoc();
    t.db.exec("DROP TRIGGER audit_no_update");
    t.db.prepare("UPDATE audit SET details = '{\"hidden\":true}' WHERE seq = 2").run();
    const result = audit.verify(t.db);
    assert.equal(result.valid, false);
    assert.equal(result.brokenAt, 2);
  });

  it("detects a deleted row in the middle of the chain", async () => {
    await sharedDoc();
    t.db.exec("DROP TRIGGER audit_no_delete");
    t.db.prepare("DELETE FROM audit WHERE seq = 2").run();
    assert.equal(audit.verify(t.db).valid, false);
  });

  it("gives the administrator a verify endpoint, and an anchor hash to store elsewhere", async () => {
    await sharedDoc();
    const admin = await t.as("admin");
    const v = await admin.get("/api/admin/audit/verify");
    assert.equal(v.data.valid, true);
    const a = await admin.get("/api/admin/audit/anchor");
    assert.match(a.data.latestHash, /^[0-9a-f]{64}$/);
  });

  it("keeps the audit log private from owners and viewers", async () => {
    await sharedDoc();
    const owner = await t.as("owner");
    assert.equal((await owner.get("/api/admin/audit")).status, 403);
  });

  it("exports CSV that spreadsheet software cannot run as formulas", async () => {
    t.db.prepare(
      "INSERT INTO audit (id, ts, actor_id, actor_email, action, entity_type, entity_id, outcome, details, prev_hash, hash) VALUES (?, ?, NULL, ?, 'test', 'x', NULL, 'allowed', '{}', ?, ?)"
    ).run("00000000-0000-4000-8000-00000000abcd", "2026-01-01T00:00:00Z", "=HYPERLINK(\"http://evil\")", "0".repeat(64), "f".repeat(64));
    const admin = await t.as("admin");
    const res = await admin.get("/api/admin/audit/export.csv");
    assert.equal(res.status, 200);
    assert.match(res.headers.get("content-type"), /text\/csv/);
    assert.ok(res.buffer.toString("utf8").includes("'=HYPERLINK"));
  });
});

describe("sign-in protection", () => {
  it("gives the same answer for an unknown email and a wrong password", async () => {
    const c = t.client();
    const a = await c.post("/api/auth/login", { json: { email: "nobody@test.local", password: "whatever-password" } });
    const b = await c.post("/api/auth/login", { json: { email: "alice@test.local", password: "whatever-password" } });
    assert.equal(a.status, 401);
    assert.equal(b.status, 401);
    assert.deepEqual(a.data, b.data);
  });

  it("locks an account after five failures from the same address", async () => {
    const c = t.client();
    for (let i = 0; i < 5; i += 1) {
      await c.post("/api/auth/login", { json: { email: "alice@test.local", password: `wrong-${i}-password` } });
    }
    const locked = await c.post("/api/auth/login", { json: { email: "alice@test.local", password: PASSWORD } });
    assert.equal(locked.status, 429);
  });

  it("does not let a deactivated account sign in", async () => {
    t.db.prepare("UPDATE users SET active = 0 WHERE id = ?").run(t.ids.bob);
    const res = await t.client().post("/api/auth/login", { json: { email: "bob@test.local", password: PASSWORD } });
    assert.equal(res.status, 401);
  });

  it("enforces the password minimum for new admin-created accounts", async () => {
    const admin = await t.as("admin");
    const res = await admin.post("/api/admin/users", {
      json: { email: "new@test.local", name: "New", role: "viewer", password: "short" },
    });
    assert.equal(res.status, 400);
  });
});
