"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { createApp } = require("../src/app");
const { hashPassword } = require("../src/security");

const PASSWORD = "correct horse battery";

const PEOPLE = [
  { key: "admin", email: "admin@test.local", name: "Admin", role: "admin" },
  { key: "owner", email: "owner@test.local", name: "Owner", role: "owner" },
  { key: "owner2", email: "owner2@test.local", name: "Second Owner", role: "owner" },
  { key: "alice", email: "alice@test.local", name: "Alice", role: "viewer" },
  { key: "bob", email: "bob@test.local", name: "Bob", role: "viewer" },
];

class Client {
  constructor(base) {
    this.base = base;
    this.cookie = null;
  }

  async request(method, url, { json, body, headers = {} } = {}) {
    const h = { ...headers };
    if (method !== "GET") h["X-TrustVault"] = "1";
    if (this.cookie) h.Cookie = this.cookie;
    let payload = body;
    if (json !== undefined) {
      h["Content-Type"] = "application/json";
      payload = JSON.stringify(json);
    }
    const res = await fetch(this.base + url, { method, headers: h, body: payload, redirect: "manual" });
    const setCookie = res.headers.get("set-cookie");
    if (setCookie) {
      const m = /tv_session=([^;]*)/.exec(setCookie);
      if (m && m[1]) this.cookie = `tv_session=${m[1]}`;
      if (/Max-Age=0/.test(setCookie)) this.cookie = null;
    }
    const buffer = Buffer.from(await res.arrayBuffer());
    let data = null;
    const type = res.headers.get("content-type") || "";
    if (type.includes("application/json")) data = JSON.parse(buffer.toString("utf8"));
    return { status: res.status, data, buffer, headers: res.headers };
  }

  get(url, opts) { return this.request("GET", url, opts); }
  post(url, opts) { return this.request("POST", url, opts); }
  patch(url, opts) { return this.request("PATCH", url, opts); }
  del(url, opts) { return this.request("DELETE", url, opts); }

  async login(email, password = PASSWORD) {
    return this.post("/api/auth/login", { json: { email, password } });
  }
}

async function startTestApp(extra = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tv-test-"));
  const app = createApp({
    dbPath: path.join(dir, "test.db"),
    uploadDir: path.join(dir, "uploads"),
    cookieSecure: false,
    ...extra,
  });
  await new Promise((resolve) => app.server.listen(0, "127.0.0.1", resolve));
  const base = `http://127.0.0.1:${app.server.address().port}`;

  const ids = {};
  const now = new Date().toISOString();
  for (const p of PEOPLE) {
    const id = crypto.randomUUID();
    ids[p.key] = id;
    app.db
      .prepare("INSERT INTO users (id, email, name, role, password_hash, active, created_at) VALUES (?, ?, ?, ?, ?, 1, ?)")
      .run(id, p.email, p.name, p.role, await hashPassword(PASSWORD), now);
  }

  return {
    app,
    db: app.db,
    base,
    dir,
    ids,
    client: () => new Client(base),
    async as(key) {
      const c = new Client(base);
      const person = PEOPLE.find((p) => p.key === key);
      const res = await c.login(person.email);
      if (res.status !== 200) throw new Error(`login failed for ${key}: ${res.status}`);
      return c;
    },
    close() {
      app.server.closeAllConnections();
      app.close();
      fs.rmSync(dir, { recursive: true, force: true });
    },
  };
}

async function upload(client, {
  title = "Salary letter",
  category = "HR",
  name = "letter.txt",
  content = Buffer.from("Confidential salary letter for Q3\n", "utf8"),
  type = "application/octet-stream",
} = {}) {
  const qs = new URLSearchParams({ title, category });
  return client.post(`/api/documents?${qs}`, {
    headers: { "Content-Type": type, "X-File-Name": encodeURIComponent(name) },
    body: content,
  });
}

module.exports = { startTestApp, upload, PASSWORD, Client };
