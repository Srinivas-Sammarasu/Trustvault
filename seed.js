"use strict";

// Creates the first admin, one owner and one viewer, plus a sample document.
// Does nothing if any user already exists, so it is safe to run more than once.
//
//   SEED_ADMIN_PASSWORD, SEED_OWNER_PASSWORD, SEED_VIEWER_PASSWORD
//     Optional. If unset, a random password is generated and printed once.

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { createApp } = require("./src/app");
const { hashPassword, sha256 } = require("./src/security");
const audit = require("./src/audit");
const { tx } = require("./src/db");

const ACCOUNTS = [
  { role: "admin", email: "admin@trustvault.example", name: "Workspace Admin", env: "SEED_ADMIN_PASSWORD" },
  { role: "owner", email: "owner@trustvault.example", name: "Demo Owner", env: "SEED_OWNER_PASSWORD" },
  { role: "viewer", email: "viewer@trustvault.example", name: "Demo Viewer", env: "SEED_VIEWER_PASSWORD" },
];

function randomPassword() {
  return crypto.randomBytes(12).toString("base64url");
}

async function main() {
  const app = createApp({
    dbPath: process.env.TV_DB || path.join(__dirname, "data", "trustvault.db"),
    uploadDir: process.env.TV_UPLOADS || path.join(__dirname, "uploads"),
  });
  const db = app.db;

  try {
    if (db.prepare("SELECT COUNT(*) AS n FROM users").get().n > 0) {
      console.log("Accounts already exist. Nothing was changed.");
      return;
    }

    const printed = [];
    const created = {};
    const ts = new Date().toISOString();

    for (const account of ACCOUNTS) {
      const password = process.env[account.env] || randomPassword();
      if (password.length < 12) throw new Error(`${account.env} must be at least 12 characters.`);
      const id = crypto.randomUUID();
      created[account.role] = id;
      db.prepare("INSERT INTO users (id, email, name, role, password_hash, active, created_at) VALUES (?, ?, ?, ?, ?, 1, ?)")
        .run(id, account.email, account.name, account.role, await hashPassword(password), ts);
      if (!process.env[account.env]) printed.push([account, password]);
    }

    // Sample document, owned by the owner account, readable by the viewer account.
    const content = Buffer.from(
      "Sample HR letter.\nThis file is visible to the owner and to the viewer account only.\n",
      "utf8"
    );
    const storedName = crypto.randomBytes(24).toString("hex");
    const docId = crypto.randomUUID();
    fs.mkdirSync(app.config.uploadDir, { recursive: true });
    fs.writeFileSync(path.join(app.config.uploadDir, storedName), content, { flag: "wx", mode: 0o600 });

    tx(db, () => {
      db.prepare(
        `INSERT INTO documents (id, owner_id, title, category, original_name, stored_name, mime, size, sha256, created_at, updated_at)
         VALUES (?, ?, 'Sample HR letter', 'HR', 'sample-hr-letter.txt', ?, 'text/plain; charset=utf-8', ?, ?, ?, ?)`
      ).run(docId, created.owner, storedName, content.length, sha256(content), ts, ts);
      db.prepare(
        "INSERT INTO grants (id, document_id, user_id, permission, granted_by, created_at) VALUES (?, ?, ?, 'read', ?, ?)"
      ).run(crypto.randomUUID(), docId, created.viewer, created.owner, ts);
      audit.record(db, {
        actor: { id: created.owner, email: "owner@trustvault.example" },
        action: "seed.create", entityType: "document", entityId: docId, outcome: "allowed",
        details: { note: "sample data" },
      });
    });

    console.log("Created accounts:");
    for (const account of ACCOUNTS) {
      const pw = printed.find(([a]) => a.role === account.role);
      console.log(`  ${account.role.padEnd(7)} ${account.email}${pw ? `  password: ${pw[1]}` : "  (password from environment)"}`);
    }
    console.log("Store these passwords now. They are not shown again.");
  } finally {
    app.close();
  }
}

main().catch((err) => {
  console.error(err.message);
  process.exit(1);
});
