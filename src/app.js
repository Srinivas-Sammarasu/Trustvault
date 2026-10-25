"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const http = require("node:http");

const db_ = require("./db");
const { tx } = db_;
const audit = require("./audit");
const { PERM, permissionsFor } = require("./authz");
const files = require("./files");
const sec = require("./security");
const {
  HttpError,
  createRouter,
  readBody,
  readJson,
  sendJson,
  sendFile,
  parseCookies,
  serveStatic,
} = require("./http");

const CATEGORIES = ["HR", "Contracts", "Finance", "Legal", "Engineering", "Other"];
const ROLES = ["admin", "owner", "viewer"];
const COOKIE = "tv_session";
const SESSION_HOURS = 8;
const MIN_PASSWORD = 12;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
const SHARE_PATH_RE = /^\/share\/[A-Za-z0-9_-]+$/;
const PASSCODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // no 0/O or 1/I/L

const DOC_SELECT =
  "SELECT d.*, u.email AS owner_email, u.name AS owner_name FROM documents d JOIN users u ON u.id = d.owner_id";

function createApp(options = {}) {
  const cfg = {
    dbPath: options.dbPath ?? path.join(__dirname, "..", "data", "trustvault.db"),
    uploadDir: options.uploadDir ?? path.join(__dirname, "..", "uploads"),
    publicUrl: options.publicUrl ?? process.env.TV_PUBLIC_URL ?? "",
    trustProxy: options.trustProxy ?? process.env.TV_TRUST_PROXY === "1",
    cookieSecure:
      options.cookieSecure ?? (process.env.TV_COOKIE_SECURE ?? (process.env.NODE_ENV === "production" ? "1" : "0")) === "1",
  };

  fs.mkdirSync(cfg.uploadDir, { recursive: true });
  if (cfg.dbPath !== ":memory:") fs.mkdirSync(path.dirname(cfg.dbPath), { recursive: true });
  const db = db_.open(cfg.dbPath);

  const loginLimiter = sec.createLimiter({ max: 5, windowMs: 15 * 60e3, lockMs: 15 * 60e3 });
  const passcodeLimiter = sec.createLimiter({ max: 5, windowMs: 15 * 60e3, lockMs: 30 * 60e3 });
  const router = createRouter();

  // ---------- helpers ----------

  const now = () => new Date().toISOString();
  const addHours = (h) => new Date(Date.now() + h * 3600e3).toISOString();

  function clean(value, max) {
    return String(value ?? "").replace(/[\u0000-\u001f\u007f]/g, " ").trim().slice(0, max);
  }

  function normalizeEmail(value) {
    const email = String(value ?? "").trim().toLowerCase().slice(0, 254);
    return EMAIL_RE.test(email) ? email : null;
  }

  function clampInt(value, min, max, fallback) {
    const n = Number(value);
    if (value === undefined || value === null || value === "" || !Number.isFinite(n)) return fallback;
    return Math.min(max, Math.max(min, Math.trunc(n)));
  }

  function validDate(value) {
    if (!DATE_RE.test(value) || Number.isNaN(Date.parse(`${value}T00:00:00Z`))) {
      throw new HttpError(400, "Dates must use the form YYYY-MM-DD.");
    }
    return value;
  }

  function nextDay(value) {
    return new Date(Date.parse(`${value}T00:00:00Z`) + 86400000).toISOString().slice(0, 10);
  }

  function escapeLike(value) {
    return value.replace(/[\\%_]/g, "\\$&");
  }

  function clientIp(req) {
    if (cfg.trustProxy) {
      const forwarded = String(req.headers["x-forwarded-for"] || "").split(",")[0].trim();
      if (forwarded) return forwarded;
    }
    return req.socket.remoteAddress || "unknown";
  }

  function publicUser(u) {
    return { id: u.id, email: u.email, name: u.name, role: u.role, active: Boolean(u.active) };
  }

  function docView(d, perms) {
    return {
      id: d.id,
      title: d.title,
      category: d.category,
      originalName: d.original_name,
      mime: d.mime,
      size: d.size,
      sha256: d.sha256,
      createdAt: d.created_at,
      updatedAt: d.updated_at,
      deletedAt: d.deleted_at,
      owner: { id: d.owner_id, email: d.owner_email, name: d.owner_name },
      permissions: [...perms].sort(),
    };
  }

  function storedPathFor(storedName) {
    return path.join(cfg.uploadDir, path.basename(storedName));
  }

  function requireUser(ctx) {
    if (!ctx.user) throw new HttpError(401, "Please sign in to continue.");
    return ctx.user;
  }

  function requireRole(ctx, ...roles) {
    requireUser(ctx);
    if (!roles.includes(ctx.user.role)) {
      audit.record(db, {
        actor: ctx.user, action: "access.role_denied", entityType: "route",
        entityId: ctx.path, outcome: "denied", details: { required: roles },
      });
      throw new HttpError(403, "Your role does not allow this action.");
    }
  }

  // The one gate for every document route.
  // A user with no permission gets 404, the same as for a document that does not exist,
  // so the API does not reveal which document IDs exist. A user who can see the document
  // but lacks this permission gets 403. Every refusal is written to the audit log.
  function requireDoc(ctx, id, perm, action) {
    // Log anonymous document access attempts too. Authentication must not be a
    // blind spot in the evidence trail for requests aimed at protected resources.
    if (!ctx.user) {
      audit.record(db, {
        actor: null, action, entityType: "document", entityId: id,
        outcome: "denied", details: { required: perm, reason: "unauthenticated" },
      });
      throw new HttpError(401, "Please sign in to continue.");
    }
    const doc = db.prepare(`${DOC_SELECT} WHERE d.id = ?`).get(id);
    const perms = permissionsFor(db, ctx.user, doc);
    if (doc && perms.has(perm)) return { doc, perms };
    audit.record(db, {
      actor: ctx.user, action, entityType: "document", entityId: id,
      outcome: "denied", details: { required: perm },
    });
    if (perms.size === 0) throw new HttpError(404, "Document not found.");
    throw new HttpError(403, "Your access to this document does not allow this action.");
  }

  function requireLive(doc) {
    if (doc.deleted_at) throw new HttpError(409, "This document is in the trash. Restore it first.");
  }

  function sessionUser(req) {
    const token = parseCookies(req.headers.cookie)[COOKIE];
    if (!token) return null;
    return (
      db
        .prepare(
          `SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id
           WHERE s.token_hash = ? AND s.expires_at > ? AND u.active = 1`
        )
        .get(sec.sha256(token), now()) || null
    );
  }

  function checkOrigin(req) {
    const origin = req.headers.origin;
    if (!origin) return;
    const allowed = new Set([`http://${req.headers.host}`, `https://${req.headers.host}`]);
    if (cfg.publicUrl) allowed.add(new URL(cfg.publicUrl).origin);
    if (!allowed.has(origin)) throw new HttpError(403, "Cross-site request refused.");
  }

  function buildCookie(c) {
    const parts = [`${COOKIE}=${encodeURIComponent(c.value)}`, "Path=/", "HttpOnly", "SameSite=Strict", `Max-Age=${c.maxAge}`];
    if (cfg.cookieSecure) parts.push("Secure");
    return parts.join("; ");
  }

  function generatePasscode() {
    let out = "";
    for (let i = 0; i < 10; i += 1) out += PASSCODE_ALPHABET[crypto.randomInt(PASSCODE_ALPHABET.length)];
    return out;
  }

  function headerFilename(req) {
    const raw = req.headers["x-file-name"];
    if (!raw) return "";
    try {
      return decodeURIComponent(String(raw)).slice(0, 255);
    } catch {
      throw new HttpError(400, "The file name is not valid.");
    }
  }

  function findLinkByToken(token) {
    return db
      .prepare(
        `SELECT l.*, d.title, d.original_name, d.size, d.mime, d.stored_name, d.deleted_at AS doc_deleted
         FROM share_links l JOIN documents d ON d.id = l.document_id WHERE l.token_hash = ?`
      )
      .get(sec.sha256(token));
  }

  function linkUsable(link) {
    return Boolean(
      link && !link.revoked_at && !link.doc_deleted &&
      link.expires_at > now() && link.download_count < link.max_downloads
    );
  }

  // ---------- auth ----------

  router.add("POST", "/api/auth/login", async (ctx) => {
    const body = await readJson(ctx.req);
    const email = normalizeEmail(body.email) ?? "";
    const password = String(body.password ?? "").slice(0, 1024);
    const key = `${email}|${clientIp(ctx.req)}`;
    if (loginLimiter.isLocked(key)) {
      throw new HttpError(429, "Too many failed sign-in attempts. Try again in 15 minutes.");
    }

    const user = email ? db.prepare("SELECT * FROM users WHERE email = ?").get(email) : undefined;
    const ok = await sec.verifyPassword(password, user ? user.password_hash : sec.DUMMY_HASH);
    if (!user || !user.active || !ok) {
      loginLimiter.fail(key);
      audit.record(db, {
        actor: { id: user?.id ?? null, email: email || "unknown" },
        action: "auth.login", entityType: "user", entityId: user?.id ?? null,
        outcome: "failed", details: { reason: user ? (user.active ? "password" : "inactive") : "unknown_email" },
      });
      throw new HttpError(401, "Invalid email or password.");
    }

    loginLimiter.reset(key);
    const token = sec.newToken();
    tx(db, () => {
      db.prepare("DELETE FROM sessions WHERE expires_at <= ?").run(now());
      db.prepare("INSERT INTO sessions (token_hash, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)")
        .run(sec.sha256(token), user.id, now(), addHours(SESSION_HOURS));
      audit.record(db, { actor: user, action: "auth.login", entityType: "user", entityId: user.id, outcome: "allowed" });
    });
    ctx.cookie = { value: token, maxAge: SESSION_HOURS * 3600 };
    return { body: { user: publicUser(user) } };
  });

  router.add("POST", "/api/auth/logout", (ctx) => {
    const token = parseCookies(ctx.req.headers.cookie)[COOKIE];
    tx(db, () => {
      if (token) db.prepare("DELETE FROM sessions WHERE token_hash = ?").run(sec.sha256(token));
      if (ctx.user) {
        audit.record(db, { actor: ctx.user, action: "auth.logout", entityType: "user", entityId: ctx.user.id, outcome: "allowed" });
      }
    });
    ctx.cookie = { value: "", maxAge: 0 };
    return { body: { ok: true } };
  });

  router.add("GET", "/api/me", (ctx) => {
    requireUser(ctx);
    return { body: { user: publicUser(ctx.user) } };
  });

  // ---------- documents ----------

  router.add("GET", "/api/documents", (ctx) => {
    requireUser(ctx);
    const q = clean(ctx.query.get("q"), 120);
    const category = ctx.query.get("category") ?? "";
    const owner = normalizeEmail(ctx.query.get("owner") ?? "");
    const from = ctx.query.get("from") ?? "";
    const to = ctx.query.get("to") ?? "";

    // Only documents the caller owns or holds a grant on. Search never sees the rest.
    const where = [
      "d.deleted_at IS NULL",
      "(d.owner_id = ? OR EXISTS (SELECT 1 FROM grants g WHERE g.document_id = d.id AND g.user_id = ? AND g.revoked_at IS NULL))",
    ];
    const args = [ctx.user.id, ctx.user.id];
    if (q) {
      where.push("d.title LIKE ? ESCAPE '\\'");
      args.push(`%${escapeLike(q)}%`);
    }
    if (category) {
      if (!CATEGORIES.includes(category)) throw new HttpError(400, "Choose a valid category.");
      where.push("d.category = ?");
      args.push(category);
    }
    if (owner) {
      where.push("u.email = ?");
      args.push(owner);
    }
    if (from) {
      where.push("d.created_at >= ?");
      args.push(`${validDate(from)}T00:00:00`);
    }
    if (to) {
      where.push("d.created_at < ?");
      args.push(`${nextDay(validDate(to))}T00:00:00`);
    }

    const rows = db
      .prepare(`${DOC_SELECT} WHERE ${where.join(" AND ")} ORDER BY d.created_at DESC LIMIT 200`)
      .all(...args);
    return { body: { documents: rows.map((r) => docView(r, permissionsFor(db, ctx.user, r))) } };
  });

  router.add("POST", "/api/documents", async (ctx) => {
    requireRole(ctx, "owner");
    const title = clean(ctx.query.get("title"), 120);
    const category = ctx.query.get("category") ?? "";
    const filename = headerFilename(ctx.req);
    if (!title) throw new HttpError(400, "Enter a title for the document.");
    if (!CATEGORIES.includes(category)) throw new HttpError(400, "Choose a valid category.");
    if (!filename) throw new HttpError(400, "The file name is missing.");

    const ext = files.extensionOf(filename);
    if (!files.TYPES[ext]) {
      throw new HttpError(400, "File type not allowed. Use PDF, PNG, JPG or TXT.");
    }
    const buffer = await readBody(ctx.req, files.MAX_BYTES);
    if (files.checkContent(ext, buffer) === false) {
      throw new HttpError(400, "The file content does not match its type.");
    }

    const id = crypto.randomUUID();
    const storedName = crypto.randomBytes(24).toString("hex");
    const storedPath = storedPathFor(storedName);
    fs.writeFileSync(storedPath, buffer, { flag: "wx", mode: 0o600 });
    const ts = now();
    try {
      tx(db, () => {
        db.prepare(
          `INSERT INTO documents (id, owner_id, title, category, original_name, stored_name, mime, size, sha256, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        ).run(id, ctx.user.id, title, category, files.displayName(filename), storedName,
          files.TYPES[ext].mime, buffer.length, sec.sha256(buffer), ts, ts);
        audit.record(db, {
          actor: ctx.user, action: "document.upload", entityType: "document", entityId: id, outcome: "allowed",
          details: { originalName: files.displayName(filename), size: buffer.length, category },
        });
      });
    } catch (err) {
      fs.rmSync(storedPath, { force: true });
      throw err;
    }
    return { status: 201, body: { id } };
  });

  router.add("GET", "/api/documents/:id", (ctx) => {
    const { doc, perms } = requireDoc(ctx, ctx.params.id, PERM.READ, "document.view");
    audit.record(db, { actor: ctx.user, action: "document.view", entityType: "document", entityId: doc.id, outcome: "allowed" });
    return { body: { document: docView(doc, perms) } };
  });

  router.add("PATCH", "/api/documents/:id", async (ctx) => {
    const { doc, perms } = requireDoc(ctx, ctx.params.id, PERM.EDIT, "document.edit");
    requireLive(doc);
    const body = await readJson(ctx.req);
    const title = body.title !== undefined ? clean(body.title, 120) : doc.title;
    const category = body.category !== undefined ? String(body.category) : doc.category;
    if (!title) throw new HttpError(400, "Enter a title for the document.");
    if (!CATEGORIES.includes(category)) throw new HttpError(400, "Choose a valid category.");

    const changes = {};
    if (title !== doc.title) changes.title = { from: doc.title, to: title };
    if (category !== doc.category) changes.category = { from: doc.category, to: category };
    if (Object.keys(changes).length === 0) return { body: { document: docView(doc, perms) } };

    tx(db, () => {
      db.prepare("UPDATE documents SET title = ?, category = ?, updated_at = ? WHERE id = ?").run(title, category, now(), doc.id);
      audit.record(db, { actor: ctx.user, action: "document.edit", entityType: "document", entityId: doc.id, outcome: "allowed", details: changes });
    });
    const updated = db.prepare(`${DOC_SELECT} WHERE d.id = ?`).get(doc.id);
    return { body: { document: docView(updated, permissionsFor(db, ctx.user, updated)) } };
  });

  router.add("GET", "/api/documents/:id/download", (ctx) => {
    const { doc } = requireDoc(ctx, ctx.params.id, PERM.READ, "document.download");
    if (doc.deleted_at) throw new HttpError(410, "This document is in the trash.");
    const filePath = storedPathFor(doc.stored_name);
    if (!fs.existsSync(filePath)) throw new HttpError(404, "The stored file is missing.");
    const buffer = fs.readFileSync(filePath);
    audit.record(db, {
      actor: ctx.user, action: "document.download", entityType: "document", entityId: doc.id, outcome: "allowed",
      details: { originalName: doc.original_name, sha256: doc.sha256 },
    });
    return {
      raw: buffer,
      headers: {
        "Content-Type": doc.mime,
        "Content-Disposition": files.contentDisposition(doc.original_name),
        "X-Content-Type-Options": "nosniff",
      },
    };
  });

  router.add("DELETE", "/api/documents/:id", (ctx) => {
    const { doc } = requireDoc(ctx, ctx.params.id, PERM.DELETE, "document.delete");
    let revoked = 0;
    tx(db, () => {
      db.prepare("UPDATE documents SET deleted_at = ?, updated_at = ? WHERE id = ?").run(now(), now(), doc.id);
      revoked = db.prepare("UPDATE share_links SET revoked_at = ? WHERE document_id = ? AND revoked_at IS NULL")
        .run(now(), doc.id).changes;
      audit.record(db, {
        actor: ctx.user, action: "document.delete", entityType: "document", entityId: doc.id, outcome: "allowed",
        details: { originalName: doc.original_name, shareLinksRevoked: revoked },
      });
    });
    return { body: { ok: true } };
  });

  router.add("POST", "/api/documents/:id/restore", (ctx) => {
    const { doc } = requireDoc(ctx, ctx.params.id, PERM.RESTORE, "document.restore");
    tx(db, () => {
      db.prepare("UPDATE documents SET deleted_at = NULL, updated_at = ? WHERE id = ?").run(now(), doc.id);
      audit.record(db, { actor: ctx.user, action: "document.restore", entityType: "document", entityId: doc.id, outcome: "allowed" });
    });
    return { body: { ok: true } };
  });

  router.add("GET", "/api/documents/:id/activity", (ctx) => {
    const { doc } = requireDoc(ctx, ctx.params.id, PERM.ACTIVITY, "document.activity");
    const rows = db
      .prepare(
        `SELECT ts, actor_email, action, outcome, details FROM audit
         WHERE entity_id = ? OR details LIKE ? ORDER BY seq DESC LIMIT 500`
      )
      .all(doc.id, `%"documentId":"${doc.id}"%`);
    return {
      body: {
        events: rows.map((r) => ({ ts: r.ts, actor: r.actor_email, action: r.action, outcome: r.outcome, details: JSON.parse(r.details) })),
      },
    };
  });

  // ---------- grants (owner only) ----------

  router.add("GET", "/api/documents/:id/grants", (ctx) => {
    requireDoc(ctx, ctx.params.id, PERM.SHARE, "grant.list");
    const rows = db
      .prepare(
        `SELECT g.id, g.permission, g.created_at, g.revoked_at, u.email, u.name
         FROM grants g JOIN users u ON u.id = g.user_id WHERE g.document_id = ? ORDER BY g.created_at DESC`
      )
      .all(ctx.params.id);
    return {
      body: {
        grants: rows.map((r) => ({ id: r.id, email: r.email, name: r.name, permission: r.permission, createdAt: r.created_at, revokedAt: r.revoked_at })),
      },
    };
  });

  router.add("POST", "/api/documents/:id/grants", async (ctx) => {
    const { doc } = requireDoc(ctx, ctx.params.id, PERM.SHARE, "grant.create");
    requireLive(doc);
    const body = await readJson(ctx.req);
    const email = normalizeEmail(body.email);
    const permission = body.permission === "edit" ? "edit" : body.permission === "read" ? "read" : null;
    if (!email) throw new HttpError(400, "Enter a valid email address.");
    if (!permission) throw new HttpError(400, "Permission must be read or edit.");
    const target = db.prepare("SELECT * FROM users WHERE email = ? AND active = 1").get(email);
    if (!target) throw new HttpError(404, "No active user has that email address.");
    if (target.id === doc.owner_id) throw new HttpError(400, "The owner already has full access.");

    const grantId = crypto.randomUUID();
    tx(db, () => {
      db.prepare("UPDATE grants SET revoked_at = ? WHERE document_id = ? AND user_id = ? AND revoked_at IS NULL")
        .run(now(), doc.id, target.id);
      db.prepare("INSERT INTO grants (id, document_id, user_id, permission, granted_by, created_at) VALUES (?, ?, ?, ?, ?, ?)")
        .run(grantId, doc.id, target.id, permission, ctx.user.id, now());
      audit.record(db, {
        actor: ctx.user, action: "grant.create", entityType: "document", entityId: doc.id, outcome: "allowed",
        details: { grantee: target.email, permission, grantId, documentId: doc.id },
      });
    });
    return { status: 201, body: { grant: { id: grantId, email: target.email, permission } } };
  });

  router.add("DELETE", "/api/documents/:id/grants/:grantId", (ctx) => {
    const { doc } = requireDoc(ctx, ctx.params.id, PERM.SHARE, "grant.revoke");
    const grant = db
      .prepare(
        `SELECT g.*, u.email FROM grants g JOIN users u ON u.id = g.user_id
         WHERE g.id = ? AND g.document_id = ?`
      )
      .get(ctx.params.grantId, doc.id);
    if (!grant) throw new HttpError(404, "Grant not found.");
    if (!grant.revoked_at) {
      tx(db, () => {
        db.prepare("UPDATE grants SET revoked_at = ? WHERE id = ?").run(now(), grant.id);
        audit.record(db, {
          actor: ctx.user, action: "grant.revoke", entityType: "document", entityId: doc.id, outcome: "allowed",
          details: { grantee: grant.email, permission: grant.permission, grantId: grant.id, documentId: doc.id },
        });
      });
    }
    return { body: { ok: true } };
  });

  // ---------- share links (owner only) ----------

  router.add("GET", "/api/documents/:id/links", (ctx) => {
    requireDoc(ctx, ctx.params.id, PERM.SHARE, "link.list");
    const rows = db
      .prepare("SELECT * FROM share_links WHERE document_id = ? ORDER BY created_at DESC")
      .all(ctx.params.id);
    return {
      body: {
        links: rows.map((l) => ({
          id: l.id,
          label: l.label,
          createdAt: l.created_at,
          expiresAt: l.expires_at,
          maxDownloads: l.max_downloads,
          downloadCount: l.download_count,
          revokedAt: l.revoked_at,
          active: linkUsable({ ...l, doc_deleted: null }),
        })),
      },
    };
  });

  router.add("POST", "/api/documents/:id/links", async (ctx) => {
    const { doc } = requireDoc(ctx, ctx.params.id, PERM.SHARE, "link.create");
    requireLive(doc);
    const body = await readJson(ctx.req);
    const label = clean(body.label, 80) || "Shared link";
    const hours = clampInt(body.expiresHours, 1, 168, 24);
    const maxDownloads = clampInt(body.maxDownloads, 1, 50, 1);
    const generated = body.passcode === undefined || body.passcode === "";
    const passcode = generated ? generatePasscode() : String(body.passcode);
    if (passcode.length < 6 || passcode.length > 64) {
      throw new HttpError(400, "The passcode must be 6 to 64 characters.");
    }

    const token = sec.newToken();
    const linkId = crypto.randomUUID();
    const expiresAt = addHours(hours);
    const passcodeHash = await sec.hashPassword(passcode);
    tx(db, () => {
      db.prepare(
        `INSERT INTO share_links (id, document_id, token_hash, passcode_hash, label, created_by, created_at, expires_at, max_downloads)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
      ).run(linkId, doc.id, sec.sha256(token), passcodeHash, label, ctx.user.id, now(), expiresAt, maxDownloads);
      audit.record(db, {
        actor: ctx.user, action: "link.create", entityType: "share_link", entityId: linkId, outcome: "allowed",
        details: { documentId: doc.id, label, expiresAt, maxDownloads },
      });
    });

    const base = cfg.publicUrl || `${ctx.req.socket.encrypted ? "https" : "http"}://${ctx.req.headers.host}`;
    return {
      status: 201,
      body: {
        link: { id: linkId, label, expiresAt, maxDownloads, url: `${base}/share/${token}` },
        // Shown once. Only the hash is stored.
        passcode: generated ? passcode : undefined,
      },
    };
  });

  router.add("POST", "/api/links/:id/revoke", (ctx) => {
    const link = db.prepare("SELECT * FROM share_links WHERE id = ?").get(ctx.params.id);
    const { doc } = requireDoc(ctx, link ? link.document_id : ctx.params.id, PERM.SHARE, "link.revoke");
    if (link && !link.revoked_at) {
      tx(db, () => {
        db.prepare("UPDATE share_links SET revoked_at = ? WHERE id = ?").run(now(), link.id);
        audit.record(db, {
          actor: ctx.user, action: "link.revoke", entityType: "share_link", entityId: link.id, outcome: "allowed",
          details: { documentId: doc.id, label: link.label },
        });
      });
    }
    return { body: { ok: true } };
  });

  // ---------- public share links (anyone with the link and passcode) ----------

  router.add("GET", "/api/public/links/:token", (ctx) => {
    const link = findLinkByToken(ctx.params.token);
    if (!linkUsable(link)) {
      if (link) audit.record(db, { actor: null, action: "link.view", entityType: "share_link", entityId: link.id, outcome: "denied", details: { documentId: link.document_id } });
      throw new HttpError(410, "This link is no longer available.");
    }
    // The URL token alone is not sufficient to disclose document metadata.
    // Return only a generic state here; the passcode-protected download returns
    // the filename in Content-Disposition after successful verification.
    audit.record(db, { actor: null, action: "link.view", entityType: "share_link", entityId: link.id, outcome: "allowed", details: { metadataWithheld: true } });
    return { body: { requiresPasscode: true, message: "This is a password-protected document." } };
  });

  router.add("POST", "/api/public/links/:token/download", async (ctx) => {
    const token = ctx.params.token;
    const key = `link:${sec.sha256(token)}`;
    if (passcodeLimiter.isLocked(key)) {
      throw new HttpError(429, "Too many incorrect passcodes. Try again later.");
    }
    const link = findLinkByToken(token);
    if (!linkUsable(link)) {
      if (link) audit.record(db, { actor: null, action: "link.download", entityType: "share_link", entityId: link.id, outcome: "denied", details: { reason: "unusable", documentId: link.document_id } });
      throw new HttpError(410, "This link is no longer available.");
    }

    const body = await readJson(ctx.req);
    const passcode = String(body.passcode ?? "").slice(0, 128);
    if (!(await sec.verifyPassword(passcode, link.passcode_hash))) {
      passcodeLimiter.fail(key);
      audit.record(db, { actor: null, action: "link.download", entityType: "share_link", entityId: link.id, outcome: "denied", details: { reason: "passcode", documentId: link.document_id } });
      throw new HttpError(403, "That passcode is not correct.");
    }
    passcodeLimiter.reset(key);

    const storedPath = storedPathFor(link.stored_name);
    if (!fs.existsSync(storedPath)) throw new HttpError(404, "The stored file is missing.");
    const buffer = fs.readFileSync(storedPath);

    // Consume one download atomically. Two simultaneous requests cannot both use the last one.
    const consumed = tx(db, () => {
      const result = db
        .prepare(
          `UPDATE share_links SET download_count = download_count + 1
           WHERE id = ? AND download_count < max_downloads AND revoked_at IS NULL AND expires_at > ?`
        )
        .run(link.id, now());
      if (result.changes !== 1) return false;
      audit.record(db, {
        actor: null, action: "link.download", entityType: "share_link", entityId: link.id, outcome: "allowed",
        details: { documentId: link.document_id, originalName: link.original_name },
      });
      return true;
    });
    if (!consumed) throw new HttpError(410, "This link is no longer available.");

    return {
      raw: buffer,
      headers: {
        "Content-Type": link.mime,
        "Content-Disposition": files.contentDisposition(link.original_name),
        "X-Content-Type-Options": "nosniff",
      },
    };
  });

  // ---------- admin ----------

  router.add("GET", "/api/admin/users", (ctx) => {
    requireRole(ctx, "admin");
    const rows = db.prepare("SELECT * FROM users ORDER BY created_at").all();
    return { body: { users: rows.map(publicUser) } };
  });

  router.add("POST", "/api/admin/users", async (ctx) => {
    requireRole(ctx, "admin");
    const body = await readJson(ctx.req);
    const email = normalizeEmail(body.email);
    const name = clean(body.name, 80);
    const role = String(body.role ?? "");
    const password = String(body.password ?? "");
    if (!email) throw new HttpError(400, "Enter a valid email address.");
    if (!name) throw new HttpError(400, "Enter the user's name.");
    if (!ROLES.includes(role)) throw new HttpError(400, "Choose a valid role.");
    if (password.length < MIN_PASSWORD) throw new HttpError(400, `The password must be at least ${MIN_PASSWORD} characters.`);
    if (db.prepare("SELECT 1 FROM users WHERE email = ?").get(email)) throw new HttpError(409, "That email address already has an account.");

    const user = { id: crypto.randomUUID(), email, name, role, hash: await sec.hashPassword(password) };
    tx(db, () => {
      db.prepare("INSERT INTO users (id, email, name, role, password_hash, active, created_at) VALUES (?, ?, ?, ?, ?, 1, ?)")
        .run(user.id, user.email, user.name, user.role, user.hash, now());
      audit.record(db, {
        actor: ctx.user, action: "user.create", entityType: "user", entityId: user.id, outcome: "allowed",
        details: { email, role },
      });
    });
    return { status: 201, body: { user: { id: user.id, email, name, role, active: true } } };
  });

  router.add("PATCH", "/api/admin/users/:id", async (ctx) => {
    requireRole(ctx, "admin");
    const target = db.prepare("SELECT * FROM users WHERE id = ?").get(ctx.params.id);
    if (!target) throw new HttpError(404, "User not found.");
    const body = await readJson(ctx.req);
    const changes = {};
    if (body.role !== undefined) {
      if (!ROLES.includes(body.role)) throw new HttpError(400, "Choose a valid role.");
      if (body.role !== target.role) changes.role = { from: target.role, to: body.role };
    }
    if (body.active !== undefined) {
      if (typeof body.active !== "boolean") throw new HttpError(400, "Active must be true or false.");
      if (Boolean(target.active) !== body.active) changes.active = { from: Boolean(target.active), to: body.active };
    }
    if (target.id === ctx.user.id && (changes.role || (changes.active && changes.active.to === false))) {
      throw new HttpError(400, "You cannot change your own role or deactivate your own account.");
    }
    if (Object.keys(changes).length === 0) return { body: { user: publicUser(target) } };

    tx(db, () => {
      if (changes.role) db.prepare("UPDATE users SET role = ? WHERE id = ?").run(changes.role.to, target.id);
      if (changes.active) {
        db.prepare("UPDATE users SET active = ? WHERE id = ?").run(changes.active.to ? 1 : 0, target.id);
        if (!changes.active.to) db.prepare("DELETE FROM sessions WHERE user_id = ?").run(target.id);
      }
      audit.record(db, {
        actor: ctx.user, action: "user.update", entityType: "user", entityId: target.id, outcome: "allowed",
        details: { email: target.email, ...changes },
      });
    });
    const updated = db.prepare("SELECT * FROM users WHERE id = ?").get(target.id);
    return { body: { user: publicUser(updated) } };
  });

  router.add("GET", "/api/admin/documents", (ctx) => {
    requireRole(ctx, "admin");
    const rows = db
      .prepare(
        `SELECT d.id, d.title, d.category, d.original_name, d.size, d.created_at, d.deleted_at,
                u.email AS owner_email,
                (SELECT COUNT(*) FROM grants g WHERE g.document_id = d.id AND g.revoked_at IS NULL) AS active_grants,
                (SELECT COUNT(*) FROM share_links l WHERE l.document_id = d.id AND l.revoked_at IS NULL
                   AND l.expires_at > ? AND l.download_count < l.max_downloads) AS active_links
         FROM documents d JOIN users u ON u.id = d.owner_id ORDER BY d.created_at DESC`
      )
      .all(now());
    // Metadata only. Admins see who holds what, never the file contents.
    return {
      body: {
        documents: rows.map((r) => ({
          id: r.id, title: r.title, category: r.category, originalName: r.original_name, size: r.size,
          createdAt: r.created_at, deletedAt: r.deleted_at, owner: r.owner_email,
          activeGrants: r.active_grants, activeLinks: r.active_links,
        })),
      },
    };
  });

  function auditRows(params) {
    const where = [];
    const args = [];
    if (params.action) {
      where.push("action = ?");
      args.push(params.action);
    }
    if (params.outcome) {
      where.push("outcome = ?");
      args.push(params.outcome);
    }
    const sql = `SELECT * FROM audit ${where.length ? `WHERE ${where.join(" AND ")}` : ""} ORDER BY seq DESC LIMIT ?`;
    return db.prepare(sql).all(...args, params.limit);
  }

  router.add("GET", "/api/admin/audit", (ctx) => {
    requireRole(ctx, "admin");
    const rows = auditRows({
      action: clean(ctx.query.get("action"), 60),
      outcome: ["allowed", "denied", "failed"].includes(ctx.query.get("outcome")) ? ctx.query.get("outcome") : "",
      limit: clampInt(ctx.query.get("limit"), 1, 500, 200),
    });
    return {
      body: {
        events: rows.map((r) => ({
          seq: r.seq, ts: r.ts, actor: r.actor_email, action: r.action, entityType: r.entity_type,
          entityId: r.entity_id, outcome: r.outcome, details: JSON.parse(r.details), hash: r.hash,
        })),
      },
    };
  });

  router.add("GET", "/api/admin/audit/verify", (ctx) => {
    requireRole(ctx, "admin");
    return { body: audit.verify(db) };
  });

  // The latest hash is what you copy to storage the admin does not control. See README.
  router.add("GET", "/api/admin/audit/anchor", (ctx) => {
    requireRole(ctx, "admin");
    const result = audit.verify(db);
    const last = db.prepare("SELECT seq, ts, hash FROM audit ORDER BY seq DESC LIMIT 1").get();
    return {
      body: {
        valid: result.valid,
        entries: result.checked,
        latestSeq: last ? last.seq : null,
        latestAt: last ? last.ts : null,
        latestHash: last ? last.hash : audit.GENESIS,
        generatedAt: now(),
      },
    };
  });

  router.add("GET", "/api/admin/audit/export.csv", (ctx) => {
    requireRole(ctx, "admin");
    audit.record(db, { actor: ctx.user, action: "audit.export", entityType: "audit", outcome: "allowed" });
    const rows = db.prepare("SELECT * FROM audit ORDER BY seq").all();
    // Cells that start with a formula character are prefixed, so spreadsheet software will not run them.
    const cell = (v) => {
      let s = String(v ?? "");
      if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
      return `"${s.replace(/"/g, '""')}"`;
    };
    const header = ["seq", "ts", "actor", "action", "entity_type", "entity_id", "outcome", "details", "hash"];
    const lines = [header.join(",")].concat(
      rows.map((r) => [r.seq, r.ts, r.actor_email, r.action, r.entity_type, r.entity_id, r.outcome, r.details, r.hash].map(cell).join(","))
    );
    return {
      raw: Buffer.from(lines.join("\r\n"), "utf8"),
      headers: {
        "Content-Type": "text/csv; charset=utf-8",
        "Content-Disposition": 'attachment; filename="trustvault-audit.csv"',
      },
    };
  });

  router.add("GET", "/api/health", () => ({ body: { ok: true, service: "TrustVault" } }));

  // ---------- dispatcher ----------

  async function handle(req, res) {
    const url = new URL(req.url, "http://localhost");
    const pathname = url.pathname;
    try {
      if (!pathname.startsWith("/api/")) {
        if (req.method !== "GET" && req.method !== "HEAD") throw new HttpError(405, "Method not allowed.");
        if (SHARE_PATH_RE.test(pathname)) return await serveStatic(res, "/share.html");
        return await serveStatic(res, pathname);
      }

      const match = router.match(req.method, pathname);
      if (!match) throw new HttpError(404, "API route not found.");

      const unsafe = req.method !== "GET" && req.method !== "HEAD";
      if (unsafe) {
        // Browsers cannot add a custom header in a cross-site form post, so this header blocks CSRF.
        if (req.headers["x-trustvault"] !== "1") throw new HttpError(403, "Missing required request header.");
        checkOrigin(req);
      }

      const ctx = {
        req, res, path: pathname, params: match.params, query: url.searchParams,
        user: sessionUser(req), cookie: null,
      };
      const result = (await match.handler(ctx)) || { status: 204 };
      if (ctx.cookie) res.setHeader("Set-Cookie", buildCookie(ctx.cookie));
      if (result.raw) return sendFile(res, 200, result.raw, result.headers || {});
      return sendJson(res, result.status || 200, result.body ?? {});
    } catch (err) {
      if (err instanceof HttpError) {
        if (!res.headersSent) sendJson(res, err.status, { error: err.message });
        return undefined;
      }
      console.error("[trustvault] unexpected error:", err);
      if (!res.headersSent) sendJson(res, 500, { error: "Unexpected server error." });
      return undefined;
    }
  }

  const server = http.createServer((req, res) => {
    handle(req, res);
  });

  return {
    server,
    db,
    config: cfg,
    close() {
      server.close();
      db.close();
    },
  };
}

module.exports = { createApp, CATEGORIES, ROLES };
