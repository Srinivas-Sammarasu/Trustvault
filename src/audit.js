"use strict";

const crypto = require("node:crypto");

const GENESIS = "0".repeat(64);

// Field order here is part of the format. Changing it invalidates every stored hash.
function canonical(r) {
  return JSON.stringify([
    r.id, r.ts, r.actor_id, r.actor_email, r.action,
    r.entity_type, r.entity_id, r.outcome, r.details, r.prev_hash,
  ]);
}

function digest(r) {
  return crypto.createHash("sha256").update(canonical(r)).digest("hex");
}

function record(db, { actor, action, entityType, entityId = null, outcome, details = {} }) {
  const last = db.prepare("SELECT hash FROM audit ORDER BY seq DESC LIMIT 1").get();
  const row = {
    id: crypto.randomUUID(),
    ts: new Date().toISOString(),
    actor_id: actor?.id ?? null,
    actor_email: String(actor?.email ?? "anonymous").slice(0, 200),
    action,
    entity_type: entityType,
    entity_id: entityId,
    outcome,
    details: JSON.stringify(details),
    prev_hash: last ? last.hash : GENESIS,
  };
  row.hash = digest(row);
  db.prepare(
    `INSERT INTO audit (id, ts, actor_id, actor_email, action, entity_type, entity_id,
                        outcome, details, prev_hash, hash)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(row.id, row.ts, row.actor_id, row.actor_email, row.action, row.entity_type,
        row.entity_id, row.outcome, row.details, row.prev_hash, row.hash);
}

function verify(db) {
  let prev = GENESIS;
  let checked = 0;
  for (const r of db.prepare("SELECT * FROM audit ORDER BY seq").all()) {
    checked += 1;
    if (r.prev_hash !== prev || digest(r) !== r.hash) {
      return { valid: false, brokenAt: r.seq, checked };
    }
    prev = r.hash;
  }
  return { valid: true, brokenAt: null, checked, latestHash: prev };
}

module.exports = { record, verify, GENESIS };
