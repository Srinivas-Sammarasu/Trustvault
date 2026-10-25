"use strict";

const crypto = require("node:crypto");
const { promisify } = require("node:util");

const scryptAsync = promisify(crypto.scrypt);
const KEY_LENGTH = 64;

async function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const key = await scryptAsync(password, salt, KEY_LENGTH);
  return `scrypt$${salt}$${key.toString("hex")}`;
}

async function verifyPassword(password, stored) {
  const [scheme, salt, hex] = String(stored).split("$");
  if (scheme !== "scrypt" || !salt || !hex) return false;
  const expected = Buffer.from(hex, "hex");
  const actual = await scryptAsync(password, salt, KEY_LENGTH);
  return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
}

// Used when the email is unknown, so unknown and wrong-password logins take the same time.
const DUMMY_HASH = (() => {
  const salt = crypto.randomBytes(16).toString("hex");
  return `scrypt$${salt}$${crypto.scryptSync("not-a-real-password", salt, KEY_LENGTH).toString("hex")}`;
})();

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function newToken() {
  return crypto.randomBytes(32).toString("base64url");
}

// Failed attempts are counted per key. After `max` failures in `windowMs`, the key is locked for `lockMs`.
// State is in memory: a restart clears it, and it is per process. Documented in THREATS.md.
function createLimiter({ max, windowMs, lockMs }) {
  const buckets = new Map();
  return {
    isLocked(key) {
      const b = buckets.get(key);
      return Boolean(b && b.lockedUntil > Date.now());
    },
    fail(key) {
      const now = Date.now();
      let b = buckets.get(key);
      if (!b || now - b.first > windowMs) {
        b = { count: 0, first: now, lockedUntil: 0 };
        buckets.set(key, b);
      }
      b.count += 1;
      if (b.count >= max) b.lockedUntil = now + lockMs;
    },
    reset(key) {
      buckets.delete(key);
    },
  };
}

module.exports = { hashPassword, verifyPassword, DUMMY_HASH, sha256, newToken, createLimiter };
