"use strict";

const path = require("node:path");

const MAX_BYTES = 10 * 1024 * 1024;

// The server decides the MIME type from the validated extension. The client's Content-Type is ignored.
const TYPES = Object.freeze({
  pdf: { mime: "application/pdf", signatures: [Buffer.from("%PDF-", "ascii")] },
  png: { mime: "image/png", signatures: [Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])] },
  jpg: { mime: "image/jpeg", signatures: [Buffer.from([0xff, 0xd8, 0xff])] },
  txt: { mime: "text/plain; charset=utf-8", signatures: null },
});

function extensionOf(filename) {
  return path.extname(String(filename)).slice(1).toLowerCase();
}

// Returns null if the extension is not allowed, otherwise true or false for whether the bytes match.
function checkContent(ext, buffer) {
  const type = TYPES[ext];
  if (!type) return null;
  if (buffer.length === 0) return false;
  if (type.signatures) {
    return type.signatures.some((sig) => buffer.subarray(0, sig.length).equals(sig));
  }
  if (buffer.includes(0)) return false;
  try {
    new TextDecoder("utf-8", { fatal: true }).decode(buffer);
    return true;
  } catch {
    return false;
  }
}

// Display-only name. It is never used as a filesystem path.
function displayName(filename) {
  const base = path.basename(String(filename).replace(/\\/g, "/"));
  const cleaned = base.replace(/[^A-Za-z0-9._()-]/g, "_").slice(0, 200);
  return cleaned || "document";
}

function contentDisposition(filename) {
  const ascii = displayName(filename).replace(/"/g, "");
  return `attachment; filename="${ascii}"; filename*=UTF-8''${encodeURIComponent(filename)}`;
}

module.exports = { MAX_BYTES, TYPES, extensionOf, checkContent, displayName, contentDisposition };
