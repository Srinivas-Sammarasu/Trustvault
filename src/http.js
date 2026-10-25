"use strict";

const fs = require("node:fs");
const path = require("node:path");

const PUBLIC_DIR = path.join(__dirname, "..", "public");
const JSON_LIMIT = 64 * 1024;

const SECURITY_HEADERS = Object.freeze({
  "Content-Security-Policy":
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; " +
    "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  // Share links carry a secret in the URL. No-referrer stops it leaking to other sites.
  "Referrer-Policy": "no-referrer",
  "Cross-Origin-Opener-Policy": "same-origin",
});

const API_HEADERS = Object.freeze({ ...SECURITY_HEADERS, "Cache-Control": "no-store" });

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

function compile(pattern) {
  const keys = [];
  const source = pattern.replace(/:([A-Za-z]+)/g, (_, key) => {
    keys.push(key);
    return "([^/]+)";
  });
  return { re: new RegExp(`^${source}$`), keys };
}

function createRouter() {
  const routes = [];
  return {
    add(method, pattern, handler) {
      routes.push({ method, ...compile(pattern), handler });
    },
    match(method, pathname) {
      for (const route of routes) {
        if (route.method !== method) continue;
        const m = route.re.exec(pathname);
        if (!m) continue;
        const params = {};
        route.keys.forEach((key, i) => {
          params[key] = decodeURIComponent(m[i + 1]);
        });
        return { handler: route.handler, params };
      }
      return null;
    },
  };
}

function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    let failed = false;
    req.on("data", (chunk) => {
      if (failed) return;
      size += chunk.length;
      if (size > limit) {
        failed = true;
        reject(new HttpError(413, "Request is too large."));
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => {
      if (!failed) resolve(Buffer.concat(chunks));
    });
    req.on("error", (err) => {
      if (!failed) reject(err);
    });
  });
}

async function readJson(req) {
  const buffer = await readBody(req, JSON_LIMIT);
  if (buffer.length === 0) return {};
  try {
    const value = JSON.parse(buffer.toString("utf8"));
    return value && typeof value === "object" && !Array.isArray(value) ? value : {};
  } catch {
    throw new HttpError(400, "Request body must be valid JSON.");
  }
}

function sendJson(res, status, body) {
  const text = JSON.stringify(body);
  res.writeHead(status, {
    ...API_HEADERS,
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(text),
  });
  res.end(text);
}

function sendFile(res, status, buffer, headers) {
  res.writeHead(status, {
    ...API_HEADERS,
    "Content-Length": buffer.length,
    ...headers,
  });
  res.end(buffer);
}

function parseCookies(header) {
  const out = {};
  for (const part of String(header || "").split(";")) {
    const i = part.indexOf("=");
    if (i < 0) continue;
    const name = part.slice(0, i).trim();
    try {
      out[name] = decodeURIComponent(part.slice(i + 1).trim());
    } catch {
      // ignore malformed cookie values
    }
  }
  return out;
}

const STATIC_TYPES = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".svg": "image/svg+xml",
  ".ico": "image/x-icon",
};

async function serveStatic(res, requestPath) {
  const relative = requestPath === "/" ? "index.html" : requestPath.replace(/^\/+/, "");
  const file = path.resolve(PUBLIC_DIR, relative);
  if (!file.startsWith(PUBLIC_DIR + path.sep)) throw new HttpError(404, "Not found.");
  let data;
  try {
    data = await fs.promises.readFile(file);
  } catch {
    throw new HttpError(404, "Not found.");
  }
  const type = STATIC_TYPES[path.extname(file)] || "application/octet-stream";
  sendFile(res, 200, data, { ...SECURITY_HEADERS, "Content-Type": type, "Cache-Control": "no-cache" });
}

module.exports = {
  HttpError,
  SECURITY_HEADERS,
  createRouter,
  readBody,
  readJson,
  sendJson,
  sendFile,
  parseCookies,
  serveStatic,
};
