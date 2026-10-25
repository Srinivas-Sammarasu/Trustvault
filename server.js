"use strict";

const path = require("node:path");
const { createApp } = require("./src/app");

const PORT = Number(process.env.PORT) || 3000;
const HOST = process.env.HOST || "127.0.0.1";

const app = createApp({
  dbPath: process.env.TV_DB || path.join(__dirname, "data", "trustvault.db"),
  uploadDir: process.env.TV_UPLOADS || path.join(__dirname, "uploads"),
});

const hasAdmin = app.db.prepare("SELECT 1 FROM users WHERE role = 'admin' AND active = 1 LIMIT 1").get();
if (!hasAdmin) {
  console.warn("No active admin account exists. Run `npm run seed` first (see README).");
}

app.server.listen(PORT, HOST, () => {
  console.log(`TrustVault listening on http://${HOST}:${PORT}`);
});

function shutdown() {
  app.close();
  process.exit(0);
}
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
