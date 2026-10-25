// TrustVault client. No innerHTML anywhere: all text is inserted with textContent.

const CATEGORIES = ["HR", "Contracts", "Finance", "Legal", "Engineering", "Other"];
const AUDIT_ACTIONS = [
  "auth.login", "auth.logout", "document.upload", "document.view", "document.download",
  "document.edit", "document.delete", "document.restore", "grant.create", "grant.revoke",
  "link.create", "link.revoke", "link.view", "link.download", "user.create", "user.update",
  "audit.export", "access.role_denied",
];

const state = { user: null };
const $ = (selector, root = document) => root.querySelector(selector);

class ApiError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

// ---------- DOM helper ----------

function h(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props || {})) {
    if (value === undefined || value === null || value === false) continue;
    if (key === "class") node.className = value;
    else if (key.startsWith("on") && typeof value === "function") node.addEventListener(key.slice(2), value);
    else if (value === true) node.setAttribute(key, "");
    else node.setAttribute(key, String(value));
  }
  for (const child of children.flat()) {
    if (child === null || child === undefined || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

function setView(...nodes) {
  $("#view").replaceChildren(...nodes);
}

function toast(message, isError = false) {
  const el = $("#toast");
  el.textContent = message;
  el.className = isError ? "toast error" : "toast";
  el.hidden = false;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => { el.hidden = true; }, 3800);
}

function fmtDate(iso) {
  return iso ? new Date(iso).toLocaleString([], { dateStyle: "medium", timeStyle: "short" }) : "—";
}

function fmtSize(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1048576).toFixed(1)} MB`;
}

function roleBadge(role) {
  const label = { admin: "Administrator", owner: "Document owner", viewer: "Viewer" }[role] || role;
  return h("span", { class: `badge ${role === "admin" ? "warn" : role === "owner" ? "primary" : ""}` }, label);
}

function accessBadge(doc) {
  if (doc.owner.id === state.user.id) return h("span", { class: "badge primary" }, "Owner");
  if (doc.permissions.includes("edit")) return h("span", { class: "badge ok" }, "Can edit");
  if (doc.permissions.includes("read")) return h("span", { class: "badge" }, "Can view");
  return h("span", { class: "badge" }, "Admin metadata");
}

// ---------- API ----------

async function errorFrom(res) {
  let message = `Request failed (${res.status}).`;
  try {
    const data = await res.json();
    if (data && data.error) message = data.error;
  } catch {
    // not JSON; keep the generic message
  }
  return new ApiError(res.status, message);
}

async function api(url, opts = {}) {
  const init = {
    method: opts.method || "GET",
    credentials: "same-origin",
    headers: { Accept: "application/json", ...(opts.headers || {}) },
  };
  // Every write carries this header. A cross-site page cannot set it, so it blocks CSRF.
  if (init.method !== "GET") init.headers["X-TrustVault"] = "1";
  if (opts.json !== undefined) {
    init.headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(opts.json);
  } else if (opts.body !== undefined) {
    init.body = opts.body;
  }

  const res = await fetch(url, init);
  if (opts.raw) {
    if (!res.ok) throw await errorFrom(res);
    return res;
  }
  if (!res.ok) {
    const error = await errorFrom(res);
    if (res.status === 401 && state.user) {
      state.user = null;
      showLogin("Your session has ended. Sign in again.");
    }
    throw error;
  }
  return res.status === 204 ? null : res.json();
}

// ---------- shell ----------

function showLogin(message = "") {
  $("#boot").hidden = true;
  $("#app-view").hidden = true;
  $("#login-view").hidden = false;
  $("#login-error").textContent = message;
  $("#login-email").focus();
}

function showApp() {
  $("#boot").hidden = true;
  $("#login-view").hidden = true;
  $("#app-view").hidden = false;
  $("#whoami-name").textContent = state.user.name;
  $("#whoami-role").replaceChildren(roleBadge(state.user.role));
  $("[data-nav='admin']").hidden = state.user.role !== "admin";
  route();
}

function setActiveNav(name) {
  document.querySelectorAll("[data-nav]").forEach((a) => {
    a.classList.toggle("active", a.dataset.nav === name);
  });
}

async function route() {
  if (!state.user) return;
  const hash = location.hash || "#/";
  try {
    const doc = hash.match(/^#\/doc\/([A-Za-z0-9-]+)$/);
    if (doc) {
      setActiveNav("documents");
      return await documentView(doc[1]);
    }
    if (hash === "#/admin") {
      if (state.user.role !== "admin") {
        location.hash = "#/";
        return;
      }
      setActiveNav("admin");
      return await adminView();
    }
    setActiveNav("documents");
    return await documentsView();
  } catch (err) {
    setView(h("div", { class: "card" }, h("h2", {}, "Something went wrong"), h("p", { class: "muted" }, err.message)));
  }
}

// ---------- documents list ----------

function field(text, control, cls = "") {
  return h("label", { class: cls }, text, control);
}

function statCard(label, value, detail) {
  return h("section", { class: "stat-card" },
    h("p", { class: "muted small" }, label),
    h("strong", { class: "stat-value" }, value),
    h("p", { class: "muted small" }, detail));
}

async function documentsView() {
  const isOwner = state.user.role === "owner";
  const search = h("input", { type: "search", placeholder: "Search by name", "aria-label": "Search by name" });
  const category = h("select", { "aria-label": "Category" },
    h("option", { value: "" }, "All categories"),
    CATEGORIES.map((c) => h("option", { value: c }, c)));
  const owner = h("input", { type: "search", placeholder: "owner@example.com", "aria-label": "Owner email" });
  const from = h("input", { type: "date", "aria-label": "Uploaded from" });
  const to = h("input", { type: "date", "aria-label": "Uploaded to" });
  const sort = h("select", { "aria-label": "Sort documents" },
    h("option", { value: "newest" }, "Newest first"),
    h("option", { value: "oldest" }, "Oldest first"),
    h("option", { value: "name-asc" }, "Name A–Z"),
    h("option", { value: "name-desc" }, "Name Z–A"),
    h("option", { value: "size-desc" }, "Largest first"),
    h("option", { value: "size-asc" }, "Smallest first"));
  const analytics = h("div", { class: "stats-grid", "aria-label": "Document summary" });
  const results = h("div", { class: "table-wrap" });
  const count = h("p", { class: "muted small" });

  async function load() {
    const params = new URLSearchParams();
    if (search.value.trim()) params.set("q", search.value.trim());
    if (category.value) params.set("category", category.value);
    if (owner.value.trim()) params.set("owner", owner.value.trim());
    if (from.value) params.set("from", from.value);
    if (to.value) params.set("to", to.value);
    try {
      const { documents } = await api(`/api/documents?${params}`);
      const sorters = {
        newest: (a, b) => new Date(b.createdAt) - new Date(a.createdAt),
        oldest: (a, b) => new Date(a.createdAt) - new Date(b.createdAt),
        "name-asc": (a, b) => a.title.localeCompare(b.title),
        "name-desc": (a, b) => b.title.localeCompare(a.title),
        "size-desc": (a, b) => b.size - a.size,
        "size-asc": (a, b) => a.size - b.size,
      };
      documents.sort(sorters[sort.value] || sorters.newest);
      renderRows(documents);
    } catch (err) {
      toast(err.message, true);
    }
  }

  function renderRows(docs) {
    count.textContent = `${docs.length} document${docs.length === 1 ? "" : "s"} matching your filters`;
    const totalBytes = docs.reduce((sum, d) => sum + (Number(d.size) || 0), 0);
    const categories = new Set(docs.map((d) => d.category));
    analytics.replaceChildren(
      statCard("Accessible documents", String(docs.length), "Matching current filters"),
      statCard("Storage represented", fmtSize(totalBytes), "Size of listed files"),
      statCard("Categories", String(categories.size), "Categories in this result")
    );
    if (docs.length === 0) {
      results.replaceChildren(h("div", { class: "empty" }, "No documents match these filters."));
      return;
    }
    const rows = docs.map((d) => h("tr", {},
      h("td", {}, h("a", { class: "row-link", href: `#/doc/${d.id}` },
        h("div", { class: "doc-title" }, d.title),
        h("div", { class: "small muted" }, d.originalName))),
      h("td", {}, d.category),
      h("td", {}, d.owner.email),
      h("td", {}, fmtDate(d.createdAt)),
      h("td", { class: "num" }, fmtSize(d.size)),
      h("td", {}, accessBadge(d))));
    results.replaceChildren(h("table", {},
      h("thead", {}, h("tr", {}, ["Document", "Category", "Owner", "Uploaded", "Size", "Your access"].map((t) => h("th", {}, t)))),
      h("tbody", {}, rows)));
  }

  let timer;
  const debounced = () => { clearTimeout(timer); timer = setTimeout(load, 220); };
  search.addEventListener("input", debounced);
  owner.addEventListener("input", debounced);
  [category, from, to].forEach((el) => el.addEventListener("change", load));
  sort.addEventListener("change", load);

  setView(
    h("div", { class: "page-head" },
      h("div", {},
        h("h1", {}, "Documents"),
        h("p", { class: "muted" }, isOwner
          ? "Documents you own, and documents others have shared with you."
          : "Documents you have been given access to.")),
      isOwner ? h("button", { class: "btn primary", type: "button", onclick: openUpload }, "Upload document") : null),
    h("div", { class: "card" },
      h("div", { class: "toolbar" },
        field("Search", search, "search"),
        field("Category", category),
        field("Owner", owner, "search"),
        field("From", from),
        field("To", to),
        field("Sort by", sort))),
    analytics,
    results,
    count);
  await load();
}

// ---------- upload ----------

const uploadDialog = $("#dlg-upload");
const uploadForm = $("#upload-form");

function openUpload() {
  uploadForm.reset();
  uploadForm.querySelector("[data-error]").textContent = "";
  uploadForm.querySelector("[data-categories]").replaceChildren(...CATEGORIES.map((c) => h("option", { value: c }, c)));
  uploadDialog.showModal();
}

uploadForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const errorEl = uploadForm.querySelector("[data-error]");
  errorEl.textContent = "";
  const file = uploadForm.elements.file.files[0];
  const title = uploadForm.elements.title.value.trim();
  const category = uploadForm.elements.category.value;
  if (!file) {
    errorEl.textContent = "Choose a file to upload.";
    return;
  }
  const submit = uploadForm.querySelector("button[type='submit']");
  submit.disabled = true;
  try {
    const params = new URLSearchParams({ title, category });
    const result = await api(`/api/documents?${params}`, {
      method: "POST",
      headers: {
        "Content-Type": file.type || "application/octet-stream",
        "X-File-Name": encodeURIComponent(file.name),
      },
      body: file,
    });
    uploadDialog.close();
    toast("Document uploaded.");
    location.hash = `#/doc/${result.id}`;
    if (location.hash === `#/doc/${result.id}`) route();
  } catch (err) {
    errorEl.textContent = err.message;
  } finally {
    submit.disabled = false;
  }
});

// ---------- document detail ----------

async function documentView(id) {
  const { document: d } = await api(`/api/documents/${encodeURIComponent(id)}`);
  const isOwner = d.owner.id === state.user.id;
  const perms = new Set(d.permissions);
  const canDownload = perms.has("read") && !d.deletedAt;
  const canEdit = perms.has("edit") && !d.deletedAt;

  const actions = h("div", { class: "actions" },
    d.deletedAt ? h("span", { class: "badge danger" }, "In trash") : null,
    canDownload ? h("button", { class: "btn primary", type: "button", onclick: () => download(d) }, "Download") : null,
    isOwner && d.deletedAt ? h("button", { class: "btn", type: "button", onclick: () => restore(d) }, "Restore") : null,
    isOwner && !d.deletedAt ? h("button", { class: "btn danger", type: "button", onclick: () => remove(d) }, "Move to trash") : null);

  const meta = h("div", { class: "card" },
    h("dl", { class: "grid-meta" },
      h("div", {}, h("dt", {}, "Category"), h("dd", {}, d.category)),
      h("div", {}, h("dt", {}, "Owner"), h("dd", {}, d.owner.email)),
      h("div", {}, h("dt", {}, "File"), h("dd", {}, d.originalName)),
      h("div", {}, h("dt", {}, "Size"), h("dd", {}, fmtSize(d.size))),
      h("div", {}, h("dt", {}, "Type"), h("dd", {}, d.mime)),
      h("div", {}, h("dt", {}, "Uploaded"), h("dd", {}, fmtDate(d.createdAt))),
      h("div", {}, h("dt", {}, "Last changed"), h("dd", {}, fmtDate(d.updatedAt))),
      h("div", { style: "grid-column: 1 / -1" }, h("dt", {}, "SHA-256"), h("dd", { class: "mono" }, d.sha256))));

  const editCard = canEdit ? editPanel(d) : null;
  const ownerPanels = isOwner ? [grantsPanel(d), linksPanel(d), activityPanel(d)] : [];

  setView(
    h("div", { class: "page-head" },
      h("div", {},
        h("p", {}, h("a", { href: "#/" }, "← Back to documents")),
        h("h1", {}, d.title),
        h("p", { class: "muted" }, isOwner ? "You own this document." : `Owned by ${d.owner.email}`)),
      actions),
    meta,
    editCard,
    ...ownerPanels);
}

function editPanel(d) {
  const title = h("input", { name: "title", maxlength: "120", value: d.title, required: true });
  const category = h("select", { name: "category" }, CATEGORIES.map((c) => h("option", { value: c, selected: c === d.category }, c)));
  const error = h("p", { class: "form-error" });
  const form = h("form", { class: "stack" },
    h("div", { class: "card-head" }, h("h2", {}, "Edit details")),
    h("div", { class: "grid-2" }, field("Title", title), field("Category", category)),
    error,
    h("div", { class: "actions" }, h("button", { class: "btn primary", type: "submit" }, "Save changes")));
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      await api(`/api/documents/${encodeURIComponent(d.id)}`, {
        method: "PATCH", json: { title: title.value.trim(), category: category.value },
      });
      toast("Changes saved.");
      route();
    } catch (err) {
      error.textContent = err.message;
    }
  });
  return h("div", { class: "card" }, form);
}

async function download(d) {
  try {
    const res = await api(`/api/documents/${encodeURIComponent(d.id)}/download`, { raw: true });
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const link = h("a", { href: url, download: d.originalName });
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 2000);
    toast("Download started.");
  } catch (err) {
    toast(err.message, true);
  }
}

async function remove(d) {
  if (!confirm("Move this document to the trash? Share links will stop working. You can restore it later.")) return;
  try {
    await api(`/api/documents/${encodeURIComponent(d.id)}`, { method: "DELETE" });
    toast("Moved to trash.");
    location.hash = "#/";
  } catch (err) {
    toast(err.message, true);
  }
}

async function restore(d) {
  try {
    await api(`/api/documents/${encodeURIComponent(d.id)}/restore`, { method: "POST" });
    toast("Document restored.");
    route();
  } catch (err) {
    toast(err.message, true);
  }
}

// ---------- grants ----------

function grantsPanel(d) {
  const email = h("input", { type: "email", placeholder: "colleague@example.com", "aria-label": "Colleague email", required: true });
  const permission = h("select", { "aria-label": "Permission" },
    h("option", { value: "read" }, "Can view"),
    h("option", { value: "edit" }, "Can edit"));
  const error = h("p", { class: "form-error" });
  const body = h("tbody", {});
  const table = h("div", { class: "table-wrap" }, h("table", {},
    h("thead", {}, h("tr", {}, ["Person", "Access", "Granted", "Status", ""].map((t) => h("th", {}, t)))),
    body));

  api(`/api/documents/${encodeURIComponent(d.id)}/grants`).then(({ grants }) => {
    if (grants.length === 0) {
      body.replaceChildren(h("tr", {}, h("td", { colspan: "5", class: "empty" }, "Nobody else has access yet.")));
      return;
    }
    body.replaceChildren(...grants.map((g) => h("tr", {},
      h("td", {}, g.email),
      h("td", {}, g.permission === "edit" ? "Can edit" : "Can view"),
      h("td", {}, fmtDate(g.createdAt)),
      h("td", {}, g.revokedAt ? h("span", { class: "badge" }, "Revoked") : h("span", { class: "badge ok" }, "Active")),
      h("td", { class: "num" }, g.revokedAt ? null : h("button", {
        class: "btn small danger", type: "button",
        onclick: async () => {
          try {
            await api(`/api/documents/${encodeURIComponent(d.id)}/grants/${encodeURIComponent(g.id)}`, { method: "DELETE" });
            toast("Access removed. It stops working immediately.");
            route();
          } catch (err) { toast(err.message, true); }
        },
      }, "Remove access")))));
  }).catch((err) => {
    body.replaceChildren(h("tr", {}, h("td", { colspan: "5", class: "form-error" }, err.message)));
  });

  const form = h("form", { class: "stack" },
    h("h3", {}, "Give someone access"),
    h("p", { class: "muted small" }, "Access is for this document only. Only accounts that already exist can be added."),
    h("div", { class: "toolbar" }, field("Email", email, "search"), field("Permission", permission)),
    error,
    h("div", { class: "actions" }, h("button", { class: "btn primary", type: "submit" }, "Grant access")));
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      await api(`/api/documents/${encodeURIComponent(d.id)}/grants`, {
        method: "POST", json: { email: email.value.trim(), permission: permission.value },
      });
      toast("Access granted.");
      route();
    } catch (err) {
      error.textContent = err.message;
    }
  });

  return h("div", { class: "card" },
    h("div", { class: "card-head" }, h("h2", {}, "Who can access this")),
    table,
    h("div", { style: "margin-top:18px" }, form));
}

// ---------- share links ----------

const linkDialog = $("#dlg-link");
const linkForm = $("#link-form");
const resultDialog = $("#dlg-result");
let currentShare = null;

function linksPanel(d) {
  const body = h("tbody", {});
  const table = h("div", { class: "table-wrap" }, h("table", {},
    h("thead", {}, h("tr", {}, ["Label", "Status", "Expires", "Downloads", ""].map((t) => h("th", {}, t)))),
    body));

  api(`/api/documents/${encodeURIComponent(d.id)}/links`).then(({ links }) => {
    if (links.length === 0) {
      body.replaceChildren(h("tr", {}, h("td", { colspan: "5", class: "empty" }, "No share links yet.")));
      return;
    }
    body.replaceChildren(...links.map((l) => h("tr", {},
      h("td", {}, l.label),
      h("td", {}, l.active ? h("span", { class: "badge ok" }, "Active") : h("span", { class: "badge" }, l.revokedAt ? "Revoked" : "Expired or used")),
      h("td", {}, fmtDate(l.expiresAt)),
      h("td", {}, `${l.downloadCount} of ${l.maxDownloads}`),
      h("td", { class: "num" }, l.active ? h("button", {
        class: "btn small danger", type: "button",
        onclick: async () => {
          try {
            await api(`/api/links/${encodeURIComponent(l.id)}/revoke`, { method: "POST" });
            toast("Link revoked.");
            route();
          } catch (err) { toast(err.message, true); }
        },
      }, "Revoke") : null))));
  }).catch((err) => {
    body.replaceChildren(h("tr", {}, h("td", { colspan: "5", class: "form-error" }, err.message)));
  });

  return h("div", { class: "card" },
    h("div", { class: "card-head" },
      h("h2", {}, "Share links"),
      h("button", {
        class: "btn primary small", type: "button",
        onclick: () => {
          currentShare = d.id;
          linkForm.reset();
          linkForm.querySelector("[data-error]").textContent = "";
          linkDialog.showModal();
        },
      }, "New share link")),
    table);
}

linkForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const errorEl = linkForm.querySelector("[data-error]");
  errorEl.textContent = "";
  const typed = linkForm.elements.passcode.value;
  const submit = linkForm.querySelector("button[type='submit']");
  submit.disabled = true;
  try {
    const result = await api(`/api/documents/${encodeURIComponent(currentShare)}/links`, {
      method: "POST",
      json: {
        label: linkForm.elements.label.value.trim(),
        expiresHours: Number(linkForm.elements.expiresHours.value),
        maxDownloads: Number(linkForm.elements.maxDownloads.value),
        passcode: typed || undefined,
      },
    });
    linkDialog.close();
    $("#result-url").value = result.link.url;
    $("#result-passcode").value = result.passcode || typed;
    resultDialog.showModal();
    route();
  } catch (err) {
    errorEl.textContent = err.message;
  } finally {
    submit.disabled = false;
  }
});

$("#copy-both").addEventListener("click", async () => {
  const text = `${$("#result-url").value}\nPasscode: ${$("#result-passcode").value}`;
  try {
    await navigator.clipboard.writeText(text);
    toast("Copied.");
  } catch {
    toast("Could not copy. Select the fields and copy them manually.", true);
  }
});

// ---------- activity ----------

function activityPanel(d) {
  const list = h("ol", { class: "timeline" });
  api(`/api/documents/${encodeURIComponent(d.id)}/activity`).then(({ events }) => {
    if (events.length === 0) {
      list.replaceChildren(h("li", {}, h("span", { class: "muted" }, "No activity yet.")));
      return;
    }
    list.replaceChildren(...events.map((e) => h("li", {},
      h("span", { class: "when" }, fmtDate(e.ts)),
      h("div", {},
        h("strong", {}, e.action), " ",
        h("span", { class: `badge ${e.outcome === "allowed" ? "ok" : "danger"}` }, e.outcome),
        h("div", { class: "small muted" }, `${e.actor}${Object.keys(e.details).length ? " · " + JSON.stringify(e.details).slice(0, 140) : ""}`)))));
  }).catch((err) => {
    list.replaceChildren(h("li", {}, h("span", { class: "form-error" }, err.message)));
  });
  return h("div", { class: "card" },
    h("div", { class: "card-head" }, h("h2", {}, "Activity"), h("span", { class: "muted small" }, "Every access and change, including refused attempts")),
    list);
}

// ---------- admin ----------

async function adminView() {
  const tabs = ["Users", "Documents", "Audit"];
  let current = "Users";
  const tabBar = h("div", { class: "tabs", role: "tablist" });
  const panel = h("div", {});

  function drawTabs() {
    tabBar.replaceChildren(...tabs.map((t) => h("button", {
      type: "button", role: "tab", "aria-selected": String(t === current),
      onclick: () => { current = t; drawTabs(); show(); },
    }, t)));
  }

  async function show() {
    panel.replaceChildren(h("p", { class: "muted" }, "Loading…"));
    try {
      if (current === "Users") await usersPanel(panel);
      else if (current === "Documents") await documentsAdminPanel(panel);
      else await auditPanel(panel);
    } catch (err) {
      panel.replaceChildren(h("p", { class: "form-error" }, err.message));
    }
  }

  setView(
    h("div", { class: "page-head" }, h("div", {},
      h("h1", {}, "Administration"),
      h("p", { class: "muted" }, "Manage accounts and review activity. Administrators can see who holds what, but cannot open document contents."))),
    tabBar,
    panel);
  drawTabs();
  await show();
}

async function usersPanel(panel) {
  const { users } = await api("/api/admin/users");
  const rows = users.map((u) => {
    const isMe = u.id === state.user.id;
    const roleSelect = h("select", { "aria-label": `Role for ${u.email}`, disabled: isMe },
      ["viewer", "owner", "admin"].map((r) => h("option", { value: r, selected: r === u.role }, r)));
    roleSelect.addEventListener("change", async () => {
      try {
        await api(`/api/admin/users/${encodeURIComponent(u.id)}`, { method: "PATCH", json: { role: roleSelect.value } });
        toast("Role updated.");
      } catch (err) {
        toast(err.message, true);
        roleSelect.value = u.role;
      }
    });
    const toggle = h("button", {
      class: `btn small ${u.active ? "danger" : ""}`, type: "button", disabled: isMe,
      onclick: async () => {
        try {
          await api(`/api/admin/users/${encodeURIComponent(u.id)}`, { method: "PATCH", json: { active: !u.active } });
          toast(u.active ? "Account deactivated. Its sessions ended." : "Account reactivated.");
          await show2();
        } catch (err) { toast(err.message, true); }
      },
    }, u.active ? "Deactivate" : "Reactivate");
    return h("tr", {},
      h("td", {}, h("div", { class: "doc-title" }, u.name), h("div", { class: "small muted" }, u.email)),
      h("td", {}, roleSelect),
      h("td", {}, u.active ? h("span", { class: "badge ok" }, "Active") : h("span", { class: "badge danger" }, "Deactivated")),
      h("td", { class: "num" }, isMe ? h("span", { class: "muted small" }, "You") : toggle));
  });

  async function show2() {
    await usersPanel(panel);
  }

  const email = h("input", { type: "email", required: true });
  const name = h("input", { required: true, maxlength: "80" });
  const role = h("select", {}, ["viewer", "owner", "admin"].map((r) => h("option", { value: r }, r)));
  const password = h("input", { type: "password", minlength: "12", required: true, autocomplete: "new-password" });
  const error = h("p", { class: "form-error" });
  const form = h("form", { class: "stack" },
    h("h2", {}, "Add an account"),
    h("div", { class: "grid-2" }, field("Name", name), field("Email", email)),
    h("div", { class: "grid-2" }, field("Role", role), field("Temporary password (12+ characters)", password)),
    error,
    h("div", { class: "actions" }, h("button", { class: "btn primary", type: "submit" }, "Create account")));
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      await api("/api/admin/users", {
        method: "POST",
        json: { email: email.value.trim(), name: name.value.trim(), role: role.value, password: password.value },
      });
      toast("Account created. Share the temporary password securely.");
      await usersPanel(panel);
    } catch (err) {
      error.textContent = err.message;
    }
  });

  panel.replaceChildren(
    h("div", { class: "table-wrap" }, h("table", {},
      h("thead", {}, h("tr", {}, ["Person", "Role", "Status", ""].map((t) => h("th", {}, t)))),
      h("tbody", {}, rows))),
    h("div", { class: "card", style: "margin-top:18px" }, form));
}

async function documentsAdminPanel(panel) {
  const { documents } = await api("/api/admin/documents");
  if (documents.length === 0) {
    panel.replaceChildren(h("div", { class: "empty" }, "No documents exist yet."));
    return;
  }
  const rows = documents.map((d) => {
    const status = d.deletedAt
      ? h("span", { class: "badge danger" }, "In trash")
      : h("span", { class: "badge ok" }, "Active");
    return h("tr", {},
      h("td", {}, h("div", { class: "doc-title" }, d.title), h("div", { class: "small muted" }, d.category)),
      h("td", {}, d.owner),
      h("td", {}, fmtDate(d.createdAt)),
      h("td", { class: "num" }, String(d.activeGrants)),
      h("td", { class: "num" }, String(d.activeLinks)),
      h("td", {}, status));
  });
  const head = h("tr", {}, ["Document", "Owner", "Uploaded", "Grants", "Links", "Status"].map((t) => h("th", {}, t)));
  panel.replaceChildren(
    h("p", { class: "muted small" }, "Metadata only. Administrators cannot download these files unless an owner grants them access."),
    h("div", { class: "table-wrap" }, h("table", {}, h("thead", {}, head), h("tbody", {}, rows))));
}

async function auditPanel(panel) {
  const action = h("select", { "aria-label": "Filter by action" },
    h("option", { value: "" }, "All actions"),
    AUDIT_ACTIONS.map((a) => h("option", { value: a }, a)));
  const outcome = h("select", { "aria-label": "Filter by outcome" },
    h("option", { value: "" }, "All outcomes"),
    ["allowed", "denied", "failed"].map((o) => h("option", { value: o }, o)));
  const verifyOut = h("span", { class: "badge" }, "Not checked yet");
  const anchorOut = h("p", { class: "small muted" });
  const tableBody = h("tbody", {});

  async function loadEvents() {
    const params = new URLSearchParams({ limit: "200" });
    if (action.value) params.set("action", action.value);
    if (outcome.value) params.set("outcome", outcome.value);
    const { events } = await api(`/api/admin/audit?${params}`);
    tableBody.replaceChildren(...(events.length ? events.map((e) => h("tr", {},
      h("td", { class: "num" }, String(e.seq)),
      h("td", {}, fmtDate(e.ts)),
      h("td", {}, e.actor),
      h("td", {}, e.action),
      h("td", {}, e.entityId ? h("span", { class: "mono" }, e.entityId.slice(0, 8)) : "—"),
      h("td", {}, h("span", { class: `badge ${e.outcome === "allowed" ? "ok" : "danger"}` }, e.outcome)),
      h("td", { class: "mono" }, `${e.hash.slice(0, 12)}…`))) : [h("tr", {}, h("td", { colspan: "7", class: "empty" }, "No events match."))]));
  }

  async function verify() {
    const result = await api("/api/admin/audit/verify");
    verifyOut.className = result.valid ? "badge ok" : "badge danger";
    verifyOut.textContent = result.valid
      ? `Chain intact · ${result.checked} entries checked`
      : `Chain BROKEN at entry ${result.brokenAt}`;
  }

  async function anchor() {
    const a = await api("/api/admin/audit/anchor");
    anchorOut.replaceChildren(
      `Latest entry ${a.latestSeq ?? "none"} at ${fmtDate(a.latestAt)}. Latest hash: `,
      h("span", { class: "mono" }, a.latestHash),
      " Copy this value to storage you do not control, daily or after important changes.");
  }

  async function exportCsv() {
    try {
      const res = await api("/api/admin/audit/export.csv", { raw: true });
      const url = URL.createObjectURL(await res.blob());
      const link = h("a", { href: url, download: "trustvault-audit.csv" });
      document.body.append(link);
      link.click();
      link.remove();
      setTimeout(() => URL.revokeObjectURL(url), 2000);
    } catch (err) {
      toast(err.message, true);
    }
  }

  action.addEventListener("change", () => loadEvents().catch((e) => toast(e.message, true)));
  outcome.addEventListener("change", () => loadEvents().catch((e) => toast(e.message, true)));

  panel.replaceChildren(
    h("div", { class: "card" },
      h("div", { class: "card-head" },
        h("h2", {}, "Audit trail"),
        h("div", { class: "actions" },
          h("button", { class: "btn small", type: "button", onclick: () => verify().catch((e) => toast(e.message, true)) }, "Verify chain"),
          h("button", { class: "btn small", type: "button", onclick: () => anchor().catch((e) => toast(e.message, true)) }, "Show anchor"),
          h("button", { class: "btn small primary", type: "button", onclick: exportCsv }, "Export CSV"))),
      h("div", { class: "toolbar" }, field("Action", action), field("Outcome", outcome)),
      h("p", {}, verifyOut),
      anchorOut),
    h("div", { class: "table-wrap" }, h("table", {},
      h("thead", {}, h("tr", {}, ["#", "Time", "Who", "Action", "Entity", "Outcome", "Hash"].map((t) => h("th", {}, t)))),
      tableBody)));

  await loadEvents();
}

// ---------- login and boot ----------

$("#login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const errorEl = $("#login-error");
  errorEl.textContent = "";
  const submit = event.target.querySelector("button[type='submit']");
  submit.disabled = true;
  try {
    const { user } = await api("/api/auth/login", {
      method: "POST",
      json: { email: $("#login-email").value.trim(), password: $("#login-password").value },
    });
    state.user = user;
    $("#login-password").value = "";
    if (location.hash !== "" && location.hash !== "#/") location.hash = "#/";
    showApp();
  } catch (err) {
    errorEl.textContent = err.message;
  } finally {
    submit.disabled = false;
  }
});

$("#signout").addEventListener("click", async () => {
  try {
    await api("/api/auth/logout", { method: "POST", json: {} });
  } catch {
    // the cookie is cleared server-side anyway
  }
  state.user = null;
  location.hash = "";
  showLogin("You have signed out.");
});

document.querySelectorAll("[data-close]").forEach((button) => {
  button.addEventListener("click", () => button.closest("dialog").close());
});

window.addEventListener("hashchange", () => route());

(async function boot() {
  try {
    const { user } = await api("/api/me");
    state.user = user;
    showApp();
  } catch {
    showLogin();
  }
})();
