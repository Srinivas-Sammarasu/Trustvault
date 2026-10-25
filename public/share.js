// Public share page. The token is in the path; the passcode is sent only in a POST body.

const token = location.pathname.split("/").pop();
const info = document.getElementById("share-info");
const form = document.getElementById("share-form");
const passcode = document.getElementById("share-passcode");
const errorEl = document.getElementById("share-error");

function fmtSize(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1048576).toFixed(1)} MB`;
}

function line(text, cls = "") {
  const p = document.createElement("p");
  p.className = cls;
  p.textContent = text;
  return p;
}

function filenameFromDisposition(value) {
  if (!value) return "";
  const utf8 = /filename\*=UTF-8''([^;]+)/i.exec(value);
  if (utf8) {
    try { return decodeURIComponent(utf8[1].replace(/^"|"$/g, "")); } catch { /* use ASCII fallback */ }
  }
  const ascii = /filename="?([^";]+)"?/i.exec(value);
  return ascii ? ascii[1] : "";
}

async function loadInfo() {
  try {
    const res = await fetch(`/api/public/links/${encodeURIComponent(token)}`, {
      headers: { Accept: "application/json" },
      credentials: "omit",
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || "This link is not available.");
    // Do not display document title, filename, size or expiry until the
    // recipient has proven possession of the passcode by downloading.
    info.replaceChildren(
      line("This is a password-protected document.", "doc-title"),
      line("Enter the passcode provided by the sender to download it.", "small"),
    );
    form.hidden = false;
    passcode.focus();
  } catch (err) {
    info.replaceChildren(line(err.message, "form-error"));
  }
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  errorEl.textContent = "";
  const button = form.querySelector("button");
  button.disabled = true;
  try {
    const res = await fetch(`/api/public/links/${encodeURIComponent(token)}/download`, {
      method: "POST",
      credentials: "omit",
      headers: { "Content-Type": "application/json", "X-TrustVault": "1" },
      body: JSON.stringify({ passcode: passcode.value }),
    });
    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      throw new Error(data.error || `Download failed (${res.status}).`);
    }
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filenameFromDisposition(res.headers.get("content-disposition")) || "document";
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 2000);
    passcode.value = "";
    info.replaceChildren(line("Download started. Check your downloads folder.", "small"));
    form.hidden = true;
  } catch (err) {
    errorEl.textContent = err.message;
  } finally {
    button.disabled = false;
  }
});

loadInfo();
