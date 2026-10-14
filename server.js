const express = require("express");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const app = express();
app.use(express.json({ limit: "32kb" }));
const PORT = Number(process.env.PORT || 3000);
const DATA_FILE = process.env.DATA_FILE || path.join(__dirname, "data", "licenses.json");
const ADMIN_TOKEN = process.env.ADMIN_API_TOKEN || "";
const PRIVATE_XML = process.env.LICENSE_PRIVATE_XML || "";
const WEBHOOK_URL = process.env.DISCORD_WEBHOOK_URL || "";

function b64url(buf) { return Buffer.from(buf).toString("base64").replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_"); }
function fromB64url(s) { s = s.replace(/-/g, "+").replace(/_/g, "/"); while (s.length % 4) s += "="; return Buffer.from(s, "base64"); }
function xmlParam(xml, name) {
  const m = xml.match(new RegExp("<" + name + ">([^<]+)</" + name + ">"));
  if (!m) throw new Error("Missing RSA parameter: " + name);
  return b64url(Buffer.from(m[1], "base64"));
}
function privateKeyObject() {
  if (!PRIVATE_XML || PRIVATE_XML.includes("PASTE_EXISTING")) throw new Error("LICENSE_PRIVATE_XML is not configured on the server.");
  const names = ["Modulus","Exponent","P","Q","DP","DQ","InverseQ","D"];
  const jwk = { kty: "RSA", n: xmlParam(PRIVATE_XML,"Modulus"), e: xmlParam(PRIVATE_XML,"Exponent"),
    d: xmlParam(PRIVATE_XML,"D"), p: xmlParam(PRIVATE_XML,"P"), q: xmlParam(PRIVATE_XML,"Q"),
    dp: xmlParam(PRIVATE_XML,"DP"), dq: xmlParam(PRIVATE_XML,"DQ"), qi: xmlParam(PRIVATE_XML,"InverseQ") };
  return crypto.createPrivateKey({ key: jwk, format: "jwk" });
}
function signBytes(data) { return crypto.sign("sha256", Buffer.from(data), privateKeyObject()); }
function loadDb() {
  try {
    const parsed = JSON.parse(fs.readFileSync(DATA_FILE, "utf8"));
    if (parsed && Array.isArray(parsed.licenses)) return parsed;
  } catch {}
  return { licenses: [] };
}
function saveDb(db) {
  fs.mkdirSync(path.dirname(DATA_FILE), { recursive: true });
  const tmp = DATA_FILE + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(db, null, 2), { mode: 0o600 });
  fs.renameSync(tmp, DATA_FILE);
}
let db = loadDb();
function auth(req, res, next) {
  const token = (req.headers.authorization || "").replace(/^Bearer\s+/i, "");
  if (!ADMIN_TOKEN || !token || Buffer.byteLength(token) !== Buffer.byteLength(ADMIN_TOKEN) || !crypto.timingSafeEqual(Buffer.from(token), Buffer.from(ADMIN_TOKEN))) {
    return res.status(401).json({ ok: false, error: "Unauthorized" });
  }
  next();
}
function licensePayload(name, pc, expiry) {
  const safeName = String(name || "").trim().replace(/[|\r\n]/g, " ").slice(0, 100);
  const safePc = String(pc || "*").trim();
  const safeExpiry = String(expiry || "never").trim();
  if (!safeName) throw new Error("Customer name is required.");
  if (safePc !== "*" && !/^[A-Za-z0-9-]{4,40}$/.test(safePc)) throw new Error("PC ID must be * or a valid machine ID.");
  if (safeExpiry !== "never" && !/^\d{4}-\d{2}-\d{2}$/.test(safeExpiry)) throw new Error("Expiry must be YYYY-MM-DD or never.");
  if (safeExpiry !== "never" && Number.isNaN(Date.parse(safeExpiry + "T00:00:00Z"))) throw new Error("Expiry date is invalid.");
  return Buffer.from(`${safeName}|${safePc}|${safeExpiry}`, "utf8");
}
function idForPayload(payload) { return crypto.createHash("sha256").update(payload).digest("hex"); }
function findLicense(id) { return db.licenses.find(x => x.id === id); }
function issue(name, pc, expiry) {
  const payload = licensePayload(name, pc, expiry);
  const sig = signBytes(payload);
  const key = `FC1.${b64url(payload)}.${b64url(sig)}`;
  const id = idForPayload(payload);
  db.licenses.push({ id, name: String(name).trim(), pc: pc || "*", expiry: expiry || "never", revoked: false, issuedAt: new Date().toISOString() });
  saveDb(db);
  return { key, id, name: String(name).trim(), pc: pc || "*", expiry: expiry || "never" };
}
function setRevoked(id, revoked, details = {}) {
  if (!/^[0-9a-f]{64}$/.test(String(id || ""))) throw new Error("Invalid license ID.");
  let lic = findLicense(id);
  // Supports licenses issued by the previous local generator before migration.
  if (!lic) {
    lic = { id, name: String(details.name || "Imported license").slice(0, 100),
      pc: String(details.pc || "*"), expiry: String(details.expiry || "never"),
      issuedAt: new Date().toISOString(), imported: true };
    db.licenses.push(lic);
  }
  lic.revoked = revoked; lic.updatedAt = new Date().toISOString(); saveDb(db);
  return lic;
}
function signedRevokedList() {
  const ids = db.licenses.filter(x => x.revoked).map(x => x.id).sort();
  const data = ids.join("\n");
  const sig = signBytes(Buffer.from(data, "utf8"));
  return "FCR1\n" + (ids.length ? ids.join("\n") + "\n" : "") + "SIG " + b64url(sig) + "\n";
}
async function sendWebhook(title, description, color = 5793266) {
  if (!WEBHOOK_URL) return;
  try {
    const response = await fetch(WEBHOOK_URL, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        username: "FRAMECUT Licenses",
        allowed_mentions: { parse: [] },
        embeds: [{ title, description: String(description).slice(0, 3500), color,
          timestamp: new Date().toISOString() }]
      }),
      signal: AbortSignal.timeout(5000)
    });
    if (!response.ok) console.error(`Discord webhook returned HTTP ${response.status}`);
  } catch (e) {
    // Notifications are best-effort and must never undo a license operation.
    console.error("Discord webhook notification failed:", e.message);
  }
}
app.get("/health", (_req, res) => res.json({ ok: true, service: "license-service", webhookConfigured: Boolean(WEBHOOK_URL) }));
app.get("/revoked_list.txt", (_req, res) => {
  try { res.type("text/plain").set("Cache-Control", "no-store, max-age=0").send(signedRevokedList()); }
  catch (e) { res.status(503).type("text/plain").send("License service not configured."); }
});
app.post("/api/license/issue", auth, async (req, res) => {
  try {
    const r = issue(req.body.name, req.body.pc || "*", req.body.expiry || "never");
    await sendWebhook("License issued", `Customer: ${r.name}\nPC ID: ${r.pc === "*" ? "Any PC" : r.pc}\nExpires: ${r.expiry === "never" ? "Lifetime" : r.expiry}\nLicense ID: ${r.id}`, 5763719);
    res.json({ ok: true, ...r });
  } catch (e) { res.status(400).json({ ok: false, error: e.message }); }
});
app.post("/api/license/revoke", auth, async (req, res) => {
  try {
    const lic = setRevoked(req.body.id, true, req.body);
    await sendWebhook("License revoked", `Customer: ${lic.name}\nPC ID: ${lic.pc === "*" ? "Any PC" : lic.pc}\nExpires: ${lic.expiry === "never" ? "Lifetime" : lic.expiry}\nLicense ID: ${lic.id}`, 15548997);
    res.json({ ok: true, id: lic.id, revoked: true });
  } catch (e) { res.status(400).json({ ok: false, error: e.message }); }
});
app.post("/api/license/restore", auth, async (req, res) => {
  try {
    const lic = setRevoked(req.body.id, false, req.body);
    await sendWebhook("License restored", `Customer: ${lic.name}\nPC ID: ${lic.pc === "*" ? "Any PC" : lic.pc}\nExpires: ${lic.expiry === "never" ? "Lifetime" : lic.expiry}\nLicense ID: ${lic.id}`, 16705372);
    res.json({ ok: true, id: lic.id, revoked: false });
  } catch (e) { res.status(400).json({ ok: false, error: e.message }); }
});
app.get("/api/license/status/:id", auth, (req, res) => {
  const lic = findLicense(req.params.id);
  if (!lic) return res.status(404).json({ ok: false, error: "License not found" });
  res.json({ ok: true, id: lic.id, name: lic.name, pc: lic.pc, expiry: lic.expiry, revoked: lic.revoked });
});

app.listen(PORT, "0.0.0.0", () => console.log(`License HTTP service listening on ${PORT}`));
