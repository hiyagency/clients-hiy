import express from "express";
import path from "path";
import crypto from "crypto";

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3000;
const ROOT = path.resolve("public");

// --- simple signed cookie session (no DB) ---
const COOKIE_NAME = "hiy_sess";
const SESSION_SECRET = process.env.SESSION_SECRET || "change-me-in-railway";

function sign(payload) {
  const data = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const sig = crypto.createHmac("sha256", SESSION_SECRET).update(data).digest("base64url");
  return `${data}.${sig}`;
}
function verify(token) {
  if (!token || !token.includes(".")) return null;
  const [data, sig] = token.split(".");
  const exp = crypto.createHmac("sha256", SESSION_SECRET).update(data).digest("base64url");
  if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(exp))) return null;
  try {
    return JSON.parse(Buffer.from(data, "base64url").toString("utf8"));
  } catch {
    return null;
  }
}
function getCookie(req, name) {
  const raw = req.headers.cookie || "";
  const parts = raw.split(";").map(s => s.trim());
  for (const p of parts) {
    const i = p.indexOf("=");
    if (i > 0 && p.slice(0, i) === name) return decodeURIComponent(p.slice(i + 1));
  }
  return null;
}
function setCookie(res, name, value, opts = {}) {
  const parts = [`${name}=${encodeURIComponent(value)}`];
  parts.push("Path=/");
  parts.push("HttpOnly");
  parts.push("SameSite=Lax");
  if (opts.maxAge === 0) parts.push("Max-Age=0");
  else if (typeof opts.maxAge === "number") parts.push(`Max-Age=${opts.maxAge}`);
  // Railway usually sits behind HTTPS; still set Secure when we detect it
  if (process.env.NODE_ENV === "production") parts.push("Secure");
  res.setHeader("Set-Cookie", parts.join("; "));
}

function creds() {
  return {
    adminUser: process.env.ADMIN_USER || "admin",
    adminPass: process.env.ADMIN_PASS || "hiy2024",
    clientUser: process.env.CLIENT_USER || "desijayka",
    clientPass: process.env.CLIENT_PASS || "demo123",
    clientId: process.env.CLIENT_ID || "c1",
  };
}

app.post("/api/login", (req, res) => {
  const { role, username, password } = req.body || {};
  const c = creds();

  if (role === "admin") {
    if (username === c.adminUser && password === c.adminPass) {
      setCookie(res, COOKIE_NAME, sign({ role: "admin", ts: Date.now() }), { maxAge: 60 * 60 * 12 });
      return res.json({ ok: true });
    }
    return res.status(401).json({ ok: false });
  }

  if (role === "client") {
    if (username === c.clientUser && password === c.clientPass) {
      setCookie(res, COOKIE_NAME, sign({ role: "client", clientId: c.clientId, ts: Date.now() }), { maxAge: 60 * 60 * 12 });
      return res.json({ ok: true, clientId: c.clientId });
    }
    return res.status(401).json({ ok: false });
  }

  return res.status(400).json({ ok: false });
});

app.post("/api/logout", (req, res) => {
  setCookie(res, COOKIE_NAME, "x", { maxAge: 0 });
  res.json({ ok: true });
});

app.get("/api/me", (req, res) => {
  const token = getCookie(req, COOKIE_NAME);
  const sess = verify(token);
  if (!sess) return res.status(401).json({ ok: false });
  res.json({ ok: true, ...sess });
});

// static
app.use(express.static(ROOT, { extensions: ["html"] }));

app.listen(PORT, () => {
  console.log(`HIY CLIENTS running on :${PORT}`);
});
