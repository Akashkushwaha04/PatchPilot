// Campus Bazaar API — SYNTHETIC DEMO CODE (corrected version).
const express = require("express");
const cors = require("cors");
const { execFile } = require("child_process");
const path = require("path");
const { Pool } = require("pg");
const jwt = require("jsonwebtoken");
const { requireUser, requireAdmin } = require("./auth");

const app = express();
app.use(express.json());
const allowedOrigins = (process.env.ALLOWED_ORIGINS || "").split(",").filter(Boolean);
app.use(cors({ origin: allowedOrigins, credentials: true }));

const db = new Pool({ connectionString: process.env.DATABASE_URL });
app.use((req, _res, next) => { req.db = db; next(); });

app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  console.log("Login attempt", email);
  const user = await db.query("SELECT * FROM users WHERE email = $1", [email]);
  if (!user.rows.length) return res.status(401).json({ error: "Invalid login" });
  const token = jwt.sign({ id: user.rows[0].id }, process.env.JWT_SECRET, { expiresIn: "1h" });
  res.json({ token });
});

app.get("/api/products/search", async (req, res) => {
  try {
    const q = String(req.query.q || "");
    const result = await db.query("SELECT * FROM products WHERE name LIKE $1", [`%${q}%`]);
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Search failed" });
  }
});

app.get("/api/orders/export", requireUser, requireAdmin, async (req, res) => {
  const result = await db.query("SELECT id, email, total FROM orders");
  res.json(result.rows);
});

app.delete("/api/admin/users/:id", requireUser, requireAdmin, async (req, res) => {
  await db.query("DELETE FROM users WHERE id = $1", [req.params.id]);
  res.json({ deleted: req.params.id });
});

app.post("/api/products/thumbnail", requireUser, (req, res) => {
  const name = path.basename(String(req.body.filename || ""));
  if (!/^[\w.-]+\.(png|jpe?g)$/i.test(name)) return res.status(400).json({ error: "Invalid file name" });
  execFile("convert", [path.join("uploads", name), "-resize", "200x200", "thumbs/out.png"], (err) => {
    if (err) return res.status(500).json({ error: "Thumbnail failed" });
    res.json({ ok: true });
  });
});

app.get("/api/ai/describe", requireUser, async (req, res) => {
  // The LLM key now lives only on the server and is read from the environment.
  res.json({ configured: Boolean(process.env.LLM_API_KEY) });
});

app.listen(4000, () => console.log("Campus Bazaar API on :4000"));
