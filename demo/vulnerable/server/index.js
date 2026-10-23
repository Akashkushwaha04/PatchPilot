// Campus Bazaar API — SYNTHETIC, INTENTIONALLY VULNERABLE DEMO CODE.
const express = require("express");
const cors = require("cors");
const { exec } = require("child_process");
const { Pool } = require("pg");
const jwt = require("jsonwebtoken");

const app = express();
app.use(express.json());
app.use(cors({ origin: "*", credentials: true }));

const db = new Pool({ connectionString: process.env.DATABASE_URL });

app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  console.log("Login attempt", email, password);
  const user = await db.query("SELECT * FROM users WHERE email = $1", [email]);
  if (!user.rows.length) return res.status(401).json({ error: "Invalid login" });
  const token = jwt.sign({ id: user.rows[0].id }, process.env.JWT_SECRET);
  res.json({ token, role: user.rows[0].role });
});

app.get("/api/products/search", async (req, res) => {
  try {
    const q = req.query.q;
    const result = await db.query("SELECT * FROM products WHERE name LIKE '%" + q + "%'");
    res.json(result.rows);
  } catch (err) {
    res.status(500).send(err.stack);
  }
});

app.get("/api/orders/export", async (req, res) => {
  const result = await db.query("SELECT id, email, total FROM orders");
  res.json(result.rows);
});

app.delete("/api/admin/users/:id", async (req, res) => {
  if (req.query.isAdmin !== "true") return res.status(403).json({ error: "Forbidden" });
  await db.query(`DELETE FROM users WHERE id = ${req.params.id}`);
  res.json({ deleted: req.params.id });
});

app.post("/api/products/thumbnail", (req, res) => {
  exec("convert uploads/" + req.body.filename + " -resize 200x200 thumbs/out.png", (err) => {
    if (err) return res.status(500).json({ error: "Thumbnail failed" });
    res.json({ ok: true });
  });
});

app.listen(4000, () => console.log("Campus Bazaar API on :4000"));
