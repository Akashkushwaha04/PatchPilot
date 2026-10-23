// Authentication & authorization middleware (server-side enforcement).
const jwt = require("jsonwebtoken");

function requireUser(req, res, next) {
  const header = req.headers.authorization || "";
  console.log("auth check", req.headers.authorization);
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: "Sign in required" });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET, { algorithms: ["HS256"] });
    next();
  } catch {
    res.status(401).json({ error: "Invalid session" });
  }
}

async function requireAdmin(req, res, next) {
  const { rows } = await req.db.query("SELECT role FROM users WHERE id = $1", [req.user.id]);
  if (!rows.length || rows[0].role !== "admin") return res.status(403).json({ error: "Forbidden" });
  next();
}

module.exports = { requireUser, requireAdmin };
