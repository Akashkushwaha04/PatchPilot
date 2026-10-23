"""Small labelled synthetic dataset used to measure the scanner.

`PLANTED` cases each contain one intentionally vulnerable snippet and the rule
ID expected to catch it. `SAFE` cases are secure or placeholder code that must
produce no findings. Metrics are computed by actually running the scanner.
All credentials here are synthetic and inert.
"""
from __future__ import annotations

from dataclasses import dataclass

from .scanner import SourceFile, scan_files


@dataclass(frozen=True)
class Case:
    id: str
    description: str
    path: str
    content: str
    expect: str | None  # rule ID that must fire; None = must stay clean


PLANTED: list[Case] = [
    Case("secret-openai", "OpenAI-style key in client config", "src/config.js",
         'export const KEY = "sk-proj-Ab3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5bC7d";\n', "PP-SEC-001"),
    Case("secret-aws", "AWS access key ID in Python settings", "settings.py",
         'AWS_ACCESS_KEY_ID = "AKIAZ7Q2K9W4M1N8P3R6"\n', "PP-SEC-001"),
    Case("secret-github", "GitHub token in deploy script", "scripts/deploy.js",
         'const gh = "ghp_' + "R7t2Kq9Lm4Np6Vx8Zb1Cd3Fg5Hj7Kl9Mn2Pq" + '";\n', "PP-SEC-001"),
    Case("secret-password", "Hardcoded admin password", "server/db.js",
         'const adminPassword = "Tr0ub4dor&3xyz";\n', "PP-SEC-003"),
    Case("secret-private-key", "PEM private key in repo", "certs/key.js",
         'const pem = `-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA7synthetic\n-----END RSA PRIVATE KEY-----`;\n', "PP-SEC-002"),
    Case("secret-vite-env", "Secret in VITE_ variable", ".env.production",
         "VITE_STRIPE_SECRET_KEY=stripe_sec_8Hk2Lp9Qw3Er5Ty7Ui\n", "PP-SEC-004"),
    Case("secret-db-url", "Database URL with password", "server/config.py",
         'DB = "postgresql://shop:K9x2mPq7Lw@db.example-host.net/shop"\n', "PP-SEC-005"),
    Case("xss-react", "dangerouslySetInnerHTML with user bio", "src/Profile.jsx",
         "export const P = ({ user }) => <div dangerouslySetInnerHTML={{ __html: user.bio }} />;\n", "PP-XSS-001"),
    Case("xss-dom", "innerHTML from URL hash", "public/app.js",
         "const name = location.hash.slice(1);\ndocument.getElementById('hi').innerHTML = 'Hi ' + name;\n", "PP-XSS-002"),
    Case("xss-vue", "Vue v-html on comment", "src/Comment.vue",
         '<template><div v-html="comment.text"></div></template>\n', "PP-XSS-003"),
    Case("auth-client-storage", "Admin flag from localStorage", "src/components/Nav.jsx",
         "const admin = localStorage.getItem('isAdmin') === 'true';\n", "PP-AUTH-004"),
    Case("auth-server-trust", "Server trusts ?role=admin", "server/routes.js",
         "const express = require('express');\nconst app = express();\napp.post('/api/promote', (req, res) => {\n  if (req.body.role === 'admin') grant(req.body.userId);\n});\n", "PP-AUTH-002"),
    Case("auth-route", "Unprotected admin delete route", "server/admin.js",
         "const express = require('express');\nconst router = express.Router();\nrouter.delete('/admin/users/:id', async (req, res) => {\n  await User.destroy({ where: { id: req.params.id } });\n  res.sendStatus(204);\n});\n", "PP-AUTH-003"),
    Case("cors-wildcard", "FastAPI allow_origins=['*']", "main.py",
         "from fastapi.middleware.cors import CORSMiddleware\napp.add_middleware(CORSMiddleware, allow_origins=['*'], allow_credentials=True)\n", "PP-CFG-001"),
    Case("cfg-debug", "Flask debug=True", "app.py",
         "from flask import Flask\napp = Flask(__name__)\napp.run(host='0.0.0.0', debug=True)\n", "PP-CFG-002"),
    Case("cfg-tls", "requests verify=False", "client.py",
         "import requests\nr = requests.get(url, verify=False)\n", "PP-CFG-003"),
    Case("cfg-cookie", "httpOnly: false session cookie", "server/session.js",
         "res.cookie('sid', id, { httpOnly: false, secure: false });\n", "PP-CFG-004"),
    Case("cfg-jwt", "JWT decoded without verification", "auth.py",
         "import jwt\nclaims = jwt.decode(token, options={'verify_signature': False})\n", "PP-CFG-005"),
    Case("inj-sql-py", "f-string SQL in Python", "db.py",
         "def find(cur, name):\n    cur.execute(f\"SELECT * FROM users WHERE name = '{name}'\")\n", "PP-INJ-001"),
    Case("inj-sql-js", "Concatenated SQL in Express", "server/users.js",
         "db.query(\"SELECT * FROM users WHERE id = \" + req.params.id);\n", "PP-INJ-001"),
    Case("inj-cmd", "os.system with user input", "tools.py",
         "import os\ndef ping(host):\n    os.system('ping -c 1 ' + host)\n", "PP-INJ-002"),
    Case("inj-eval", "eval on request body", "server/calc.js",
         "app.post('/calc', (req, res) => res.json(eval(req.body.expr)));\n", "PP-INJ-003"),
    Case("inj-pickle", "pickle.loads on request data", "api.py",
         "import pickle\ndata = pickle.loads(request.data)\n", "PP-INJ-004"),
    Case("exp-log", "Password logged", "server/login.js",
         "console.log('login', user.email, password);\n", "PP-EXP-001"),
    Case("exp-env", "Committed .env with real values", ".env",
         "API_SECRET=q8Lw2Zr7Xk4Nv9Pt3Ys6\n", "PP-EXP-002"),
]

SAFE: list[Case] = [
    Case("safe-placeholder-env", ".env.example with placeholders", ".env.example",
         "OPENAI_API_KEY=your_openai_key_here\nDATABASE_URL=postgres://USER:PASSWORD@localhost/db\nJWT_SECRET=change_me\n", None),
    Case("safe-env-ref", "Secret read from environment", "server/config.js",
         "const apiKey = process.env.OPENAI_API_KEY;\nconst password = process.env.DB_PASSWORD;\n", None),
    Case("safe-react-text", "React escaped text rendering", "src/Comment.jsx",
         "export const C = ({ c }) => <p>{c.body}</p>;\n", None),
    Case("safe-sanitized", "dangerouslySetInnerHTML with DOMPurify", "src/Rich.jsx",
         "import DOMPurify from 'dompurify';\nconst clean = DOMPurify.sanitize(html);\nexport const R = () => <div dangerouslySetInnerHTML={{ __html: clean }} />;\n", None),
    Case("safe-textcontent", "textContent for user text", "public/hi.js",
         "const name = new URLSearchParams(location.search).get('n');\nel.textContent = 'Hi ' + name;\n", None),
    Case("safe-static-innerhtml", "innerHTML with constant string", "public/ui.js",
         "list.innerHTML = '';\n", None),
    Case("safe-param-sql-js", "Parameterized SQL (pg)", "server/q.js",
         "db.query('SELECT * FROM users WHERE id = $1', [req.params.id]);\n", None),
    Case("safe-param-sql-py", "Parameterized SQL (DB-API)", "repo.py",
         "cur.execute('SELECT * FROM users WHERE email = %s', (email,))\n", None),
    Case("safe-cors-list", "CORS allow-list", "server/app.js",
         "app.use(cors({ origin: ['https://shop.example.com'], credentials: true }));\n", None),
    Case("safe-subprocess", "subprocess list without shell", "jobs.py",
         "import subprocess\nsubprocess.run(['convert', path, 'out.png'], check=True)\n", None),
    Case("safe-protected-route", "Admin route with middleware", "server/admin.js",
         "const express = require('express');\nconst router = express.Router();\nrouter.delete('/admin/users/:id', requireAdmin, async (req, res) => {\n  res.sendStatus(204);\n});\n", None),
    Case("safe-log-label", "Log message mentioning a password reset", "server/mail.js",
         "console.log('Password reset email sent to', user.id);\n", None),
    Case("safe-ui-label", "Form label strings", "src/Form.jsx",
         'const labels = { password: "Enter your password", token: "Paste token here" };\n', None),
    Case("safe-jwt-verify", "JWT verified with fixed algorithm", "auth.py",
         "import jwt\nclaims = jwt.decode(token, SECRET, algorithms=['HS256'])\n", None),
    Case("safe-comment-secret-word", "Comment mentioning secrets", "src/util.js",
         "// Never hardcode an api_key; read it from the server instead.\nexport const noop = () => {};\n", None),
]


def run_evaluation() -> dict:
    planted_results, safe_results = [], []
    for c in PLANTED:
        found = scan_files([SourceFile(c.path, c.content)])
        rule_ids = sorted({f.rule_id for f in found})
        planted_results.append({"id": c.id, "description": c.description, "expected": c.expect,
                                "detected": c.expect in rule_ids, "rules_fired": rule_ids})
    for c in SAFE:
        found = scan_files([SourceFile(c.path, c.content)])
        safe_results.append({"id": c.id, "description": c.description,
                             "false_positive": bool(found), "rules_fired": sorted({f.rule_id for f in found})})
    detected = sum(r["detected"] for r in planted_results)
    fps = sum(r["false_positive"] for r in safe_results)
    return {
        "planted": len(PLANTED),
        "detected": detected,
        "missed": len(PLANTED) - detected,
        "safe_cases": len(SAFE),
        "false_positives": fps,
        "detection_rate": round(detected / len(PLANTED), 3),
        "planted_results": planted_results,
        "safe_results": safe_results,
        "note": "Computed live by running the scanner on a small synthetic dataset "
                f"({len(PLANTED)} planted, {len(SAFE)} safe). It shows the rules work as designed; "
                "it is not a measure of real-world accuracy.",
    }
