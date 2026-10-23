"""Framework-specific scanner extension for modern architectures (Next.js & Supabase).

Next.js projects often handle authentication globally in `middleware.ts` rather than
in individual API route files. Similarly, Supabase projects enforce authorization
at the database tier using Postgres Row Level Security (RLS) policies in
`supabase/migrations/*.sql`.

This extension checks for these modern protections and automatically lowers the
severity or dismisses 'missing server-side auth' warnings (PP-AUTH-003) for the
protected routes.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Literal

from .models import Finding, SourceFile

# Regex patterns for Next.js JWT and Auth validation in middleware
NEXTJS_JWT_PATTERNS: list[tuple[re.Pattern, str]] = [
    # NextAuth / Auth.js
    (re.compile(r"\bwithAuth\(", re.I), "NextAuth withAuth() middleware wrapper"),
    (re.compile(r"getToken\(\s*\{[^}]*req", re.I), "next-auth getToken() JWT verification"),
    (re.compile(r"['\"]next-auth(?:/jwt|/middleware)?['\"]", re.I), "next-auth JWT/middleware import"),
    (re.compile(r"export\s+\{\s*default\s*\}\s*from\s+['\"]next-auth/middleware['\"]", re.I), "next-auth default middleware export"),
    # Supabase Auth
    (re.compile(r"(?:supabase\.auth\.(?:getUser|getSession)|updateSession)\(", re.I), "Supabase auth session/user verification"),
    (re.compile(r"(?:createMiddlewareClient|createServerClient)\b", re.I), "Supabase middleware client session validation"),
    (re.compile(r"['\"]@supabase/(?:auth-helpers-nextjs|ssr)['\"]", re.I), "Supabase Next.js auth helper import"),
    # Clerk
    (re.compile(r"\b(?:clerkMiddleware|authMiddleware)\b|\bauth\(\)\.protect\(", re.I), "Clerk authentication middleware"),
    # Jose / jsonwebtoken
    (re.compile(r"\b(?:jwtVerify|jwt\.verify|decodeJwt)\(", re.I), "JWT verification (jose/jsonwebtoken)"),
    # Generic & custom token verification
    (re.compile(r"\b(?:verifyToken|validateToken|verifyJwt|checkAuth|authenticateRequest)\(", re.I), "Custom token verification function"),
    (re.compile(r"(?:headers\.get\(['\"]authorization['\"]\)|cookies\.get\(['\"](?:token|jwt|session|sb-[^'\"]+-auth-token)['\"]\))", re.I), "Authorization header / auth cookie token extraction"),
    (re.compile(r"\bjwt\b.*(?:\.verify|verify_signature|sub|payload|userId|user_id)", re.I), "JWT token payload verification"),
]

# Patterns for Supabase Row Level Security in SQL migrations
SUPABASE_RLS_ENABLE_PAT = re.compile(
    r"ALTER\s+TABLE\s+(?:ONLY\s+)?([A-Za-z0-9_.\"']+)\s+ENABLE\s+ROW\s+LEVEL\s+SECURITY",
    re.I,
)
SUPABASE_POLICY_PAT = re.compile(
    r"CREATE\s+POLICY\s+['\"]?([^'\"\n]+)['\"]?\s+ON\s+([A-Za-z0-9_.\"']+)",
    re.I,
)
SUPABASE_AUTH_HELPERS_PAT = re.compile(
    r"\bauth\.(?:uid|jwt|role|email)\(\)",
    re.I,
)


@dataclass
class NextJsMiddlewareInfo:
    file_path: str
    has_jwt_validation: bool
    evidence: list[str] = field(default_factory=list)
    matchers: list[str] = field(default_factory=list)
    matches_all: bool = False

    def protects_route(self, route_path: str, file_path: str = "") -> bool:
        """Check if this middleware protects the given route or file."""
        if not self.has_jwt_validation:
            return False
        if self.matches_all:
            return True

        norm_route = route_path.lower().strip()
        norm_file = file_path.lower().replace("\\", "/").strip()

        for m in self.matchers:
            clean_m = m.lower().replace(":path*", "").replace("(.*)", "").rstrip("/*").rstrip("/")
            if not clean_m:
                return True
            # Match against route path (e.g. /api/admin/users)
            if norm_route.startswith(clean_m) or clean_m in norm_route:
                return True
            # Match against file path (e.g. app/api/admin/users/route.ts)
            clean_suffix = clean_m.lstrip("/")
            if clean_suffix and clean_suffix in norm_file:
                return True

        return False


@dataclass
class SupabaseRlsInfo:
    migration_files: list[str] = field(default_factory=list)
    has_rls_policies: bool = False
    tables_with_rls: set[str] = field(default_factory=set)
    policies: list[dict[str, str]] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)

    def protects_route(self, route_path: str, file_path: str = "", file_content: str = "") -> bool:
        """Check if Supabase RLS protects the given route or database access."""
        if not self.has_rls_policies:
            return False

        norm_content = file_content.lower()
        norm_route = route_path.lower()
        norm_file = file_path.lower().replace("\\", "/")

        # 1. Does the route use Supabase client?
        uses_supabase = bool(
            re.search(r"@supabase/|createClient|supabase\.from\(|supabase\.rpc\(", norm_content)
        )

        # 2. Check if a specific table with RLS is mentioned or mapped to route
        for table in self.tables_with_rls:
            clean_tbl = table.rsplit(".", 1)[-1].strip("\"'").lower()
            if not clean_tbl:
                continue
            # Mentioned in route code e.g. .from('users') or .from("users")
            if f"'{clean_tbl}'" in norm_content or f'"{clean_tbl}"' in norm_content or f"`{clean_tbl}`" in norm_content:
                return True
            # Route path corresponds to table e.g. /api/users or /admin/users
            if f"/{clean_tbl}" in norm_route or f"/{clean_tbl}/" in norm_route or f"/{clean_tbl}." in norm_file:
                return True

        # 3. If file directly uses Supabase and project has RLS policies
        if uses_supabase and self.tables_with_rls:
            return True

        # 4. If project has RLS policies on main tables (like users, profiles, accounts) and route matches them
        route_segments = [seg for seg in re.split(r"[/._-]", norm_route) if seg]
        for seg in route_segments:
            if seg in self.tables_with_rls:
                return True

        return False


@dataclass
class FrameworkContext:
    nextjs_middleware: NextJsMiddlewareInfo | None = None
    supabase_rls: SupabaseRlsInfo | None = None
    dismissed_findings: list[tuple[Finding, str]] = field(default_factory=list)

    def is_route_protected(
        self, route_path: str, file_path: str = "", file_content: str = ""
    ) -> tuple[bool, str]:
        """Check if Next.js middleware or Supabase RLS protects this route."""
        if self.nextjs_middleware and self.nextjs_middleware.protects_route(route_path, file_path):
            ev = ", ".join(self.nextjs_middleware.evidence[:2])
            return True, f"Next.js middleware at `{self.nextjs_middleware.file_path}` validates JWTs ({ev})"

        if self.supabase_rls and self.supabase_rls.protects_route(route_path, file_path, file_content):
            tables = ", ".join(sorted(self.supabase_rls.tables_with_rls)[:3])
            tbl_info = f" (tables: {tables})" if tables else ""
            return True, f"Supabase Row Level Security (RLS) policies in `supabase/migrations/` enforce access control at the database tier{tbl_info}"

        return False, ""


def detect_nextjs_middleware(files: list[SourceFile]) -> NextJsMiddlewareInfo | None:
    """Find and inspect Next.js middleware.ts / middleware.js file."""
    middleware_file = None
    for f in files:
        name = f.path.rsplit("/", 1)[-1].lower()
        if name in ("middleware.ts", "middleware.js"):
            middleware_file = f
            break

    if not middleware_file:
        return None

    content = middleware_file.content
    evidence = []
    for pat, desc in NEXTJS_JWT_PATTERNS:
        if pat.search(content):
            evidence.append(desc)

    has_jwt_validation = len(evidence) > 0

    # Parse config.matcher
    matchers: list[str] = []
    matches_all = False

    # Extract matcher block: matcher: [...] or matcher: '...'
    matcher_m = re.search(r"\bmatcher\s*:\s*(\[[^\]]*\]|['\"][^'\"]+['\"])", content)
    if matcher_m:
        raw_val = matcher_m.group(1).strip()
        extracted = re.findall(r"['\"]([^'\"]+)['\"]", raw_val)
        for m in extracted:
            # Check for catch-all or negative lookahead patterns
            if "(?!" in m or m in ("/:path*", "/*", "/(.*)", "/"):
                matches_all = True
            matchers.append(m)
    else:
        # Next.js default when matcher is omitted is to run on all requests
        matches_all = True

    return NextJsMiddlewareInfo(
        file_path=middleware_file.path,
        has_jwt_validation=has_jwt_validation,
        evidence=evidence,
        matchers=matchers,
        matches_all=matches_all,
    )


def detect_supabase_rls(files: list[SourceFile]) -> SupabaseRlsInfo | None:
    """Find and inspect Supabase migration SQL files for Row Level Security policies."""
    migration_files = []
    tables_with_rls = set()
    policies = []
    evidence = []

    for f in files:
        norm = f.path.lower().replace("\\", "/")
        is_migration = (
            "supabase/migrations/" in norm
            or norm.startswith("supabase/migrations/")
            or ("migrations/" in norm and norm.endswith(".sql"))
            or (norm.endswith(".sql") and "supabase" in norm)
        )
        if not is_migration and not (norm.endswith(".sql") and "rls" in norm):
            continue

        migration_files.append(f.path)
        content = f.content

        # Check for ALTER TABLE ... ENABLE ROW LEVEL SECURITY
        for m in SUPABASE_RLS_ENABLE_PAT.finditer(content):
            raw_tbl = m.group(1).strip().strip("\"'").lower()
            clean_tbl = raw_tbl.rsplit(".", 1)[-1].strip("\"'")
            tables_with_rls.add(raw_tbl)
            tables_with_rls.add(clean_tbl)
            evidence.append(f"ENABLE ROW LEVEL SECURITY on {raw_tbl} in {f.path}")

        # Check for CREATE POLICY ... ON table
        for m in SUPABASE_POLICY_PAT.finditer(content):
            p_name, raw_tbl = m.group(1).strip(), m.group(2).strip().strip("\"'").lower()
            clean_tbl = raw_tbl.rsplit(".", 1)[-1].strip("\"'")
            tables_with_rls.add(raw_tbl)
            tables_with_rls.add(clean_tbl)
            policies.append({"table": raw_tbl, "policy": p_name, "file": f.path})
            evidence.append(f"Policy '{p_name}' on {raw_tbl}")

        # Check for auth.uid() usage
        if SUPABASE_AUTH_HELPERS_PAT.search(content):
            evidence.append(f"auth.uid()/jwt() helpers in {f.path}")

    if not migration_files and not tables_with_rls and not policies:
        return None

    has_rls_policies = bool(tables_with_rls or policies)
    return SupabaseRlsInfo(
        migration_files=migration_files,
        has_rls_policies=has_rls_policies,
        tables_with_rls=tables_with_rls,
        policies=policies,
        evidence=evidence,
    )


def detect_framework_protections(files: list[SourceFile]) -> FrameworkContext:
    """Aggregate all detected framework protections across project files."""
    return FrameworkContext(
        nextjs_middleware=detect_nextjs_middleware(files),
        supabase_rls=detect_supabase_rls(files),
    )


def extract_route_from_finding(finding: Finding) -> str:
    """Extract the route path from finding evidence, snippet, or file path."""
    # Example evidence: "`DELETE /admin/users/:id` has no auth middleware..."
    m = re.search(r"`(?:GET|POST|PUT|PATCH|DELETE|ALL)\s+([^`]+)`", finding.evidence, re.I)
    if m:
        return m.group(1).strip()
    m = re.search(r"`(?:GET|POST|PUT|PATCH|DELETE|ALL)\s+([^`]+)`", finding.snippet, re.I)
    if m:
        return m.group(1).strip()

    # Fallback to file path
    f_path = finding.file.replace("\\", "/")
    if "/api/" in f_path:
        sub = f_path[f_path.find("/api/"):]
        return sub.replace("/route.ts", "").replace("/route.js", "").replace(".ts", "").replace(".js", "")
    return "/" + finding.file


def apply_framework_extensions(
    files: list[SourceFile],
    findings: list[Finding],
    action: Literal["dismiss", "lower_severity"] = "dismiss",
) -> list[Finding]:
    """Inspect project for Next.js & Supabase protections and adjust findings.

    Parameters
    ----------
    files:
        Source files scanned in the project.
    findings:
        Raw findings list to filter or adjust.
    action:
        `"dismiss"` to remove protected route warnings completely, or
        `"lower_severity"` to downgrade to 'info' with contextual explanations.
    """
    ctx = detect_framework_protections(files)
    if not ctx.nextjs_middleware and not ctx.supabase_rls:
        return findings

    file_map = {f.path: f for f in files}
    result: list[Finding] = []

    for f in findings:
        # Only target 'missing server-side auth' warnings (PP-AUTH-003)
        if f.rule_id != "PP-AUTH-003":
            result.append(f)
            continue

        route_path = extract_route_from_finding(f)
        src_file = file_map.get(f.file)
        file_content = src_file.content if src_file else ""

        is_protected, reason = ctx.is_route_protected(route_path, f.file, file_content)
        if not is_protected:
            result.append(f)
            continue

        ctx.dismissed_findings.append((f, reason))

        if action == "dismiss":
            # Dismiss the finding entirely
            continue
        elif action == "lower_severity":
            # Lower the severity to info and update context/evidence
            f.severity = "info"
            f.confidence = "low"
            f.kind = "heuristic"
            f.evidence = f"{f.evidence}\n[Framework Protection Verified] {reason}."
            f.description = f"{f.description} (Note: {reason})"
            result.append(f)
        else:
            # Fallback
            continue

    return result
