"""Unit tests for Next.js and Supabase framework scanner extensions."""
import pytest
from app.scanner import (
    SourceFile,
    apply_framework_extensions,
    detect_framework_protections,
    detect_nextjs_middleware,
    detect_supabase_rls,
    scan_files,
)


# ----------------------------------------------------------------
# Next.js Middleware Tests
# ----------------------------------------------------------------

def test_detect_nextjs_middleware_with_jwt_validation():
    middleware_code = """
import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { getToken } from 'next-auth/jwt';

export async function middleware(req: NextRequest) {
  const token = await getToken({ req, secret: process.env.NEXTAUTH_SECRET });
  if (!token) {
    return NextResponse.redirect(new URL('/login', req.url));
  }
  return NextResponse.next();
}

export const config = {
  matcher: ['/api/admin/:path*', '/dashboard/:path*'],
};
"""
    files = [SourceFile("middleware.ts", middleware_code)]
    info = detect_nextjs_middleware(files)
    assert info is not None
    assert info.has_jwt_validation is True
    assert info.matches_all is False
    assert "/api/admin/:path*" in info.matchers
    assert info.protects_route("/api/admin/users") is True
    assert info.protects_route("/dashboard/settings") is True
    assert info.protects_route("/public/home") is False


def test_detect_nextjs_middleware_supabase_auth_and_catchall():
    middleware_code = """
import { createServerClient } from '@supabase/ssr';
import { NextResponse, type NextRequest } from 'next/server';

export async function middleware(request: NextRequest) {
  const supabase = createServerClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
    { cookies: {} }
  );
  const { data: { user } } = await supabase.auth.getUser();
  if (!user && request.nextUrl.pathname.startsWith('/api')) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }
  return NextResponse.next();
}

export const config = {
  matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'],
};
"""
    files = [SourceFile("src/middleware.ts", middleware_code)]
    info = detect_nextjs_middleware(files)
    assert info is not None
    assert info.has_jwt_validation is True
    assert info.matches_all is True
    assert info.protects_route("/api/admin/delete") is True
    assert info.protects_route("/api/users/123") is True


def test_detect_nextjs_middleware_without_jwt():
    middleware_code = """
import { NextResponse } from 'next/server';

export function middleware(req) {
  console.log("Request visited:", req.url);
  return NextResponse.next();
}
"""
    files = [SourceFile("middleware.js", middleware_code)]
    info = detect_nextjs_middleware(files)
    assert info is not None
    assert info.has_jwt_validation is False
    assert info.protects_route("/api/admin") is False


# ----------------------------------------------------------------
# Supabase Row Level Security (RLS) Tests
# ----------------------------------------------------------------

def test_detect_supabase_rls_migrations():
    migration_sql = """
-- Create tables
CREATE TABLE public.users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email TEXT NOT NULL,
    role TEXT DEFAULT 'user'
);

-- Enable Row Level Security
ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;

-- Policies
CREATE POLICY "Users can view own data"
    ON public.users
    FOR SELECT
    USING (auth.uid() = id);

CREATE POLICY "Admins can manage users"
    ON public.users
    FOR ALL
    USING (auth.jwt() ->> 'role' = 'admin');
"""
    files = [SourceFile("supabase/migrations/20240101000000_init.sql", migration_sql)]
    info = detect_supabase_rls(files)
    assert info is not None
    assert info.has_rls_policies is True
    assert "users" in info.tables_with_rls
    assert len(info.policies) == 2
    assert info.protects_route("/api/admin/users", "app/api/admin/users/route.ts", "await supabase.from('users').delete()") is True


def test_detect_supabase_migration_without_rls():
    migration_sql = """
CREATE TABLE public.logs (
    id SERIAL PRIMARY KEY,
    message TEXT
);
"""
    files = [SourceFile("supabase/migrations/20240101000000_logs.sql", migration_sql)]
    info = detect_supabase_rls(files)
    assert info is not None
    assert info.has_rls_policies is False
    assert len(info.tables_with_rls) == 0


# ----------------------------------------------------------------
# End-to-End Scan: Next.js Route Protection
# ----------------------------------------------------------------

def test_nextjs_route_without_middleware_flags_auth_warning():
    route_file = SourceFile(
        "app/api/admin/users/route.ts",
        """
export async function DELETE(request: Request) {
    const { id } = await request.json();
    await db.users.delete({ where: { id } });
    return Response.json({ success: true });
}
"""
    )
    findings = scan_files([route_file])
    assert any(f.rule_id == "PP-AUTH-003" for f in findings)


def test_nextjs_route_with_jwt_middleware_dismisses_auth_warning():
    route_file = SourceFile(
        "app/api/admin/users/route.ts",
        """
export async function DELETE(request: Request) {
    const { id } = await request.json();
    await db.users.delete({ where: { id } });
    return Response.json({ success: true });
}
"""
    )
    middleware_file = SourceFile(
        "middleware.ts",
        """
import { NextResponse } from 'next/server';
import { getToken } from 'next-auth/jwt';

export async function middleware(req) {
  const token = await getToken({ req });
  if (!token) return NextResponse.redirect('/login');
  return NextResponse.next();
}

export const config = {
  matcher: ['/api/admin/:path*'],
};
"""
    )
    # Default dismissal action
    findings = scan_files([route_file, middleware_file], framework_auth_action="dismiss")
    auth_findings = [f for f in findings if f.rule_id == "PP-AUTH-003"]
    assert len(auth_findings) == 0


def test_nextjs_route_with_jwt_middleware_lowers_severity():
    route_file = SourceFile(
        "app/api/admin/users/route.ts",
        """
export async function DELETE(request: Request) {
    const { id } = await request.json();
    await db.users.delete({ where: { id } });
    return Response.json({ success: true });
}
"""
    )
    middleware_file = SourceFile(
        "middleware.ts",
        """
import { NextResponse } from 'next/server';
import { getToken } from 'next-auth/jwt';

export async function middleware(req) {
  const token = await getToken({ req });
  if (!token) return NextResponse.redirect('/login');
  return NextResponse.next();
}

export const config = {
  matcher: ['/api/admin/:path*'],
};
"""
    )
    # Lower severity action
    findings = scan_files([route_file, middleware_file], framework_auth_action="lower_severity")
    auth_findings = [f for f in findings if f.rule_id == "PP-AUTH-003"]
    assert len(auth_findings) == 1
    assert auth_findings[0].severity == "info"
    assert "Framework Protection Verified" in auth_findings[0].evidence
    assert "Next.js middleware" in auth_findings[0].evidence


# ----------------------------------------------------------------
# End-to-End Scan: Supabase RLS Route Protection
# ----------------------------------------------------------------

def test_supabase_route_with_rls_policies_dismisses_auth_warning():
    route_file = SourceFile(
        "server/routes/users.js",
        """
const express = require('express');
const router = express.Router();

router.delete('/admin/users/:id', async (req, res) => {
    const { data, error } = await supabase.from('users').delete().eq('id', req.params.id);
    res.json({ success: true });
});
"""
    )
    migration_file = SourceFile(
        "supabase/migrations/20240101_init.sql",
        """
CREATE TABLE users (id UUID PRIMARY KEY, name TEXT);
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Users can only delete self" ON users FOR DELETE USING (auth.uid() = id);
"""
    )
    findings = scan_files([route_file, migration_file], framework_auth_action="dismiss")
    auth_findings = [f for f in findings if f.rule_id == "PP-AUTH-003"]
    assert len(auth_findings) == 0


def test_supabase_route_with_rls_policies_lowers_severity():
    route_file = SourceFile(
        "server/routes/users.js",
        """
const express = require('express');
const router = express.Router();

router.delete('/admin/users/:id', async (req, res) => {
    const { data, error } = await supabase.from('users').delete().eq('id', req.params.id);
    res.json({ success: true });
});
"""
    )
    migration_file = SourceFile(
        "supabase/migrations/20240101_init.sql",
        """
CREATE TABLE users (id UUID PRIMARY KEY, name TEXT);
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Users can only delete self" ON users FOR DELETE USING (auth.uid() = id);
"""
    )
    findings = scan_files([route_file, migration_file], framework_auth_action="lower_severity")
    auth_findings = [f for f in findings if f.rule_id == "PP-AUTH-003"]
    assert len(auth_findings) == 1
    assert auth_findings[0].severity == "info"
    assert "Supabase Row Level Security" in auth_findings[0].evidence
