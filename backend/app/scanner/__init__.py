from .engine import scan_files, scan_files_async, shutdown_executor
from .frameworks import (
    FrameworkContext,
    NextJsMiddlewareInfo,
    SupabaseRlsInfo,
    apply_framework_extensions,
    detect_framework_protections,
    detect_nextjs_middleware,
    detect_supabase_rls,
)
from .models import Finding, SourceFile
from .rules import ALL_RULES, RULES_BY_ID
from .sca import extract_dependencies, parse_package_json, parse_requirements_txt, query_osv_package, run_sca_scan
from .secret_verify import TokenVerificationResult, verify_finding_secret, verify_token_active
from .semgrep import is_semgrep_available, parse_semgrep_output, run_semgrep_on_directory, run_semgrep_on_files

__all__ = [
    "scan_files",
    "scan_files_async",
    "shutdown_executor",
    "apply_framework_extensions",
    "detect_framework_protections",
    "detect_nextjs_middleware",
    "detect_supabase_rls",
    "FrameworkContext",
    "NextJsMiddlewareInfo",
    "SupabaseRlsInfo",
    "verify_token_active",
    "verify_finding_secret",
    "TokenVerificationResult",
    "extract_dependencies",
    "parse_package_json",
    "parse_requirements_txt",
    "query_osv_package",
    "run_sca_scan",
    "is_semgrep_available",
    "parse_semgrep_output",
    "run_semgrep_on_directory",
    "run_semgrep_on_files",
    "Finding",
    "SourceFile",
    "ALL_RULES",
    "RULES_BY_ID",
]
