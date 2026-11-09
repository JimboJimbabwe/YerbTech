#!/usr/bin/env python3
"""
WSTG-CONF-02 — Application Platform Configuration
Script: conf_02_wordlist.py

Builds a wordlist for probing exposed configuration, debug, and default
paths on an application platform. Sources:

  1. Hardcoded base lists (categorised):
       debug       — /debug, /actuator, /swagger-ui, /phpinfo, etc.
       dotslash    — ./ and ../ traversal variants
       config      — /config, /conf, /settings, /admin, /management, etc.
       default     — common framework default paths (/app, /api/v1, etc.)

  2. svc_repo.json  (secondary service repo — same logic as BUSL-08)
       Reads Ports[] → PotentialServices[] →
         DefaultEndpoints + CommonEndpoints + UndesirableEndpoints
       Tagged as category "svc_repo"

  3. MISSING LOGIC stub  (primary service repo)
       Returns [] with a yellow terminal warning

  4. OBJ1 / OBJ2 backup variant generation
       Every path from sources 1–3 gets backup/old suffixes appended:
         .bak  .backup  .old  .orig  .1  .swp  ~
         _bak  _backup  _old  _orig  _copy
         /bak  /backup  /old
       These go into category "backup_variants"

Outputs:
  WSTG-CONF-02/inputs/wordlist/conf_02_paths.txt   — flat Burp-ready list
  WSTG-CONF-02/inputs/json/conf_02_paths.json      — categorised JSON

Usage:
  python3 WSTG-CONF-02/utilities/python/conf_02_wordlist.py \\
      [--repo  WSTG-CONF-02/inputs/json/svc_repo.json]
"""

import argparse
import json
import os
import sys
from datetime import datetime


# ---------------------------------------------------------------------------
# ANSI
# ---------------------------------------------------------------------------
BOLD    = "\033[1m"
DIM     = "\033[2m"
GREEN   = "\033[92m"
YELLOW  = "\033[93m"
RED     = "\033[91m"
CYAN    = "\033[96m"
RESET   = "\033[0m"


# ---------------------------------------------------------------------------
# Hardcoded base lists — categorised
# ---------------------------------------------------------------------------

DEBUG_PATHS = [
    # Generic debug/test endpoints
    "/debug",
    "/Debug",
    "/DEBUG",
    "/debug/",
    "/debug/vars",
    "/debug/pprof",
    "/debug/pprof/",
    "/debug/pprof/heap",
    "/debug/pprof/goroutine",
    "/debug/pprof/cmdline",
    "/debug/pprof/profile",
    "/debug/pprof/trace",
    "/debug/metrics",
    "/debug/info",
    "/debug/env",
    "/debug/routes",
    "/debug/logs",
    "/debug/requests",
    "/.debug",
    "/test",
    "/test/",
    "/testing",
    "/trace",
    "/traces",
    # Spring Boot Actuator
    "/actuator",
    "/actuator/",
    "/actuator/env",
    "/actuator/beans",
    "/actuator/configprops",
    "/actuator/dump",
    "/actuator/health",
    "/actuator/info",
    "/actuator/logfile",
    "/actuator/loggers",
    "/actuator/mappings",
    "/actuator/metrics",
    "/actuator/shutdown",
    "/actuator/threaddump",
    "/actuator/trace",
    "/actuator/httptrace",
    "/actuator/auditevents",
    "/actuator/scheduledtasks",
    "/actuator/flyway",
    "/actuator/liquibase",
    "/actuator/refresh",
    # PHP info / diagnostics
    "/phpinfo.php",
    "/phpinfo",
    "/info.php",
    "/php_info.php",
    "/test.php",
    "/check.php",
    # Django / Python
    "/__debug__/",
    "/__debug__/sql/",
    "/__debug__/static/",
    "/django-admin/",
    # Rails
    "/rails/info",
    "/rails/info/properties",
    "/rails/info/routes",
    "/rails/mailers",
    # Node / Express
    "/_debug",
    "/node_modules/",
    # Swagger / OpenAPI
    "/swagger",
    "/swagger/",
    "/swagger-ui",
    "/swagger-ui/",
    "/swagger-ui.html",
    "/swagger-ui/index.html",
    "/swagger.json",
    "/swagger.yaml",
    "/swagger.yml",
    "/api-docs",
    "/api-docs/",
    "/v2/api-docs",
    "/v3/api-docs",
    "/openapi",
    "/openapi.json",
    "/openapi.yaml",
    "/openapi.yml",
    "/api/swagger",
    "/api/swagger-ui",
    "/api/docs",
    "/redoc",
    "/docs/",
    # Health / status
    "/health",
    "/health/",
    "/healthcheck",
    "/healthz",
    "/livez",
    "/readyz",
    "/ping",
    "/status",
    "/status/",
    "/version",
    "/version.json",
    "/build",
    "/build.json",
    "/info",
    "/info/",
    # Metrics
    "/metrics",
    "/metrics/",
    "/prometheus",
    "/prometheus/metrics",
    "/_prometheus/metrics",
    "/grafana",
    # Environment / config dumps
    "/env",
    "/env/",
    "/_env",
    "/environment",
    # Error / diagnostics
    "/error",
    "/error/",
    "/errors",
    "/500",
    "/400",
    "/404",
    "/403",
    # Profiling
    "/pprof",
    "/profile",
    "/profiler",
]

DOTSLASH_PATHS = [
    # Dot-slash and dot-dot traversal variants as URL paths
    "./",
    "../",
    "./../",
    "../../",
    "../../../",
    ".%2F",
    "..%2F",
    ".%2F.%2F",
    "%2F.",
    "%2F..",
    "%2F..%2F",
    "%2F%2F",
    "%252F",
    "%252F%252F",
    "..%252F",
    ".%252F",
    "..%c0%af",
    "..%c1%9c",
    "..%5c",
    "..\\/",
    # Hidden / dot files
    "/.git",
    "/.git/",
    "/.git/HEAD",
    "/.git/config",
    "/.git/index",
    "/.git/COMMIT_EDITMSG",
    "/.gitignore",
    "/.gitmodules",
    "/.svn",
    "/.svn/entries",
    "/.hg",
    "/.hg/hgrc",
    "/.env",
    "/.env.local",
    "/.env.dev",
    "/.env.development",
    "/.env.prod",
    "/.env.production",
    "/.env.staging",
    "/.env.test",
    "/.env.backup",
    "/.env.bak",
    "/.env.old",
    "/.htaccess",
    "/.htpasswd",
    "/.well-known",
    "/.well-known/",
    "/.well-known/security.txt",
    "/.well-known/openid-configuration",
    "/.DS_Store",
    "/.idea",
    "/.idea/",
    "/.vscode",
    "/.vscode/",
    "/.npmrc",
    "/.yarnrc",
    "/.bash_history",
    "/.bash_profile",
    "/.bashrc",
    "/.ssh",
    "/.ssh/id_rsa",
    "/.ssh/id_rsa.pub",
    "/.ssh/authorized_keys",
    "/.ssh/known_hosts",
    # Dot-paths with files
    "./config.json",
    "./settings.json",
    "./database.yml",
    "./secrets.yml",
    "./docker-compose.yml",
    "./docker-compose.yaml",
    "./Dockerfile",
    "./Makefile",
    "./package.json",
    "./composer.json",
    "./requirements.txt",
    "./Pipfile",
    "./Gemfile",
    "./pom.xml",
    "./build.gradle",
]

CONFIG_PATHS = [
    # Generic config
    "/config",
    "/config/",
    "/configs",
    "/configuration",
    "/conf",
    "/conf/",
    "/settings",
    "/settings.json",
    "/settings.yaml",
    "/settings.yml",
    "/settings.php",
    "/settings.py",
    "/setting",
    # App config files
    "/config.json",
    "/config.yaml",
    "/config.yml",
    "/config.xml",
    "/config.php",
    "/config.rb",
    "/config.py",
    "/config.ini",
    "/config.cfg",
    "/config.env",
    "/app.config",
    "/web.config",
    "/application.yml",
    "/application.yaml",
    "/application.properties",
    "/application.json",
    "/bootstrap.yml",
    "/bootstrap.yaml",
    "/bootstrap.json",
    # Database config
    "/database.yml",
    "/database.yaml",
    "/database.json",
    "/db.json",
    "/db.config",
    "/db_config.php",
    "/dbconfig.php",
    # Admin / management
    "/admin",
    "/admin/",
    "/admin/config",
    "/administration",
    "/administrator",
    "/administrator/",
    "/manage",
    "/manage/",
    "/management",
    "/management/",
    "/manager",
    "/manager/",
    "/panel",
    "/panel/",
    "/cpanel",
    "/control",
    "/controlpanel",
    "/dashboard",
    "/dashboard/",
    # Server config files
    "/nginx.conf",
    "/httpd.conf",
    "/apache.conf",
    "/apache2.conf",
    "/server.xml",
    "/web.xml",
    "/context.xml",
    # Secrets / keys
    "/secrets",
    "/secrets/",
    "/secret",
    "/keys",
    "/keys/",
    "/key",
    "/private",
    "/private/",
    "/credentials",
    "/credentials.json",
    "/credentials.xml",
    "/certs",
    "/certs/",
    "/ssl",
    "/ssl/",
    "/tls",
    "/tls/",
    # Logs (configuration-adjacent — exposed logs often reveal config)
    "/logs",
    "/logs/",
    "/log",
    "/log/",
    "/log/access.log",
    "/log/error.log",
    "/logs/access.log",
    "/logs/error.log",
    "/var/log",
    "/var/log/",
    # Infrastructure / deploy
    "/docker-compose.yml",
    "/docker-compose.yaml",
    "/Dockerfile",
    "/k8s",
    "/k8s/",
    "/kubernetes",
    "/terraform",
    "/ansible",
    "/Makefile",
    "/.terraform",
    "/.terraform/",
    "/deploy",
    "/deploy/",
    "/deployment",
    "/infrastructure",
    # CI/CD
    "/.github",
    "/.github/",
    "/.github/workflows",
    "/.circleci",
    "/.circleci/config.yml",
    "/.travis.yml",
    "/Jenkinsfile",
    "/.gitlab-ci.yml",
]

DEFAULT_PLATFORM_PATHS = [
    # PHP defaults
    "/index.php",
    "/info.php",
    "/phpMyAdmin",
    "/phpmyadmin",
    "/pma",
    "/myadmin",
    "/wp-admin",
    "/wp-login.php",
    "/wp-config.php",
    "/wp-content",
    "/wp-includes",
    "/wp-json",
    "/wp-json/wp/v2",
    "/xmlrpc.php",
    # Joomla
    "/administrator",
    "/administrator/",
    "/joomla",
    # Drupal
    "/user/login",
    "/admin/config",
    "/sites/default/settings.php",
    # Java / Tomcat
    "/manager",
    "/manager/html",
    "/host-manager",
    "/host-manager/html",
    "/struts",
    "/struts2",
    "/WEB-INF",
    "/WEB-INF/web.xml",
    "/META-INF",
    "/META-INF/context.xml",
    # IIS
    "/iisadmin",
    "/iisadmpwd",
    "/_vti_bin",
    "/_vti_pvt",
    "/_vti_cnf",
    "/_vti_log",
    "/_vti_txt",
    # Python / Django / Flask
    "/admin/",
    "/api/",
    "/api/v1/",
    "/api/v2/",
    "/api/v3/",
    "/rest/",
    "/rest/api/",
    "/graphql",
    "/graphql/",
    "/graphiql",
    "/playground",
    # Ruby on Rails
    "/rails",
    "/sidekiq",
    "/resque",
    # Node / Express
    "/app",
    "/app/",
    "/server",
    "/server/",
    # General API / portal defaults
    "/portal",
    "/portal/",
    "/gateway",
    "/gateway/",
    "/proxy",
    "/proxy/",
    "/api-gateway",
    "/console",
    "/console/",
    "/shell",
    "/shell/",
    # Auth defaults
    "/login",
    "/logout",
    "/signup",
    "/register",
    "/forgot-password",
    "/reset-password",
    "/oauth",
    "/oauth/",
    "/oauth/authorize",
    "/oauth/token",
    "/oauth2",
    "/oauth2/",
    "/oauth2/authorize",
    "/oauth2/token",
    "/saml",
    "/saml/",
    "/sso",
    "/sso/",
    "/auth",
    "/auth/",
    "/authenticate",
    "/token",
    # Upload defaults
    "/upload",
    "/uploads",
    "/files",
    "/file",
    "/static",
    "/static/",
    "/assets",
    "/assets/",
    "/public",
    "/public/",
    "/media",
    "/media/",
    "/images",
    "/js",
    "/css",
    "/dist",
    "/build",
    # README / doc files often left on server
    "/README",
    "/README.md",
    "/README.txt",
    "/CHANGELOG",
    "/CHANGELOG.md",
    "/INSTALL",
    "/INSTALL.md",
    "/COPYING",
    "/LICENSE",
    "/TODO",
    "/TODO.md",
    # Backup / temp files
    "/backup",
    "/backup/",
    "/backups",
    "/bak",
    "/temp",
    "/temp/",
    "/tmp",
    "/tmp/",
    "/old",
    "/old/",
    "/archive",
    "/archive/",
]

BACKUP_SUFFIXES = [
    ".bak",
    ".backup",
    ".old",
    ".orig",
    ".1",
    ".2",
    ".swp",
    ".swo",
    "~",
    "_bak",
    "_backup",
    "_old",
    "_orig",
    "_copy",
    ".copy",
    "/bak",
    "/backup",
    "/old",
]


# ---------------------------------------------------------------------------
# svc_repo.json reader — same logic as BUSL-08
# ---------------------------------------------------------------------------

def get_primary_repo_paths() -> list[str]:
    """MISSING LOGIC — Primary service repository lookup. Returns []."""
    print(f"  {YELLOW}[!] Primary service repo: MISSING LOGIC — returning []{RESET}")
    return []


def get_svc_repo_paths(repo_path: str) -> list[str]:
    """
    Reads svc_repo.json:
      Ports[] → PotentialServices[] →
        DefaultEndpoints + CommonEndpoints + UndesirableEndpoints
    Returns deduplicated list preserving order.
    """
    try:
        with open(repo_path, "r", encoding="utf-8") as f:
            repo = json.load(f)
    except FileNotFoundError:
        print(f"  {YELLOW}[!] svc_repo.json not found at {repo_path} — skipping{RESET}")
        return []
    except json.JSONDecodeError as e:
        print(f"  {RED}[!] svc_repo.json parse error: {e} — skipping{RESET}")
        return []

    paths = []
    seen  = set()

    for port_entry in repo.get("Ports", []):
        for svc in port_entry.get("PotentialServices", []):
            for key in ("DefaultEndpoints", "CommonEndpoints", "UndesirableEndpoints"):
                for ep in svc.get(key, []):
                    ep = ep.strip()
                    if ep and ep not in seen:
                        seen.add(ep)
                        paths.append(ep)

    print(f"  {DIM}svc_repo.json: {len(paths)} paths loaded{RESET}")
    return paths


# ---------------------------------------------------------------------------
# Backup variant generator
# ---------------------------------------------------------------------------

def generate_backup_variants(paths: list[str]) -> list[str]:
    """
    For every path, append each backup suffix. Deduplicated.
    Skips paths that are pure traversal strings (contain only ./..%\\ chars).
    """
    variants = []
    seen     = set()

    traversal_only = set([
        "./", "../", "./../", "../../", "../../../",
        ".%2F", "..%2F", ".%2F.%2F", "%2F.", "%2F..",
        "%2F..%2F", "%2F%2F", "%252F", "%252F%252F",
        "..%252F", ".%252F", "..%c0%af", "..%c1%9c",
        "..%5c", "..\\/",
    ])

    for path in paths:
        if path in traversal_only:
            continue
        # Strip trailing slash before appending suffix
        base = path.rstrip("/")
        for suffix in BACKUP_SUFFIXES:
            variant = base + suffix
            if variant not in seen:
                seen.add(variant)
                variants.append(variant)

    return variants


# ---------------------------------------------------------------------------
# Dedup preserving order
# ---------------------------------------------------------------------------

def dedup(lst: list[str]) -> list[str]:
    seen = set()
    out  = []
    for item in lst:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(
        description="WSTG-CONF-02 wordlist generator"
    )
    p.add_argument("--repo",
        default=os.path.join("WSTG-CONF-02", "inputs", "json", "svc_repo.json"),
        metavar="PATH",
        help="Path to svc_repo.json")
    p.add_argument("--wordlist",
        default=os.path.join("WSTG-CONF-02", "inputs", "wordlist", "conf_02_paths.txt"),
        metavar="PATH")
    p.add_argument("--json-out",
        default=os.path.join("WSTG-CONF-02", "inputs", "json", "conf_02_paths.json"),
        metavar="PATH")
    args = p.parse_args()

    width = 65
    print(f"\n{BOLD}{'='*width}{RESET}")
    print(f"{BOLD}  WSTG-CONF-02 — Platform Configuration Wordlist{RESET}")
    print(f"{BOLD}{'='*width}{RESET}\n")

    # ── Collect per-category ─────────────────────────────────────────────────
    categories: dict[str, list[str]] = {
        "debug":    dedup(DEBUG_PATHS),
        "dotslash": dedup(DOTSLASH_PATHS),
        "config":   dedup(CONFIG_PATHS),
        "default":  dedup(DEFAULT_PLATFORM_PATHS),
        "svc_repo": [],
    }

    # Primary repo (stub)
    primary = get_primary_repo_paths()
    if primary:
        categories["svc_repo"].extend(primary)

    # Secondary repo (svc_repo.json)
    svc_paths = get_svc_repo_paths(args.repo)
    categories["svc_repo"] = dedup(categories["svc_repo"] + svc_paths)

    # ── Backup variants from all sources ─────────────────────────────────────
    all_base: list[str] = []
    for paths in categories.values():
        all_base.extend(paths)
    all_base = dedup(all_base)

    backup_variants = generate_backup_variants(all_base)
    categories["backup_variants"] = dedup(backup_variants)

    # ── Stats ────────────────────────────────────────────────────────────────
    print(f"\n  {'Category':<22} {'Count':>6}")
    print(f"  {'─'*30}")
    total = 0
    for cat, paths in categories.items():
        print(f"  {cat:<22} {len(paths):>6}")
        total += len(paths)

    # Build master flat list (deduped across all categories)
    master: list[str] = dedup(all_base + backup_variants)
    print(f"  {'─'*30}")
    print(f"  {'TOTAL (deduped)':<22} {len(master):>6}")

    # ── Write outputs ────────────────────────────────────────────────────────
    os.makedirs(os.path.dirname(args.wordlist),  exist_ok=True)
    os.makedirs(os.path.dirname(args.json_out),  exist_ok=True)

    with open(args.wordlist, "w", encoding="utf-8") as f:
        f.write("\n".join(master) + "\n")
    print(f"\n{GREEN}[+] Wordlist   → {args.wordlist}{RESET}  ({len(master)} entries)")

    json_out = {
        "_meta": {
            "generated":  datetime.now().isoformat(),
            "total_paths": len(master),
            "categories":  {cat: len(paths) for cat, paths in categories.items()},
        },
        "categories": categories,
        "master_list": master,
    }
    with open(args.json_out, "w", encoding="utf-8") as f:
        json.dump(json_out, f, indent=2)
    print(f"{GREEN}[+] JSON index → {args.json_out}{RESET}")

    print(f"\n  {DIM}Next: send conf_02_paths.txt to Burp Intruder (Sniper, §path§ position).{RESET}")
    print(f"  {DIM}Export results as XML, then run conf_02_verdict.py to classify.{RESET}\n")


if __name__ == "__main__":
    main()
