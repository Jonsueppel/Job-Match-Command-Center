#!/usr/bin/env python3
"""Self-hosted job discovery, matching, deduplication, and email alerts."""

from __future__ import annotations

import argparse
import base64
import csv
import datetime as dt
import email.message
import hashlib
import html
import json
import os
import re
import secrets
import shutil
import smtplib
import sqlite3
import threading
import textwrap
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse


APP_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("APP_DATA_DIR", str(APP_DIR))).resolve()
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "job_ranker.sqlite3"
CONFIG_PATH = DATA_DIR / "config.json"
SCAN_LOCK = threading.Lock()
SCAN_LOCK_PATH = DATA_DIR / "scan.lock"
SCAN_LOCK_STALE_SECONDS = 4 * 60 * 60
MAX_REQUEST_BYTES = int(os.environ.get("MAX_REQUEST_BYTES", str(10 * 1024 * 1024)))
CONFIG_WRITE_LOCK = threading.Lock()


def acquire_scan_lock() -> bool:
    if not SCAN_LOCK.acquire(blocking=False):
        return False
    try:
        if SCAN_LOCK_PATH.exists() and time.time() - SCAN_LOCK_PATH.stat().st_mtime > SCAN_LOCK_STALE_SECONDS:
            SCAN_LOCK_PATH.unlink()
        fd = os.open(str(SCAN_LOCK_PATH), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump({"started_at": utcnow(), "pid": os.getpid()}, stream)
        return True
    except FileExistsError:
        SCAN_LOCK.release()
        return False
    except Exception:
        SCAN_LOCK.release()
        raise


def release_scan_lock() -> None:
    try:
        SCAN_LOCK_PATH.unlink(missing_ok=True)
    finally:
        SCAN_LOCK.release()

DEFAULT_CONFIG = {
    "app": {
        "title": "Job Match Command Center",
        "subtitle": "Personal job discovery, resume matching, alerts, and application tracking",
        "setup_complete": False,
    },
    "resume_profile": {
        "enabled": True,
        "filename": "",
        "uploaded_at": "",
        "text": "",
        "keywords": [],
        "max_points": 35,
    },
    "candidate_name": "",
    "candidate_email": "",
    "home_location": "",
    "target_salary_min": 0,
    "apply_now_score": 90,
    "strong_apply_score": 80,
    "review_score": 70,
    "low_priority_score": 60,
    "specialty_gap_rules_enabled": False,
    "email": {
        "enabled": False,
        "smtp_host": "",
        "smtp_port": 587,
        "smtp_username": "",
        "smtp_password": "",
        "smtp_starttls": True,
        "from_email": "",
        "to_email": "",
        "subject_prefix": "[Apply Now Job]",
        "alert_verdicts": ["APPLY NOW", "STRONG APPLY"],
    },
    "scheduled_search": {
        "enabled": True,
        "run_on_startup": True,
        "interval_minutes": 60,
        "run_times": ["07:30", "18:30"],
        "sources": [],
    },
    "job_search": {
        "days_posted": 7,
        "max_results_per_source": 60,
        "us_only": True,
        "allow_global_remote": False,
        "resume_driven_search": True,
        "resume_query_count": 8,
        "minimum_resume_keyword_hits": 1,
        "required_terms": [],
        "excluded_terms": [],
        "queries": [],
        "locations": ["remote"],
    },
    "digest": {
        "enabled": True,
        "include_apply_now": True,
        "include_strong_apply": True,
        "include_review": False,
        "max_jobs": 5,
        "top_jobs_only": True,
    },
    "ideal_job": {
        "enabled": True,
        "desired_terms": [],
        "must_have_any": [],
        "strong_titles": [],
        "dealbreakers": [],
        "target_companies": [],
    },
}

RESUME_PROFILE = {
    "summary": (
        "Senior Infrastructure Engineer / Senior Systems Administrator with 12+ years "
        "in hybrid enterprise infrastructure, Azure, Microsoft 365, Entra ID, VMware, "
        "Windows Server, Linux, networking, automation, security hardening, DR, and "
        "multi-site manufacturing and healthcare environments."
    ),
    "core_terms": [
        "azure",
        "microsoft 365",
        "m365",
        "entra",
        "azure ad",
        "active directory",
        "intune",
        "windows server",
        "linux",
        "vmware",
        "vsphere",
        "esxi",
        "vcenter",
        "veeam",
        "powershell",
        "powercli",
        "gpo",
        "group policy",
        "dns",
        "dhcp",
        "iam",
        "identity",
        "sso",
        "saml",
        "oidc",
        "mfa",
        "conditional access",
        "rbac",
        "networking",
        "routing",
        "switching",
        "vlan",
        "vpn",
        "firewall",
        "backup",
        "disaster recovery",
        "business continuity",
        "monitoring",
        "automation",
        "security hardening",
        "vulnerability",
        "certificates",
        "pki",
        "ssl",
        "tls",
        "tier 3",
        "root cause",
        "high availability",
        "capacity planning",
        "multi-site",
        "manufacturing",
    ],
    "finance_terms": [
        "bank",
        "credit union",
        "financial services",
        "finance",
        "fintech",
        "insurance",
        "payments",
        "mortgage",
        "wealth",
        "investment",
        "sox",
        "glba",
        "pci",
        "ffiec",
        "soc 2",
        "audit",
        "compliance",
        "risk",
        "privileged access",
        "access review",
        "change management",
        "disaster recovery",
        "business continuity",
        "regulated",
    ],
    "target_titles": [
        "senior systems administrator",
        "senior systems engineer",
        "senior infrastructure engineer",
        "senior infrastructure administrator",
        "lead systems engineer",
        "lead it systems engineer",
        "lead systems administrator",
        "enterprise infrastructure engineer",
        "microsoft platform engineer",
        "microsoft infrastructure engineer",
        "azure infrastructure engineer",
        "systems engineer iii",
        "infrastructure administrator iii",
        "senior it engineer",
        "senior cloud administrator",
        "senior windows systems administrator",
        "senior m365 engineer",
        "senior microsoft 365 administrator",
        "senior entra engineer",
        "senior identity engineer",
        "senior cloud identity engineer",
        "microsoft identity architect",
        "entra id iam architect",
        "identity engineer",
        "microsoft identity engineer",
        "infrastructure operations engineer",
        "infrastructure architect",
        "enterprise infrastructure architect",
        "platform engineer",
    ],
}

PENALTY_RULES = [
    ("active clearance required", -100, "Active clearance appears required"),
    ("active secret", -100, "Active Secret clearance appears required"),
    ("active top secret", -100, "Active Top Secret clearance appears required"),
    ("ts/sci", -100, "Active TS/SCI clearance appears required"),
    ("must currently possess", -100, "Current clearance appears required"),
    ("help desk", -35, "Help desk / end-user support emphasis"),
    ("desktop support", -35, "Desktop support emphasis"),
    ("field technician", -35, "Field technician emphasis"),
    ("noc technician", -35, "NOC technician emphasis"),
    ("systems administrator i", -50, "Junior systems administrator title"),
    ("it engineer i", -50, "Junior IT engineer title"),
    ("managed services", -25, "MSP / managed services environment"),
    ("msp", -25, "MSP environment"),
    ("consulting", -25, "Consulting/customer delivery environment"),
    ("contract-to-hire", -25, "Contract-to-hire role"),
    ("contract role", -25, "Contract role"),
    ("salesforce administrator", -50, "Salesforce specialization"),
    ("salesforce developer", -50, "Salesforce specialization"),
    ("customer success", -35, "Customer success emphasis"),
    ("relocation required", -40, "Relocation required"),
    ("sailpoint certification", -30, "SailPoint certification/product specialization"),
    ("sailpoint identity security cloud", -45, "SailPoint ISC specialization is outside the strongest resume lane"),
    ("sailpoint isc", -45, "SailPoint ISC specialization is outside the strongest resume lane"),
    ("beanshell", -25, "BeanShell/SailPoint rule development specialization"),
    ("sailpoint rule", -30, "SailPoint rule development specialization"),
    ("identityiq", -35, "SailPoint IdentityIQ specialization"),
    ("cyberark", -25, "CyberArk/PAM specialization may be too product-specific"),
    ("saviynt", -35, "Saviynt/IGA product specialization"),
]

PRODUCT_SPECIALIST_GAP_RULES = [
    {
        "name": "SailPoint implementation-owner role",
        "product_terms": ["sailpoint", "identity security cloud", "sailpoint isc", "identityiq"],
        "depth_terms": ["6+ years", "six years", "hands-on", "rule development", "beanshell", "certification", "application onboarding", "access certification", "lifecycle workflow", "sod"],
        "resume_counter_terms": ["sailpoint", "identityiq", "beanshell"],
        "amount": -48,
    },
    {
        "name": "Specialized IGA platform owner role",
        "product_terms": ["saviynt", "oracle identity governance", "okta workflows", "ping identity", "cyberark"],
        "depth_terms": ["implementation", "architect", "developer", "certification", "rule development", "hands-on"],
        "resume_counter_terms": ["saviynt", "oracle identity governance", "cyberark", "ping identity"],
        "amount": -32,
    },
]

DEEP_PLATFORM_TERMS = [
    "eks",
    "kubernetes",
    "terraform",
    "ci/cd",
    "golang",
    "go developer",
    "distributed systems",
    "site reliability engineer",
    "sre",
]

NON_US_LOCATION_TERMS = [
    "hamburg",
    "germany",
    "berlin",
    "munich",
    "frankfurt",
    "london",
    "united kingdom",
    "uk only",
    "england",
    "canada",
    "toronto",
    "vancouver",
    "montreal",
    "india",
    "bengaluru",
    "bangalore",
    "hyderabad",
    "pune",
    "mumbai",
    "delhi",
    "europe",
    "emea",
    "eu only",
    "netherlands",
    "amsterdam",
    "france",
    "paris",
    "spain",
    "madrid",
    "poland",
    "warsaw",
    "romania",
    "australia",
    "sydney",
    "singapore",
    "philippines",
    "latin america",
    "latam",
]

US_LOCATION_TERMS = [
    "united states",
    "usa",
    "u.s.",
    "us remote",
    "remote us",
    "remote, us",
    "remote - us",
    "north carolina",
    "nc",
    "charlotte",
    "gastonia",
    "shelby",
]

RESPONSIBILITY_TERMS = [
    "owner",
    "ownership",
    "subject matter expert",
    "architecture",
    "design",
    "implementation",
    "modernization",
    "tier 3",
    "root cause",
    "automation",
    "migration",
    "hybrid",
    "disaster recovery",
    "capacity planning",
    "mentoring",
    "technical leadership",
    "high availability",
    "production",
]

GROWTH_TERMS = [
    "architecture",
    "modernization",
    "automation",
    "cloud migration",
    "hybrid",
    "identity governance",
    "lead",
    "mentor",
]


def utcnow() -> str:
    return dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat()


def get_default_config() -> dict[str, Any]:
    config = json.loads(json.dumps(DEFAULT_CONFIG))
    config["active_focus_profiles"] = []
    config["company_watchlist"] = {
        "enabled": True,
        "boost_points": 6,
        "companies": [
            "Truist",
            "Bank of America",
            "Wells Fargo",
            "Fifth Third Bank",
            "First Citizens Bank",
            "Ally",
            "AvidXchange",
            "LPL Financial",
            "Vanguard",
            "TIAA",
            "Navy Federal Credit Union",
            "Local Government Federal Credit Union",
            "SECU",
            "Blue Cross NC",
            "LendingTree",
            "Synchrony",
            "FIS",
            "Fiserv",
            "Global Payments",
            "Jack Henry",
            "Principal Financial Group",
            "Travelers",
            "The Hartford",
            "Duke Energy",
            "Lowe's",
            "Nucor",
            "Honeywell",
            "Corning",
            "Charter Communications",
            "Spectrum",
            "Atrium Health",
            "Novant Health",
            "CaroMont Health",
            "Premier",
            "USAA",
            "Edward Jones",
            "Raymond James",
            "MassMutual",
            "Lincoln Financial",
            "MetLife",
            "Prudential",
            "Equitable",
            "Aflac",
            "Chubb",
            "AIG",
            "Cigna",
            "UnitedHealth Group",
            "Elevance Health",
            "Humana",
            "Labcorp",
            "IQVIA",
            "Red Ventures",
            "Credit Karma",
            "Rocket Companies",
            "SoFi",
            "PayPal",
            "Block",
            "Stripe",
            "NCR Voyix",
            "Deluxe",
            "Blackbaud",
            "Schaeffler",
            "Bosch",
            "Siemens",
            "Daimler Truck",
        ],
    }
    # New installations start neutral; users add target employers during setup.
    config["company_watchlist"]["companies"] = []
    config["rejection_learning"] = {
        "enabled": True,
        "penalty_points": -12,
        "category_terms": {
            "MSP": ["msp", "managed services", "client support", "customer environments"],
            "Too much help desk": ["help desk", "desktop support", "laptop provisioning", "end-user support"],
            "Too low salary": ["salary below target", "low salary"],
            "Too far / onsite": ["onsite", "on-site", "relocation", "5 days", "five days"],
            "Too much AWS/Kubernetes/SRE": ["kubernetes", "eks", "terraform", "sre", "ci/cd"],
            "Contract": ["contract", "contract-to-hire"],
            "Not senior enough": ["junior", "administrator i", "engineer i", "1 year", "2 years"],
            "Clearance blocker": ["active secret", "active top secret", "ts/sci", "must possess clearance"],
            "Wrong specialty": ["sailpoint", "identityiq", "identity security cloud", "beanshell", "saviynt", "cyberark", "salesforce", "jira administrator"],
        },
    }
    config["scheduled_search"]["sources"] = [
        {
            "name": "Remotive remote jobs",
            "type": "remotive",
            "enabled": True,
            "max_results": 80,
        },
        {
            "name": "Arbeitnow public jobs",
            "type": "arbeitnow",
            "enabled": True,
            "max_pages": 2,
            "max_results": 80,
        },
        {
            "name": "Remote OK public jobs",
            "type": "remoteok",
            "enabled": True,
            "max_results": 80,
        },
        {
            "name": "Jobicy remote jobs",
            "type": "jobicy",
            "enabled": True,
            "max_results": 80,
            "geo": "usa",
        },
        {
            "name": "The Muse jobs",
            "type": "themuse",
            "enabled": True,
            "pages": 2,
            "categories": [],
            "locations": ["Remote"],
        },
        {
            "name": "Himalayas remote jobs",
            "type": "himalayas",
            "enabled": True,
            "max_results": 80,
        },
        {
            "name": "We Work Remotely RSS",
            "type": "weworkremotely",
            "enabled": True,
            "feeds": [
                "https://weworkremotely.com/remote-full-time-jobs.rss",
            ],
            "max_results": 80,
        },
        {
            "name": "Priority job boards discovery",
            "type": "priority_job_boards",
            "enabled": True,
            "max_results": 100,
            "fetch_detail_pages": True,
            "max_detail_fetches": 12,
            "max_boards": 14,
            "max_queries_per_board": 1,
            "extra_terms": [],
            "boards": [
                {"priority": 1, "name": "LinkedIn Jobs", "domain": "linkedin.com/jobs"},
                {"priority": 2, "name": "Indeed", "domain": "indeed.com"},
                {"priority": 3, "name": "Built In", "domain": "builtin.com"},
                {"priority": 4, "name": "Dice", "domain": "dice.com"},
                {"priority": 5, "name": "Glassdoor Jobs", "domain": "glassdoor.com"},
                {"priority": 6, "name": "We Work Remotely", "domain": "weworkremotely.com"},
                {"priority": 7, "name": "Remote OK", "domain": "remoteok.com"},
                {"priority": 8, "name": "Wellfound", "domain": "wellfound.com"},
                {"priority": 9, "name": "FlexJobs", "domain": "flexjobs.com"},
                {"priority": 10, "name": "Remotive", "domain": "remotive.com"},
                {"priority": 11, "name": "Himalayas", "domain": "himalayas.app"},
                {"priority": 12, "name": "Welcome to the Jungle", "domain": "welcometothejungle.com"},
                {"priority": 13, "name": "ZipRecruiter", "domain": "ziprecruiter.com"},
                {"priority": 14, "name": "Ladders", "domain": "theladders.com"},
            ],
        },
        {
            "name": "Bing web/RSS discovery",
            "type": "bing_rss",
            "enabled": True,
            "max_results": 40,
            "fetch_detail_pages": True,
            "max_detail_fetches": 20,
            "query_suffixes": [
                "remote jobs",
                "hiring careers",
            ],
        },
        {
            "name": "Bing ATS/career-board discovery",
            "type": "bing_rss",
            "enabled": True,
            "max_results": 80,
            "fetch_detail_pages": True,
            "max_detail_fetches": 30,
            "query_suffixes": [
                "site:boards.greenhouse.io",
                "site:jobs.lever.co",
                "site:jobs.ashbyhq.com",
                "site:jobs.smartrecruiters.com",
                "site:myworkdayjobs.com",
                "site:careers.icims.com",
                "site:recruitee.com",
                "site:apply.workable.com",
                "site:jobs.jobvite.com",
                "site:paylocity.com/recruiting/jobs",
                "site:ultipro.com",
                "site:successfactors.com",
                "site:workforcenow.adp.com",
            ],
        },
        {
            "name": "Target company career discovery",
            "type": "target_company_bing",
            "enabled": True,
            "max_results": 120,
            "fetch_detail_pages": True,
            "max_detail_fetches": 40,
            "max_companies": 25,
            "max_roles_per_company": 5,
            "query_suffixes": ["jobs careers", "careers apply"],
            "companies": [],
        },
        {
            "name": "Greenhouse watched boards",
            "type": "greenhouse",
            "enabled": False,
            "boards": [],
        },
        {
            "name": "Lever watched sites",
            "type": "lever",
            "enabled": False,
            "sites": [],
        },
        {
            "name": "Adzuna US jobs",
            "type": "adzuna",
            "enabled": False,
            "country": "us",
            "app_id": "",
            "app_key": "",
            "pages": 1,
        },
        {
            "name": "USAJOBS searches",
            "type": "usajobs",
            "enabled": False,
            "user_agent": "",
            "api_key": "",
            "results_per_page": 25,
        },
    ]
    config["match_categories"] = [
        {
            "id": "target_titles",
            "label": "Target title",
            "terms": [],
            "scope": "title",
            "max_points": 8,
            "points_per_match": 4,
            "base_points": 0,
            "fit_group": "career",
            "enabled": True,
        },
        {
            "id": "core_technical",
            "label": "Resume and skill alignment",
            "terms": [],
            "scope": "full",
            "max_points": 30,
            "points_per_match": 2.1,
            "base_points": 0,
            "fit_group": "technical",
            "enabled": True,
        },
        {
            "id": "senior_ownership",
            "label": "Senior ownership/responsibility",
            "terms": RESPONSIBILITY_TERMS,
            "scope": "full",
            "max_points": 12,
            "points_per_match": 1,
            "base_points": 4,
            "fit_group": "career",
            "enabled": True,
        },
        {
            "id": "career_growth",
            "label": "Career growth",
            "terms": GROWTH_TERMS,
            "scope": "full",
            "max_points": 10,
            "points_per_match": 1,
            "base_points": 4,
            "fit_group": "career",
            "enabled": True,
        },
    ]
    config["penalty_rules"] = []
    return config


def load_config() -> dict[str, Any]:
    default_config = get_default_config()
    if CONFIG_PATH.exists():
        data = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        config = merge_dict(default_config, data)
    else:
        config = default_config
    email_cfg = config.setdefault("email", {})
    env_overrides = {
        "smtp_host": "SMTP_HOST", "smtp_username": "SMTP_USERNAME",
        "smtp_password": "SMTP_PASSWORD", "from_email": "SMTP_FROM_EMAIL",
        "to_email": "SMTP_TO_EMAIL",
    }
    for key, env_name in env_overrides.items():
        if os.environ.get(env_name):
            email_cfg[key] = os.environ[env_name]
    if os.environ.get("SMTP_PORT"):
        email_cfg["smtp_port"] = int(os.environ["SMTP_PORT"])
    return config


def save_config(config: dict[str, Any]) -> None:
    persisted = json.loads(json.dumps(config))
    if os.environ.get("SMTP_PASSWORD"):
        persisted.setdefault("email", {})["smtp_password"] = ""
    temp_path = CONFIG_PATH.with_suffix(".json.tmp")
    with CONFIG_WRITE_LOCK:
        temp_path.write_text(json.dumps(persisted, indent=2), encoding="utf-8")
        os.replace(temp_path, CONFIG_PATH)


def merge_dict(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = merge_dict(merged[key], value)
        else:
            merged[key] = value
    return merged


def bool_from_form(form: dict[str, str], key: str) -> bool:
    return form.get(key) in {"on", "true", "1", "yes", "Yes"}


def split_lines(value: str) -> list[str]:
    return [line.strip() for line in value.replace(",", "\n").splitlines() if line.strip()]


def source_template(source_type: str = "bing_rss") -> dict[str, Any]:
    templates = {
        "bing_rss": {
            "name": "Custom Bing source",
            "type": "bing_rss",
            "enabled": True,
            "max_results": 40,
            "fetch_detail_pages": True,
            "max_detail_fetches": 12,
            "query_suffixes": ["site:example.com/jobs remote"],
        },
        "priority_job_boards": {
            "name": "Custom priority boards",
            "type": "priority_job_boards",
            "enabled": True,
            "max_results": 60,
            "fetch_detail_pages": True,
            "max_detail_fetches": 12,
            "max_boards": 3,
            "max_queries_per_board": 1,
            "extra_terms": ["remote"],
            "boards": [{"priority": 1, "name": "Example Board", "domain": "example.com"}],
        },
        "weworkremotely": {
            "name": "Custom RSS source",
            "type": "weworkremotely",
            "enabled": True,
            "feeds": ["https://example.com/jobs.rss"],
            "max_results": 40,
        },
        "greenhouse": {"name": "Greenhouse watched boards", "type": "greenhouse", "enabled": True, "boards": [{"token": "companytoken", "company": "Company"}]},
        "lever": {"name": "Lever watched sites", "type": "lever", "enabled": True, "sites": [{"site": "company", "company": "Company"}]},
        "json": {"name": "Local JSON import", "type": "json", "enabled": True, "path": "/data/imports/jobs.json"},
        "csv": {"name": "Local CSV import", "type": "csv", "enabled": True, "path": "/data/imports/jobs.csv"},
    }
    return json.loads(json.dumps(templates.get(source_type, templates["bing_rss"])))


def save_settings_form(form: dict[str, str]) -> None:
    config = load_config()
    config.setdefault("app", {})
    config["app"]["title"] = form.get("app_title", config["app"].get("title", "")).strip() or "Job Match Command Center"
    config["app"]["subtitle"] = form.get("app_subtitle", config["app"].get("subtitle", "")).strip()
    config["candidate_name"] = form.get("candidate_name", config.get("candidate_name", "")).strip()
    config["candidate_email"] = form.get("candidate_email", config.get("candidate_email", "")).strip()
    config["home_location"] = form.get("home_location", config.get("home_location", "")).strip()
    for key in ["target_salary_min", "apply_now_score", "strong_apply_score", "review_score", "low_priority_score"]:
        if form.get(key):
            config[key] = int(form[key])

    scheduled = config.setdefault("scheduled_search", {})
    scheduled["enabled"] = bool_from_form(form, "scheduled_enabled")
    scheduled["run_on_startup"] = bool_from_form(form, "run_on_startup")
    scheduled["interval_minutes"] = int(form.get("interval_minutes") or scheduled.get("interval_minutes") or 60)
    scheduled["run_times"] = split_lines(form.get("run_times", ""))

    job_search = config.setdefault("job_search", {})
    job_search["queries"] = split_lines(form.get("queries", ""))
    job_search["locations"] = split_lines(form.get("locations", ""))
    job_search["us_only"] = bool_from_form(form, "us_only")
    job_search["allow_global_remote"] = bool_from_form(form, "allow_global_remote")
    job_search["resume_driven_search"] = bool_from_form(form, "resume_driven_search")
    job_search["resume_query_count"] = int(form.get("resume_query_count") or job_search.get("resume_query_count") or 8)
    job_search["minimum_resume_keyword_hits"] = int(form.get("minimum_resume_keyword_hits") or 0)
    job_search["days_posted"] = int(form.get("days_posted") or job_search.get("days_posted") or 7)
    job_search["required_terms"] = split_lines(form.get("required_terms", ""))
    job_search["excluded_terms"] = split_lines(form.get("excluded_terms", ""))
    if form.get("max_results_per_source"):
        job_search["max_results_per_source"] = int(form["max_results_per_source"])

    ideal = config.setdefault("ideal_job", {})
    ideal["enabled"] = bool_from_form(form, "ideal_enabled")
    ideal["desired_terms"] = split_lines(form.get("ideal_desired_terms", ""))
    ideal["must_have_any"] = split_lines(form.get("ideal_must_have_any", ""))
    ideal["strong_titles"] = split_lines(form.get("ideal_strong_titles", ""))
    ideal["dealbreakers"] = split_lines(form.get("ideal_dealbreakers", ""))
    ideal["target_companies"] = split_lines(form.get("ideal_target_companies", ""))

    email_cfg = config.setdefault("email", {})
    email_cfg["enabled"] = bool_from_form(form, "email_enabled")
    email_cfg["smtp_host"] = form.get("smtp_host", "").strip()
    email_cfg["smtp_port"] = int(form.get("smtp_port") or 587)
    email_cfg["smtp_username"] = form.get("smtp_username", "").strip()
    if form.get("smtp_password"):
        email_cfg["smtp_password"] = form["smtp_password"].strip()
    email_cfg["smtp_starttls"] = bool_from_form(form, "smtp_starttls")
    email_cfg["from_email"] = form.get("from_email", "").strip()
    email_cfg["to_email"] = form.get("to_email", "").strip()
    email_cfg["subject_prefix"] = form.get("subject_prefix", "[Apply Now Job]").strip()
    email_cfg["alert_verdicts"] = split_lines(form.get("alert_verdicts", ""))

    digest = config.setdefault("digest", {})
    digest["enabled"] = bool_from_form(form, "digest_enabled")
    digest["include_apply_now"] = bool_from_form(form, "digest_apply_now")
    digest["include_strong_apply"] = bool_from_form(form, "digest_strong_apply")
    digest["include_review"] = bool_from_form(form, "digest_review")
    digest["top_jobs_only"] = bool_from_form(form, "digest_top_jobs_only")
    digest["max_jobs"] = int(form.get("digest_max_jobs") or digest.get("max_jobs") or 12)
    save_config(config)


def save_setup_form(form: dict[str, str]) -> None:
    config = load_config()
    config["candidate_name"] = form.get("candidate_name", "").strip()
    config["candidate_email"] = form.get("candidate_email", "").strip()
    config["home_location"] = form.get("home_location", "").strip()
    config["target_salary_min"] = int(form.get("target_salary_min") or 0)
    config.setdefault("job_search", {})["queries"] = split_lines(form.get("queries", ""))
    config["job_search"]["locations"] = split_lines(form.get("locations", "")) or ["remote"]
    config["job_search"]["excluded_terms"] = split_lines(form.get("excluded_terms", ""))
    config["job_search"]["us_only"] = bool_from_form(form, "us_only")
    ideal = config.setdefault("ideal_job", {})
    ideal["strong_titles"] = list(config["job_search"]["queries"])
    ideal["desired_terms"] = split_lines(form.get("desired_terms", ""))
    ideal["must_have_any"] = split_lines(form.get("must_have_any", ""))
    ideal["dealbreakers"] = list(config["job_search"]["excluded_terms"])
    config.setdefault("email", {})["to_email"] = config["candidate_email"]
    config.setdefault("app", {})["setup_complete"] = bool(config["job_search"]["queries"])
    save_config(config)


def save_source_form(form: dict[str, str]) -> None:
    config = load_config()
    sources = config.setdefault("scheduled_search", {}).setdefault("sources", [])
    try:
        source = json.loads(form.get("source_json", "{}"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"Source JSON is invalid: {exc}") from exc
    if not isinstance(source, dict):
        raise ValueError("Source JSON must be an object.")
    if not source.get("name") or not source.get("type"):
        raise ValueError("Source must include name and type.")
    source["enabled"] = bool_from_form(form, "enabled")
    index_text = form.get("source_index", "")
    if index_text == "":
        sources.append(source)
    else:
        index = int(index_text)
        if index < 0 or index >= len(sources):
            raise ValueError("Source index is out of range.")
        sources[index] = source
    save_config(config)


def toggle_source(index: int) -> None:
    config = load_config()
    sources = config.setdefault("scheduled_search", {}).setdefault("sources", [])
    if 0 <= index < len(sources):
        sources[index]["enabled"] = not sources[index].get("enabled", True)
        save_config(config)


def delete_source(index: int) -> None:
    config = load_config()
    sources = config.setdefault("scheduled_search", {}).setdefault("sources", [])
    if 0 <= index < len(sources):
        del sources[index]
        save_config(config)


def parse_multipart(body: bytes, content_type: str) -> tuple[dict[str, str], dict[str, dict[str, Any]]]:
    match = re.search(r"boundary=(?:\"([^\"]+)\"|([^;]+))", content_type)
    if not match:
        return {}, {}
    boundary = (match.group(1) or match.group(2)).encode("utf-8")
    form: dict[str, str] = {}
    files: dict[str, dict[str, Any]] = {}
    for part in body.split(b"--" + boundary):
        part = part.strip(b"\r\n")
        if not part or part == b"--":
            continue
        head, sep, payload = part.partition(b"\r\n\r\n")
        if not sep:
            continue
        payload = payload.rstrip(b"\r\n")
        headers = head.decode("utf-8", errors="ignore")
        disp = re.search(r'content-disposition:.*?name="([^"]+)"(?:;\s*filename="([^"]*)")?', headers, flags=re.I)
        if not disp:
            continue
        name = disp.group(1)
        filename = disp.group(2)
        if filename is not None:
            files[name] = {"filename": filename, "content": payload, "headers": headers}
        else:
            form[name] = payload.decode("utf-8", errors="replace").strip()
    return form, files


def extract_resume_text(filename: str, content: bytes) -> str:
    lower = filename.lower()
    if lower.endswith(".txt") or lower.endswith(".md"):
        return content.decode("utf-8", errors="replace")
    if lower.endswith(".docx"):
        with zipfile.ZipFile(io_bytes(content)) as archive:
            xml = archive.read("word/document.xml").decode("utf-8", errors="ignore")
        xml = re.sub(r"</w:p>", "\n", xml)
        return html_to_text(xml)
    if lower.endswith(".pdf"):
        text = extract_pdf_text_with_pypdf(content)
        if resume_text_quality_ok(text):
            return text
        text = extract_pdf_text_best_effort(content)
        if resume_text_quality_ok(text):
            return text
        raise ValueError("I could not extract clean resume text from this PDF. Try uploading a DOCX or TXT copy.")
    return content.decode("utf-8", errors="replace")


def io_bytes(content: bytes):
    import io

    return io.BytesIO(content)


def extract_pdf_text_with_pypdf(content: bytes) -> str:
    try:
        from pypdf import PdfReader
    except Exception:
        return ""
    try:
        reader = PdfReader(io_bytes(content))
        pages = []
        for page in reader.pages:
            pages.append(page.extract_text() or "")
        return html_to_text("\n".join(pages))
    except Exception:
        return ""


def resume_text_quality_ok(text: str) -> bool:
    cleaned = html_to_text(text)
    if len(cleaned) < 250:
        return False
    letters = sum(1 for char in cleaned if char.isalpha())
    printable = sum(1 for char in cleaned if char.isprintable() and not char.isspace())
    if printable and letters / printable < 0.55:
        return False
    bad_tokens = [" obj ", " endobj ", " stream ", " endstream ", " xref ", "/flatedecode", " en-us en-us en-us"]
    blob = normalize_text(cleaned[:5000])
    return not any(token.strip() in blob for token in bad_tokens)


def extract_pdf_text_best_effort(content: bytes) -> str:
    chunks: list[bytes] = []
    for match in re.finditer(rb"stream\r?\n(.*?)\r?\nendstream", content, flags=re.S):
        stream = match.group(1)
        prefix = content[max(0, match.start() - 250):match.start()]
        if b"FlateDecode" in prefix:
            try:
                import zlib

                chunks.append(zlib.decompress(stream))
                continue
            except Exception:
                pass
        chunks.append(stream)
    haystack = b"\n".join(chunks) if chunks else content
    text_parts: list[str] = []
    for raw in re.findall(rb"\((?:\\.|[^\\)]){2,}\)", haystack):
        value = raw[1:-1]
        value = value.replace(rb"\(", b"(").replace(rb"\)", b")").replace(rb"\\", b"\\")
        text_parts.append(value.decode("latin-1", errors="ignore"))
    if len(" ".join(text_parts)) < 200:
        text_parts.extend(
            item.decode("latin-1", errors="ignore")
            for item in re.findall(rb"[A-Za-z][A-Za-z0-9,./+#&()\- ]{4,}", haystack)
        )
    return html_to_text(" ".join(text_parts))


RESUME_STOPWORDS = {
    "about", "after", "also", "and", "are", "based", "been", "for", "from", "have", "into", "more", "not",
    "that", "the", "their", "this", "through", "with", "years", "your", "you", "will", "work", "working",
    "experience", "responsible", "including", "using", "across", "support", "system", "systems",
}


def resume_keywords(text: str, limit: int = 80) -> list[str]:
    normalized = normalize_text(text)
    phrases = [
        "active directory", "azure", "azure ad", "entra", "microsoft 365", "office 365", "intune",
        "windows server", "vmware", "vsphere", "powershell", "veeam", "networking", "firewall",
        "disaster recovery", "backup", "identity", "mfa", "conditional access", "linux", "automation",
        "dns", "dhcp", "gpo", "group policy", "security hardening", "infrastructure", "hybrid cloud",
    ]
    found = [phrase for phrase in phrases if phrase in normalized]
    words = re.findall(r"[a-z][a-z0-9+#.-]{3,}", normalized)
    counts: dict[str, int] = {}
    for word in words:
        if word in RESUME_STOPWORDS or word.isdigit():
            continue
        counts[word] = counts.get(word, 0) + 1
    ranked = [word for word, _ in sorted(counts.items(), key=lambda item: (-item[1], item[0]))]
    keywords: list[str] = []
    for term in found + ranked:
        if term not in keywords:
            keywords.append(term)
        if len(keywords) >= limit:
            break
    return keywords


def save_resume_upload(filename: str, content: bytes) -> dict[str, Any]:
    text = extract_resume_text(filename, content)
    if len(text.strip()) < 100:
        raise ValueError("I could not extract enough text from that resume. Try uploading a DOCX or TXT version.")
    config = load_config()
    profile = config.setdefault("resume_profile", {})
    profile["enabled"] = True
    profile["filename"] = filename
    profile["uploaded_at"] = utcnow()
    profile["text"] = text[:120_000]
    profile["keywords"] = resume_keywords(text)
    profile["max_points"] = int(profile.get("max_points", 12) or 12)
    save_config(config)
    return profile


def db() -> sqlite3.Connection:
    con = sqlite3.connect(DB_PATH, timeout=30)
    con.row_factory = sqlite3.Row
    con.execute("pragma busy_timeout = 30000")
    con.execute("pragma foreign_keys = on")
    return con


def init_db() -> None:
    with db() as con:
        con.execute("pragma journal_mode = wal")
        con.execute("pragma synchronous = normal")
        con.executescript(
            """
            create table if not exists jobs (
                id integer primary key autoincrement,
                canonical_url text,
                url_hash text,
                req_id text,
                title text not null,
                company text not null,
                location text,
                work_arrangement text,
                office_days text,
                salary_range text,
                employment_type text,
                environment_type text,
                source text,
                description text not null,
                normalized_key text not null,
                posted_date text not null default '',
                first_seen text not null,
                last_seen text not null,
                status text not null default 'new',
                candidate_notes text not null default '',
                rejection_reason text not null default '',
                score integer not null,
                verdict text not null,
                technical_fit integer not null,
                career_fit integer not null,
                scoring_json text not null,
                shown integer not null default 0,
                applied integer not null default 0,
                alert_sent integer not null default 0,
                digest_sent integer not null default 0,
                description_hash text not null default '',
                last_changed text,
                change_summary text not null default '',
                pipeline_stage text not null default 'new',
                applied_date text not null default '',
                contact_name text not null default '',
                contact_email text not null default '',
                follow_up_date text not null default '',
                resume_version text not null default '',
                rejection_category text not null default '',
                watched_company integer not null default 0
            );
            create unique index if not exists idx_jobs_url_hash on jobs(url_hash) where url_hash is not null;
            create index if not exists idx_jobs_normalized_key on jobs(normalized_key);
            create index if not exists idx_jobs_verdict on jobs(verdict);
            create index if not exists idx_jobs_status on jobs(status);
            create table if not exists scan_runs (
                id integer primary key autoincrement,
                started_at text not null,
                completed_at text,
                reason text not null default '',
                status text not null default 'running',
                message text not null default ''
            );
            create table if not exists scan_source_results (
                id integer primary key autoincrement,
                scan_run_id integer not null,
                source_name text not null,
                source_type text not null,
                enabled integer not null default 1,
                fetched integer not null default 0,
                created integer not null default 0,
                updated integer not null default 0,
                status text not null default 'ok',
                message text not null default '',
                created_at text not null,
                foreign key(scan_run_id) references scan_runs(id)
            );
            create index if not exists idx_scan_source_results_run on scan_source_results(scan_run_id);
            """
        )
        existing_cols = {row["name"] for row in con.execute("pragma table_info(jobs)").fetchall()}
        migrations = {
            "digest_sent": "alter table jobs add column digest_sent integer not null default 0",
            "description_hash": "alter table jobs add column description_hash text not null default ''",
            "last_changed": "alter table jobs add column last_changed text",
            "change_summary": "alter table jobs add column change_summary text not null default ''",
            "pipeline_stage": "alter table jobs add column pipeline_stage text not null default 'new'",
            "applied_date": "alter table jobs add column applied_date text not null default ''",
            "contact_name": "alter table jobs add column contact_name text not null default ''",
            "contact_email": "alter table jobs add column contact_email text not null default ''",
            "follow_up_date": "alter table jobs add column follow_up_date text not null default ''",
            "resume_version": "alter table jobs add column resume_version text not null default ''",
            "rejection_category": "alter table jobs add column rejection_category text not null default ''",
            "watched_company": "alter table jobs add column watched_company integer not null default 0",
            "posted_date": "alter table jobs add column posted_date text not null default ''",
        }
        for col, sql in migrations.items():
            if col not in existing_cols:
                con.execute(sql)


def normalize_text(value: str | None) -> str:
    return re.sub(r"\s+", " ", (value or "").strip().lower())


def normalize_posted_date(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, dt.datetime):
        return value.date().isoformat()
    if isinstance(value, dt.date):
        return value.isoformat()
    text = str(value).strip()
    if not text:
        return ""
    if text.isdigit():
        try:
            timestamp = int(text)
            if timestamp > 10_000_000_000:
                timestamp = timestamp // 1000
            return dt.datetime.fromtimestamp(timestamp, dt.UTC).date().isoformat()
        except (OverflowError, ValueError, OSError):
            pass
    for pattern in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%SZ", "%a, %d %b %Y %H:%M:%S %z", "%a, %d %b %Y %H:%M:%S %Z"):
        try:
            return dt.datetime.strptime(text.replace(" GMT", " +0000"), pattern).date().isoformat()
        except ValueError:
            continue
    match = re.search(r"\d{4}-\d{2}-\d{2}", text)
    return match.group(0) if match else ""


def posted_date_is_within_range(posted_date: str, days: int) -> bool:
    if not posted_date or days <= 0:
        return True
    try:
        posted = dt.date.fromisoformat(posted_date[:10])
    except ValueError:
        return True
    oldest = dt.datetime.now(dt.UTC).date() - dt.timedelta(days=days)
    return posted >= oldest


def normalize_for_key(value: str | None) -> str:
    text = normalize_text(value)
    text = re.sub(r"[^a-z0-9]+", " ", text)
    text = re.sub(r"\b(senior|sr|iii|ii|lead)\b", "", text)
    return re.sub(r"\s+", " ", text).strip()


def canonicalize_url(url: str | None) -> str:
    if not url:
        return ""
    parsed = urlparse(url.strip())
    if not parsed.scheme or not parsed.netloc:
        return url.strip()
    path = parsed.path.rstrip("/")
    return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}{path}"


def url_hash(url: str | None) -> str | None:
    canonical = canonicalize_url(url)
    if not canonical:
        return None
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def text_hash(text: str | None) -> str:
    return hashlib.sha256(normalize_text(text).encode("utf-8")).hexdigest()


def normalized_key(title: str, company: str, location: str | None) -> str:
    return "|".join(
        [
            normalize_for_key(company),
            normalize_for_key(title),
            normalize_for_key(location),
        ]
    )


def count_matches(text: str, terms: list[str]) -> list[str]:
    found = []
    padded = f" {text} "
    for term in terms:
        t = term.lower()
        if re.search(rf"(?<![a-z0-9]){re.escape(t)}(?![a-z0-9])", padded):
            found.append(term)
    return found


def active_match_categories(config: dict[str, Any]) -> list[dict[str, Any]]:
    active_profiles = set(config.get("active_focus_profiles", []))
    categories = []
    for category in config.get("match_categories", []):
        if not category.get("enabled", True):
            continue
        profile = category.get("focus_profile")
        if profile and profile not in active_profiles:
            continue
        categories.append(category)
    return categories


def score_match_categories(blob: str, title: str, config: dict[str, Any]) -> list[dict[str, Any]]:
    results = []
    for category in active_match_categories(config):
        source = title if category.get("scope") == "title" else blob
        terms = [str(term) for term in category.get("terms", [])]
        if not terms and category.get("id") == "target_titles":
            terms = list(config.get("ideal_job", {}).get("strong_titles", [])) or list(config.get("job_search", {}).get("queries", []))
        if not terms and category.get("id") == "core_technical":
            terms = list(config.get("resume_profile", {}).get("keywords", [])) + list(config.get("ideal_job", {}).get("desired_terms", []))
        hits = count_matches(source, terms)
        base_points = float(category.get("base_points", 0))
        points_per_match = float(category.get("points_per_match", 1))
        max_points = float(category.get("max_points", 0))
        points = min(max_points, base_points + len(hits) * points_per_match)
        if not hits and base_points <= 0:
            points = 0
        results.append(
            {
                "id": category.get("id", "category"),
                "label": category.get("label", category.get("id", "Category")),
                "hits": hits,
                "points": round(points, 2),
                "max_points": max_points,
                "fit_group": category.get("fit_group", "focus"),
                "focus_profile": category.get("focus_profile"),
            }
        )
    return results


def category_hits(category_results: list[dict[str, Any]], category_id: str) -> list[str]:
    for result in category_results:
        if result["id"] == category_id:
            return result["hits"]
    return []


def category_points(category_results: list[dict[str, Any]], fit_group: str) -> float:
    return sum(float(result["points"]) for result in category_results if result["fit_group"] == fit_group)


def category_max(category_results: list[dict[str, Any]], fit_group: str) -> float:
    return sum(float(result["max_points"]) for result in category_results if result["fit_group"] == fit_group)


def watchlist_match(company: str, config: dict[str, Any]) -> str:
    watch = config.get("company_watchlist", {})
    if not watch.get("enabled", True):
        return ""
    normalized_company = normalize_for_key(company)
    for watched in watch.get("companies", []):
        if normalize_for_key(str(watched)) in normalized_company or normalized_company in normalize_for_key(str(watched)):
            return str(watched)
    return ""


def learned_rejection_penalties(blob: str, config: dict[str, Any]) -> list[dict[str, Any]]:
    learning = config.get("rejection_learning", {})
    if not learning.get("enabled", True):
        return []
    learned = []
    for category, terms in learning.get("category_terms", {}).items():
        hits = count_matches(blob, [str(term) for term in terms])
        if hits:
            learned.append(
                {
                    "amount": int(learning.get("penalty_points", -12)),
                    "reason": f"Learned rejection pattern: {category} ({', '.join(hits[:4])})",
                    "category": category,
                }
            )
    return learned


def product_specialist_gap_penalties(blob: str, resume_text: str) -> list[dict[str, Any]]:
    penalties = []
    resume_blob = normalize_text(resume_text)
    for rule in PRODUCT_SPECIALIST_GAP_RULES:
        product_hits = count_matches(blob, [str(term) for term in rule["product_terms"]])
        if not product_hits:
            continue
        depth_hits = count_matches(blob, [str(term) for term in rule["depth_terms"]])
        resume_hits = count_matches(resume_blob, [str(term) for term in rule["resume_counter_terms"]])
        if len(product_hits) >= 2 or depth_hits:
            amount = int(rule["amount"])
            if resume_hits:
                amount = round(amount / 2)
            penalties.append(
                {
                    "amount": amount,
                    "reason": f"{rule['name']}: {', '.join((product_hits + depth_hits)[:6])}",
                    "category": "product_specialist_gap",
                }
            )
    return penalties


def score_ideal_profile(blob: str, title: str, company: str, config: dict[str, Any]) -> dict[str, Any]:
    ideal = config.get("ideal_job", {})
    if not ideal.get("enabled", True):
        return {"points": 0, "hits": [], "missing_must": [], "dealbreakers": [], "title_hits": [], "company_hits": []}
    desired_hits = count_matches(blob, [str(term) for term in ideal.get("desired_terms", [])])
    must_terms = [str(term) for term in ideal.get("must_have_any", []) if str(term).strip()]
    must_hits = count_matches(blob, must_terms)
    title_hits = count_matches(title, [str(term) for term in ideal.get("strong_titles", [])])
    company_hits = count_matches(normalize_text(company), [str(term) for term in ideal.get("target_companies", [])])
    dealbreakers = count_matches(blob, [str(term) for term in ideal.get("dealbreakers", [])])
    points = min(18, len(desired_hits) * 1.5 + len(title_hits) * 4 + len(company_hits) * 3)
    missing_must = [] if must_hits else must_terms[:8]
    if missing_must:
        points -= 22
    if dealbreakers:
        points -= min(45, len(dealbreakers) * 12)
    return {
        "points": round(points, 2),
        "hits": desired_hits,
        "must_hits": must_hits,
        "missing_must": missing_must,
        "dealbreakers": dealbreakers,
        "title_hits": title_hits,
        "company_hits": company_hits,
    }


def classify_role_family(title: str, blob: str) -> dict[str, Any]:
    families = [
        ("Best fit: Microsoft enterprise infrastructure", 12, ["senior infrastructure engineer", "senior systems engineer", "microsoft platform engineer", "windows systems engineer", "enterprise infrastructure"], ["active directory", "microsoft 365", "entra", "vmware", "windows server"]),
        ("Good fit: Microsoft identity / M365", 9, ["senior identity engineer", "entra engineer", "m365 engineer", "microsoft identity architect", "cloud identity"], ["entra", "azure ad", "conditional access", "sso", "mfa", "intune"]),
        ("Stretch fit: infrastructure architect", 6, ["infrastructure architect", "cloud infrastructure architect", "solution architect"], ["infrastructure", "architecture", "hybrid", "enterprise"]),
        ("Usually poor fit: product-specific IAM", -22, ["sailpoint", "saviynt", "cyberark", "identityiq"], ["sailpoint", "beanshell", "rule development", "identity security cloud"]),
        ("Usually poor fit: developer / SRE lane", -24, ["developer", "software engineer", "sre", "site reliability"], ["kubernetes", "terraform", "ci/cd", "golang"]),
        ("Usually poor fit: support / customer lane", -24, ["help desk", "desktop support", "customer success", "sales engineer"], ["ticket queue", "end-user support", "customer environments"]),
    ]
    best = {"name": "Unclassified", "points": 0, "hits": []}
    for name, points, title_terms, body_terms in families:
        hits = count_matches(title, title_terms) + count_matches(blob, body_terms)
        if hits and abs(points) > abs(int(best["points"])):
            best = {"name": name, "points": points, "hits": hits[:10]}
    return best


def location_eligibility(location: str, work: str, blob: str, config: dict[str, Any]) -> dict[str, Any]:
    job_search = config.get("job_search", {})
    if not job_search.get("us_only", True):
        return {"eligible": True, "reason": "US-only filter disabled", "non_us_hits": [], "us_hits": []}
    location_blob = normalize_text(f"{location} {work}")
    full_blob = normalize_text(f"{location_blob} {blob[:1200]}")
    non_us_hits = count_matches(location_blob, NON_US_LOCATION_TERMS)
    if not non_us_hits:
        non_us_hits = count_matches(full_blob, NON_US_LOCATION_TERMS)[:3]
    us_hits = count_matches(full_blob, US_LOCATION_TERMS)
    remote = "remote" in location_blob or "remote" in full_blob
    if non_us_hits and not us_hits:
        return {"eligible": False, "reason": "Non-US location detected: " + ", ".join(non_us_hits[:5]), "non_us_hits": non_us_hits, "us_hits": us_hits}
    if remote and us_hits:
        return {"eligible": True, "reason": "Remote role appears US-eligible", "non_us_hits": non_us_hits, "us_hits": us_hits}
    if remote and job_search.get("allow_global_remote", False):
        return {"eligible": True, "reason": "Global remote allowed", "non_us_hits": non_us_hits, "us_hits": us_hits}
    if remote:
        return {"eligible": True, "reason": "Remote role; verify US eligibility", "non_us_hits": non_us_hits, "us_hits": us_hits}
    if us_hits:
        return {"eligible": True, "reason": "US location signal found", "non_us_hits": non_us_hits, "us_hits": us_hits}
    return {"eligible": True, "reason": "Location eligibility unclear", "non_us_hits": non_us_hits, "us_hits": us_hits}


def score_job(job: dict[str, str], config: dict[str, Any] | None = None) -> dict[str, Any]:
    config = config or load_config()
    blob = normalize_text(
        " ".join(
            [
                job.get("title", ""),
                job.get("company", ""),
                job.get("location", ""),
                job.get("work_arrangement", ""),
                job.get("salary_range", ""),
                job.get("employment_type", ""),
                job.get("environment_type", ""),
                job.get("description", ""),
            ]
        )
    )
    title = normalize_text(job.get("title", ""))
    location = normalize_text(job.get("location", ""))
    company = normalize_text(job.get("company", ""))
    salary = normalize_text(job.get("salary_range", ""))
    work = normalize_text(job.get("work_arrangement", ""))
    employment = normalize_text(job.get("employment_type", ""))
    environment = normalize_text(job.get("environment_type", ""))

    category_results = score_match_categories(blob, title, config)
    core_hits = category_hits(category_results, "core_technical")
    focus_hits = [hit for result in category_results if result.get("fit_group") == "focus" for hit in result.get("hits", [])]
    title_hits = category_hits(category_results, "target_titles")
    responsibility_hits = category_hits(category_results, "senior_ownership")

    technical = category_points(category_results, "technical")
    seniority = category_points(category_results, "career")

    salary_score, salary_notes = score_salary(salary, config)
    location_score, location_notes = score_location(location, work, config)
    employer_score = score_employer(blob, environment, focus_hits)
    worklife_score, worklife_notes = score_worklife(blob)
    focus_score = category_points(category_results, "focus")
    ideal_score = score_ideal_profile(blob, title, company, config)
    role_family = classify_role_family(title, blob) if config.get("specialty_gap_rules_enabled", False) else {"name": "Preference-driven", "points": 0, "hits": []}
    eligibility = location_eligibility(location, work, blob, config)
    resume_profile = config.get("resume_profile", {})
    resume_alignment_hits: list[str] = []
    resume_alignment_score = 0
    if resume_profile.get("enabled") and resume_profile.get("keywords"):
        resume_alignment_hits = [
            str(term)
            for term in resume_profile.get("keywords", [])
            if normalize_text(str(term)) and normalize_text(str(term)) in blob
        ][:20]
        resume_alignment_score = min(int(resume_profile.get("max_points", 12) or 12), len(resume_alignment_hits))

    base = technical + seniority + salary_score + location_score + employer_score + worklife_score
    base += focus_score + resume_alignment_score + float(ideal_score["points"]) + int(role_family["points"])
    watched = watchlist_match(job.get("company", ""), config)
    watchlist_bonus = int(config.get("company_watchlist", {}).get("boost_points", 0)) if watched else 0
    base += watchlist_bonus

    penalties = []
    penalty_total = 0
    for rule in config.get("penalty_rules", []):
        if not rule.get("enabled", True):
            continue
        phrase = normalize_text(str(rule.get("term", "")))
        if phrase and phrase in blob:
            amount = int(rule.get("points", 0))
            penalties.append({"amount": amount, "reason": rule.get("reason", phrase)})
            penalty_total += amount
    for learned in learned_rejection_penalties(blob, config):
        penalties.append(learned)
        penalty_total += int(learned["amount"])
    if config.get("specialty_gap_rules_enabled", False):
        for product_gap in product_specialist_gap_penalties(blob, str(resume_profile.get("text") or "")):
            penalties.append(product_gap)
            penalty_total += int(product_gap["amount"])
    if ideal_score["missing_must"]:
        penalties.append({"amount": -22, "reason": "Missing ideal-job must-have lane: " + ", ".join(ideal_score["missing_must"][:5])})
    for breaker in ideal_score["dealbreakers"][:5]:
        penalties.append({"amount": -12, "reason": f"Ideal-job dealbreaker matched: {breaker}"})
    if not eligibility["eligible"]:
        penalties.append({"amount": -100, "reason": eligibility["reason"]})
        penalty_total -= 100

    deep_hits = count_matches(blob, DEEP_PLATFORM_TERMS) if config.get("specialty_gap_rules_enabled", False) else []
    if len(deep_hits) >= 3 and not any(t in blob for t in ["windows", "vmware", "microsoft", "entra", "active directory"]):
        penalties.append({"amount": -35, "reason": "Deep AWS/Kubernetes/Terraform/SRE specialization dominates"})
        penalty_total -= 35

    max_salary = extract_max_salary(salary)
    salary_floor = int(config.get("target_salary_min", 0) or 0)
    if salary_floor and max_salary and max_salary < salary_floor:
        penalties.append({"amount": -40, "reason": f"Maximum published salary below target (${salary_floor:,})"})
        penalty_total -= 40

    score = max(0, min(100, round(base + penalty_total)))
    if any(p["amount"] <= -100 for p in penalties):
        score = 0

    verdict = verdict_for_score(score, config)
    technical_max = category_max(category_results, "technical") or 1
    career_max = category_max(category_results, "career") or 1
    technical_fit = min(100, round((technical / technical_max) * 100))
    career_fit = min(100, round((seniority / career_max) * 100))

    strong_matches = []
    for result in category_results:
        if result["hits"]:
            strong_matches.append(f"{result['label']}: {', '.join(result['hits'][:12])}")
    if resume_alignment_hits:
        strong_matches.append(f"Uploaded resume alignment: {', '.join(resume_alignment_hits[:12])}")
    if ideal_score["hits"]:
        strong_matches.append(f"Ideal job profile: {', '.join(ideal_score['hits'][:12])}")
    if ideal_score["title_hits"]:
        strong_matches.append(f"Strong target title: {', '.join(ideal_score['title_hits'][:5])}")

    gaps = []
    if len(core_hits) < 7:
        gaps.append("Limited overlap with the configured skills and resume")
    if resume_profile.get("enabled") and resume_profile.get("text") and not resume_alignment_hits:
        gaps.append("No strong overlap with uploaded resume keywords")
    if deep_hits:
        gaps.append(f"Growth or mismatch technologies present: {', '.join(deep_hits[:8])}")
    if ideal_score["missing_must"]:
        gaps.append("Does not show one of the configured must-have skills or job lanes")
    if ideal_score["dealbreakers"]:
        gaps.append(f"Ideal-job dealbreaker terms present: {', '.join(ideal_score['dealbreakers'][:8])}")
    if not eligibility["eligible"]:
        gaps.append(eligibility["reason"])
    if int(role_family["points"]) < 0:
        gaps.append(f"Role family risk: {role_family['name']}")
    if not salary:
        gaps.append("Salary unknown - investigate")
    if "bachelor" in blob and "equivalent" not in blob and "experience" not in blob:
        gaps.append("Education requirement - verify flexibility")

    hard_blockers = [p["reason"] for p in penalties if p["amount"] <= -100]

    one_liner = make_one_liner(score, verdict, focus_hits, core_hits, penalties)
    details = {
        "base_score": base,
        "penalty_total": penalty_total,
        "strong_matches": strong_matches,
        "real_gaps": gaps,
        "hard_blockers": hard_blockers,
        "compensation_assessment": salary_notes,
        "work_arrangement_assessment": location_notes,
        "work_life_assessment": worklife_notes,
        "penalties": penalties,
        "watched_company": watched,
        "watchlist_bonus": watchlist_bonus,
        "resume_alignment_score": resume_alignment_score,
        "resume_alignment_hits": resume_alignment_hits,
        "resume_filename": resume_profile.get("filename", ""),
        "ideal_profile": ideal_score,
        "role_family": role_family,
        "location_eligibility": eligibility,
        "category_results": category_results,
        "core_hits": core_hits,
        "focus_hits": focus_hits,
        "responsibility_hits": responsibility_hits,
        "one_sentence": one_liner,
        "career_rationale": career_rationale(verdict, focus_hits, responsibility_hits, core_hits, penalties),
    }
    return {
        "score": score,
        "verdict": verdict,
        "technical_fit": technical_fit,
        "career_fit": career_fit,
        "details": details,
    }


def score_salary(salary: str, config: dict[str, Any]) -> tuple[int, str]:
    if not salary:
        return 8, "SALARY UNKNOWN - INVESTIGATE"
    max_salary = extract_max_salary(salary)
    if not max_salary:
        return 8, "Salary present but could not parse; investigate realistic range."
    target = int(config.get("target_salary_min", 0) or 0)
    if not target:
        return 10, "Salary found; set a target salary to score compensation fit."
    ratio = max_salary / target
    if ratio >= 1.15:
        return 15, "Published compensation is comfortably above the target."
    if ratio >= 1:
        return 13, "Published compensation meets the target."
    if ratio >= .9:
        return 8, "Published compensation is slightly below the target."
    return 0, "Maximum salary appears below the configured target."


def extract_max_salary(text: str) -> int | None:
    if not text:
        return None
    nums = []
    for raw in re.findall(r"\$?\s*(\d{2,3})(?:,\d{3})?\s*k?", text.lower()):
        num = int(raw)
        if num < 1000:
            num *= 1000
        nums.append(num)
    return max(nums) if nums else None


def score_location(location: str, work: str, config: dict[str, Any]) -> tuple[int, str]:
    blob = f"{location} {work}"
    preferred = [normalize_text(value) for value in config.get("job_search", {}).get("locations", [])]
    home = normalize_text(str(config.get("home_location", "")))
    if any(term and term in blob for term in preferred + ([home] if home else [])):
        return 15, "Location matches a configured preference."
    if "remote" in blob:
        return 12, "Remote role; geographic eligibility should be verified."
    if "relocation" in blob:
        return 0, "Relocation appears required."
    return 7, "Location fit needs manual verification."


def score_growth(blob: str) -> int:
    terms = ["architecture", "modernization", "automation", "cloud migration", "hybrid", "identity governance", "lead", "mentor"]
    return min(10, 4 + len(count_matches(blob, terms)))


def score_employer(blob: str, environment: str, finance_hits: list[str]) -> int:
    score = 2
    if any(x in environment for x in ["internal", "corporate", "enterprise"]):
        score += 2
    if any(x in blob for x in ["manufacturing", "healthcare", "bank", "credit union", "insurance", "financial services", "utility"]):
        score += 2
    if finance_hits:
        score += 1
    return min(5, score)


def score_worklife(blob: str) -> tuple[int, str]:
    if any(x in blob for x in ["24x7", "24/7", "constant availability", "nights and weekends"]):
        return 1, "Work-life risk: posting suggests heavy availability."
    if any(x in blob for x in ["on-call rotation", "shared on-call", "occasional after-hours"]):
        return 4, "Acceptable work-life signal if rotation is reasonable."
    return 3, "Work-life balance not clear from posting."


def verdict_for_score(score: int, config: dict[str, Any]) -> str:
    if score >= int(config["apply_now_score"]):
        return "APPLY NOW"
    if score >= int(config["strong_apply_score"]):
        return "STRONG APPLY"
    if score >= int(config["review_score"]):
        return "REVIEW"
    if score >= int(config["low_priority_score"]):
        return "LOW PRIORITY"
    return "SKIP"


def make_one_liner(score: int, verdict: str, focus_hits: list[str], core_hits: list[str], penalties: list[dict[str, Any]]) -> str:
    if penalties and score < 60:
        return f"{score}/100 - Correct-title risk or blocker detected: {penalties[0]['reason']}; {verdict.lower()}."
    focus = "preferred-field " if focus_hits else ""
    skills = ", ".join(core_hits[:5]) if core_hits else "limited visible resume alignment"
    return f"{score}/100 - {verdict}: {focus}role with {skills}."


def career_rationale(verdict: str, focus_hits: list[str], responsibility_hits: list[str], core_hits: list[str], penalties: list[dict[str, Any]]) -> str:
    if any(p["amount"] <= -100 for p in penalties):
        return "This should not advance the search because a hard blocker appears present."
    if verdict in {"APPLY NOW", "STRONG APPLY"}:
        parts = ["This role aligns with the candidate's configured career direction"]
        if focus_hits:
            parts.append("in a preferred field or environment")
        if responsibility_hits:
            parts.append("with visible ownership, modernization, or escalation responsibility")
        if core_hits:
            parts.append("and strong overlap with resume skills")
        return " ".join(parts) + "."
    return "This needs review because the posting may not provide enough skill, compensation, title, or location alignment."


def insert_or_update_job(form: dict[str, str]) -> tuple[int, bool]:
    init_db()
    config = load_config()
    canonical = canonicalize_url(form.get("canonical_url") or form.get("url"))
    uhash = url_hash(canonical)
    key = normalized_key(form["title"], form["company"], form.get("location", ""))
    scored = score_job(form, config)
    now = utcnow()
    desc_hash = text_hash(form.get("description", ""))
    watched = 1 if scored["details"].get("watched_company") else 0
    values = {
        "canonical_url": canonical,
        "url_hash": uhash,
        "req_id": form.get("req_id", ""),
        "title": form["title"],
        "company": form["company"],
        "location": form.get("location", ""),
        "work_arrangement": form.get("work_arrangement", ""),
        "office_days": form.get("office_days", ""),
        "salary_range": form.get("salary_range", ""),
        "employment_type": form.get("employment_type", ""),
        "environment_type": form.get("environment_type", ""),
        "source": form.get("source", "manual"),
        "description": form.get("description", ""),
        "description_hash": desc_hash,
        "normalized_key": key,
        "posted_date": normalize_posted_date(
            form.get("posted_date")
            or form.get("date_posted")
            or form.get("published_at")
            or form.get("publication_date")
            or form.get("created_at")
            or form.get("created")
        ),
        "last_seen": now,
        "score": scored["score"],
        "verdict": scored["verdict"],
        "technical_fit": scored["technical_fit"],
        "career_fit": scored["career_fit"],
        "scoring_json": json.dumps(scored["details"], indent=2),
        "watched_company": watched,
    }
    with db() as con:
        existing = None
        if uhash:
            existing = con.execute("select * from jobs where url_hash = ?", (uhash,)).fetchone()
        if existing is None:
            existing = con.execute(
                "select * from jobs where normalized_key = ? or (req_id != '' and req_id = ?)",
                (key, form.get("req_id", "")),
            ).fetchone()
        if existing:
            change_summary = ""
            last_changed = existing["last_changed"]
            if desc_hash and existing["description_hash"] and desc_hash != existing["description_hash"]:
                change_summary = "Description changed since last seen."
                last_changed = now
            elif existing["salary_range"] != values["salary_range"]:
                change_summary = "Salary range changed since last seen."
                last_changed = now
            elif existing["location"] != values["location"] or existing["work_arrangement"] != values["work_arrangement"]:
                change_summary = "Location or work arrangement changed since last seen."
                last_changed = now
            con.execute(
                """
                update jobs set
                    canonical_url=:canonical_url, url_hash=:url_hash, req_id=:req_id,
                    title=:title, company=:company, location=:location,
                    work_arrangement=:work_arrangement, office_days=:office_days,
                    salary_range=:salary_range, employment_type=:employment_type,
                    environment_type=:environment_type, source=:source,
                    description=:description, description_hash=:description_hash,
                    normalized_key=:normalized_key,
                    posted_date=:posted_date,
                    last_seen=:last_seen, score=:score, verdict=:verdict,
                    technical_fit=:technical_fit, career_fit=:career_fit,
                    scoring_json=:scoring_json, change_summary=:change_summary,
                    last_changed=:last_changed, watched_company=:watched_company
                where id=:id
                """,
                {**values, "id": existing["id"], "change_summary": change_summary, "last_changed": last_changed},
            )
            return int(existing["id"]), False
        cur = con.execute(
            """
            insert into jobs (
                canonical_url, url_hash, req_id, title, company, location, work_arrangement,
                office_days, salary_range, employment_type, environment_type, source,
                description, description_hash, normalized_key, posted_date, first_seen, last_seen,
                last_changed, score, verdict, technical_fit, career_fit, scoring_json,
                watched_company
            ) values (
                :canonical_url, :url_hash, :req_id, :title, :company, :location,
                :work_arrangement, :office_days, :salary_range, :employment_type,
                :environment_type, :source, :description, :description_hash,
                :normalized_key, :posted_date, :first_seen, :last_seen, :last_changed, :score,
                :verdict, :technical_fit, :career_fit, :scoring_json, :watched_company
            )
            """,
            {**values, "first_seen": now, "last_changed": now},
        )
        return int(cur.lastrowid), True


def get_jobs(filter_name: str = "active") -> list[sqlite3.Row]:
    init_db()
    where = "1=1"
    params: tuple[Any, ...] = ()
    if filter_name in {"apply", "best"}:
        where = "verdict in ('APPLY NOW', 'STRONG APPLY', 'REVIEW') and status not in ('rejected', 'ignored')"
    elif filter_name == "finance":
        where = "scoring_json like '%finance_hits%[]%' = 0"
    elif filter_name == "active":
        where = "status not in ('rejected', 'ignored') and verdict != 'SKIP'"
    elif filter_name in {"new_today", "new"}:
        where = "datetime(first_seen) >= datetime('now', '-24 hours')"
    elif filter_name == "low_priority":
        where = "verdict = 'LOW PRIORITY' and status not in ('rejected', 'ignored')"
    elif filter_name == "skipped":
        where = "verdict = 'SKIP' and status not in ('rejected', 'ignored')"
    elif filter_name == "all":
        where = "1=1"
    elif filter_name == "hidden":
        where = "status in ('rejected', 'ignored')"
    elif filter_name == "applied":
        where = "applied = 1 or status = 'applied'"
    elif filter_name == "watchlist":
        where = "watched_company = 1"
    elif filter_name == "changed":
        where = "change_summary != ''"
    elif filter_name == "stale":
        where = "julianday('now') - julianday(first_seen) > 14 and verdict not in ('APPLY NOW', 'STRONG APPLY')"
    elif filter_name == "pipeline":
        where = "pipeline_stage not in ('new', 'rejected', 'ignored')"
    with db() as con:
        return con.execute(
            f"select * from jobs where {where} order by score desc, datetime(last_seen) desc limit 300",
            params,
        ).fetchall()


def get_job(job_id: int) -> sqlite3.Row | None:
    init_db()
    with db() as con:
        return con.execute("select * from jobs where id = ?", (job_id,)).fetchone()


def delete_job(job_id: int) -> None:
    init_db()
    with db() as con:
        con.execute("delete from jobs where id = ?", (job_id,))


def purge_skipped_jobs() -> int:
    init_db()
    with db() as con:
        cur = con.execute("delete from jobs where verdict = 'SKIP'")
        return int(cur.rowcount or 0)


def update_job_status(job_id: int, status: str, notes: str, rejection_reason: str, applied: bool, form: dict[str, str] | None = None) -> None:
    form = form or {}
    pipeline_stage = form.get("pipeline_stage") or status
    applied_date = form.get("applied_date", "")
    if applied and not applied_date:
        applied_date = dt.date.today().isoformat()
    with db() as con:
        con.execute(
            """
            update jobs set status = ?, candidate_notes = ?, rejection_reason = ?, applied = ?,
                pipeline_stage = ?, applied_date = ?, contact_name = ?, contact_email = ?,
                follow_up_date = ?, resume_version = ?, rejection_category = ?
            where id = ?
            """,
            (
                status,
                notes,
                rejection_reason,
                1 if applied else 0,
                pipeline_stage,
                applied_date,
                form.get("contact_name", ""),
                form.get("contact_email", ""),
                form.get("follow_up_date", ""),
                form.get("resume_version", ""),
                form.get("rejection_category", ""),
                job_id,
            ),
        )


FEEDBACK_ACTIONS = {
    "good": ("saved", "saved", "", "Good match"),
    "bad": ("ignored", "ignored", "Other", "Bad match"),
    "wrong-specialty": ("ignored", "ignored", "Wrong specialty", "Wrong specialty"),
    "too-junior": ("ignored", "ignored", "Not senior enough", "Too junior"),
    "too-developer": ("ignored", "ignored", "Too much AWS/Kubernetes/SRE", "Too developer / SRE"),
    "too-support": ("ignored", "ignored", "Too much help desk", "Too much support"),
    "too-onsite": ("ignored", "ignored", "Too far / onsite", "Too much onsite"),
    "too-low": ("ignored", "ignored", "Too low salary", "Too low salary"),
}


def apply_job_feedback(job_id: int, action: str) -> None:
    status, stage, rejection_category, label = FEEDBACK_ACTIONS.get(action, FEEDBACK_ACTIONS["bad"])
    job = get_job(job_id)
    if not job:
        return
    notes = (job["candidate_notes"] or "").strip()
    stamp = dt.datetime.now().strftime("%Y-%m-%d")
    feedback_note = f"{stamp}: Feedback - {label}"
    notes = f"{notes}\n{feedback_note}".strip() if notes else feedback_note
    rejection_reason = job["rejection_reason"] or ""
    if status == "ignored" and not rejection_reason:
        rejection_reason = label
    with db() as con:
        con.execute(
            """
            update jobs set status = ?, pipeline_stage = ?, candidate_notes = ?,
                rejection_reason = ?, rejection_category = ?
            where id = ?
            """,
            (status, stage, notes, rejection_reason, rejection_category or job["rejection_category"], job_id),
        )


def start_scan_run(reason: str) -> int:
    init_db()
    with db() as con:
        con.execute(
            """
            update scan_runs
            set completed_at = ?, status = 'interrupted',
                message = 'Marked interrupted when a new scan started.'
            where status = 'running'
            """,
            (utcnow(),),
        )
        cur = con.execute(
            "insert into scan_runs (started_at, reason, status) values (?, ?, 'running')",
            (utcnow(), reason),
        )
        return int(cur.lastrowid)


def finish_scan_run(scan_run_id: int, status: str, message: str = "") -> None:
    with db() as con:
        con.execute(
            "update scan_runs set completed_at = ?, status = ?, message = ? where id = ?",
            (utcnow(), status, message, scan_run_id),
        )


def record_scan_source(scan_run_id: int, source: dict[str, Any], fetched: int, created: int, updated: int, status: str = "ok", message: str = "") -> None:
    with db() as con:
        con.execute(
            """
            insert into scan_source_results (
                scan_run_id, source_name, source_type, enabled, fetched, created,
                updated, status, message, created_at
            ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_run_id,
                str(source.get("name") or source.get("type") or "source"),
                str(source.get("type") or ""),
                1 if source.get("enabled", True) else 0,
                fetched,
                created,
                updated,
                status,
                message,
                utcnow(),
            ),
        )


def latest_scan_runs(limit: int = 10) -> list[sqlite3.Row]:
    init_db()
    with db() as con:
        return con.execute(
            "select * from scan_runs order by datetime(started_at) desc limit ?",
            (limit,),
        ).fetchall()


def scan_source_results(scan_run_id: int) -> list[sqlite3.Row]:
    with db() as con:
        return con.execute(
            "select * from scan_source_results where scan_run_id = ? order by id",
            (scan_run_id,),
        ).fetchall()


def source_quality_rows(limit: int = 50) -> list[sqlite3.Row]:
    init_db()
    with db() as con:
        return con.execute(
            """
            select
                source,
                count(*) as total_jobs,
                sum(case when verdict in ('APPLY NOW', 'STRONG APPLY', 'REVIEW') then 1 else 0 end) as quality_jobs,
                sum(case when verdict = 'SKIP' then 1 else 0 end) as skipped_jobs,
                max(last_seen) as last_seen,
                round(avg(score), 1) as avg_score
            from jobs
            group by source
            order by quality_jobs desc, avg_score desc, total_jobs desc
            limit ?
            """,
            (limit,),
        ).fetchall()


def create_backup(retention_days: int = 14) -> Path:
    backup_dir = DATA_DIR / "backups"
    backup_dir.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    backup_path = backup_dir / f"finance-job-ranker-{stamp}.sqlite3"
    with db() as source, sqlite3.connect(backup_path) as destination:
        source.backup(destination)
        if destination.execute("pragma integrity_check").fetchone()[0] != "ok":
            raise RuntimeError("Backup integrity check failed")
    if CONFIG_PATH.exists():
        shutil.copy2(CONFIG_PATH, backup_dir / f"config-{stamp}.json")
    cutoff = time.time() - max(1, retention_days) * 86400
    for candidate in backup_dir.glob("*"):
        if candidate.is_file() and candidate.stat().st_mtime < cutoff:
            candidate.unlink()
    return backup_path


def maybe_daily_backup() -> str:
    backup_dir = DATA_DIR / "backups"
    today = dt.datetime.now().strftime("%Y%m%d")
    if any(backup_dir.glob(f"finance-job-ranker-{today}-*.sqlite3")) if backup_dir.exists() else False:
        return "Daily backup already exists."
    return f"Backup created: {create_backup().name}"


def send_apply_now_alerts(dry_run: bool = False) -> list[str]:
    init_db()
    config = load_config()
    verdicts = config.get("email", {}).get("alert_verdicts") or ["APPLY NOW"]
    placeholders = ",".join("?" for _ in verdicts)
    with db() as con:
        jobs = con.execute(
            f"""
            select * from jobs
            where verdict in ({placeholders})
              and alert_sent = 0
              and status not in ('rejected', 'ignored')
            order by score desc
            """,
            tuple(verdicts),
        ).fetchall()
    if not jobs:
        return [f"No unsent strongest-job alerts for: {', '.join(verdicts)}."]
    messages = []
    for job in jobs:
        body = render_email_body(job)
        subject = f"{config['email']['subject_prefix']} {job['score']}/100 - {job['title']} - {job['company']}"
        if dry_run or not config["email"].get("enabled"):
            messages.append(f"DRY RUN: {subject}\n{body[:900]}")
            continue
        send_email(config, subject, body)
        with db() as con:
            con.execute("update jobs set alert_sent = 1 where id = ?", (job["id"],))
        messages.append(f"Sent: {subject}")
    return messages


def send_digest(dry_run: bool = False) -> list[str]:
    init_db()
    config = load_config()
    digest = config.get("digest", {})
    verdicts = []
    if digest.get("include_apply_now", True):
        verdicts.append("APPLY NOW")
    if digest.get("include_strong_apply", True):
        verdicts.append("STRONG APPLY")
    if digest.get("include_review", False):
        verdicts.append("REVIEW")
    if not verdicts:
        return ["Digest has no enabled verdict groups."]
    max_jobs = int(digest.get("max_jobs", 5) or 5)
    if digest.get("top_jobs_only", True):
        max_jobs = min(max_jobs, 5)
    placeholders = ",".join("?" for _ in verdicts)
    with db() as con:
        jobs = con.execute(
            f"""
            select * from jobs
            where verdict in ({placeholders})
              and digest_sent = 0
              and status not in ('rejected', 'ignored')
            order by score desc, datetime(first_seen) desc
            limit ?
            """,
            (*verdicts, max_jobs),
        ).fetchall()
    if not jobs:
        return ["No new digest-worthy jobs."]
    subject = f"{config['email']['subject_prefix']} Daily digest - {len(jobs)} job(s)"
    body = render_digest_body(jobs)
    if dry_run or not config["email"].get("enabled"):
        return [f"DRY RUN: {subject}\n{body}"]
    send_email(config, subject, body)
    with db() as con:
        con.executemany("update jobs set digest_sent = 1 where id = ?", [(job["id"],) for job in jobs])
    return [f"Sent digest: {subject}"]


def send_email(config: dict[str, Any], subject: str, body: str) -> None:
    email_cfg = config["email"]
    msg = email.message.EmailMessage()
    msg["Subject"] = subject
    msg["From"] = email_cfg.get("from_email") or email_cfg["smtp_username"]
    msg["To"] = email_cfg["to_email"]
    msg.set_content(body)
    with smtplib.SMTP(email_cfg["smtp_host"], int(email_cfg["smtp_port"]), timeout=30) as smtp:
        if email_cfg.get("smtp_starttls"):
            smtp.starttls()
        if email_cfg.get("smtp_username"):
            smtp.login(email_cfg["smtp_username"], email_cfg["smtp_password"])
        smtp.send_message(msg)


def render_digest_body(jobs: list[sqlite3.Row]) -> str:
    lines = ["Daily Job Digest", ""]
    counts: dict[str, int] = {}
    for job in jobs:
        counts[job["verdict"]] = counts.get(job["verdict"], 0) + 1
    for verdict, count in counts.items():
        lines.append(f"{verdict}: {count}")
    lines.append("")
    for job in jobs:
        details = json.loads(job["scoring_json"])
        stale = staleness_label(job)
        lines.extend(
            [
                f"{job['score']}/100 - {job['verdict']} - {job['title']} - {job['company']}",
                f"Location: {job['location'] or 'Unknown'} | Work: {job['work_arrangement'] or 'Unknown'} | Salary: {job['salary_range'] or 'Unknown'}",
                f"Status: {stale} | First seen: {job['first_seen'][:10]} | Last seen: {job['last_seen'][:10]}",
                details.get("one_sentence", ""),
                f"URL: {job['canonical_url'] or 'No URL stored'}",
                "",
            ]
        )
    return "\n".join(lines)


def render_email_body(job: sqlite3.Row) -> str:
    details = json.loads(job["scoring_json"])
    sections = [
        f"{job['score']}/100 - {job['verdict']}",
        f"{job['title']} - {job['company']}",
        f"Location: {job['location'] or 'Unknown'}",
        f"Work arrangement: {job['work_arrangement'] or 'Unknown'}",
        f"Salary: {job['salary_range'] or 'SALARY UNKNOWN - INVESTIGATE'}",
        f"URL: {job['canonical_url'] or 'No URL stored'}",
        "",
        details.get("one_sentence", ""),
        "",
        "STRONG MATCHES",
        bullet(details.get("strong_matches", [])),
        "",
        "REAL GAPS",
        bullet(details.get("real_gaps", [])),
        "",
        "HARD BLOCKERS",
        bullet(details.get("hard_blockers", [])),
        "",
        "COMPENSATION ASSESSMENT",
        details.get("compensation_assessment", ""),
        "",
        "WORK ARRANGEMENT ASSESSMENT",
        details.get("work_arrangement_assessment", ""),
        "",
        "WHY THIS WOULD OR WOULD NOT ADVANCE THE CANDIDATE'S CAREER",
        details.get("career_rationale", ""),
    ]
    return "\n".join(sections)


def bullet(items: list[str]) -> str:
    return "\n".join(f"- {item}" for item in items) if items else "- None found"


def staleness_label(job: sqlite3.Row) -> str:
    first_seen = dt.datetime.fromisoformat(job["first_seen"].replace("Z", "+00:00"))
    age_days = (dt.datetime.now(dt.UTC) - first_seen).days
    if job["change_summary"]:
        return "Changed since last review"
    if age_days <= 1:
        return "New within 24 hours"
    if age_days <= 3:
        return "Seen within 3 days"
    if age_days <= 7:
        return "Seen within 7 days"
    if age_days <= 14:
        return "Older than 7 days"
    return "Older than 14 days"


def tailoring_advice(job: sqlite3.Row) -> dict[str, Any]:
    config = load_config()
    details = json.loads(job["scoring_json"])
    hits = set()
    for result in details.get("category_results", []):
        hits.update(result.get("hits", []))
    priority_terms = list(config.get("resume_profile", {}).get("keywords", [])) + list(config.get("ideal_job", {}).get("desired_terms", []))
    missing = [term for term in priority_terms if normalize_text(term) in normalize_text(job["description"]) and normalize_text(term) not in {normalize_text(hit) for hit in hits}]
    candidate = config.get("candidate_name") or "Candidate"
    strongest = sorted(hits)[:10]
    summary = f"{candidate} offers relevant experience in {', '.join(strongest) if strongest else 'the skills described in the uploaded resume'}."
    recruiter = (
        f"Hi, I am interested in the {job['title']} role at {job['company']}. "
        f"My background aligns with {', '.join(strongest[:6]) if strongest else 'several of the role requirements'}. "
        "I would welcome the chance to discuss how my experience could support your team."
    )
    return {"covered": sorted(hits), "missing": missing[:12], "summary": summary, "recruiter": recruiter}


def fetch_url_text(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "JobMatchCommandCenter/1.0"})
    with urllib.request.urlopen(req, timeout=30) as res:
        raw = res.read(2_000_000)
    text = raw.decode("utf-8", errors="replace")
    text = re.sub(r"<script\b[^<]*(?:(?!</script>)<[^<]*)*</script>", " ", text, flags=re.I)
    text = re.sub(r"<style\b[^<]*(?:(?!</style>)<[^<]*)*</style>", " ", text, flags=re.I)
    text = re.sub(r"<[^>]+>", " ", text)
    return html.unescape(re.sub(r"\s+", " ", text)).strip()


def fetch_url_text_lenient(url: str) -> str:
    try:
        return fetch_url_text(url)
    except Exception:
        return ""


def fetch_json(url: str, headers: dict[str, str] | None = None) -> Any:
    request_headers = {"User-Agent": "JobMatchCommandCenter/1.0"}
    if headers:
        request_headers.update(headers)
    req = urllib.request.Request(url, headers=request_headers)
    with urllib.request.urlopen(req, timeout=40) as res:
        raw = res.read(5_000_000)
    return json.loads(raw.decode("utf-8", errors="replace"))


def html_to_text(value: str | None) -> str:
    text = value or ""
    text = re.sub(r"<script\b[^<]*(?:(?!</script>)<[^<]*)*</script>", " ", text, flags=re.I)
    text = re.sub(r"<style\b[^<]*(?:(?!</style>)<[^<]*)*</style>", " ", text, flags=re.I)
    text = re.sub(r"<[^>]+>", " ", text)
    return html.unescape(re.sub(r"\s+", " ", text)).strip()


def salary_from_range(low: Any, high: Any) -> str:
    parts = []
    for value in (low, high):
        if value in (None, "", 0):
            continue
        try:
            parts.append(f"${int(float(value)):,.0f}")
        except (TypeError, ValueError):
            parts.append(str(value))
    if len(parts) == 2:
        return f"{parts[0]} - {parts[1]}"
    return parts[0] if parts else ""


def resume_search_queries(config: dict[str, Any]) -> list[str]:
    job_search = config.get("job_search", {})
    profile = config.get("resume_profile", {})
    if not job_search.get("resume_driven_search", True) or not profile.get("enabled") or not profile.get("keywords"):
        return []
    keywords = [normalize_text(str(term)) for term in profile.get("keywords", [])]
    tech_groups = [
        ["azure", "microsoft 365", "entra", "active directory", "intune"],
        ["vmware", "vsphere", "veeam", "windows server"],
        ["powershell", "automation", "disaster recovery", "backup"],
        ["identity", "mfa", "conditional access", "security hardening"],
        ["networking", "firewall", "dns", "dhcp"],
    ]
    titles = [
        "senior infrastructure engineer",
        "senior systems engineer",
        "infrastructure architect",
        "microsoft infrastructure engineer",
        "senior cloud administrator",
        "identity engineer",
    ]
    queries: list[str] = []
    for title in titles:
        hits = []
        for group in tech_groups:
            group_hits = [term for term in group if term in keywords]
            if group_hits:
                hits.append(group_hits[0])
        suffix = " ".join(hits[:3])
        query = f"{title} {suffix}".strip()
        if query not in queries:
            queries.append(query)
    for term in keywords:
        if term in {"azure", "microsoft 365", "entra", "active directory", "vmware", "powershell", "intune"}:
            query = f"senior {term} engineer"
            if query not in queries:
                queries.append(query)
    return queries[: int(job_search.get("resume_query_count", 8) or 8)]


def source_queries(config: dict[str, Any], source: dict[str, Any]) -> list[str]:
    configured = source.get("queries") or config.get("job_search", {}).get("queries", [])
    queries: list[str] = []
    ideal = config.get("ideal_job", {})
    ideal_queries = []
    if ideal.get("enabled", True):
        ideal_queries.extend(str(query) for query in ideal.get("strong_titles", []) if str(query).strip())
    for query in [str(query) for query in configured if str(query).strip()] + resume_search_queries(config) + ideal_queries:
        if query not in queries:
            queries.append(query)
    return queries


def imported_job_passes_search_tuning(item: dict[str, Any], config: dict[str, Any]) -> tuple[bool, str]:
    job_search = config.get("job_search", {})
    blob = normalize_text(" ".join(str(item.get(key, "")) for key in ["title", "company", "location", "description", "environment_type"]))
    eligibility = location_eligibility(str(item.get("location", "")), str(item.get("work_arrangement", "")), blob, config)
    if not eligibility["eligible"]:
        return False, eligibility["reason"]
    posted_date = normalize_posted_date(
        item.get("posted_date")
        or item.get("date_posted")
        or item.get("published_at")
        or item.get("publication_date")
        or item.get("created_at")
        or item.get("created")
    )
    days_posted = int(job_search.get("days_posted", 0) or 0)
    if posted_date and not posted_date_is_within_range(posted_date, days_posted):
        return False, f"posted before configured {days_posted}-day range"
    required_terms = [normalize_text(term) for term in job_search.get("required_terms", []) if str(term).strip()]
    if required_terms and not any(term in blob for term in required_terms):
        return False, "missing required search term"
    excluded_terms = [normalize_text(term) for term in job_search.get("excluded_terms", []) if str(term).strip()]
    if any(term in blob for term in excluded_terms):
        return False, "matched excluded search term"
    profile = config.get("resume_profile", {})
    min_hits = int(job_search.get("minimum_resume_keyword_hits", 0) or 0)
    if min_hits > 0 and profile.get("enabled") and profile.get("keywords"):
        hits = [term for term in profile.get("keywords", []) if normalize_text(str(term)) in blob]
        if len(hits) < min_hits:
            return False, "below resume keyword overlap threshold"
    return True, ""


def source_limit(config: dict[str, Any], source: dict[str, Any]) -> int:
    return int(source.get("max_results") or config.get("job_search", {}).get("max_results_per_source", 60))


def domain_from_url(url: str) -> str:
    parsed = urlparse(url)
    return parsed.netloc.replace("www.", "") or "Web result"


def looks_like_job_result(title: str, url: str, snippet: str, config: dict[str, Any]) -> bool:
    blob = normalize_text(f"{title} {url} {snippet}")
    blocked_terms = [
        "senior living",
        "senior care",
        "retirement",
        "assisted living",
        "nursing home",
        "55+",
        "senior center",
        "elder care",
    ]
    if any(term in blob for term in blocked_terms):
        return False
    job_page_terms = [
        "job",
        "jobs",
        "career",
        "careers",
        "apply",
        "greenhouse",
        "lever.co",
        "workdayjobs",
        "myworkdayjobs",
        "smartrecruiters",
        "icims",
        "jobvite",
        "bamboohr",
        "ashbyhq",
        "paylocity",
        "ultipro",
        "successfactors",
        "recruiting",
        "linkedin.com/jobs",
        "indeed.com",
        "builtin.com",
        "dice.com",
        "glassdoor.com",
        "wellfound.com",
        "flexjobs.com",
        "welcometothejungle.com",
        "ziprecruiter.com",
        "theladders.com",
    ]
    role_terms = [
        "infrastructure",
        "systems engineer",
        "system engineer",
        "systems administrator",
        "system administrator",
        "microsoft",
        "azure",
        "m365",
        "entra",
        "identity",
        "vmware",
        "windows",
        "cloud engineer",
        "platform engineer",
        "it engineer",
        "network engineer",
        "solution architect",
        "systems architect",
        "infrastructure architect",
        "enterprise architect",
        "technology architect",
        "it architect",
        "systems analyst",
        "technical lead",
        "senior it",
        "endpoint engineer",
        "desktop engineer",
        "collaboration engineer",
        "exchange engineer",
        "sharepoint engineer",
        "server engineer",
        "storage engineer",
        "backup engineer",
        "operations engineer",
    ]
    has_job_page_signal = any(term in blob for term in job_page_terms)
    has_title_signal = any(term in blob for term in role_terms)
    return has_job_page_signal and has_title_signal


def fetch_bing_rss_jobs(source: dict[str, Any], config: dict[str, Any]) -> list[dict[str, str]]:
    jobs = []
    seen_urls = set()
    detail_fetches = 0
    suffixes = source.get("query_suffixes") or [""]
    for base_query in source_queries(config, source):
        for suffix in suffixes:
            query = f'"{base_query}" jobs careers apply {suffix}'.strip()
            url = f"https://www.bing.com/search?{urlencode({'q': query, 'format': 'rss'})}"
            raw = urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "JobMatchCommandCenter/1.0"}), timeout=30).read(2_000_000)
            root = ET.fromstring(raw)
            for item in root.findall("./channel/item"):
                title = html_to_text(item.findtext("title") or "")
                link_url = item.findtext("link") or ""
                snippet = html_to_text(item.findtext("description") or "")
                posted_date = normalize_posted_date(item.findtext("pubDate") or item.findtext("published") or "")
                if not link_url or link_url in seen_urls:
                    continue
                if not looks_like_job_result(title, link_url, snippet, config):
                    continue
                seen_urls.add(link_url)
                detail = ""
                if source.get("fetch_detail_pages", True) and detail_fetches < int(source.get("max_detail_fetches", 20)):
                    detail = fetch_url_text_lenient(link_url)
                    detail_fetches += 1
                company = domain_from_url(link_url)
                jobs.append(
                    {
                        "title": title[:180],
                        "company": company,
                        "location": "Web discovery",
                        "work_arrangement": "",
                        "salary_range": "",
                        "employment_type": "",
                        "environment_type": "Web discovery",
                        "canonical_url": link_url,
                        "posted_date": posted_date,
                        "req_id": "",
                        "source": "bing_rss",
                        "description": f"{snippet}\n\n{detail}",
                    }
                )
                if len(jobs) >= source_limit(config, source):
                    return jobs
    return jobs


def fetch_target_company_bing_jobs(source: dict[str, Any], config: dict[str, Any]) -> list[dict[str, str]]:
    jobs = []
    seen_urls = set()
    detail_fetches = 0
    watch = config.get("company_watchlist", {})
    companies = source.get("companies") or watch.get("companies", [])
    configured_queries = source_queries(config, source)
    fallback_queries = [
        "senior infrastructure engineer",
        "systems engineer",
        "IT systems engineer",
        "infrastructure architect",
        "cloud infrastructure engineer",
        "M365 engineer",
        "identity engineer",
        "VMware engineer",
        "Windows systems engineer",
        "IT operations engineer",
    ]
    role_queries = configured_queries + [query for query in fallback_queries if query not in configured_queries]
    max_companies = int(source.get("max_companies", 25))
    max_roles_per_company = int(source.get("max_roles_per_company", 5))
    suffixes = source.get("query_suffixes") or ["jobs careers", "careers apply"]
    for company in [str(c) for c in companies[:max_companies]]:
        for role in role_queries[:max_roles_per_company]:
            for suffix in suffixes:
                query = f'"{company}" "{role}" {suffix}'
                url = f"https://www.bing.com/search?{urlencode({'q': query, 'format': 'rss'})}"
                try:
                    raw = urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "JobMatchCommandCenter/1.0"}), timeout=30).read(2_000_000)
                    root = ET.fromstring(raw)
                except (urllib.error.URLError, TimeoutError, ET.ParseError):
                    continue
                for item in root.findall("./channel/item"):
                    title = html_to_text(item.findtext("title") or "")
                    link_url = item.findtext("link") or ""
                    snippet = html_to_text(item.findtext("description") or "")
                    posted_date = normalize_posted_date(item.findtext("pubDate") or item.findtext("published") or "")
                    if not link_url or link_url in seen_urls:
                        continue
                    if not looks_like_job_result(title, link_url, snippet, config):
                        continue
                    seen_urls.add(link_url)
                    detail = ""
                    if source.get("fetch_detail_pages", True) and detail_fetches < int(source.get("max_detail_fetches", 40)):
                        detail = fetch_url_text_lenient(link_url)
                        detail_fetches += 1
                    jobs.append(
                        {
                            "title": title[:180],
                            "company": company,
                            "location": "Target company discovery",
                            "work_arrangement": "",
                            "salary_range": "",
                            "employment_type": "",
                            "environment_type": "Target employer career discovery",
                            "canonical_url": link_url,
                            "posted_date": posted_date,
                            "req_id": "",
                            "source": "target_company_bing",
                            "description": f"{snippet}\n\n{detail}",
                        }
                    )
                    if len(jobs) >= source_limit(config, source):
                        return jobs
    return jobs


def fetch_priority_job_board_bing_jobs(source: dict[str, Any], config: dict[str, Any]) -> list[dict[str, str]]:
    jobs = []
    seen_urls = set()
    detail_fetches = 0
    boards = source.get("boards", [])
    role_queries = source_queries(config, source)
    max_boards = int(source.get("max_boards", len(boards) or 14))
    max_queries_per_board = int(source.get("max_queries_per_board", 1))
    extra_terms = source.get("extra_terms") or ["remote", "North Carolina", "Charlotte"]
    for board in boards[:max_boards]:
        name = str(board.get("name") or board.get("domain") or "Job board")
        domain = str(board.get("domain") or "").strip()
        if not domain:
            continue
        for role in role_queries[:max_queries_per_board]:
            for extra in extra_terms:
                query = f'site:{domain} "{role}" jobs {extra}'
                url = f"https://www.bing.com/search?{urlencode({'q': query, 'format': 'rss'})}"
                try:
                    raw = urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "JobMatchCommandCenter/1.0"}), timeout=12).read(2_000_000)
                    root = ET.fromstring(raw)
                except (urllib.error.URLError, TimeoutError, ET.ParseError):
                    continue
                for item in root.findall("./channel/item"):
                    title = html_to_text(item.findtext("title") or "")
                    link_url = item.findtext("link") or ""
                    snippet = html_to_text(item.findtext("description") or "")
                    posted_date = normalize_posted_date(item.findtext("pubDate") or item.findtext("published") or "")
                    if not link_url or link_url in seen_urls:
                        continue
                    if domain not in link_url:
                        continue
                    if not looks_like_job_result(title, link_url, snippet, config):
                        continue
                    seen_urls.add(link_url)
                    detail = ""
                    if source.get("fetch_detail_pages", True) and detail_fetches < int(source.get("max_detail_fetches", 20)):
                        detail = fetch_url_text_lenient(link_url)
                        detail_fetches += 1
                    jobs.append(
                        {
                            "title": title[:180],
                            "company": name,
                            "location": "Priority job-board discovery",
                            "work_arrangement": "",
                            "salary_range": "",
                            "employment_type": "",
                            "environment_type": f"{name} job-board discovery",
                            "canonical_url": link_url,
                            "posted_date": posted_date,
                            "req_id": "",
                            "source": "priority_job_boards",
                            "description": f"{snippet}\n\n{detail}",
                        }
                    )
                    if len(jobs) >= source_limit(config, source):
                        return jobs
    return jobs


def fetch_remotive_jobs(source: dict[str, Any], config: dict[str, Any]) -> list[dict[str, str]]:
    jobs = []
    seen_urls = set()
    for query in source_queries(config, source):
        params = urlencode({"search": query})
        data = fetch_json(f"https://remotive.com/api/remote-jobs?{params}")
        for item in data.get("jobs", []):
            url = str(item.get("url") or "")
            if url in seen_urls:
                continue
            seen_urls.add(url)
            location = item.get("candidate_required_location") or "Remote"
            tags = ", ".join(str(tag) for tag in item.get("tags") or [])
            jobs.append(
                {
                    "title": str(item.get("title") or ""),
                    "company": str(item.get("company_name") or ""),
                    "location": str(location),
                    "work_arrangement": "Remote",
                    "salary_range": str(item.get("salary") or ""),
                    "employment_type": str(item.get("job_type") or "Full-time"),
                    "environment_type": "Unknown",
                    "canonical_url": url,
                    "posted_date": normalize_posted_date(item.get("publication_date") or item.get("published_at") or ""),
                    "req_id": str(item.get("id") or ""),
                    "source": "remotive",
                    "description": html_to_text(item.get("description")) + f" Tags: {tags}",
                }
            )
            if len(jobs) >= source_limit(config, source):
                return jobs
    return jobs


def fetch_arbeitnow_jobs(source: dict[str, Any], config: dict[str, Any]) -> list[dict[str, str]]:
    jobs = []
    terms = [normalize_text(term) for term in source_queries(config, source)]
    max_pages = int(source.get("max_pages", 2))
    for page_num in range(1, max_pages + 1):
        data = fetch_json(f"https://www.arbeitnow.com/api/job-board-api?page={page_num}")
        for item in data.get("data", []):
            title = str(item.get("title") or "")
            description = html_to_text(item.get("description"))
            blob = normalize_text(f"{title} {description}")
            if terms and not any(term in blob for term in terms):
                continue
            remote = bool(item.get("remote"))
            location = item.get("location") or ("Remote" if remote else "")
            job_types = ", ".join(str(v) for v in item.get("job_types") or [])
            tags = ", ".join(str(v) for v in item.get("tags") or [])
            jobs.append(
                {
                    "title": title,
                    "company": str(item.get("company_name") or ""),
                    "location": str(location),
                    "work_arrangement": "Remote" if remote else str(location),
                    "salary_range": "",
                    "employment_type": job_types,
                    "environment_type": "Unknown",
                    "canonical_url": str(item.get("url") or ""),
                    "posted_date": normalize_posted_date(item.get("created_at") or item.get("createdAt") or ""),
                    "req_id": str(item.get("slug") or ""),
                    "source": "arbeitnow",
                    "description": f"{description} Tags: {tags}",
                }
            )
            if len(jobs) >= source_limit(config, source):
                return jobs
    return jobs


def fetch_remoteok_jobs(source: dict[str, Any], config: dict[str, Any]) -> list[dict[str, str]]:
    jobs = []
    terms = [normalize_text(term) for term in source_queries(config, source)]
    strict = bool(source.get("strict_query_filter", False))
    data = fetch_json("https://remoteok.com/api", headers={"User-Agent": "JobMatchCommandCenter/1.0"})
    for item in data:
        if not isinstance(item, dict) or not item.get("position"):
            continue
        title = str(item.get("position") or "")
        description = html_to_text(item.get("description"))
        blob = normalize_text(f"{title} {description} {' '.join(str(t) for t in item.get('tags') or [])}")
        if strict and terms and not any(term in blob for term in terms):
            continue
        tags = ", ".join(str(tag) for tag in item.get("tags") or [])
        jobs.append(
            {
                "title": title,
                "company": str(item.get("company") or ""),
                "location": str(item.get("location") or "Remote"),
                "work_arrangement": "Remote",
                "salary_range": salary_from_range(item.get("salary_min"), item.get("salary_max")),
                "employment_type": "Remote",
                "environment_type": "Unknown",
                "canonical_url": str(item.get("apply_url") or item.get("url") or ""),
                "posted_date": normalize_posted_date(item.get("date") or item.get("epoch") or ""),
                "req_id": str(item.get("id") or item.get("slug") or ""),
                "source": "remoteok",
                "description": f"{description} Tags: {tags}",
            }
        )
        if len(jobs) >= source_limit(config, source):
            return jobs
    return jobs


def fetch_jobicy_jobs(source: dict[str, Any], config: dict[str, Any]) -> list[dict[str, str]]:
    jobs = []
    seen = set()
    geo = source.get("geo", "usa")
    for query in source_queries(config, source):
        params = urlencode({"count": min(200, source_limit(config, source)), "geo": geo, "tag": query[:50]})
        data = fetch_json(f"https://jobicy.com/api/v2/remote-jobs?{params}")
        for item in data.get("jobs", []):
            url = str(item.get("url") or "")
            if url in seen:
                continue
            seen.add(url)
            jobs.append(
                {
                    "title": str(item.get("jobTitle") or ""),
                    "company": str(item.get("companyName") or ""),
                    "location": str(item.get("jobGeo") or "Remote"),
                    "work_arrangement": "Remote",
                    "salary_range": salary_from_range(item.get("salaryMin"), item.get("salaryMax")),
                    "employment_type": ", ".join(str(v) for v in item.get("jobType") or []),
                    "environment_type": "Unknown",
                    "canonical_url": url,
                    "posted_date": normalize_posted_date(item.get("pubDate") or item.get("published_at") or item.get("datePosted") or ""),
                    "req_id": str(item.get("id") or item.get("jobSlug") or ""),
                    "source": "jobicy",
                    "description": html_to_text(item.get("jobDescription") or item.get("jobExcerpt")),
                }
            )
            if len(jobs) >= source_limit(config, source):
                return jobs
    return jobs


def fetch_themuse_jobs(source: dict[str, Any], config: dict[str, Any]) -> list[dict[str, str]]:
    jobs = []
    terms = [normalize_text(term) for term in source_queries(config, source)]
    strict = bool(source.get("strict_query_filter", False))
    pages = int(source.get("pages", 2))
    categories = source.get("categories") or ["Computer and IT"]
    locations = source.get("locations") or ["Remote"]
    for category in categories:
        for location in locations:
            for page_num in range(1, pages + 1):
                params = urlencode({"page": page_num, "category": category, "location": location})
                data = fetch_json(f"https://www.themuse.com/api/public/jobs?{params}")
                for item in data.get("results", []):
                    title = str(item.get("name") or "")
                    description = html_to_text(item.get("contents"))
                    blob = normalize_text(f"{title} {description}")
                    if strict and terms and not any(term in blob for term in terms):
                        continue
                    locs = ", ".join(str(v.get("name") or "") for v in item.get("locations") or [])
                    levels = ", ".join(str(v.get("name") or "") for v in item.get("levels") or [])
                    categories_text = ", ".join(str(v.get("name") or "") for v in item.get("categories") or [])
                    company = item.get("company") or {}
                    refs = item.get("refs") or {}
                    jobs.append(
                        {
                            "title": title,
                            "company": str(company.get("name") or ""),
                            "location": locs,
                            "work_arrangement": locs,
                            "salary_range": "",
                            "employment_type": str(item.get("type") or ""),
                            "environment_type": "Unknown",
                            "canonical_url": str(refs.get("landing_page") or ""),
                            "posted_date": normalize_posted_date(item.get("publication_date") or item.get("published_at") or ""),
                            "req_id": str(item.get("id") or ""),
                            "source": "themuse",
                            "description": f"{description} Levels: {levels}. Categories: {categories_text}.",
                        }
                    )
                    if len(jobs) >= source_limit(config, source):
                        return jobs
    return jobs


def fetch_himalayas_jobs(source: dict[str, Any], config: dict[str, Any]) -> list[dict[str, str]]:
    jobs = []
    terms = [normalize_text(term) for term in source_queries(config, source)]
    strict = bool(source.get("strict_query_filter", False))
    data = fetch_json("https://himalayas.app/jobs/api")
    for item in data.get("jobs", []):
        title = str(item.get("title") or "")
        description = html_to_text(item.get("description") or item.get("excerpt"))
        categories = ", ".join(str(v) for v in item.get("categories") or [])
        blob = normalize_text(f"{title} {description} {categories}")
        if strict and terms and not any(term in blob for term in terms):
            continue
        location = ", ".join(str(v) for v in item.get("locationRestrictions") or []) or "Remote"
        seniority = ", ".join(str(v) for v in item.get("seniority") or [])
        jobs.append(
            {
                "title": title,
                "company": str(item.get("companyName") or ""),
                "location": location,
                "work_arrangement": "Remote",
                "salary_range": salary_from_range(item.get("minSalary"), item.get("maxSalary")),
                "employment_type": str(item.get("employmentType") or ""),
                "environment_type": "Unknown",
                "canonical_url": str(item.get("applicationLink") or ""),
                "posted_date": normalize_posted_date(item.get("publishedAt") or item.get("createdAt") or item.get("postedAt") or ""),
                "req_id": str(item.get("guid") or ""),
                "source": "himalayas",
                "description": f"{description} Categories: {categories}. Seniority: {seniority}.",
            }
        )
        if len(jobs) >= source_limit(config, source):
            return jobs
    return jobs


def fetch_weworkremotely_jobs(source: dict[str, Any], config: dict[str, Any]) -> list[dict[str, str]]:
    jobs = []
    terms = [normalize_text(term) for term in source_queries(config, source)]
    strict = bool(source.get("strict_query_filter", False))
    seen = set()
    for feed_url in source.get("feeds", []):
        try:
            raw = urllib.request.urlopen(
                urllib.request.Request(str(feed_url), headers={"User-Agent": "JobMatchCommandCenter/1.0"}),
                timeout=30,
            ).read(3_000_000)
        except Exception:
            continue
        root = ET.fromstring(raw)
        for item in root.findall("./channel/item"):
            title = html_to_text(item.findtext("title") or "")
            link_url = item.findtext("link") or ""
            description = html_to_text(item.findtext("description") or "")
            posted_date = normalize_posted_date(item.findtext("pubDate") or item.findtext("published") or "")
            if not link_url or link_url in seen:
                continue
            seen.add(link_url)
            blob = normalize_text(f"{title} {description}")
            if strict and terms and not any(term in blob for term in terms):
                continue
            company = "We Work Remotely"
            title_parts = re.split(r"\s*:\s*", title, maxsplit=1)
            if len(title_parts) == 2:
                company, title = title_parts[0], title_parts[1]
            jobs.append(
                {
                    "title": title,
                    "company": company,
                    "location": "Remote",
                    "work_arrangement": "Remote",
                    "salary_range": "",
                    "employment_type": "Remote",
                    "environment_type": "Unknown",
                    "canonical_url": link_url,
                    "posted_date": posted_date,
                    "req_id": link_url.rsplit("/", 1)[-1],
                    "source": "weworkremotely",
                    "description": description,
                }
            )
            if len(jobs) >= source_limit(config, source):
                return jobs
    return jobs


def fetch_greenhouse_jobs(source: dict[str, Any], config: dict[str, Any]) -> list[dict[str, str]]:
    jobs = []
    terms = [normalize_text(term) for term in source_queries(config, source)]
    for board in source.get("boards", []):
        token = str(board.get("token") if isinstance(board, dict) else board)
        if not token:
            continue
        data = fetch_json(f"https://boards-api.greenhouse.io/v1/boards/{token}/jobs?content=true")
        for item in data.get("jobs", []):
            title = str(item.get("title") or "")
            description = html_to_text(item.get("content"))
            blob = normalize_text(f"{title} {description}")
            if terms and not any(term in blob for term in terms):
                continue
            location = ""
            if item.get("location"):
                location = str(item["location"].get("name") or "")
            company = str(board.get("company") if isinstance(board, dict) else token)
            jobs.append(
                {
                    "title": title,
                    "company": company,
                    "location": location,
                    "work_arrangement": location,
                    "salary_range": "",
                    "employment_type": "",
                    "environment_type": "Employer career site",
                    "canonical_url": str(item.get("absolute_url") or ""),
                    "posted_date": normalize_posted_date(item.get("updated_at") or item.get("created_at") or ""),
                    "req_id": str(item.get("internal_job_id") or item.get("id") or ""),
                    "source": f"greenhouse:{token}",
                    "description": description,
                }
            )
            if len(jobs) >= source_limit(config, source):
                return jobs
    return jobs


def fetch_lever_jobs(source: dict[str, Any], config: dict[str, Any]) -> list[dict[str, str]]:
    jobs = []
    terms = [normalize_text(term) for term in source_queries(config, source)]
    for site in source.get("sites", []):
        site_name = str(site.get("site") if isinstance(site, dict) else site)
        if not site_name:
            continue
        data = fetch_json(f"https://api.lever.co/v0/postings/{site_name}?mode=json")
        for item in data:
            title = str(item.get("text") or "")
            categories = item.get("categories") or {}
            list_text = " ".join(html_to_text(part.get("content")) for group in item.get("lists") or [] for part in group.get("content", []))
            description = " ".join([html_to_text(item.get("descriptionPlain") or item.get("description")), list_text])
            blob = normalize_text(f"{title} {description}")
            if terms and not any(term in blob for term in terms):
                continue
            company = str(site.get("company") if isinstance(site, dict) else site_name)
            jobs.append(
                {
                    "title": title,
                    "company": company,
                    "location": str(categories.get("location") or ""),
                    "work_arrangement": str(categories.get("location") or ""),
                    "salary_range": "",
                    "employment_type": str(categories.get("commitment") or ""),
                    "environment_type": "Employer career site",
                    "canonical_url": str(item.get("hostedUrl") or ""),
                    "posted_date": normalize_posted_date(item.get("createdAt") or item.get("created_at") or ""),
                    "req_id": str(item.get("id") or ""),
                    "source": f"lever:{site_name}",
                    "description": description,
                }
            )
            if len(jobs) >= source_limit(config, source):
                return jobs
    return jobs


def fetch_adzuna_jobs(source: dict[str, Any], config: dict[str, Any]) -> list[dict[str, str]]:
    app_id = source.get("app_id") or os.environ.get("ADZUNA_APP_ID")
    app_key = source.get("app_key") or os.environ.get("ADZUNA_APP_KEY")
    if not app_id or not app_key:
        raise ValueError("Adzuna source requires app_id/app_key or ADZUNA_APP_ID/ADZUNA_APP_KEY.")
    jobs = []
    country = source.get("country", "us")
    pages = int(source.get("pages", 1))
    days = int(config.get("job_search", {}).get("days_posted", 7))
    for query in source_queries(config, source):
        for page_num in range(1, pages + 1):
            params = urlencode(
                {
                    "app_id": app_id,
                    "app_key": app_key,
                    "what": query,
                    "where": "United States",
                    "max_days_old": days,
                    "results_per_page": min(50, source_limit(config, source)),
                    "sort_by": "date",
                }
            )
            data = fetch_json(f"https://api.adzuna.com/v1/api/jobs/{country}/search/{page_num}?{params}")
            for item in data.get("results", []):
                jobs.append(
                    {
                        "title": str(item.get("title") or ""),
                        "company": str((item.get("company") or {}).get("display_name") or ""),
                        "location": str((item.get("location") or {}).get("display_name") or ""),
                        "work_arrangement": str((item.get("location") or {}).get("display_name") or ""),
                        "salary_range": salary_from_range(item.get("salary_min"), item.get("salary_max")),
                        "employment_type": str(item.get("contract_type") or ""),
                        "environment_type": "Unknown",
                        "canonical_url": str(item.get("redirect_url") or ""),
                        "posted_date": normalize_posted_date(item.get("created") or ""),
                        "req_id": str(item.get("id") or ""),
                        "source": "adzuna",
                        "description": html_to_text(item.get("description")),
                    }
                )
                if len(jobs) >= source_limit(config, source):
                    return jobs
    return jobs


def fetch_usajobs(source: dict[str, Any], config: dict[str, Any]) -> list[dict[str, str]]:
    user_agent = source.get("user_agent") or os.environ.get("USAJOBS_USER_AGENT")
    api_key = source.get("api_key") or os.environ.get("USAJOBS_API_KEY")
    if not user_agent or not api_key:
        raise ValueError("USAJOBS source requires user_agent/api_key or USAJOBS_USER_AGENT/USAJOBS_API_KEY.")
    jobs = []
    headers = {"Host": "data.usajobs.gov", "User-Agent": str(user_agent), "Authorization-Key": str(api_key)}
    days = int(config.get("job_search", {}).get("days_posted", 7))
    for query in source_queries(config, source):
        params = urlencode(
            {
                "Keyword": query,
                "JobCategoryCode": "2210",
                "WhoMayApply": "public",
                "DatePosted": days,
                "Fields": "Full",
                "ResultsPerPage": int(source.get("results_per_page", 25)),
            }
        )
        data = fetch_json(f"https://data.usajobs.gov/api/Search?{params}", headers=headers)
        for wrapper in (data.get("SearchResult") or {}).get("SearchResultItems", []):
            item = wrapper.get("MatchedObjectDescriptor") or {}
            locations = item.get("PositionLocation") or []
            location = "; ".join(str(loc.get("LocationName") or "") for loc in locations)
            remuneration = item.get("PositionRemuneration") or []
            salary = ""
            if remuneration:
                salary = salary_from_range(remuneration[0].get("MinimumRange"), remuneration[0].get("MaximumRange"))
            jobs.append(
                {
                    "title": str(item.get("PositionTitle") or ""),
                    "company": str(item.get("OrganizationName") or item.get("DepartmentName") or "USAJOBS"),
                    "location": location,
                    "work_arrangement": "Remote" if item.get("RemoteIndicator") else location,
                    "salary_range": salary,
                    "employment_type": "; ".join(str(v.get("Name") or "") for v in item.get("PositionSchedule") or []),
                    "environment_type": "Government",
                    "canonical_url": str((item.get("ApplyURI") or [item.get("PositionURI") or ""])[0]),
                    "posted_date": normalize_posted_date(item.get("PublicationStartDate") or item.get("PositionStartDate") or ""),
                    "req_id": str(item.get("PositionID") or ""),
                    "source": "usajobs",
                    "description": html_to_text(" ".join(str(item.get(k) or "") for k in ["QualificationSummary", "JobSummary", "MajorDuties", "Education", "Evaluations"])),
                }
            )
            if len(jobs) >= source_limit(config, source):
                return jobs
    return jobs


SOURCE_FETCHERS = {
    "bing_rss": fetch_bing_rss_jobs,
    "target_company_bing": fetch_target_company_bing_jobs,
    "remotive": fetch_remotive_jobs,
    "arbeitnow": fetch_arbeitnow_jobs,
    "remoteok": fetch_remoteok_jobs,
    "jobicy": fetch_jobicy_jobs,
    "themuse": fetch_themuse_jobs,
    "himalayas": fetch_himalayas_jobs,
    "weworkremotely": fetch_weworkremotely_jobs,
    "priority_job_boards": fetch_priority_job_board_bing_jobs,
    "greenhouse": fetch_greenhouse_jobs,
    "lever": fetch_lever_jobs,
    "adzuna": fetch_adzuna_jobs,
    "usajobs": fetch_usajobs,
}


class Handler(BaseHTTPRequestHandler):
    server_version = "JobMatchCommandCenter/1.0"

    def authenticated(self) -> bool:
        expected_user = os.environ.get("APP_USERNAME", "")
        expected_password = os.environ.get("APP_PASSWORD", "")
        if not expected_user or not expected_password:
            return True
        auth = self.headers.get("authorization", "")
        try:
            scheme, encoded = auth.split(" ", 1)
            decoded = base64.b64decode(encoded).decode("utf-8")
            username, password = decoded.split(":", 1)
        except (ValueError, UnicodeDecodeError):
            scheme, username, password = "", "", ""
        return scheme.lower() == "basic" and secrets.compare_digest(username, expected_user) and secrets.compare_digest(password, expected_password)

    def require_auth(self) -> bool:
        if self.authenticated():
            return True
        self.send_response(401)
        self.send_header("www-authenticate", 'Basic realm="Finance Job Ranker"')
        self.send_header("content-length", "0")
        self.end_headers()
        return False

    def valid_post_origin(self) -> bool:
        origin = self.headers.get("origin")
        return not origin or urlparse(origin).netloc == self.headers.get("host", "")

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/healthz":
            self.health()
            return
        if not self.require_auth():
            return
        query = parse_qs(urlparse(self.path).query)
        if path == "/setup":
            self.html(render_setup())
        elif path == "/" and not load_config().get("app", {}).get("setup_complete", False):
            self.html(render_setup())
        elif path == "/":
            self.html(render_dashboard(query.get("filter", ["active"])[0]))
        elif path == "/settings":
            self.html(render_settings())
        elif path == "/sources":
            self.html(render_sources())
        elif path == "/quality":
            self.html(render_quality_report())
        elif path == "/operations":
            self.html(render_operations())
        elif path == "/resume":
            self.html(render_resume())
        elif path == "/source/new":
            self.html(render_source_editor(None, query.get("type", ["bing_rss"])[0]))
        elif path.startswith("/source/"):
            self.html(render_source_editor(int(path.split("/")[-1])))
        elif path == "/new":
            self.html(render_new_form())
        elif path.startswith("/job/"):
            job = get_job(int(path.split("/")[-1]))
            self.html(render_job(job) if job else page("Not found", "<p>Job not found.</p>"), 404 if not job else 200)
        elif path == "/export.csv":
            self.export_csv()
        else:
            self.html(page("Not found", "<p>Not found.</p>"), 404)

    def do_POST(self) -> None:
        if not self.require_auth():
            return
        if not self.valid_post_origin():
            self.html(page("Forbidden", "<p>Invalid request origin.</p>"), 403)
            return
        path = urlparse(self.path).path
        length = int(self.headers.get("content-length", "0"))
        if length < 0 or length > MAX_REQUEST_BYTES:
            self.html(page("Upload Too Large", "<p>The request exceeded the 10 MB limit.</p>"), 413)
            return
        raw_body = self.rfile.read(length)
        if self.headers.get("content-type", "").lower().startswith("multipart/form-data"):
            form, files = parse_multipart(raw_body, self.headers.get("content-type", ""))
        else:
            data = parse_qs(raw_body.decode("utf-8"), keep_blank_values=True)
            form = {k: v[0].strip() for k, v in data.items()}
            files = {}
        if path == "/create":
            if form.get("fetch_url") and form.get("canonical_url") and not form.get("description"):
                try:
                    form["description"] = fetch_url_text(form["canonical_url"])
                except (urllib.error.URLError, TimeoutError, ValueError) as exc:
                    form["description"] = f"URL fetch failed: {exc}"
            job_id, created = insert_or_update_job(form)
            self.redirect(f"/job/{job_id}?created={1 if created else 0}")
        elif path == "/setup":
            save_setup_form(form)
            self.redirect("/resume")
        elif path.startswith("/status/"):
            job_id = int(path.split("/")[-1])
            update_job_status(
                job_id,
                form.get("status", "reviewed"),
                form.get("candidate_notes", ""),
                form.get("rejection_reason", ""),
                form.get("applied") == "on",
                form,
            )
            self.redirect(f"/job/{job_id}")
        elif path.startswith("/job/delete/"):
            delete_job(int(path.split("/")[-1]))
            self.redirect("/")
        elif path.startswith("/feedback/"):
            parts = path.strip("/").split("/")
            if len(parts) >= 3:
                apply_job_feedback(int(parts[1]), parts[2])
            self.redirect(self.headers.get("referer", "/"))
        elif path == "/jobs/purge-skipped":
            deleted = purge_skipped_jobs()
            body = f"""
              <p><a href="/">Back to dashboard</a></p>
              <section class="settings-note">
                <h2>Skipped Jobs Purged</h2>
                <p>Deleted {deleted} skipped job{'s' if deleted != 1 else ''}.</p>
              </section>
            """
            self.html(page("Skipped Jobs Purged", body))
        elif path == "/run-sources":
            messages = run_scheduled_scan("manual web run")
            body = """
              <p><a href="/sources">Back to sources</a> · <a href="/">Dashboard</a></p>
              <pre>""" + html.escape("\n".join(messages)) + """</pre>
            """
            self.html(page("Manual Scan Results", body))
        elif path == "/alerts":
            messages = send_digest(dry_run=form.get("dry") == "1") if form.get("digest") == "1" else send_apply_now_alerts(dry_run=form.get("dry") == "1")
            self.html(page("Alert Results", "<pre>" + html.escape("\n\n".join(messages)) + "</pre>"))
        elif path == "/settings":
            save_settings_form(form)
            self.redirect("/settings?saved=1")
        elif path == "/resume/upload":
            upload = files.get("resume_file")
            if not upload or not upload.get("content"):
                self.html(page("Resume Upload Error", '<p><a href="/resume">Back to resume</a></p><p>No resume file was uploaded.</p>'), 400)
                return
            try:
                save_resume_upload(str(upload.get("filename") or "resume"), upload["content"])
            except ValueError as exc:
                self.html(page("Resume Upload Error", f'<p><a href="/resume">Back to resume</a></p><pre>{esc(str(exc))}</pre>'), 400)
                return
            messages = rescore_all()
            self.html(page("Resume Uploaded", '<p><a href="/resume">Back to resume</a> · <a href="/">Dashboard</a></p><pre>' + esc("\n".join(messages[:30])) + "</pre>"))
        elif path == "/resume/clear":
            config = load_config()
            config["resume_profile"] = get_default_config()["resume_profile"]
            save_config(config)
            rescore_all()
            self.redirect("/resume")
        elif path.startswith("/source/toggle/"):
            toggle_source(int(path.split("/")[-1]))
            self.redirect("/sources")
        elif path.startswith("/source/delete/"):
            delete_source(int(path.split("/")[-1]))
            self.redirect("/sources")
        elif path == "/source/save":
            try:
                save_source_form(form)
            except ValueError as exc:
                self.html(page("Source Error", f'<p><a href="/sources">Back to sources</a></p><pre>{esc(str(exc))}</pre>'), 400)
                return
            self.redirect("/sources")
        else:
            self.html(page("Not found", "<p>Not found.</p>"), 404)

    def html(self, body: str, status: int = 200) -> None:
        raw = body.encode("utf-8")
        self.send_response(status)
        self.send_header("content-type", "text/html; charset=utf-8")
        self.send_header("x-content-type-options", "nosniff")
        self.send_header("x-frame-options", "DENY")
        self.send_header("referrer-policy", "same-origin")
        self.send_header("content-security-policy", "default-src 'self'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'")
        self.send_header("content-length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def health(self) -> None:
        try:
            with db() as con:
                con.execute("select 1").fetchone()
            payload = json.dumps({"status": "ok", "database": "ok", "time": utcnow()}).encode("utf-8")
            status = 200
        except Exception as exc:
            payload = json.dumps({"status": "error", "error": str(exc)}).encode("utf-8")
            status = 503
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("cache-control", "no-store")
        self.send_header("content-length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def redirect(self, location: str) -> None:
        self.send_response(303)
        self.send_header("location", location)
        self.end_headers()

    def export_csv(self) -> None:
        jobs = get_jobs("active")
        import io

        stream = io.StringIO()
        writer = csv.writer(stream)
        writer.writerow(["score", "verdict", "title", "company", "location", "salary", "status", "pipeline_stage", "posted_date", "first_seen", "last_seen", "change_summary", "watched_company", "url"])
        for job in jobs:
            writer.writerow(
                [
                    job["score"],
                    job["verdict"],
                    job["title"],
                    job["company"],
                    job["location"],
                    job["salary_range"],
                    job["status"],
                    job["pipeline_stage"],
                    job["posted_date"],
                    job["first_seen"],
                    job["last_seen"],
                    job["change_summary"],
                    "yes" if job["watched_company"] else "no",
                    job["canonical_url"],
                ]
            )
        raw = stream.getvalue().encode("utf-8")
        self.send_response(200)
        self.send_header("content-type", "text/csv; charset=utf-8")
        self.send_header("content-disposition", "attachment; filename=finance-job-ranker-export.csv")
        self.send_header("content-length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


def render_dashboard(filter_name: str) -> str:
    jobs = get_jobs(filter_name)
    cards = []
    for job in jobs:
        details = json.loads(job["scoring_json"])
        stale = staleness_label(job)
        changed = f"<span>{esc(job['change_summary'])}</span>" if job["change_summary"] else ""
        watched = "<span>Watched company</span>" if job["watched_company"] else ""
        posted = job["posted_date"] or "Unknown"
        cards.append(
            f"""
            <article class="job {css_verdict(job['verdict'])}">
              <div class="score">{job['score']}</div>
              <div>
                <h2><a href="/job/{job['id']}">{esc(job['title'])}</a></h2>
                <p class="meta">{esc(job['company'])} · {esc(job['location'] or 'Unknown')} · {esc(job['work_arrangement'] or 'Unknown')} · {esc(job['salary_range'] or 'Salary unknown')}</p>
                <p>{esc(details.get('one_sentence', ''))}</p>
                <p class="tags"><span>{esc(job['verdict'])}</span><span>{esc(job['status'])}</span><span>Posted {esc(posted)}</span><span>{esc(stale)}</span>{watched}{changed}<span>Found {esc(job['first_seen'][:10])}</span></p>
                <p class="card-actions">
                  <a class="button small" href="/job/{job['id']}">Open</a>
                  <form method="post" action="/feedback/{job['id']}/good" class="inline-form"><button class="small" type="submit">Good Match</button></form>
                  <form method="post" action="/feedback/{job['id']}/wrong-specialty" class="inline-form"><button class="small" type="submit">Wrong Specialty</button></form>
                  <form method="post" action="/job/delete/{job['id']}" class="inline-form"><button class="small danger" type="submit">Delete</button></form>
                </p>
              </div>
            </article>
            """
        )
    body = f"""
      <div class="toolbar">
        <a class="button" href="/new">Add Job</a>
        <form method="post" action="/run-sources" class="inline-form"><button type="submit">Run Scan Now</button></form>
        <form method="post" action="/jobs/purge-skipped" class="inline-form"><button class="danger" type="submit">Purge Skipped Jobs</button></form>
        <a class="button" href="/quality">Search Quality</a>
        <a class="button" href="/export.csv">Export CSV</a>
      </div>
      <nav class="filters">
        {filter_link('active', filter_name)} {filter_link('new', filter_name)} {filter_link('best', filter_name)} {filter_link('low_priority', filter_name)}
        {filter_link('skipped', filter_name)} {filter_link('applied', filter_name)} {filter_link('all', filter_name)}
      </nav>
      <section class="jobs">{''.join(cards) if cards else '<p>No jobs in this view yet.</p>'}</section>
    """
    return page(load_config().get("app", {}).get("title", "Job Match Command Center"), body)


def checked(value: Any) -> str:
    return " checked" if value else ""


def render_setup() -> str:
    config = load_config()
    search = config.get("job_search", {})
    ideal = config.get("ideal_job", {})
    body = f"""
      <section class="settings-note">
        <h2>Set Up Your Job Search</h2>
        <p>Tell the app what you want. After this step, upload your resume so searches and rankings can adapt to your experience.</p>
      </section>
      <form method="post" action="/setup" class="admin-form">
        <div class="grid-2">
          <label>Your name <input name="candidate_name" value="{esc(config.get('candidate_name', ''))}" autocomplete="name"></label>
          <label>Email for job alerts <input name="candidate_email" type="email" value="{esc(config.get('candidate_email', ''))}" autocomplete="email"></label>
          <label>Home location <input name="home_location" value="{esc(config.get('home_location', ''))}" placeholder="City, state, or country"></label>
          <label>Minimum target salary <input name="target_salary_min" type="number" min="0" value="{esc(config.get('target_salary_min', 0))}"></label>
        </div>
        <label>Job titles you want <textarea name="queries" rows="5" required placeholder="Project Manager&#10;Operations Manager&#10;Program Manager">{esc(chr(10).join(search.get('queries', [])))}</textarea></label>
        <label>Locations <textarea name="locations" rows="3" placeholder="remote&#10;Chicago, IL">{esc(chr(10).join(search.get('locations', [])))}</textarea></label>
        <label>Skills or qualities you want to use <textarea name="desired_terms" rows="4" placeholder="project delivery&#10;stakeholder management&#10;budgeting">{esc(chr(10).join(ideal.get('desired_terms', [])))}</textarea></label>
        <label>At least one required skill or job lane <textarea name="must_have_any" rows="3">{esc(chr(10).join(ideal.get('must_have_any', [])))}</textarea></label>
        <label>Terms to exclude <textarea name="excluded_terms" rows="3" placeholder="commission only&#10;temporary">{esc(chr(10).join(search.get('excluded_terms', [])))}</textarea></label>
        <label class="checkbox"><input type="checkbox" name="us_only"{checked(search.get('us_only', True))}> Only show jobs eligible in the United States</label>
        <button type="submit">Continue to Resume Upload</button>
      </form>
    """
    return page("First-Run Setup", body)


def render_settings() -> str:
    config = load_config()
    email_cfg = config.get("email", {})
    scheduled = config.get("scheduled_search", {})
    job_search = config.get("job_search", {})
    digest = config.get("digest", {})
    ideal = config.get("ideal_job", {})
    generated_resume_queries = resume_search_queries(config)
    category_rows = []
    for category in config.get("match_categories", []):
        enabled = "Yes" if category.get("enabled", True) else "No"
        profile = category.get("focus_profile", "Always active")
        term_count = len(category.get("terms", []))
        category_rows.append(
            f"""
            <tr>
              <td>{esc(category.get('label', category.get('id', 'Category')))}</td>
              <td>{esc(category.get('id', ''))}</td>
              <td>{enabled}</td>
              <td>{esc(profile)}</td>
              <td>{esc(category.get('fit_group', 'focus'))}</td>
              <td>{esc(category.get('max_points', 0))}</td>
              <td>{esc(category.get('points_per_match', 0))}</td>
              <td>{term_count}</td>
            </tr>
            """
        )
    penalty_rows = []
    for rule in config.get("penalty_rules", []):
        if not rule.get("enabled", True):
            continue
        penalty_rows.append(
            f"<tr><td>{esc(rule.get('term', ''))}</td><td>{esc(rule.get('points', ''))}</td><td>{esc(rule.get('reason', ''))}</td></tr>"
        )
    body = f"""
      <div class="toolbar">
        <a class="button" href="/">Dashboard</a>
        <a class="button" href="/sources">Sources</a>
        <form method="post" action="/run-sources" class="inline-form"><button type="submit">Run Scan Now</button></form>
      </div>
      <form method="post" action="/settings" class="admin-form">
        <section class="settings-note">
          <h2>App Branding</h2>
          <div class="grid-2">
            <label>App title <input name="app_title" value="{esc(config.get('app', {}).get('title', 'Job Match Command Center'))}"></label>
            <label>Subtitle <input name="app_subtitle" value="{esc(config.get('app', {}).get('subtitle', ''))}"></label>
            <label>Your name <input name="candidate_name" value="{esc(config.get('candidate_name', ''))}"></label>
            <label>Your email <input name="candidate_email" type="email" value="{esc(config.get('candidate_email', ''))}"></label>
            <label>Home location <input name="home_location" value="{esc(config.get('home_location', ''))}"></label>
            <label>Target salary minimum <input name="target_salary_min" type="number" value="{esc(config.get('target_salary_min', ''))}"></label>
          </div>
        </section>
        <section class="settings-note">
          <h2>Scoring Thresholds</h2>
          <div class="grid-4">
            <label>Apply Now <input name="apply_now_score" type="number" value="{esc(config.get('apply_now_score', ''))}"></label>
            <label>Strong Apply <input name="strong_apply_score" type="number" value="{esc(config.get('strong_apply_score', ''))}"></label>
            <label>Review <input name="review_score" type="number" value="{esc(config.get('review_score', ''))}"></label>
            <label>Low Priority <input name="low_priority_score" type="number" value="{esc(config.get('low_priority_score', ''))}"></label>
          </div>
        </section>
        <section class="settings-note">
          <h2>Scheduler And Search</h2>
          <div class="grid-3">
            <label class="checkbox"><input type="checkbox" name="scheduled_enabled"{checked(scheduled.get('enabled', True))}> Scheduler enabled</label>
            <label class="checkbox"><input type="checkbox" name="run_on_startup"{checked(scheduled.get('run_on_startup', True))}> Scan on startup</label>
            <label>Every N minutes <input name="interval_minutes" type="number" value="{esc(scheduled.get('interval_minutes', 60))}"></label>
          </div>
          <label>Fixed run times <textarea name="run_times" rows="2">{esc(chr(10).join(scheduled.get('run_times', [])))}</textarea></label>
          <label>Search queries <textarea name="queries" rows="7">{esc(chr(10).join(job_search.get('queries', [])))}</textarea></label>
          <label>Search locations <textarea name="locations" rows="3">{esc(chr(10).join(job_search.get('locations', [])))}</textarea></label>
          <div class="grid-4">
            <label class="checkbox"><input type="checkbox" name="us_only"{checked(job_search.get('us_only', True))}> US-only jobs</label>
            <label class="checkbox"><input type="checkbox" name="allow_global_remote"{checked(job_search.get('allow_global_remote', False))}> Allow global remote</label>
            <label class="checkbox"><input type="checkbox" name="resume_driven_search"{checked(job_search.get('resume_driven_search', True))}> Use resume-driven queries</label>
            <label>Resume query count <input name="resume_query_count" type="number" value="{esc(job_search.get('resume_query_count', 8))}"></label>
            <label>Minimum resume keyword hits <input name="minimum_resume_keyword_hits" type="number" value="{esc(job_search.get('minimum_resume_keyword_hits', 1))}"></label>
            <label>Default max results per source <input name="max_results_per_source" type="number" value="{esc(job_search.get('max_results_per_source', 60))}"></label>
            <label>Date posted range in days <input name="days_posted" type="number" min="0" value="{esc(job_search.get('days_posted', 7))}"></label>
          </div>
          <label>Required terms <textarea name="required_terms" rows="2" placeholder="Optional. Example: azure, active directory">{esc(chr(10).join(job_search.get('required_terms', [])))}</textarea></label>
          <label>Excluded terms <textarea name="excluded_terms" rows="3" placeholder="Terms to reject before importing">{esc(chr(10).join(job_search.get('excluded_terms', [])))}</textarea></label>
          <p><strong>Generated resume queries:</strong> {esc('; '.join(generated_resume_queries) if generated_resume_queries else 'Upload a resume or enable resume-driven search to generate these.')}</p>
        </section>
        <section class="settings-note">
          <h2>Ideal Job Profile</h2>
          <label class="checkbox"><input type="checkbox" name="ideal_enabled"{checked(ideal.get('enabled', True))}> Use ideal-job scoring</label>
          <label>Desired terms <textarea name="ideal_desired_terms" rows="5">{esc(chr(10).join(ideal.get('desired_terms', [])))}</textarea></label>
          <label>Must include at least one of these lanes <textarea name="ideal_must_have_any" rows="4">{esc(chr(10).join(ideal.get('must_have_any', [])))}</textarea></label>
          <label>Strong target titles <textarea name="ideal_strong_titles" rows="5">{esc(chr(10).join(ideal.get('strong_titles', [])))}</textarea></label>
          <label>Dealbreakers <textarea name="ideal_dealbreakers" rows="5">{esc(chr(10).join(ideal.get('dealbreakers', [])))}</textarea></label>
          <label>Target companies <textarea name="ideal_target_companies" rows="4" placeholder="Optional companies that should get an ideal-profile boost">{esc(chr(10).join(ideal.get('target_companies', [])))}</textarea></label>
        </section>
        <section class="settings-note">
          <h2>Email Alerts</h2>
          <div class="grid-2">
            <label class="checkbox"><input type="checkbox" name="email_enabled"{checked(email_cfg.get('enabled'))}> Email enabled</label>
            <label class="checkbox"><input type="checkbox" name="smtp_starttls"{checked(email_cfg.get('smtp_starttls', True))}> Use StartTLS</label>
            <label>SMTP host <input name="smtp_host" value="{esc(email_cfg.get('smtp_host', ''))}"></label>
            <label>SMTP port <input name="smtp_port" type="number" value="{esc(email_cfg.get('smtp_port', 587))}"></label>
            <label>SMTP username <input name="smtp_username" value="{esc(email_cfg.get('smtp_username', ''))}"></label>
            <label>SMTP password <input name="smtp_password" type="password" placeholder="Leave blank to keep current password"></label>
            <label>From email <input name="from_email" type="email" value="{esc(email_cfg.get('from_email', ''))}"></label>
            <label>To email <input name="to_email" type="email" value="{esc(email_cfg.get('to_email', ''))}"></label>
            <label>Subject prefix <input name="subject_prefix" value="{esc(email_cfg.get('subject_prefix', '[Apply Now Job]'))}"></label>
            <label>Alert verdicts <textarea name="alert_verdicts" rows="2">{esc(chr(10).join(email_cfg.get('alert_verdicts', [])))}</textarea></label>
          </div>
        </section>
        <section class="settings-note">
          <h2>Digest</h2>
          <div class="grid-4">
            <label class="checkbox"><input type="checkbox" name="digest_enabled"{checked(digest.get('enabled', True))}> Enabled</label>
            <label class="checkbox"><input type="checkbox" name="digest_apply_now"{checked(digest.get('include_apply_now', True))}> Apply Now</label>
            <label class="checkbox"><input type="checkbox" name="digest_strong_apply"{checked(digest.get('include_strong_apply', True))}> Strong Apply</label>
            <label class="checkbox"><input type="checkbox" name="digest_review"{checked(digest.get('include_review', False))}> Review</label>
            <label class="checkbox"><input type="checkbox" name="digest_top_jobs_only"{checked(digest.get('top_jobs_only', True))}> Top jobs only</label>
          </div>
          <label>Max digest jobs <input name="digest_max_jobs" type="number" value="{esc(digest.get('max_jobs', 12))}"></label>
        </section>
        <button type="submit">Save Settings</button>
      </form>
      <h2>Match Categories</h2>
      <section class="settings-note">
        <p>Scoring categories are still JSON-backed for now. You can see what is active here; source, scheduler, search, email, and branding are editable in the UI above.</p>
        <p>Active focus profiles: <strong>{esc(', '.join(config.get('active_focus_profiles', [])) or 'None')}</strong></p>
      </section>
      <div class="table-wrap">
        <table>
          <thead><tr><th>Label</th><th>ID</th><th>Enabled</th><th>Profile</th><th>Fit Group</th><th>Max</th><th>Per Hit</th><th>Terms</th></tr></thead>
          <tbody>{''.join(category_rows)}</tbody>
        </table>
      </div>
      <h2>Enabled Penalties</h2>
      <div class="table-wrap">
        <table>
          <thead><tr><th>Term</th><th>Points</th><th>Reason</th></tr></thead>
          <tbody>{''.join(penalty_rows)}</tbody>
        </table>
      </div>
    """
    return page("Settings", body)


def render_sources() -> str:
    config = load_config()
    scheduled = config.get("scheduled_search", {})
    source_rows = []
    for index, source in enumerate(scheduled.get("sources", [])):
        details = []
        if source.get("type") == "bing_rss":
            details.append("suffixes: " + ", ".join(str(v) for v in source.get("query_suffixes", [])[:8]))
        if source.get("type") == "target_company_bing":
            companies = source.get("companies") or config.get("company_watchlist", {}).get("companies", [])
            details.append("companies: " + ", ".join(str(v) for v in companies[:12]))
            if len(companies) > 12:
                details.append(f"+{len(companies) - 12} more companies")
            details.append("suffixes: " + ", ".join(str(v) for v in source.get("query_suffixes", [])))
        if source.get("type") == "weworkremotely":
            details.append("feeds: " + ", ".join(str(v) for v in source.get("feeds", [])))
        if source.get("type") == "priority_job_boards":
            board_names = [str(board.get("name") or board.get("domain")) for board in source.get("boards", [])]
            details.append("boards: " + ", ".join(board_names[:10]))
            if len(board_names) > 10:
                details.append(f"+{len(board_names) - 10} more boards")
            details.append("query terms: " + ", ".join(str(v) for v in source.get("extra_terms", [])))
        if source.get("type") == "themuse":
            details.append("categories: " + ", ".join(str(v) for v in source.get("categories", [])))
            details.append("locations: " + ", ".join(str(v) for v in source.get("locations", [])))
        if source.get("type") == "greenhouse":
            details.append("boards: " + str(len(source.get("boards", []))))
        if source.get("type") == "lever":
            details.append("sites: " + str(len(source.get("sites", []))))
        if source.get("type") == "adzuna":
            details.append("country: " + str(source.get("country", "us")))
        if source.get("type") == "usajobs":
            details.append("requires API key")
        if source.get("max_results"):
            details.append("max: " + str(source.get("max_results")))
        source_rows.append(
            f"""
            <tr>
              <td>{esc(source.get('name') or source.get('type'))}</td>
              <td>{esc(source.get('type'))}</td>
              <td>{'Yes' if source.get('enabled', True) else 'No'}</td>
              <td>{esc('; '.join(details))}</td>
              <td>
                <a class="button small" href="/source/{index}">Edit</a>
                <form method="post" action="/source/toggle/{index}" class="inline-form"><button class="small" type="submit">{'Disable' if source.get('enabled', True) else 'Enable'}</button></form>
                <form method="post" action="/source/delete/{index}" class="inline-form"><button class="small danger" type="submit">Delete</button></form>
              </td>
            </tr>
            """
        )
    site_rows = []
    source_site_labels = {
        "remotive": "remotive.com public remote jobs API",
        "arbeitnow": "arbeitnow.com public jobs API",
        "remoteok": "remoteok.com public jobs API",
        "jobicy": "jobicy.com remote jobs feed",
        "themuse": "themuse.com jobs API",
        "himalayas": "himalayas.app remote jobs feed",
        "weworkremotely": "weworkremotely.com RSS feeds",
        "priority_job_boards": "Bing RSS discovery over prioritized job-board sites",
        "bing_rss": "Bing RSS web search over public job/career pages",
        "target_company_bing": "Bing RSS target-company career discovery",
        "greenhouse": "Greenhouse employer boards",
        "lever": "Lever employer postings",
        "adzuna": "Adzuna Jobs API",
        "usajobs": "USAJOBS Search API",
    }
    for source in scheduled.get("sources", []):
        source_type = str(source.get("type") or "")
        if source_type == "priority_job_boards":
            for board in source.get("boards", []):
                priority = board.get("priority", "")
                label = f"{priority}. {board.get('name')}" if priority else str(board.get("name") or source.get("name"))
                site_rows.append(
                    f"""
                    <tr>
                      <td>{esc(label)}</td>
                      <td>{esc(board.get('domain') or '')} via Bing RSS discovery</td>
                      <td>{'Yes' if source.get('enabled', True) else 'No'}</td>
                    </tr>
                    """
                )
        else:
            site_rows.append(
                f"""
                <tr>
                  <td>{esc(source.get('name') or source_type)}</td>
                  <td>{esc(source_site_labels.get(source_type, source_type or 'custom source'))}</td>
                  <td>{'Yes' if source.get('enabled', True) else 'No'}</td>
                </tr>
                """
            )
    query_items = "".join(f"<li>{esc(q)}</li>" for q in config.get("job_search", {}).get("queries", []))
    run_blocks = []
    for run in latest_scan_runs(12):
        results = scan_source_results(int(run["id"]))
        result_rows = []
        for result in results:
            result_rows.append(
                f"""
                <tr>
                  <td>{esc(result['source_name'])}</td>
                  <td>{esc(result['source_type'])}</td>
                  <td>{esc(result['status'])}</td>
                  <td>{result['fetched']}</td>
                  <td>{result['created']}</td>
                  <td>{result['updated']}</td>
                  <td>{esc(result['message'])}</td>
                </tr>
                """
            )
        run_blocks.append(
            f"""
            <details class="settings-note">
              <summary><strong>{esc(run['started_at'])}</strong> - {esc(run['reason'])} - {esc(run['status'])}</summary>
              <p>Completed: {esc(run['completed_at'] or 'running')}</p>
              <div class="table-wrap">
                <table>
                  <thead><tr><th>Source</th><th>Type</th><th>Status</th><th>Fetched</th><th>Created</th><th>Updated</th><th>Message</th></tr></thead>
                  <tbody>{''.join(result_rows) if result_rows else '<tr><td colspan="7">No source results recorded yet.</td></tr>'}</tbody>
                </table>
              </div>
            </details>
            """
        )
    body = f"""
      <p><a href="/">Back to dashboard</a></p>
      <section class="settings-note">
        <p><strong>Scheduler:</strong> {'enabled' if scheduled.get('enabled', True) else 'disabled'} · startup scan: {'on' if scheduled.get('run_on_startup', True) else 'off'} · interval: {esc(scheduled.get('interval_minutes', ''))} minutes · fixed times: {esc(', '.join(scheduled.get('run_times', [])))}</p>
        <form method="post" action="/run-sources" class="inline-form"><button type="submit">Run Scan Now</button></form>
        <a class="button" href="/source/new">Add Source</a>
        <a class="button" href="/settings">App Settings</a>
      </section>
      <h2>Sites It Searches</h2>
      <div class="table-wrap">
        <table>
          <thead><tr><th>Source</th><th>Site / Search Area</th><th>Enabled</th></tr></thead>
          <tbody>{''.join(site_rows)}</tbody>
        </table>
      </div>
      <h2>Configured Sources</h2>
      <div class="table-wrap">
        <table>
          <thead><tr><th>Name</th><th>Type</th><th>Enabled</th><th>Details</th><th>Actions</th></tr></thead>
          <tbody>{''.join(source_rows)}</tbody>
        </table>
      </div>
      <h2>Search Terms</h2>
      <ul>{query_items}</ul>
      <h2>Recent Scan Runs</h2>
      {''.join(run_blocks) if run_blocks else '<p>No scan runs recorded yet. The next manual or scheduled scan will populate this page.</p>'}
    """
    return page("Sources And Scan Log", body)


def render_quality_report() -> str:
    rows = []
    for row in source_quality_rows():
        total = int(row["total_jobs"] or 0)
        quality = int(row["quality_jobs"] or 0)
        skipped = int(row["skipped_jobs"] or 0)
        rate = round((quality / total) * 100, 1) if total else 0
        skip_rate = round((skipped / total) * 100, 1) if total else 0
        rows.append(
            f"""
            <tr>
              <td>{esc(row['source'] or 'unknown')}</td>
              <td>{total}</td>
              <td>{quality}</td>
              <td>{rate}%</td>
              <td>{skipped}</td>
              <td>{skip_rate}%</td>
              <td>{esc(row['avg_score'] or 0)}</td>
              <td>{esc((row['last_seen'] or '')[:10])}</td>
            </tr>
            """
        )
    body = f"""
      <div class="toolbar">
        <a class="button" href="/">Dashboard</a>
        <a class="button" href="/sources">Sources</a>
        <a class="button" href="/settings">Settings</a>
      </div>
      <section class="settings-note">
        <h2>Search Quality Report</h2>
        <p>This shows which sources are producing strong matches and which are mostly producing skipped jobs.</p>
      </section>
      <div class="table-wrap">
        <table>
          <thead><tr><th>Source</th><th>Total</th><th>Quality</th><th>Quality rate</th><th>Skipped</th><th>Skip rate</th><th>Avg score</th><th>Last seen</th></tr></thead>
          <tbody>{''.join(rows) if rows else '<tr><td colspan="8">No jobs collected yet.</td></tr>'}</tbody>
        </table>
      </div>
    """
    return page("Search Quality", body)


def render_operations() -> str:
    runs = latest_scan_runs(8)
    latest = runs[0] if runs else None
    backup_dir = DATA_DIR / "backups"
    backups = sorted(backup_dir.glob("finance-job-ranker-*.sqlite3"), reverse=True) if backup_dir.exists() else []
    source_rows = source_quality_rows()
    weak_sources = [row for row in source_rows if int(row["total_jobs"] or 0) >= 10 and int(row["skipped_jobs"] or 0) / int(row["total_jobs"] or 1) >= .9]
    status = "Healthy" if latest and latest["status"] == "ok" else "Needs attention"
    latest_backup = backups[0].name if backups else "No backup created yet"
    weak = ", ".join(str(row["source"] or "unknown") for row in weak_sources) or "None"
    run_rows = "".join(
        f"<tr><td>{esc(run['started_at'])}</td><td>{esc(run['reason'])}</td><td>{esc(run['status'])}</td><td>{esc(run['message'])}</td></tr>"
        for run in runs
    )
    body = f"""
      <div class="toolbar"><a class="button" href="/">Dashboard</a><a class="button" href="/sources">Sources</a></div>
      <section class="settings-note"><h2>System Status: {status}</h2>
        <p><strong>Last scan:</strong> {esc(latest['started_at'] if latest else 'Never')} · {esc(latest['status'] if latest else 'unknown')}</p>
        <p><strong>Latest verified backup:</strong> {esc(latest_backup)} · retention: 14 days</p>
        <p><strong>Sources with 90%+ skip rate:</strong> {esc(weak)}</p>
        <p><strong>Authentication:</strong> {'enabled' if os.environ.get('APP_USERNAME') and os.environ.get('APP_PASSWORD') else 'disabled - configure APP_USERNAME and APP_PASSWORD'}</p>
      </section>
      <div class="table-wrap"><table><thead><tr><th>Started</th><th>Reason</th><th>Status</th><th>Message</th></tr></thead><tbody>{run_rows or '<tr><td colspan="4">No scans yet.</td></tr>'}</tbody></table></div>
    """
    return page("Operations", body)


def render_source_editor(index: int | None, source_type: str = "bing_rss") -> str:
    config = load_config()
    sources = config.get("scheduled_search", {}).get("sources", [])
    if index is None:
        source = source_template(source_type)
        title = "Add Source"
        index_value = ""
    else:
        if index < 0 or index >= len(sources):
            return page("Source Not Found", '<p><a href="/sources">Back to sources</a></p><p>Source not found.</p>')
        source = sources[index]
        title = f"Edit Source: {source.get('name', source.get('type', index))}"
        index_value = str(index)
    enabled = source.get("enabled", True)
    source_json = json.dumps(source, indent=2)
    type_links = " ".join(
        f'<a class="button small" href="/source/new?type={esc(source_type_id)}">{esc(label)}</a>'
        for source_type_id, label in [
            ("bing_rss", "Bing / site search"),
            ("priority_job_boards", "Priority boards"),
            ("weworkremotely", "RSS feed"),
            ("greenhouse", "Greenhouse"),
            ("lever", "Lever"),
            ("json", "JSON import"),
            ("csv", "CSV import"),
        ]
    )
    body = f"""
      <div class="toolbar">
        <a class="button" href="/sources">Back to Sources</a>
        <a class="button" href="/settings">Settings</a>
      </div>
      <section class="settings-note">
        <p>Edit the source JSON below. Required fields are <code>name</code>, <code>type</code>, and <code>enabled</code>. This lets you add custom sites, RSS feeds, Greenhouse boards, Lever sites, local CSV/JSON imports, and targeted Bing source searches.</p>
        <p><strong>New source templates:</strong> {type_links}</p>
      </section>
      <form method="post" action="/source/save" class="form wide-form">
        <input type="hidden" name="source_index" value="{esc(index_value)}">
        <label class="checkbox"><input type="checkbox" name="enabled"{checked(enabled)}> Enabled</label>
        <label>Source JSON <textarea name="source_json" rows="24" spellcheck="false">{esc(source_json)}</textarea></label>
        <button type="submit">Save Source</button>
      </form>
    """
    return page(title, body)


def render_resume() -> str:
    config = load_config()
    profile = config.get("resume_profile", {})
    keywords = profile.get("keywords", [])
    keyword_tags = "".join(f"<span>{esc(term)}</span>" for term in keywords[:60])
    text = profile.get("text", "")
    loaded = bool(text)
    generated_queries = resume_search_queries(config)
    query_tags = "".join(f"<span>{esc(query)}</span>" for query in generated_queries)
    body = f"""
      <div class="toolbar">
        <a class="button" href="/">Dashboard</a>
        <a class="button" href="/settings">Settings</a>
      </div>
      <section class="settings-note">
        <h2>Resume Match Profile</h2>
        <p>Status: <strong>{'Loaded' if loaded else 'No resume uploaded'}</strong></p>
        <p>File: <strong>{esc(profile.get('filename') or 'None')}</strong></p>
        <p>Uploaded: <strong>{esc(profile.get('uploaded_at') or 'Never')}</strong></p>
        <p>Resume match can add up to <strong>{esc(profile.get('max_points', 12))}</strong> points when job postings overlap with your uploaded resume keywords.</p>
      </section>
      <section class="settings-note">
        <h2>Upload Resume</h2>
        <form method="post" action="/resume/upload" enctype="multipart/form-data" class="form">
          <label>Resume file <input type="file" name="resume_file" accept=".pdf,.docx,.txt,.md" required></label>
          <button type="submit">Upload And Rescore Jobs</button>
        </form>
        <form method="post" action="/resume/clear" class="inline-form"><button class="danger" type="submit">Clear Resume Profile</button></form>
      </section>
      <h2>Extracted Keywords</h2>
      <p class="tags">{keyword_tags if keyword_tags else '<span>No keywords extracted yet</span>'}</p>
      <h2>Resume-Driven Search Queries</h2>
      <p class="tags">{query_tags if query_tags else '<span>No generated queries yet</span>'}</p>
      <h2>Extracted Resume Text</h2>
      <details class="settings-note" {'open' if loaded else ''}>
        <summary>Review extracted text</summary>
        <pre>{esc(text[:20000]) if text else 'Upload a resume to populate this section.'}</pre>
      </details>
    """
    return page("Resume Profile", body)


def filter_link(name: str, current: str) -> str:
    labels = {
        "active": "Active",
        "new": "New",
        "new_today": "New",
        "best": "Best",
        "apply": "Best",
        "low_priority": "Low Priority",
        "skipped": "Skipped",
        "applied": "Applied",
        "all": "All",
    }
    label = labels.get(name, name.replace("_", " ").title())
    klass = "active" if name == current else ""
    return f'<a class="{klass}" href="/?filter={name}">{label}</a>'


def render_new_form() -> str:
    body = """
    <form method="post" action="/create" class="form">
      <label>Job title <input name="title" required></label>
      <label>Company <input name="company" required></label>
      <label>Location <input name="location" placeholder="Remote, Charlotte, NC, etc."></label>
      <label>Remote / hybrid / onsite <input name="work_arrangement"></label>
      <label>Required office days <input name="office_days"></label>
      <label>Salary range <input name="salary_range" placeholder="$130,000-$155,000 or unknown"></label>
      <label>Direct hire or contract <input name="employment_type" placeholder="Full-time direct hire"></label>
      <label>Internal IT / MSP / consulting / contractor <input name="environment_type" placeholder="Internal enterprise IT"></label>
      <label>Job URL <input name="canonical_url" type="url"></label>
      <label>Date posted <input name="posted_date" type="date"></label>
      <label>Requisition ID <input name="req_id"></label>
      <label>Source <input name="source" value="manual"></label>
      <label class="checkbox"><input type="checkbox" name="fetch_url"> Fetch text from URL if description is blank</label>
      <label>Job description <textarea name="description" rows="18" required></textarea></label>
      <button type="submit">Score and Save</button>
    </form>
    """
    return page("Add Job", body)


def render_job(job: sqlite3.Row) -> str:
    details = json.loads(job["scoring_json"])
    advice = tailoring_advice(job)
    posted = job["posted_date"] or "Unknown"
    body = f"""
      <div class="toolbar">
        <a class="button" href="/">Back to Dashboard</a>
        <form method="post" action="/feedback/{job['id']}/good" class="inline-form"><button type="submit">Good Match</button></form>
        <form method="post" action="/feedback/{job['id']}/bad" class="inline-form"><button type="submit">Bad Match</button></form>
        <form method="post" action="/feedback/{job['id']}/wrong-specialty" class="inline-form"><button type="submit">Wrong Specialty</button></form>
        <form method="post" action="/feedback/{job['id']}/too-junior" class="inline-form"><button type="submit">Too Junior</button></form>
        <form method="post" action="/feedback/{job['id']}/too-developer" class="inline-form"><button type="submit">Too Developer</button></form>
        <form method="post" action="/feedback/{job['id']}/too-support" class="inline-form"><button type="submit">Too Support</button></form>
        <form method="post" action="/feedback/{job['id']}/too-onsite" class="inline-form"><button type="submit">Too Onsite</button></form>
        <form method="post" action="/job/delete/{job['id']}" class="inline-form"><button class="danger" type="submit">Delete Job</button></form>
      </div>
      <section class="detail">
        <div class="hero-score">{job['score']}</div>
        <div>
          <h1>{esc(job['title'])}</h1>
          <p class="meta">{esc(job['company'])} · {esc(job['location'] or 'Unknown')} · {esc(job['work_arrangement'] or 'Unknown')}</p>
          <p class="one">{esc(details.get('one_sentence', ''))}</p>
        </div>
      </section>
      <dl class="facts">
        <dt>Salary range</dt><dd>{esc(job['salary_range'] or 'SALARY UNKNOWN - INVESTIGATE')}</dd>
        <dt>Office days</dt><dd>{esc(job['office_days'] or 'Unknown')}</dd>
        <dt>Employment</dt><dd>{esc(job['employment_type'] or 'Unknown')}</dd>
        <dt>Environment</dt><dd>{esc(job['environment_type'] or 'Unknown')}</dd>
        <dt>Verdict</dt><dd>{esc(job['verdict'])}</dd>
        <dt>Technical fit</dt><dd>{job['technical_fit']}%</dd>
        <dt>Career fit</dt><dd>{job['career_fit']}%</dd>
        <dt>Posted date</dt><dd>{esc(posted)}</dd>
        <dt>Found date</dt><dd>{esc(job['first_seen'][:10])}</dd>
        <dt>Resume match</dt><dd>{esc(details.get('resume_alignment_score', 0))} point(s) from {esc(details.get('resume_filename') or 'uploaded resume')}</dd>
        <dt>Staleness</dt><dd>{esc(staleness_label(job))}</dd>
        <dt>Change</dt><dd>{esc(job['change_summary'] or 'No detected change')}</dd>
        <dt>Watched company</dt><dd>{'Yes' if job['watched_company'] else 'No'}</dd>
        <dt>Location eligibility</dt><dd>{esc((details.get('location_eligibility') or {}).get('reason', 'Unknown'))}</dd>
        <dt>Role family</dt><dd>{esc((details.get('role_family') or {}).get('name', 'Unclassified'))}</dd>
        <dt>Ideal profile hits</dt><dd>{esc(', '.join((details.get('ideal_profile') or {}).get('hits', [])[:20]) or 'None')}</dd>
        <dt>URL</dt><dd>{link(job['canonical_url'])}</dd>
      </dl>
      {section('UPLOADED RESUME OVERLAP', details.get('resume_alignment_hits', []))}
      {section('STRONG MATCHES', details.get('strong_matches', []))}
      {section('REAL GAPS', details.get('real_gaps', []))}
      {section('HARD BLOCKERS', details.get('hard_blockers', []))}
      {category_breakdown(details.get('category_results', []))}
      <h2>COMPENSATION ASSESSMENT</h2><p>{esc(details.get('compensation_assessment', ''))}</p>
      <h2>WORK ARRANGEMENT ASSESSMENT</h2><p>{esc(details.get('work_arrangement_assessment', ''))}</p>
      <h2>WHY THIS WOULD OR WOULD NOT ADVANCE THE CANDIDATE'S CAREER</h2><p>{esc(details.get('career_rationale', ''))}</p>
      <h2>WHY AM I SEEING THIS?</h2>
      <p>{esc(details.get('one_sentence', ''))} {esc('Watched employer boost applied.' if details.get('watched_company') else '')}</p>
      <h2>RESUME TAILORING</h2>
      <div class="split">
        <section>
          <h3>Covered Keywords</h3>
          <p>{esc(', '.join(advice['covered'][:30]) or 'No major keywords captured yet.')}</p>
          <h3>Possible Missing Keywords</h3>
          <p>{esc(', '.join(advice['missing']) or 'No obvious missing priority keywords.')}</p>
        </section>
        <section>
          <h3>Targeted Summary</h3>
          <textarea rows="5" readonly>{esc(advice['summary'])}</textarea>
          <h3>Recruiter Message</h3>
          <textarea rows="6" readonly>{esc(advice['recruiter'])}</textarea>
        </section>
      </div>
      <form method="post" action="/status/{job['id']}" class="form compact">
        <label>Status
          <select name="status">
            {options(['new','reviewed','saved','applied','rejected','ignored'], job['status'])}
          </select>
        </label>
        <label>Pipeline stage
          <select name="pipeline_stage">
            {options(['new','review','saved','apply','applied','recruiter contacted','interview','offer','rejected','ignored'], job['pipeline_stage'])}
          </select>
        </label>
        <label class="checkbox"><input type="checkbox" name="applied" {'checked' if job['applied'] else ''}> Applied</label>
        <label>Applied date <input name="applied_date" type="date" value="{esc(job['applied_date'])}"></label>
        <label>Contact name <input name="contact_name" value="{esc(job['contact_name'])}"></label>
        <label>Contact email <input name="contact_email" type="email" value="{esc(job['contact_email'])}"></label>
        <label>Follow-up date <input name="follow_up_date" type="date" value="{esc(job['follow_up_date'])}"></label>
        <label>Resume version used <input name="resume_version" value="{esc(job['resume_version'])}"></label>
        <label>Rejection category
          <select name="rejection_category">
            {options(['','Wrong specialty','MSP','Too much help desk','Too low salary','Too far / onsite','Too much AWS/Kubernetes/SRE','Contract','Not senior enough','Clearance blocker','Other'], job['rejection_category'])}
          </select>
        </label>
        <label>Candidate notes <textarea name="candidate_notes" rows="4">{esc(job['candidate_notes'])}</textarea></label>
        <label>Rejection reason <textarea name="rejection_reason" rows="3">{esc(job['rejection_reason'])}</textarea></label>
        <button type="submit">Update Status</button>
      </form>
      <details><summary>Original description</summary><pre>{esc(job['description'])}</pre></details>
    """
    return page(f"{job['score']} - {job['title']}", body)


def section(title: str, items: list[str]) -> str:
    lis = "".join(f"<li>{esc(item)}</li>" for item in items) if items else "<li>None found</li>"
    return f"<h2>{esc(title)}</h2><ul>{lis}</ul>"


def category_breakdown(results: list[dict[str, Any]]) -> str:
    if not results:
        return ""
    rows = []
    for result in results:
        hits = ", ".join(result.get("hits", [])[:10]) or "None"
        rows.append(
            f"<tr><td>{esc(result.get('label'))}</td><td>{esc(result.get('points'))}/{esc(result.get('max_points'))}</td><td>{esc(result.get('fit_group'))}</td><td>{esc(hits)}</td></tr>"
        )
    return f"""
      <h2>CATEGORY BREAKDOWN</h2>
      <div class="table-wrap">
        <table>
          <thead><tr><th>Category</th><th>Points</th><th>Group</th><th>Matched Terms</th></tr></thead>
          <tbody>{''.join(rows)}</tbody>
        </table>
      </div>
    """


def options(values: list[str], selected: str) -> str:
    return "".join(f'<option value="{esc(v)}" {"selected" if v == selected else ""}>{esc(v.title())}</option>' for v in values)


def esc(value: Any) -> str:
    return html.escape(str(value or ""))


def link(url: str | None) -> str:
    if not url:
        return "No URL stored"
    return f'<a href="{esc(url)}" target="_blank" rel="noreferrer">{esc(url)}</a>'


def css_verdict(verdict: str) -> str:
    return verdict.lower().replace(" ", "-")


def page(title: str, body: str) -> str:
    try:
        app_cfg = load_config().get("app", {})
    except Exception:
        app_cfg = {}
    app_title = app_cfg.get("title") or "Job Match Command Center"
    app_subtitle = app_cfg.get("subtitle") or "Personal job discovery, resume matching, alerts, and application tracking"
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{esc(title)} · {esc(app_title)}</title>
  <style>
    :root {{ color-scheme: light; --ink:#17212b; --muted:#60717f; --line:#d7dee6; --bg:#f5f7fa; --panel:#fff; --good:#0f766e; --warn:#b45309; --bad:#b91c1c; --blue:#1f5fbf; --nav:#13202b; }}
    * {{ box-sizing: border-box; }}
    body {{ margin:0; font:15px/1.5 system-ui, Segoe UI, Arial, sans-serif; color:var(--ink); background:var(--bg); }}
    header {{ background:var(--nav); color:white; padding:18px clamp(16px, 5vw, 56px); border-bottom:4px solid #2f8f83; }}
    header h1 {{ margin:0; font-size:clamp(24px, 3vw, 34px); letter-spacing:0; }}
    header p {{ margin:3px 0 0; color:#cbd5df; }}
    .topnav {{ display:flex; flex-wrap:wrap; gap:8px; margin-top:14px; }}
    .topnav a {{ color:white; border:1px solid rgba(255,255,255,.22); border-radius:6px; padding:7px 10px; text-decoration:none; font-weight:650; }}
    main {{ max-width:1180px; margin:0 auto; padding:24px clamp(14px, 4vw, 32px) 48px; }}
    a {{ color:var(--blue); }}
    .toolbar, .filters {{ display:flex; flex-wrap:wrap; gap:10px; margin-bottom:16px; align-items:center; }}
    .inline-form {{ display:inline-flex; margin:0; }}
    .button, button, .filters a {{ border:1px solid var(--line); background:var(--panel); color:var(--ink); border-radius:6px; padding:9px 12px; text-decoration:none; cursor:pointer; font-weight:650; }}
    .filters a.active, button {{ background:#1f2937; color:white; border-color:#1f2937; }}
    .button.small, button.small {{ padding:6px 9px; font-size:13px; margin:2px; }}
    button.danger {{ background:#991b1b; border-color:#991b1b; color:white; }}
    .jobs {{ display:grid; gap:12px; }}
    .job {{ display:grid; grid-template-columns:76px 1fr; gap:14px; background:var(--panel); border:1px solid var(--line); border-left:6px solid #8b949e; border-radius:8px; padding:14px; }}
    .job.apply-now {{ border-left-color:var(--good); }}
    .job.strong-apply {{ border-left-color:#16a34a; }}
    .job.review {{ border-left-color:var(--warn); }}
    .job.skip {{ border-left-color:var(--bad); }}
    .score, .hero-score {{ display:grid; place-items:center; width:60px; height:60px; background:#edf2f7; border:1px solid var(--line); border-radius:8px; font-size:24px; font-weight:800; }}
    h2 {{ margin:0 0 5px; font-size:19px; letter-spacing:0; }}
    .meta, .tags {{ color:var(--muted); margin:4px 0; }}
    .tags span {{ display:inline-block; border:1px solid var(--line); border-radius:999px; padding:2px 8px; margin-right:6px; margin-top:4px; background:#fff; }}
    .card-actions {{ display:flex; flex-wrap:wrap; gap:8px; margin:10px 0 0; }}
    .form, .admin-form {{ display:grid; gap:13px; max-width:980px; }}
    .wide-form {{ max-width:1180px; }}
    .grid-2 {{ display:grid; grid-template-columns:repeat(2, minmax(0, 1fr)); gap:13px; }}
    .grid-3 {{ display:grid; grid-template-columns:repeat(3, minmax(0, 1fr)); gap:13px; }}
    .grid-4 {{ display:grid; grid-template-columns:repeat(4, minmax(0, 1fr)); gap:13px; }}
    label {{ display:grid; gap:5px; font-weight:650; }}
    input, textarea, select {{ width:100%; border:1px solid var(--line); border-radius:6px; padding:10px; font:inherit; background:white; }}
    textarea {{ min-height:120px; }}
    .checkbox {{ display:flex; gap:8px; align-items:center; }}
    .checkbox input {{ width:auto; }}
    .detail {{ display:flex; gap:18px; align-items:center; background:white; border:1px solid var(--line); border-radius:8px; padding:18px; }}
    .detail h1 {{ margin:0; font-size:30px; letter-spacing:0; }}
    .one {{ font-size:18px; margin-bottom:0; }}
    .facts {{ display:grid; grid-template-columns:190px 1fr; gap:8px 14px; background:white; border:1px solid var(--line); border-radius:8px; padding:16px; }}
    .split {{ display:grid; grid-template-columns:1fr 1fr; gap:16px; align-items:start; }}
    .split section {{ background:white; border:1px solid var(--line); border-radius:8px; padding:14px; }}
    h3 {{ margin:10px 0 6px; font-size:16px; }}
    dt {{ font-weight:800; }}
    dd {{ margin:0; overflow-wrap:anywhere; }}
    pre {{ white-space:pre-wrap; background:#111827; color:#f9fafb; padding:16px; border-radius:8px; overflow:auto; }}
    code {{ background:#eef2f7; border:1px solid var(--line); border-radius:5px; padding:1px 5px; }}
    .settings-note {{ background:white; border:1px solid var(--line); border-radius:8px; padding:16px; margin-bottom:18px; }}
    .table-wrap {{ overflow:auto; background:white; border:1px solid var(--line); border-radius:8px; margin:10px 0 22px; }}
    table {{ width:100%; border-collapse:collapse; min-width:720px; }}
    th, td {{ padding:10px 12px; border-bottom:1px solid var(--line); text-align:left; vertical-align:top; }}
    th {{ background:#f1f5f9; font-size:13px; text-transform:uppercase; letter-spacing:.04em; }}
    tr:last-child td {{ border-bottom:0; }}
    @media (max-width:700px) {{ .job {{ grid-template-columns:1fr; }} .detail {{ align-items:flex-start; flex-direction:column; }} .facts, .split, .grid-2, .grid-3, .grid-4 {{ grid-template-columns:1fr; }} }}
  </style>
</head>
<body>
  <header>
    <h1>{esc(app_title)}</h1>
    <p>{esc(app_subtitle)}</p>
    <nav class="topnav">
      <a href="/">Dashboard</a>
      <a href="/sources">Sources</a>
      <a href="/quality">Quality</a>
      <a href="/operations">Operations</a>
      <a href="/settings">Settings</a>
      <a href="/resume">Resume</a>
      <a href="/new">Add Job</a>
    </nav>
  </header>
  <main>{body}</main>
</body>
</html>"""


def ensure_config() -> None:
    if not CONFIG_PATH.exists():
        save_config(get_default_config())
        return
    existing = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    merged = merge_dict(get_default_config(), existing)
    changed = existing != merged
    # Existing personalized installations skip first-run setup and retain the
    # legacy optional IT specialty guards. Fresh installations remain neutral.
    if existing.get("candidate_name") and existing.get("job_search", {}).get("queries"):
        if not merged.setdefault("app", {}).get("setup_complete"):
            merged["app"]["setup_complete"] = True
            changed = True
        legacy_ids = {str(item.get("id", "")) for item in existing.get("match_categories", [])}
        if "finance_it" in legacy_ids and "specialty_gap_rules_enabled" not in existing:
            merged["specialty_gap_rules_enabled"] = True
            changed = True
    default_sources = get_default_config()["scheduled_search"]["sources"]
    if not merged.get("scheduled_search", {}).get("sources"):
        merged["scheduled_search"]["sources"] = default_sources
        changed = True
    else:
        existing_source_keys = {
            (str(source.get("type")), str(source.get("name", "")))
            for source in merged["scheduled_search"]["sources"]
        }
        for source in default_sources:
            key = (str(source.get("type")), str(source.get("name", "")))
            if key not in existing_source_keys:
                merged["scheduled_search"]["sources"].append(source)
                existing_source_keys.add(key)
                changed = True
    if not merged.get("job_search", {}).get("queries"):
        merged["job_search"] = get_default_config()["job_search"]
        changed = True
    else:
        existing_queries = {normalize_text(str(query)) for query in merged.get("job_search", {}).get("queries", [])}
        for query in get_default_config()["job_search"]["queries"]:
            if normalize_text(str(query)) not in existing_queries:
                merged["job_search"]["queries"].append(query)
                existing_queries.add(normalize_text(str(query)))
                changed = True
    if "us_only" not in merged.setdefault("job_search", {}):
        merged["job_search"]["us_only"] = True
        changed = True
    if "allow_global_remote" not in merged.setdefault("job_search", {}):
        merged["job_search"]["allow_global_remote"] = False
        changed = True
    existing_penalty_terms = {normalize_text(str(rule.get("term", ""))) for rule in merged.get("penalty_rules", [])}
    for rule in get_default_config().get("penalty_rules", []):
        term_key = normalize_text(str(rule.get("term", "")))
        if term_key and term_key not in existing_penalty_terms:
            merged.setdefault("penalty_rules", []).append(rule)
            existing_penalty_terms.add(term_key)
            changed = True
    existing_category_ids = {str(category.get("id", "")) for category in merged.get("match_categories", [])}
    for category in get_default_config().get("match_categories", []):
        category_id = str(category.get("id", ""))
        if category_id and category_id not in existing_category_ids:
            merged.setdefault("match_categories", []).append(category)
            existing_category_ids.add(category_id)
            changed = True
    watch = merged.setdefault("company_watchlist", {})
    watch.setdefault("companies", [])
    existing_companies = {normalize_text(str(company)) for company in watch.get("companies", [])}
    for company in get_default_config().get("company_watchlist", {}).get("companies", []):
        if normalize_text(str(company)) not in existing_companies:
            watch["companies"].append(company)
            existing_companies.add(normalize_text(str(company)))
            changed = True
    ideal = merged.setdefault("ideal_job", {})
    default_ideal = get_default_config().get("ideal_job", {})
    for key in ["desired_terms", "must_have_any", "strong_titles", "dealbreakers", "target_companies"]:
        ideal.setdefault(key, [])
        existing_values = {normalize_text(str(value)) for value in ideal.get(key, [])}
        for value in default_ideal.get(key, []):
            if normalize_text(str(value)) not in existing_values:
                ideal[key].append(value)
                existing_values.add(normalize_text(str(value)))
                changed = True
    if changed:
        save_config(merged)


def run_server(host: str, port: int) -> None:
    ensure_config()
    init_db()
    server = ThreadingHTTPServer((host, port), Handler)
    print(f"Job Match Command Center running at http://{host}:{port}")
    server.serve_forever()


def run_scheduler(interval_seconds: int = 60) -> None:
    config = load_config()
    seen: set[str] = set()
    last_interval_run: dt.datetime | None = None
    print("Scheduler running. Automated imports are enabled when scheduled_search.enabled is true.")
    if config.get("scheduled_search", {}).get("enabled", True) and config.get("scheduled_search", {}).get("run_on_startup", True):
        print("\n".join(run_scheduled_scan("startup")))
        last_interval_run = dt.datetime.now()
    while True:
        config = load_config()
        if not config.get("scheduled_search", {}).get("enabled", True):
            time.sleep(interval_seconds)
            continue
        now = dt.datetime.now().strftime("%H:%M")
        if now in config["scheduled_search"].get("run_times", []) and now not in seen:
            print("\n".join(run_scheduled_scan(f"scheduled time {now}")))
            seen.add(now)
            last_interval_run = dt.datetime.now()
        interval_minutes = int(config.get("scheduled_search", {}).get("interval_minutes", 0) or 0)
        if interval_minutes > 0:
            current = dt.datetime.now()
            if last_interval_run is None or (current - last_interval_run).total_seconds() >= interval_minutes * 60:
                print("\n".join(run_scheduled_scan(f"interval {interval_minutes} minutes")))
                last_interval_run = current
        if now == "00:00":
            seen.clear()
        time.sleep(interval_seconds)


def run_scheduled_scan(reason: str) -> list[str]:
    if not acquire_scan_lock():
        return [f"{utcnow()} scan skipped: another scan is already running."]
    config = load_config()
    scan_run_id = start_scan_run(reason)
    messages = [f"{utcnow()} scan start: {reason}"]
    try:
        messages.extend(run_source_watchers(scan_run_id=scan_run_id, lock_already_held=True))
        messages.extend(rescore_all())
        messages.extend(send_apply_now_alerts(dry_run=not config["email"].get("enabled")))
        if config.get("digest", {}).get("enabled", True):
            messages.extend(send_digest(dry_run=not config["email"].get("enabled")))
        messages.append(maybe_daily_backup())
        messages.append(f"{utcnow()} scan complete: {reason}")
        finish_scan_run(scan_run_id, "ok", "\n".join(messages[-5:]))
    except Exception as exc:
        messages.append(f"{utcnow()} scan failed: {exc}")
        finish_scan_run(scan_run_id, "failed", str(exc))
    finally:
        release_scan_lock()
    return messages


def import_json(path: Path) -> list[str]:
    items = json.loads(path.read_text(encoding="utf-8"))
    messages = []
    for item in items:
        job_id, created = insert_or_update_job({k: str(v) for k, v in item.items()})
        action = "created" if created else "updated"
        messages.append(f"{action} job {job_id}: {item.get('title', 'Untitled')} - {item.get('company', 'Unknown')}")
    return messages


def import_csv(path: Path) -> list[str]:
    messages = []
    with path.open(newline="", encoding="utf-8-sig") as stream:
        for row in csv.DictReader(stream):
            cleaned = {k: str(v or "") for k, v in row.items() if k}
            if not cleaned.get("title") or not cleaned.get("company"):
                messages.append("skipped row without title/company")
                continue
            if not cleaned.get("description"):
                cleaned["description"] = " ".join(str(v or "") for v in row.values())
            job_id, created = insert_or_update_job(cleaned)
            action = "created" if created else "updated"
            messages.append(f"{action} job {job_id}: {cleaned.get('title')} - {cleaned.get('company')}")
    return messages or ["No rows imported."]


def run_source_watchers(scan_run_id: int | None = None, lock_already_held: bool = False) -> list[str]:
    acquired_lock = False
    if not lock_already_held:
        if not acquire_scan_lock():
            return [f"{utcnow()} source scan skipped: another scan is already running."]
        acquired_lock = True
    config = load_config()
    own_scan = False
    try:
        if scan_run_id is None:
            scan_run_id = start_scan_run("manual source run")
            own_scan = True
        messages = []
        for source in config.get("scheduled_search", {}).get("sources", []):
            if not source.get("enabled", True):
                record_scan_source(scan_run_id, source, 0, 0, 0, "disabled", "Source disabled")
                continue
            source_type = source.get("type")
            path = source.get("path")
            source_name = source.get("name") or source_type or "source"
            try:
                if source_type == "json" and path:
                    messages.extend(import_json(Path(path)))
                    record_scan_source(scan_run_id, source, 0, 0, 0, "ok", "Imported JSON file")
                elif source_type == "csv" and path:
                    messages.extend(import_csv(Path(path)))
                    record_scan_source(scan_run_id, source, 0, 0, 0, "ok", "Imported CSV file")
                elif source_type == "url_list":
                    fetched_count = 0
                    for url in source.get("urls", []):
                        text = fetch_url_text(str(url))
                        fetched_count += 1
                        messages.append(f"fetched URL source {url}: {len(text)} characters; paste/import parser still needs title/company mapping")
                    record_scan_source(scan_run_id, source, fetched_count, 0, 0)
                elif source_type in SOURCE_FETCHERS:
                    fetched = SOURCE_FETCHERS[str(source_type)](source, config)
                    created = 0
                    updated = 0
                    filtered = 0
                    for item in fetched:
                        if not item.get("title") or not item.get("company") or not item.get("description"):
                            continue
                        keep, _reason = imported_job_passes_search_tuning(item, config)
                        if not keep:
                            filtered += 1
                            continue
                        _, was_created = insert_or_update_job({k: str(v or "") for k, v in item.items()})
                        created += 1 if was_created else 0
                        updated += 0 if was_created else 1
                    suffix = f", filtered {filtered}" if filtered else ""
                    messages.append(f"{source_name}: fetched {len(fetched)}, created {created}, updated {updated}{suffix}")
                    record_scan_source(scan_run_id, source, len(fetched), created, updated, "ok", f"Filtered {filtered} before import" if filtered else "")
                else:
                    messages.append(f"skipped unsupported source: {source}")
                    record_scan_source(scan_run_id, source, 0, 0, 0, "skipped", "Unsupported source type")
            except Exception as exc:
                messages.append(f"{source_name}: failed - {exc}")
                record_scan_source(scan_run_id, source, 0, 0, 0, "failed", str(exc))
        if own_scan:
            finish_scan_run(scan_run_id, "ok", "\n".join(messages[-5:]))
        return messages or ["No enabled sources configured."]
    finally:
        if acquired_lock:
            release_scan_lock()


def rescore_all() -> list[str]:
    init_db()
    messages = []
    with db() as con:
        jobs = con.execute("select * from jobs").fetchall()
    for job in jobs:
        form = {key: str(job[key] or "") for key in job.keys() if key in {
            "canonical_url",
            "req_id",
            "title",
            "company",
            "location",
            "work_arrangement",
            "office_days",
            "salary_range",
            "employment_type",
            "environment_type",
            "source",
            "description",
        }}
        scored = score_job(form, load_config())
        desc_hash = text_hash(form.get("description", ""))
        watched = 1 if scored["details"].get("watched_company") else 0
        with db() as con:
            con.execute(
                """
                update jobs set score = ?, verdict = ?, technical_fit = ?, career_fit = ?,
                    scoring_json = ?, description_hash = ?, watched_company = ?, last_seen = last_seen
                where id = ?
                """,
                (
                    scored["score"],
                    scored["verdict"],
                    scored["technical_fit"],
                    scored["career_fit"],
                    json.dumps(scored["details"], indent=2),
                    desc_hash,
                    watched,
                    job["id"],
                ),
            )
        messages.append(f"rescored job {job['id']}: {scored['score']} {scored['verdict']} - {job['title']}")
    return messages or ["No jobs to rescore."]


def main() -> None:
    parser = argparse.ArgumentParser(description="Self-hosted job discovery and resume matching")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8088)
    parser.add_argument("--init-db", action="store_true")
    parser.add_argument("--send-alerts", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--scheduler", action="store_true")
    parser.add_argument("--import-json", type=Path)
    parser.add_argument("--import-csv", type=Path)
    parser.add_argument("--rescore", action="store_true")
    parser.add_argument("--send-digest", action="store_true")
    parser.add_argument("--run-sources", action="store_true")
    args = parser.parse_args()
    ensure_config()
    init_db()
    if args.init_db:
        print(f"Initialized {DB_PATH}")
    elif args.import_json:
        print("\n".join(import_json(args.import_json)))
    elif args.import_csv:
        print("\n".join(import_csv(args.import_csv)))
    elif args.rescore:
        print("\n".join(rescore_all()))
    elif args.run_sources:
        print("\n".join(run_source_watchers()))
    elif args.send_alerts:
        print("\n\n".join(send_apply_now_alerts(dry_run=args.dry_run)))
    elif args.send_digest:
        print("\n\n".join(send_digest(dry_run=args.dry_run)))
    elif args.scheduler:
        run_scheduler()
    else:
        run_server(args.host, args.port)


if __name__ == "__main__":
    main()
