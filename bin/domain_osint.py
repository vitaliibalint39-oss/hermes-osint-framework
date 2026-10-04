#!/usr/bin/env python3
"""Domain OSINT Investigation runner v1.3.7.

Passive/public-source collection runner for the Domain OSINT Investigation skill.
Collectors produce normalized evidence and preserve raw responses. The runner does
not perform attribution and does not actively scan targets.
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import ipaddress
import json
import os
import re
import shutil
import shlex
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

VERSION = "1.3.9"
UA = f"domain-osint-skill/{VERSION} passive-research"
DNS_TYPES = ("A", "AAAA", "NS", "MX", "TXT", "CNAME", "SOA", "CAA")


def runner_identity() -> Dict[str, Any]:
    path = Path(__file__).resolve()
    skill_root = path.parent.parent
    canonical_layout = (
        path.name == "domain_osint.py"
        and path.parent.name == "bin"
        and (skill_root / "SKILL.md").is_file()
        and (skill_root / "modules" / "domain" / "SKILL.md").is_file()
    )
    try:
        digest = sha256_file(path)
    except Exception:
        digest = "unavailable"
    return {
        "runner_path": str(path),
        "runner_sha256": digest,
        "execution_mode": "canonical_runner" if canonical_layout else "noncanonical_copy",
        "canonical_layout": canonical_layout,
    }


CREDENTIAL_KEYS = {
    "NETLAS_API_KEY",
    "CENSYS_PAT",
    "URLSCAN_API_KEY",
    "VT_API_KEY",
    "SHODAN_API_KEY",
    "HUNT_API_KEY",
    "HUNT_IO_TOKEN",
    "GREYNOISE_API_KEY",
}
CREDENTIAL_ORIGINS: Dict[str, str] = {}


def _parse_shell_assignment_value(raw: str) -> Optional[str]:
    """Parse a simple shell assignment RHS without executing shell code."""
    raw = raw.strip().rstrip("\r")
    if not raw:
        return ""
    try:
        parts = shlex.split(raw, comments=True, posix=True)
    except ValueError:
        return None
    if len(parts) != 1:
        return None
    return parts[0]


def load_credentials_file(path: Path, *, require_private_permissions: bool = True) -> Dict[str, str]:
    """Load whitelisted API credentials from a local shell-style file.

    This never executes the file. Existing environment variables take precedence.
    Secret values are never returned in logs or reports; the return value maps key
    names to a non-secret origin label only.
    """
    origins: Dict[str, str] = {}
    if not path.exists():
        return origins
    try:
        mode = path.stat().st_mode & 0o777
    except OSError:
        return origins
    if require_private_permissions and (mode & 0o077):
        print(f"[!] Credential file permissions are too broad ({oct(mode)}): {path}", file=sys.stderr)
        print("[!] Run: chmod 600 ~/.osint_keys", file=sys.stderr)
        return origins
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        print(f"[!] Could not read credential file {path}: {exc}", file=sys.stderr)
        return origins
    pattern = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$")
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        m = pattern.match(line)
        if not m:
            continue
        key, rhs = m.group(1), m.group(2)
        if key not in CREDENTIAL_KEYS:
            continue
        if os.environ.get(key):
            origins[key] = "environment"
            continue
        value = _parse_shell_assignment_value(rhs)
        if value is None or value == "":
            continue
        os.environ[key] = value
        origins[key] = str(path)
    return origins


def credential_origin(key: str) -> str:
    if not key:
        return "n/a"
    if key in CREDENTIAL_ORIGINS:
        origin = CREDENTIAL_ORIGINS[key]
        return "environment" if origin == "environment" else "credentials_file"
    return "environment" if os.environ.get(key) else "absent"


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def safe_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", value)[:180]


def normalize_domain(domain: str) -> str:
    value = domain.strip().rstrip(".").lower()
    if "://" in value:
        value = urllib.parse.urlsplit(value).hostname or value
    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError(f"Invalid internationalized domain: {exc}")
    if not re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", value):
        raise ValueError("Target must be a valid DNS domain name, e.g. example.com")
    return value


def json_dump(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")


def text_dump(path: Path, data: str) -> None:
    path.write_text(data, encoding="utf-8", errors="replace")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def http_get(url: str, headers: Optional[Dict[str, str]] = None, timeout: int = 30) -> Tuple[int, bytes, Dict[str, str]]:
    hdrs = {"User-Agent": UA, "Accept": "application/json, text/plain;q=0.9, */*;q=0.8"}
    if headers:
        for key, value in headers.items():
            # urllib rejects CR/LF in header values. Credential files copied from
            # Windows or editors can accidentally retain them, so normalize here
            # without ever logging the secret value.
            clean_key = str(key).strip()
            clean_value = str(value).replace("\r", "").replace("\n", "").strip()
            if clean_key and clean_value:
                hdrs[clean_key] = clean_value
    req = urllib.request.Request(url, headers=hdrs, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read(), dict(resp.headers.items())
    except urllib.error.HTTPError as exc:
        body = exc.read() if exc.fp else b""
        return exc.code, body, dict(exc.headers.items()) if exc.headers else {}


def parse_json_bytes(body: bytes) -> Any:
    return json.loads(body.decode("utf-8", errors="replace"))


def command_exists(name: str) -> bool:
    return shutil.which(name) is not None


def run_cmd(args: List[str], timeout: int = 90) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)


def run_adapter_safely(case: "Case", adapter: str, func, *args, default=None):
    """Run one collector without allowing a single-source failure to abort the case.

    Unexpected adapter exceptions become ERROR status records. KeyboardInterrupt is
    re-raised so the user can stop the run; main() still persists the partial case.
    """
    try:
        return func(*args)
    except KeyboardInterrupt:
        raise
    except Exception as exc:
        case.metrics["adapter_failure_count"] = int(case.metrics.get("adapter_failure_count", 0)) + 1
        case.flags["partial_run"] = True
        case.add_status(adapter, "ERROR", case.domain, f"Unhandled adapter exception isolated: {type(exc).__name__}: {exc}")
        print(f"[!] {adapter}: isolated failure ({type(exc).__name__}); continuing", file=sys.stderr)
        return default


class Case:
    def __init__(self, domain: str, objective: str, scope: str, case_id: str, root: Path):
        self.domain = domain
        self.objective = objective
        self.scope = scope
        self.case_id = case_id
        self.root = root
        self.raw = root / "raw"
        self.screens = root / "screenshots"
        self.raw.mkdir(parents=True, exist_ok=True)
        self.screens.mkdir(parents=True, exist_ok=True)
        self.evidence: List[Dict[str, Any]] = []
        self.statuses: List[Dict[str, str]] = []
        self.flags: Dict[str, Any] = {}
        self.metrics: Dict[str, Any] = {"adapter_failure_count": 0}
        self.sources: Dict[str, Dict[str, Any]] = {}
        self.start = utc_now()
        self.counter = 0
        self.runner_meta = runner_identity()

    def add_status(self, adapter: str, status: str, query: str, notes: str = "") -> None:
        self.statuses.append({
            "adapter": adapter,
            "status": status,
            "query": query,
            "collected_utc": utc_now(),
            "notes": notes,
        })
        src_name = source_from_adapter(adapter)
        if src_name in self.sources:
            used = status in {"OK", "PARTIAL", "NO_RESULT", "RATE_LIMITED", "LIMITED"}
            self.update_source(src_name, status, used=used, notes=notes)

    def register_source(self, name: str, *, access: str, credential_env: str = "",
                        configured: bool = True, limitation: str = "") -> None:
        self.sources[name] = {
            "access": access,
            "credential_env": credential_env,
            "configured": bool(configured),
            "credential_present": bool(os.environ.get(credential_env)) if credential_env else None,
            "credential_source": credential_origin(credential_env) if credential_env else "n/a",
            "runtime_status": "NOT_RUN",
            "used": False,
            "limitation": limitation,
            "notes": "",
        }

    def update_source(self, name: str, runtime_status: str, *, used: bool = False,
                      limitation: Optional[str] = None, notes: str = "") -> None:
        src = self.sources.setdefault(name, {
            "access": "unknown", "credential_env": "", "configured": False,
            "credential_present": None, "credential_source": "n/a", "runtime_status": "NOT_RUN", "used": False,
            "limitation": "", "notes": ""})
        src["runtime_status"] = runtime_status
        src["used"] = bool(used)
        if limitation is not None:
            src["limitation"] = limitation
        if notes:
            src["notes"] = notes

    def add_evidence(self, *, adapter: str, source_name: str, source_url: str, query: str,
                     artifact_type: str, artifact: str, relationship: str, observation: str,
                     raw_ref: str, confidence: str = "low", notes: str = "",
                     observed_utc: Optional[str] = None, signal_strength: Optional[str] = None) -> Dict[str, Any]:
        self.counter += 1
        if signal_strength is None:
            signal_strength = default_signal_strength(relationship, artifact_type)
        rec = {
            "evidence_id": f"{self.case_id}-E{self.counter:04d}",
            "case_id": self.case_id,
            "source_adapter": adapter,
            "source_name": source_name,
            "source_url": source_url,
            "query": query,
            "collected_utc": utc_now(),
            "observed_utc": observed_utc,
            "artifact_type": artifact_type,
            "artifact": artifact,
            "relationship": relationship,
            "observation": observation,
            "raw_ref": raw_ref,
            "confidence": confidence,
            "signal_strength": signal_strength,
            "notes": notes,
        }
        self.evidence.append(rec)
        return rec

    def save(self) -> None:
        with (self.root / "evidence.jsonl").open("w", encoding="utf-8") as f:
            for rec in self.evidence:
                f.write(json.dumps(rec, ensure_ascii=False, sort_keys=True) + "\n")
        end = utc_now()
        # Simple YAML that requires no external dependency.
        case_yaml = [
            f'case_id: {json.dumps(self.case_id)}',
            f'target_domain: {json.dumps(self.domain)}',
            f'objective: {json.dumps(self.objective)}',
            f'scope: {json.dumps(self.scope)}',
            f'start_utc: {json.dumps(self.start)}',
            f'end_utc: {json.dumps(end)}',
            f'runner_version: {json.dumps(VERSION)}',
            f'runner_path: {json.dumps(self.runner_meta.get("runner_path"))}',
            f'runner_sha256: {json.dumps(self.runner_meta.get("runner_sha256"))}',
            f'execution_mode: {json.dumps(self.runner_meta.get("execution_mode"))}',
            f'canonical_layout: {json.dumps(self.runner_meta.get("canonical_layout"))}',
            'flags:',
        ]
        for key, value in sorted(self.flags.items()):
            case_yaml.append(f'  {key}: {json.dumps(value)}')
        case_yaml += [
            'metrics:',
        ]
        for key, value in sorted(self.metrics.items()):
            case_yaml.append(f'  {key}: {json.dumps(value)}')
        case_yaml += [
            'source_capabilities:',
        ]
        for name, src in sorted(self.sources.items()):
            case_yaml += [
                f'  {name}:',
                f'    access: {json.dumps(src.get("access"))}',
                f'    credential_env: {json.dumps(src.get("credential_env"))}',
                f'    credential_present: {json.dumps(src.get("credential_present"))}',
                f'    credential_source: {json.dumps(src.get("credential_source"))}',
                f'    configured: {json.dumps(src.get("configured"))}',
                f'    runtime_status: {json.dumps(src.get("runtime_status"))}',
                f'    used: {json.dumps(src.get("used"))}',
                f'    limitation: {json.dumps(src.get("limitation"))}',
                f'    notes: {json.dumps(src.get("notes"))}',
            ]
        case_yaml += [
            'adapter_status:',
        ]
        for s in self.statuses:
            case_yaml += [
                f'  - adapter: {json.dumps(s["adapter"])}',
                f'    status: {json.dumps(s["status"])}',
                f'    query: {json.dumps(s["query"])}',
                f'    collected_utc: {json.dumps(s["collected_utc"])}',
                f'    notes: {json.dumps(s["notes"])}',
            ]
        text_dump(self.root / "case.yaml", "\n".join(case_yaml) + "\n")
        findings = {
            "case_id": self.case_id,
            "automated_attribution": False,
            "note": "The runner collects and normalizes evidence. Material attribution findings require analyst corroboration.",
            "candidate_relationships": build_candidate_relationships(self.evidence, self.domain),
        }
        # YAML-compatible JSON is intentional and machine-readable.
        text_dump(self.root / "findings.yaml", json.dumps(findings, indent=2, ensure_ascii=False) + "\n")
        text_dump(self.root / "graph.mmd", build_mermaid_graph(self.evidence, self.domain))
        text_dump(self.root / "report.md", build_report(self, end))



def initialize_source_capabilities(case: Case) -> None:
    case.register_source("rdap", access="PUBLIC", limitation="Coverage depends on TLD registry bootstrap; registry WHOIS fallback may be used.")
    case.register_source("whois", access="LOCAL_PUBLIC", configured=command_exists("whois"), limitation="Registry formats vary; conservative parsing only.")
    case.register_source("dns", access="PUBLIC", configured=True, limitation="Current DNS snapshot; historical DNS requires enrichment sources.")
    case.register_source("crtsh", access="PUBLIC", limitation="Certificate Transparency is historical issuance data, not proof a service is currently active.")
    case.register_source("live_tls", access="DIRECT_PUBLIC", limitation="Normal client TLS validation only; bounded hostname set.")
    case.register_source("wayback", access="PUBLIC", limitation="Archive coverage is incomplete and robots/exclusions may affect availability.")
    case.register_source("urlscan", access="AUTHENTICATED" if os.environ.get("URLSCAN_API_KEY") else "PUBLIC_LIMITED", credential_env="URLSCAN_API_KEY", configured=True, limitation="Unauthenticated mode has lower quotas; scans are historical and may be user-submitted.")
    case.register_source("netlas", access="AUTHENTICATED", credential_env="NETLAS_API_KEY", configured=bool(os.environ.get("NETLAS_API_KEY")), limitation="Free/community plans have request/result limits; available fields vary by plan.")
    case.register_source("virustotal", access="AUTHENTICATED", credential_env="VT_API_KEY", configured=bool(os.environ.get("VT_API_KEY")), limitation="Community API is rate-limited and some relationships require higher tiers. last_analysis_stats is vendor-engine context; undetected does not mean benign and engine verdicts are not independent corroboration.")
    case.register_source("censys", access="AUTHENTICATED", credential_env="CENSYS_PAT", configured=bool(os.environ.get("CENSYS_PAT")), limitation="Free tier supports selected asset lookups; search/history fields may require paid access and consume credits.")
    case.register_source("shodan", access="AUTHENTICATED_LOCAL_CLI", credential_env="SHODAN_API_KEY", configured=command_exists("shodan"), limitation="Plan/credit restrictions apply; shared CDN edge IP enrichment may be deliberately suppressed.")
    case.register_source("robtex", access="PUBLIC_LIMITED", configured=True, limitation="Free API is rate limited (10 requests/hour/IP per current public documentation); passive DNS is historical third-party observation.")
    case.register_source("sherlock", access="LOCAL_PUBLIC", configured=command_exists("sherlock"), limitation="Username reuse is a lead only and never establishes identity by itself.")
    hunt_env = "HUNT_API_KEY" if os.environ.get("HUNT_API_KEY") else "HUNT_IO_TOKEN"
    case.register_source("huntio", access="AUTHENTICATED_OPTIONAL", credential_env=hunt_env, configured=bool(os.environ.get("HUNT_API_KEY") or os.environ.get("HUNT_IO_TOKEN")), limitation="Optional commercial source; methodology must remain functional when unavailable.")

def source_from_adapter(adapter: str) -> str:
    return {"dig":"dns","whois-fallback":"whois","whois":"whois","live-tls":"live_tls"}.get(adapter, adapter)


def default_signal_strength(relationship: str, artifact_type: str) -> str:
    rel = (relationship or "").lower()
    if rel in {"resolves_to", "shodan_host_observation", "hunt_observed_ip"}:
        return "weak"
    if "nameserver" in rel or "mail_exchanger" in rel or "certificate" in rel or "cname" in rel:
        return "moderate"
    if "rdap" in rel or "domain_status" in rel:
        return "strong"
    if artifact_type in {"username", "url"}:
        return "weak"
    return "moderate"

def build_mermaid_graph(evidence: List[Dict[str, Any]], domain: str) -> str:
    def nid(value: str) -> str:
        return "N" + hashlib.sha1(value.encode("utf-8", errors="ignore")).hexdigest()[:10]
    lines = ["graph LR", f'  {nid(domain)}["{domain}"]']
    seen = set()
    for rec in evidence:
        artifact = str(rec.get("artifact") or "").strip()
        if not artifact or artifact == domain:
            continue
        relationship = str(rec.get("relationship") or "observed_with")
        key = (artifact, relationship)
        if key in seen:
            continue
        seen.add(key)
        label = artifact.replace('"', "'")[:80]
        edge = relationship.replace('"', "'")[:50]
        lines.append(f'  {nid(artifact)}["{label}"]')
        lines.append(f'  {nid(domain)} -- "{edge}" --> {nid(artifact)}')
        if len(seen) >= 120:
            break
    return "\n".join(lines) + "\n"

def classify_http_status(code: int) -> str:
    if 200 <= code < 300:
        return "OK"
    if code == 404:
        return "NO_RESULT"
    if code == 429:
        return "RATE_LIMITED"
    if code in (401, 403):
        return "UNAVAILABLE"
    return "ERROR"


def rdap_endpoint(domain: str, raw_dir: Path) -> Tuple[Optional[str], str]:
    bootstrap_url = "https://data.iana.org/rdap/dns.json"
    code, body, _ = http_get(bootstrap_url)
    path = raw_dir / "iana-rdap-dns-bootstrap.json"
    path.write_bytes(body)
    if code != 200:
        return None, f"IANA bootstrap HTTP {code}"
    try:
        data = parse_json_bytes(body)
        labels = domain.split(".")
        tld = labels[-1]
        matches = []
        for service in data.get("services", []):
            suffixes, urls = service
            if tld in [s.lower() for s in suffixes]:
                matches.extend(urls)
        if not matches:
            return None, f"No RDAP service found for .{tld}"
        return matches[0].rstrip("/") + "/domain/" + urllib.parse.quote(domain), ""
    except Exception as exc:
        return None, f"RDAP bootstrap parse error: {exc}"


def collect_registry_whois(case: Case, reason: str = "") -> None:
    """Fallback to registry WHOIS when no authoritative RDAP service is bootstrapped.

    The local `whois` client follows registry referrals for ccTLDs such as .lv.
    WHOIS output is preserved as raw evidence; the runner intentionally avoids
    aggressive parsing because registry formats differ significantly.
    """
    if not command_exists("whois"):
        case.add_status("whois-fallback", "UNAVAILABLE", case.domain,
                        f"RDAP unavailable ({reason}); local whois client not installed")
        return
    try:
        cp = run_cmd(["whois", case.domain], timeout=60)
    except Exception as exc:
        case.add_status("whois-fallback", "UNAVAILABLE", case.domain,
                        f"RDAP unavailable ({reason}); whois execution failed: {exc}")
        return
    raw_path = case.raw / f"whois-{safe_name(case.domain)}.txt"
    text_dump(raw_path, cp.stdout + ("\n# STDERR\n" + cp.stderr if cp.stderr else ""))
    if cp.returncode != 0 or not cp.stdout.strip():
        case.add_status("whois-fallback", "ERROR", case.domain,
                        f"RDAP unavailable ({reason}); whois exited {cp.returncode}")
        return
    rel = str(raw_path.relative_to(case.root))
    # Extract only conservative, common fields while preserving the full raw record.
    patterns = {
        "registrar": r"(?im)^\s*(?:registrar|registrar name)\s*:\s*(.+?)\s*$",
        "created": r"(?im)^\s*(?:created|creation date|registered)\s*:\s*(.+?)\s*$",
        "updated": r"(?im)^\s*(?:updated|last updated|modified)\s*:\s*(.+?)\s*$",
        "status": r"(?im)^\s*(?:status|domain status)\s*:\s*(.+?)\s*$",
    }
    found = 0
    for field, pattern in patterns.items():
        for m in re.finditer(pattern, cp.stdout):
            value = m.group(1).strip()
            if not value:
                continue
            found += 1
            case.add_evidence(adapter="whois", source_name="Registry WHOIS via local referral-aware client", source_url="",
                              query=case.domain, artifact_type="domain", artifact=case.domain,
                              relationship=f"whois_{field}", observation=f"WHOIS {field}: {value}",
                              raw_ref=rel, confidence="medium",
                              notes="Registry-specific WHOIS fallback; full record preserved in raw/ and should be reviewed manually")
    # Nameserver fields are common enough to normalize carefully.
    for m in re.finditer(r"(?im)^\s*(?:name server|nameserver|nserver)\s*:\s*([^\s]+)", cp.stdout):
        ns = m.group(1).strip().lower().rstrip('.')
        if ns:
            found += 1
            case.add_evidence(adapter="whois", source_name="Registry WHOIS via local referral-aware client", source_url="",
                              query=case.domain, artifact_type="dns", artifact=ns, relationship="registered_nameserver",
                              observation=f"WHOIS lists nameserver {ns}", raw_ref=rel, confidence="medium")
    case.add_status("whois-fallback", "OK", case.domain,
                    f"RDAP unavailable ({reason}); registry WHOIS fallback succeeded; normalized {found} conservative field(s)")


def collect_rdap(case: Case) -> None:
    url, err = rdap_endpoint(case.domain, case.raw)
    if not url:
        case.add_status("rdap", "UNAVAILABLE", case.domain, err)
        collect_registry_whois(case, err)
        return
    code, body, _ = http_get(url)
    raw_path = case.raw / f"rdap-{safe_name(case.domain)}.json"
    raw_path.write_bytes(body)
    status = classify_http_status(code)
    if status != "OK":
        case.add_status("rdap", status, case.domain, f"HTTP {code}")
        # A failed authoritative RDAP lookup may still be recoverable through WHOIS.
        collect_registry_whois(case, f"RDAP HTTP {code}")
        return
    try:
        data = parse_json_bytes(body)
    except Exception as exc:
        case.add_status("rdap", "ERROR", case.domain, f"Invalid JSON: {exc}")
        collect_registry_whois(case, "RDAP returned invalid JSON")
        return
    rel = str(raw_path.relative_to(case.root))
    handle = data.get("handle")
    if handle:
        case.add_evidence(adapter="rdap", source_name="Authoritative RDAP service", source_url=url, query=case.domain,
                          artifact_type="domain", artifact=case.domain, relationship="rdap_handle",
                          observation=f"RDAP handle: {handle}", raw_ref=rel, confidence="high")
    for event in data.get("events", []) or []:
        action, date = event.get("eventAction"), event.get("eventDate")
        if action and date:
            case.add_evidence(adapter="rdap", source_name="Authoritative RDAP service", source_url=url, query=case.domain,
                              artifact_type="domain", artifact=case.domain, relationship=f"rdap_event:{action}",
                              observation=f"RDAP event {action}: {date}", raw_ref=rel, confidence="high", observed_utc=date)
    for ns in data.get("nameservers", []) or []:
        name = (ns.get("ldhName") or ns.get("unicodeName") or "").lower().rstrip(".")
        if name:
            case.add_evidence(adapter="rdap", source_name="Authoritative RDAP service", source_url=url, query=case.domain,
                              artifact_type="dns", artifact=name, relationship="registered_nameserver",
                              observation=f"RDAP lists nameserver {name}", raw_ref=rel, confidence="high")
    for status_value in data.get("status", []) or []:
        case.add_evidence(adapter="rdap", source_name="Authoritative RDAP service", source_url=url, query=case.domain,
                          artifact_type="domain", artifact=case.domain, relationship="domain_status",
                          observation=f"RDAP status: {status_value}", raw_ref=rel, confidence="high")
    case.add_status("rdap", "OK", case.domain, f"Authoritative endpoint: {url}")

def parse_dig_answer(line: str) -> Optional[Tuple[str, str, str, str]]:
    if not line or line.startswith(";"):
        return None
    parts = line.split()
    if len(parts) < 5:
        return None
    name, ttl, _klass, rtype = parts[:4]
    value = " ".join(parts[4:]).strip()
    return name.rstrip("."), ttl, rtype.upper(), value


def collect_dns(case: Case) -> List[str]:
    ips: List[str] = []
    if not command_exists("dig"):
        # Minimal A/AAAA fallback; still remain passive.
        raw_path = case.raw / f"dns-socket-{safe_name(case.domain)}.txt"
        try:
            rows = socket.getaddrinfo(case.domain, None)
            unique = sorted({r[4][0] for r in rows})
            text_dump(raw_path, "\n".join(unique) + "\n")
            for ip in unique:
                typ = "AAAA" if ":" in ip else "A"
                ips.append(ip)
                case.add_evidence(adapter="dig", source_name="System DNS resolver", source_url="", query=f"{case.domain} {typ}",
                                  artifact_type="ip", artifact=ip, relationship="resolves_to",
                                  observation=f"{case.domain} resolved to {ip} via the system resolver", raw_ref=str(raw_path.relative_to(case.root)), confidence="high",
                                  notes="dig unavailable; fallback does not collect NS/MX/TXT/CNAME/SOA/CAA")
            case.add_status("dig", "OK", case.domain, "dig unavailable; collected A/AAAA using system resolver only")
            return ips
        except Exception as exc:
            case.add_status("dig", "ERROR", case.domain, f"dig unavailable and resolver failed: {exc}")
            return ips
    all_out = []
    any_answer = False
    for rtype in DNS_TYPES:
        cp = run_cmd(["dig", case.domain, rtype, "+noall", "+answer"], timeout=30)
        all_out.append(f"### {rtype}\n{cp.stdout}{cp.stderr}\n")
        for line in cp.stdout.splitlines():
            parsed = parse_dig_answer(line)
            if not parsed:
                continue
            any_answer = True
            _name, ttl, actual_type, value = parsed
            artifact = value
            artifact_type = "dns"
            relationship = f"dns_{actual_type.lower()}"
            if actual_type in ("A", "AAAA"):
                artifact_type, artifact, relationship = "ip", value.rstrip("."), "resolves_to"
                ips.append(artifact)
            elif actual_type == "NS":
                artifact = value.rstrip(".")
                relationship = "authoritative_nameserver"
                if artifact.lower().endswith(".ns.cloudflare.com"):
                    case.flags["cloudflare_detected"] = True
                    case.flags["cloudflare_detection_basis"] = "authoritative_nameserver"
                    case.flags["dns_provider_context"] = "Cloudflare authoritative DNS / proxy context; this is not registrar evidence"
            elif actual_type == "MX":
                artifact = value.split()[-1].rstrip(".")
                relationship = "mail_exchanger"
            elif actual_type == "CNAME":
                artifact = value.rstrip(".")
                relationship = "cname_to"
            dns_note = "Current DNS observation."
            if actual_type == "NS":
                dns_note += " Nameserver/provider context must not be reported as the domain registrar."
            case.add_evidence(adapter="dig", source_name="Public DNS resolution", source_url="", query=f"{case.domain} {rtype}",
                              artifact_type=artifact_type, artifact=artifact, relationship=relationship,
                              observation=f"DNS {actual_type} answer for {case.domain}: {value} (TTL {ttl})",
                              raw_ref=f"raw/dns-{safe_name(case.domain)}.txt", confidence="high", notes=dns_note)
    raw_path = case.raw / f"dns-{safe_name(case.domain)}.txt"
    text_dump(raw_path, "\n".join(all_out))
    case.add_status("dig", "OK" if any_answer else "NO_RESULT", case.domain, "Current public DNS records")
    return sorted(set(ips))


def _looks_like_json(headers: Dict[str, str], body: bytes) -> bool:
    content_type = ""
    for key, value in headers.items():
        if key.lower() == "content-type":
            content_type = value.lower()
            break
    stripped = body.lstrip()
    return ("json" in content_type) or stripped.startswith(b"[") or stripped.startswith(b"{")


def _crtsh_http_with_retry(url: str, attempts: int = 4) -> Tuple[int, bytes, Dict[str, str], int, str]:
    """Fetch crt.sh with bounded retry/backoff for transient failures.

    Returns (status_code, body, headers, attempts_used, note).
    Network exceptions are converted into a synthetic code 0 so callers can
    distinguish service unavailability from a genuine empty CT result.
    """
    delays = (0, 2, 5, 12)
    last_code = 0
    last_body = b""
    last_headers: Dict[str, str] = {}
    last_note = ""
    for idx in range(max(1, min(attempts, len(delays)))):
        if delays[idx]:
            time.sleep(delays[idx])
        try:
            code, body, headers = http_get(url, timeout=45)
            last_code, last_body, last_headers = code, body, headers
            # Retry only temporary service/rate-limit responses. A 200 with an
            # HTML error body is also treated as temporary/unavailable.
            if code == 200 and _looks_like_json(headers, body):
                return code, body, headers, idx + 1, ""
            if code == 200:
                last_note = "HTTP 200 but response was not JSON"
                continue
            if code not in (429, 500, 502, 503, 504):
                return code, body, headers, idx + 1, ""
            last_note = f"Transient HTTP {code}"
        except Exception as exc:
            last_code, last_body, last_headers = 0, b"", {}
            last_note = f"Network error: {exc}"
    return last_code, last_body, last_headers, max(1, min(attempts, len(delays))), last_note


def _crtsh_psql_fallback(case: Case) -> Tuple[Optional[List[Dict[str, Any]]], str, Optional[Path]]:
    """Optional fallback to crt.sh's public PostgreSQL interface.

    This is attempted only when the local `psql` client exists. Failure never
    aborts the case and never becomes NO_RESULT; it is recorded as unavailable.
    """
    if not command_exists("psql"):
        return None, "psql client not installed", None
    # Query certificate identities matching the base domain or any subdomain.
    # COPY ... CSV keeps parsing predictable and avoids psql table formatting.
    escaped = case.domain.replace("'", "''")
    sql = (
        "COPY ("
        "SELECT DISTINCT ci.NAME_VALUE "
        "FROM certificate_identity ci "
        "WHERE lower(ci.NAME_VALUE) = lower('" + escaped + "') "
        "OR lower(ci.NAME_VALUE) LIKE lower('%." + escaped + "') "
        "LIMIT 5000"
        ") TO STDOUT WITH CSV;"
    )
    try:
        proc = run_cmd([
            "psql", "-h", "crt.sh", "-p", "5432", "-U", "guest", "-d", "certwatch",
            "-v", "ON_ERROR_STOP=1", "-c", sql,
        ], timeout=75)
    except Exception as exc:
        return None, f"psql fallback error: {exc}", None
    raw_path = case.raw / f"crtsh-psql-{safe_name(case.domain)}.csv"
    text_dump(raw_path, proc.stdout + ("\n# STDERR\n" + proc.stderr if proc.stderr else ""))
    if proc.returncode != 0:
        return None, f"psql fallback exited {proc.returncode}", raw_path
    rows: List[Dict[str, Any]] = []
    for line in proc.stdout.splitlines():
        name = line.strip().strip('"').lower().rstrip(".")
        if name.startswith("*."):
            name = name[2:]
        if name:
            rows.append({"name_value": name, "id": "psql-fallback", "issuer_name": "", "not_before": None, "not_after": None})
    return rows, "", raw_path


def collect_crtsh(case: Case) -> List[str]:
    query = f"%.{case.domain}"
    url = "https://crt.sh/?" + urllib.parse.urlencode({"q": query, "output": "json"})
    code, body, headers, attempts_used, retry_note = _crtsh_http_with_retry(url, attempts=4)
    raw_path = case.raw / f"crtsh-{safe_name(case.domain)}.json"
    raw_path.write_bytes(body)

    rows: Any = None
    used_fallback = False
    fallback_raw: Optional[Path] = None

    if code == 200 and _looks_like_json(headers, body):
        try:
            rows = parse_json_bytes(body)
        except Exception as exc:
            retry_note = f"Invalid JSON after {attempts_used} attempt(s): {exc}"
    else:
        if code == 429:
            primary_status = "RATE_LIMITED"
        elif code in (0, 500, 502, 503, 504) or (code == 200 and not _looks_like_json(headers, body)):
            primary_status = "UNAVAILABLE"
        else:
            primary_status = classify_http_status(code)
        case.add_status("crtsh-http", primary_status, query,
                        f"Primary endpoint failed after {attempts_used} attempt(s); HTTP {code or 'network'}; {retry_note}".strip())

    if not isinstance(rows, list):
        fallback_rows, fallback_note, fallback_raw = _crtsh_psql_fallback(case)
        if isinstance(fallback_rows, list):
            rows = fallback_rows
            used_fallback = True
            case.add_status("crtsh-fallback", "OK" if rows else "NO_RESULT", query,
                            f"Public PostgreSQL fallback returned {len(rows)} certificate-name row(s)")
        else:
            case.add_status("crtsh-fallback", "UNAVAILABLE", query, fallback_note)

    if not isinstance(rows, list):
        # Crucial: service failure is not evidence of no certificates.
        case.add_status("crtsh", "UNAVAILABLE", query,
                        "No trustworthy CT result obtained; do not interpret as NO_RESULT")
        return []

    rel_path = fallback_raw if used_fallback and fallback_raw else raw_path
    rel = str(rel_path.relative_to(case.root))

    raw_observations = 0
    cert_ids = set()
    host_agg: Dict[str, Dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        entry_id = str(row.get("id", "")).strip()
        issuer = str(row.get("issuer_name", "") or "")
        nb = row.get("not_before")
        na = row.get("not_after")
        if entry_id:
            cert_ids.add(entry_id)
        names = str(row.get("name_value", "")).splitlines()
        for name in names:
            name = name.strip().lower().rstrip(".")
            if name.startswith("*."):
                name = name[2:]
            if not name:
                continue
            raw_observations += 1
            agg = host_agg.setdefault(name, {"entries": set(), "issuers": set(), "first": None, "last": None})
            if entry_id:
                agg["entries"].add(entry_id)
            if issuer:
                agg["issuers"].add(issuer)
            if nb and (agg["first"] is None or str(nb) < str(agg["first"])):
                agg["first"] = nb
            if na and (agg["last"] is None or str(na) > str(agg["last"])):
                agg["last"] = na

    unique_hosts = sorted(host_agg)
    case.metrics["ct_raw_name_observations"] = raw_observations
    case.metrics["ct_unique_certificate_ids"] = len(cert_ids)
    case.metrics["ct_unique_hostnames"] = len(unique_hosts)

    for name in unique_hosts:
        agg = host_agg[name]
        cert_count = len(agg["entries"]) if agg["entries"] else 0
        issuers = sorted(agg["issuers"])[:3]
        issuer_text = "; ".join(issuers) if issuers else "unknown"
        case.add_evidence(
            adapter="crtsh",
            source_name="crt.sh Certificate Transparency" + (" (PostgreSQL fallback)" if used_fallback else ""),
            source_url=url if not used_fallback else "postgresql://guest@crt.sh:5432/certwatch",
            query=query,
            artifact_type="certificate",
            artifact=name,
            relationship="certificate_name",
            observation=(f"CT references hostname {name}; unique_certificate_entries={cert_count}; "
                         f"first_not_before={agg['first']}; latest_not_after={agg['last']}; issuers={issuer_text}"),
            raw_ref=rel,
            confidence="medium",
            observed_utc=agg["first"],
            notes="Historical CT issuance observation only. Do not label this hostname or certificate as currently active unless live TLS validation independently succeeds. Certificate association is not proof of common ownership.",
        )

    if unique_hosts:
        final_status = "PARTIAL" if used_fallback else "OK"
        note = (f"CT raw name observations={raw_observations}; unique certificate IDs={len(cert_ids)}; "
                f"unique hostnames={len(unique_hosts)}")
        if used_fallback:
            note += "; primary HTTP endpoint unavailable, fallback used"
        case.add_status("crtsh", final_status, query, note)
    else:
        case.add_status("crtsh", "NO_RESULT", query,
                        "CT source responded successfully and returned no certificate-name observations")
    return unique_hosts


def collect_live_tls(case: Case, hostnames: List[str]) -> None:
    """Validate a bounded set of CT-derived hostnames with a live TLS handshake.

    This is a normal client-side TLS connection, not a vulnerability scan. It exists
    to prevent historical CT observations from being mislabeled as currently active.
    """
    seen = []
    for h in hostnames:
        h = (h or "").strip().lower().rstrip(".")
        if h and h not in seen:
            seen.append(h)
    # Keep the validation bounded; target and www first, then CT-derived names.
    ordered = []
    for h in [case.domain, f"www.{case.domain}"] + seen:
        if h not in ordered:
            ordered.append(h)
    targets = ordered[:30]
    if not targets:
        case.add_status("live-tls", "NO_RESULT", case.domain, "No hostnames available for live TLS validation")
        return
    ok = 0
    dns_only = 0
    failures = 0
    ctx = ssl.create_default_context()
    for host in targets:
        raw_path = case.raw / f"live-tls-{safe_name(host)}.json"
        try:
            addrs = sorted({ai[4][0] for ai in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)})
        except Exception as exc:
            json_dump(raw_path, {"host": host, "status": "DNS_INACTIVE", "error": str(exc)})
            failures += 1
            case.add_evidence(adapter="live-tls", source_name="Live TLS validation", source_url=f"https://{host}/", query=host,
                              artifact_type="hostname", artifact=host, relationship="historical_only_unresolved",
                              observation=f"Hostname {host} was observed historically but does not currently resolve for TLS validation",
                              raw_ref=str(raw_path.relative_to(case.root)), confidence="high",
                              notes="Current DNS lookup failed; CT history does not imply current activity")
            continue
        try:
            with socket.create_connection((host, 443), timeout=8) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert() or {}
                    not_after = cert.get("notAfter")
                    issuer = cert.get("issuer")
                    subject = cert.get("subject")
                    san = cert.get("subjectAltName", [])
                    payload = {"host": host, "status": "WEB_TLS_ACTIVE", "addresses": addrs, "not_after": not_after, "issuer": issuer, "subject": subject, "san": san}
                    json_dump(raw_path, payload)
                    ok += 1
                    case.add_evidence(adapter="live-tls", source_name="Live TLS validation", source_url=f"https://{host}/", query=host,
                                      artifact_type="hostname", artifact=host, relationship="live_tls_active",
                                      observation=f"Live TLS handshake succeeded for {host}; addresses={addrs}; certificate_not_after={not_after}",
                                      raw_ref=str(raw_path.relative_to(case.root)), confidence="high",
                                      notes="Current-state validation. Historical CT issuer history is kept separate from the live certificate.")
        except Exception as exc:
            json_dump(raw_path, {"host": host, "status": "DNS_ACTIVE_TLS_UNAVAILABLE", "addresses": addrs, "error": str(exc)})
            dns_only += 1
            case.add_evidence(adapter="live-tls", source_name="Live TLS validation", source_url=f"https://{host}/", query=host,
                              artifact_type="hostname", artifact=host, relationship="dns_active_tls_unavailable",
                              observation=f"Hostname {host} currently resolves to {addrs}, but a TLS handshake on port 443 did not succeed",
                              raw_ref=str(raw_path.relative_to(case.root)), confidence="high",
                              notes="DNS activity does not establish that an HTTPS service is active")
    case.metrics["live_tls_targets_checked"] = len(targets)
    case.metrics["live_tls_active"] = ok
    case.metrics["live_tls_dns_only"] = dns_only
    case.metrics["live_tls_unresolved"] = failures
    case.add_status("live-tls", "OK" if ok else "PARTIAL", ",".join(targets),
                    f"Checked {len(targets)} hostnames; WEB_TLS_ACTIVE={ok}; DNS_ACTIVE_TLS_UNAVAILABLE={dns_only}; DNS_INACTIVE={failures}")


def collect_wayback(case: Case) -> None:
    # CDX expects collapse as its own parameter, not as a filter.
    params = [("url", f"{case.domain}/*"), ("output", "json"),
              ("filter", "statuscode:200"), ("collapse", "digest"),
              ("fl", "timestamp,original,statuscode,digest")]
    url = "https://web.archive.org/cdx/search/cdx?" + urllib.parse.urlencode(params)
    code, body, _ = http_get(url, timeout=60)
    raw_path = case.raw / f"wayback-{safe_name(case.domain)}.json"
    raw_path.write_bytes(body)
    if code == 400:
        case.add_status("wayback", "ERROR_BAD_REQUEST", case.domain,
                        "HTTP 400 from CDX API; this is a request/service error, not evidence that no archives exist")
        return
    if code == 429:
        case.add_status("wayback", "RATE_LIMITED", case.domain, "HTTP 429 from CDX API")
        return
    if code in (500, 502, 503, 504):
        case.add_status("wayback", "UNAVAILABLE", case.domain, f"HTTP {code} from CDX API")
        return
    status = classify_http_status(code)
    if status != "OK":
        case.add_status("wayback", status, case.domain, f"HTTP {code}")
        return
    try:
        rows = parse_json_bytes(body)
    except Exception as exc:
        case.add_status("wayback", "ERROR", case.domain, f"Invalid JSON: {exc}")
        return
    if not isinstance(rows, list) or len(rows) <= 1:
        case.add_status("wayback", "NO_RESULT", case.domain,
                        "CDX API returned a successful, parseable response with no archived 200 snapshots")
        return
    header = rows[0]
    indexes = {name: i for i, name in enumerate(header)}
    rel = str(raw_path.relative_to(case.root))
    count = 0
    for row in rows[1:501]:
        try:
            ts = row[indexes["timestamp"]]
            original = row[indexes["original"]]
            digest = row[indexes["digest"]]
        except Exception:
            continue
        iso = None
        try:
            iso = dt.datetime.strptime(ts, "%Y%m%d%H%M%S").replace(tzinfo=dt.timezone.utc).isoformat().replace("+00:00", "Z")
        except Exception:
            pass
        count += 1
        case.add_evidence(adapter="wayback", source_name="Internet Archive Wayback CDX", source_url=url, query=case.domain,
                          artifact_type="archive", artifact=original, relationship="archived_url",
                          observation=f"Wayback CDX records archived URL {original} at {ts} (digest {digest})", raw_ref=rel,
                          confidence="high", observed_utc=iso)
    case.metrics["wayback_normalized_snapshots"] = count
    case.add_status("wayback", "OK", case.domain,
                    f"Normalized first {count} snapshots after digest collapse; full raw response preserved")


def collect_urlscan(case: Case) -> None:
    query = f"page.domain:{case.domain}"
    url = "https://urlscan.io/api/v1/search/?" + urllib.parse.urlencode({"q": query, "size": "100"})
    headers = {}
    key = os.environ.get("URLSCAN_API_KEY")
    if key:
        headers["api-key"] = key
    code, body, _ = http_get(url, headers=headers, timeout=45)
    raw_path = case.raw / f"urlscan-{safe_name(case.domain)}.json"
    raw_path.write_bytes(body)
    status = classify_http_status(code)
    if status != "OK":
        case.add_status("urlscan", status, query, f"HTTP {code}; set URLSCAN_API_KEY if your quota requires authentication")
        return
    try:
        data = parse_json_bytes(body)
    except Exception as exc:
        case.add_status("urlscan", "ERROR", query, f"Invalid JSON: {exc}")
        return
    rel = str(raw_path.relative_to(case.root))
    count = 0
    for row in data.get("results", []) or []:
        task = row.get("task", {}) or {}
        page = row.get("page", {}) or {}
        when = task.get("time") or row.get("sort", [None])[0]
        url_value = page.get("url") or task.get("url") or ""
        if url_value:
            count += 1
            case.add_evidence(adapter="urlscan", source_name="urlscan.io Search API", source_url=url, query=query,
                              artifact_type="url", artifact=url_value, relationship="observed_on_urlscan",
                              observation=f"urlscan historical search returned {url_value}; IP={page.get('ip')}; ASN={page.get('asn')}; status={page.get('status')}",
                              raw_ref=rel, confidence="medium", observed_utc=str(when) if when else None,
                              notes="Historical/public scan observation; freshness depends on scan time. IP diversity may reflect redirects, CDNs, third-party resources, shared hosting, or infrastructure changes; do not infer migration from IP count alone.")
    auth_mode = "authenticated" if key else "public/unauthenticated"
    case.flags["urlscan_authenticated"] = bool(key)
    case.add_status("urlscan", "OK" if count else "NO_RESULT", query, f"Normalized {count} public scan observations; mode={auth_mode}")


def _candidate_rows(data: Any) -> List[Dict[str, Any]]:
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    if isinstance(data, dict):
        for key in ("items", "results", "data", "documents", "records"):
            value = data.get(key)
            if isinstance(value, list):
                return [x for x in value if isinstance(x, dict)]
        return [data]
    return []

def collect_netlas(case: Case) -> None:
    key = os.environ.get("NETLAS_API_KEY")
    if not key:
        case.add_status("netlas", "UNAVAILABLE", case.domain, "NETLAS_API_KEY is not set; Netlas enrichment omitted")
        return
    query = f"domain:{case.domain}"
    params = urllib.parse.urlencode({"q": query})
    url = f"https://app.netlas.io/api/domains/?{params}"
    code, body, headers = http_get(url, headers={"Authorization": f"Bearer {key}"}, timeout=60)
    raw_path = case.raw / f"netlas-{safe_name(case.domain)}.json"
    raw_path.write_bytes(body)
    if code == 429:
        case.add_status("netlas", "RATE_LIMITED", query, "HTTP 429; authenticated key present but current quota/throttle prevented collection")
        return
    if code == 402:
        case.add_status("netlas", "LIMITED", query, "HTTP 402; key works but current subscription/coin allowance does not permit this request")
        return
    if code in (401, 403):
        case.add_status("netlas", "LIMITED", query, f"HTTP {code}; key was supplied but account/plan permissions did not allow this endpoint")
        return
    if code != 200:
        case.add_status("netlas", "ERROR", query, f"HTTP {code}")
        return
    try:
        data = parse_json_bytes(body)
    except Exception as exc:
        case.add_status("netlas", "ERROR", query, f"Invalid JSON: {exc}")
        return
    rel = str(raw_path.relative_to(case.root))
    rows = _candidate_rows(data)
    count = 0
    def emit(value: Any, relname: str, atype: str = "dns") -> None:
        nonlocal count
        vals = value if isinstance(value, list) else [value]
        for v in vals:
            if isinstance(v, dict):
                v = v.get("value") or v.get("address") or v.get("host") or v.get("name")
            if v is None:
                continue
            txt = str(v).strip().rstrip(".")
            if not txt:
                continue
            count += 1
            case.add_evidence(adapter="netlas", source_name="Netlas Domains API", source_url=url, query=query,
                              artifact_type=atype, artifact=txt, relationship=relname,
                              observation=f"Netlas domain search associated {case.domain} with {txt} ({relname})",
                              raw_ref=rel, confidence="medium",
                              notes="Third-party indexed observation; corroborate timing and shared-infrastructure explanations")
    for row in rows[:50]:
        emit(row.get("a"), "netlas_a", "ip")
        emit(row.get("aaaa"), "netlas_aaaa", "ip")
        emit(row.get("ns"), "netlas_ns")
        emit(row.get("mx"), "netlas_mx")
        emit(row.get("cname"), "netlas_cname")
    case.add_status("netlas", "OK" if count else "NO_RESULT", query, f"Authenticated API request succeeded; normalized {count} domain/DNS observations")

def collect_virustotal(case: Case) -> None:
    key = os.environ.get("VT_API_KEY")
    if not key:
        case.add_status("virustotal", "UNAVAILABLE", case.domain, "VT_API_KEY is not set; VirusTotal enrichment omitted")
        return
    url = f"https://www.virustotal.com/api/v3/domains/{urllib.parse.quote(case.domain)}"
    code, body, headers = http_get(url, headers={"x-apikey": key}, timeout=45)
    raw_path = case.raw / f"virustotal-{safe_name(case.domain)}.json"
    raw_path.write_bytes(body)
    if code == 429:
        case.add_status("virustotal", "RATE_LIMITED", case.domain, "HTTP 429; API key present but Community/API quota was hit")
        return
    if code in (401, 403):
        case.add_status("virustotal", "LIMITED", case.domain, f"HTTP {code}; API key supplied but request was not permitted")
        return
    if code == 404:
        case.add_status("virustotal", "NO_RESULT", case.domain, "VirusTotal returned no domain object")
        return
    if code != 200:
        case.add_status("virustotal", "ERROR", case.domain, f"HTTP {code}")
        return
    try:
        data = parse_json_bytes(body)
    except Exception as exc:
        case.add_status("virustotal", "ERROR", case.domain, f"Invalid JSON: {exc}")
        return
    attrs = ((data.get("data") or {}).get("attributes") or {}) if isinstance(data, dict) else {}
    rel = str(raw_path.relative_to(case.root))
    count = 0
    registrar = attrs.get("registrar")
    if registrar:
        count += 1
        case.add_evidence(adapter="virustotal", source_name="VirusTotal Domain API", source_url=url, query=case.domain,
                          artifact_type="domain", artifact=case.domain, relationship="vt_registrar_context",
                          observation=f"VirusTotal domain object reports registrar context: {registrar}", raw_ref=rel, confidence="medium",
                          notes="Third-party domain metadata; corroborate with registry RDAP/WHOIS")
    stats = attrs.get("last_analysis_stats")
    if isinstance(stats, dict):
        normalized_stats = {}
        for k, v in stats.items():
            try:
                normalized_stats[str(k)] = int(v)
            except Exception:
                continue
        engine_total = sum(v for v in normalized_stats.values() if v >= 0)
        case.metrics["virustotal_last_analysis_stats"] = normalized_stats
        case.metrics["virustotal_engine_total"] = engine_total
        count += 1
        case.add_evidence(adapter="virustotal", source_name="VirusTotal Domain API", source_url=url, query=case.domain,
                          artifact_type="domain", artifact=case.domain, relationship="vt_reputation_context",
                          observation=f"VirusTotal last_analysis_stats={json.dumps(normalized_stats, sort_keys=True)}; engine_total={engine_total}", raw_ref=rel, confidence="medium",
                          notes="Aggregated vendor-engine context only. Categories in last_analysis_stats should be reported exactly as returned and, when a denominator is needed, use engine_total=sum(last_analysis_stats values). Do not call undetected benign/harmless, do not infer false positives from undetected, and do not count engines as independent corroborating sources.")
    dns_records = attrs.get("last_dns_records") or []
    for rec in dns_records[:50] if isinstance(dns_records, list) else []:
        if not isinstance(rec, dict):
            continue
        value = rec.get("value")
        rtype = str(rec.get("type") or "").upper()
        if value:
            count += 1
            atype = "ip" if rtype in {"A", "AAAA"} else "dns"
            case.add_evidence(adapter="virustotal", source_name="VirusTotal Domain API", source_url=url, query=case.domain,
                              artifact_type=atype, artifact=str(value).rstrip("."), relationship=f"vt_dns_{rtype.lower() or 'record'}",
                              observation=f"VirusTotal last DNS records include {rtype} {value}", raw_ref=rel, confidence="medium",
                              notes="Third-party last-observed DNS; compare with current authoritative resolution")
    case.add_status("virustotal", "OK" if count else "NO_RESULT", case.domain, f"Authenticated domain lookup succeeded; normalized {count} context observation(s)")

def collect_robtex(case: Case) -> None:
    url = f"https://freeapi.robtex.com/pdns/forward/{urllib.parse.quote(case.domain)}?format=json"
    code, body, headers = http_get(url, timeout=45)
    raw_path = case.raw / f"robtex-{safe_name(case.domain)}.json"
    raw_path.write_bytes(body)
    if code == 429:
        case.add_status("robtex", "RATE_LIMITED", case.domain, "Free API rate limit reached; documented public tier is intentionally low")
        return
    if code != 200:
        case.add_status("robtex", "ERROR", case.domain, f"HTTP {code}")
        return
    try:
        data = parse_json_bytes(body)
    except Exception as exc:
        case.add_status("robtex", "ERROR", case.domain, f"Invalid JSON: {exc}")
        return
    rows = _candidate_rows(data)
    rel = str(raw_path.relative_to(case.root))
    count = 0
    for row in rows[:100]:
        rrdata = row.get("rrdata") or row.get("value")
        rrtype = str(row.get("rrtype") or row.get("type") or "").upper()
        if not rrdata:
            continue
        count += 1
        atype = "ip" if rrtype in {"A", "AAAA"} else "dns"
        first = row.get("time_first")
        last = row.get("time_last")
        case.add_evidence(adapter="robtex", source_name="Robtex Free Passive DNS API", source_url=url, query=case.domain,
                          artifact_type=atype, artifact=str(rrdata).rstrip("."), relationship=f"robtex_pdns_{rrtype.lower() or 'record'}",
                          observation=f"Robtex passive DNS observed {rrtype} {rrdata}; first={first}; last={last}",
                          raw_ref=rel, confidence="medium", notes="Historical passive-DNS observation; free API is heavily rate limited")
    case.add_status("robtex", "OK" if count else "NO_RESULT", case.domain, f"Public passive-DNS request succeeded; normalized {count} observation(s)")

def collect_censys(case: Case, ips: Iterable[str]) -> None:
    token = os.environ.get("CENSYS_PAT")
    ips = list(dict.fromkeys(ips))
    if not token:
        case.add_status("censys", "UNAVAILABLE", ",".join(ips), "CENSYS_PAT is not set; Censys host validation omitted")
        return
    if case.flags.get("cloudflare_detected"):
        case.add_status("censys", "LIMITED", ",".join(ips), "PAT is present, but host lookups were skipped because current DNS points to Cloudflare shared edge IPs; this preserves credits and avoids misleading edge-host context")
        return
    if not ips:
        case.add_status("censys", "NO_RESULT", case.domain, "No current IPs available for Censys host lookup")
        return
    any_ok = False
    normalized = 0
    for ip in ips[:5]:
        url = f"https://api.platform.censys.io/v3/global/asset/host/{urllib.parse.quote(ip)}"
        code, body, headers = http_get(url, headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.censys.api.v3.host.v1+json"}, timeout=45)
        raw_path = case.raw / f"censys-{safe_name(ip)}.json"
        raw_path.write_bytes(body)
        if code == 429:
            case.add_status("censys", "RATE_LIMITED", ip, "Censys concurrency/credit limit encountered")
            return
        if code in (401, 403):
            case.add_status("censys", "LIMITED", ip, f"HTTP {code}; PAT present but current account/plan cannot access requested host lookup")
            return
        if code == 404:
            continue
        if code != 200:
            continue
        any_ok = True
        try:
            data = parse_json_bytes(body)
        except Exception:
            continue
        rel = str(raw_path.relative_to(case.root))
        normalized += 1
        case.add_evidence(adapter="censys", source_name="Censys Platform Host API", source_url=url, query=ip,
                          artifact_type="ip", artifact=ip, relationship="censys_host_lookup",
                          observation=f"Censys returned a current host asset record for {ip}", raw_ref=rel, confidence="medium",
                          notes="Asset lookup validates indexed host context; fields and history available depend on Censys plan")
    case.add_status("censys", "OK" if any_ok else "NO_RESULT", ",".join(ips[:5]), f"Authenticated host lookup completed; normalized {normalized} host asset observation(s)")

def collect_huntio(case: Case) -> None:
    token = os.environ.get("HUNT_API_KEY") or os.environ.get("HUNT_IO_TOKEN")
    if not token:
        case.flags["huntio_configured"] = False
        case.add_status("huntio", "UNAVAILABLE", case.domain, "Set HUNT_API_KEY or HUNT_IO_TOKEN")
        return
    case.flags["huntio_configured"] = True
    url = f"https://api.hunt.io/v1/enrich/domain/{urllib.parse.quote(case.domain)}"
    code, body, _ = http_get(url, headers={"token": token, "accept": "application/json"}, timeout=60)
    raw_path = case.raw / f"huntio-{safe_name(case.domain)}.json"
    raw_path.write_bytes(body)
    status = classify_http_status(code)
    if status != "OK":
        case.add_status("huntio", status, case.domain, f"HTTP {code}")
        return
    try:
        data = parse_json_bytes(body)
    except Exception as exc:
        case.add_status("huntio", "ERROR", case.domain, f"Invalid JSON: {exc}")
        return
    rel = str(raw_path.relative_to(case.root))
    count = 0
    for ip in data.get("ips", []) or []:
        count += 1
        case.add_evidence(adapter="huntio", source_name="Hunt.io Domain Enrichment API", source_url=url, query=case.domain,
                          artifact_type="ip", artifact=str(ip), relationship="hunt_observed_ip",
                          observation=f"Hunt.io domain enrichment returned IP {ip} for {case.domain}", raw_ref=rel, confidence="medium",
                          notes="Third-party intelligence observation; corroborate independently")
    for cert in data.get("certificates", []) or []:
        fp = cert.get("sha256") or cert.get("fingerprint") or cert.get("hash") or json.dumps(cert, sort_keys=True)[:160]
        count += 1
        case.add_evidence(adapter="huntio", source_name="Hunt.io Domain Enrichment API", source_url=url, query=case.domain,
                          artifact_type="certificate", artifact=str(fp), relationship="hunt_certificate_observation",
                          observation="Hunt.io domain enrichment returned a certificate observation for the target domain",
                          raw_ref=rel, confidence="medium", notes="See raw artifact for full fields; corroborate independently")
    for key in ("malware", "phishing", "jarm", "protocol", "http", "ssh", "opendir", "honeypot"):
        values = data.get(key, []) or []
        if values:
            count += 1
            case.add_evidence(adapter="huntio", source_name="Hunt.io Domain Enrichment API", source_url=url, query=case.domain,
                              artifact_type="domain", artifact=case.domain, relationship=f"hunt_{key}_context",
                              observation=f"Hunt.io returned {len(values)} {key} record(s) associated with its observations of the target",
                              raw_ref=rel, confidence="low", notes="Context signal only; inspect raw data and corroborate before conclusions")
    case.add_status("huntio", "OK" if count else "NO_RESULT", case.domain, f"Normalized {count} enrichment observations")


def collect_shodan(case: Case, ips: Iterable[str]) -> None:
    ips = list(dict.fromkeys(ips))
    if case.flags.get("cloudflare_detected"):
        case.add_status("shodan", "SKIPPED", ",".join(ips),
                        "Cloudflare authoritative nameservers detected; reverse-IP host enrichment on edge IPs suppressed to reduce unrelated shared-infrastructure noise")
        return
    if not ips:
        case.add_status("shodan", "NO_RESULT", case.domain, "No validated IPs available from DNS")
        return
    if not command_exists("shodan"):
        case.flags["shodan_configured"] = False
        case.add_status("shodan", "UNAVAILABLE", ",".join(ips), "Shodan CLI not installed/configured")
        return
    case.flags["shodan_configured"] = True
    any_ok = False
    for ip in ips[:20]:
        cp = run_cmd(["shodan", "host", ip], timeout=60)
        raw_path = case.raw / f"shodan-{safe_name(ip)}.txt"
        text_dump(raw_path, cp.stdout + ("\nSTDERR:\n" + cp.stderr if cp.stderr else ""))
        if cp.returncode != 0:
            continue
        lines = [l for l in cp.stdout.splitlines() if l.strip()]
        if not lines:
            continue
        any_ok = True
        case.add_evidence(adapter="shodan", source_name="Shodan CLI", source_url="https://www.shodan.io/", query=ip,
                          artifact_type="ip", artifact=ip, relationship="shodan_host_observation",
                          observation=f"Shodan returned {len(lines)} line(s) of historical/current host-enrichment data for {ip}",
                          raw_ref=str(raw_path.relative_to(case.root)), confidence="medium",
                          notes="Shodan data can be stale; inspect timestamps in raw output")
    case.add_status("shodan", "OK" if any_ok else "UNAVAILABLE", ",".join(ips[:20]), "Passive enrichment via local Shodan CLI")


def collect_sherlock(case: Case, usernames: List[str]) -> None:
    if not usernames:
        case.add_status("sherlock", "NO_RESULT", "", "No validated usernames supplied with --username")
        return
    if not command_exists("sherlock"):
        case.add_status("sherlock", "UNAVAILABLE", ",".join(usernames), "Sherlock command not found")
        return
    for username in usernames:
        safe_user = safe_name(username)
        out_csv = case.raw / f"{safe_user}.csv"
        cp = run_cmd(["sherlock", "--folderoutput", str(case.raw), "--print-found", "--csv", username], timeout=180)
        generated = case.raw / f"{username}.csv"
        if generated.exists() and generated != out_csv:
            try:
                generated.replace(out_csv)
            except OSError:
                out_csv = generated
        if cp.returncode != 0 and not out_csv.exists():
            case.add_status("sherlock", "ERROR", username, cp.stderr.strip()[:300])
            continue
        found = 0
        if out_csv.exists():
            try:
                with out_csv.open(newline="", encoding="utf-8", errors="replace") as f:
                    for row in csv.DictReader(f):
                        url = row.get("url_user") or row.get("url") or row.get("profile") or ""
                        if not url:
                            continue
                        found += 1
                        case.add_evidence(adapter="sherlock", source_name="Sherlock local CLI", source_url="", query=username,
                                          artifact_type="username", artifact=username, relationship="public_username_match",
                                          observation=f"Sherlock reported a public username match at {url}",
                                          raw_ref=str(out_csv.relative_to(case.root)), confidence="low",
                                          notes="Username reuse alone does not establish common identity; corroborate profile content independently")
            except Exception as exc:
                case.add_status("sherlock", "ERROR", username, f"Could not parse CSV: {exc}")
                continue
        case.add_status("sherlock", "OK" if found else "NO_RESULT", username, f"{found} public matches normalized")


def build_candidate_relationships(evidence: List[Dict[str, Any]], domain: str) -> List[Dict[str, Any]]:
    groups: Dict[Tuple[str, str], set] = {}
    for rec in evidence:
        key = (rec.get("artifact_type", ""), rec.get("artifact", ""))
        groups.setdefault(key, set()).add(rec.get("source_adapter", ""))
    out = []
    for (atype, artifact), sources in sorted(groups.items()):
        if not artifact or artifact == domain or len(sources) < 2:
            continue
        out.append({
            "artifact_type": atype,
            "artifact": artifact,
            "independent_adapter_count": len(sources),
            "adapters": sorted(sources),
            "assessment": "corroborated technical observation; analyst review required before attribution",
        })
    return out[:100]


def md_escape(value: Any) -> str:
    return str(value if value is not None else "").replace("|", "\\|").replace("\n", " ")


def methodology_coverage(case: Case) -> Tuple[str, str, List[str]]:
    good = {"OK", "PARTIAL", "NO_RESULT"}
    def ok(name: str) -> bool:
        return (case.sources.get(name) or {}).get("runtime_status") in good
    registry_ok = ok("rdap") or ok("whois")
    core_checks = {
        "registration": registry_ok,
        "current_dns": ok("dns"),
        "certificate_history": ok("crtsh"),
        "current_tls_validation": ok("live_tls"),
        "web_archive": ok("wayback"),
        "web_scan_history": ok("urlscan"),
    }
    core_count = sum(core_checks.values())
    core_label = "FULL" if core_count == len(core_checks) else ("PARTIAL" if core_count >= 3 else "LIMITED")
    enrichment_names = ["netlas", "virustotal", "robtex", "censys", "shodan"]
    enrichment_ok = sum(ok(n) for n in enrichment_names)
    enrichment_label = "FULL" if enrichment_ok == len(enrichment_names) else ("PARTIAL" if enrichment_ok >= 2 else "LIMITED")
    limitations = []
    for name, src in sorted(case.sources.items()):
        st = src.get("runtime_status")
        if st in {"UNAVAILABLE", "ERROR", "ERROR_BAD_REQUEST", "RATE_LIMITED", "LIMITED", "SKIPPED", "NOT_RUN"}:
            note = src.get("notes") or src.get("limitation") or "No additional detail."
            limitations.append(f"{name}: {st} — {note}")
    return core_label, enrichment_label, limitations

def source_capability_markdown(case: Case) -> str:
    rows = []
    for name, src in sorted(case.sources.items()):
        cred = src.get("credential_present")
        cred_text = "n/a" if cred is None else ("yes" if cred else "no")
        cred_source = src.get("credential_source", "n/a")
        rows.append(
            f"| {md_escape(name)} | {md_escape(src.get('access'))} | {cred_text} | {md_escape(cred_source)} | "
            f"{md_escape(src.get('runtime_status'))} | {'yes' if src.get('used') else 'no'} | {md_escape(src.get('limitation'))} |"
        )
    return "\n".join(rows) or "| - | - | - | - | - | - | - |"

def build_report(case: Case, end: str) -> str:
    core_coverage, enrichment_coverage, methodology_limits = methodology_coverage(case)
    source_matrix = source_capability_markdown(case)
    limitation_text = "\n".join(f"- {md_escape(x)}" for x in methodology_limits) or "- No runtime source limitations were detected in this pass."
    statuses = "\n".join(
        f"| {md_escape(s['adapter'])} | {md_escape(s['status'])} | {md_escape(s['query'])} | {md_escape(s['collected_utc'])} | {md_escape(s['notes'])} |"
        for s in case.statuses
    ) or "| - | - | - | - | - |"
    evidence_rows = []
    for rec in case.evidence[:250]:
        evidence_rows.append(
            f"| {rec['evidence_id']} | {md_escape(rec['source_adapter'])} | {md_escape(rec['artifact_type'])} | {md_escape(rec['artifact'])} | {md_escape(rec['relationship'])} | {md_escape(rec['observation'])} | {md_escape(rec.get('signal_strength',''))} | {md_escape(rec['confidence'])} |"
        )
    evidence_table = "\n".join(evidence_rows) or "| - | - | - | - | - | - | - | - |"
    candidates = build_candidate_relationships(case.evidence, case.domain)
    candidate_text = "\n".join(
        f"- **{md_escape(c['artifact'])}** ({c['artifact_type']}): observed by {', '.join(c['adapters'])}. This is a corroborated technical observation, not an ownership attribution."
        for c in candidates
    ) or "- No artifact was independently corroborated by two adapters in this automated pass."
    return f"""# Domain OSINT Investigation Report\n\n## Case Information\n\n- **Case ID:** {case.case_id}\n- **Target domain:** {case.domain}\n- **Objective:** {case.objective}\n- **Scope:** {case.scope}\n- **Start UTC:** {case.start}\n- **End UTC:** {end}\n- **Runner:** domain-osint {VERSION}\n- **Runner path:** `{md_escape(case.runner_meta.get("runner_path"))}`\n- **Runner SHA-256:** `{md_escape(case.runner_meta.get("runner_sha256"))}`\n- **Execution mode:** `{md_escape(case.runner_meta.get("execution_mode"))}`\n\n## Executive Summary\n\nThe automated runner collected passive/public-source observations and normalized them into an evidence register. It **does not make ownership or identity attribution automatically**. Candidate relationships below require analyst review, corroboration, and alternative-explanation analysis.\n\nCollected evidence records: **{len(case.evidence)}**.\n\n## Scope and Limitations\n\nDefault mode is passive/public-source collection. No authentication attempts, credential testing, exploitation, access-control bypass, or active vulnerability scanning are performed. Third-party intelligence can be historical or incomplete. Shared infrastructure is not treated as proof of common control.\n\n## Methodology Coverage\n\n- **Core methodology coverage:** {core_coverage}\n- **Optional enrichment coverage:** {enrichment_coverage}\n\nA credential being present does **not** mean the source was successfully used. Runtime status records whether the request actually succeeded, was rate-limited, blocked by plan permissions, deliberately skipped, or unavailable.\n\n### Source Capability Matrix\n\n| Source | Access mode | Credential present | Credential source | Runtime status | Used this run | Known limitation |\n|---|---|---|---|---|---|---|\n{source_matrix}\n\n### Runtime Methodology Limitations\n\n{limitation_text}\n\n## Adapter Collection Status\n\n| Adapter | Status | Query / Target | Collected UTC | Notes |\n|---|---|---|---|---|\n{statuses}\n\n## Normalized Evidence Summary\n\n| Evidence ID | Adapter | Artifact type | Artifact | Relationship | Observation | Signal | Confidence |\n|---|---|---|---|---|---|---|---|\n{evidence_table}\n\n> The table is capped at the first 250 normalized records. The complete evidence set is in `evidence.jsonl`, and raw responses are in `raw/`.\n\n## Candidate Corroborated Technical Observations\n\n{candidate_text}\n\n## Analyst Interpretation Guardrails (v1.3.9)\n\n- Keep registry lookup source, registrar, registrant/holder, DNS provider, and nameserver provider as separate concepts.\n- Certificate Transparency is historical issuance evidence. Use live DNS/TLS/HTTP for current-state claims. Recent CT issuance alone is not proof of ongoing operation.\n- VirusTotal `last_analysis_stats` is aggregated vendor-engine context. Use the runner metric `virustotal_engine_total` when a denominator is needed; `undetected` does not mean benign/harmless or false positive.\n- Historical urlscan/archive path names are literal observations. Do not characterize them as fraud, phishing, blackhat, criminal, or abusive without independent corroboration.\n- Multiple historical IPs/ASNs are ambiguous and do not establish infrastructure migration or operator movement by themselves.\n\n## Analytical Separation\n\n### Observation\nUse the evidence register and raw artifacts for directly observed facts.\n\n### Inference\nAny inference about common operation, control, or identity must be written by the analyst after checking independence, timing, specificity, and alternative explanations.\n\n### Unknown\nThe automated collection alone does not establish who owns, operates, or controls the target or related artifacts.\n\n## Evidence Preservation\n\n- `case.yaml` - case metadata and adapter status\n- `evidence.jsonl` - normalized evidence\n- `findings.yaml` - candidate technical relationships only\n- `graph.mmd` - Mermaid relationship graph for analyst review\n- `raw/` - original responses/CLI output\n- `screenshots/` - reserved for analyst-preserved visual evidence\n\n## Conclusion\n\nThis report is a collection artifact, not an automatic attribution verdict. Material conclusions should follow the skill's corroboration and confidence model.\n"""


def install_launcher(script_path: Path) -> int:
    target_dir = Path.home() / ".local" / "bin"
    target_dir.mkdir(parents=True, exist_ok=True)
    launcher = target_dir / "domain-osint"
    body = f"#!/bin/sh\nexec {shlex_quote(sys.executable)} {shlex_quote(str(script_path.resolve()))} \"$@\"\n"
    launcher.write_text(body, encoding="utf-8")
    launcher.chmod(0o755)
    print(f"Installed launcher: {launcher}")
    if str(target_dir) not in os.environ.get("PATH", "").split(os.pathsep):
        print(f"Add {target_dir} to PATH to call `domain-osint` directly.")
    return 0


def shlex_quote(value: str) -> str:
    import shlex
    return shlex.quote(value)


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Passive Domain OSINT Investigation runner")
    p.add_argument("domain", nargs="?", help="Target DNS domain, e.g. example.com")
    p.add_argument("--objective", default="Identify public infrastructure and potentially related technical artifacts.")
    p.add_argument("--scope", default="passive-public")
    p.add_argument("--case-id", default="")
    p.add_argument("--output-base", default="cases")
    p.add_argument("--username", action="append", default=[], help="Validated public username to check with Sherlock; repeatable")
    p.add_argument("--skip", action="append", default=[], choices=["rdap", "dig", "crtsh", "live-tls", "wayback", "urlscan", "netlas", "virustotal", "robtex", "censys", "huntio", "shodan", "sherlock"], help="Skip an adapter; repeatable")
    p.add_argument("--no-third-party-intel", action="store_true", help="Skip Hunt.io and Shodan")
    p.add_argument("--credentials-file", default="~/.osint_keys", help="Local credential file to read without sourcing into Hermes (default: ~/.osint_keys)")
    p.add_argument("--no-credentials-file", action="store_true", help="Do not read the local credential file; use environment variables only")
    p.add_argument("--self-check", action="store_true", help="Print non-secret runner identity/integrity metadata and exit")
    p.add_argument("--install", action="store_true", help="Install a launcher at ~/.local/bin/domain-osint")
    p.add_argument("--version", action="version", version=VERSION)
    args = p.parse_args(argv)
    if args.install:
        return install_launcher(Path(__file__))
    if args.self_check:
        meta = runner_identity()
        for key in ("runner_path", "runner_sha256", "execution_mode", "canonical_layout"):
            print(f"{key}: {meta[key]}")
        return 0
    if not args.domain:
        p.error("domain is required unless --install is used")
    global CREDENTIAL_ORIGINS
    for key in CREDENTIAL_KEYS:
        if os.environ.get(key):
            CREDENTIAL_ORIGINS[key] = "environment"
    if not args.no_credentials_file:
        cred_path = Path(args.credentials_file).expanduser()
        loaded = load_credentials_file(cred_path)
        CREDENTIAL_ORIGINS.update(loaded)
        loaded_count = sum(1 for k, origin in loaded.items() if origin != "environment")
        if loaded_count:
            print(f"[+] Credentials: loaded {loaded_count} key(s) from local credential file (values hidden)")
    try:
        domain = normalize_domain(args.domain)
    except ValueError as exc:
        p.error(str(exc)); return 2
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d")
    case_id = args.case_id or f"CASE-{stamp}-{hashlib.sha1((domain+utc_now()).encode()).hexdigest()[:6].upper()}"
    root = Path(args.output_base).expanduser().resolve() / case_id
    if root.exists() and any(root.iterdir()):
        p.error(f"Case directory already exists and is not empty: {root}")
    case = Case(domain, args.objective, args.scope, case_id, root)
    initialize_source_capabilities(case)
    skip = set(args.skip)
    skip_source_map = {"rdap":"rdap", "dig":"dns", "crtsh":"crtsh", "live-tls":"live_tls", "wayback":"wayback", "urlscan":"urlscan", "netlas":"netlas", "virustotal":"virustotal", "robtex":"robtex", "censys":"censys", "huntio":"huntio", "shodan":"shodan", "sherlock":"sherlock"}
    for adapter in skip:
        src = skip_source_map.get(adapter)
        if src in case.sources:
            case.update_source(src, "SKIPPED", used=False, notes="Skipped explicitly by command-line option")
    if args.no_third_party_intel:
        for src in ("huntio", "shodan"):
            if src in case.sources:
                case.update_source(src, "SKIPPED", used=False, notes="Skipped by --no-third-party-intel")
    print(f"[+] Case: {case_id}")
    print(f"[+] Target: {domain}")
    print(f"[+] Output: {root}")
    ips: List[str] = []
    ct_hosts: List[str] = []
    interrupted = False
    try:
        if "rdap" not in skip:
            print("[*] RDAP"); run_adapter_safely(case, "rdap", collect_rdap, case)
        if "dig" not in skip:
            print("[*] DNS"); ips = run_adapter_safely(case, "dig", collect_dns, case, default=[]) or []
        if "crtsh" not in skip:
            print("[*] Certificate Transparency"); ct_hosts = run_adapter_safely(case, "crtsh", collect_crtsh, case, default=[]) or []
        if "live-tls" not in skip:
            print("[*] Live TLS validation"); run_adapter_safely(case, "live-tls", collect_live_tls, case, ct_hosts)
        if "wayback" not in skip:
            print("[*] Wayback CDX"); run_adapter_safely(case, "wayback", collect_wayback, case)
        if "urlscan" not in skip:
            print("[*] urlscan.io historical search"); run_adapter_safely(case, "urlscan", collect_urlscan, case)
        if "netlas" not in skip:
            print("[*] Netlas domain enrichment"); run_adapter_safely(case, "netlas", collect_netlas, case)
        if "virustotal" not in skip:
            print("[*] VirusTotal domain enrichment"); run_adapter_safely(case, "virustotal", collect_virustotal, case)
        if "robtex" not in skip:
            print("[*] Robtex passive DNS"); run_adapter_safely(case, "robtex", collect_robtex, case)
        if "censys" not in skip:
            print("[*] Censys host validation"); run_adapter_safely(case, "censys", collect_censys, case, ips)
        if not args.no_third_party_intel and "huntio" not in skip:
            print("[*] Hunt.io"); run_adapter_safely(case, "huntio", collect_huntio, case)
        if not args.no_third_party_intel and "shodan" not in skip:
            print("[*] Shodan"); run_adapter_safely(case, "shodan", collect_shodan, case, ips)
        if "sherlock" not in skip:
            print("[*] Sherlock"); run_adapter_safely(case, "sherlock", collect_sherlock, case, args.username)
    except KeyboardInterrupt:
        interrupted = True
        case.flags["partial_run"] = True
        case.flags["interrupted_by_user"] = True
        case.add_status("runner", "PARTIAL", case.domain, "Run interrupted by user; partial artifacts preserved")
        print("\n[!] Interrupted; preserving partial case artifacts", file=sys.stderr)
    finally:
        failures = int(case.metrics.get("adapter_failure_count", 0))
        if failures:
            case.flags["partial_run"] = True
        case.metrics["adapter_failure_count"] = failures
        try:
            case.save()
        except Exception as exc:
            print(f"[!] Finalization error: {type(exc).__name__}: {exc}", file=sys.stderr)
            return 3
    print(f"[+] Evidence: {len(case.evidence)} records")
    print(f"[+] Adapter failures isolated: {case.metrics.get('adapter_failure_count', 0)}")
    print(f"[+] Report: {case.root / 'report.md'}")
    return 130 if interrupted else 0


if __name__ == "__main__":
    raise SystemExit(main())
