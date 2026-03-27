#!/usr/bin/env python3
from __future__ import annotations
import argparse
import json
import os
import sys
import time
import re
import random
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse
from typing import Dict, Any, List, Optional, Set

import requests

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

try:
    from faker import Faker
    fake = Faker()
    FAKER_AVAILABLE = True
except ImportError:
    FAKER_AVAILABLE = False

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.prompt import Prompt, Confirm
    from rich.table import Table
    from rich.text import Text
    from rich.columns import Columns
    from rich.rule import Rule
    from rich.progress import (
        Progress, SpinnerColumn, BarColumn,
        TaskProgressColumn, TimeElapsedColumn,
        TextColumn, MofNCompleteColumn,
    )
    from rich import box
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

_NO_COLOR = bool(os.environ.get("NO_COLOR", ""))

def _c(code: str) -> str:
    return "" if _NO_COLOR else code

RESET   = _c("\033[0m")
GREEN   = _c("\033[32m")
YELLOW  = _c("\033[33m")
RED     = _c("\033[31m")
BLUE    = _c("\033[34m")
MAGENTA = _c("\033[35m")
CYAN    = _c("\033[36m")
BOLD    = _c("\033[1m")

_RAINBOW = [
    _c("\033[31m"), _c("\033[33m"), _c("\033[32m"),
    _c("\033[36m"), _c("\033[34m"), _c("\033[35m"),
]

ascii_art = r"""
███████╗██╗    ██╗ █████╗  ██████╗  ██████╗ ███████╗██████╗     ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ 
██╔════╝██║    ██║██╔══██╗██╔════╝ ██╔════╝ ██╔════╝██╔══██╗    ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
███████╗██║ █╗ ██║███████║██║  ███╗██║  ███╗█████╗  ██████╔╝    ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
╚════██║██║███╗██║██╔══██║██║   ██║██║   ██║██╔══╝  ██╔══██╗    ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
███████║╚███╔███╔╝██║  ██║╚██████╔╝╚██████╔╝███████╗██║  ██║    ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
╚══════╝ ╚══╝╚══╝ ╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚══════╝╚═╝  ╚═╝    ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
"""

def rainbow_text(text: str) -> str:
    if _NO_COLOR:
        return text
    out, idx = [], 0
    for ch in text:
        if ch not in (" ", "\n"):
            out.append(_RAINBOW[idx % len(_RAINBOW)] + ch)
            idx += 1
        else:
            out.append(ch)
    out.append(RESET)
    return "".join(out)

# Constants

DEFAULT_TIMEOUT      = 8.0
MAX_PROBE_RETRIES    = 2
RETRY_AFTER_DEFAULT  = 2

DUMMY_VALUES: Dict[str, str] = {
    "string": "test", "integer": 1, "number": 1.0,
    "boolean": True, "array": [], "object": {}, "file": "FILE",
}

INTERESTING_KEYWORDS = [
    r"\badmin\b", r"\bdebug\b", r"\binternal\b", r"\bupload\b",
    r"\btoken\b", r"\bauth\b",  r"\blogin\b",    r"\bcallback\b",
    r"\boauth\b", r"\bsecret\b",r"\bsecret_key\b",r"\bkey\b",
]

SENSITIVE_RESPONSE_PATTERNS = [
    r"password", r"passwd", r"secret", r"api[*-]?key",
    r"access[*-]?token", r"refresh[*-]?token", r"private[*-]?key",
    r"AWS_", r"BEGIN (RSA|EC|OPENSSH)", r"client[*-]?secret",
    r"auth[*-]?token", r"bearer",
]

METHOD_COLORS = {
    "GET":     "bold green",
    "POST":    "bold yellow",
    "PUT":     "bold cyan",
    "PATCH":   "bold magenta",
    "DELETE":  "bold red",
    "HEAD":    "bold blue",
    "OPTIONS": "bold white",
}

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}

# Fetch

def fetch_swagger(url: str, timeout: float = DEFAULT_TIMEOUT, proxies: Optional[Dict] = None) -> Dict[str, Any]:
    if url.startswith("file://"):
        path = url[len("file://"):]
        with open(path, "r", encoding="utf-8") as fh:
            raw = fh.read()
        if path.endswith((".yaml", ".yml")):
            if not YAML_AVAILABLE:
                raise RuntimeError("PyYAML required: pip install pyyaml")
            return yaml.safe_load(raw)
        return json.loads(raw)
    
    r = requests.get(url, timeout=timeout, proxies=proxies, verify=False)
    r.raise_for_status()
    ct = r.headers.get("content-type", "")
    if "yaml" in ct or url.rstrip("/").endswith((".yaml", ".yml")):
        if not YAML_AVAILABLE:
            raise RuntimeError("PyYAML required: pip install pyyaml")
        return yaml.safe_load(r.text)
    return r.json()

# Base-URL / Auth

def guess_base_url(swagger: Dict[str, Any], swagger_url: str) -> str:
    if "servers" in swagger and isinstance(swagger["servers"], list) and swagger["servers"]:
        url = swagger["servers"][0].get("url")
        if url:
            return url
    host     = swagger.get("host")
    schemes  = swagger.get("schemes", [])
    basePath = swagger.get("basePath", "/")
    if host:
        scheme = schemes[0] if schemes else (urlparse(swagger_url).scheme or "http")
        return f"{scheme}://{host}{basePath}"
    parsed = urlparse(swagger_url)
    return f"{parsed.scheme}://{parsed.netloc}"

def extract_auth_hints(swagger: Dict[str, Any]) -> List[str]:
    schemes: Dict = (
        swagger.get("components", {}).get("securitySchemes", {})
        or swagger.get("securityDefinitions", {})
    )
    hints = []
    for name, scheme in schemes.items():
        t = scheme.get("type", "")
        if t == "apiKey":
            hints.append(f"API key '{scheme.get('name')}' in {scheme.get('in')} (scheme: {name})")
        elif t == "http":
            hints.append(f"HTTP {scheme.get('scheme', 'auth')} (scheme: {name})")
        elif t == "oauth2":
            hints.append(f"OAuth2 flows {list(scheme.get('flows', {}).keys())} (scheme: {name})")
        elif t == "openIdConnect":
            hints.append(f"OpenID Connect: {scheme.get('openIdConnectUrl','?')} (scheme: {name})")
        else:
            hints.append(f"Unknown type '{t}' (scheme: {name})")
    return hints

# $ref resolution

def resolve_local_ref(root: Dict[str, Any], ref: str) -> Optional[Any]:
    if not ref or not ref.startswith("#/"):
        return None
    node = root
    try:
        for p in ref.lstrip("#/").split("/"):
            node = node[p]
        if isinstance(node, dict) and "$ref" in node:
            return resolve_local_ref(root, node["$ref"])
        return node
    except Exception:
        return None

def deep_resolve(node: Any, root: Dict[str, Any], seen: Optional[frozenset] = None) -> Any:
    if seen is None:
        seen = frozenset()
    if isinstance(node, dict):
        if "$ref" in node:
            ref = node["$ref"]
            if ref in seen:
                return node
            resolved = resolve_local_ref(root, ref)
            if resolved is None:
                return node
            merged = dict(resolved)
            for k, v in node.items():
                if k != "$ref":
                    merged[k] = deep_resolve(v, root, seen | {ref})
            return deep_resolve(merged, root, seen | {ref})
        return {k: deep_resolve(v, root, seen) for k, v in node.items()}
    elif isinstance(node, list):
        return [deep_resolve(x, root, seen) for x in node]
    return node

def expand_components_pathitems(swagger: Dict[str, Any]) -> None:
    paths     = swagger.setdefault("paths", {})
    comps     = swagger.get("components", {})
    pathitems = comps.get("pathItems", {}) if isinstance(comps, dict) else {}
    for k, v in pathitems.items():
        if k not in paths:
            paths[k] = v

def preprocess_swagger(swagger: Dict[str, Any]) -> Dict[str, Any]:
    expand_components_pathitems(swagger)
    return deep_resolve(swagger, swagger)

# Dummy-value generation

def choose_dummy_from_schema(schema: Optional[Dict[str, Any]]) -> Any:
    if not schema:
        return DUMMY_VALUES["string"]
    if "example" in schema:
        return schema["example"]
    if "default" in schema:
        return schema["default"]
    if "enum" in schema and isinstance(schema["enum"], list) and schema["enum"]:
        return schema["enum"][0]
    
    t   = schema.get("type")
    fmt = schema.get("format")
    pat = schema.get("pattern")
    
    if pat:
        return "1" if (r"\d" in pat or "[0-9]" in pat) else "test"
        
    if t == "string" or t is None:
        if FAKER_AVAILABLE:
            if fmt == "email": return fake.email()
            if fmt == "uuid": return fake.uuid4()
            if fmt == "date": return fake.date()
            if fmt == "date-time": return fake.iso8601()
            if fmt == "hostname": return fake.hostname()
            if fmt in ("uri", "url"): return fake.uri()
            if "name" in str(schema).lower(): return fake.name()
        
        return {
            "uuid": "00000000-0000-0000-0000-000000000000",
            "email": "test@example.com", "date": "2020-01-01",
            "date-time": "2020-01-01T00:00:00Z", "hostname": "example.com",
            "uri": "http://example.com/", "url": "http://example.com/",
            "binary": "dGVzdA==", "byte": "dGVzdA==",
        }.get(fmt, DUMMY_VALUES["string"])
        
    if t in ("integer", "number"):
        return 1
    if t == "boolean":
        return True
    if t == "array":
        return [choose_dummy_from_schema(schema.get("items", {}))]
    if t == "object":
        props = schema.get("properties", {})
        return {k: choose_dummy_from_schema(v) for k, v in list(props.items())[:3]} if props else {}
        
    return DUMMY_VALUES.get(str(t), DUMMY_VALUES["string"])

# Endpoint building

def build_example_path(path_template: str, parameters: List[Dict]) -> str:
    path = path_template
    for p in parameters or []:
        if p.get("in") == "path":
            name   = p.get("name")
            schema = p.get("schema") or (p.get("type") and {"type": p.get("type")})
            path   = path.replace("{" + name + "}", str(choose_dummy_from_schema(schema)))
    return path

def collect_parameters(operation: Dict, path_params: List[Dict]) -> List[Dict]:
    params: List[Dict] = list(path_params or [])
    params.extend(operation.get("parameters") or [])
    if "requestBody" in operation:
        rb      = operation["requestBody"]
        content = rb.get("content", {}) if isinstance(rb, dict) else {}
        media   = content.get("application/json") or next(iter(content.values()), None)
        schema  = media.get("schema") if media else None
        params.append({"in": "body", "name": "requestBody", "schema": schema or {}})
    return params

def tag_endpoint(path: str, method: str, summary: Optional[str]) -> List[str]:
    text = (path + " " + (summary or "")).lower()
    return [kw.strip(r"\b") for kw in INTERESTING_KEYWORDS if re.search(kw, text)]

def enumerate_swagger(swagger: Dict[str, Any], base_url: str, swagger_version: str) -> Dict[str, Any]:
    output: Dict[str, Any] = {"base": base_url, "endpoints": []}
    for path_template, path_item in swagger.get("paths", {}).items():
        if not isinstance(path_item, dict):
            continue
        path_level_params = path_item.get("parameters", [])
        for method in ("get", "post", "put", "delete", "patch", "head", "options"):
            if method not in path_item:
                continue
            op       = path_item[method] or {}
            params   = collect_parameters(op, path_level_params)
            ex_path  = build_example_path(path_template, params)
            full_url = urljoin(base_url.rstrip("/") + "/", ex_path.lstrip("/"))
            summary  = op.get("summary") or op.get("description")
            output["endpoints"].append({
                "path_template": path_template,
                "method":        method.upper(),
                "summary":       summary,
                "description":   op.get("description", ""),
                "parameters":    params,
                "url_example":   full_url,
                "tags":          tag_endpoint(path_template, method, summary),
                "security":      op.get("security"),
                "responses":     op.get("responses", {}),
            })
    return output

# Probing

def _scan_response_body(text: str) -> List[str]:
    return [pat for pat in SENSITIVE_RESPONSE_PATTERNS if re.search(pat, text, re.IGNORECASE)]

def conservative_probe(
    endpoint: Dict[str, Any],
    timeout: float,
    delay: float = 0.0,
    token: Optional[str] = None,
    proxies: Optional[Dict] = None,
    extra_headers: Optional[Dict[str, str]] = None,
    safe_mode: bool = False,
    test_unauth: bool = False,
) -> Dict[str, Any]:
    
    url, method = endpoint["url_example"], endpoint["method"]
    res = {
        "url": url, "method": method, "status": None,
        "headers": None, "snippet": None, "sensitive_hits": [], 
        "error": None, "skipped": False, "unauth_vuln": False
    }

    if safe_mode and method not in SAFE_METHODS:
        res["skipped"] = True
        return res

    if delay and delay > 0:
        time.sleep(delay + random.uniform(0, delay))

    hdrs: Dict[str, str] = {"Accept": "application/json"}
    if method not in ("GET", "HEAD", "OPTIONS"):
        hdrs["Content-Type"] = "application/json"
    if token:
        hdrs["Authorization"] = f"Bearer {token}"
    if extra_headers:
        hdrs.update(extra_headers)

    backoff = RETRY_AFTER_DEFAULT
    
    for attempt in range(MAX_PROBE_RETRIES + 1):
        try:
            if method in ("GET", "HEAD", "OPTIONS"):
                r = requests.request(method, url, headers=hdrs, timeout=timeout,
                                     allow_redirects=True, proxies=proxies, verify=False)
            else:
                body: Dict = {}
                for p in endpoint.get("parameters", []):
                    if p.get("in") in ("body", "formData"):
                        schema = p.get("schema") or (p.get("type") and {"type": p.get("type")})
                        body[p.get("name", "body")] = choose_dummy_from_schema(schema)
                r = requests.request(method, url, headers=hdrs, json=body or None,
                                     timeout=timeout, allow_redirects=False,
                                     proxies=proxies, verify=False)
            
            if r.status_code == 429 and attempt < MAX_PROBE_RETRIES:
                retry_hdr = r.headers.get("Retry-After")
                if retry_hdr and retry_hdr.isdigit():
                    time.sleep(int(retry_hdr))
                else:
                    time.sleep(backoff)
                    backoff *= 2
                continue
                
            snippet               = (r.text or "")[:800]
            res["status"]         = r.status_code
            res["headers"]        = dict(r.headers)
            res["snippet"]        = snippet
            res["sensitive_hits"] = _scan_response_body(snippet)
            
            # Unauthenticated Bypass Check
            if token and test_unauth and r.status_code < 400:
                hdrs_no_auth = {k: v for k, v in hdrs.items() if k.lower() != "authorization"}
                r_no = requests.request(method, url, headers=hdrs_no_auth, timeout=timeout, 
                                        allow_redirects=False, proxies=proxies, verify=False)
                if 200 <= r_no.status_code < 300:
                    res["unauth_vuln"] = True

            break
        except Exception as exc:
            res["error"] = str(exc)
            break
    return res

# Exports

def export_burp_xml(report: Dict[str, Any], filename: str) -> None:
    root_el = ET.Element("items")
    for ep in report["endpoints"]:
        item = ET.SubElement(root_el, "item")
        ET.SubElement(item, "method").text  = ep["method"]
        ET.SubElement(item, "path").text    = ep["path_template"]
        ET.SubElement(item, "url").text     = ep["url_example"]
        ET.SubElement(item, "summary").text = ep.get("summary") or ""
    ET.ElementTree(root_el).write(filename, encoding="utf-8", xml_declaration=True)

def export_postman(report: Dict[str, Any], filename: str,
                   collection_name: str = "SwaggerHunter Collection",
                   token: Optional[str] = None,
                   limit: int = 0,
                   methods: Optional[List[str]] = None) -> None:
    endpoints = report.get("endpoints", [])
    if methods:
        mu        = [m.upper() for m in methods]
        endpoints = [ep for ep in endpoints if ep.get("method", "").upper() in mu]
    if limit > 0:
        endpoints = endpoints[:limit]
    
    items = []
    for ep in endpoints:
        url    = ep["url_example"]
        parsed = urlparse(url)
        pm_url = {
            "raw":   url,
            "host":  [parsed.scheme + "://" + parsed.netloc],
            "path":  parsed.path.lstrip("/").split("/") if parsed.path else [],
            "query": [],
        }
        for p in ep.get("parameters", []):
            if p.get("in") == "query":
                pm_url["query"].append({
                    "key":   p.get("name"),
                    "value": str(choose_dummy_from_schema(p.get("schema") or {})),
                })
        req: Dict[str, Any] = {
            "name": f"{ep['method']} {ep['path_template']}",
            "request": {"method": ep["method"], "header": [], "url": pm_url},
        }
        if token:
            req["request"]["header"].append({"key": "Authorization", "value": f"Bearer {token}"})
        if ep.get("summary"):
            req["request"]["description"] = ep["summary"]
        items.append(req)
        
    collection = {
        "info": {
            "name":   collection_name,
            "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
        },
        "item": items,
    }
    with open(filename, "w", encoding="utf-8") as fh:
        json.dump(collection, fh, indent=2)


# CLI helpers
def color_for_method(m: str) -> str:
    return {"GET": GREEN, "POST": YELLOW, "PATCH": CYAN,
            "PUT": CYAN, "DELETE": RED}.get(m, MAGENTA)

def clean_html(s: str) -> str:
    if not s:
        return ""
    s = re.sub(r"(?i)<br\s*/?>", "\n", s)
    return re.sub(r"<[^>]+>", "", s).strip()

def parse_extra_headers(raw: Optional[List[str]]) -> Dict[str, str]:
    result: Dict[str, str] = {}
    for entry in raw or []:
        if ":" in entry:
            k, _, v = entry.partition(":")
            result[k.strip()] = v.strip()
    return result

def parse_range_selection(raw: str, max_idx: int) -> Set[int]:
    indices: Set[int] = set()
    for part in raw.split(","):
        part = part.strip()
        if "-" in part:
            try:
                lo, hi = part.split("-", 1)
                for i in range(int(lo.strip()), int(hi.strip()) + 1):
                    if 1 <= i <= max_idx:
                        indices.add(i)
            except ValueError:
                pass
        else:
            try:
                i = int(part)
                if 1 <= i <= max_idx:
                    indices.add(i)
            except ValueError:
                pass
    return indices

def pretty_print_summary(report: Dict[str, Any], limit: int = 50) -> None:
    n = len(report["endpoints"])
    print(f"[*] Found {n} endpoints (templates).")
    for i, e in enumerate(report["endpoints"][:limit], 1):
        col    = color_for_method(e["method"])
        tagstr = f" [{','.join(e['tags'])}]" if e.get("tags") else ""
        print(f"{i:03d}. {col}{e['method']:6}{RESET} {e['path_template']} -> {e['url_example']}{tagstr}")

def pretty_print_verbose(report: Dict[str, Any], limit: int = 50) -> None:
    n = len(report["endpoints"])
    print(f"[*] Found {n} endpoints (templates). Verbose:")
    for i, e in enumerate(report["endpoints"][:limit], 1):
        col = color_for_method(e["method"])
        print(f"{BOLD}{i:03d}. {col}{e['method']}{RESET} {BOLD}{e['path_template']}{RESET}")
        if e.get("summary"):
            print(f"  {BLUE}summary:{RESET}     {clean_html(e['summary'])}")
        if e.get("description"):
            print(f"  {CYAN}description:{RESET} {clean_html(e['description'])[:200]}")
        if e.get("tags"):
            print(f"  {YELLOW}tags:{RESET}        {', '.join(e['tags'])}")
        print()

# TUI widget builders

def _method_badge(method: str) -> Text:
    style = METHOD_COLORS.get(method, "bold white")
    return Text(f" {method:<7}", style=style)

def _status_style(status: Optional[int]) -> str:
    if status is None:
        return "dim"
    if 200 <= status < 300:
        return "bold green"
    if 300 <= status < 400:
        return "bold yellow"
    if 400 <= status < 500:
        return "bold red"
    if 500 <= status < 600:
        return "bold magenta"
    return "white"

def build_endpoint_table(
    endpoints: List[Dict[str, Any]],
    scope_indices: Optional[Set[int]] = None,
    keyword: str = "",
    title: str = "Endpoints",
    max_rows: int = 40,
    start_idx: int = 1,
) -> Table:
    show_scope = scope_indices is not None
    tbl = Table(
        title=title, box=box.SIMPLE_HEAVY, show_lines=True,
        header_style="bold cyan", border_style="bright_black",
        title_style="bold cyan", expand=False,
    )
    tbl.add_column("#",       style="dim",       width=5,  justify="right")
    if show_scope:
        tbl.add_column("✓",   width=3,  justify="center")
    tbl.add_column("Method",  no_wrap=True,       width=9)
    tbl.add_column("Path",    style="cyan",       min_width=30, overflow="fold")
    tbl.add_column("Tags",    style="yellow dim", width=20, overflow="fold")
    tbl.add_column("Summary", style="dim",        min_width=20, overflow="fold")

    shown = 0
    for abs_i, ep in enumerate(endpoints, start_idx):
        if shown >= max_rows:
            break
        if keyword:
            haystack = (ep["path_template"] + " " + (ep.get("summary") or "")).lower()
            if keyword.lower() not in haystack:
                continue
        in_scope   = (scope_indices is not None) and (abs_i in scope_indices)
        scope_mark = "[green]●[/green]" if in_scope else "[bright_black]○[/bright_black]"
        row_vals   = [str(abs_i)]
        if show_scope:
            row_vals.append(scope_mark)
        row_vals.extend([
            _method_badge(ep["method"]),
            ep["path_template"],
            ", ".join(ep.get("tags", [])) or "—",
            (clean_html(ep.get("summary") or ""))[:55] or "—",
        ])
        tbl.add_row(*row_vals)
        shown += 1
    return tbl

def build_drill_panel(ep: Dict[str, Any], idx: int) -> Panel:
    method = ep["method"]
    badge  = METHOD_COLORS.get(method, "white")
    lines: List[str] = [
        f"[{badge}]{method}[/{badge}]  [bold cyan]{ep['path_template']}[/bold cyan]",
        "",
    ]
    if ep.get("summary"):
        lines.append(f"[bold]Summary:[/bold]      {clean_html(ep['summary'])}")
    if ep.get("description"):
        desc = clean_html(ep["description"])
        if desc and desc != clean_html(ep.get("summary") or ""):
            lines.append(f"[bold]Description:[/bold]  {desc[:300]}")
    if ep.get("tags"):
        lines.append(f"[bold]Tags:[/bold]         [yellow]{', '.join(ep['tags'])}[/yellow]")
    sec = ep.get("security")
    if sec is not None:
        lines.append(f"[bold]Security:[/bold]     {sec if sec else '[dim]none / open endpoint[/dim]'}")
    lines.append(f"\n[bold]Full URL:[/bold]\n  [blue underline]{ep['url_example']}[/blue underline]")

    # Parameters
    params      = [p for p in (ep.get("parameters") or []) if p.get("in") != "body"]
    body_params = [p for p in (ep.get("parameters") or []) if p.get("in") == "body"]
    if params:
        lines.append("\n[bold]Parameters:[/bold]")
        for p in params:
            loc      = p.get("in", "?")
            name     = p.get("name", "?")
            schema   = p.get("schema") or {}
            ptype    = schema.get("type", p.get("type", "string"))
            required = "[red]*[/red]" if p.get("required") else " "
            desc     = (p.get("description") or "")[:55]
            lines.append(
                f"  {required} [cyan]{name}[/cyan]  [dim]({loc}, {ptype})[/dim]"
                + (f"  — {desc}" if desc else "")
            )
    if body_params:
        lines.append("\n[bold]Request Body:[/bold]")
        props = body_params[0].get("schema", {}).get("properties", {})
        if props:
            for pname, pschema in list(props.items())[:10]:
                ptype = pschema.get("type", "?")
                lines.append(f"  [cyan]{pname}[/cyan]  [dim]({ptype})[/dim]")
        else:
            lines.append("  [dim](no schema properties declared)[/dim]")

    # Responses
    responses = ep.get("responses", {})
    if responses:
        lines.append("\n[bold]Declared Responses:[/bold]")
        for code, rdata in list(responses.items())[:6]:
            rdesc  = (rdata.get("description", "") if isinstance(rdata, dict) else "")[:55]
            cstyle = _status_style(int(code) if str(code).isdigit() else None)
            lines.append(f"  [{cstyle}]{code}[/{cstyle}]  [dim]{rdesc}[/dim]")

    return Panel(
        "\n".join(lines),
        title=f"[bold cyan] Endpoint #{idx} Detail [/bold cyan]",
        border_style="cyan",
        padding=(1, 3),
    )

def build_probe_summary_panel(probe_results: List[Dict]) -> Panel:
    ok         = sum(1 for p in probe_results if p["result"].get("status") and 200 <= p["result"]["status"] < 300)
    redirects  = sum(1 for p in probe_results if p["result"].get("status") and 300 <= p["result"]["status"] < 400)
    client_err = sum(1 for p in probe_results if p["result"].get("status") and 400 <= p["result"]["status"] < 500)
    server_err = sum(1 for p in probe_results if p["result"].get("status") and 500 <= p["result"]["status"] < 600)
    errors     = sum(1 for p in probe_results if p["result"].get("error"))
    sens_count = sum(1 for p in probe_results if p["result"].get("sensitive_hits"))
    skipped    = sum(1 for p in probe_results if p["result"].get("skipped"))
    unauth     = sum(1 for p in probe_results if p["result"].get("unauth_vuln"))

    tbl = Table(box=box.SIMPLE, show_header=False, padding=(0, 3))
    tbl.add_column(justify="right", style="bold")
    tbl.add_column()
    tbl.add_row("[green]2xx OK[/green]",                str(ok))
    tbl.add_row("[yellow]3xx Redirect[/yellow]",        str(redirects))
    tbl.add_row("[red]4xx Client error[/red]",          str(client_err))
    tbl.add_row("[magenta]5xx Server error[/magenta]",  str(server_err))
    
    if skipped:
        tbl.add_row("[dim]Skipped (Safe Mode)[/dim]",   str(skipped))
    if errors:
        tbl.add_row("[dim]Connection errors[/dim]",     str(errors))
    if unauth:
        tbl.add_row("[bold red]  Unauth Bypass[/bold red]", str(unauth))
    if sens_count:
        tbl.add_row("[bold red]  Sensitive hits[/bold red]", str(sens_count))

    return Panel(
        tbl,
        title="[bold cyan] Probe Summary [/bold cyan]",
        border_style="cyan",
        padding=(0, 2),
    )

# Interactive TUI

def interactive_tui() -> None:
    if not RICH_AVAILABLE:
        print(f"{RED}[!] Interactive mode requires 'rich': pip install rich{RESET}")
        sys.exit(1)

    print(rainbow_text(ascii_art))
    console = Console()

    console.print(Panel.fit(
        "[bold cyan]SwaggerHunter[/bold cyan]  [yellow dim]v2.5[/yellow dim]\n"
        "[dim]Interactive Swagger / OpenAPI Recon & Analysis[/dim]",
        border_style="cyan",
        padding=(0, 6),
    ))

    console.print()
    swagger_url = Prompt.ask("[bold cyan]>[/bold cyan] Swagger/OpenAPI URL [dim](or file:/// path)[/dim]")
    if not swagger_url.strip():
        console.print("[red]URL is required.[/red]")
        sys.exit(1)

    proxy_raw = Prompt.ask(
        "[bold cyan]>[/bold cyan] HTTP proxy [dim](optional — Enter to skip)[/dim]",
        default="",
    )
    proxies = {"http": proxy_raw, "https": proxy_raw} if proxy_raw else None

    console.print()
    with console.status("[cyan]Fetching specification…[/cyan]", spinner="dots"):
        try:
            swagger = fetch_swagger(swagger_url, timeout=DEFAULT_TIMEOUT, proxies=proxies)
        except Exception as e:
            console.print(f"[red]✗ Failed to fetch:[/red] {e}")
            sys.exit(2)

    version    = swagger.get("openapi") or swagger.get("swagger", "unknown")
    base       = guess_base_url(swagger, swagger_url)
    auth_hints = extract_auth_hints(swagger)

    info_lines = [
        f"[bold]Version :[/bold]  [yellow]{version}[/yellow]",
        f"[bold]Base URL:[/bold]  [blue]{base}[/blue]",
    ]
    if auth_hints:
        for h in auth_hints[:3]:
            info_lines.append(f"[bold]Auth    :[/bold]  [yellow]{h}[/yellow]")
    if proxy_raw:
        info_lines.append(f"[bold]Proxy   :[/bold]  [dim]{proxy_raw}[/dim]")
    
    if FAKER_AVAILABLE:
        info_lines.append("[bold]Faker   :[/bold]  [green]Active (Realistic Payloads)[/green]")

    console.print(Panel(
        "\n".join(info_lines),
        title="[bold cyan] Specification [/bold cyan]",
        border_style="bright_black",
        padding=(0, 2),
    ))

    with console.status("[cyan]Resolving $refs and enumerating paths…[/cyan]", spinner="dots"):
        try:
            swagger_resolved = preprocess_swagger(swagger)
        except Exception as e:
            console.print(f"[yellow] $ref warning: {e}[/yellow]")
            swagger_resolved = swagger
        report = enumerate_swagger(swagger_resolved, base, version)

    total = len(report["endpoints"])
    console.print(f"\n[green]✓[/green] Discovered [bold]{total}[/bold] endpoints\n")

    scope_indices:  Set[int]   = set(range(1, total + 1)) 
    active_keyword: str        = ""
    probe_results:  List[Dict] = []

    while True:
        if active_keyword:
            visible_eps = [
                ep for ep in report["endpoints"]
                if active_keyword.lower() in
                   (ep["path_template"] + " " + (ep.get("summary") or "")).lower()
            ]
            tbl_title = (
                f"Endpoints  [yellow]🔍 '{active_keyword}'[/yellow]"
                f"  [dim]({len(visible_eps)}/{total} match)[/dim]"
            )
        else:
            visible_eps = report["endpoints"]
            tbl_title   = f"Endpoints  [dim]({total} total)[/dim]"

        console.print(build_endpoint_table(
            visible_eps,
            scope_indices=scope_indices,
            title=tbl_title,
            max_rows=40,
        ))

        in_scope_n = len(scope_indices)
        status_parts = [
            f"[green]●[/green] [bold]{in_scope_n}[/bold] in scope",
            f"[bright_black]○[/bright_black] [dim]{total - in_scope_n}[/dim] excluded",
        ]
        if active_keyword:
            status_parts.append(f"[yellow]🔍 filter: '{active_keyword}'[/yellow]")
        if probe_results:
            status_parts.append(f"[cyan]⚡ {len(probe_results)} probed[/cyan]")
        console.print("  " + "   ".join(status_parts))

        console.print()
        console.print(Rule("[bold cyan]Actions[/bold cyan]", style="bright_black"))
        menu = Columns([
            "[cyan]1[/cyan] Probe in-scope",
            "[cyan]2[/cyan] Filter by keyword",
            "[cyan]3[/cyan] View endpoint detail",
            "[cyan]4[/cyan] Manage scope",
            "[cyan]5[/cyan] Export JSON",
            "[cyan]6[/cyan] Export Postman",
            "[cyan]7[/cyan] Export Burp XML",
            "[cyan]8[/cyan] Clear filter",
            "[cyan]9[/cyan] Exit",
        ], equal=True, expand=True)
        console.print(menu)
        console.print()

        choice = Prompt.ask(
            "[bold cyan]>[/bold cyan] Action",
            choices=[str(i) for i in range(1, 10)],
            default="9",
        )

        if choice == "1":
            token       = Prompt.ask("\n[bold cyan]>[/bold cyan] Bearer token [dim](optional — Enter to skip)[/dim]", default="")
            test_unauth = False
            if token:
                test_unauth = Confirm.ask("[bold cyan]>[/bold cyan] Test for unauthenticated bypass? (Removes token & verifies access)", default=False)
            
            safe_mode   = Confirm.ask("[bold cyan]>[/bold cyan] Enable Safe Mode? (Skip POST/PUT/DELETE)", default=True)
            concurrency = int(Prompt.ask("[bold cyan]>[/bold cyan] Threads", default="5"))
            delay       = float(Prompt.ask("[bold cyan]>[/bold cyan] Delay per request (seconds)", default="0.1"))
            hdr_raw     = Prompt.ask(
                "[bold cyan]>[/bold cyan] Extra headers [dim](KEY:VAL,KEY2:VAL2 or Enter)[/dim]",
                default="",
            )
            
            extra_hdrs: Dict[str, str] = {}
            if hdr_raw:
                for pair in hdr_raw.split(","):
                    if ":" in pair:
                        k, _, v = pair.partition(":")
                        extra_hdrs[k.strip()] = v.strip()

            eps_to_probe = [
                ep for i, ep in enumerate(report["endpoints"], 1)
                if i in scope_indices
            ]
            if not eps_to_probe:
                console.print("[yellow] No in-scope endpoints.[/yellow]")
                continue

            console.print(
                f"\n[yellow]→[/yellow] Probing [bold]{len(eps_to_probe)}[/bold] in-scope endpoints"
                + (f" via [dim]{proxy_raw}[/dim]" if proxy_raw else "") + "\n"
            )

            probe_results = []
            sensitive_eps: List[Dict] = []
            unauth_eps: List[Dict] = []

            with Progress(
                SpinnerColumn(style="cyan"),
                TextColumn("[dim]{task.description}[/dim]"),
                BarColumn(bar_width=38, style="bright_black", complete_style="cyan"),
                MofNCompleteColumn(),
                TaskProgressColumn(),
                TimeElapsedColumn(),
                console=console,
                transient=False,
            ) as progress:
                task = progress.add_task("Starting…", total=len(eps_to_probe))

                with ThreadPoolExecutor(max_workers=concurrency) as ex:
                    futures = {
                        ex.submit(
                            conservative_probe, ep, DEFAULT_TIMEOUT, delay,
                            token or None, proxies, extra_hdrs or None, safe_mode, test_unauth
                        ): ep
                        for ep in eps_to_probe
                    }
                    try:
                        for fut in as_completed(futures):
                            ep = futures[fut]
                            try:
                                r = fut.result()
                            except Exception as exc:
                                r = {"url": ep.get("url_example"),
                                     "method": ep.get("method"), "error": str(exc), "skipped": False}
                            probe_results.append({"endpoint": ep, "result": r})

                            status = r.get("status")
                            meth   = r.get("method") or ep.get("method")
                            url    = r.get("url") or ep.get("url_example")
                            hits   = r.get("sensitive_hits", [])
                            short  = (url[:55] + "…") if len(url or "") > 55 else (url or "")
                            
                            if r.get("skipped"):
                                st_str = "SKIP"
                                sty = "dim"
                            else:
                                st_str = str(status) if status else "ERR"
                                sty    = _status_style(status)

                            progress.update(
                                task, advance=1,
                                description=f"[{sty}]{st_str}[/{sty}]  {meth} {short}",
                            )
                            if hits:
                                sensitive_eps.append({"endpoint": ep, "result": r})
                            if r.get("unauth_vuln"):
                                unauth_eps.append({"endpoint": ep, "result": r})
                    except KeyboardInterrupt:
                        console.print(f"\n[yellow] Interrupted.[/yellow]")

            console.print()
            console.print(build_probe_summary_panel(probe_results))

            if unauth_eps:
                console.print("\n[bold red] Unauthenticated Access Vulnerabilities Detected:[/bold red]")
                for item in unauth_eps:
                    ep  = item["endpoint"]
                    mc  = METHOD_COLORS.get(ep["method"], "white")
                    console.print(
                        f"  [red]•[/red] [{mc}]{ep['method']}[/{mc}] [cyan]{ep['path_template']}[/cyan] "
                        f"[dim](Bypassed Auth successfully)[/dim]"
                    )

            if sensitive_eps:
                console.print("\n[bold red] Sensitive data patterns detected:[/bold red]")
                for item in sensitive_eps:
                    ep  = item["endpoint"]
                    res = item["result"]
                    mc  = METHOD_COLORS.get(ep["method"], "white")
                    console.print(
                        f"  [red]•[/red] [[{_status_style(res['status'])}]{res['status']}[/{_status_style(res['status'])}]]"
                        f"  [{mc}]{ep['method']}[/{mc}]  [cyan]{ep['path_template']}[/cyan]"
                        f"  [dim]→[/dim]  [red]{res['sensitive_hits']}[/red]"
                    )

            console.print()
            if Confirm.ask("[bold cyan]>[/bold cyan] Save probe results to JSON?", default=False):
                fn = Prompt.ask("Filename", default="probe_results.json")
                with open(fn, "w", encoding="utf-8") as fh:
                    json.dump({"endpoints": eps_to_probe, "probe_results": probe_results}, fh, indent=2)
                console.print(f"[green]✓[/green] Saved → [cyan]{fn}[/cyan]")
            continue

        elif choice == "2":
            kw = Prompt.ask(
                "\n[bold cyan]>[/bold cyan] Filter keyword [dim](searches path + summary)[/dim]",
                default="",
            )
            active_keyword = kw.strip()
            if active_keyword:
                matches = sum(
                    1 for ep in report["endpoints"]
                    if active_keyword.lower() in
                       (ep["path_template"] + " " + (ep.get("summary") or "")).lower()
                )
                console.print(
                    f"[green]✓[/green] Filter [yellow]'{active_keyword}'[/yellow]"
                    f" — [bold]{matches}[/bold] of {total} endpoints match"
                )
            else:
                console.print("[dim]Filter cleared.[/dim]")
            continue

        elif choice == "3":
            raw = Prompt.ask(
                f"\n[bold cyan]>[/bold cyan] Endpoint number [dim](1–{total})[/dim]",
                default="1",
            )
            try:
                idx = int(raw.strip())
                if not (1 <= idx <= total):
                    raise ValueError
                console.print()
                console.print(build_drill_panel(report["endpoints"][idx - 1], idx))
            except (ValueError, IndexError):
                console.print(f"[red]Enter a number between 1 and {total}.[/red]")
            continue

        elif choice == "4":
            console.print(
                f"\n[bold]Scope:[/bold] [green]{len(scope_indices)}[/green] in-scope  "
                f"[dim]{total - len(scope_indices)} excluded[/dim]\n"
            )
            console.print(Panel(
                "[dim]Commands:[/dim]\n"
                "  [cyan bold]all[/cyan bold]        — mark all endpoints in scope\n"
                "  [cyan bold]none[/cyan bold]       — clear scope entirely\n"
                "  [cyan bold]+1,3,5-8[/cyan bold]   — add to scope\n"
                "  [cyan bold]-2,4[/cyan bold]       — remove from scope\n"
                "  [cyan bold]=1,5,10-15[/cyan bold] — set scope to exactly these\n"
                "  [cyan bold]1,3,7[/cyan bold]      — toggle individual endpoints\n"
                "  [dim]Enter[/dim]       — keep current scope unchanged",
                title="[bold cyan] Scope Help [/bold cyan]",
                border_style="bright_black",
                padding=(0, 2),
            ))

            scope_tbl = Table(box=box.MINIMAL, show_header=False, padding=(0, 1))
            scope_tbl.add_column(width=5, justify="right", style="dim")
            scope_tbl.add_column(width=3, justify="center")
            scope_tbl.add_column(min_width=50)
            for i, ep in enumerate(report["endpoints"][:35], 1):
                mark = "[green]●[/green]" if i in scope_indices else "[bright_black]○[/bright_black]"
                mc   = METHOD_COLORS.get(ep["method"], "white")
                scope_tbl.add_row(
                    str(i), mark,
                    f"[{mc}]{ep['method']}[/{mc}]  [cyan]{ep['path_template']}[/cyan]"
                    + (f"  [dim]{(ep.get('summary') or '')[:35]}[/dim]" if ep.get("summary") else ""),
                )
            if total > 35:
                scope_tbl.add_row("…", "…", f"[dim]…and {total - 35} more[/dim]")
            console.print(scope_tbl)

            cmd = Prompt.ask("\n[bold cyan]>[/bold cyan] Command", default="").strip()
            if not cmd:
                pass
            elif cmd.lower() == "all":
                scope_indices = set(range(1, total + 1))
                console.print(f"[green]✓[/green] All {total} endpoints in scope.")
            elif cmd.lower() == "none":
                scope_indices = set()
                console.print("[yellow] Scope cleared.[/yellow]")
            elif cmd.startswith("+"):
                added = parse_range_selection(cmd[1:], total)
                scope_indices |= added
                console.print(f"[green]✓[/green] Added {len(added)}. Scope: {len(scope_indices)}")
            elif cmd.startswith("-"):
                removed = parse_range_selection(cmd[1:], total)
                scope_indices -= removed
                console.print(f"[yellow]✓[/yellow] Removed {len(removed)}. Scope: {len(scope_indices)}")
            elif cmd.startswith("="):
                scope_indices = parse_range_selection(cmd[1:], total)
                console.print(f"[green]✓[/green] Scope set to {len(scope_indices)} endpoints.")
            else:
                toggled = parse_range_selection(cmd, total)
                for idx in toggled:
                    if idx in scope_indices:
                        scope_indices.discard(idx)
                    else:
                        scope_indices.add(idx)
                console.print(f"[cyan]✓[/cyan] Toggled {len(toggled)}. Scope: {len(scope_indices)}")
            continue

        elif choice == "5":
            fn         = Prompt.ask("\n[bold cyan]>[/bold cyan] JSON filename", default="endpoints.json")
            scoped_eps = [ep for i, ep in enumerate(report["endpoints"], 1) if i in scope_indices]
            with open(fn, "w", encoding="utf-8") as fh:
                json.dump({"endpoints": scoped_eps}, fh, indent=2)
            console.print(f"[green]✓[/green] Exported [bold]{len(scoped_eps)}[/bold] endpoints → [cyan]{fn}[/cyan]")
            continue

        elif choice == "6":
            fn         = Prompt.ask("\n[bold cyan]>[/bold cyan] Postman filename", default="collection.json")
            token      = Prompt.ask("[bold cyan]>[/bold cyan] Bearer token [dim](optional)[/dim]", default="")
            scoped_eps = [ep for i, ep in enumerate(report["endpoints"], 1) if i in scope_indices]
            export_postman({"endpoints": scoped_eps}, fn, token=token or None)
            console.print(f"[green]✓[/green] Exported [bold]{len(scoped_eps)}[/bold] endpoints → [cyan]{fn}[/cyan]")
            continue

        elif choice == "7":
            fn         = Prompt.ask("\n[bold cyan]>[/bold cyan] Burp XML filename", default="burp_sitemap.xml")
            scoped_eps = [ep for i, ep in enumerate(report["endpoints"], 1) if i in scope_indices]
            export_burp_xml({"endpoints": scoped_eps}, fn)
            console.print(f"[green]✓[/green] Exported [bold]{len(scoped_eps)}[/bold] endpoints → [cyan]{fn}[/cyan]")
            continue

        elif choice == "8":
            active_keyword = ""
            console.print("[dim]Filter cleared.[/dim]")
            continue

        elif choice == "9":
            console.print("\n[dim cyan]Goodbye.[/dim cyan]\n")
            return

# CLI entry-point

def main() -> None:
    if len(sys.argv) == 1:
        interactive_tui()
        return

    print(rainbow_text(ascii_art))

    parser = argparse.ArgumentParser(description="SwaggerHunter v2.5 — Swagger/OpenAPI enumerator + probe")
    parser.add_argument("-u", "--url", required=True)
    parser.add_argument("--probe",       action="store_true")
    parser.add_argument("--safe-mode",   action="store_true", help="Skip destructive HTTP methods during probe")
    parser.add_argument("--test-unauth", action="store_true", help="Test for unauthenticated bypasses (if --token provided)")
    parser.add_argument("-o", "--output")
    parser.add_argument("--timeout",     type=float, default=DEFAULT_TIMEOUT)
    parser.add_argument("--limit",       type=int,   default=0)
    parser.add_argument("--concurrency", type=int,   default=5)
    parser.add_argument("--delay",       type=float, default=0.1)
    parser.add_argument("--burp")
    parser.add_argument("--postman")
    parser.add_argument("--summary",     action="store_true")
    parser.add_argument("--verbose",     action="store_true")
    parser.add_argument("--show-all",    action="store_true")
    parser.add_argument("--token")
    parser.add_argument("--method")
    parser.add_argument("--proxy")
    parser.add_argument("--header", action="append", dest="headers", metavar="KEY:VALUE")
    args = parser.parse_args()

    proxies       = {"http": args.proxy, "https": args.proxy} if args.proxy else None
    extra_headers = parse_extra_headers(args.headers)

    if proxies:
        print(f"[*] Proxy: {args.proxy}")
    if extra_headers:
        print(f"[*] Custom headers: {extra_headers}")

    print(f"[*] Fetching specification from: {args.url}")
    try:
        swagger = fetch_swagger(args.url, timeout=args.timeout, proxies=proxies)
    except Exception as e:
        print(f"{RED}[!] Failed:{RESET} {e}")
        sys.exit(2)

    version = swagger.get("openapi") or swagger.get("swagger", "")
    base    = guess_base_url(swagger, args.url)
    print(f"[*] Version: {version}  |  Base: {base}")

    for hint in extract_auth_hints(swagger):
        print(f"[*] Auth: {YELLOW}{hint}{RESET}")

    try:
        swagger_resolved = preprocess_swagger(swagger)
    except Exception as e:
        print(f"{YELLOW}[!] $ref warning: {e}{RESET}")
        swagger_resolved = swagger

    report        = enumerate_swagger(swagger_resolved, base, version)
    limit_display = 9999 if args.show_all else 50

    if args.verbose:
        pretty_print_verbose(report, limit=limit_display)
    else:
        pretty_print_summary(report, limit=limit_display)

    endpoints_filtered = report["endpoints"]
    if args.method:
        allowed            = [m.strip().upper() for m in args.method.split(",")]
        endpoints_filtered = [ep for ep in endpoints_filtered
                               if ep.get("method", "").upper() in allowed]
        print(f"[*] Method filter: {', '.join(allowed)}  ({len(report['endpoints'])} → {len(endpoints_filtered)})")
    if args.limit > 0:
        endpoints_filtered = endpoints_filtered[:args.limit]

    filtered_report = {"endpoints": endpoints_filtered}

    if args.burp:
        try:
            export_burp_xml(filtered_report, args.burp)
            print(f"[*] Burp XML → {args.burp}")
        except Exception as e:
            print(f"{YELLOW}[!] Burp XML failed: {e}{RESET}")

    if args.postman:
        try:
            export_postman(filtered_report, args.postman, token=args.token)
            print(f"[*] Postman → {args.postman}")
        except Exception as e:
            print(f"{RED}[!] Postman failed: {e}{RESET}")

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as fh:
                json.dump(filtered_report, fh, indent=2)
            print(f"[*] JSON report → {args.output}")
        except Exception as e:
            print(f"{RED}[!] JSON write failed: {e}{RESET}")
    else:
        print("[*] No -o specified. Use -o to save results.")

    if args.probe:
        print(f"[*] Probing endpoints (Safe Mode: {'ON' if args.safe_mode else 'OFF'}).")
        probe_results: List[Dict] = []
        with ThreadPoolExecutor(max_workers=max(1, args.concurrency)) as ex:
            futures = {
                ex.submit(
                    conservative_probe, ep, args.timeout, args.delay,
                    args.token, proxies, extra_headers or None, args.safe_mode, args.test_unauth
                ): ep
                for ep in endpoints_filtered
            }
            try:
                for fut in as_completed(futures):
                    ep = futures[fut]
                    try:
                        r = fut.result()
                    except Exception as exc:
                        r = {"url": ep.get("url_example"), "method": ep.get("method"),
                             "error": str(exc), "skipped": False}
                    probe_results.append({"endpoint": ep, "result": r})
                    status  = r.get("status")
                    skipped = r.get("skipped")
                    url     = r.get("url") or ep.get("url_example")
                    meth    = r.get("method") or ep.get("method")
                    hits    = r.get("sensitive_hits", [])
                    unauth  = r.get("unauth_vuln")
                    
                    if skipped:
                        print(f"{BOLD}[SKIP]{RESET} {meth} {url} (Safe Mode)")
                        continue
                        
                    col = (GREEN  if status and 200 <= status < 300 else
                           YELLOW if status and 300 <= status < 400 else
                           RED    if status and 400 <= status < 600 else MAGENTA)
                    
                    if status is None:
                        print(f"{RED}[!] {meth} {url} → {r.get('error')}{RESET}")
                    else:
                        sens = f"  {RED} {hits}{RESET}" if hits else ""
                        vuln = f"  {RED} UNAUTH BYPASS{RESET}" if unauth else ""
                        print(f"{col}[{status}] {meth} {url}{RESET}{sens}{vuln}")
            except KeyboardInterrupt:
                print(f"\n{YELLOW}[!] Interrupted.[/RESET]")

        ok         = sum(1 for p in probe_results if p["result"].get("status") and 200 <= p["result"]["status"] < 300)
        redirects  = sum(1 for p in probe_results if p["result"].get("status") and 300 <= p["result"]["status"] < 400)
        client_err = sum(1 for p in probe_results if p["result"].get("status") and 400 <= p["result"]["status"] < 500)
        server_err = sum(1 for p in probe_results if p["result"].get("status") and 500 <= p["result"]["status"] < 600)
        sens_count = sum(1 for p in probe_results if p["result"].get("sensitive_hits"))
        skip_count = sum(1 for p in probe_results if p["result"].get("skipped"))
        print(
            f"[*] Probe summary: {GREEN}{ok} OK{RESET}, {YELLOW}{redirects} redirects{RESET}, "
            f"{RED}{client_err} client errs{RESET}, {RED}{server_err} server errs{RESET}, {BOLD}{skip_count} skipped{RESET}"
            + (f", {RED}{sens_count} sensitive{RESET}" if sens_count else "")
        )
        report["probe_results"] = probe_results

if __name__ == "__main__":
    main()
