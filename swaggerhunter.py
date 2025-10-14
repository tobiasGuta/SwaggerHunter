#!/usr/bin/env python3

from __future__ import annotations
import argparse
import json
import requests
import sys
import time
import re
import random
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse
from typing import Dict, Any, List, Optional

# ANSI colors (works on most *nix terminals and modern Windows terminals)
RESET = "\033[0m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
RED = "\033[31m"
BLUE = "\033[34m"
MAGENTA = "\033[35m"
CYAN = "\033[36m"
BOLD = "\033[1m"

DEFAULT_TIMEOUT = 8.0
DUMMY_VALUES = {
    'string': 'test',
    'integer': '1',
    'number': '1',
    'boolean': 'true',
    'array': '[]',
    'object': '{}',
    'file': 'FILE',
}

INTERESTING_KEYWORDS = [
    r'\badmin\b', r'\bdebug\b', r'\binternal\b', r'\bupload\b',
    r'\btoken\b', r'\bauth\b', r'\blogin\b', r'\bcallback\b',
    r'\boauth\b', r'\bsecret\b', r'\bsecret_key\b', r'\bkey\b',
]

def fetch_swagger(url: str, timeout: float = DEFAULT_TIMEOUT) -> Dict[str, Any]:
    if url.startswith("file://"):
        path = url[len("file://"):]
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    r = requests.get(url, timeout=timeout)
    r.raise_for_status()
    return r.json()

def guess_base_url(swagger: Dict[str, Any], swagger_url: str) -> str:
    if 'servers' in swagger and isinstance(swagger['servers'], list) and swagger['servers']:
        server = swagger['servers'][0]
        url = server.get('url')
        if url:
            return url
    host = swagger.get('host')
    schemes = swagger.get('schemes', [])
    basePath = swagger.get('basePath', '/')
    if host:
        scheme = schemes[0] if schemes else urlparse(swagger_url).scheme or 'http'
        return f"{scheme}://{host}{basePath}"
    parsed = urlparse(swagger_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    return base

def resolve_local_ref(root: Dict[str, Any], ref: str) -> Optional[Any]:
    if not ref or not ref.startswith('#/'):
        return None
    path = ref.lstrip('#/').split('/')
    node = root
    try:
        for p in path:
            node = node[p]
        if isinstance(node, dict) and '$ref' in node:
            return resolve_local_ref(root, node['$ref'])
        return node
    except Exception:
        return None

def deep_resolve(node: Any, root: Dict[str, Any], seen: Optional[set]=None) -> Any:
    if seen is None:
        seen = set()
    if isinstance(node, dict):
        if '$ref' in node:
            ref = node['$ref']
            if ref in seen:
                return node
            seen.add(ref)
            resolved = resolve_local_ref(root, ref)
            if resolved is None:
                return node
            merged = dict(resolved)
            for k, v in node.items():
                if k == '$ref':
                    continue
                merged[k] = deep_resolve(v, root, seen)
            return deep_resolve(merged, root, seen)
        else:
            out = {}
            for k, v in node.items():
                out[k] = deep_resolve(v, root, seen)
            return out
    elif isinstance(node, list):
        return [deep_resolve(x, root, seen) for x in node]
    else:
        return node

def expand_components_pathitems(swagger: Dict[str, Any]) -> None:
    paths = swagger.setdefault('paths', {})
    comps = swagger.get('components', {})
    pathitems = comps.get('pathItems', {}) if isinstance(comps, dict) else {}
    for k, v in pathitems.items():
        if k not in paths:
            paths[k] = v

def preprocess_swagger(swagger: Dict[str, Any]) -> Dict[str, Any]:
    expand_components_pathitems(swagger)
    resolved = deep_resolve(swagger, swagger)
    return resolved

def choose_dummy_from_schema(schema: Dict[str, Any]) -> str:
    if not schema:
        return DUMMY_VALUES['string']
    if 'example' in schema:
        return str(schema['example'])
    if 'default' in schema:
        return str(schema['default'])
    if 'enum' in schema and isinstance(schema['enum'], list) and schema['enum']:
        return str(schema['enum'][0])
    t = schema.get('type')
    fmt = schema.get('format')
    pattern = schema.get('pattern')
    if pattern:
        if r'\d' in pattern or '[0-9]' in pattern:
            return '1'
        if r'[a-zA-Z]' in pattern or '\\w' in pattern:
            return 'test'
        return 'test'
    if t == 'string' or t is None:
        if fmt == 'uuid':
            return '00000000-0000-0000-0000-000000000000'
        if fmt == 'email':
            return 'test@example.com'
        if fmt == 'date':
            return '2020-01-01'
        if fmt == 'date-time':
            return '2020-01-01T00:00:00Z'
        if fmt == 'hostname':
            return 'example.com'
        if fmt == 'uri' or fmt == 'url':
            return 'http://example.com/'
        return DUMMY_VALUES['string']
    if t in ('integer', 'number'):
        return '1'
    if t == 'boolean':
        return 'true'
    if t == 'array':
        items_schema = schema.get('items', {})
        item = choose_dummy_from_schema(items_schema)
        return item
    if t == 'object':
        return '{}'
    return DUMMY_VALUES.get(t, DUMMY_VALUES['string'])

def build_example_path(path_template: str, parameters: List[Dict[str, Any]]) -> str:
    path = path_template
    for p in parameters or []:
        if p.get('in') == 'path':
            name = p.get('name')
            schema = p.get('schema') or (p.get('type') and {'type': p.get('type')})
            val = choose_dummy_from_schema(schema)
            path = path.replace('{' + name + '}', str(val))
    return path

def collect_parameters(operation: Dict[str, Any], path_params: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    params = []
    if path_params:
        params.extend(path_params)
    if operation.get('parameters'):
        params.extend(operation['parameters'])
    if 'requestBody' in operation:
        rb = operation['requestBody']
        if isinstance(rb, dict):
            content = rb.get('content', {})
            media = content.get('application/json') or next(iter(content.values()), None)
            schema = media.get('schema') if media else None
            params.append({'in': 'body', 'name': 'requestBody', 'schema': schema or {}})
    return params

def tag_endpoint(path: str, method: str, summary: Optional[str]) -> List[str]:
    tags = []
    text = (path + ' ' + (summary or '')).lower()
    for kw in INTERESTING_KEYWORDS:
        if re.search(kw, text):
            tags.append(kw.strip('\\b'))
    return tags

def enumerate_swagger(swagger: Dict[str, Any], base_url: str, swagger_version: str) -> Dict[str, Any]:
    output = {'base': base_url, 'endpoints': []}
    paths = swagger.get('paths', {})
    for path_template, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        path_level_params = path_item.get('parameters', [])
        for method in ('get','post','put','delete','patch','head','options'):
            if method in path_item:
                op = path_item[method] or {}
                params = collect_parameters(op, path_level_params)
                example_path = build_example_path(path_template, params)
                full_url = urljoin(base_url.rstrip('/')+'/', example_path.lstrip('/'))
                summary = op.get('summary') or op.get('description')
                description = op.get('description', '')
                endpoint = {
                    'path_template': path_template,
                    'method': method.upper(),
                    'summary': summary,
                    'description': description,
                    'parameters': params,
                    'url_example': full_url,
                    'tags': tag_endpoint(path_template, method, summary),
                }
                output['endpoints'].append(endpoint)
    return output

def conservative_probe(endpoint: Dict[str, Any], timeout: float, delay: float = 0.0, token: Optional[str] = None) -> Dict[str, Any]:
    if delay and delay > 0:
        time.sleep(delay + random.uniform(0, delay))

    url = endpoint['url_example']
    method = endpoint['method']
    res = {'url': url, 'method': method, 'status': None, 'headers': None, 'snippet': None, 'error': None}

    # build headers based on swagger info
    headers = {"Accept": "application/json"}
    if method not in ('GET', 'HEAD', 'OPTIONS'):
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"

    try:
        if method in ('GET', 'HEAD', 'OPTIONS'):
            r = requests.request(method, url, headers=headers, timeout=timeout, allow_redirects=True)
        else:
            body = {}
            for p in endpoint.get('parameters', []):
                if p.get('in') in ('body', 'formData'):
                    schema = p.get('schema') or (p.get('type') and {'type': p.get('type')})
                    body[p.get('name', 'body')] = choose_dummy_from_schema(schema)

            # send JSON body if needed
            json_body = body if body else None
            r = requests.request(method, url, headers=headers, json=json_body, timeout=timeout, allow_redirects=False)

        res['status'] = r.status_code
        res['headers'] = dict(r.headers)
        res['snippet'] = (r.text or '')[:800]

    except Exception as e:
        res['error'] = str(e)

    return res

def export_burp_xml(report: Dict[str, Any], filename: str) -> None:
    root = ET.Element('items')
    for ep in report['endpoints']:
        item = ET.SubElement(root, 'item')
        ET.SubElement(item, 'method').text = ep['method']
        ET.SubElement(item, 'path').text = ep['path_template']
        ET.SubElement(item, 'url').text = ep['url_example']
        ET.SubElement(item, 'summary').text = ep.get('summary') or ''
    tree = ET.ElementTree(root)
    tree.write(filename, encoding='utf-8', xml_declaration=True)
    print(f"[*] Burp sitemap written to {filename}")

def export_postman(report: dict, filename: str, collection_name: str='SwaggerHunter Collection', token: str = None, limit: int = 0, methods: list = None) -> None:
    """
    Export Swagger endpoints to a Postman v2.1 collection.
    - token: optional Bearer token for Authorization header
    - limit: number of endpoints to include (0 = all)
    - methods: optional list of HTTP methods to filter (upper-case strings)
    """
    items = []

    endpoints = report.get('endpoints', [])
    
    # Apply method filter
    if methods:
        methods_upper = [m.upper() for m in methods]
        endpoints = [ep for ep in endpoints if ep.get('method', '').upper() in methods_upper]
    
    # Apply limit
    if limit > 0:
        endpoints = endpoints[:limit]

    for ep in endpoints:
        url = ep['url_example']
        parsed = urlparse(url)
        raw = url
        pm_url = {
            "raw": raw,
            "host": [parsed.scheme + "://" + parsed.netloc],
            "path": parsed.path.lstrip('/').split('/') if parsed.path else [],
            "query": []
        }

        for p in ep.get('parameters', []):
            if p.get('in') == 'query':
                schema = p.get('schema') or {}
                pm_url['query'].append({
                    "key": p.get('name'),
                    "value": choose_dummy_from_schema(schema)
                })

        request = {
            "name": f"{ep['method']} {ep['path_template']}",
            "request": {
                "method": ep['method'],
                "header": [],
                "url": pm_url
            }
        }

        # Add Authorization header if token provided
        if token:
            request['request']['header'].append({
                "key": "Authorization",
                "value": f"Bearer {token}"
            })

        items.append(request)

    collection = {
        "info": {
            "name": collection_name,
            "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
        },
        "item": items
    }

    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(collection, f, indent=2)


def color_for_method(m: str) -> str:
    if m == 'GET':
        return GREEN
    if m == 'POST':
        return YELLOW
    if m in ('PATCH','PUT'):
        return CYAN
    if m == 'DELETE':
        return RED
    return MAGENTA

def pretty_print_summary(report: Dict[str, Any], limit: int = 50) -> None:
    n = len(report['endpoints'])
    print(f"[*] Found {n} endpoints (templates).")
    for i, e in enumerate(report['endpoints'][:limit], 1):
        col = color_for_method(e['method'])
        tagstr = f" [{','.join(e['tags'])}]" if e.get('tags') else ''
        print(f"{i:03d}. {col}{e['method']:6}{RESET} {e['path_template']} -> {e['url_example']}{tagstr}")

def clean_html(s: str) -> str:
    if not s:
        return ''
    # Remove basic HTML tags, convert <br> to newline, keep text
    s = re.sub(r'(?i)<br\s*/?>', '\n', s)
    s = re.sub(r'<[^>]+>', '', s)
    return s.strip()

def pretty_print_verbose(report: Dict[str, Any], limit: int = 50) -> None:
    n = len(report['endpoints'])
    print(f"[*] Found {n} endpoints (templates). Verbose output:")
    for i, e in enumerate(report['endpoints'][:limit], 1):
        col = color_for_method(e['method'])
        print(f"{BOLD}{i:03d}. {col}{e['method']}{RESET} {BOLD}{e['path_template']}{RESET}")
        if e.get('summary'):
            print(f"  {BLUE}summary:{RESET} {clean_html(e['summary'])}")
        if e.get('description'):
            print(f"  {CYAN}description:{RESET} {clean_html(e['description'])}")
        if e.get('tags'):
            print(f"  {YELLOW}tags:{RESET} {', '.join(e['tags'])}")
        print("")  # blank line between entries

def main():
    parser = argparse.ArgumentParser(description="Swagger/OpenAPI enumerator + lightweight probe (v2.2)")
    parser.add_argument('-u','--url', required=True, help='URL to swagger/openapi json (or file:///path)')
    parser.add_argument('--probe', action='store_true', help='Make conservative HTTP requests to endpoints')
    parser.add_argument('-o','--output', help='Write JSON results to file')
    parser.add_argument('--timeout', type=float, default=DEFAULT_TIMEOUT, help='HTTP request timeout (seconds)')
    parser.add_argument('--limit', type=int, default=0, help='Limit number of endpoints to probe/export (0 = all)')
    parser.add_argument('--concurrency', type=int, default=5, help='Number of worker threads for probing')
    parser.add_argument('--delay', type=float, default=0.1, help='Base delay (seconds) for rate control/jitter per request')
    parser.add_argument('--burp', help='Write Burp-compatible XML sitemap to file')
    parser.add_argument('--postman', help='Write Postman collection v2.1 JSON to file')
    parser.add_argument('--summary', action='store_true', help='Only print a compact summary of endpoints')
    parser.add_argument('--verbose', action='store_true', help='Print detailed info (summary+description) for endpoints')
    parser.add_argument('--show-all', action='store_true', help='Show all endpoints in the console (overrides default 50)')
    parser.add_argument('--token', help='Optional JWT Bearer token for Authorization header')
    parser.add_argument('--method', help='Comma-separated list of HTTP methods to probe/export (e.g. GET,POST). Case-insensitive.')
    args = parser.parse_args()

    print("[*] swaggerhunter: fetching specification from:", args.url)
    try:
        swagger = fetch_swagger(args.url, timeout=args.timeout)
    except Exception as e:
        print(f"{RED}[!] Failed to fetch swagger JSON:{RESET} {e}")
        sys.exit(2)

    version = swagger.get('openapi') or swagger.get('swagger', '')
    base = guess_base_url(swagger, args.url)
    print(f"[*] Detected version: {version}  | base url guess: {base}")

    try:
        swagger_resolved = preprocess_swagger(swagger)
    except Exception as e:
        print(f"{YELLOW}[!] Warning: error while resolving $ref: {e}{RESET}")
        swagger_resolved = swagger

    report = enumerate_swagger(swagger_resolved, base, version)

    # printing behavior
    limit_display = 9999 if args.show_all else 9999 if args.summary else 50
    if args.verbose:
        pretty_print_verbose(report, limit=limit_display)
    elif args.summary:
        pretty_print_summary(report, limit=limit_display)
    else:
        pretty_print_summary(report, limit=limit_display)

    # Apply method filter for probing/export
    endpoints_filtered = report['endpoints']
    if args.method:
        allowed_methods = [m.strip().upper() for m in args.method.split(',')]
        endpoints_filtered = [ep for ep in endpoints_filtered if ep.get('method', '').upper() in allowed_methods]
        print(f"[*] Method filter: {', '.join(allowed_methods)}  (filtered {len(report['endpoints'])} -> {len(endpoints_filtered)})")

    # Apply limit if specified
    if args.limit > 0:
        endpoints_filtered = endpoints_filtered[:args.limit]

    # Exports (Burp / Postman / JSON)
    if args.burp:
        try:
            export_burp_xml(endpoints_filtered, args.burp)
            print(f"[*] Burp XML written to {args.burp}")
        except Exception as e:
            print(f"{YELLOW}[!] Failed to write Burp XML: {e}{RESET}")

    if args.postman:
        try:
            # wrap list in dict with 'endpoints', pass token for Authorization header
            export_postman({'endpoints': endpoints_filtered}, args.postman, token=args.token)
            print(f"[*] Postman collection written to {args.postman}")
        except Exception as e:
            print(f"{RED}[!] Failed to write Postman collection: {e}{RESET}")

    if args.output:
        try:
            with open(args.output, 'w', encoding='utf-8') as f:
                json.dump({'endpoints': endpoints_filtered}, f, indent=2)
            print(f"[*] Written JSON report to {args.output}")
        except Exception as e:
            print(f"{RED}[!] Failed to write JSON report: {e}{RESET}")
    else:
        print("[*] No JSON output file specified. Use -o to save a structured report.")

    # Probing
    if args.probe:
        print("[*] Probing endpoints (conservative). Ensure you have permission.")
        probe_results = []
        with ThreadPoolExecutor(max_workers=max(1, args.concurrency)) as ex:
            futures = {ex.submit(conservative_probe, ep, args.timeout, args.delay, args.token): ep for ep in endpoints_filtered}
            try:
                for fut in as_completed(futures):
                    ep = futures[fut]
                    try:
                        r = fut.result()
                    except Exception as e:
                        r = {'url': ep.get('url_example'), 'method': ep.get('method'), 'error': str(e)}
                    probe_results.append({'endpoint': ep, 'result': r})

                    # friendly console output
                    status = r.get('status')
                    url = r.get('url') or ep.get('url_example')
                    meth = r.get('method') or ep.get('method')
                    col = GREEN if status and 200 <= status < 300 else \
                          YELLOW if status and 300 <= status < 400 else \
                          RED if status and 400 <= status < 600 else MAGENTA
                    if status is None:
                        print(f"{RED}[!] {meth} {url} -> error: {r.get('error')}{RESET}")
                    else:
                        print(f"{col}[{status}] {meth} {url}{RESET}")
            except KeyboardInterrupt:
                print(f"\n{YELLOW}[!] Interrupted by user. Gathering partial results...{RESET}")

        report['probe_results'] = probe_results
        # Summarize probe hits
        ok = sum(1 for p in probe_results if p['result'].get('status') and 200 <= p['result']['status'] < 300)
        redirects = sum(1 for p in probe_results if p['result'].get('status') and 300 <= p['result']['status'] < 400)
        client_err = sum(1 for p in probe_results if p['result'].get('status') and 400 <= p['result']['status'] < 500)
        server_err = sum(1 for p in probe_results if p['result'].get('status') and 500 <= p['result']['status'] < 600)
        print(f"[*] Probe summary: {GREEN}{ok} OK{RESET}, {YELLOW}{redirects} redirects{RESET}, {RED}{client_err} client errs{RESET}, {RED}{server_err} server errs{RESET}")

if __name__ == '__main__':
    main()



