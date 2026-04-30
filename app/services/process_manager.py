import os
import shlex
import shutil
import subprocess
from urllib.parse import urlsplit


def tool_exists(name):
    return shutil.which(name) is not None


def _line_buffer(cmd: str) -> str:
    if shutil.which("stdbuf"):
        return f"stdbuf -oL -eL {cmd}"
    if shutil.which("script"):
        return f"script -q /dev/null {cmd}"
    return cmd


def _spawn(cmd_list, out_path):
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    out = open(out_path, "w", encoding="utf-8")
    proc = subprocess.Popen(cmd_list, stdout=out, stderr=subprocess.STDOUT, start_new_session=True)
    return proc.pid


def _normalize_target(target: str) -> str:
    target = (target or "").strip()
    if not target:
        return ""
    if "://" not in target:
        target = f"//{target}"
    parts = urlsplit(target)
    host = (parts.hostname or parts.path or "").strip().lower().rstrip(".")
    return host


PASSIVE_SCANNER_CODE = r'''
import http.client
import socket
import ssl
import subprocess
import sys
from urllib.parse import quote
from urllib.request import urlopen


def safe_print(msg: str):
    print(msg, flush=True)


def uniq(items):
    seen = set()
    out = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


def shutil_which(name):
    import shutil
    return shutil.which(name)


def run_cmd(cmd, timeout=90):
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=timeout)
        return p.stdout or ""
    except Exception:
        return ""


def resolve_host(host):
    records = []
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        for info in infos:
            ip = info[4][0]
            family = info[0]
            rtype = 'A' if family == socket.AF_INET else 'AAAA'
            records.append((host, rtype, ip))
    except Exception:
        pass
    return uniq(records)


def cert_names(domain):
    names = []
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert() or {}
        for typ, value in cert.get('subjectAltName', []):
            if typ != 'DNS':
                continue
            name = value.lower().strip().lstrip('*.')
            if name == domain or name.endswith('.' + domain):
                names.append(name)
    except Exception:
        pass
    return uniq(names)


def ct_names(domain):
    names = []
    url = 'https://crt.sh/?q=' + quote(domain) + '&output=json'
    try:
        with urlopen(url, timeout=8) as resp:
            body = resp.read().decode('utf-8', errors='ignore')
        if body.strip().startswith('['):
            import json
            rows = json.loads(body)
            for row in rows[:200]:
                raw = (row.get('name_value') or '').lower()
                for piece in raw.splitlines():
                    piece = piece.strip().lstrip('*.')
                    if piece and (piece == domain or piece.endswith('.' + domain)):
                        names.append(piece)
    except Exception:
        pass
    return uniq(names)


def external_subdomains(domain):
    found = []
    if shutil_which('amass'):
        for line in run_cmd(['amass', 'enum', '-passive', '-norecursive', '-noalts', '-d', domain]).splitlines():
            line = line.strip().lower()
            if line == domain or line.endswith('.' + domain):
                found.append(line)
    if shutil_which('subfinder'):
        for line in run_cmd(['subfinder', '-silent', '-d', domain]).splitlines():
            line = line.strip().lower()
            if line == domain or line.endswith('.' + domain):
                found.append(line)
    return uniq(found)


def fetch_headers(domain, scheme, timeout=6):
    headers = {}
    try:
        if scheme == 'https':
            conn = http.client.HTTPSConnection(domain, timeout=timeout, context=ssl.create_default_context())
        else:
            conn = http.client.HTTPConnection(domain, timeout=timeout)
        conn.request('HEAD', '/')
        resp = conn.getresponse()
        safe_print(f'discovery,http,{scheme}://{domain}/,status,{resp.status}')
        headers = {k: v for k, v in resp.getheaders()}
        conn.close()
    except Exception:
        pass
    return headers


def tech_from_headers(headers):
    tech = []
    for key, value in (headers or {}).items():
        lk = key.lower()
        if lk in {'server', 'x-powered-by', 'via', 'cf-ray', 'x-cache'}:
            tech.append(f'{key}={value}')
    return uniq(tech)


def emit_summary(name: str, value):
    safe_print(f'summary,{name},{value}')


def main():
    domain = sys.argv[1].strip().lower()
    fast_demo = sys.argv[2].lower() == 'true'

    safe_print(f'[#] passive scan: {domain}')

    subdomains = []
    safe_print('[#] subdomain discovery')
    subdomains.extend(external_subdomains(domain))
    subdomains.extend(cert_names(domain))
    if not fast_demo:
        subdomains.extend(ct_names(domain))
    subdomains = uniq([s for s in subdomains if s != domain and s.endswith('.' + domain)])
    for sub in subdomains[:50]:
        safe_print(f'discovery,subdomain,{sub}')

    candidate_hosts = uniq([domain] + subdomains)
    dns_records = []
    safe_print('---')
    safe_print('[#] dns resolution')
    for host in candidate_hosts[:(8 if fast_demo else 25)]:
        for fqdn, rtype, ip in resolve_host(host):
            dns_records.append((fqdn, rtype, ip))
            safe_print(f'discovery,dns,{fqdn},{rtype},{ip}')

    http_hits = 0
    tech_hits = []
    safe_print('---')
    safe_print('[#] http fingerprinting')
    schemes = ['https'] if fast_demo else ['https', 'http']
    for scheme in schemes:
        headers = fetch_headers(domain, scheme)
        if headers:
            http_hits += 1
        for item in tech_from_headers(headers):
            tech_hits.append(item)
            safe_print(f'discovery,tech,{domain},{item}')

    emit_summary('subdomains', len(subdomains))
    emit_summary('dns_records', len(uniq(dns_records)))
    emit_summary('http_endpoints', http_hits)
    emit_summary('tech_fingerprints', len(uniq(tech_hits)))
    emit_summary('candidate_hosts', len(candidate_hosts))
    safe_print('==PASSIVE_DONE==')


if __name__ == '__main__':
    main()
'''


ACTIVE_SCANNER_CODE = r'''
import concurrent.futures
import http.client
import socket
import ssl
import sys


def safe_print(msg: str):
    print(msg, flush=True)


RISKY_PORTS = {
    22: ('ssh', 'medium', 0.35),
    25: ('smtp', 'medium', 0.30),
    2375: ('docker-api', 'critical', 0.95),
    3306: ('mysql', 'high', 0.80),
    3389: ('rdp', 'high', 0.85),
    5432: ('postgresql', 'high', 0.80),
    5900: ('vnc', 'high', 0.80),
    6379: ('redis', 'critical', 0.90),
    9200: ('elasticsearch', 'critical', 0.90),
    9300: ('elasticsearch-transport', 'high', 0.75),
    11211: ('memcached', 'high', 0.75),
    27017: ('mongodb', 'critical', 0.90),
}


def scan_port(host: str, port: int, timeout: float = 0.75):
    families = [socket.AF_INET]
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        families = []
        for info in infos:
            fam = info[0]
            if fam not in families:
                families.append(fam)
    except Exception:
        pass

    for family in families:
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            result = sock.connect_ex((host, port))
            if result == 0:
                try:
                    service = socket.getservbyport(port, 'tcp')
                except Exception:
                    service = 'unknown'
                return port, service
        except Exception:
            continue
        finally:
            try:
                sock.close()
            except Exception:
                pass
    return None


def finding(severity: str, description: str, target: str, category: str = 'general', weight: float = 0.20):
    safe_print(f'finding,{severity},{description},{target}')
    safe_print(f'findingmeta,{severity},{category},{weight:.2f},{description},{target}')


def grab_http_headers(host: str, scheme: str, timeout: int = 5):
    headers = {}
    missing_headers = 0
    try:
        if scheme == 'https':
            conn = http.client.HTTPSConnection(host, timeout=timeout, context=ssl.create_default_context())
        else:
            conn = http.client.HTTPConnection(host, timeout=timeout)
        conn.request('HEAD', '/')
        resp = conn.getresponse()
        headers = {k: v for k, v in resp.getheaders()}
        conn.close()
    except Exception:
        return 0

    for k, v in headers.items():
        finding('info', f'http-header:{k}={v}', f'{scheme}://{host}/', 'http-header', 0.05)

    wanted = {
        'strict-transport-security': ('hsts', 'medium', 0.55),
        'content-security-policy': ('csp', 'medium', 0.50),
        'x-frame-options': ('x-frame-options', 'low', 0.20),
        'x-content-type-options': ('x-content-type-options', 'low', 0.20),
    }
    lower = {k.lower(): v for k, v in headers.items()}
    for key, (short_name, default_sev, weight) in wanted.items():
        if key not in lower:
            sev = default_sev if scheme == 'https' else 'low'
            finding(sev, f'missing-security-header:{short_name}', f'{scheme}://{host}/', 'header-misconfig', weight)
            missing_headers += 1
    return missing_headers


def tls_probe(host: str):
    weak_tls = 0
    san_count = 0
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert() or {}
                version = ssock.version() or 'unknown'
                finding('info', f'tls-version:{version}', host, 'tls-info', 0.05)
                cipher = ssock.cipher()
                if cipher:
                    finding('info', f'tls-cipher:{cipher[0]}', host, 'tls-info', 0.05)
                if version in {'TLSv1', 'TLSv1.1', 'SSLv3', 'SSLv2'}:
                    finding('high', f'weak-tls-version:{version}', host, 'tls-weakness', 0.85)
                    weak_tls += 1
                for typ, value in cert.get('subjectAltName', [])[:10]:
                    if typ == 'DNS':
                        san_count += 1
                        finding('info', f'tls-san:{value}', host, 'tls-san', 0.02)
    except Exception:
        return 0, 0
    return weak_tls, san_count


def emit_summary(name: str, value):
    safe_print(f'summary,{name},{value}')


def main():
    domain = sys.argv[1].strip().lower()
    fast_demo = sys.argv[2].lower() == 'true'

    safe_print(f'[#] active scan: {domain}')
    safe_print('header,PORT,STATE,SERVICE')

    common_ports = [
        21,22,25,53,80,110,111,135,139,143,443,445,465,587,993,995,1433,1521,2049,
        2375,3000,3306,3389,5000,5432,5601,5900,6379,6443,8000,8080,8081,8443,9000,
        9200,9300,11211,27017
    ]
    ports = common_ports[:12] if fast_demo else common_ports

    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(32, len(ports) or 1)) as ex:
        futures = [ex.submit(scan_port, domain, p, 0.5 if fast_demo else 0.9) for p in ports]
        for fut in concurrent.futures.as_completed(futures):
            result = fut.result()
            if result:
                open_ports.append(result)

    risky_open_ports = []
    severity_counts = {'info': 0, 'low': 0, 'medium': 0, 'high': 0, 'critical': 0}

    for port, service in sorted(open_ports):
        safe_print(f'discovery,service,{port}/tcp,{service}')
        if port in RISKY_PORTS:
            risk_name, sev, weight = RISKY_PORTS[port]
            risky_open_ports.append(port)
            severity_counts[sev] += 1
            finding(sev, f'exposed-service:{risk_name}:{port}', domain, 'service-exposure', weight)

    safe_print('---')
    weak_tls = 0
    tls_sans = 0
    if any(p == 443 for p, _ in open_ports):
        safe_print(f'[#] tls probe: {domain}:443')
        weak_tls, tls_sans = tls_probe(domain)
        severity_counts['high'] += weak_tls
        severity_counts['info'] += 2 + tls_sans
        safe_print('---')

    missing_headers = 0
    if any(p == 80 for p, _ in open_ports):
        safe_print(f'[#] http headers: http://{domain}/')
        missing_headers += grab_http_headers(domain, 'http')
        safe_print('---')
    if any(p == 443 for p, _ in open_ports):
        safe_print(f'[#] http headers: https://{domain}/')
        missing_headers += grab_http_headers(domain, 'https')

    # Re-count header severities conservatively into summary estimates.
    # HTTPS missing HSTS/CSP are higher-impact; the simulator parses exact records.
    emit_summary('open_ports', len(open_ports))
    emit_summary('risky_open_ports', len(risky_open_ports))
    emit_summary('weak_tls', weak_tls)
    emit_summary('missing_headers', missing_headers)
    emit_summary('tls_sans', tls_sans)
    emit_summary('service_findings', len(risky_open_ports))
    safe_print('==ACTIVE_DONE==')


if __name__ == '__main__':
    main()
'''


def launch_passive(domain: str, out_path: str, real_scans: bool, fast_demo: bool):
    domain = _normalize_target(domain)
    if real_scans:
        lines = []
        if tool_exists("amass"):
            lines.append(f"amass enum -passive -norecursive -noalts -d {shlex.quote(domain)} || true")
        if tool_exists("subfinder"):
            lines.append(f"subfinder -silent -d {shlex.quote(domain)} || true")
        if lines:
            script = " && echo '---' && ".join(_line_buffer(x) for x in lines) + " && echo '---' && "
            script += f"python -u -c {shlex.quote(PASSIVE_SCANNER_CODE)} {shlex.quote(domain)} {str(fast_demo)}"
            return _spawn(["bash", "-lc", script], out_path)

    return _spawn(["python", "-u", "-c", PASSIVE_SCANNER_CODE, domain, str(fast_demo)], out_path)



def launch_active(domain: str, out_path: str, real_scans: bool, consent: bool, fast_demo: bool):
    domain = _normalize_target(domain)
    if not consent:
        with open(out_path, "w", encoding="utf-8") as f:
            f.write("Active scans skipped (no consent)\n==ACTIVE_DONE==\n")
        return None

    if real_scans:
        lines = []
        nmap_ports = "80,443,22,25,53,110,111,135,139,143,445,465,587,993,995,1433,2049,2375,3000,3306,3389,5000,5432,5601,5900,6379,6443,8000,8080,8081,8443,9000,9200,9300,11211,27017"
        if tool_exists("nmap"):
            demo_ports = "22,80,443,8080,8443,3306,5432,6379,9200,27017,25,3389"
            lines.append(f"nmap -Pn -n -p {demo_ports if fast_demo else nmap_ports} --open {shlex.quote(domain)} || true")
        if tool_exists("nuclei"):
            lines.append(f"nuclei -duc -silent -u https://{shlex.quote(domain)} -tags ssl,misconfig,exposure,tech || true")
        if lines:
            script = " && echo '---' && ".join(_line_buffer(x) for x in lines) + " && echo '---' && "
            script += f"python -u -c {shlex.quote(ACTIVE_SCANNER_CODE)} {shlex.quote(domain)} {str(fast_demo)}"
            return _spawn(["bash", "-lc", script], out_path)

    return _spawn(["python", "-u", "-c", ACTIVE_SCANNER_CODE, domain, str(fast_demo)], out_path)
