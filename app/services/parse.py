def _clean(value):
    return (value or "").strip()


def _title(value):
    return _clean(value).replace("-", " ").replace("_", " ").title()


def _format_result(risk, evidence, remediation):
    return f"Risk: {risk} | Evidence: {evidence} | Remediation: {remediation}"


def parse_passive_line(line: str):
    parts = [p.strip() for p in line.strip().split(",")]
    if not parts:
        return None

    tag = parts[0].lower()
    if tag != "discovery" or len(parts) < 3:
        return None

    kind = parts[1].lower()

    if kind == "subdomain" and len(parts) >= 3:
        subdomain = parts[2]
        return {
            "severity": "low",
            "category": "External Attack Surface",
            "description": _format_result(
                "A public subdomain increases the organization’s exposed attack surface.",
                f"Discovered public subdomain: {subdomain}",
                "Review whether this subdomain is still needed, ensure it is patched, protected by TLS, and monitored."
            )
        }

    if kind == "dns" and len(parts) >= 5:
        host, record_type, value = parts[2], parts[3], parts[4]
        return {
            "severity": "low",
            "category": "DNS Exposure",
            "description": _format_result(
                "Public DNS records can reveal infrastructure details to attackers.",
                f"{host} has {record_type} record pointing to {value}",
                "Validate that the DNS record is required, remove stale records, and avoid exposing unnecessary internal naming patterns."
            )
        }

    if kind == "tech" and len(parts) >= 4:
        host = parts[2]
        technology = ",".join(parts[3:])
        return {
            "severity": "medium",
            "category": "Technology Exposure",
            "description": _format_result(
                "Public technology fingerprints may help attackers identify known vulnerabilities.",
                f"{host} appears to expose technology/header: {technology}",
                "Hide unnecessary version banners, keep the platform patched, and verify that exposed services are intentionally public."
            )
        }

    if kind == "http" and len(parts) >= 3:
        endpoint = parts[2]
        status = " ".join(parts[3:]) if len(parts) > 3 else "reachable"
        return {
            "severity": "low",
            "category": "Public HTTP Endpoint",
            "description": _format_result(
                "Public web endpoints may increase exposure if not properly secured.",
                f"{endpoint} is reachable; {status}",
                "Confirm the endpoint is intended to be public, enforce HTTPS, and review security headers."
            )
        }

    return None


def parse_active_line(line: str):
    parts = [p.strip() for p in line.strip().split(",")]
    if not parts:
        return None

    tag = parts[0].lower()

    if tag == "discovery" and len(parts) >= 4 and parts[1].lower() == "service":
        port = parts[2]
        service = parts[3]
        severity = "medium"

        risky_ports = {
            "22": ("SSH exposed to the internet may be targeted for brute-force or credential attacks.", "Restrict SSH to VPN or trusted IPs, require MFA where possible, disable password login, and monitor authentication failures."),
            "25": ("SMTP exposure may allow abuse, relay attempts, or mail server enumeration.", "Verify relay restrictions, enforce SPF/DKIM/DMARC, and restrict access if mail service is not required."),
            "3306": ("MySQL exposed publicly can lead to database compromise.", "Do not expose MySQL directly to the internet. Restrict access to private networks or VPN and enforce strong authentication."),
            "3389": ("RDP exposed publicly is a high-value ransomware entry point.", "Disable public RDP exposure, require VPN/ZTNA, enforce MFA, and monitor login attempts."),
            "5432": ("PostgreSQL exposed publicly can lead to database compromise.", "Restrict PostgreSQL to private networks or VPN and enforce strong authentication."),
            "6379": ("Redis exposed publicly can lead to data exposure or remote abuse.", "Bind Redis to localhost/private networks, require authentication, and block public access."),
            "9200": ("Elasticsearch exposed publicly can leak sensitive indexed data.", "Restrict Elasticsearch to private networks, enforce authentication, and review index permissions."),
            "27017": ("MongoDB exposed publicly can lead to unauthorized database access.", "Restrict MongoDB to private networks, require authentication, and validate firewall rules.")
        }

        port_num = port.split("/")[0]

        if port_num in risky_ports:
            severity = "high"
            risk, remediation = risky_ports[port_num]
        else:
            risk = "An open service increases the attack surface and may be abused if misconfigured."
            remediation = "Verify the service is required, restrict access with firewall rules, and ensure it is patched and monitored."

        return {
            "severity": severity,
            "category": "Open Service",
            "description": _format_result(
                risk,
                f"Open service detected: {port} ({service})",
                remediation
            )
        }

    if tag == "findingmeta" and len(parts) >= 6:
        sev = (parts[1] or "low").lower()
        raw_category = (parts[2] or "general").lower()
        weight = parts[3]
        finding = parts[4]
        target = ",".join(parts[5:])
        return _classify_active_finding(sev, raw_category, finding, target, weight)

    if tag == "finding" and len(parts) >= 4:
        sev = (parts[1] or "low").lower()
        finding = parts[2]
        target = ",".join(parts[3:])
        return _classify_active_finding(sev, "general", finding, target)

    return None


def _classify_active_finding(severity, raw_category, finding, target, weight=None):
    finding_l = finding.lower()
    raw_category = raw_category.lower()

    if finding_l.startswith("exposed-service:"):
        pieces = finding.split(":")
        service = pieces[1] if len(pieces) > 1 else "service"
        port = pieces[2] if len(pieces) > 2 else "unknown"

        severity = severity if severity in ("high", "critical") else "high"

        return {
            "severity": severity,
            "category": "Exposed Service",
            "description": _format_result(
                f"{service.upper()} is exposed and may be exploitable if misconfigured or unpatched.",
                f"{service} exposed on port {port} at {target}",
                "Restrict access to trusted IPs/VPN, disable the service if unnecessary, patch it, and monitor authentication or access attempts."
            )
        }

    if finding_l.startswith("missing-security-header:"):
        header = finding.split(":", 1)[1] if ":" in finding else "security header"

        header_remediation = {
            "hsts": "Add the Strict-Transport-Security header to enforce HTTPS connections.",
            "csp": "Add a Content-Security-Policy header to reduce cross-site scripting and content injection risk.",
            "x-frame-options": "Add X-Frame-Options or CSP frame-ancestors to reduce clickjacking risk.",
            "x-content-type-options": "Add X-Content-Type-Options: nosniff to reduce MIME-sniffing attacks."
        }

        return {
            "severity": severity or "medium",
            "category": "Security Header Misconfiguration",
            "description": _format_result(
                f"The application is missing the {header} security header.",
                f"{finding} at {target}",
                header_remediation.get(header, "Add the missing security header using the web server, reverse proxy, or application framework.")
            )
        }

    if finding_l.startswith("weak-tls-version:"):
        version = finding.split(":", 1)[1] if ":" in finding else "weak TLS version"

        return {
            "severity": "high",
            "category": "TLS Weakness",
            "description": _format_result(
                "Weak TLS versions may allow downgrade attacks or insecure encrypted communication.",
                f"{version} detected at {target}",
                "Disable SSLv2, SSLv3, TLS 1.0, and TLS 1.1. Require TLS 1.2 or TLS 1.3 with strong cipher suites."
            )
        }

    if finding_l.startswith("http-header:"):
        return {
            "severity": "info",
            "category": "HTTP Header Evidence",
            "description": _format_result(
                "This is informational evidence, not necessarily a vulnerability.",
                f"{finding} at {target}",
                "Review exposed headers and remove unnecessary server/version banners where possible."
            )
        }

    if finding_l.startswith("tls-version:"):
        return {
            "severity": "info",
            "category": "TLS Configuration Evidence",
            "description": _format_result(
                "This records the negotiated TLS version for visibility.",
                f"{finding} at {target}",
                "Confirm TLS 1.2 or TLS 1.3 is used and older protocols are disabled."
            )
        }

    if finding_l.startswith("tls-cipher:"):
        return {
            "severity": "info",
            "category": "TLS Cipher Evidence",
            "description": _format_result(
                "This records the negotiated TLS cipher for visibility.",
                f"{finding} at {target}",
                "Confirm only strong cipher suites are enabled and weak/deprecated ciphers are disabled."
            )
        }

    if finding_l.startswith("tls-san:"):
        return {
            "severity": "info",
            "category": "Certificate Evidence",
            "description": _format_result(
                "This records certificate Subject Alternative Names for visibility.",
                f"{finding} at {target}",
                "Review certificate SANs and remove stale or unnecessary hostnames."
            )
        }

    category_map = {
        "service-exposure": "Exposed Service",
        "header-misconfig": "Security Header Misconfiguration",
        "tls-weakness": "TLS Weakness",
        "http-header": "HTTP Header Evidence",
        "tls-info": "TLS Configuration Evidence",
        "tls-san": "Certificate Evidence",
        "general": "Vulnerability"
    }

    category = category_map.get(raw_category, _title(raw_category))

    return {
        "severity": severity or "low",
        "category": category,
        "description": _format_result(
            "A scanner finding was detected and should be reviewed.",
            f"{finding} at {target}",
            "Validate the finding, determine business impact, and remediate based on vendor/application owner guidance."
        )
    }