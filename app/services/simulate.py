import csv
import json
import math
import os
import random
from statistics import quantiles

# Fast enough for the UI polling/finalization path.
DEFAULT_TRIALS = 1000

# Prevent unrealistic zero-dollar years while still allowing low-risk vendors to stay low.
MIN_EVENT_LOSS = 750.0
BASELINE_ANNUAL_LOSS_FLOOR = 5_000.0

# Severity drives technical exposure/frequency. Business size is applied later.
SEVERITY_DEFAULTS = {
    'info': (0.03, 0.01, 2_500),
    'low': (0.14, 0.035, 12_000),
    'medium': (0.38, 0.09, 55_000),
    'high': (0.80, 0.18, 160_000),
    'critical': (1.20, 0.32, 400_000),
}

# Risky services emitted by process_manager.py as discovery,service and findingmeta.
RISKY_PORT_SCORES = {
    22: (0.22, 0.035, 20_000),       # SSH
    25: (0.18, 0.030, 18_000),       # SMTP
    2375: (1.55, 0.42, 450_000),     # Docker API
    3306: (0.90, 0.20, 220_000),     # MySQL
    3389: (0.85, 0.18, 200_000),     # RDP
    5432: (0.90, 0.20, 220_000),     # PostgreSQL
    5900: (0.65, 0.14, 140_000),     # VNC
    6379: (1.20, 0.30, 325_000),     # Redis
    9200: (1.25, 0.32, 375_000),     # Elasticsearch
    9300: (0.95, 0.22, 250_000),
    11211: (0.65, 0.12, 120_000),    # Memcached
    27017: (1.15, 0.28, 325_000),    # MongoDB
}

# No company names are hardcoded. These tiers are inferred from observed scan footprint.
# min_baseline and p90_tail are intentionally business-impact focused.
ORG_SIZE_TIERS = {
    'startup': {
        'min_baseline': 8_000.0,
        'loss_mult': 1.0,
        'frequency_mult': 1.00,
        'lm_power': 1.00,
        'soft_cap': 300_000.0,
        'p90_tail_prob': 0.001,
        'p90_tail_min': 25_000.0,
        'p90_tail_max': 120_000.0,
    },
    'small-business': {
        'min_baseline': 25_000.0,
        'loss_mult': 1.8,
        'frequency_mult': 1.08,
        'lm_power': 1.15,
        'soft_cap': 900_000.0,
        'p90_tail_prob': 0.003,
        'p90_tail_min': 75_000.0,
        'p90_tail_max': 350_000.0,
    },
    'mid-market': {
        'min_baseline': 125_000.0,
        'loss_mult': 4.5,
        'frequency_mult': 1.22,
        'lm_power': 1.35,
        'soft_cap': 3_500_000.0,
        'p90_tail_prob': 0.008,
        'p90_tail_min': 250_000.0,
        'p90_tail_max': 1_500_000.0,
    },
    'enterprise': {
        'min_baseline': 550_000.0,
        'loss_mult': 12.0,
        'frequency_mult': 1.42,
        'lm_power': 1.65,
        'soft_cap': None,
        'p90_tail_prob': 0.018,
        'p90_tail_min': 1_000_000.0,
        'p90_tail_max': 8_000_000.0,
    },
    'mega-enterprise': {
        'min_baseline': 1_800_000.0,
        'loss_mult': 28.0,
        'frequency_mult': 1.70,
        'lm_power': 1.90,
        'soft_cap': None,
        'p90_tail_prob': 0.035,
        'p90_tail_min': 3_000_000.0,
        'p90_tail_max': 25_000_000.0,
    },
}

CATEGORY_MULTS = {
    'service-exposure': (1.25, 1.40, 1.45),
    'tls-weakness': (0.95, 1.50, 1.45),
    'header-misconfig': (0.55, 0.85, 0.35),
    'vuln': (1.35, 1.35, 1.50),
    'general': (1.00, 1.00, 1.00),
    'tls-info': (0.06, 0.10, 0.05),
    'http-header': (0.03, 0.05, 0.03),
    'tls-san': (0.02, 0.04, 0.02),
}


def _clamp(value, low, high):
    return max(low, min(high, value))


def _to_float(value, default=0.0):
    try:
        return float(value)
    except Exception:
        return default


def _to_int(value, default=0):
    try:
        return int(float(value))
    except Exception:
        return default


def _parse_port(text):
    if not text:
        return None
    digits = []
    for ch in str(text):
        if ch.isdigit():
            digits.append(ch)
        elif digits:
            break
    if not digits:
        return None
    try:
        return int(''.join(digits))
    except Exception:
        return None


class ScanFeatures:
    def __init__(self):
        self.summary = {}
        self.findings = []
        self.findingmeta = []
        self.open_ports = set()
        self.risky_ports = set()
        self.subdomains = set()
        self.tech = set()
        self.http_endpoints = set()
        self.dns_records = set()

    def add_summary(self, name, value):
        self.summary[name] = _to_float(value, value)

    def add_finding(self, severity, description, target=''):
        severity = (severity or 'low').lower()
        description = description or ''
        self.findings.append({'severity': severity, 'description': description, 'target': target or ''})
        self._infer_from_finding(description)

    def add_findingmeta(self, severity, category, weight, description, target=''):
        severity = (severity or 'low').lower()
        description = description or ''
        self.findingmeta.append({
            'severity': severity,
            'category': category or 'general',
            'weight': _clamp(_to_float(weight, 0.20), 0.05, 2.0),
            'description': description,
            'target': target or '',
        })
        self._infer_from_finding(description)

    def _infer_from_finding(self, description):
        desc = (description or '').lower()
        port = _parse_port(desc)
        if desc.startswith('exposed-service:') and port is not None:
            self.open_ports.add(port)
            if port in RISKY_PORT_SCORES:
                self.risky_ports.add(port)

    def severity_counts(self):
        counts = {'info': 0, 'low': 0, 'medium': 0, 'high': 0, 'critical': 0}
        source = self.findingmeta if self.findingmeta else self.findings
        for item in source:
            sev = (item.get('severity') or 'low').lower()
            counts[sev] = counts.get(sev, 0) + 1
        return counts


def _read_log_file(path, features):
    if not path or not os.path.exists(path):
        return features
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as handle:
            for raw_line in handle:
                line = raw_line.strip()
                if not line or line.startswith('[#]') or line == '---' or line.startswith('header,'):
                    continue
                parts = [p.strip() for p in line.split(',')]
                tag = parts[0].lower() if parts else ''
                if tag == 'summary' and len(parts) >= 3:
                    features.add_summary(parts[1], parts[2])
                elif tag == 'discovery' and len(parts) >= 3:
                    subtype = parts[1].lower()
                    if subtype == 'subdomain':
                        features.subdomains.add(parts[2])
                    elif subtype == 'dns' and len(parts) >= 5:
                        features.dns_records.add((parts[2], parts[3], parts[4]))
                    elif subtype == 'tech' and len(parts) >= 4:
                        features.tech.add(','.join(parts[3:]))
                    elif subtype == 'http':
                        features.http_endpoints.add(parts[2])
                    elif subtype == 'service' and len(parts) >= 4:
                        port = _parse_port(parts[2])
                        if port is not None:
                            features.open_ports.add(port)
                            if port in RISKY_PORT_SCORES:
                                features.risky_ports.add(port)
                elif tag == 'findingmeta' and len(parts) >= 6:
                    features.add_findingmeta(parts[1], parts[2], parts[3], parts[4], ','.join(parts[5:]))
                elif tag == 'finding' and len(parts) >= 4:
                    features.add_finding(parts[1], parts[2], ','.join(parts[3:]))
    except OSError:
        pass
    return features


def _gather_features(run):
    features = ScanFeatures()
    _read_log_file(getattr(run, 'passive_path', None), features)
    _read_log_file(getattr(run, 'active_path', None), features)

    # Fallback/augmentation from DB findings, so the simulator still works if logs are partial.
    for fd in getattr(run, 'findings', []) or []:
        severity = getattr(fd, 'severity', 'low')
        description = getattr(fd, 'description', getattr(fd, 'title', ''))
        target = getattr(fd, 'target', getattr(fd, 'asset', ''))
        features.add_finding(severity, description, target)

    defaults = {
        'open_ports': len(features.open_ports),
        'risky_open_ports': len(features.risky_ports),
        'subdomains': len(features.subdomains),
        'dns_records': len(features.dns_records),
        'tech_fingerprints': len(features.tech),
        'http_endpoints': len(features.http_endpoints),
    }
    for key, value in defaults.items():
        if key not in features.summary:
            features.summary[key] = value

    missing_headers = 0
    weak_tls = 0
    tls_sans = 0
    for item in features.findings + features.findingmeta:
        desc = item.get('description', '').lower()
        if desc.startswith('missing-security-header:'):
            missing_headers += 1
        elif desc.startswith('weak-tls-version:'):
            weak_tls += 1
        elif desc.startswith('tls-san:'):
            tls_sans += 1

    features.summary['missing_headers'] = max(_to_int(features.summary.get('missing_headers', 0)), missing_headers)
    features.summary['weak_tls'] = max(_to_int(features.summary.get('weak_tls', 0)), weak_tls)
    features.summary['tls_sans'] = max(_to_int(features.summary.get('tls_sans', 0)), tls_sans)
    return features


def _estimate_org_scale(features, run=None):
    """Infer organization scale from live scan evidence only. No vendor names are hardcoded."""
    subdomains = _to_int(features.summary.get('subdomains', 0))
    dns_count = _to_int(features.summary.get('dns_records', 0))
    tech_count = _to_int(features.summary.get('tech_fingerprints', 0))
    http_count = _to_int(features.summary.get('http_endpoints', 0))
    open_ports = _to_int(features.summary.get('open_ports', 0))
    risky_ports = _to_int(features.summary.get('risky_open_ports', 0))
    tls_sans = _to_int(features.summary.get('tls_sans', 0))
    missing_headers = _to_int(features.summary.get('missing_headers', 0))
    weak_tls = _to_int(features.summary.get('weak_tls', 0))
    sev = features.severity_counts()

    # Footprint estimates business scale. Risk complexity estimates technical pressure.
    # Business scale dominates loss magnitude; technical pressure drives likelihood.
    footprint_score = (
        min(subdomains, 500) * 2.50 +
        min(dns_count, 500) * 0.80 +
        min(tls_sans, 250) * 1.60 +
        min(tech_count, 120) * 1.20 +
        min(http_count, 100) * 1.25 +
        min(open_ports, 50) * 1.50 +
        min(risky_ports, 25) * 3.50
    )
    risk_complexity_score = (
        min(missing_headers, 40) * 0.45 +
        min(weak_tls, 15) * 2.00 +
        min(sev.get('medium', 0), 60) * 0.60 +
        min(sev.get('high', 0), 35) * 1.60 +
        min(sev.get('critical', 0), 20) * 3.80
    )
    score = footprint_score + risk_complexity_score

    if score >= 320 or subdomains >= 125 or dns_count >= 200 or tls_sans >= 110:
        tier = 'mega-enterprise'
    elif score >= 140 or subdomains >= 55 or dns_count >= 90 or tls_sans >= 45:
        tier = 'enterprise'
    elif score >= 55 or subdomains >= 20 or dns_count >= 35 or tls_sans >= 20:
        tier = 'mid-market'
    elif score >= 14 or subdomains >= 5 or dns_count >= 10 or open_ports >= 5:
        tier = 'small-business'
    else:
        tier = 'startup'

    return tier, ORG_SIZE_TIERS[tier], score, footprint_score, risk_complexity_score


def _scale_lm(base_lm, tier_config):
    # Superlinear scaling: business impact grows faster than technical finding count.
    loss_mult = float(tier_config['loss_mult'])
    power = float(tier_config['lm_power'])
    return base_lm * (loss_mult ** power)


def _estimate_baseline_loss(features, tier_config):
    subdomains = _to_int(features.summary.get('subdomains', 0))
    open_ports = _to_int(features.summary.get('open_ports', 0))
    risky_ports = _to_int(features.summary.get('risky_open_ports', 0))
    weak_tls = _to_int(features.summary.get('weak_tls', 0))
    missing_headers = _to_int(features.summary.get('missing_headers', 0))
    total_findings = len(features.findings) + len(features.findingmeta)

    exposure_addon = (
        450 * min(subdomains, 80)
        + 900 * min(open_ports, 30)
        + 8_000 * min(risky_ports, 12)
        + 10_000 * min(weak_tls, 6)
        + 500 * min(missing_headers, 20)
        + 350 * min(total_findings, 75)
    )
    scaled = BASELINE_ANNUAL_LOSS_FLOOR + exposure_addon * (tier_config['loss_mult'] ** 1.15)
    return max(tier_config['min_baseline'], scaled)


def _build_factors(features, run=None):
    counts = features.severity_counts()
    open_port_count = _to_int(features.summary.get('open_ports', 0))
    risky_port_count = _to_int(features.summary.get('risky_open_ports', 0))
    subdomain_count = _to_int(features.summary.get('subdomains', 0))
    dns_count = _to_int(features.summary.get('dns_records', 0))
    tech_count = _to_int(features.summary.get('tech_fingerprints', 0))
    http_count = _to_int(features.summary.get('http_endpoints', 0))
    missing_headers = _to_int(features.summary.get('missing_headers', 0))
    weak_tls = _to_int(features.summary.get('weak_tls', 0))

    org_tier, tier_config, org_score, footprint_score, risk_complexity_score = _estimate_org_scale(features, run=run)
    frequency_mult = tier_config['frequency_mult']
    factors = []

    # Attack surface factor: frequency driven by exposure, magnitude driven by org scale.
    surface_tef = (
        0.12 + 0.07 * min(open_port_count, 12) + 0.20 * min(risky_port_count, 8)
        + 0.045 * min(subdomain_count, 30) + 0.020 * min(dns_count, 40)
        + 0.030 * min(tech_count, 15) + 0.030 * min(http_count, 12)
    ) * frequency_mult
    surface_lef = _clamp(
        0.012 + 0.014 * min(risky_port_count, 8) + 0.007 * min(weak_tls, 4)
        + 0.003 * min(missing_headers, 10),
        0.01, 0.35
    )
    surface_lm_base = (
        18_000 + 3_500 * min(open_port_count, 15) + 45_000 * min(risky_port_count, 8)
        + 2_000 * min(subdomain_count, 30) + 1_200 * min(tech_count, 15)
    )
    factors.append((surface_tef, surface_lef, _scale_lm(surface_lm_base, tier_config)))

    if features.findingmeta:
        # Use the top weighted process_manager findings only to stay fast and avoid factor explosion.
        ranked = sorted(features.findingmeta, key=lambda x: x.get('weight', 0.2), reverse=True)[:15]
        for item in ranked:
            base_tef, base_lef, base_lm = SEVERITY_DEFAULTS.get(item['severity'], SEVERITY_DEFAULTS['low'])
            m_tef, m_lef, m_lm = CATEGORY_MULTS.get(item['category'], CATEGORY_MULTS['general'])
            weight = item['weight']
            factors.append((
                base_tef * m_tef * (0.75 + weight) * frequency_mult,
                _clamp(base_lef * m_lef * (0.80 + weight), 0.008, 0.95),
                _scale_lm(base_lm * m_lm * (0.85 + weight), tier_config),
            ))
    else:
        for sev, count in counts.items():
            if count <= 0:
                continue
            base_tef, base_lef, base_lm = SEVERITY_DEFAULTS.get(sev, SEVERITY_DEFAULTS['low'])
            capped_count = min(count, 10)
            factors.append((
                base_tef * capped_count * frequency_mult,
                _clamp(base_lef + (0.01 * capped_count), 0.008, 0.80),
                _scale_lm(base_lm * (1.0 + 0.35 * capped_count), tier_config),
            ))

    for port in sorted(features.risky_ports)[:10]:
        tef, lef, lm = RISKY_PORT_SCORES[port]
        factors.append((tef * frequency_mult, lef, _scale_lm(lm, tier_config)))

    # Exposure combinations create realistic jumps without making every single finding huge.
    if risky_port_count >= 2 and weak_tls > 0:
        factors.append((1.0 * frequency_mult, 0.24, _scale_lm(180_000, tier_config)))
    if risky_port_count >= 1 and missing_headers >= 2:
        factors.append((0.60 * frequency_mult, 0.13, _scale_lm(60_000, tier_config)))
    if open_port_count >= 5 and subdomain_count >= 5:
        factors.append((0.75 * frequency_mult, 0.12, _scale_lm(85_000, tier_config)))

    if not factors:
        factors = [(0.35 * frequency_mult, 0.03, _scale_lm(18_000, tier_config))]

    baseline_loss = _estimate_baseline_loss(features, tier_config)
    meta = {
        'org_tier': org_tier,
        'org_score': org_score,
        'footprint_score': footprint_score,
        'risk_complexity_score': risk_complexity_score,
        'org_scale_method': 'observed_scan_footprint_only_no_hardcoded_company_names',
        'org_loss_mult': tier_config['loss_mult'],
        'org_frequency_mult': frequency_mult,
        'lm_power': tier_config['lm_power'],
        'soft_cap': tier_config['soft_cap'],
        'p90_tail_prob': tier_config['p90_tail_prob'],
        'p90_tail_min': tier_config['p90_tail_min'],
        'p90_tail_max': tier_config['p90_tail_max'],
    }
    return factors, baseline_loss, meta


def _sample_count(mean):
    mean = max(0.0, float(mean))
    if mean <= 0.0:
        return 0
    if mean < 25.0:
        limit = math.exp(-mean)
        product = 1.0
        k = 0
        while product > limit:
            k += 1
            product *= random.random()
        return k - 1
    return max(0, int(random.gauss(mean, math.sqrt(mean)) + 0.5))


def _sample_aggregate_lognormal(hit_count, lm, sigma):
    if hit_count <= 0:
        return 0.0
    mu = math.log(max(lm, 1.0)) - 0.5 * sigma ** 2
    if hit_count == 1:
        return max(MIN_EVENT_LOSS, random.lognormvariate(mu, sigma))

    mean_one = math.exp(mu + 0.5 * sigma ** 2)
    var_one = (math.exp(sigma ** 2) - 1.0) * math.exp(2.0 * mu + sigma ** 2)
    sum_mean = hit_count * mean_one
    sum_var = hit_count * var_one
    if sum_mean <= 0.0 or sum_var <= 0.0:
        return float(hit_count) * max(MIN_EVENT_LOSS, lm)

    sigma_sum_sq = math.log(1.0 + (sum_var / (sum_mean ** 2)))
    mu_sum = math.log(sum_mean) - 0.5 * sigma_sum_sq
    sigma_sum = math.sqrt(max(0.0, sigma_sum_sq))
    return max(hit_count * MIN_EVENT_LOSS, random.lognormvariate(mu_sum, sigma_sum))


def _apply_tail_and_caps(total, model_meta):
    # Large companies have rare but real secondary-loss tail events: legal, customer, outage, reputation.
    if random.random() < float(model_meta.get('p90_tail_prob', 0.0)):
        low = float(model_meta.get('p90_tail_min', 0.0))
        high = float(model_meta.get('p90_tail_max', 0.0))
        if high > low > 0:
            total += random.lognormvariate(
                math.log((low + high) / 2.0) - 0.5 * 0.85 ** 2,
                0.85,
            )

    # Startups can have bad outcomes, but the model should not let one bad technical finding
    # routinely outrank enterprise business impact.
    cap = model_meta.get('soft_cap')
    if cap:
        total = min(total, float(cap))
    return total


def simulate_ale(factors, trials=DEFAULT_TRIALS, seed=None, baseline_loss=0.0, model_meta=None):
    if seed is not None:
        random.seed(seed)
    model_meta = model_meta or {}

    safe_factors = []
    for tef, lef, lm in factors:
        tef = _clamp(_to_float(tef, 0.0), 0.0, 100000.0)
        lef = _clamp(_to_float(lef, 0.0), 0.0, 0.999)
        lm = max(_to_float(lm, 0.0), 0.0)
        if tef > 0.0 and lef > 0.0 and lm > 0.0:
            safe_factors.append((tef, lef, lm))
    if not safe_factors:
        safe_factors = [(0.35, 0.03, 18_000.0)]

    results = []
    for _ in range(max(1, int(trials))):
        # Quiet years still cost something, but the baseline varies per trial.
        baseline_sigma = 0.30
        baseline_mu = math.log(max(baseline_loss, 1.0)) - 0.5 * baseline_sigma ** 2
        total = max(MIN_EVENT_LOSS, random.lognormvariate(baseline_mu, baseline_sigma))

        for tef, lef, lm in safe_factors:
            # Small floors prevent totally flat distributions.
            tef = max(tef, 0.08)
            lef = max(lef, 0.018)
            event_mean = max(0.0, random.gauss(tef, max(0.38, math.sqrt(max(tef, 0.1)) * 0.95)))
            hits = _sample_count(event_mean * lef)
            sigma = 0.80 if lm < 100_000 else 1.00 if lm < 750_000 else 1.25
            total += _sample_aggregate_lognormal(hits, lm, sigma)

        total = _apply_tail_and_caps(total, model_meta)
        results.append(total)

    if len(results) < 2:
        p10 = p50 = p90 = results[0] if results else 0.0
    else:
        deciles = quantiles(results, n=10)
        p10 = deciles[0]
        p50 = quantiles(results, n=2)[0]
        p90 = deciles[8]
    return p10, p50, p90, results


def run_simulation(run, trials=DEFAULT_TRIALS, seed=None):
    features = _gather_features(run)
    factors, baseline_loss, model_meta = _build_factors(features, run=run)
    p10, p50, p90, results = simulate_ale(
        factors,
        trials=trials or DEFAULT_TRIALS,
        seed=seed,
        baseline_loss=baseline_loss,
        model_meta=model_meta,
    )

    output_dir = getattr(run, 'run_path', None) or 'data/runs/_sim'
    os.makedirs(output_dir, exist_ok=True)
    sim_path = os.path.join(output_dir, 'sim.csv')
    with open(sim_path, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['ale'])
        for value in results:
            writer.writerow([f'{value:.2f}'])

    try:
        with open(os.path.join(output_dir, 'sim_meta.json'), 'w', encoding='utf-8') as f:
            json.dump({
                **model_meta,
                'baseline_loss': round(float(baseline_loss), 2),
                'factor_count': len(factors),
                'trials': int(trials or DEFAULT_TRIALS),
                'p10': round(float(p10), 2),
                'p50': round(float(p50), 2),
                'p90': round(float(p90), 2),
                'summary': {
                    'subdomains': _to_int(features.summary.get('subdomains', 0)),
                    'dns_records': _to_int(features.summary.get('dns_records', 0)),
                    'tls_sans': _to_int(features.summary.get('tls_sans', 0)),
                    'open_ports': _to_int(features.summary.get('open_ports', 0)),
                    'risky_open_ports': _to_int(features.summary.get('risky_open_ports', 0)),
                    'weak_tls': _to_int(features.summary.get('weak_tls', 0)),
                    'missing_headers': _to_int(features.summary.get('missing_headers', 0)),
                },
            }, f, indent=2)
    except Exception:
        pass

    return p10, p50, p90, sim_path
