# FAIR Risk Report

Vendor: Apple

P10: 629,248.02

P50: 1,148,729.28

P90: 1,949,835.80

## Findings
- [LOW] surface: subdomain discovered: www.{d}
- [LOW] surface: subdomain discovered: app.{d}
- [LOW] surface: subdomain discovered: api.{d}
- [LOW] surface: subdomain discovered: cdn.{d}
- [MEDIUM] service: Open 80/{proto} ({svc})
- [LOW] surface: subdomain discovered: portal.{d}
- [LOW] surface: subdomain discovered: sso.{d}
- [LOW] surface: subdomain discovered: assets.{d}
- [MEDIUM] service: Open 443/{proto} ({svc})
- [LOW] surface: subdomain discovered: files.{d}
- [LOW] surface: subdomain discovered: status.{d}
- [LOW] dns: www.{d} A {random.choice(ips)}
- [LOW] dns: app.{d} A {random.choice(ips)}
- [MEDIUM] service: Open 22/{proto} ({svc})
- [LOW] dns: api.{d} A {random.choice(ips)}
- [LOW] dns: cdn.{d} A {random.choice(ips)}
- [LOW] dns: portal.{d} A {random.choice(ips)}
- [MEDIUM] service: Open 25/{proto} ({svc})
- [LOW] dns: sso.{d} A {random.choice(ips)}
- [LOW] dns: assets.{d} A {random.choice(ips)}
- [LOW] dns: files.{d} A {random.choice(ips)}
- [MEDIUM] service: Open 3389/{proto} ({svc})
- [LOW] dns: status.{d} A {random.choice(ips)}
- [MEDIUM] tech-exposure: www.{d} runs {random.choice(tech)}
- [MEDIUM] tech-exposure: app.{d} runs {random.choice(tech)}
- [MEDIUM] tech-exposure: api.{d} runs {random.choice(tech)}
- [{SEV}] vuln: {desc} at https://apple.com
- [MEDIUM] tech-exposure: cdn.{d} runs {random.choice(tech)}
- [MEDIUM] tech-exposure: portal.{d} runs {random.choice(tech)}
- [MEDIUM] tech-exposure: sso.{d} runs {random.choice(tech)}
