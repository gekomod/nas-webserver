# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 2.3.x (current) | ✅ |
| 2.2.x | ✅ security fixes only |
| < 2.2 | ❌ |

## Reporting a vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Please report them via one of the following channels:

1. **GitHub private advisory** (preferred):  
   <https://github.com/nas-panel/nas-web/security/advisories/new>

2. **E-mail**:  
   `security@nas-panel.dev`  
   GPG key fingerprint: _(add your key fingerprint here)_

### What to include

- Description of the vulnerability and affected component
- Steps to reproduce / proof-of-concept (even partial)
- Potential impact assessment
- Suggested fix if you have one

### Response timeline

| Step | Target |
|------|--------|
| Initial acknowledgement | 48 hours |
| Triage & severity assessment | 5 business days |
| Patch / mitigation | 30 days (critical: 7 days) |
| Public disclosure | After patch is released (coordinated) |

We follow [responsible disclosure](https://en.wikipedia.org/wiki/Responsible_disclosure).  
CVE assignment is requested for confirmed vulnerabilities with CVSS ≥ 4.0.

## Scope

In scope:
- `nas-web` server binary (C++ core, WAF, TLS, admin panel)
- Debian/Ubuntu packaging (privilege escalation via packaging scripts)
- Default configuration shipped with the package

Out of scope:
- Third-party libraries (report upstream; we will update dependencies)
- Vulnerabilities requiring physical access to the host
- Denial-of-service via excessive legitimate traffic

## Security hardening checklist (for operators)

- [ ] Change default `admin_password` in `/etc/nas-web/nas-web.conf`
- [ ] Restrict admin panel with `admin_allow_ips` (LAN-only)
- [ ] Enable TLS (`ssl_cert` / `ssl_key`) and set `admin_tls_only true`
- [ ] Run the service as a non-root user with `CAP_NET_BIND_SERVICE`
- [ ] Keep the package up to date: `apt-get upgrade nas-web`
