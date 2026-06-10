# Security Policy

Thunderhead is a reverse proxy that sits in front of your infrastructure and analyzes incoming traffic. Because of this, security vulnerabilities may have direct impact on protected systems.

We take security issues seriously and appreciate responsible disclosure.

---

## Reporting a vulnerability

If you discover a security issue, **do not open a public GitHub issue**.

Instead, please report it privately via:

* **Email:** `bhavdeeparora1@gmail.com`

(Replace this with your actual email or security contact.)

---

## What to include

When reporting a vulnerability, please provide:

* Description of the issue
* Steps to reproduce
* Affected version/commit hash
* Potential impact
* Suggested mitigation (if any)

The more detail you provide, the faster we can respond.

---

## Scope

This security policy applies to:

* Core proxy logic (`internal/proxy`)
* Intent scoring system (`internal/analyzer`)
* Allowlist / blocking mechanisms
* Dashboard and TUI interfaces
* Configuration parsing

Out of scope (unless directly exploitable through Thunderhead):

* Upstream applications behind the proxy
* Third-party dependencies outside Thunderhead’s control

---

## Response timeline

We aim to:

* Acknowledge reports within **48 hours**
* Provide a status update within **5–7 days**
* Release a fix as soon as practical for valid vulnerabilities

---

## Responsible disclosure

We ask that researchers:

* Avoid accessing or modifying user data beyond what is necessary to demonstrate the issue
* Do not publicly disclose vulnerabilities before a fix is released
* Give us reasonable time to address the issue before publication

---

## Security philosophy

Thunderhead is designed with a few core principles:

* Minimal attack surface
* Transparent decision-making (all actions are logged)
* No external dependencies for core security logic
* Self-hosted control over all behavior

However, like any network-facing system, it is not inherently secure by default and should be deployed with appropriate operational safeguards.

---

## Thanks

We appreciate security researchers and contributors who help improve Thunderhead. Responsible disclosure helps make the ecosystem safer for everyone.
