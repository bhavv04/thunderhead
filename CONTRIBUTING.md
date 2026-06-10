# Contributing to Thunderhead

Thanks for your interest in contributing to Thunderhead.

Thunderhead is a lightweight reverse proxy that detects and mitigates automated traffic using passive behavioral analysis. The goal is to remain simple, transparent, and self-hostable while providing useful protection against crawlers and scanners.

## Ways to contribute

Contributions of all sizes are welcome, including:

* New intent-scoring signals
* Performance improvements
* Bug fixes
* Documentation improvements
* Dashboard and TUI enhancements
* Tests and benchmarks
* Deployment tooling (Docker, systemd, CI)

If you're planning a larger feature, consider opening an issue first so we can discuss the design before implementation.

---

## Development setup

### Prerequisites

* Go 1.24+
* Git

Clone the repository:

```bash
git clone https://github.com/<your-username>/thunderhead.git
cd thunderhead
```

Install dependencies:

```bash
go mod download
```

Run tests:

```bash
go test ./...
```

Run the web dashboard:

```bash
go run ./cmd/thunderhead
```

Run the terminal dashboard:

```bash
go run ./cmd/tui
```

---

## Project structure

```text
internal/
├── allowlist/   # IP, CIDR, and user-agent allowlists
├── analyzer/    # intent scoring engine
├── config/      # configuration loading
├── logger/      # structured logging
└── proxy/       # reverse proxy and action handling
```

### Adding a new signal

Most contributions will involve adding new scoring signals inside the analyzer package.

A signal should:

1. Be deterministic.
2. Have a clearly documented weight.
3. Avoid excessive memory or CPU usage.
4. Minimize false positives.
5. Be explainable in logs and dashboards.

Example signals:

* Repeated access to known sensitive paths
* Abnormal navigation patterns
* User-agent inconsistencies
* Header fingerprint anomalies
* Honeypot endpoint access

When adding a signal:

* Add tests.
* Update the README scoring table.
* Document any new configuration options.

---

## Code style

Please follow standard Go conventions.

Format code before submitting:

```bash
go fmt ./...
```

Run vet:

```bash
go vet ./...
```

Guidelines:

* Prefer clear code over clever code.
* Keep dependencies minimal.
* Avoid introducing external services.
* Keep Thunderhead self-hostable by default.

---

## Pull requests

Before opening a PR:

* Ensure the project builds successfully.
* Run all tests.
* Update documentation when necessary.
* Keep PRs focused on a single change.

PR descriptions should include:

* What changed
* Why it changed
* Any performance or behavioral impact
* Screenshots for dashboard/TUI changes

---

## Reporting issues

When reporting bugs, please include:

* Thunderhead version or commit hash
* Operating system
* Go version
* Configuration file (if relevant)
* Steps to reproduce
* Expected behavior
* Actual behavior

---

## Design principles

Thunderhead aims to remain:

* Lightweight
* Self-hosted
* Observable
* Explainable
* Dependency-light

New features should support these goals and avoid turning Thunderhead into a full web application firewall.

---

## License

By contributing to Thunderhead, you agree that your contributions will be licensed under the same license as the project.
