# Contributing to Zenux

Thanks for your interest in contributing. Zenux is an open, AI-native security
engine, and we welcome bug reports, scanner improvements, SDK fixes, and
documentation.

## Ground rules

- Be respectful. All participation is governed by our
  [Code of Conduct](CODE_OF_CONDUCT.md).
- Zenux is licensed under **AGPL-3.0-or-later**. By contributing you agree your
  contributions are licensed under the same terms. See [`LICENSE`](LICENSE) and
  [`NOTICE`](NOTICE).
- **Never commit secrets, credentials, real customer data, or PII.** Scanner
  fixtures and tests must use synthetic data only.
- Use the scanners responsibly. Only run probes against targets you own or are
  explicitly authorized to test.

## Getting started

1. Fork the repository and create a feature branch off `main`
   (`git checkout -b feat/short-description`).
2. Make focused changes with clear commit messages.
3. Add or update tests where behavior changes.
4. Run the project's lint and test steps before opening a PR.
5. Open a pull request describing the change and the motivation.

## Pull requests

- Keep PRs scoped to a single concern; small PRs review faster.
- Reference any related issue.
- Use the [pull request template](.github/PULL_REQUEST_TEMPLATE.md) and complete
  the checklist.
- Ensure CI is green. Maintainers review on a best-effort basis.

## Developer Certificate of Origin (DCO)

Contributions are accepted under the repository's **AGPL-3.0-or-later** license.
To certify that you wrote the contribution (or otherwise have the right to submit
it under that license), sign off each commit:

```bash
git commit -s -m "your message"
```

This adds a `Signed-off-by: Your Name <you@example.com>` line, which is your
agreement to the [Developer Certificate of Origin](https://developercertificate.org/).
PRs whose commits are not signed off may be asked to amend.

> Note: A Contributor License Agreement (CLA) may be introduced later; until
> then, contributions are under AGPL-3.0 via DCO.

## Reporting security issues

Do **not** open a public issue for security vulnerabilities. Follow the process
in [SECURITY.md](SECURITY.md).
