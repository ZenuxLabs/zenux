<!--
Thanks for contributing to Zenux! Please read CONTRIBUTING.md first.
Do NOT use this PR to disclose a security vulnerability — see SECURITY.md.
-->

## Summary

Briefly describe what this PR changes and why.

## Related issue

Closes #<!-- issue number, or describe the motivation if there is no issue -->

## Type of change

- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New feature (non-breaking change that adds functionality)
- [ ] New or updated scanner / probe
- [ ] Breaking change (fix or feature that changes existing behavior)
- [ ] Documentation only
- [ ] Build / CI / tooling

## Testing done

Describe how you verified this change. For scanners, confirm probes were only
run against authorized/synthetic targets.

```
# commands run, e.g.
cd tools && python3 -m unittest discover tests/ -v
```

## Checklist

- [ ] My change is focused on a single concern
- [ ] I ran the relevant build/lint/test steps from the README and they pass
- [ ] I added or updated tests where behavior changed
- [ ] Docs updated (README / inline docs) where needed
- [ ] No secrets, credentials, real customer data, or PII are included; fixtures use synthetic data only
- [ ] I signed off my commits (DCO) with `git commit -s`
