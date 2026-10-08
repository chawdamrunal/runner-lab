# runner-lab — authorized security-research PoC repo (GitHub Actions hosted-runner boundary)

Reproduction artifacts for a finding reported to GitHub's bug bounty program
(bounty.github.com → HackerOne github). Engagement workspace authorization on
file. Self-contained: `repro-f004` is a triager-safe workflow that prints only
HTTP status codes and non-secret metadata — it never prints credentials.
