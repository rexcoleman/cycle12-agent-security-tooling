# Can Bandit or Semgrep Detect Agent Vulnerabilities? We Tested 3 Scanners on 37 MCP Servers

## Methodology

We used Operating Characteristic curve methodology adapted from manufacturing quality assurance to evaluate each scanner at multiple operating points. 37 test cases, 25 vulnerable across 5 OWASP Agentic AI categories, 12 safe controls. Fisher's exact test with Bonferroni correction for pairwise comparisons. 45,900+ total test configurations across all scanner × threshold × category combinations.

Full experimental design, all data, and reproduction scripts: [cycle12-agent-security-tooling on GitHub](https://github.com/rexcoleman/cycle12-agent-security-tooling).

Specific numbers:

- <!-- TEACHING — 50% target -->
- Traditional SAST tools can catch ASI05 (that's just "don't use `eval()`"). But ASI01 — arguably the most dangerous category, because it's invisible to code analysis — gets 0% detection from every scanner we tested.
- <!-- FINDINGS — 30% target -->
- | Sigil (+ bandit) | 80% | 50% | 0.30 |
- | MEDUSA (high threshold) | 16% | 0% | 0.16 |

Full write-up with code: [YOUR_BLOG_URL]

Repo: https://github.com/rexcoleman/cycle12-agent-security-tooling