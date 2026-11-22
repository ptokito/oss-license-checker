# OSS License and Vulnerability Policy Gate

A small Python tool and Jenkins pipeline that checks a project's open source dependencies
for license compliance and known vulnerabilities, writes a report for legal and security
teams, and blocks the build when policy is broken.

## What it does
1. Reads pinned dependencies from `requirements.txt`
2. Looks up each package's license for that exact version (PyPI)
3. Looks up known vulnerabilities and their severity for that exact version (OSV.dev)
4. Writes `oss_report.csv` with per-severity counts for legal and security review
5. Applies policy and exits with code 1 to fail the pipeline on a violation

## Policy
| License type | Examples | Action |
|---|---|---|
| Strong copyleft | GPL, AGPL | Denied: build fails |
| Weak copyleft | LGPL, MPL | Review: flagged for legal, build continues |
| Permissive | MIT, Apache-2.0, BSD | Allowed |
| Unknown | No license found | Review |

Vulnerabilities fail the build with `--fail-on-vulns`. Add `--min-severity` to block only at
a given level (`low`, `moderate`, `high`, `critical`). The pipeline blocks on HIGH and above.

## What the pipeline showed
| Build | Change | Result |
|---|---|---|
| 1 | Baseline scan | Failed: GPL v3 dependency (PyQt5) |
| 2 | Removed PyQt5 | Passed, but 117 known vulnerabilities across 5 packages |
| 3 | Enforced vulnerability policy | Failed: security policy |
| 4 | Upgraded dependencies | Passed both policies |
| 5 | Auto-triggered on push: GPL package re-added | Failed: license policy, no manual action |
| 6 | Reverted the change | Passed, auto-triggered |
| 7 | Severity threshold: block HIGH and CRITICAL only | Passed |

## Lessons
- **A green build can still ship risk.** License-only policy passed while 117 known
  vulnerabilities went through. Enforcing one policy is not enforcing all of them.
- **Licenses change between versions.** chardet moved from LGPL (5.2.0) to 0BSD (7.7.0),
  so a routine upgrade changed the legal position. Checks must run per version, not per package name.
- **Upgrading is not free.** Clearing vulnerabilities meant major version jumps (Django 2.2 to 6.1)
  that would break a real application. That is why real policies block on severity, not on everything.
- **Severity data has gaps.** Of Django 2.2.0's 75 vulnerabilities, 32 (43%) carried no severity
  label, so a "block on high" policy silently let them through. Many are likely duplicates of
  labeled advisories under a different ID. The fix is deduplicating across databases and treating
  unknown severity as "review", not "pass", before trusting the dashboard.

## Run it

    pip install requests
    python3 oss_checker.py --file requirements.txt
    python3 oss_checker.py --file requirements.txt --fail-on-vulns --min-severity high

## Jenkins
`jenkins/Dockerfile` builds Jenkins with Python. The `Jenkinsfile` runs the check on every
commit (polling every 2 minutes) and archives the CSV report. Jenkins is served over HTTPS
through a Caddy reverse proxy and is not exposed directly.
