# OSS License and Vulnerability Policy Gate

A small Python tool and Jenkins pipeline that checks a project's open source dependencies
for license compliance and known vulnerabilities, writes a report for legal and security
teams, and blocks the build when policy is broken.

## What it does
1. Reads pinned dependencies from `requirements.txt`
2. Looks up each package's license for that exact version (PyPI)
3. Looks up known vulnerabilities for that exact version (OSV.dev)
4. Writes `oss_report.csv` for legal and security review
5. Applies policy and exits with code 1 to fail the pipeline on a violation

## Policy
| License type | Examples | Action |
|---|---|---|
| Strong copyleft | GPL, AGPL | Denied: build fails |
| Weak copyleft | LGPL, MPL | Review: flagged for legal, build continues |
| Permissive | MIT, Apache-2.0, BSD | Allowed |
| Unknown | No license found | Review |

Vulnerabilities fail the build when run with `--fail-on-vulns`.

## What the pipeline showed
| Build | Change | Result |
|---|---|---|
| 1 | Baseline scan | Failed: GPL v3 dependency (PyQt5) |
| 2 | Removed PyQt5 | Passed, but 117 known vulnerabilities across 5 packages |
| 3 | Enforced vulnerability policy | Failed: security policy |
| 4 | Upgraded dependencies | Passed both policies |

## Lessons
- **A green build can still ship risk.** License-only policy passed while 117 known
  vulnerabilities went through. Enforcing one policy is not enforcing all of them.
- **Licenses change between versions.** chardet moved from LGPL (5.2.0) to 0BSD (7.7.0),
  so a routine upgrade changed the legal position. Checks must run per version, not per package name.
- **Upgrading is not free.** Clearing vulnerabilities meant major version jumps (Django 2.2 to 6.1)
  that would break a real application. Real policies usually block on critical and high severity
  and track the rest with remediation deadlines.

## Run it

## Jenkins
`jenkins/Dockerfile` builds Jenkins with Python. The `Jenkinsfile` runs the check on every
build and archives the CSV report.
