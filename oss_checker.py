"""
oss_checker.py
A mini version of what FOSSA does for a Python project:
  1. Reads the project's dependency list (requirements.txt)
  2. Looks up each package's license (from PyPI, the Python package registry)
  3. Looks up known vulnerabilities and their severity (from OSV.dev, Google's free database)
  4. Writes a CSV report a lawyer or project manager can open in Excel
  5. Applies a policy and fails the build (exit code 1) if the policy is broken

Run it:
  pip install requests
  python3 oss_checker.py                                    # license policy only
  python3 oss_checker.py --fail-on-vulns                    # also fail on ANY vulnerability
  python3 oss_checker.py --fail-on-vulns --min-severity high  # fail only on HIGH or CRITICAL
"""

import argparse   # reads options typed on the command line (like --file)
import csv        # writes the spreadsheet report
import sys        # lets us set the exit code that Jenkins / GitHub Actions reads

import requests   # calls web APIs

# ---------------------------------------------------------------------------
# POLICY: the rules the customer's legal and security teams set.
# In FOSSA this lives in the web UI; here it is just lists and a ranking.
# ---------------------------------------------------------------------------
DENIED_LICENSES = ["AGPL", "GPL"]   # copyleft: may force you to publish your own code
FLAGGED_LICENSES = ["LGPL", "MPL"]  # weaker copyleft: allowed, but legal should review
# Note: "LGPL" also contains "GPL", so we check the flagged list first.

# Severity ranking, so we can compare "is this at least HIGH?" with a simple >=.
# GitHub's advisory database says MODERATE where other sources say MEDIUM, so both map to 2.
SEVERITY_RANK = {"UNKNOWN": 0, "LOW": 1, "MODERATE": 2, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def read_requirements(path):
    """Turn lines like 'requests==2.19.0' into a list of (name, version) pairs."""
    packages = []
    with open(path) as f:
        for line in f:
            line = line.strip()                      # remove spaces and line breaks
            if not line or line.startswith("#"):     # skip blank lines and comments
                continue
            if "==" not in line:                     # we need an exact version to check vulns
                print(f"Skipping '{line}': no pinned version (use name==version)")
                continue
            name, version = line.split("==", 1)      # 'requests==2.19.0' -> 'requests', '2.19.0'
            packages.append((name.strip(), version.strip()))
    return packages


def get_license(name, version):
    """Ask PyPI which license this package version uses."""
    url = f"https://pypi.org/pypi/{name}/{version}/json"
    try:
        r = requests.get(url, timeout=10)
        r.raise_for_status()                          # turn a 404 or 500 into an error
        info = r.json()["info"]                       # JSON becomes a dictionary
    except requests.RequestException as e:
        print(f"  Could not reach PyPI for {name}: {e}")
        return "UNKNOWN"

    # Packages record their license in different places, so try the best one first.
    if info.get("license_expression"):                # newest standard, e.g. "MIT"
        return info["license_expression"]
    for c in info.get("classifiers", []):             # e.g. "License :: OSI Approved :: MIT License"
        if c.startswith("License ::"):
            return c.split("::")[-1].strip()
    lic = (info.get("license") or "").strip()         # older free-text field
    if lic and len(lic) < 60:                         # ignore it if someone pasted the whole license text
        return lic
    return "UNKNOWN"


def vuln_severity(vuln):
    """
    Pull the severity label out of one vulnerability record.
    The record is nested JSON, roughly:
      {"id": "GHSA-...", "database_specific": {"severity": "HIGH"}, ...}
    GitHub advisories (GHSA-...) carry a label; some other sources (PYSEC-...) do not.
    """
    label = (vuln.get("database_specific") or {}).get("severity", "UNKNOWN")
    label = str(label).upper()
    return label if label in SEVERITY_RANK else "UNKNOWN"


def get_vulns(name, version):
    """Ask OSV.dev for known vulnerabilities in this exact version.
    Returns a list of (id, severity) pairs, or None if the lookup failed."""
    payload = {"package": {"name": name, "ecosystem": "PyPI"}, "version": version}
    try:
        r = requests.post("https://api.osv.dev/v1/query", json=payload, timeout=10)
        r.raise_for_status()
        vulns = r.json().get("vulns", [])             # empty list if there are none
        return [(v["id"], vuln_severity(v)) for v in vulns]
    except requests.RequestException as e:
        print(f"  Could not reach OSV for {name}: {e}")
        return None                                   # None means "we don't know", not "safe"


def license_status(lic):
    """Apply the license policy to one license."""
    upper = lic.upper()
    if lic == "UNKNOWN":
        return "REVIEW"                               # unknown is a risk; a human must look
    if any(x in upper for x in FLAGGED_LICENSES) or "LESSER" in upper:
        return "REVIEW"
    if any(x in upper for x in DENIED_LICENSES) or "GENERAL PUBLIC" in upper:
        return "DENIED"
    return "OK"


def highest(severities):
    """Return the worst severity in a list, e.g. ['LOW', 'HIGH'] -> 'HIGH'."""
    if not severities:
        return "NONE"
    return max(severities, key=lambda s: SEVERITY_RANK[s])


def main():
    parser = argparse.ArgumentParser(description="Open source license and vulnerability check")
    parser.add_argument("--file", default="requirements.txt", help="dependency file to scan")
    parser.add_argument("--report", default="oss_report.csv", help="where to save the CSV")
    parser.add_argument("--fail-on-vulns", action="store_true", help="fail the build on vulnerabilities")
    parser.add_argument("--min-severity", default="low", choices=["low", "moderate", "high", "critical"],
                        help="with --fail-on-vulns, only fail at this severity or above (default: low = any)")
    args = parser.parse_args()
    threshold = SEVERITY_RANK[args.min_severity.upper()]

    packages = read_requirements(args.file)
    print(f"Scanning {len(packages)} packages from {args.file}")
    if args.fail_on_vulns:
        print(f"Vulnerability policy: block at {args.min_severity.upper()} or above")
    print()

    denied, review, blocking_vulns, unchecked = [], [], [], []
    totals = {"CRITICAL": 0, "HIGH": 0, "MODERATE": 0, "LOW": 0, "UNKNOWN": 0}

    with open(args.report, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["package", "version", "license", "license_status",
                         "vuln_count", "critical", "high", "moderate", "low", "unknown",
                         "worst_severity", "vuln_ids"])

        for name, version in packages:
            lic = get_license(name, version)
            status = license_status(lic)
            vulns = get_vulns(name, version)

            if vulns is None:
                unchecked.append(name)
                counts = {k: "" for k in totals}
                worst, vuln_count, ids = "UNCHECKED", "unknown", ""
            else:
                # Count this package's vulnerabilities by severity
                counts = {k: 0 for k in totals}
                for _id, sev in vulns:
                    key = "MODERATE" if sev == "MEDIUM" else sev
                    counts[key] += 1
                    totals[key] += 1
                worst = highest([sev for _id, sev in vulns])
                vuln_count = len(vulns)
                ids = " ".join(vid for vid, _sev in vulns[:5])   # first 5 keeps the sheet readable

                # Does any vulnerability meet or beat the threshold?
                if any(SEVERITY_RANK[sev] >= threshold for _id, sev in vulns if sev != "UNKNOWN"):
                    blocking_vulns.append(f"{name} ({worst})")

            writer.writerow([name, version, lic, status, vuln_count,
                             counts["CRITICAL"], counts["HIGH"], counts["MODERATE"],
                             counts["LOW"], counts["UNKNOWN"], worst, ids])
            pkg = f"{name}=={version}"
            print(f"{pkg:<22} license: {lic:<28} [{status}]  vulns: {vuln_count} (worst: {worst})")

            if status == "DENIED":
                denied.append(name)
            elif status == "REVIEW":
                review.append(name)

    # ---------------- Summary: what a CSE would tell the customer ----------------
    print(f"\nReport saved to {args.report}")
    print(f"Denied licenses:       {denied or 'none'}")
    print(f"Needs legal review:    {review or 'none'}")
    print("Vulnerabilities:       " + ", ".join(f"{k.lower()} {v}" for k, v in totals.items()))
    if args.fail_on_vulns:
        print(f"Blocking ({args.min_severity}+):     {blocking_vulns or 'none'}")
    if totals["UNKNOWN"]:
        print("Note: vulnerabilities with no severity label never block; review them by hand.")
    if unchecked:
        print(f"Vulns not checked:     {unchecked} (OSV.dev unreachable)")

    # ---------------- Policy gate: the exit code the pipeline reads ----------------
    failed = bool(denied) or (args.fail_on_vulns and bool(blocking_vulns))
    if failed:
        print("\nPOLICY FAILED: build blocked")
        sys.exit(1)      # non-zero = Jenkins / GitHub Actions marks the build as failed
    print("\nPOLICY PASSED")
    sys.exit(0)


if __name__ == "__main__":
    main()