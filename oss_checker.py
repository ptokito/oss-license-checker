"""
oss_checker.py
A mini version of what FOSSA does for a Python project:
  1. Reads the project's dependency list (requirements.txt)
  2. Looks up each package's license (from PyPI, the Python package registry)
  3. Looks up known vulnerabilities for that exact version (from OSV.dev, Google's free database)
  4. Writes a CSV report a lawyer or project manager can open in Excel
  5. Applies a policy and fails the build (exit code 1) if the policy is broken

Run it:
  pip install requests
  python3 oss_checker.py                      # checks requirements.txt
  python3 oss_checker.py --file other.txt     # checks a different file
  python3 oss_checker.py --fail-on-vulns      # also fail the build on vulnerabilities
"""

import argparse   # reads options typed on the command line (like --file)
import csv        # writes the spreadsheet report
import sys        # lets us set the exit code that Jenkins / GitHub Actions reads

import requests   # calls web APIs

# ---------------------------------------------------------------------------
# POLICY: the rules the customer's legal team sets.
# In FOSSA this lives in the web UI; here it is just two lists.
# ---------------------------------------------------------------------------
DENIED_LICENSES = ["AGPL", "GPL"]   # copyleft: may force you to publish your own code
FLAGGED_LICENSES = ["LGPL", "MPL"]  # weaker copyleft: allowed, but legal should review
# Note: "LGPL" also contains "GPL", so we check the flagged list first.


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


def get_vulns(name, version):
    """Ask OSV.dev for known vulnerabilities in this exact version."""
    payload = {"package": {"name": name, "ecosystem": "PyPI"}, "version": version}
    try:
        r = requests.post("https://api.osv.dev/v1/query", json=payload, timeout=10)
        r.raise_for_status()
        vulns = r.json().get("vulns", [])             # empty list if there are none
        return [v["id"] for v in vulns]               # keep just the IDs, e.g. "GHSA-x84v-..."
    except requests.RequestException as e:
        print(f"  Could not reach OSV for {name}: {e}")
        return None                                   # None means "we don't know", not "safe"


def license_status(lic):
    """Apply the policy to one license."""
    upper = lic.upper()
    if lic == "UNKNOWN":
        return "REVIEW"                               # unknown is a risk; a human must look
    if any(x in upper for x in FLAGGED_LICENSES) or "LESSER" in upper:
        return "REVIEW"
    if any(x in upper for x in DENIED_LICENSES) or "GENERAL PUBLIC" in upper:
        return "DENIED"
    return "OK"


def main():
    parser = argparse.ArgumentParser(description="Open source license and vulnerability check")
    parser.add_argument("--file", default="requirements.txt", help="dependency file to scan")
    parser.add_argument("--report", default="oss_report.csv", help="where to save the CSV")
    parser.add_argument("--fail-on-vulns", action="store_true", help="fail the build on any vulnerability")
    args = parser.parse_args()

    packages = read_requirements(args.file)
    print(f"Scanning {len(packages)} packages from {args.file}\n")

    denied, review, vulnerable, unchecked = [], [], [], []

    with open(args.report, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["package", "version", "license", "license_status", "vuln_count", "vuln_ids"])

        for name, version in packages:
            lic = get_license(name, version)
            status = license_status(lic)
            vulns = get_vulns(name, version)

            vuln_count = "unknown" if vulns is None else len(vulns)
            vuln_ids = "" if not vulns else " ".join(vulns[:5])   # first 5 IDs keeps the sheet readable

            writer.writerow([name, version, lic, status, vuln_count, vuln_ids])
            pkg = f"{name}=={version}"
            print(f"{pkg:<22} license: {lic:<28} [{status}]  vulns: {vuln_count}")

            if status == "DENIED":
                denied.append(name)
            elif status == "REVIEW":
                review.append(name)
            if vulns:
                vulnerable.append(name)
            elif vulns is None:
                unchecked.append(name)

    # ---------------- Summary: what a CSE would tell the customer ----------------
    print(f"\nReport saved to {args.report}")
    print(f"Denied licenses:       {denied or 'none'}")
    print(f"Needs legal review:    {review or 'none'}")
    print(f"Known vulnerabilities: {vulnerable or 'none'}")
    if unchecked:
        print(f"Vulns not checked:     {unchecked} (OSV.dev unreachable)")

    # ---------------- Policy gate: the exit code the pipeline reads ----------------
    failed = bool(denied) or (args.fail_on_vulns and bool(vulnerable))
    if failed:
        print("\nPOLICY FAILED: build blocked")
        sys.exit(1)      # non-zero = Jenkins / GitHub Actions marks the build as failed
    print("\nPOLICY PASSED")
    sys.exit(0)


if __name__ == "__main__":
    main()
