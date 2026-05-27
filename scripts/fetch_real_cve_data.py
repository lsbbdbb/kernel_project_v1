#!/usr/bin/env python3
"""Fetch real CVE data from NVD API 2.0 and GitHub kernel mirror.

Usage:
    python3 scripts/fetch_real_cve_data.py CVE-2025-21638

Output:
    tests/testdata/patches/<CVE-ID>_<scenario>.patch
    tests/testdata/metadata/<CVE-ID>_metadata.json
"""

import json
import os
import re
import sys
import urllib.request

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="
GITHUB_PATCH = "https://github.com/torvalds/linux/commit/{}.patch"
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def fetch_nvd(cve_id):
    url = NVD_API + cve_id
    with urllib.request.urlopen(url, timeout=30) as resp:
        data = json.load(resp)
    vuln = data["vulnerabilities"][0]["cve"]
    return vuln


def find_stable_commit(nvd_data):
    """Find a git.kernel.org/stable/c/<hash> reference in NVD data."""
    for ref in nvd_data.get("references", []):
        url = ref.get("url", "")
        m = re.search(r'git\.kernel\.org/stable/c/([a-f0-9]{12,})', url)
        if m:
            return m.group(1)
    # Fallback: any 40-char commit hash in references (torvalds or stable)
    for ref in nvd_data.get("references", []):
        url = ref.get("url", "")
        m = re.search(r'/([a-f0-9]{40})\b', url)
        if m:
            return m.group(1)
    return None


def fetch_patch(commit_hash):
    url = GITHUB_PATCH.format(commit_hash)
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.read().decode("utf-8")


def build_metadata(cve_id, nvd, commit_hash):
    desc = nvd.get("descriptions", [{}])[0].get("value", "")
    cvss_data = {}
    metrics = nvd.get("metrics", {})
    if "cvssMetricV31" in metrics:
        cvss_data = metrics["cvssMetricV31"][0]["cvssData"]
    elif "cvssMetricV30" in metrics:
        cvss_data = metrics["cvssMetricV30"][0]["cvssData"]
    elif "cvssMetricV2" in metrics:
        cvss_data = metrics["cvssMetricV2"][0]["cvssData"]

    return {
        "cve_id": cve_id,
        "nvd": {
            "description": desc,
            "cvss": {
                "version": cvss_data.get("version", "N/A"),
                "score": cvss_data.get("baseScore", 0),
                "severity": cvss_data.get("baseSeverity", "NONE"),
                "vectorString": cvss_data.get("vectorString", ""),
            },
            "references": [
                {"url": ref["url"], "source": ref.get("source", "")}
                for ref in nvd.get("references", [])
            ],
        },
        "candidates": [{
            "source": "linux_stable",
            "commit_id": commit_hash,
            "branch": "linux-6.6.y",
            "confidence": 0.95,
        }],
    }


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 scripts/fetch_real_cve_data.py CVE-YYYY-NNNN")
        sys.exit(1)

    cve_id = sys.argv[1]
    patches_dir = os.path.join(PROJECT_ROOT, "tests", "testdata", "patches")
    metadata_dir = os.path.join(PROJECT_ROOT, "tests", "testdata", "metadata")
    os.makedirs(patches_dir, exist_ok=True)
    os.makedirs(metadata_dir, exist_ok=True)

    print("[1/3] Fetching NVD data for {}...".format(cve_id))
    nvd = fetch_nvd(cve_id)

    print("[2/3] Finding stable commit hash...")
    commit_hash = find_stable_commit(nvd)
    if not commit_hash:
        print("ERROR: No stable commit found for {}".format(cve_id))
        print("References checked:")
        for ref in nvd.get("references", []):
            print("  - {}".format(ref.get("url", "")))
        sys.exit(1)
    print("  Found commit: {}".format(commit_hash))

    print("[3/3] Fetching patch from GitHub...")
    try:
        patch_content = fetch_patch(commit_hash)
    except urllib.error.HTTPError as e:
        print("ERROR: HTTP {} fetching patch for commit {}".format(e.code, commit_hash))
        print("  URL: {}".format(GITHUB_PATCH.format(commit_hash)))
        # Try with longer hash
        if len(commit_hash) < 40:
            print("  Trying full 40-char hash from URL...")
            # Search NVD refs for the full hash
            for ref in nvd.get("references", []):
                url = ref.get("url", "")
                m = re.search(r'/([a-f0-9]{40})\b', url)
                if m and m.group(1).startswith(commit_hash):
                    commit_hash = m.group(1)
                    print("  Found full hash: {}".format(commit_hash))
                    break
            patch_content = fetch_patch(commit_hash)
        else:
            raise

    # Extract scenario name from patch subject
    subject_match = re.search(r'Subject: \[PATCH[^\]]*\]\s*(.+)', patch_content)
    if subject_match:
        scenario = subject_match.group(1).strip()[:40].lower().replace(" ", "_")
    else:
        scenario = "fix"
    scenario = re.sub(r'[^a-z0-9_]', '', scenario)
    scenario = scenario[:50]

    # Write patch file
    patch_path = os.path.join(patches_dir, "{}_{}.patch".format(cve_id, scenario))
    with open(patch_path, "w") as f:
        f.write(patch_content)
    print("  Patch written: {}".format(patch_path))

    # Build and write metadata
    metadata = build_metadata(cve_id, nvd, commit_hash)
    metadata_path = os.path.join(metadata_dir, "{}_metadata.json".format(cve_id))
    with open(metadata_path, "w") as f:
        json.dump(metadata, f, indent=2)
    print("  Metadata written: {}".format(metadata_path))

    print("Done: {}".format(cve_id))

    # Print summary for registration in conftest.py
    diff_files = re.findall(r'--- a/(.*?)\n\+\+\+ b/', patch_content)
    print("\n  CVE: {}".format(cve_id))
    print("  Scenario: {}".format(scenario))
    print("  Files changed: {}: {}".format(len(diff_files), diff_files))
    print("  CVSS: {} {}".format(metadata['nvd']['cvss']['score'], metadata['nvd']['cvss']['severity']))


if __name__ == "__main__":
    main()
