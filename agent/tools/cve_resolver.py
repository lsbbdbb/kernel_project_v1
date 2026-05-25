"""CVE Resolver - queries NVD, Linux CVE announce, and Linux stable for CVE information."""
import json
import os
import re
import requests
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any


class CVEResolver:
    """Multi-source CVE information resolver."""

    NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    STABLE_GIT_BASE = "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git"
    
    def __init__(self, workdir: str, cve_id: str):
        self.workdir = workdir
        self.cve_id = cve_id
        self.metadata_dir = os.path.join(workdir, cve_id, "metadata")
        os.makedirs(self.metadata_dir, exist_ok=True)

    @staticmethod
    def _nvd_cache_dir() -> str:
        cache_dir = os.path.expanduser("~/.cache/kpatch-agent/nvd")
        os.makedirs(cache_dir, exist_ok=True)
        return cache_dir

    def query_nvd(self) -> Dict:
        """Query NVD for CVE metadata with retry + fallback to disk cache."""
        url = f"{self.NVD_API_BASE}?cveId={self.cve_id}"
        result = {"source": "nvd", "cve_id": self.cve_id, 
                  "description": "", "cvss": None, "references": [],
                  "error": None}

        # Try disk cache first
        cache_dir = self._nvd_cache_dir()
        cache_path = os.path.join(cache_dir, f"{self.cve_id}.json")
        if os.path.isfile(cache_path):
            try:
                with open(cache_path) as f:
                    cached = json.load(f)
                if cached.get("references"):
                    result = cached
                    result["note"] = "loaded from disk cache"
                    self._save_metadata("raw_nvd.json", result)
                    return result
            except (json.JSONDecodeError, OSError):
                pass
        
        # Exponential backoff retry for transient network errors
        import time
        max_retries = 3
        for attempt in range(max_retries):
            try:
                resp = requests.get(url, timeout=30)
                if resp.status_code == 200:
                    data = resp.json()
                    vulnerabilities = data.get("vulnerabilities", [])
                    if vulnerabilities:
                        cve_item = vulnerabilities[0].get("cve", {})
                        descriptions = cve_item.get("descriptions", [])
                        for desc in descriptions:
                            if desc.get("lang") == "en":
                                result["description"] = desc.get("value", "")
                                break
                        metrics = cve_item.get("metrics", {})
                        for severity_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                            if metrics.get(severity_key):
                                cvss_data = metrics[severity_key][0].get("cvssData", {})
                                result["cvss"] = {
                                    "version": cvss_data.get("version"),
                                    "score": cvss_data.get("baseScore"),
                                    "severity": cvss_data.get("baseSeverity"),
                                }
                                break
                        refs = cve_item.get("references", [])
                        result["references"] = [
                            {"url": r.get("url"), "source": r.get("source", "")}
                            for r in refs
                        ]
                    self._save_metadata("raw_nvd.json", result)
                    # Save successful result to disk cache
                    try:
                        with open(cache_path, "w") as f:
                            json.dump(result, f, indent=2)
                    except OSError:
                        pass
                    return result
                elif resp.status_code == 429 and attempt < max_retries - 1:
                    time.sleep(2 ** attempt)
                    continue
                else:
                    result["error"] = f"HTTP {resp.status_code}"
            except Exception as e:
                result["error"] = str(e)
                if attempt < max_retries - 1:
                    time.sleep(2 ** attempt)
                    continue
        
        self._save_metadata("raw_nvd.json", result)
        return result

    def search_stable_commits(self) -> List[Dict]:
        """Search stable tree for fix commits by CVE ID.

        Extracts commit hashes from NVD references that point to
        git.kernel.org, and returns them as candidate commits.
        """
        candidates = []
        # First, try to find commit hashes from NVD references already fetched
        nvd_path = os.path.join(self.metadata_dir, "raw_nvd.json")
        if os.path.exists(nvd_path):
            try:
                with open(nvd_path) as f:
                    nvd_data = json.load(f)
                seen_hashes = set()
                for ref in nvd_data.get("references", []):
                    url = ref.get("url", "")
                    _m = re.match(r'(https?://git\.kernel\.org)/.*?/c/([0-9a-f]{7,})', url)
                    if _m:
                        commit_hash = _m.group(2)
                        if commit_hash not in seen_hashes:
                            seen_hashes.add(commit_hash)
                            candidates.append({
                                "source": "nvd_reference",
                                "commit": commit_hash,
                                "patch_url": f"{_m.group(1)}/pub/scm/linux/kernel/git/stable/linux.git/patch/?id={commit_hash}",
                                "commit_url": url,
                            })
            except (json.JSONDecodeError, OSError):
                pass

        if not candidates:
            # Fallback: record the CVE-ID-based search URL
            candidates.append({
                "source": "linux_stable",
                "query": self.cve_id,
                "search_url": f"{self.STABLE_GIT_BASE}/log/?search={self.cve_id}",
                "status": "searched",
                "note": "No kernel.org commit URL found in NVD references — search URL recorded for manual follow-up",
            })
        return candidates

    def resolve(self) -> Dict:
        nvd_data = self.query_nvd()
        # Only use CVE ID as search keyword — description words are meaningless as search terms
        candidates = self.search_stable_commits()
        result = {
            "cve_id": self.cve_id,
            "nvd": nvd_data,
            "candidates": candidates,
            "resolved_at": datetime.now(timezone.utc).isoformat(),
        }
        self._save_metadata("cve_metadata.json", result)
        return result

    def _save_metadata(self, filename: str, data: Any):
        path = os.path.join(self.metadata_dir, filename)
        with open(path, "w") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
