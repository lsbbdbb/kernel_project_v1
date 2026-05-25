"""Patch Fetcher - downloads or generates patch files from various sources."""
import hashlib
import json
import os
import shutil

import requests
from datetime import datetime
from typing import Optional, Dict


def _url_to_cache_key(url: str) -> str:
    """Convert a URL to a safe filesystem cache key."""
    return hashlib.sha256(url.encode()).hexdigest()[:32]


class PatchFetcher:
    """Fetch and save original patch files."""

    def __init__(self, workdir: str, cve_id: str):
        self.workdir = workdir
        self.cve_id = cve_id
        self.patches_dir = os.path.join(workdir, cve_id, "patches")
        os.makedirs(self.patches_dir, exist_ok=True)

    @staticmethod
    def _patch_cache_dir() -> str:
        """Return the persistent patch cache directory."""
        cache_dir = os.path.expanduser("~/.cache/kpatch-agent/patches")
        os.makedirs(cache_dir, exist_ok=True)
        return cache_dir

    def fetch_from_url(self, url: str, verify_ssl: bool = True) -> Dict:
        result = {
            "source_url": url,
            "success": False,
            "error": None,
            "path": None,
        }
        # Check persistent cache first — copy to workdir if found
        cache_key = _url_to_cache_key(url)
        cache_dir = self._patch_cache_dir()
        cache_path = os.path.join(cache_dir, f"{cache_key}.patch")
        if os.path.isfile(cache_path):
            workdir_path = os.path.join(self.patches_dir, "original.patch")
            shutil.copy2(cache_path, workdir_path)
            result["success"] = True
            result["path"] = workdir_path
            result["size"] = os.path.getsize(cache_path)
            result["note"] = "loaded from cache"
            return result

        try:
            headers = {"User-Agent": "kernel-livepatch-agent/1.0"}
            resp = requests.get(url, timeout=60, verify=verify_ssl, headers=headers)
            if resp.status_code == 200:
                if b"diff --git " not in resp.content:
                    result["error"] = "Response does not contain a unified git diff"
                else:
                    # Save to workdir AND persistent cache
                    path = os.path.join(self.patches_dir, "original.patch")
                    with open(path, "wb") as f:
                        f.write(resp.content)
                    shutil.copy2(path, cache_path)
                    result["success"] = True
                    result["path"] = path
                    result["size"] = len(resp.content)
            else:
                result["error"] = f"HTTP {resp.status_code}"
        except Exception as e:
            result["error"] = str(e)
        meta_path = os.path.join(self.patches_dir, "patch_source.json")
        with open(meta_path, "w") as f:
            json.dump(result, f, indent=2)
        return result

    def save_raw_patch(self, content: str, source_info: Dict) -> Dict:
        path = os.path.join(self.patches_dir, "original.patch")
        with open(path, "w") as f:
            f.write(content)
        result = {
            "source": source_info,
            "success": True,
            "path": path,
            "size": len(content),
        }
        meta_path = os.path.join(self.patches_dir, "patch_source.json")
        with open(meta_path, "w") as f:
            json.dump(result, f, indent=2)
        return result
