"""Detect patches that target code omitted by the target kernel config."""
import os
import re
from typing import Dict, List


class KernelConfigChecker:
    """Resolve patched source files through Kbuild Makefiles and `.config`."""

    CONFIG_LINE = re.compile(r"^(CONFIG_[A-Z0-9_]+)=(.+)$")
    DISABLED_LINE = re.compile(r"^# (CONFIG_[A-Z0-9_]+) is not set$")
    KBUILD_LINE = re.compile(
        r"^[A-Za-z0-9_-]+-\$\((CONFIG_[A-Z0-9_]+)\)\s*(?:\+?=|:=)\s*(.+)$"
    )

    def __init__(self, source_dir: str):
        self.source_dir = source_dir
        self.config_path = os.path.join(source_dir, ".config")

    def check_files(self, patched_files: List[str]) -> Dict:
        config = self._read_config()
        result = {
            "config_path": self.config_path,
            "available": os.path.isfile(self.config_path),
            "files": [],
            "disabled": [],
            "skipped": False,
        }
        if not result["available"]:
            return result

        for path in patched_files:
            symbols = self._resolve_symbols(path)
            status = [
                {"symbol": symbol, "value": config.get(symbol, "not_set"),
                 "enabled": config.get(symbol) in {"y", "m"}}
                for symbol in sorted(symbols)
            ]
            disabled_by_config = bool(status) and all(
                not item["enabled"] for item in status
            )
            file_result = {
                "path": path,
                "config_symbols": status,
                "disabled_by_config": disabled_by_config,
            }
            result["files"].append(file_result)
            if disabled_by_config:
                result["disabled"].append(file_result)

        if result["files"] and all(
            item["disabled_by_config"] for item in result["files"]
        ):
            result["skipped"] = True
            result["failure_mode"] = "config.module_disabled"
            result["reason_code"] = "module_disabled"
        return result

    def _read_config(self) -> Dict[str, str]:
        values: Dict[str, str] = {}
        if not os.path.isfile(self.config_path):
            return values
        with open(self.config_path, encoding="utf-8", errors="ignore") as config_file:
            for line in config_file:
                line = line.strip()
                match = self.CONFIG_LINE.match(line)
                if match:
                    values[match.group(1)] = match.group(2)
                    continue
                match = self.DISABLED_LINE.match(line)
                if match:
                    values[match.group(1)] = "not_set"
        return values

    def _resolve_symbols(self, patched_file: str) -> set:
        normalized = patched_file.removeprefix("a/").removeprefix("b/")
        relative_dir = os.path.dirname(normalized)
        target = os.path.splitext(os.path.basename(normalized))[0] + ".o"
        symbols = set()

        while relative_dir:
            makefile = os.path.join(self.source_dir, relative_dir, "Makefile")
            if os.path.isfile(makefile):
                with open(makefile, encoding="utf-8", errors="ignore") as contents:
                    for line in contents:
                        match = self.KBUILD_LINE.match(line.strip())
                        if match and self._contains_target(match.group(2), target):
                            symbols.add(match.group(1))
            parent = os.path.dirname(relative_dir)
            if parent == relative_dir:
                break
            target = os.path.basename(relative_dir) + "/"
            relative_dir = parent
        return symbols

    @staticmethod
    def _contains_target(value: str, target: str) -> bool:
        targets = re.split(r"\s+", value.split("#", 1)[0].strip())
        return target in targets
