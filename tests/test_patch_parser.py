"""Tests for PatchParser."""
import os
import tempfile
import pytest
from agent.tools.patch_parser import PatchParser


SAMPLE_PATCH = """From: Test Author <test@kernel.org>
Subject: [PATCH] Fix boundary check in example function

diff --git a/net/example.c b/net/example.c
index abc..def 100644
--- a/net/example.c
+++ b/net/example.c
@@ -100,6 +100,10 @@ int example_check(struct sk_buff *skb, unsigned int len)
 {
 	int ret = 0;
 
+	if (len > MAX_LEN) {
+		return -EINVAL;
+	}
+
 	ret = do_something(skb, len);
 	return ret;
 }
"""


class TestPatchParser:
    def setup_method(self):
        self.tmpdir = tempfile.mkdtemp()
        self.patch_path = os.path.join(self.tmpdir, "test.patch")
        with open(self.patch_path, "w") as f:
            f.write(SAMPLE_PATCH)

    def test_parse_patch_basic(self):
        parser = PatchParser(self.tmpdir, "CVE-2026-0001")
        patch_ir = parser.parse_patch(self.patch_path)
        assert len(patch_ir["files"]) >= 1

    def test_change_units_generated(self):
        parser = PatchParser(self.tmpdir, "CVE-2026-0001")
        parser.parse_patch(self.patch_path)
        change_path = os.path.join(self.tmpdir, "CVE-2026-0001", "change_units.json")
        assert os.path.exists(change_path)

    def test_semantic_summary_contains_boundary(self):
        parser = PatchParser(self.tmpdir, "CVE-2026-0001")
        patch_ir = parser.parse_patch(self.patch_path)
        summary = patch_ir.get("semantic_summary", "")
        assert "boundary" in summary

    def test_patch_ir_saved(self):
        parser = PatchParser(self.tmpdir, "CVE-2026-0001")
        parser.parse_patch(self.patch_path)
        ir_path = os.path.join(self.tmpdir, "CVE-2026-0001", "patch_ir.json")
        assert os.path.exists(ir_path)

    def test_files_parsed(self):
        parser = PatchParser(self.tmpdir, "CVE-2026-0001")
        patch_ir = parser.parse_patch(self.patch_path)
        assert len(patch_ir["files"]) > 0

    def test_risk_tags_detected(self):
        parser = PatchParser(self.tmpdir, "CVE-2026-0001")
        patch_ir = parser.parse_patch(self.patch_path)
        assert isinstance(patch_ir.get("risk_tags"), list)

    def test_rejects_placeholder_without_unified_diff(self):
        with open(self.patch_path, "w") as f:
            f.write("# No upstream patch found\n")

        with pytest.raises(ValueError, match="no unified diff"):
            PatchParser(self.tmpdir, "CVE-2026-0001").parse_patch(self.patch_path)
