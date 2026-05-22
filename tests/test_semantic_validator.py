"""Tests for SemanticValidator."""
import pytest
from agent.tools.semantic_validator import SemanticValidator


ORIGINAL_PATCH = """--- a/net/example.c
+++ b/net/example.c
@@ -100,6 +100,8 @@ static int example_check(struct sock *sk)
 {
 \tint ret = 0;
 
+\tif (!sk)
+\t\treturn -EINVAL;
 \tlock_sock(sk);
 \tret = do_check(sk);
 \tunlock_sock(sk);
"""

REWRITTEN_GOOD = """--- a/net/example.c
+++ b/net/example.c
@@ -100,6 +100,8 @@ static int example_fix(struct sock *sk)
 {
 \tint ret = 0;
 
+\tif (!sk)
+\t\treturn -EINVAL;
 \tlock_sock(sk);
 \tret = do_fix(sk);
 \tunlock_sock(sk);
"""

REWRITTEN_MISSING_CHECK = """--- a/net/example.c
+++ b/net/example.c
@@ -100,6 +100,6 @@ static int example_fix(struct sock *sk)
 {
 \tint ret = 0;
 
 \tlock_sock(sk);
 \tret = do_fix(sk);
"""

REWRITTEN_NEW_GLOBAL = """--- a/net/example.c
+++ b/net/example.c
@@ -100,6 +100,9 @@ static int example_fix(struct sock *sk)
 {
 \tint ret = 0;
 
+\tif (!sk)
+\t\treturn -EINVAL;
+static int new_global_counter = 0;
 \tlock_sock(sk);
 \tret = do_fix(sk);
 \tunlock_sock(sk);
"""


class TestSemanticValidator:
    def setup_method(self):
        self.validator = SemanticValidator()

    def test_valid_rewrite_passes(self):
        result = self.validator.validate(ORIGINAL_PATCH, REWRITTEN_GOOD)
        assert result["valid"] is True

    def test_missing_security_check_fails(self):
        result = self.validator.validate(ORIGINAL_PATCH, REWRITTEN_MISSING_CHECK)
        assert result["valid"] is False
        assert any("security" in i.lower() for i in result["issues"])

    def test_new_global_detected(self):
        result = self.validator.validate(ORIGINAL_PATCH, REWRITTEN_NEW_GLOBAL)
        assert result["valid"] is False
        assert any("global" in i.lower() or "export" in i.lower()
                   for i in result["issues"])

    def test_error_return_preserved_detection(self):
        # Patch with error returns should be ok
        result = self.validator.validate(ORIGINAL_PATCH, REWRITTEN_GOOD)
        missing_error = any("error return" in i.lower() for i in result["issues"])
        assert not missing_error

    def test_empty_patches_pass(self):
        result = self.validator.validate("", "")
        assert result["valid"] is True

    def test_identical_patches_pass(self):
        result = self.validator.validate(ORIGINAL_PATCH, ORIGINAL_PATCH)
        assert result["valid"] is True
