"""Tests for FailureClassifier."""
import os
import tempfile
from agent.tools.failure_classifier import FailureClassifier


class TestFailureClassifier:
    def setup_method(self):
        self.tmpdir = tempfile.mkdtemp()
        os.makedirs(os.path.join(self.tmpdir, "CVE-2026-0001"))

    def test_classify_api_mismatch(self):
        log_path = os.path.join(self.tmpdir, "build.log")
        with open(log_path, "w") as f:
            f.write("error: too many arguments to function 'do_something'\n")
        classifier = FailureClassifier(self.tmpdir, "CVE-2026-0001")
        failure = classifier.classify(log_path)
        assert failure["category"] == "compile"
        assert failure["reason_code"] == "api_mismatch"
        assert failure["retryable"] is True

    def test_classify_api_argument_type_mismatch(self):
        log_path = os.path.join(self.tmpdir, "build.log")
        with open(log_path, "w") as f:
            f.write("error: passing argument 1 of 'do_something' from incompatible pointer type\n")
        classifier = FailureClassifier(self.tmpdir, "CVE-2026-0001")
        failure = classifier.classify(log_path)
        assert failure["category"] == "compile"
        assert failure["reason_code"] == "api_mismatch"

    def test_classify_no_fentry(self):
        log_path = os.path.join(self.tmpdir, "build.log")
        with open(log_path, "w") as f:
            f.write("no fentry call found for function example_check\n")
        classifier = FailureClassifier(self.tmpdir, "CVE-2026-0001")
        failure = classifier.classify(log_path)
        assert failure["category"] == "kpatch_limit"
        assert failure["reason_code"] == "no_fentry"

    def test_classify_hunk_failed(self):
        log_path = os.path.join(self.tmpdir, "build.log")
        with open(log_path, "w") as f:
            f.write("error: patch failed: net/example.c:100\nhunk FAILED\n")
        classifier = FailureClassifier(self.tmpdir, "CVE-2026-0001")
        failure = classifier.classify(log_path)
        assert failure["category"] == "patch_apply"
        assert failure["reason_code"] == "hunk_failed"

    def test_classify_unknown(self):
        log_path = os.path.join(self.tmpdir, "build.log")
        with open(log_path, "w") as f:
            f.write("some random build output\n")
        classifier = FailureClassifier(self.tmpdir, "CVE-2026-0001")
        failure = classifier.classify(log_path)
        assert failure["reason_code"] == "unrecognized"

    def test_failure_json_saved(self):
        log_path = os.path.join(self.tmpdir, "build.log")
        with open(log_path, "w") as f:
            f.write("error: too many arguments to function\n")
        classifier = FailureClassifier(self.tmpdir, "CVE-2026-0001")
        classifier.classify(log_path)
        failure_path = os.path.join(self.tmpdir, "CVE-2026-0001", "failure.json")
        assert os.path.exists(failure_path)
