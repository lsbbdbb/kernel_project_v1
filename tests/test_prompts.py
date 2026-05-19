"""Tests for LLM prompt templates."""
from agent.llm.prompts.templates import (
    decide_retry,
    diagnose_failure,
    generate_rewrite_diff,
    plan_rewrite_strategy,
)


def _assert_messages(messages):
    assert isinstance(messages, list)
    assert len(messages) == 2
    assert messages[0]["role"] == "system"
    assert messages[1]["role"] == "user"
    assert messages[1]["content"]


def test_diagnose_failure_template():
    messages = diagnose_failure("error: too many arguments to function", {"files": ["net/x.c"]})

    _assert_messages(messages)
    assert "recommended_action" in messages[1]["content"]
    assert "too many arguments" in messages[1]["content"]


def test_plan_rewrite_strategy_template():
    messages = plan_rewrite_strategy(
        {"reason_code": "api_mismatch"},
        {"units": [{"change_id": "CU-001"}]},
        [{"attempt": 1}],
    )

    _assert_messages(messages)
    assert "semantic_must_keep" in messages[1]["content"]
    assert "CU-001" in messages[1]["content"]


def test_generate_rewrite_diff_template():
    messages = generate_rewrite_diff(
        "diff --git a/a.c b/a.c",
        {"reason_code": "hunk_failed"},
        {"units": []},
        {"strategy": "context_drift"},
        {"kernel_version": "6.6"},
    )

    _assert_messages(messages)
    assert "unified diff" in messages[1]["content"]
    assert "diff --git" in messages[1]["content"]


def test_decide_retry_template():
    messages = decide_retry(
        {"state": "FailureClassified"},
        {"retryable": True},
        attempt=1,
        max_attempts=5,
    )

    _assert_messages(messages)
    assert "next_action" in messages[1]["content"]
    assert "max_attempts: 5" in messages[1]["content"]
