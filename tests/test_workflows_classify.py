"""Tests for workflows._classify — Bubble 400 response parsing.

Real message shapes observed across several Bubble apps:

  {"statusCode": 400, "body": {"status": "MISSING_DATA",
    "message": "Missing parameter for workflow X: parameter code"}}   # unquoted

  {"statusCode": 400, "body": {"status": "MISSING_DATA",
    "message": "Missing parameter 'email'"}}                         # single

  {"status": "NOT_RUN",
   "message": "The condition for the workflow X is not met. Workflow won't run"}

  {"statusCode": 400, "body": {"status": "INVALID",
    "message": "Invalid value for parameter user_id (must be user)"}}
"""
from __future__ import annotations

from bubblepwn.modules.workflows import (
    _classify,
    _extract_bubble_message,
)


class TestClassifyMissing:
    def test_missing_parameter_unquoted(self):
        body = {
            "statusCode": 400,
            "body": {
                "status": "MISSING_DATA",
                "message": "Missing parameter for workflow currency: parameter code",
            },
        }
        label, hint = _classify(400, body)
        assert label == "MISSING"
        assert hint == "code"

    def test_missing_parameter_single_quotes(self):
        body = {"status": "MISSING_DATA", "message": "Missing parameter 'email'"}
        label, hint = _classify(400, body)
        assert label == "MISSING"
        assert hint == "email"

    def test_missing_parameter_double_quotes(self):
        body = {"message": 'Missing parameter "user_id"'}
        label, hint = _classify(400, body)
        assert label == "MISSING"
        assert hint == "user_id"

    def test_missing_data_body_without_named_param(self):
        # No explicit parameter name in the message — should still be
        # classified MISSING, with the message surfaced as the hint for
        # the user.
        body = {"status": "MISSING_DATA", "message": "Missing required data"}
        label, hint = _classify(400, body)
        assert label == "MISSING"
        assert hint is not None and "Missing required data" in hint


class TestClassifyInvalid:
    def test_invalid_value_unquoted(self):
        body = {
            "statusCode": 400,
            "body": {
                "message": "Invalid value for parameter user_id (must be user)",
            },
        }
        label, hint = _classify(400, body)
        assert label == "INVALID"
        assert hint == "user_id"

    def test_invalid_value_quoted(self):
        body = {"message": "Invalid value for parameter 'amount' — NaN"}
        label, hint = _classify(400, body)
        assert label == "INVALID"
        assert hint == "amount"

    def test_bad_format_unnamed_falls_back_to_message(self):
        body = {"message": "Bad request — something went wrong"}
        label, hint = _classify(400, body)
        assert label == "INVALID"
        # Fallback: surface the Bubble message so the user can act on it
        # even though no param name was extractable.
        assert hint is not None and "Bad request" in hint


class TestClassifyNotRun:
    def test_not_run_status_keyword(self):
        body = {
            "status": "NOT_RUN",
            "message": "The condition for the workflow creator_images is not met. Workflow won't run",
        }
        label, hint = _classify(400, body)
        assert label == "NOT_RUN"
        # Message surfaces so the user sees the precondition.
        assert hint is not None and "condition" in hint

    def test_not_run_from_message_text(self):
        body = {"message": "Workflow won't run: condition failed"}
        label, hint = _classify(400, body)
        assert label == "NOT_RUN"


class TestClassifyNonErrorStatuses:
    def test_200_open_ok(self):
        assert _classify(200, {"ok": True}) == ("OPEN_OK", None)

    def test_204_open_ok(self):
        assert _classify(204, "") == ("OPEN_OK", None)

    def test_401_auth(self):
        assert _classify(401, {"msg": "x"}) == ("AUTH", None)

    def test_403_auth(self):
        assert _classify(403, {"msg": "x"}) == ("AUTH", None)

    def test_404_blocked(self):
        assert _classify(404, {"message": "Workflow not found"}) == ("BLOCKED", None)

    def test_500_error(self):
        assert _classify(500, {"msg": "x"}) == ("ERROR", None)


class TestExtractBubbleMessage:
    def test_flat_message(self):
        assert _extract_bubble_message({"message": "hi"}) == "hi"

    def test_nested_body_message(self):
        assert _extract_bubble_message({"body": {"message": "nested"}}) == "nested"

    def test_string_body(self):
        assert _extract_bubble_message("plain string") == "plain string"

    def test_truncation(self):
        long = {"message": "x" * 500}
        out = _extract_bubble_message(long)
        assert out is not None and len(out) <= 160

    def test_empty_on_no_message(self):
        assert _extract_bubble_message({"other": "x"}) is None
        assert _extract_bubble_message(None) is None
