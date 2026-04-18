"""Shared fixtures for bubblepwn tests."""
from __future__ import annotations

import pytest

from bubblepwn.context import Context


@pytest.fixture(autouse=True)
def reset_context():
    """Drop the Context singleton around every test.

    Context.get() returns a module-level singleton — without this fixture
    tests would bleed state (findings, target, session) into each other.
    """
    Context._reset()
    yield
    Context._reset()
