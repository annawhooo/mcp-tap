"""
conftest.py: pytest fixtures shared across the verifier test suite.

A fresh random 32-byte HMAC key per test ensures tests don't have
hard-coded keys that might mask bugs in canonicalization. Tests should
build chains and verify with the same key fixture instance — passing a
different key would cause every record to fail HMAC_MISMATCH (and that
specific behavior is verified by test_wrong_key_fails_every_record).
"""

import os

import pytest


@pytest.fixture
def key() -> bytes:
    """A fresh random 32-byte HMAC key, one per test invocation."""
    return os.urandom(32)


@pytest.fixture
def other_key() -> bytes:
    """A second, unrelated 32-byte HMAC key for negative-path tests."""
    return os.urandom(32)
