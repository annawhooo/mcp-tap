"""
Tests for fix #1 — --production mode validation in mcp_tap.py.

These tests invoke mcp-tap as a subprocess to exercise argparse and
the validation paths in main(). They verify production-mode refusals
and confirm laptop-mode behavior is unchanged.

Add these to test_suite.py inside a new TestProductionMode class.
The imports at the top of the file already cover everything except
subprocess and tempfile, which are stdlib.
"""

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


MCP_TAP_PATH = str(Path(__file__).parent / "mcp_tap.py")


def _run_cli(args, env_overrides=None, timeout=10):
    """Invoke mcp-tap with given CLI args. Returns (returncode, stdout, stderr)."""
    env = dict(os.environ)
    # Strip any leaked HMAC key from the test environment so each test
    # controls its own key state
    env.pop("MCP_TAP_HMAC_KEY", None)
    if env_overrides:
        env.update(env_overrides)
    proc = subprocess.run(
        [sys.executable, MCP_TAP_PATH, *args],
        capture_output=True, text=True, env=env, timeout=timeout,
    )
    return proc.returncode, proc.stdout, proc.stderr


class TestProductionMode(unittest.TestCase):
    """
    Production-mode (--production) validation tests.

    Each refusal path should fail closed with a clear message that names
    what's wrong and what to do. Laptop mode (no --production) must
    remain byte-identical to the pre-fix behavior.
    """

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="mcp-tap-test-")
        self.scope = Path(self.tmpdir) / "data"
        self.scope.mkdir()
        self.log_path = Path(self.tmpdir) / "audit.jsonl"
        self.test_key = os.urandom(32).hex()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_production_refuses_without_hmac_key(self):
        """No env var, no --hmac-key-file -> refuse to start."""
        rc, _, err = _run_cli([
            "--server", f"echo {self.scope}",
            "--log", str(self.log_path),
            "--server-scope", str(self.scope),
            "--sensitivity", "redact",
            "--production",
        ])
        self.assertEqual(rc, 1)
        self.assertIn(
            "refuses to start without an external HMAC key", err)

    def test_production_refuses_without_server_scope(self):
        """--production requires --server-scope -> refuse to start."""
        rc, _, err = _run_cli([
            "--server", f"echo {self.scope}",
            "--log", str(self.log_path),
            "--sensitivity", "redact",
            "--production",
        ], env_overrides={"MCP_TAP_HMAC_KEY": self.test_key})
        self.assertEqual(rc, 1)
        self.assertIn("--production requires --server-scope", err)

    def test_production_refuses_full_sensitivity(self):
        """--production forces sensitivity to at least 'redact'."""
        rc, _, err = _run_cli([
            "--server", f"echo {self.scope}",
            "--log", str(self.log_path),
            "--server-scope", str(self.scope),
            # sensitivity=full (default) -> rejected in production
            "--production",
        ], env_overrides={"MCP_TAP_HMAC_KEY": self.test_key})
        self.assertEqual(rc, 1)
        self.assertIn(
            "--production forces --sensitivity to at least 'redact'", err)

    def test_production_refuses_log_inside_scope(self):
        """--production refuses to start if log path is inside server scope."""
        bad_log = self.scope / "audit.jsonl"
        rc, _, err = _run_cli([
            "--server", f"echo {self.scope}",
            "--log", str(bad_log),
            "--server-scope", str(self.scope),
            "--sensitivity", "redact",
            "--production",
        ], env_overrides={"MCP_TAP_HMAC_KEY": self.test_key})
        self.assertEqual(rc, 1)
        self.assertIn("REFUSING to start", err)
        self.assertIn("inside --server-scope", err)

    def test_production_refuses_keyfile_under_home(self):
        """--hmac-key-file under $HOME is rejected in production mode."""
        if os.name == "nt":
            self.skipTest("File-mode permission check is POSIX-only")
        keyfile = Path.home() / ".test-mcp-tap-prod-key"
        keyfile.write_text(self.test_key)
        keyfile.chmod(0o600)
        try:
            rc, _, err = _run_cli([
                "--server", f"echo {self.scope}",
                "--log", str(self.log_path),
                "--server-scope", str(self.scope),
                "--sensitivity", "redact",
                "--hmac-key-file", str(keyfile),
                "--production",
            ])
            self.assertEqual(rc, 1)
            self.assertIn("refuses HMAC keyfile under $HOME", err)
        finally:
            keyfile.unlink(missing_ok=True)

    def test_production_refuses_keyfile_with_loose_mode(self):
        """--hmac-key-file with mode wider than 0600 is rejected."""
        if os.name == "nt":
            self.skipTest("File-mode permission check is POSIX-only")
        # Place keyfile outside $HOME so the home check passes; then test mode
        keyfile = Path(self.tmpdir) / "loose-key"
        keyfile.write_text(self.test_key)
        keyfile.chmod(0o644)  # world-readable -> should be rejected
        rc, _, err = _run_cli([
            "--server", f"echo {self.scope}",
            "--log", str(self.log_path),
            "--server-scope", str(self.scope),
            "--sensitivity", "redact",
            "--hmac-key-file", str(keyfile),
            "--production",
        ])
        # Note: $tmpdir is typically /tmp on Linux; if pytest puts it
        # under $HOME (rare), the home-check fires first. Either failure
        # mode is correct production behavior; assert just on rc=1.
        self.assertEqual(rc, 1)
        # Either the home-check or the mode-check fired; both are valid.
        self.assertTrue(
            "refuses HMAC keyfile under $HOME" in err
            or "requires HMAC keyfile mode 0600" in err,
            f"Expected home-or-mode rejection; got stderr:\n{err}",
        )

    def test_laptop_mode_does_not_demand_production_args(self):
        """
        Without --production, none of the production-mode validation
        fires. The command should NOT mention --production, --server-scope,
        or HMAC-key requirements in stderr. (echo is not an MCP server,
        so the run will exit cleanly with no logged messages, but no
        REFUSING-to-start message should appear.)
        """
        rc, _, err = _run_cli([
            "--server", "echo {}",
            "--log", str(self.log_path),
        ])
        self.assertNotIn("REFUSING to start", err)
        self.assertNotIn("--production refuses", err)
        self.assertNotIn("--production requires", err)
        self.assertNotIn("--production forces", err)


if __name__ == "__main__":
    unittest.main()
