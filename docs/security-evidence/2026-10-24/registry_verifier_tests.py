"""Offline controls for the adjacent one-off registry verifier."""

import base64
import io
import json
import unittest
import zipfile


def run(core) -> None:
    class OfflineTests(unittest.TestCase):
        def test_definitive_absence_only(self):
            self.assertTrue(core.absence_status(404))
            self.assertFalse(core.absence_status(200))
            for status in (0, 403, 429, 500, 503):
                with self.assertRaises(core.VerificationError):
                    core.absence_status(status)

        def test_checksum_mismatch_fails(self):
            with self.assertRaises(core.VerificationError):
                core.require_digest(b"fixture", "sha256", "0" * 64)

        def test_old_tokio_is_rejected(self):
            data = b'[[package]]\nname="serde-saphyr"\nversion="2.0.0"\n[[package]]\nname="tokio"\nversion="1.51.0"\n'
            with self.assertRaises(core.VerificationError):
                core.lock_checks(data, "0.2.10", require_tokio=True)

        def test_missing_required_tokio_is_rejected(self):
            data = b'[[package]]\nname="serde-saphyr"\nversion="2.0.0"\n'
            with self.assertRaises(core.VerificationError):
                core.lock_checks(data, "0.2.10", require_tokio=True)

        def test_reviewed_tokio_and_process_wrapper_are_accepted(self):
            data = b'[[package]]\nname="serde-saphyr"\nversion="2.0.0"\n[[package]]\nname="tokio"\nversion="1.51.6"\n[[package]]\nname="process-wrap"\nversion="10.0.1"\n'
            checked = core.lock_checks(data, "0.2.10", require_tokio=True)
            self.assertEqual(checked["security_versions"]["tokio"], ["1.51.6"])
            self.assertEqual(checked["security_versions"]["process-wrap"], ["10.0.1"])

        def test_wrong_process_wrapper_is_rejected(self):
            data = b'[[package]]\nname="serde-saphyr"\nversion="2.0.0"\n[[package]]\nname="process-wrap"\nversion="10.0.0"\n'
            with self.assertRaises(core.VerificationError):
                core.lock_checks(data, "0.2.10")

        def test_wheel_sbom_old_tokio_is_rejected(self):
            payload = {"bomFormat": "CycloneDX", "metadata": {"component": {"name": "agent-guard-python", "version": "0.2.10"}}, "components": [{"name": "tokio", "version": "1.51.0"}]}
            with self.assertRaises(core.VerificationError):
                core.wheel_sbom(json.dumps(payload).encode(), "0.2.10")

        def test_wheel_sbom_reviewed_tokio_is_accepted(self):
            payload = {"bomFormat": "CycloneDX", "metadata": {"component": {"name": "agent-guard-python", "version": "0.2.10"}}, "components": [{"name": "tokio", "version": "1.51.6"}]}
            self.assertEqual(core.wheel_sbom(json.dumps(payload).encode(), "0.2.10")["tokio"], ["1.51.6"])

        def test_crate_download_is_the_exact_official_archive(self):
            self.assertEqual(
                core.crate_artifact_url("agent-guard-core", "0.2.9"),
                "https://static.crates.io/crates/agent-guard-core/agent-guard-core-0.2.9.crate",
            )
            with self.assertRaises(core.VerificationError):
                core.crate_artifact_url("../outside", "0.2.9")

        def test_npm_digest_mismatch_fails(self):
            with self.assertRaises(core.VerificationError):
                core.npm_integrity(b"fixture", "sha512-" + base64.b64encode(bytes(64)).decode())

        def test_archive_path_rejected(self):
            for name in ("/outside", "../outside", "package/../../outside", r"package\outside"):
                with self.assertRaises(core.VerificationError):
                    core.safe_member(name)

        def test_missing_wheel_wrappers_fails(self):
            memory = io.BytesIO()
            with zipfile.ZipFile(memory, "w") as archive:
                archive.writestr("agent_guard/__init__.py", "")
            with self.assertRaises(core.VerificationError):
                core.wheel_members(memory.getvalue())

        def test_internal_non_exact_pin_fails(self):
            with self.assertRaises(core.VerificationError):
                core.manifest_pins({"dependencies": {"agent-guard-core": {"version": "0.2.9"}}}, "0.2.9")

        def test_provenance_subject_mismatch_fails(self):
            with self.assertRaises(core.VerificationError):
                core.provenance_statement(
                    {
                        "_type": "https://in-toto.io/Statement/v1",
                        "predicateType": "https://slsa.dev/provenance/v1",
                        "subject": [{"name": "pkg:npm/agent-guard-plugin@0.2.9",
                                     "digest": {"sha512": "0" * 128}}],
                    },
                    {"sha512": "1" * 128, "sha256": "2" * 64},
                    "0.2.9", "3" * 40, "1",
                )

        def test_https_public_registry_boundary(self):
            for url in ("http://crates.io/x", "https://example.test/x", "https://user@crates.io/x"):
                with self.assertRaises(core.VerificationError):
                    core.allowed_url(url)

    outcome = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(OfflineTests))
    if not outcome.wasSuccessful():
        raise SystemExit(1)
