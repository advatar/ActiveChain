#!/usr/bin/env python3
"""Release admission and retry tests; no signing, credentials or store access required."""
import argparse
from contextlib import redirect_stdout
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("mobile_release", ROOT / "mobile/release/release.py")
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.artifact = self.root / "wallet.aab"
        self.artifact.write_bytes(b"test-artifact-bytes")
        self.manifest = self.root / "release.json"
        self.record = {
            "format": 1, "platform": "android", "application_id": "dev.activechain.wallet",
            "source_sha": "a" * 40, "qualified_sha": "a" * 40, "qualification_run": 123,
            "version": "0.2.0", "build_number": 42, "artifact": self.artifact.name,
            "sha256": release.digest(self.artifact),
        }
        self.manifest.write_text(json.dumps(self.record))
        self.key = self.root / "credentials.json"
        self.key.write_text("{}")
        self.key.chmod(0o600)
        self.notes = self.root / "notes.txt"
        self.notes.write_text("Release admission test; no real upload.")

    def qualified(self):
        info = {"repository": {"full_name": "advatar/ActiveChain"},
                "path": ".github/workflows/kernel.yml", "status": "completed",
                "conclusion": "success", "head_sha": "a" * 40}
        detail = {"headSha": "a" * 40,
                  "jobs": [{"name": name, "conclusion": "success"} for name in release.REQUIRED_JOBS]}
        return info, detail

    def test_full_gate_accepts_retained_successes_after_an_isolated_retry(self):
        info, detail = self.qualified()
        detail["jobs"].append({"name": "Deterministic kernel development checks", "conclusion": "skipped"})
        self.assertEqual(release.validate_qualification(info, detail), "a" * 40)

    def test_wrong_workflow_repository_revision_or_incomplete_run_is_not_qualification(self):
        for field, value in [("path", ".github/workflows/mobile-store-release.yml"),
                             ("repository", {"full_name": "elsewhere/ActiveChain"}),
                             ("status", "in_progress"), ("conclusion", "failure"),
                             ("head_sha", "b" * 40)]:
            with self.subTest(field=field):
                info, detail = self.qualified()
                info[field] = value
                with self.assertRaises(release.ReleaseError):
                    release.validate_qualification(info, detail)

    def test_skipped_formal_jobs_and_green_development_checks_cannot_publish(self):
        info, detail = self.qualified()
        detail["jobs"] = [{"name": "Deterministic kernel development checks", "conclusion": "success"}]
        with self.assertRaises(release.ReleaseError):
            release.validate_qualification(info, detail)
        info, detail = self.qualified()
        detail["jobs"][0]["conclusion"] = "skipped"
        with self.assertRaises(release.ReleaseError):
            release.validate_qualification(info, detail)

    def test_artifact_modification_and_platform_substitution_are_rejected(self):
        self.assertEqual(release.load_record(self.manifest, "android"), self.record)
        with self.assertRaises(release.ReleaseError):
            release.load_record(self.manifest, "ios")
        self.artifact.write_bytes(b"different binary")
        with self.assertRaises(release.ReleaseError):
            release.load_record(self.manifest, "android")

    def test_symlink_cannot_replace_a_signed_artifact(self):
        actual = self.artifact.with_suffix(".actual")
        self.artifact.rename(actual)
        self.artifact.symlink_to(actual)
        with self.assertRaises(release.ReleaseError):
            release.load_record(self.manifest, "android")

    def test_versions_reject_shell_text_prereleases_boolean_and_store_overflow(self):
        for version, number in [("0.2.0;env", 42), ("0.2.0-beta", 42), ("01.2.0", 42),
                                ("0.2.0", True), ("0.2.0", 0), ("0.2.0", 2_100_000_001)]:
            with self.subTest(version=version, number=number):
                with self.assertRaises(release.ReleaseError):
                    release.validate_version(version, number)

    def test_private_keys_require_owner_only_permissions(self):
        with patch.dict(os.environ, TEST_RELEASE_KEY=str(self.key)):
            self.assertEqual(release.private_file("TEST_RELEASE_KEY"), self.key)
            self.key.chmod(0o644)
            with self.assertRaises(release.ReleaseError):
                release.private_file("TEST_RELEASE_KEY")

    def submit(self, execute, effect=None):
        args = argparse.Namespace(action="android-internal", manifest=str(self.manifest),
                                  notes=str(self.notes), execute=execute)
        with patch.dict(os.environ, GOOGLE_PLAY_CREDENTIALS_PATH=str(self.key),
                        ACTIVECHAIN_RELEASE_JOURNAL=str(self.root / "journal")), \
             patch.object(release, "qualify", return_value=("a" * 40, "a" * 40)), \
             patch.object(release, "fastlane", side_effect=effect) as uploader, \
             redirect_stdout(io.StringIO()):
            release.submit(args)
            return uploader.call_count

    def test_preview_cannot_upload_or_create_attempt_receipt(self):
        self.assertEqual(self.submit(False), 0)
        self.assertFalse(self.manifest.with_name("android-internal.json").exists())

    def test_completed_submission_is_idempotent_for_the_exact_artifact(self):
        self.assertEqual(self.submit(True), 1)
        self.assertEqual(self.submit(True), 0)

    def test_new_ci_download_cannot_repeat_a_completed_submission(self):
        self.assertEqual(self.submit(True), 1)
        self.manifest.with_name("android-internal.json").unlink()
        self.assertEqual(self.submit(True), 0)

    def test_new_ci_download_cannot_blindly_repeat_an_uncertain_upload(self):
        with self.assertRaises(OSError):
            self.submit(True, OSError("unknown upload outcome"))
        self.manifest.with_name("android-internal.json").unlink()
        with self.assertRaisesRegex(release.ReleaseError, "uncertain"):
            self.submit(True)

    def test_concurrent_submissions_for_the_same_build_are_excluded(self):
        path = self.root / "journal" / "submission.json"
        with release.submission_lock(path):
            with self.assertRaisesRegex(release.ReleaseError, "already running"):
                with release.submission_lock(path):
                    self.fail("second submission acquired the same build lock")

    def test_journal_storage_failure_prevents_store_mutation(self):
        with patch.object(release.os, "fsync", side_effect=OSError("journal disk unavailable")), \
             patch.object(release, "fastlane") as uploader:
            with self.assertRaisesRegex(OSError, "journal disk unavailable"):
                self.submit(True)
            uploader.assert_not_called()
        self.assertFalse(self.manifest.with_name("android-internal.json").exists())

    def test_uncertain_network_result_is_journaled_before_mutation_and_never_blindly_retried(self):
        def timeout(*_):
            receipt = json.loads(self.manifest.with_name("android-internal.json").read_text())
            self.assertEqual(receipt["state"], "attempting")
            raise OSError("upload result unknown")
        with self.assertRaises(OSError):
            self.submit(True, timeout)
        with self.assertRaisesRegex(release.ReleaseError, "uncertain"):
            self.submit(True)


if __name__ == "__main__":
    unittest.main()
