import importlib.util
from pathlib import Path
import unittest


SCRIPT = Path(__file__).parents[1] / "scripts/qualify-kanalen-pow-production.py"
SPEC = importlib.util.spec_from_file_location("qualify_kanalen_pow_production", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class ProofOfWorkReportTests(unittest.TestCase):
    def report(self):
        return {
            "schema": "actum.pow.qualification-report.v1",
            "activeChainCommit": "a" * 40,
            "proofOfWorkCommit": "b" * 40,
            "deterministic": {"qualified": True},
            "production": {"qualified": True, "status": "verified"},
        }

    def test_accepts_exact_qualified_revisions(self):
        MODULE.require_proof_of_work_report(self.report(), "a" * 40, "b" * 40)

    def test_rejects_revision_substitution(self):
        with self.assertRaises(RuntimeError):
            MODULE.require_proof_of_work_report(self.report(), "c" * 40, "b" * 40)

    def test_rejects_nonproduction_report(self):
        report = self.report()
        report["production"]["qualified"] = False
        with self.assertRaises(RuntimeError):
            MODULE.require_proof_of_work_report(report, "a" * 40, "b" * 40)


if __name__ == "__main__":
    unittest.main()
