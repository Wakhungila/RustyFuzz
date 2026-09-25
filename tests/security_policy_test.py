import copy
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import validate_vulnerability_policy as validator  # noqa: E402


class VulnerabilityPolicyTests(unittest.TestCase):
    def setUp(self):
        self.policy = validator.load_json(ROOT / "security/vulnerability-policy.json")
        self.cargo_toml = {
            "features": {
                "default": ["evm"],
                "svm": [],
                "sgx": [],
            }
        }
        self.metadata = {
            "packages": [
                {"id": "root", "name": "rusty-fuzz", "version": "0.1.0"},
                {
                    "id": "registry#tracing-subscriber",
                    "name": "tracing-subscriber",
                    "version": "0.3.23",
                },
            ],
            "resolve": {
                "nodes": [
                    {
                        "id": "root",
                        "deps": [{"pkg": "registry#tracing-subscriber"}],
                    },
                    {"id": "registry#tracing-subscriber", "deps": []},
                ]
            },
        }
        self.report = {
            "settings": {"ignore": []},
            "vulnerabilities": {"found": False, "count": 0, "list": []},
        }

    def test_clean_audit_is_accepted(self):
        validator.validate(self.policy, self.report, self.metadata, self.cargo_toml, 0)

    def test_any_vulnerability_fails_closed(self):
        report = copy.deepcopy(self.report)
        report["vulnerabilities"] = {
            "found": True,
            "count": 1,
            "list": [{
                "advisory": {"id": "RUSTSEC-OTHER", "package": "other"},
                "package": {"name": "other", "version": "1.0.0"},
            }],
        }
        with self.assertRaises(validator.PolicyError):
            validator.validate(self.policy, report, self.metadata, self.cargo_toml, 1)

    def test_nonzero_clean_audit_status_fails_closed(self):
        with self.assertRaises(validator.PolicyError):
            validator.validate(self.policy, self.report, self.metadata, self.cargo_toml, 1)

    def test_vulnerable_metadata_fails_closed(self):
        self.metadata["packages"].append({
            "id": "registry#tracing-subscriber-vulnerable",
            "name": "tracing-subscriber",
            "version": "0.2.25",
        })
        with self.assertRaises(validator.PolicyError):
            validator.validate(self.policy, self.report, self.metadata, self.cargo_toml, 0)

    def test_policy_exception_fails_closed(self):
        self.policy["exceptions"].append({"id": "RUSTSEC-2025-0055"})
        with self.assertRaises(validator.PolicyError):
            validator.validate(self.policy, self.report, self.metadata, self.cargo_toml, 0)

    def test_non_evm_scope_fails_closed(self):
        self.policy["scope"]["backend"] = "svm"
        with self.assertRaises(validator.PolicyError):
            validator.validate(self.policy, self.report, self.metadata, self.cargo_toml, 0)

    def test_global_ignore_fails_closed(self):
        self.report["settings"]["ignore"] = ["RUSTSEC-2025-0055"]
        with self.assertRaises(validator.PolicyError):
            validator.validate(self.policy, self.report, self.metadata, self.cargo_toml, 0)


if __name__ == "__main__":
    unittest.main()
