import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import run as comparison


class ComparisonHarnessTests(unittest.TestCase):
    def test_mint_pair_uses_authorization_oracle_not_supply_zero_invariant(self):
        self.assertNotIn("mint", comparison.RUSTYFUZZ_INVARIANTS)
        self.assertIn("mint", comparison.RUSTYFUZZ_COMPARABLE_PAIRS)

    def test_run_results_can_be_written_to_an_isolated_run_path(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "run-42" / "results.json"
            result = comparison.RunResult(
                "rustyfuzz", "mint", "vulnerable", None, 20,
                status="measurement_only",
            )

            comparison.write_results("rustyfuzz", [result], output)

            saved = json.loads(output.read_text())
        self.assertEqual(saved[0]["status"], "measurement_only")
        self.assertIsNone(saved[0]["found"])

    def test_target_code_is_checked_at_pinned_block(self):
        addresses = {
            "vulnerable": {"OwnerMintToken": "0x" + "11" * 20},
            "safe": {"OwnerMintToken": "0x" + "22" * 20},
        }
        with patch.object(comparison, "rpc", return_value="0x6000") as rpc:
            comparison.verify_target_code(addresses, 123)

        self.assertEqual(
            rpc.call_args_list,
            [
                unittest.mock.call("eth_getCode", [addresses["vulnerable"]["OwnerMintToken"], "0x7b"]),
                unittest.mock.call("eth_getCode", [addresses["safe"]["OwnerMintToken"], "0x7b"]),
            ],
        )

    def test_target_without_code_at_pinned_block_fails(self):
        addresses = {
            "vulnerable": {"OwnerMintToken": "0x" + "11" * 20},
            "safe": {"OwnerMintToken": "0x" + "22" * 20},
        }
        with patch.object(comparison, "rpc", side_effect=["0x6000", "0x"]):
            with self.assertRaisesRegex(RuntimeError, "no bytecode at pinned block 123"):
                comparison.verify_target_code(addresses, 123)

    def test_pinned_snapshot_rejects_anvil_advancing(self):
        addrs = {"fork_block_hash": "0x" + "ab" * 32}
        with patch.object(comparison, "rpc", return_value="0x7c"):
            with self.assertRaisesRegex(RuntimeError, "advanced from pinned block"):
                comparison.assert_pinned_snapshot(addrs, 123)

    def test_invariant_is_rebound_only_from_expected_vulnerable_template(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "mint.json"
            vulnerable = "0x" + "11" * 20
            safe = "0x" + "22" * 20
            source.write_text(json.dumps({"target": vulnerable, "invariants": []}))
            destination = root / "work" / "mint-safe.json"

            with patch.dict(comparison.RUSTYFUZZ_INVARIANTS, {"mint": source}):
                result = comparison.prepare_invariant("mint", safe, vulnerable, destination)
                self.assertEqual(json.loads(result.read_text())["target"], safe)

                with self.assertRaisesRegex(RuntimeError, "does not match"):
                    comparison.prepare_invariant("mint", safe, "0x" + "33" * 20, destination)

    def test_contract_abi_requires_matching_nonempty_pair_abis(self):
        abi = [{"type": "function", "name": "mint", "inputs": []}]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for source in ("Controls.sol", "VulnerableControls.sol"):
                artifact = root / "out" / source / "OwnerMintToken.json"
                artifact.parent.mkdir(parents=True)
                artifact.write_text(json.dumps({"abi": abi}))

            with patch.object(comparison, "CMP", root):
                abi_path = comparison.contract_abi("OwnerMintToken")
                self.assertEqual(json.loads(abi_path.read_text()), abi)
                artifact = root / "out" / "VulnerableControls.sol" / "OwnerMintToken.json"
                artifact.write_text(json.dumps({"abi": []}))
                with self.assertRaisesRegex(RuntimeError, "no ABI entries"):
                    comparison.contract_abi("OwnerMintToken")

    def test_abi_function_selectors_match_canonical_signatures(self):
        with tempfile.TemporaryDirectory() as temporary:
            abi_path = Path(temporary) / "abi.json"
            abi_path.write_text(json.dumps([
                {
                    "type": "function",
                    "name": "balanceOf",
                    "inputs": [{"type": "address"}],
                },
                {
                    "type": "function",
                    "name": "transfer",
                    "inputs": [{"type": "address"}, {"type": "uint256"}],
                },
            ]))

            self.assertEqual(
                comparison.abi_function_selectors(abi_path),
                {"70a08231", "a9059cbb"},
            )

    def test_zero_execution_summary_is_not_a_clean_result(self):
        found, executions, error = comparison.parse_rustyfuzz_summary(
            {
                "execution_status": "no_executions",
                "total_executions": 0,
                "fork_setup_status": "rpc",
                "target_bytecode_loaded": True,
                "confirmed_findings": 0,
            },
            1,
        )

        self.assertFalse(found)
        self.assertEqual(executions, 0)
        self.assertIn("no transactions executed", error)

    def test_only_completed_rpc_campaign_with_execution_counts_is_valid(self):
        summary = {
            "execution_status": "executed",
            "total_executions": 4,
            "fork_setup_status": "rpc",
            "target_bytecode_loaded": True,
            "confirmed_findings": 1,
        }

        self.assertEqual(comparison.parse_rustyfuzz_summary(summary, 0), (True, 4, None))
        invalid = dict(summary, target_bytecode_loaded=False)
        self.assertIn("bytecode", comparison.parse_rustyfuzz_summary(invalid, 0)[2])

    def test_run_manifest_must_match_pinned_chain_and_block(self):
        manifest = {
            "chain_id": 1,
            "fork_block": 123,
            "fork_block_hash": "0x" + "ab" * 32,
        }

        self.assertIsNone(
            comparison.validate_run_manifest(manifest, 123, "0x" + "AB" * 32)
        )
        self.assertIn(
            "fork block",
            comparison.validate_run_manifest(manifest, 124, "0x" + "ab" * 32),
        )

    def test_partial_terminal_campaign_is_not_a_completed_benchmark(self):
        self.assertIsNone(
            comparison.validate_terminal_status({"terminal": True, "state": "completed"})
        )
        self.assertIn(
            "partial",
            comparison.validate_terminal_status({"terminal": True, "state": "partial"}),
        )
        self.assertIn(
            "not terminal",
            comparison.validate_terminal_status({"terminal": False, "state": "completed"}),
        )

    def test_campaign_config_uses_local_rpc_without_external_seed_bundle(self):
        with tempfile.TemporaryDirectory() as temporary:
            config_path = comparison.write_campaign_config(Path(temporary), 20)
            config = config_path.read_text()

        self.assertIn(f'rpc_url = "{comparison.RPC}"', config)
        self.assertIn("require_rpc_fork = true", config)
        self.assertNotIn("mainnet_seed_bundle", config)
        self.assertNotIn("RUSTYFUZZ_RPC_API_KEY", config)

    def test_promotion_mode_passes_explicit_mutually_exclusive_cli_flag(self):
        self.assertEqual(comparison.promotion_arguments(True), ["--promote-findings"])
        self.assertEqual(comparison.promotion_arguments(False), ["--no-promote-findings"])

    def test_execution_provenance_metrics_count_target_and_sequence_exploration(self):
        target = "0x" + "11" * 20
        other = "0x" + "22" * 20
        block_hash = "0x" + "ab" * 32
        with tempfile.TemporaryDirectory() as temporary:
            run_root = Path(temporary)
            provenance = run_root / "inputs" / "execution_provenance"
            provenance.mkdir(parents=True)
            record = {
                "rpc_provenance": {
                    "chain_id": 1,
                    "fork_block": 123,
                    "fork_block_hash": block_hash,
                },
                "input": {
                    "base_snapshot_id": 7,
                    "txs": [
                        {"to": target, "input": [18, 52, 86, 120]},
                        {"to": other, "input": []},
                    ],
                },
                "execution": {
                    "call_trace": [
                        {"target": target, "phase": "Start"},
                        {"target": other, "phase": "Start"},
                        {"target": target, "phase": "End"},
                    ],
                    "tx_results": [{"coverage_hash": 99}],
                },
                "coverage_edges": 6,
                "state_novelty_score": 3,
            }
            (provenance / "run-worker-0-00000000000000000001.json").write_text(
                json.dumps(record)
            )

            measurements, error = comparison.collect_rustyfuzz_measurements(
                run_root, target, 1, 123, block_hash, 9
            )

        self.assertIsNone(error)
        self.assertEqual(measurements["target_transactions"], 1)
        self.assertEqual(measurements["target_call_observations"], 1)
        self.assertEqual(measurements["unique_target_selectors"], 1)
        self.assertEqual(measurements["max_sequence_depth"], 2)
        self.assertEqual(measurements["coverage_edges_campaign_max"], 9)
        self.assertEqual(measurements["coverage_edges_mean_per_sequence"], 6)
        self.assertEqual(measurements["coverage_edges_sequence_first_last_delta"], 0)
        self.assertEqual(measurements["positive_state_novelty_sequences"], 1)

    def test_measurement_provenance_must_match_execution_count_and_fork(self):
        with tempfile.TemporaryDirectory() as temporary:
            run_root = Path(temporary)
            provenance = run_root / "inputs" / "execution_provenance"
            provenance.mkdir(parents=True)
            metrics, error = comparison.collect_rustyfuzz_measurements(
                run_root, "0x" + "11" * 20, 1, 123, "0x" + "ab" * 32, 0
            )
        self.assertEqual(metrics, {})
        self.assertIn("record count", error)

    def test_measurements_separate_successful_calls_from_incompatible_halts(self):
        target = "0x" + "11" * 20
        block_hash = "0x" + "ab" * 32
        with tempfile.TemporaryDirectory() as temporary:
            run_root = Path(temporary)
            provenance = run_root / "inputs" / "execution_provenance"
            provenance.mkdir(parents=True)
            record = {
                "rpc_provenance": {
                    "chain_id": 1,
                    "fork_block": 123,
                    "fork_block_hash": block_hash,
                },
                "input": {
                    "base_snapshot_id": 7,
                    "txs": [
                        {"to": target, "input": [112, 160, 130, 49]},
                        {"to": target, "input": [1, 2, 3, 4]},
                    ],
                },
                "execution": {
                    "call_trace": [],
                    "tx_results": [
                        {"tx_index": 0, "status": "Success", "coverage_hash": 1},
                        {
                            "tx_index": 1,
                            "status": {"Halt": "NotActivated"},
                            "coverage_hash": 2,
                        },
                    ],
                },
                "coverage_edges": 3,
                "state_novelty_score": 0,
            }
            (provenance / "sequence.json").write_text(json.dumps(record))

            measurements, error = comparison.collect_rustyfuzz_measurements(
                run_root, target, 1, 123, block_hash, 3, {"70a08231"}
            )

        self.assertIsNone(error)
        self.assertEqual(measurements["successful_transactions"], 1)
        self.assertEqual(measurements["successful_target_transactions"], 1)
        self.assertEqual(measurements["recognized_target_transactions"], 1)
        self.assertEqual(measurements["unique_recognized_target_selectors"], 1)
        self.assertEqual(measurements["not_activated_transactions"], 1)


if __name__ == "__main__":
    unittest.main()
