#!/usr/bin/env python3
"""Matched-budget comparison runner for the local control pairs.

Design notes that matter for reading the results honestly:

* Budget. Runs use the same wall-clock cap; tool-native operation counters are
  recorded when available. A shared time limit alone does not make different
  detector/property models comparable.
* State. The on-chain tools use the same Anvil deployment and pinned block.
  Echidna's checked-in harness self-deploys, so its result is not scored as a
  same-target comparison.
* Verdicts. A "finding" is scored only when the tool completed the relevant
  property run. Tool-specific detectors and runs without verified executions
  are explicitly marked non-comparable or unverified.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import time
import urllib.request
from dataclasses import dataclass, field, asdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
CMP = ROOT / "benchmarks" / "comparison"
RESULTS = CMP / "results"

ANVIL_PORT = 8546
RPC = f"http://127.0.0.1:{ANVIL_PORT}"
SUPPORTED_CHAIN_ID = 1
# The local mainnet-profile execution must not run Cancun-compiled contracts
# under the Frontier rules implied by Anvil's default block number.
ANVIL_BLOCK_NUMBER = 20_000_000
ANVIL_TIMESTAMP = 1_710_338_135
# anvil account #0 — the deployer, and a funded actor in the harness.
DEPLOYER_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
DEPLOYER = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
ATTACKER = "0x9965507D1a55bcc269514583e49Fdf3b9bD8c1DB"
FUND = 10**24  # 1_000_000 ether


# --------------------------------------------------------------------------- rpc
def rpc(method: str, params: list):
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(RPC, data=payload, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        body = json.loads(resp.read())
    if "error" in body:
        raise RuntimeError(f"{method}: {body['error']}")
    return body.get("result")


def _keccak(data: bytes) -> bytes:
    from Crypto.Hash import keccak as _k

    h = _k.new(digest_bits=256)
    h.update(data)
    return h.digest()


def mapping_slot(key: int, base: int) -> int:
    return int.from_bytes(_keccak(key.to_bytes(32, "big") + base.to_bytes(32, "big")), "big")


def wait_for_rpc(timeout=20.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            rpc("eth_chainId", [])
            return True
        except Exception:
            time.sleep(0.2)
    return False


def port_free(port: int) -> bool:
    with socket.socket() as s:
        return s.connect_ex(("127.0.0.1", port)) != 0


# --------------------------------------------------------------------------- anvil
class Anvil:
    def __init__(self, port: int = ANVIL_PORT):
        self.port = port
        self.proc: subprocess.Popen | None = None
        self.log = Path("/tmp") / "rf-compare-anvil.log"

    def start(self):
        if not port_free(self.port):
            raise RuntimeError(f"port {self.port} already in use; stop the other anvil first")
        self.log.write_text("")
        fh = self.log.open("w")
        self.proc = subprocess.Popen(
            [
                "anvil",
                "--port", str(self.port),
                "--chain-id", str(SUPPORTED_CHAIN_ID),
                "--number", str(ANVIL_BLOCK_NUMBER),
                "--timestamp", str(ANVIL_TIMESTAMP),
                "--hardfork", "cancun",
                "--block-base-fee-per-gas", "0",
            ],
            stdout=fh,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        if not wait_for_rpc():
            raise RuntimeError(f"anvil did not come up; see {self.log}")
        return self

    def stop(self):
        if self.proc and self.proc.poll() is None:
            try:
                os.killpg(os.getpgid(self.proc.pid), signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(os.getpgid(self.proc.pid), signal.SIGKILL)

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.stop()


def contract_abi(contract: str) -> Path:
    """Extract a shared, non-empty ABI after checking both control implementations."""
    abis = []
    for source in ("Controls.sol", "VulnerableControls.sol"):
        artifact = CMP / "out" / source / f"{contract}.json"
        if not artifact.is_file():
            raise RuntimeError(f"compiled ABI artifact is missing: {artifact}")
        data = json.loads(artifact.read_text())
        if not isinstance(data, dict):
            raise RuntimeError(f"compiled ABI artifact is not a JSON object: {artifact}")
        abi = data.get("abi")
        if not isinstance(abi, list) or not abi:
            raise RuntimeError(f"compiled ABI artifact has no ABI entries: {artifact}")
        abis.append(abi)
    if abis[0] != abis[1]:
        raise RuntimeError(f"vulnerable and safe {contract} ABIs do not match")
    path = CMP / "work" / "abi" / f"{contract}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(abis[0], indent=1))
    return path


def abi_function_selectors(abi_path: Path) -> set[str]:
    abi = json.loads(abi_path.read_text())

    def canonical_type(parameter: dict) -> str:
        type_name = parameter["type"]
        if not type_name.startswith("tuple"):
            return type_name
        suffix = type_name[len("tuple"):]
        components = ",".join(canonical_type(item) for item in parameter["components"])
        return f"({components}){suffix}"

    return {
        _keccak(
            f"{entry['name']}({','.join(canonical_type(item) for item in entry['inputs'])})".encode()
        )[:4].hex()
        for entry in abi
        if entry.get("type") == "function"
    }


def deploy(smoke: bool = False) -> dict:
    """Deploy both sides, seed state, and verify code at the pinned block."""
    cmd = [
        "forge", "script", "src/DeployAll.s.sol:DeployAll",
        "--sig", "run()", "--rpc-url", RPC, "--broadcast", "--legacy",
        "--sender", DEPLOYER, "--private-key", DEPLOYER_KEY,
    ]
    proc = subprocess.run(cmd, cwd=CMP, capture_output=True, text=True, timeout=600)
    if "ONCHAIN EXECUTION COMPLETE & SUCCESSFUL" not in proc.stdout:
        raise RuntimeError(f"deploy failed:\n{proc.stdout[-2000:]}\n{proc.stderr[-2000:]}")

    chain_id = int(rpc("eth_chainId", []), 16)
    if chain_id != SUPPORTED_CHAIN_ID:
        raise RuntimeError(f"Anvil chain ID {chain_id} is not supported by RustyFuzz")
    latest = max(
        (CMP / "broadcast" / "DeployAll.s.sol" / str(SUPPORTED_CHAIN_ID)).glob("run-latest.json"),
        key=lambda p: p.stat().st_mtime,
    )
    data = json.loads(latest.read_text())
    seq = [(t["contractName"], t["contractAddress"]) for t in data["transactions"] if t.get("contractName")]
    names = ["BurnOnlyToken", "OwnerMintToken", "OffsetVault", "NoFlashPool",
             "CollateralizedLender", "GuardedGovernor"]
    if len(seq) != 2 * len(names) or [name for name, _ in seq] != names * 2:
        raise RuntimeError(f"deployment transaction list does not match expected controls: {seq}")
    out = {"vulnerable": {}, "safe": {}}
    for i, (name, addr) in enumerate(seq):
        out["vulnerable" if i < len(names) else "safe"][name] = addr

    seed_state(out)
    fork_block = int(rpc("eth_blockNumber", []), 16)
    verify_target_code(out, fork_block)
    block = rpc("eth_getBlockByNumber", [hex(fork_block), False])
    if not isinstance(block, dict) or not block.get("hash"):
        raise RuntimeError(f"could not read hash for pinned fork block {fork_block}")
    out["chain_id"] = chain_id
    out["fork_block"] = fork_block
    out["fork_block_hash"] = block["hash"]
    return out


def verify_target_code(addrs: dict, fork_block: int) -> None:
    """Require non-empty runtime bytecode for every deployed comparison target."""
    for side in ("vulnerable", "safe"):
        for contract, address in addrs[side].items():
            code = rpc("eth_getCode", [address, hex(fork_block)])
            if not isinstance(code, str) or code in ("0x", "0x0"):
                raise RuntimeError(
                    f"{side} {contract} has no bytecode at pinned block {fork_block}: {address}"
                )


def assert_pinned_snapshot(addrs: dict, fork_block: int) -> None:
    current_block = int(rpc("eth_blockNumber", []), 16)
    if current_block != fork_block:
        raise RuntimeError(
            f"Anvil advanced from pinned block {fork_block} to {current_block}"
        )
    block = rpc("eth_getBlockByNumber", [hex(fork_block), False])
    if not isinstance(block, dict) or block.get("hash") != addrs["fork_block_hash"]:
        raise RuntimeError(f"Anvil block hash changed at pinned block {fork_block}")


def set_slot(address: str, slot: int, value: int):
    rpc("anvil_setStorageAt", [address, "0x%064x" % slot, "0x%064x" % value])


def fund_coin(coin: str, who: str, amount: int):
    set_slot(coin, mapping_slot(int(who, 16), 0), amount)


def approve_coin(coin: str, owner: str, spender: str, amount: int):
    owner_slot = mapping_slot(int(owner, 16), 1)
    set_slot(coin, mapping_slot(int(spender, 16), owner_slot), amount)


def seed_state(a: dict):
    """Reproduce the fixture semantics: funded actors, seeded pools/collateral."""
    for side in ("vulnerable", "safe"):
        coin = a[side]["BurnOnlyToken"]
        pool = a[side]["NoFlashPool"]
        lender = a[side]["CollateralizedLender"]
        minter = a[side]["OwnerMintToken"]

        fund_coin(coin, ATTACKER, FUND)
        fund_coin(coin, DEPLOYER, FUND)
        fund_coin(coin, pool, 1_000 * 10**18)
        fund_coin(coin, lender, 1_000 * 10**18)
        fund_coin(minter, ATTACKER, FUND)
        fund_coin(minter, DEPLOYER, FUND)
        approve_coin(coin, ATTACKER, a[side]["OffsetVault"], FUND)

        # Wire dependent contracts (asset/token0/token1 are slot 0/1 storage).
        set_slot(a[side]["OffsetVault"], 0, int(coin, 16))
        set_slot(lender, 0, int(coin, 16))
        set_slot(pool, 0, int(coin, 16))
        set_slot(pool, 1, int(coin, 16))

        # Seed reserves, collateral and borrower (slots per the control sources).
        set_slot(pool, 2, 1_000 * 10**18)
        set_slot(pool, 3, 1_000 * 10**18)
        set_slot(lender, 2, 10**18)
        set_slot(lender, 3, int(ATTACKER, 16))


# --------------------------------------------------------------------------- results
@dataclass
class RunResult:
    tool: str
    pair: str
    side: str
    found: bool | None
    budget_secs: int
    status: str = "valid"
    target_address: str | None = None
    fork_block: int | None = None
    fork_block_hash: str | None = None
    property_id: str | None = None
    comparability: str = "same_target_property"
    ops: int | None = None
    ops_unit: str | None = None
    detail: str = ""
    error: str | None = None
    evidence: list[str] = field(default_factory=list)
    measurements: dict = field(default_factory=dict)


def write_results(
    tool: str, results: list[RunResult], output_path: Path | None = None,
):
    path = output_path or RESULTS / f"{tool}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps([asdict(r) for r in results], indent=1))
    counts = {
        status: sum(result.status == status for result in results)
        for status in ("valid", "measurement_only", "partial", "invalid", "unverified", "not_comparable")
    }
    try:
        display_path = path.relative_to(ROOT)
    except ValueError:
        display_path = path
    print(f"  wrote {display_path} statuses={counts}")


# --------------------------------------------------------------------------- echidna
ECHIDNA_PAIRS = {
    "mint": ("MintPair", "echidna_vulnerable_mint_is_authorized", "echidna_safe_mint_is_authorized"),
    "vault": ("VaultPair", "echidna_vulnerable_no_zero_share_deposit", "echidna_safe_no_zero_share_deposit"),
    "pool": ("PoolPair", "echidna_vulnerable_product_never_decreases", "echidna_safe_product_never_decreases"),
    "lend": ("LendPair", "echidna_vulnerable_debt_tracks_borrows", "echidna_safe_debt_tracks_borrows"),
    "gov": ("GovPair", "echidna_vulnerable_execute_requires_path", "echidna_safe_execute_requires_path"),
}


PAIR_PROPERTY_IDS = {
    "mint": "unauthorized_mint_does_not_increase_supply",
    "vault": "nonzero_deposit_returns_nonzero_shares",
    "pool": "swap_preserves_reserve_product",
    "lend": "borrowed_amount_is_recorded_as_debt",
    "gov": "execution_requires_governance_path",
}


def run_echidna(
    pairs: list[str], budget: int, addrs: dict, fork_block: int, seed: int = 42,
) -> list[RunResult]:
    results = []
    fails = 0
    for pair in pairs:
        assert_pinned_snapshot(addrs, fork_block)
        contract, vprop, sprop = ECHIDNA_PAIRS[pair]
        cmd = [
            "echidna", "echidna/ControlPairs.sol",
            "--contract", contract,
            "--rpc-url", RPC,
            "--rpc-block", str(fork_block),
            "--timeout", str(budget),
            "--seed", str(seed),
            "--format", "text",
        ]
        t0 = time.time()
        proc = subprocess.run(cmd, cwd=CMP, capture_output=True, text=True, timeout=budget + 120)
        elapsed = time.time() - t0
        out = proc.stdout + proc.stderr
        calls = None
        m = re.search(r"Total calls: (\d+)", out)
        if m:
            calls = int(m.group(1))

        def verdict(prop: str, failing: bool) -> tuple[bool, str]:
            # echidna prints "prop: failed!💥" or "prop: passing"
            for line in out.splitlines():
                if line.strip().startswith(prop + ":"):
                    status = line.split(":", 1)[1].strip()
                    is_fail = "failed" in status or "falsified" in status
                    return is_fail, status[:80]
            # A crash before any verdict is an error, not a negative result.
            return False, "no verdict emitted"

        v_found, v_detail = verdict(vprop, True)
        s_found, s_detail = verdict(sprop, True)
        err = None
        if v_detail == "no verdict emitted" or s_detail == "no verdict emitted":
            err = out[-800:]
        contract_name = ITYFUZZ_PAIRS[pair]
        # This checked-in harness creates its own instances. Preserve its raw
        # observation, but do not score it against the deployed Anvil targets.
        for side, detail, raw_found in (
            ("vulnerable", v_detail, v_found),
            ("safe", s_detail, s_found),
        ):
            results.append(RunResult(
                "echidna", pair, side, None, budget,
                status="not_comparable" if detail != "no verdict emitted" else "invalid",
                target_address=addrs[side][contract_name],
                fork_block=fork_block,
                fork_block_hash=addrs["fork_block_hash"],
                property_id=PAIR_PROPERTY_IDS[pair],
                comparability="self_deployed_harness",
                ops=calls,
                ops_unit="calls",
                detail=f"self-deployed harness observed {raw_found}: {detail}",
                error=err,
            ))
        print(f"  echidna {pair:5s} raw={v_detail}/{s_detail}; not scored (self-deployed harness, {elapsed:.0f}s)")
        if err:
            fails += 1
    if fails:
        print(f"  ! {fails} echidna run(s) emitted no verdict")
    return results


# --------------------------------------------------------------------------- ityfuzz
ITYFUZZ_PAIRS = {
    # pair -> (target contract name, side-specific address key)
    "mint": "OwnerMintToken",
    "vault": "OffsetVault",
    "pool": "NoFlashPool",
    "lend": "CollateralizedLender",
    "gov": "GuardedGovernor",
}


def run_ityfuzz(
    pairs: list[str], budget: int, addrs: dict, fork_block: int, seed: int = 42,
) -> list[RunResult]:
    binary = CMP / "bin" / "ityfuzz"
    results = []
    for pair in pairs:
        contract = ITYFUZZ_PAIRS[pair]
        for side in ("vulnerable", "safe"):
            target = addrs[side][contract]
            abi = contract_abi(contract)
            assert_pinned_snapshot(addrs, fork_block)
            work = CMP / "work" / "ityfuzz" / f"{pair}-{side}"
            shutil.rmtree(work, ignore_errors=True)
            work.mkdir(parents=True, exist_ok=True)
            cmd = [
                str(binary), "evm",
                "-t", target,
                "--target-type", "address",
                "-c", "local",
                "-u", RPC,
                "-b", str(fork_block),
                "-i", str(SUPPORTED_CHAIN_ID),
                "--seed", str(seed),
                "-w", str(work),
                "--force-abi", f"{target}:{abi}",
            ]
            t0 = time.time()
            found = False
            detail = "no verdict"
            out = ""
            proc = None
            try:
                proc = subprocess.run(
                    cmd, cwd=CMP, capture_output=True, text=True,
                    timeout=budget, start_new_session=True,
                )
                out = proc.stdout + proc.stderr
            except subprocess.TimeoutExpired as exc:
                out = (exc.stdout or b"").decode(errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
                out += (exc.stderr or b"").decode(errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
            elapsed = time.time() - t0
            # ItyFuzz writes findings under work_dir; also prints "Found bug" style lines.
            bug_files = list(work.glob("**/*bug*")) + list(work.glob("**/*finding*"))
            text_found = bool(re.search(r"(?i)\b(found a bug|bug found|vulnerabilit(y|ies) found|panic|typed_bug)", out))
            if bug_files:
                found = True
                detail = f"{len(bug_files)} finding artifact(s)"
            elif text_found:
                found = True
                detail = "bug reported in stdout"
            results.append(RunResult(
                "ityfuzz", pair, side, None, budget,
                status="unverified",
                target_address=target,
                fork_block=fork_block,
                fork_block_hash=addrs["fork_block_hash"],
                property_id=PAIR_PROPERTY_IDS[pair],
                comparability="built_in_detector_no_authored_property",
                detail=f"{detail}; ityfuzz does not run this authored property",
                error=(
                    None if out and proc is not None and proc.returncode == 0
                    else "timeout" if proc is None
                    else "process emitted no output" if not out and proc.returncode == 0
                    else f"exit status {proc.returncode}"
                ),
                evidence=[str(path.relative_to(CMP)) for path in bug_files],
            ))
            print(f"  ityfuzz {pair:5s} {side:10s} unverified ({elapsed:.0f}s) {detail}")
    return results


# --------------------------------------------------------------------------- rustyfuzz
RUSTYFUZZ_PAIRS = {
    "mint": "OwnerMintToken",
    "vault": "OffsetVault",
    "pool": "NoFlashPool",
    "lend": "CollateralizedLender",
    "gov": "GuardedGovernor",
}
# Comparison-specific property templates; their target addresses are validated
# and rebound to this run's deployment before fuzzing.
RUSTYFUZZ_INVARIANTS = {
    pair: CMP / "invariants" / f"{pair}.json"
    for pair in RUSTYFUZZ_PAIRS
    if pair != "mint"
}

RUSTYFUZZ_COMPARABLE_PAIRS = {"mint", "vault", "pool", "gov"}


def prepare_invariant(pair: str, target: str, vulnerable_target: str, destination: Path) -> Path:
    """Bind the benchmark property to this run's deployment after checking its template."""
    source = RUSTYFUZZ_INVARIANTS[pair]
    manifest = json.loads(source.read_text())
    if not isinstance(manifest, dict):
        raise RuntimeError(f"{pair} invariant template is not a JSON object: {source}")
    declared_target = manifest.get("target")
    if not isinstance(declared_target, str) or declared_target.lower() != vulnerable_target.lower():
        raise RuntimeError(
            f"{pair} invariant template target {declared_target!r} does not match "
            f"the deployed vulnerable target {vulnerable_target}"
        )
    manifest["target"] = target
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(manifest, indent=1))
    return destination


def parse_rustyfuzz_summary(data: dict, returncode: int) -> tuple[bool, int, str | None]:
    """Only accept findings from a successful, RPC-backed run with executions."""
    if not isinstance(data, dict):
        return False, 0, "campaign summary is not a JSON object"
    executions = data.get("total_executions")
    if type(executions) is not int or executions <= 0:
        return False, 0, "campaign summary proves no transactions executed"
    if data.get("execution_status") != "executed":
        return False, executions, "campaign summary does not report executed status"
    if returncode != 0:
        return False, executions, f"process exited with status {returncode}"
    if data.get("fork_setup_status") != "rpc":
        return False, executions, "campaign did not confirm RPC fork setup"
    if data.get("target_bytecode_loaded") is not True:
        return False, executions, "campaign did not confirm target bytecode loading"
    confirmed = data.get("confirmed_findings")
    if type(confirmed) is not int:
        return False, executions, "campaign summary lacks confirmed_findings"
    return confirmed > 0, executions, None


def validate_run_manifest(data: dict, fork_block: int, fork_block_hash: str) -> str | None:
    if not isinstance(data, dict):
        return "campaign run manifest is not a JSON object"
    if data.get("chain_id") != SUPPORTED_CHAIN_ID:
        return "run manifest chain ID does not match the benchmark"
    if data.get("fork_block") != fork_block:
        return "run manifest fork block does not match the pinned snapshot"
    observed_hash = data.get("fork_block_hash")
    if not isinstance(observed_hash, str) or observed_hash.lower() != fork_block_hash.lower():
        return "run manifest block hash does not match the pinned snapshot"
    return None


def validate_terminal_status(data: dict) -> str | None:
    if not isinstance(data, dict) or data.get("terminal") is not True:
        return "campaign terminal status is missing or not terminal"
    if data.get("state") != "completed":
        return f"campaign terminal state is {data.get('state')!r}, not completed"
    return None


def write_campaign_config(report: Path, budget_secs: int) -> Path:
    config_path = report / "config.toml"
    config_path.write_text(
        "\n".join(
            (
                f"rpc_url = {json.dumps(RPC)}",
                'chain = "evm"',
                f"timeout_secs = {budget_secs}",
                f"corpus_dir = {json.dumps(str(report / 'corpus'))}",
                f"report_dir = {json.dumps(str(report / 'reports'))}",
                "llm_enabled = false",
                "require_rpc_fork = true",
                "allow_synthetic_fallback = false",
                "",
            )
        )
    )
    return config_path


def promotion_arguments(enabled: bool) -> list[str]:
    return ["--promote-findings"] if enabled else ["--no-promote-findings"]


def collect_rustyfuzz_measurements(
    run_root: Path,
    target: str,
    expected_executions: int,
    fork_block: int,
    fork_block_hash: str,
    coverage_edges: int,
    recognized_selectors: set[str] | None = None,
) -> tuple[dict, str | None]:
    """Aggregate auditable per-sequence telemetry from persisted execution records."""
    provenance_dir = run_root / "inputs" / "execution_provenance"
    records = sorted(provenance_dir.glob("*.json"))
    if len(records) != expected_executions:
        return {}, (
            f"execution provenance record count {len(records)} does not match "
            f"campaign execution count {expected_executions}"
        )

    sequence_lengths = []
    target_transactions = 0
    recognized_target_transactions = 0
    recognized_target_selectors = set()
    target_call_observations = 0
    target_selectors = set()
    successful_transactions = 0
    reverted_transactions = 0
    halted_transactions = 0
    not_activated_transactions = 0
    successful_target_transactions = 0
    coverage_hashes = set()
    positive_novelty_sequences = 0
    state_novelty_score_sum = 0
    snapshot_ids = set()
    coverage_edges_max_sequence = 0
    coverage_edges_by_sequence = []
    sequences_with_new_coverage_hashes = 0
    coverage_hashes_first_sequence = 0
    for path in records:
        try:
            record = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError) as error:
            return {}, f"cannot read execution provenance {path.name}: {error}"
        if not isinstance(record, dict):
            return {}, f"execution provenance {path.name} is not a JSON object"
        rpc_provenance = record.get("rpc_provenance", {})
        if (
            rpc_provenance.get("chain_id") != SUPPORTED_CHAIN_ID
            or rpc_provenance.get("fork_block") != fork_block
            or str(rpc_provenance.get("fork_block_hash", "")).lower() != fork_block_hash.lower()
        ):
            return {}, f"execution provenance {path.name} does not match the pinned fork"

        input_data = record.get("input", {})
        txs = input_data.get("txs", [])
        if not isinstance(txs, list):
            return {}, f"execution provenance {path.name} has an invalid transaction sequence"
        sequence_lengths.append(len(txs))
        snapshot_ids.add(input_data.get("base_snapshot_id"))
        target_tx_indices = set()
        for tx_index, tx in enumerate(txs):
            if str(tx.get("to", "")).lower() == target.lower():
                target_transactions += 1
                tx_input = tx.get("input", [])
                if isinstance(tx_input, list) and len(tx_input) >= 4:
                    selector = bytes(tx_input[:4]).hex()
                    target_selectors.add(selector)
                    if recognized_selectors is not None and selector in recognized_selectors:
                        recognized_target_transactions += 1
                        recognized_target_selectors.add(selector)
                target_tx_indices.add(tx.get("tx_index", tx_index))

        execution = record.get("execution", {})
        calls = execution.get("call_trace", [])
        if not isinstance(calls, list):
            return {}, f"execution provenance {path.name} has an invalid call trace"
        target_call_observations += sum(
            1
            for call in calls
            if str(call.get("target", "")).lower() == target.lower()
            and call.get("phase") == "Start"
        )
        tx_results = execution.get("tx_results", [])
        if not isinstance(tx_results, list):
            return {}, f"execution provenance {path.name} has invalid transaction results"
        sequence_hashes = {
            item.get("coverage_hash")
            for item in tx_results
            if item.get("coverage_hash") not in (None, 0)
        }
        new_hashes = sequence_hashes - coverage_hashes
        if new_hashes:
            sequences_with_new_coverage_hashes += 1
        if len(sequence_lengths) == 1:
            coverage_hashes_first_sequence = len(sequence_hashes)
        coverage_hashes.update(sequence_hashes)
        for result in tx_results:
            status = result.get("status")
            tx_index = result.get("tx_index")
            if status == "Success":
                successful_transactions += 1
                if tx_index in target_tx_indices:
                    successful_target_transactions += 1
            elif status == "Revert":
                reverted_transactions += 1
            elif isinstance(status, dict) and "Halt" in status:
                halted_transactions += 1
                not_activated_transactions += status["Halt"] == "NotActivated"
        edge_count = record.get("coverage_edges", 0)
        if type(edge_count) is not int or edge_count < 0:
            return {}, f"execution provenance {path.name} has invalid coverage_edges"
        coverage_edges_by_sequence.append(edge_count)
        coverage_edges_max_sequence = max(coverage_edges_max_sequence, edge_count)
        novelty = record.get("state_novelty_score", 0)
        if type(novelty) is not int or novelty < 0:
            return {}, f"execution provenance {path.name} has invalid state_novelty_score"
        state_novelty_score_sum += novelty
        positive_novelty_sequences += novelty > 0

    return {
        "provenance_sequences": len(records),
        "coverage_edges_campaign_max": coverage_edges,
        "coverage_edges_max_sequence": coverage_edges_max_sequence,
        "coverage_edges_mean_per_sequence": (
            sum(coverage_edges_by_sequence) / len(coverage_edges_by_sequence)
        ),
        "coverage_edges_first_sequence": coverage_edges_by_sequence[0],
        "coverage_edges_last_sequence": coverage_edges_by_sequence[-1],
        "coverage_edges_sequence_first_last_delta": (
            coverage_edges_by_sequence[-1] - coverage_edges_by_sequence[0]
        ),
        "distinct_transaction_coverage_hashes": len(coverage_hashes),
        "transaction_coverage_hashes_first_sequence": coverage_hashes_first_sequence,
        "sequences_with_new_transaction_coverage_hashes": sequences_with_new_coverage_hashes,
        "target_transactions": target_transactions,
        "recognized_target_transactions": recognized_target_transactions,
        "unique_recognized_target_selectors": len(recognized_target_selectors),
        "target_call_observations": target_call_observations,
        "unique_target_selectors": len(target_selectors),
        "target_selectors": sorted(target_selectors),
        "successful_transactions": successful_transactions,
        "reverted_transactions": reverted_transactions,
        "halted_transactions": halted_transactions,
        "not_activated_transactions": not_activated_transactions,
        "successful_target_transactions": successful_target_transactions,
        "max_sequence_depth": max(sequence_lengths, default=0),
        "mean_sequence_depth": (
            sum(sequence_lengths) / len(sequence_lengths) if sequence_lengths else 0
        ),
        "distinct_base_snapshot_ids": len(snapshot_ids - {None}),
        "positive_state_novelty_sequences": positive_novelty_sequences,
        "state_novelty_score_sum": state_novelty_score_sum,
    }, None


def run_rustyfuzz(
    pairs: list[str], budget: int, addrs: dict, fork_block: int, seed: int = 42,
    max_execs: int | None = None,
    promote_findings: bool = False,
) -> list[RunResult]:
    results = []
    run_id = f"{seed}-{time.time_ns()}"
    for pair in pairs:
        contract = RUSTYFUZZ_PAIRS[pair]
        for side in ("vulnerable", "safe"):
            target = addrs[side][contract]
            report = CMP / "work" / "rustyfuzz" / run_id / f"{pair}-{side}"
            report.mkdir(parents=True, exist_ok=True)
            if pair not in RUSTYFUZZ_COMPARABLE_PAIRS:
                results.append(RunResult(
                    "rustyfuzz", pair, side, None, budget,
                    status="not_comparable",
                    target_address=target,
                    fork_block=fork_block,
                    fork_block_hash=addrs["fork_block_hash"],
                    property_id=PAIR_PROPERTY_IDS[pair],
                    comparability="no_valid_side_independent_oracle",
                    detail="the existing static invariant cannot distinguish the intended vulnerable behavior",
                ))
                continue
            campaign_id = f"cmp-{pair}-{side}-{seed}-{time.time_ns()}"
            inv = None
            if pair in RUSTYFUZZ_INVARIANTS:
                inv = prepare_invariant(
                    pair,
                    target,
                    addrs["vulnerable"][contract],
                    report / "invariants.json",
                )
            abi = contract_abi(contract)
            recognized_selectors = abi_function_selectors(abi)
            if not abi.is_file():
                raise RuntimeError(f"required ABI is missing: {abi}")
            assert_pinned_snapshot(addrs, fork_block)
            write_campaign_config(report, budget)
            cmd = [
                "cargo", "run", "--quiet", "--offline", "--locked",
                "--manifest-path", str(ROOT / "Cargo.toml"),
                "-p", "rusty-fuzz", "--bin", "rusty-fuzz", "--",
                "fuzz",
                "--rpc-url", RPC,
                "--fork-block", str(fork_block),
                "--contract", target,
                "--abi", str(abi),
                "--duration-secs", str(budget),
                "--wall-timeout-secs", str(budget + 60),
                "--deterministic",
                "--rng-seed", str(seed),
                "--single-process", "true",
                "--campaign-id", campaign_id,
                "--no-synthetic-fallback",
            ]
            cmd.extend(promotion_arguments(promote_findings))
            if inv is not None:
                cmd += ["--invariants", str(inv)]
            if max_execs:
                cmd += ["--max-execs", str(max_execs)]
            t0 = time.time()
            found = False
            detail = "no verdict"
            ops = None
            proc = None
            out = ""
            try:
                child_env = os.environ.copy()
                child_env["RUSTYFUZZ_RPC_API_KEY"] = ""
                child_env.pop("RUSTYFUZZ_RPC_API_KEY_ALLOWED_ORIGINS", None)
                child_env["RUSTYFUZZ_TEST_ALLOW_LOOPBACK"] = "1"
                proc = subprocess.run(
                    cmd, cwd=report, capture_output=True, text=True,
                    timeout=budget + 180, start_new_session=True,
                    env=child_env,
                )
                out = proc.stdout + proc.stderr
            except subprocess.TimeoutExpired as exc:
                stdout = exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
                stderr = exc.stderr.decode(errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
                out = stdout + stderr
            elapsed = time.time() - t0
            log_path = report / "rustyfuzz.log"
            log_path.write_text(out)
            run_root = report / ".rustyfuzz" / "runs" / campaign_id
            summary_path = run_root / "reports" / "campaign_summary.json"
            found = False
            ops = 0
            measurements = {}
            error = "campaign summary was not written"
            detail = "no verdict"
            manifest_path = run_root / "config.json"
            terminal_path = run_root / "terminal_status.json"
            manifest_error = (
                validate_run_manifest(
                    json.loads(manifest_path.read_text()),
                    fork_block,
                    addrs["fork_block_hash"],
                )
                if manifest_path.is_file()
                else "campaign run manifest was not written"
            )
            terminal_error = (
                validate_terminal_status(json.loads(terminal_path.read_text()))
                if terminal_path.is_file()
                else "campaign terminal status was not written"
            )
            if summary_path.is_file():
                summary_data = json.loads(summary_path.read_text())
                found, ops, error = parse_rustyfuzz_summary(
                    summary_data, 0,
                )
                if error is None:
                    error = manifest_error
                if error is None:
                    error = terminal_error
                if error is None:
                    measurements, error = collect_rustyfuzz_measurements(
                        run_root,
                        target,
                        ops,
                        fork_block,
                        addrs["fork_block_hash"],
                        summary_data.get("coverage_edges", 0),
                        recognized_selectors,
                    )
                    measurements.update({
                        "interesting_candidates": summary_data.get("interesting_candidates", 0),
                        "unproven_candidates": summary_data.get("unproven_candidates", 0),
                        "promotion_failures": summary_data.get("promotion_failures", 0),
                        "poc_count": summary_data.get("poc_count", 0),
                        "confirmed_findings": summary_data.get("confirmed_findings", 0),
                        "promotion_enabled": promote_findings,
                    })
                    if error is None and measurements["not_activated_transactions"]:
                        error = (
                            "campaign execution semantics are incompatible: "
                            f"{measurements['not_activated_transactions']} transactions halted "
                            "with NotActivated"
                        )
                if error is None and proc is None:
                    error = "campaign process timed out"
                if error is None and proc is not None and proc.returncode != 0:
                    found = False
                    error = f"process exited with status {proc.returncode}"
                    excerpt = out[-1000:].strip()
                    if excerpt:
                        error += f"; output={excerpt}"
                detail = (
                    (
                        f"{'promotion' if promote_findings else 'measurement-only'}; "
                        f"{summary_data.get('interesting_candidates', 0)} interesting candidate(s), "
                        f"{summary_data.get('confirmed_findings', 0)} confirmed finding(s)"
                    )
                    if error is None else error
                )
            elif out:
                excerpt = out[-1000:].strip()
                error = f"{error}; exit={proc.returncode if proc is not None else 'timeout'}; output={excerpt}"
            if proc is None and error is None:
                error = "process timed out"
            results.append(RunResult(
                "rustyfuzz", pair, side,
                found if promote_findings and error is None else None,
                budget,
                status=(
                    "valid" if promote_findings else "measurement_only"
                ) if error is None else (
                    "partial"
                    if error.startswith("process exited with status")
                    or error.startswith("campaign terminal state is")
                    else "invalid"
                ),
                target_address=target,
                fork_block=fork_block,
                fork_block_hash=addrs["fork_block_hash"],
                property_id=PAIR_PROPERTY_IDS[pair],
                comparability="same_target_property",
                ops=ops,
                ops_unit="executions",
                detail=detail,
                error=error,
                evidence=(
                    [str(summary_path.relative_to(ROOT))]
                    if summary_path.is_file() else []
                ) + [str(log_path.relative_to(ROOT))],
                measurements=measurements,
            ))
            if error is not None:
                mark = "INVALID"
            elif measurements.get("promotion_enabled") is False:
                mark = "MEASURED"
            else:
                mark = "FOUND" if found else "clean"
            print(
                f"  rustyfuzz {pair:5s} {side:10s} {mark} ({elapsed:.0f}s) "
                f"{detail} ops={ops} metrics={measurements}"
            )
    write_results(
        "rustyfuzz",
        results,
        CMP / "work" / "rustyfuzz" / run_id / "results.json",
    )
    return results


# --------------------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--tools", default="echidna,ityfuzz,rustyfuzz")
    ap.add_argument("--pairs", default="mint,vault,pool,lend,gov")
    ap.add_argument("--budget", type=int, default=300, help="wall-clock seconds per (tool, pair, side)")
    ap.add_argument("--max-execs", type=int, default=0, help="RustyFuzz exec cap (0 = uncapped)")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument(
        "--promote-findings",
        action="store_true",
        help="enable RustyFuzz replay/proof promotion instead of measurement-only mode",
    )
    ap.add_argument("--smoke", action="store_true", help="tiny budget, one pair, pipeline check only")
    args = ap.parse_args()

    tools = [t.strip() for t in args.tools.split(",") if t.strip()]
    pairs = [p.strip() for p in args.pairs.split(",") if p.strip()]
    unknown_tools = set(tools) - {"echidna", "ityfuzz", "rustyfuzz"}
    unknown_pairs = set(pairs) - set(PAIR_PROPERTY_IDS)
    if unknown_tools or unknown_pairs:
        ap.error(
            f"unknown tools={sorted(unknown_tools)} pairs={sorted(unknown_pairs)}"
        )
    if args.budget < 1 or args.max_execs < 0:
        ap.error("--budget must be positive and --max-execs cannot be negative")
    budget = 20 if args.smoke else args.budget
    if args.smoke:
        pairs = pairs[:1]

    print(f"# comparison: tools={tools} pairs={pairs} budget={budget}s/pair")

    if any(tool in tools for tool in ("echidna", "ityfuzz", "rustyfuzz")):
        print("\n## shared Anvil deployment (chain ID 1)")
        anvil = Anvil()
        try:
            anvil.start()
            addrs = deploy(smoke=args.smoke)
            fork_block = addrs["fork_block"]
            print(f"  deployed 12 contracts; verified code at block={fork_block}; attacker={ATTACKER}")
            if "echidna" in tools:
                print("\n## echidna (self-deployed harness; observations not scored)")
                write_results(
                    "echidna",
                    run_echidna(pairs, budget, addrs, fork_block, args.seed),
                )
            if "ityfuzz" in tools:
                write_results("ityfuzz", run_ityfuzz(pairs, budget, addrs, fork_block, args.seed))
            if "rustyfuzz" in tools:
                run_rustyfuzz(
                    pairs, budget, addrs, fork_block, args.seed, args.max_execs or None,
                    args.promote_findings,
                )
        finally:
            anvil.stop()

    print("\n# done; see benchmarks/comparison/results/")


if __name__ == "__main__":
    sys.exit(main())
