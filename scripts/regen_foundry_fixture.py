#!/usr/bin/env python3
"""Regenerate tests/fixtures/foundry_vault/*/out from the committed sources.

Needs `forge` and a solc 0.8.28 on PATH (or foundry.toml `solc`). Writes slim
artifacts holding only what rusty-fuzz reads: abi, bytecode.object,
deployedBytecode.object and the compilation target. forge-std is fetched into a
temp dir (never committed) because the test inherits from it.

    python3 scripts/regen_foundry_fixture.py [--solc /path/to/solc]
"""
import argparse, json, shutil, subprocess, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent / "tests/fixtures/foundry_vault"
ap = argparse.ArgumentParser()
ap.add_argument("--solc", default=None)
args = ap.parse_args()

for variant in ("buggy", "fixed"):
    src_dir = ROOT / variant
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp) / "p"
        shutil.copytree(src_dir, work, ignore=shutil.ignore_patterns("out"))
        subprocess.run(["forge", "init", "--force", "--no-commit", "--no-git", str(work)],
                       check=False, capture_output=True)  # installs forge-std
        # forge init overwrote nothing we need; restore our sources.
        for sub in ("src", "test"):
            shutil.rmtree(work / sub, ignore_errors=True)
            shutil.copytree(src_dir / sub, work / sub)
        toml = (src_dir / "foundry.toml").read_text()
        if args.solc:
            toml = toml.replace('solc = "solc"', f'solc = "{args.solc}"')
        (work / "foundry.toml").write_text(toml)
        subprocess.run(["forge", "build"], cwd=work, check=True)
        for rel, name in (("Vault.sol/Vault.json", "Vault"),
                          ("Vault.invariant.t.sol/VaultInvariantTest.json", "VaultInvariantTest")):
            full = json.loads((work / "out" / rel).read_text())
            slim = {
                "abi": full["abi"],
                "bytecode": {"object": full["bytecode"]["object"]},
                "deployedBytecode": {"object": full["deployedBytecode"]["object"]},
                "metadata": {"settings": {"compilationTarget":
                    full["metadata"]["settings"]["compilationTarget"]}},
            }
            dest = src_dir / "out" / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(json.dumps(slim, indent=1) + "\n")
            print("wrote", dest.relative_to(ROOT.parent.parent.parent))
