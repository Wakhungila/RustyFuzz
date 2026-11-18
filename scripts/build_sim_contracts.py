#!/usr/bin/env python3
"""Compile contracts/sim/*.sol and write runtime bytecode to contracts/sim/artifacts/<Name>.hex.

The hex files are committed so building rusty-fuzz needs no solc; rerun this
after editing a contract (solc 0.8.28, via-ir, optimizer 200, cancun).
"""
import subprocess, sys, tempfile
from pathlib import Path

SIM = Path(__file__).resolve().parent.parent / "contracts/sim"
SOURCES = ["MockToken.sol", "AtomicAttacker.sol", "MockV2Pair.sol", "MockV3Pool.sol",
           "test/SpotOracleLender.sol"]
WANT = ["MockToken", "AtomicAttacker", "MockV2Pair", "MockV3Pool", "SpotOracleLender",
        "FixedOracleLender"]
solc = sys.argv[1] if len(sys.argv) > 1 else "solc"
out = SIM / "artifacts"
out.mkdir(exist_ok=True)
with tempfile.TemporaryDirectory() as tmp:
    subprocess.run([solc, "--via-ir", "--optimize", "--optimize-runs", "200", "--evm-version",
                    "cancun", "--bin-runtime", "--overwrite", "-o", tmp,
                    *[str(SIM / s) for s in SOURCES]], check=True, capture_output=True)
    for name in WANT:
        (out / f"{name}.hex").write_text((Path(tmp) / f"{name}.bin-runtime").read_text().strip() + "\n")
        print("wrote", name)
