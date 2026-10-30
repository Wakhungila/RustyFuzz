// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;
import {MintPair} from "../echidna/ControlPairs.sol";
import {VaultPair} from "../echidna/ControlPairs.sol";
import {PoolPair} from "../echidna/ControlPairs.sol";
import {LendPair} from "../echidna/ControlPairs.sol";
import {GovPair} from "../echidna/ControlPairs.sol";
import {BurnOnlyToken} from "../src/VulnerableControls.sol";

/// setUp()-style deployers for ItyFuzz's off-chain (setup) mode: the fuzzer calls
/// setUp() once and then fuzzes everything reachable, including the harness's
/// echidna_* views (which it treats as state) and the action functions.
contract ItyMintSetup { MintPair public harness; function setUp() public { harness = new MintPair(); } }
contract ItyVaultSetup { VaultPair public harness; function setUp() public { harness = new VaultPair(); } }
contract ItyPoolSetup { PoolPair public harness; function setUp() public { harness = new PoolPair(); } }
contract ItyLendSetup { LendPair public harness; function setUp() public { harness = new LendPair(); } }
contract ItyGovSetup { GovPair public harness; function setUp() public { harness = new GovPair(); } }

/// Extraction-shaped variants: the same defect classes expressed the way
/// ItyFuzz's oracles detect them (drainable funds). These let the comparison
/// show what each tool's oracle model covers, instead of scoring a model
/// mismatch as a miss.
contract DrainablePool {
    BurnOnlyToken public token; // slot 0
    uint256 public reserve;     // slot 1

    constructor() { }

    function seed(address coin) external {
        require(address(token) == address(0), "seeded");
        _setSlot(address(this), 0, bytes32(uint256(uint160(coin))));
        _setSlot(address(this), 1, bytes32(uint256(1_000 ether)));
    }

    function _setSlot(address t, uint256 s, bytes32 v) internal {
        assembly { sstore(s, v) }
    }

    /// The defect: anyone can move the pool's inventory out.
    function swap(uint256 out, address to) external {
        BurnOnlyToken(address(token)).transfer(to, out);
        reserve = BurnOnlyToken(address(token)).balanceOf(address(this));
    }
}

/// Safe counterpart of DrainablePool: the same inventory behind a guarded move.
contract GuardedPool {
    BurnOnlyToken public token; // slot 0
    uint256 public reserve;     // slot 1
    bool internal locked;

    function seed(address coin) external {
        require(address(token) == address(0), "seeded");
        assembly { sstore(0, coin) }
        assembly { sstore(1, 1000000000000000000000) }
    }

    function swap(uint256 out, address to) external {
        require(out <= 1 wei, "capped");
        require(!locked, "reentrant");
        locked = true;
        BurnOnlyToken(address(token)).transfer(to, out);
        reserve = BurnOnlyToken(address(token)).balanceOf(address(this));
        locked = false;
    }
}
