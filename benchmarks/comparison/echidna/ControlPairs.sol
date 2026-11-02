// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

// Echidna harnesses for the matched-budget comparison. One harness contract per
// control pair; each self-deploys one vulnerable and one safe instance and states
// the same property twice (echidna_vulnerable_* / echidna_safe_*).
//
// Why both sides carry the property: a fuzzer that reports the vulnerable side
// but also "finds" the safe side is producing false positives. Stating both makes
// that measurable instead of argued.
//
// Sender model: Echidna runs every call from fuzzed senders, none of which are
// the contracts' privileged constants, so properties describe what any outsider
// can reach — the threat model the controls encode.
//
// Property style: observation flags, not reverting assertions. A `require` inside
// a fuzzed call reverts the whole transaction and rolls back the state the
// property must observe; a flag persists and the boolean property reads it.

import {
    BurnOnlyToken as VCoin,
    OwnerMintToken as VMinter,
    OffsetVault as VVault,
    NoFlashPool as VPool,
    CollateralizedLender as VLender,
    GuardedGovernor as VGov
} from "../src/VulnerableControls.sol";
import {
    BurnOnlyToken as SCoin,
    OwnerMintToken as SMinter,
    OffsetVault as SVault,
    NoFlashPool as SPool,
    CollateralizedLender as SLender,
    GuardedGovernor as SGov
} from "../src/Controls.sol";

interface Hevm {
    function store(address target, bytes32 slot, bytes32 value) external;
    function prank(address caller) external;
    function warp(uint256) external;
    function deal(address who, uint256 amount) external;
}

abstract contract HarnessBase {
    Hevm constant hevm = Hevm(address(uint160(uint256(keccak256("hevm cheat code")))));
    uint256 constant FUND = 1_000_000 ether;

    function _fund(address coin, address who, uint256 amount) internal {
        hevm.store(coin, keccak256(abi.encode(who, uint256(0))), bytes32(amount));
    }

    function _set(address target, uint256 slot, bytes32 value) internal {
        hevm.store(target, bytes32(slot), value);
    }
}

/// Pair 1 — ERC-20 owner mint. Property: mint() moves no balance unless the
/// minter policy authorizes the caller.
contract MintPair is HarnessBase {
    VMinter internal vMint;
    SMinter internal sMint;
    bool internal vUnauthorizedGain;
    bool internal sUnauthorizedGain;

    constructor() {
        vMint = new VMinter();
        sMint = new SMinter();
    }

    function mint_vulnerable(address to, uint256 amount) public {
        if (amount == 0 || amount > 1_000 ether) return;
        uint256 before_ = vMint.balanceOf(to);
        try vMint.mint(to, amount) {
            if (vMint.balanceOf(to) != before_ && !vMint.canMint(msg.sender)) {
                vUnauthorizedGain = true;
            }
        } catch {}
    }

    function mint_safe(address to, uint256 amount) public {
        if (amount == 0 || amount > 1_000 ether) return;
        uint256 before_ = sMint.balanceOf(to);
        try sMint.mint(to, amount) {
            if (sMint.balanceOf(to) != before_ && !sMint.canMint(msg.sender)) {
                sUnauthorizedGain = true;
            }
        } catch {}
    }

    function echidna_vulnerable_mint_is_authorized() public view returns (bool) {
        return !vUnauthorizedGain;
    }

    function echidna_safe_mint_is_authorized() public view returns (bool) {
        return !sUnauthorizedGain;
    }
}

/// Pair 2 — ERC-4626 zero-share deposit. Property: a nonzero deposit returns
/// nonzero shares. The same property RustyFuzz proves through a return-value
/// binding; here it is observed through Solidity.
contract VaultPair is HarnessBase {
    VCoin internal vCoin;
    VVault internal vVault;
    SCoin internal sCoin;
    SVault internal sVault;
    bool internal vZeroShareDeposit;
    bool internal sZeroShareDeposit;

    constructor() {
        vCoin = new VCoin();
        vVault = new VVault();
        _fund(address(vCoin), address(this), FUND);
        _set(address(vVault), 0, bytes32(uint256(uint160(address(vCoin)))));
        vCoin.approve(address(vVault), type(uint256).max);

        sCoin = new SCoin();
        sVault = new SVault();
        _fund(address(sCoin), address(this), FUND);
        _set(address(sVault), 0, bytes32(uint256(uint160(address(sCoin)))));
        sCoin.approve(address(sVault), type(uint256).max);
    }

    function deposit_vulnerable(uint256 assets) public {
        if (assets == 0 || assets > 1_000 ether) return;
        try vVault.deposit(assets, address(this)) returns (uint256 shares) {
            if (shares == 0) vZeroShareDeposit = true;
        } catch {}
    }

    function deposit_safe(uint256 assets) public {
        if (assets == 0 || assets > 1_000 ether) return;
        try sVault.deposit(assets, address(this)) returns (uint256 shares) {
            if (shares == 0) sZeroShareDeposit = true;
        } catch {}
    }

    /// The donation primitive: moving coins to the vault without minting shares.
    /// Without this action the share-price inflation attack is unreachable, which
    /// would be a harness gap, not a result.
    function donate_vulnerable(uint256 amount) public {
        if (amount == 0 || amount > 1_000 ether) return;
        try vCoin.transfer(address(vVault), amount) {} catch {}
    }

    function donate_safe(uint256 amount) public {
        if (amount == 0 || amount > 1_000 ether) return;
        try sCoin.transfer(address(sVault), amount) {} catch {}
    }

    function echidna_vulnerable_no_zero_share_deposit() public view returns (bool) {
        return !vZeroShareDeposit;
    }

    function echidna_safe_no_zero_share_deposit() public view returns (bool) {
        return !sZeroShareDeposit;
    }
}

/// Pair 3 — AMM swap without the reserve-product check. Property: after any
/// swap, the reserve product is at least what it was before.
contract PoolPair is HarnessBase {
    VCoin internal vCoin;
    VPool internal vPool;
    SCoin internal sCoin;
    SPool internal sPool;
    bool internal vProductDecreased;
    bool internal sProductDecreased;

    constructor() {
        vCoin = new VCoin();
        vPool = new VPool();
        _fund(address(vCoin), address(vPool), 1_000 ether);
        _set(address(vPool), 0, bytes32(uint256(uint160(address(vCoin)))));
        _set(address(vPool), 1, bytes32(uint256(uint160(address(vCoin)))));
        _set(address(vPool), 2, bytes32(uint256(1_000 ether)));
        _set(address(vPool), 3, bytes32(uint256(1_000 ether)));

        sCoin = new SCoin();
        sPool = new SPool();
        _fund(address(sCoin), address(sPool), 1_000 ether);
        _set(address(sPool), 0, bytes32(uint256(uint160(address(sCoin)))));
        _set(address(sPool), 1, bytes32(uint256(uint160(address(sCoin)))));
        _set(address(sPool), 2, bytes32(uint256(1_000 ether)));
        _set(address(sPool), 3, bytes32(uint256(1_000 ether)));
    }

    function swap_vulnerable(uint256 out0, uint256 out1) public {
        (uint256 r0, uint256 r1, ) = vPool.getReserves();
        if (out0 == 0 && out1 == 0) return;
        if (out0 >= r0 || out1 >= r1) return;
        if (out0 > 100 ether || out1 > 100 ether) return;
        uint256 beforeProduct = r0 * r1;
        try vPool.swap(out0, out1, address(this), "") {
            (uint256 n0, uint256 n1, ) = vPool.getReserves();
            if (n0 * n1 < beforeProduct) vProductDecreased = true;
        } catch {}
    }

    function swap_safe(uint256 out0, uint256 out1) public {
        (uint256 r0, uint256 r1, ) = sPool.getReserves();
        if (out0 == 0 && out1 == 0) return;
        if (out0 >= r0 || out1 >= r1) return;
        if (out0 > 100 ether || out1 > 100 ether) return;
        uint256 beforeProduct = r0 * r1;
        try sPool.swap(out0, out1, address(this), "") {
            (uint256 n0, uint256 n1, ) = sPool.getReserves();
            if (n0 * n1 < beforeProduct) sProductDecreased = true;
        } catch {}
    }

    function echidna_vulnerable_product_never_decreases() public view returns (bool) {
        return !vProductDecreased;
    }

    function echidna_safe_product_never_decreases() public view returns (bool) {
        return !sProductDecreased;
    }
}

/// Pair 4 — lending: borrowed assets are not recorded as debt. Property: every
/// successful borrow increases the recorded debt by the borrowed amount.
contract LendPair is HarnessBase {
    VCoin internal vCoin;
    VLender internal vLender;
    SCoin internal sCoin;
    SLender internal sLender;
    bool internal vDebtNotTracked;
    bool internal sDebtNotTracked;

    constructor() {
        vCoin = new VCoin();
        vLender = new VLender();
        _fund(address(vCoin), address(vLender), 1_000 ether);
        _set(address(vLender), 0, bytes32(uint256(uint160(address(vCoin)))));
        _set(address(vLender), 2, bytes32(uint256(10 ether)));
        _set(address(vLender), 3, bytes32(uint256(uint160(address(this)))));

        sCoin = new SCoin();
        sLender = new SLender();
        _fund(address(sCoin), address(sLender), 1_000 ether);
        _set(address(sLender), 0, bytes32(uint256(uint160(address(sCoin)))));
        _set(address(sLender), 2, bytes32(uint256(10 ether)));
        _set(address(sLender), 3, bytes32(uint256(uint160(address(this)))));
    }

    function borrow_vulnerable(uint256 amount) public {
        if (amount == 0 || amount > 5 ether) return;
        uint256 before_ = vLender.debt();
        try vLender.borrow(amount) {
            if (vLender.debt() != before_ + amount) vDebtNotTracked = true;
        } catch {}
    }

    function borrow_safe(uint256 amount) public {
        if (amount == 0 || amount > 5 ether) return;
        uint256 before_ = sLender.debt();
        try sLender.borrow(amount) {
            if (sLender.debt() != before_ + amount) sDebtNotTracked = true;
        } catch {}
    }

    function echidna_vulnerable_debt_tracks_borrows() public view returns (bool) {
        return !vDebtNotTracked;
    }

    function echidna_safe_debt_tracks_borrows() public view returns (bool) {
        return !sDebtNotTracked;
    }
}

/// Pair 5 — governance: execute() without proposal, quorum or timelock.
/// Property: executed stays false unless the full governance path ran.
contract GovPair is HarnessBase {
    VGov internal vGov;
    SGov internal sGov;
    bool internal vExecutedWithoutPath;
    bool internal sExecutedWithoutPath;

    constructor() {
        vGov = new VGov();
        sGov = new SGov();
    }

    /// The full legitimate path, callable by the right senders via prank.
    /// Echidna will usually call it from wrong senders, which is the point:
    /// the safe contract reverts, the vulnerable one does not.
    function full_path_vulnerable() public {
        address[] memory targets = new address[](1);
        uint256[] memory values = new uint256[](1);
        string[] memory sigs = new string[](1);
        bytes[] memory calldatas = new bytes[](1);
        try vGov.propose(targets, values, sigs, calldatas, "x") {} catch {}
        try vGov.castVote(1, 1) {} catch {}
        try vGov.queue(1) {} catch {}
        hevm.warp(block.timestamp + 200);
        try vGov.execute(1) {
            if (!vGov.executed()) return;
            // Legitimate completion is fine; reset the observable is impossible
            // (executed is one-way), so record that it happened through the path.
            vExecutedWithoutPath = false;
        } catch {}
    }

    function execute_vulnerable(uint256 id) public {
        if (id == 0) return;
        try vGov.execute(id) {
            // If this succeeded from an arbitrary sender with no quorum state,
            // the guard is gone. The legitimate path also lands here; the flag
            // distinction is whether votes were ever cast (they cannot be, from
            // non-VOTER senders Echidna controls).
            vExecutedWithoutPath = true;
        } catch {}
    }

    function execute_safe(uint256 id) public {
        if (id == 0) return;
        try sGov.execute(id) {
            sExecutedWithoutPath = true;
        } catch {}
    }

    function echidna_vulnerable_execute_requires_path() public view returns (bool) {
        return !vExecutedWithoutPath;
    }

    function echidna_safe_execute_requires_path() public view returns (bool) {
        return !sExecutedWithoutPath;
    }
}
