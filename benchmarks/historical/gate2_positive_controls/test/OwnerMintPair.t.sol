// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {
    BurnOnlyToken,
    OwnerMintToken as VulnerableOwnerMintToken
} from "../contracts/VulnerableControls.sol";
import {OwnerMintToken as SafeOwnerMintToken} from "../../negative_controls/contracts/Controls.sol";
import {
    OffsetVault as VulnerableOffsetVault,
    NoFlashPool as VulnerableNoFlashPool,
    CollateralizedLender as VulnerableCollateralizedLender,
    GuardedGovernor as VulnerableGuardedGovernor
} from "../contracts/VulnerableControls.sol";
import {
    OffsetVault as SafeOffsetVault,
    NoFlashPool as SafeNoFlashPool,
    CollateralizedLender as SafeCollateralizedLender,
    GuardedGovernor as SafeGuardedGovernor
} from "../../negative_controls/contracts/Controls.sol";

interface Vm {
    function store(address target, bytes32 slot, bytes32 value) external;
    function prank(address caller) external;
}

contract OwnerMintPairTest {
    Vm private constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    address private constant VICTIM = 0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB;

    function testVulnerableUnauthorizedMintViolatesBalanceAndSupplyInvariant() external {
        VulnerableOwnerMintToken token = new VulnerableOwnerMintToken();
        address attacker = address(this);
        uint256 amount = 100 ether;

        require(!token.canMint(attacker), "caller must not be authorized");
        uint256 balanceBefore = token.balanceOf(attacker);
        uint256 supplyBefore = token.totalSupply();

        token.mint(attacker, amount);

        require(token.balanceOf(attacker) == balanceBefore + amount, "minted balance not observed");
        require(token.totalSupply() == supplyBefore + amount, "minted supply not observed");
    }

    function testSafeUnauthorizedMintRevertsAndPreservesBalanceAndSupply() external {
        SafeOwnerMintToken token = new SafeOwnerMintToken();
        address attacker = address(this);

        (bool success,) = address(token).call(
            abi.encodeCall(token.mint, (attacker, 100 ether))
        );

        require(!success, "unauthorized mint unexpectedly succeeded");
        require(token.balanceOf(attacker) == 0, "failed mint changed attacker balance");
        require(token.totalSupply() == 0, "failed mint changed total supply");
    }

    function testVulnerableVaultAllowsZeroShareDepositAndDrain() external {
        BurnOnlyToken asset = new BurnOnlyToken();
        VulnerableOffsetVault vault = new VulnerableOffsetVault();
        _seedVault(address(vault), address(asset), 1);

        vm.prank(VICTIM);
        uint256 shares = vault.deposit(1, VICTIM);
        require(shares == 0, "vulnerable vault unexpectedly issued shares");
        require(vault.balanceOf(VICTIM) == 0, "victim unexpectedly owns shares");

        uint256 assetsBefore = asset.balanceOf(address(this));
        vault.redeem(1, address(this), address(this));
        require(
            asset.balanceOf(address(this)) > assetsBefore,
            "attacker did not withdraw assets after victim deposit"
        );
    }

    function testSafeVaultIssuesVictimSharesAndPreventsDrain() external {
        BurnOnlyToken asset = new BurnOnlyToken();
        SafeOffsetVault vault = new SafeOffsetVault();
        _seedVault(address(vault), address(asset), 1);

        vm.prank(VICTIM);
        uint256 shares = vault.deposit(1, VICTIM);
        require(shares > 0, "safe vault issued zero shares");
        require(vault.balanceOf(VICTIM) == shares, "victim shares were not recorded");

        uint256 assetsBefore = asset.balanceOf(address(this));
        vault.redeem(1, address(this), address(this));
        require(
            asset.balanceOf(address(this)) == assetsBefore,
            "safe vault paid attacker for victim's deposit"
        );
    }

    function testVulnerablePoolSwapReducesReserveProduct() external {
        BurnOnlyToken token0 = new BurnOnlyToken();
        BurnOnlyToken token1 = new BurnOnlyToken();
        VulnerableNoFlashPool pool = new VulnerableNoFlashPool();
        _seedPool(address(pool), address(token0), address(token1));

        uint256 productBefore = 1_000_000 * 1_000_000;
        pool.swap(100_000, 0, address(this), "");
        (uint112 reserve0, uint112 reserve1,) = pool.getReserves();

        require(
            uint256(reserve0) * uint256(reserve1) < productBefore,
            "vulnerable pool preserved the reserve product"
        );
        require(token0.balanceOf(address(this)) == 100_000, "attacker did not receive output");
    }

    function testSafePoolRejectsSwapThatReducesReserveProduct() external {
        BurnOnlyToken token0 = new BurnOnlyToken();
        BurnOnlyToken token1 = new BurnOnlyToken();
        SafeNoFlashPool pool = new SafeNoFlashPool();
        _seedPool(address(pool), address(token0), address(token1));

        (bool success,) = address(pool).call(
            abi.encodeCall(pool.swap, (100_000, 0, address(this), bytes("")))
        );
        (uint112 reserve0, uint112 reserve1,) = pool.getReserves();

        require(!success, "safe pool accepted an invariant-breaking swap");
        require(reserve0 == 1_000_000 && reserve1 == 1_000_000, "revert changed reserves");
        require(token0.balanceOf(address(this)) == 0, "revert transferred pool assets");
    }

    function testVulnerableLenderTransfersAssetsWithoutRecordingDebt() external {
        BurnOnlyToken asset = new BurnOnlyToken();
        VulnerableCollateralizedLender lender = new VulnerableCollateralizedLender();
        _seedLender(address(lender), address(asset));

        lender.borrow(100);

        require(asset.balanceOf(address(this)) == 100, "borrowed assets not received");
        require(lender.debt() == 0, "vulnerable lender recorded debt");
    }

    function testSafeLenderRecordsDebtWhenTransferringAssets() external {
        BurnOnlyToken asset = new BurnOnlyToken();
        SafeCollateralizedLender lender = new SafeCollateralizedLender();
        _seedLender(address(lender), address(asset));

        lender.borrow(100);

        require(asset.balanceOf(address(this)) == 100, "borrowed assets not received");
        require(lender.debt() == 100, "safe lender failed to record debt");
    }

    function testVulnerableGovernorExecutesWithoutProposalOrQuorum() external {
        VulnerableGuardedGovernor governor = new VulnerableGuardedGovernor();

        governor.execute(1);

        require(governor.executed(), "vulnerable governor did not execute");
        require(governor.proposed() == 0 && governor.votes() == 0, "test unexpectedly seeded quorum");
    }

    function testSafeGovernorRejectsExecutionWithoutProposalOrQuorum() external {
        SafeGuardedGovernor governor = new SafeGuardedGovernor();

        (bool success,) = address(governor).call(abi.encodeCall(governor.execute, (1)));

        require(!success, "safe governor executed without proposal or quorum");
        require(!governor.executed(), "failed execution changed governor state");
    }

    function _seedVault(address vault, address asset, uint256 attackerShares) private {
        vm.store(vault, bytes32(uint256(0)), bytes32(uint256(uint160(asset))));
        vm.store(vault, bytes32(uint256(1)), bytes32(attackerShares));
        vm.store(
            vault,
            _mappingSlot(address(this), 2),
            bytes32(attackerShares)
        );
        _storeTokenBalance(asset, vault, 1_001);
        _storeTokenBalance(asset, VICTIM, 1);
        _storeTokenAllowance(asset, VICTIM, vault, 1);
    }

    function _seedPool(address pool, address token0, address token1) private {
        vm.store(pool, bytes32(uint256(0)), bytes32(uint256(uint160(token0))));
        vm.store(pool, bytes32(uint256(1)), bytes32(uint256(uint160(token1))));
        vm.store(pool, bytes32(uint256(2)), bytes32(uint256(1_000_000)));
        vm.store(pool, bytes32(uint256(3)), bytes32(uint256(1_000_000)));
        _storeTokenBalance(token0, pool, 1_000_000);
        _storeTokenBalance(token1, pool, 1_000_000);
    }

    function _seedLender(address lender, address asset) private {
        vm.store(lender, bytes32(uint256(0)), bytes32(uint256(uint160(asset))));
        vm.store(lender, bytes32(uint256(1)), bytes32(uint256(0)));
        vm.store(lender, bytes32(uint256(2)), bytes32(uint256(1_000)));
        vm.store(lender, bytes32(uint256(3)), bytes32(uint256(uint160(address(this)))));
        _storeTokenBalance(asset, lender, 1_000);
    }

    function _storeTokenBalance(address token, address account, uint256 amount) private {
        vm.store(token, _mappingSlot(account, 0), bytes32(amount));
    }

    function _storeTokenAllowance(address token, address owner, address spender, uint256 amount)
        private
    {
        bytes32 ownerSlot = _mappingSlot(owner, 1);
        bytes32 allowanceSlot = keccak256(abi.encode(spender, ownerSlot));
        vm.store(token, allowanceSlot, bytes32(amount));
    }

    function _mappingSlot(address key, uint256 baseSlot) private pure returns (bytes32) {
        return keccak256(abi.encode(key, baseSlot));
    }
}
