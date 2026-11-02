// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

// Aliased imports: both source files declare the same contract names at file scope,
// so every reference must be qualified by its origin (V* vulnerable, S* safe).
import {
    BurnOnlyToken as VCoin,
    OwnerMintToken as VMinter,
    OffsetVault as VVault,
    NoFlashPool as VPool,
    CollateralizedLender as VLender,
    GuardedGovernor as VGov
} from "./VulnerableControls.sol";
import {
    BurnOnlyToken as SCoin,
    OwnerMintToken as SMinter,
    OffsetVault as SVault,
    NoFlashPool as SPool,
    CollateralizedLender as SLender,
    GuardedGovernor as SGov
} from "./Controls.sol";

/// Deploys one vulnerable + one safe instance of every control pair and funds the
/// actors the fuzzers will impersonate. Deterministic: same anvil state, same
/// deployment transaction order, same addresses on every boot.
///
/// Funding uses `vm.store` because the shared coin contract has no public mint and
/// the fuzzers must be able to move real balances.
interface Vm {
    function store(address target, bytes32 slot, bytes32 value) external;
    function prank(address caller) external;
    function deal(address who, uint256 amount) external;
    function startBroadcast() external;
    function stopBroadcast() external;
}

contract DeployAll {
    Vm private constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    // Deterministic actor set shared by all tools. Keys are anvil defaults (rich
    // accounts #5 and #6).
    address constant ATTACKER = 0x9965507D1a55bcc269514583e49Fdf3b9bD8c1DB;
    address constant VICTIM = 0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB;
    uint256 constant FUND = 1_000_000 ether;

    struct Deployment {
        // vulnerable
        address vMinter;
        address vVault;
        address vAmm;
        address vLender;
        address vGovernor;
        // safe counterparts
        address sMinter;
        address sVault;
        address sAmm;
        address sLender;
        address sGovernor;
        // shared funded coins for pool, lender and vault flows
        address vCoin;
        address sCoin;
    }

    Deployment public d;

    function run() external {
        vm.startBroadcast();
        VCoin vCoin = new VCoin();
        VMinter vMint = new VMinter();
        VVault vVault = new VVault();
        VPool vAmm = new VPool();
        VLender vLender = new VLender();
        VGov vGov = new VGov();

        SCoin sCoin = new SCoin();
        SMinter sMint = new SMinter();
        SVault sVault = new SVault();
        SPool sAmm = new SPool();
        SLender sLender = new SLender();
        SGov sGov = new SGov();

        // Wire dependent contracts. The asset and the two pool reserves live in
        // slot 0/1 storage of the minimal controls (documented in the sources).
        _setSlot(address(vVault), 0, bytes32(uint256(uint160(address(vCoin)))));
        _setSlot(address(sVault), 0, bytes32(uint256(uint160(address(sCoin)))));
        _setSlot(address(vLender), 0, bytes32(uint256(uint160(address(vCoin)))));
        _setSlot(address(sLender), 0, bytes32(uint256(uint160(address(sCoin)))));
        _setSlot(address(vAmm), 0, bytes32(uint256(uint160(address(vCoin)))));
        _setSlot(address(vAmm), 1, bytes32(uint256(uint160(address(vCoin)))));
        _setSlot(address(sAmm), 0, bytes32(uint256(uint160(address(sCoin)))));
        _setSlot(address(sAmm), 1, bytes32(uint256(uint160(address(sCoin)))));

        // Fund: attacker and victim hold balances; contracts hold inventory.
        _fund(address(vCoin), ATTACKER, FUND);
        _fund(address(vCoin), VICTIM, FUND);
        _fund(address(vCoin), address(vAmm), 1_000 ether);
        _fund(address(vCoin), address(vLender), 1_000 ether);
        _fund(address(vMint), ATTACKER, FUND);
        _fund(address(vMint), VICTIM, FUND);

        _fund(address(sCoin), ATTACKER, FUND);
        _fund(address(sCoin), VICTIM, FUND);
        _fund(address(sCoin), address(sAmm), 1_000 ether);
        _fund(address(sCoin), address(sLender), 1_000 ether);
        _fund(address(sMint), ATTACKER, FUND);
        _fund(address(sMint), VICTIM, FUND);

        // Seed reserves, collateral and the borrower role (slots documented in the
        // control sources).
        _setSlot(address(vAmm), 2, bytes32(uint256(1_000 ether)));
        _setSlot(address(vAmm), 3, bytes32(uint256(1_000 ether)));
        _setSlot(address(sAmm), 2, bytes32(uint256(1_000 ether)));
        _setSlot(address(sAmm), 3, bytes32(uint256(1_000 ether)));
        _setSlot(address(vLender), 2, bytes32(uint256(1 ether))); // collateral
        _setSlot(address(sLender), 2, bytes32(uint256(1 ether)));
        // borrower = attacker (slot 3, address-packed)
        _setSlot(address(vLender), 3, bytes32(uint256(uint160(ATTACKER))));
        _setSlot(address(sLender), 3, bytes32(uint256(uint160(ATTACKER))));

        d = Deployment(
            address(vMint),
            address(vVault),
            address(vAmm),
            address(vLender),
            address(vGov),
            address(sMint),
            address(sVault),
            address(sAmm),
            address(sLender),
            address(sGov),
            address(vCoin),
            address(sCoin)
        );
        vm.stopBroadcast();
    }

    function _setSlot(address target, uint256 slot, bytes32 value) internal {
        require(target.code.length > 0, "deploy first");
        vm.store(target, bytes32(slot), value);
    }

    function _fund(address coin, address who, uint256 amount) internal {
        // The holder mapping sits at slot 0 in the minimal coin contract.
        bytes32 slot = keccak256(abi.encode(who, 0));
        vm.store(coin, slot, bytes32(amount));
    }
}
