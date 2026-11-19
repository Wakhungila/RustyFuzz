// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {Vault} from "../src/Vault.sol";

contract VaultInvariantTest is Test {
    Vault vault;
    address alice;

    function setUp() public {
        vault = new Vault();
        alice = makeAddr("alice");
        vm.deal(alice, 100 ether);
        vm.prank(alice);
        vault.deposit{value: 10 ether}();
    }

    /// The books must never claim more than the vault holds.
    function invariant_solvent() public view {
        assertGe(address(vault).balance, vault.totalDeposits());
    }
}
