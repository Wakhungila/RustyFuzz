// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {SpendPermissionTestBase} from "./SpendPermissionTestBase.sol";

contract SpendPermissionForkTest is SpendPermissionTestBase {
    function test_base_deployments_match_expected_code_hashes() public {
        require(trySelectBaseFork(), "BASE_RPC_URL missing; Base fork validation blocked");

        assertEq(block.chainid, 8453);
        assertTrue(BASE_MANAGER.code.length > 0);
        assertTrue(BASE_ROUTER.code.length > 0);
        assertTrue(BASE_VALIDATOR.code.length > 0);
        assertEq(keccak256(BASE_MANAGER.code), MANAGER_RUNTIME_HASH);
        assertEq(keccak256(BASE_ROUTER.code), ROUTER_RUNTIME_HASH);
        assertEq(keccak256(BASE_VALIDATOR.code), VALIDATOR_RUNTIME_HASH);
    }
}
