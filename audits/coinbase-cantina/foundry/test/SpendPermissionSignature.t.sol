// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {SpendPermissionManager} from "spend-permissions/src/SpendPermissionManager.sol";
import {SpendPermissionTestBase} from "./SpendPermissionTestBase.sol";

contract SpendPermissionSignatureTest is SpendPermissionTestBase {
    function setUp() public {
        deployLocal();
    }

    function test_permission_hash_separates_account_spender_token_and_extra_data() public {
        SpendPermissionManager.SpendPermission memory permission = basePermission();
        bytes32 original = manager.getHash(permission);

        permission.account = address(0x1234);
        assertNotEq(original, manager.getHash(permission));
        permission = basePermission();
        permission.spender = address(0x5678);
        assertNotEq(original, manager.getHash(permission));
        permission = basePermission();
        permission.token = address(0x9ABC);
        assertNotEq(original, manager.getHash(permission));
        permission = basePermission();
        permission.extraData = abi.encode(address(0x1111), address(0x2222));
        assertNotEq(original, manager.getHash(permission));
    }

    function test_eip712_domain_separates_chain_and_verifying_contract() public {
        SpendPermissionManager.SpendPermission memory permission = basePermission();
        bytes32 onFirstManager = manager.getHash(permission);

        SpendPermissionManager second = new SpendPermissionManager(validator, address(0xF00D));
        assertNotEq(onFirstManager, second.getHash(permission));

        vm.chainId(8454);
        assertNotEq(onFirstManager, manager.getHash(permission));
    }
}
