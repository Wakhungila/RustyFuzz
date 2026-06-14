// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {SpendPermissionManager} from "spend-permissions/src/SpendPermissionManager.sol";
import {SpendPermissionTestBase} from "./SpendPermissionTestBase.sol";

contract SpendPermissionInvariantTest is SpendPermissionTestBase {
    function setUp() public {
        deployLocal();
    }

    function test_multiple_partial_spends_are_capped_by_period_allowance_before_transfer() public {
        SpendPermissionManager.SpendPermission memory permission = basePermission();
        vm.prank(owner);
        assertTrue(manager.approve(permission));

        vm.warp(permission.start);
        vm.prank(spender);
        vm.expectRevert();
        manager.spend(permission, permission.allowance + 1);

        SpendPermissionManager.PeriodSpend memory period = manager.getLastUpdatedPeriod(permission);
        assertEq(period.spend, 0);
    }

    function test_revoked_permission_is_not_valid() public {
        SpendPermissionManager.SpendPermission memory permission = basePermission();
        vm.prank(owner);
        assertTrue(manager.approve(permission));
        vm.prank(owner);
        manager.revoke(permission);
        assertFalse(manager.isValid(permission));
    }
}
