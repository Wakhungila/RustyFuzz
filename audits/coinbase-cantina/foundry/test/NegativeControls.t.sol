// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {SpendPermissionManager} from "spend-permissions/src/SpendPermissionManager.sol";
import {SpendPermissionTestBase} from "./SpendPermissionTestBase.sol";

contract NegativeControlsTest is SpendPermissionTestBase {
    function setUp() public {
        deployLocal();
    }

    function test_unauthorized_direct_approval_reverts() public {
        SpendPermissionManager.SpendPermission memory permission = basePermission();
        vm.prank(attacker);
        vm.expectRevert(abi.encodeWithSelector(SpendPermissionManager.InvalidSender.selector, attacker, owner));
        manager.approve(permission);
    }

    function test_invalid_permission_parameters_reject_approval() public {
        SpendPermissionManager.SpendPermission memory permission = basePermission();
        vm.prank(owner);
        permission.token = address(0);
        vm.expectRevert(SpendPermissionManager.ZeroToken.selector);
        manager.approve(permission);

        permission = basePermission();
        permission.spender = address(0);
        vm.prank(owner);
        vm.expectRevert(SpendPermissionManager.ZeroSpender.selector);
        manager.approve(permission);

        permission = basePermission();
        permission.allowance = 0;
        vm.prank(owner);
        vm.expectRevert(SpendPermissionManager.ZeroAllowance.selector);
        manager.approve(permission);

        permission = basePermission();
        permission.period = 0;
        vm.prank(owner);
        vm.expectRevert(SpendPermissionManager.ZeroPeriod.selector);
        manager.approve(permission);

        permission = basePermission();
        permission.end = permission.start;
        vm.prank(owner);
        vm.expectRevert(
            abi.encodeWithSelector(SpendPermissionManager.InvalidStartEnd.selector, permission.start, permission.end)
        );
        manager.approve(permission);
    }
}
