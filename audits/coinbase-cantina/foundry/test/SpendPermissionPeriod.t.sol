// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {SpendPermissionManager} from "spend-permissions/src/SpendPermissionManager.sol";
import {SpendPermissionTestBase} from "./SpendPermissionTestBase.sol";

contract SpendPermissionPeriodTest is SpendPermissionTestBase {
    function setUp() public {
        deployLocal();
    }

    function test_current_period_includes_start_and_excludes_end() public {
        SpendPermissionManager.SpendPermission memory permission = basePermission();

        vm.warp(permission.start);
        SpendPermissionManager.PeriodSpend memory atStart = manager.getCurrentPeriod(permission);
        assertEq(atStart.start, permission.start);
        assertEq(atStart.end, permission.start + permission.period);
        assertEq(atStart.spend, 0);

        vm.warp(permission.end);
        vm.expectRevert(
            abi.encodeWithSelector(SpendPermissionManager.AfterSpendPermissionEnd.selector, uint48(permission.end), permission.end)
        );
        manager.getCurrentPeriod(permission);
    }

    function test_period_rollover_boundaries_are_exact() public {
        SpendPermissionManager.SpendPermission memory permission = basePermission();

        vm.warp(permission.start + permission.period - 1);
        SpendPermissionManager.PeriodSpend memory before = manager.getCurrentPeriod(permission);
        assertEq(before.start, permission.start);
        assertEq(before.end, permission.start + permission.period);

        vm.warp(permission.start + permission.period);
        SpendPermissionManager.PeriodSpend memory afterRollover = manager.getCurrentPeriod(permission);
        assertEq(afterRollover.start, permission.start + permission.period);
        assertEq(afterRollover.end, permission.start + 2 * permission.period);
    }

    function test_before_start_reverts() public {
        SpendPermissionManager.SpendPermission memory permission = basePermission();
        vm.warp(permission.start - 1);
        vm.expectRevert(
            abi.encodeWithSelector(
                SpendPermissionManager.BeforeSpendPermissionStart.selector, uint48(permission.start - 1), permission.start
            )
        );
        manager.getCurrentPeriod(permission);
    }
}
