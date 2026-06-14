// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {SpendPermissionManager} from "spend-permissions/src/SpendPermissionManager.sol";
import {SpendRouter} from "spend-permissions/src/SpendRouter.sol";
import {SpendPermissionTestBase} from "./SpendPermissionTestBase.sol";

contract SpendRouterTest is SpendPermissionTestBase {
    function setUp() public {
        deployLocal();
    }

    function test_extra_data_round_trip_and_zero_rejection() public {
        bytes memory extraData = router.encodeExtraData(spender, recipient);
        (address decodedExecutor, address decodedRecipient) = router.decodeExtraData(extraData);
        assertEq(decodedExecutor, spender);
        assertEq(decodedRecipient, recipient);

        vm.expectRevert(SpendRouter.ZeroAddress.selector);
        router.encodeExtraData(address(0), recipient);
        vm.expectRevert(SpendRouter.ZeroAddress.selector);
        router.encodeExtraData(spender, address(0));
    }

    function test_decode_rejects_malformed_extra_data() public {
        vm.expectRevert();
        router.decodeExtraData(hex"1234");
    }

    function test_router_revoke_requires_executor_from_extra_data() public {
        SpendPermissionManager.SpendPermission memory permission = routerPermission();
        vm.prank(attacker);
        vm.expectRevert(abi.encodeWithSelector(SpendRouter.UnauthorizedSender.selector, attacker, spender));
        router.revokeAsSpender(permission);
    }
}
