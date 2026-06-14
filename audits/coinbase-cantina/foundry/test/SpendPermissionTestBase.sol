// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {SpendPermissionManager} from "spend-permissions/src/SpendPermissionManager.sol";
import {SpendRouter} from "spend-permissions/src/SpendRouter.sol";
import {PublicERC6492Validator} from "spend-permissions/src/PublicERC6492Validator.sol";

contract SpendPermissionTestBase is Test {
    address internal constant BASE_MANAGER = 0xf85210B21cC50302F477BA56686d2019dC9b67Ad;
    address internal constant BASE_ROUTER = 0x1a672dE48c82278b2F1BB68d7b9141634dD6BE29;
    address internal constant BASE_VALIDATOR = 0xcfCE48B757601F3f351CB6f434CB0517aEEE293D;
    bytes32 internal constant MANAGER_RUNTIME_HASH =
        0x2e9e272aa2f685632aae292aaf8bca67f22e4494ec831959bc6e9ff071378bea;
    bytes32 internal constant ROUTER_RUNTIME_HASH =
        0x55cd7a6cb8e76d5404d6678f552f3df3428bea3669ab6748c347f52015bc5ced;
    bytes32 internal constant VALIDATOR_RUNTIME_HASH =
        0x94a000eab18fdda0465241bd0e82487463fb2e539854a3645542e57ed8dde484;
    uint256 internal constant FORK_BLOCK = 47_324_840;

    address internal owner = address(0xA11CE);
    address internal spender = address(0xB0B);
    address internal attacker = address(0xA77A);
    address internal token = address(0x70C0);
    address internal recipient = address(0xCAFE);

    PublicERC6492Validator internal validator;
    SpendPermissionManager internal manager;
    SpendRouter internal router;

    function deployLocal() internal {
        validator = new PublicERC6492Validator();
        manager = new SpendPermissionManager(validator, address(0xF00D));
        router = new SpendRouter(manager);
    }

    function basePermission() internal view returns (SpendPermissionManager.SpendPermission memory permission) {
        permission = SpendPermissionManager.SpendPermission({
            account: owner,
            spender: spender,
            token: token,
            allowance: 100 ether,
            period: 1 days,
            start: 1000,
            end: 1000 + 30 days,
            salt: 1,
            extraData: ""
        });
    }

    function routerPermission() internal view returns (SpendPermissionManager.SpendPermission memory permission) {
        permission = basePermission();
        permission.spender = address(router);
        permission.extraData = router.encodeExtraData(spender, recipient);
    }

    function trySelectBaseFork() internal returns (bool) {
        string memory rpc = vm.envOr("BASE_RPC_URL", string(""));
        if (bytes(rpc).length == 0) return false;
        vm.createSelectFork(rpc, FORK_BLOCK);
        return true;
    }
}
