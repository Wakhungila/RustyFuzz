// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract OffsetVault {
    uint8 internal constant _decimalsOffset = 6;
    uint256 internal constant VIRTUAL_ASSETS = 1e6;
    uint256 internal constant VIRTUAL_SHARES = 1e6;

    function totalAssets() public view returns (uint256) {
        return VIRTUAL_ASSETS + address(this).balance;
    }

    function convertToShares(uint256 assets) public pure returns (uint256) {
        return assets * VIRTUAL_SHARES / VIRTUAL_ASSETS;
    }
}
