// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract NaiveVault {
    IERC20 public asset;
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;

    function totalAssets() public view returns (uint256) {
        return asset.balanceOf(address(this));
    }

    function deposit(uint256 assets) external returns (uint256 shares) {
        shares = assets * totalSupply / totalAssets();
        asset.transferFrom(msg.sender, address(this), assets);
        balanceOf[msg.sender] += shares;
        totalSupply += shares;
    }
}

interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}
