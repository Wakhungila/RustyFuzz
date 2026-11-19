// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Minimal ETH vault. `withdrawAll` pays the caller but forgets to reduce
/// `totalDeposits`, so the books claim more than the vault holds.
contract Vault {
    mapping(address => uint256) public balanceOf;
    uint256 public totalDeposits;

    function deposit() external payable {
        balanceOf[msg.sender] += msg.value;
        totalDeposits += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balanceOf[msg.sender] >= amount, "insufficient");
        balanceOf[msg.sender] -= amount;
        totalDeposits -= amount;
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "send failed");
    }

    function withdrawAll() external {
        uint256 amount = balanceOf[msg.sender];
        balanceOf[msg.sender] = 0;
        // BUG: totalDeposits is not reduced.
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "send failed");
    }
}
