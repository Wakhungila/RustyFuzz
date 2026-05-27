// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract OracleLending {
    IFeed public feed;
    mapping(address => uint256) public debt;
    mapping(address => uint256) public collateral;

    function borrow(uint256 amount) external {
        (, int256 answer,,,) = feed.latestRoundData();
        require(uint256(answer) * collateral[msg.sender] > amount, "health");
        debt[msg.sender] += amount;
    }
}

interface IFeed {
    function latestRoundData() external view returns (
        uint80 roundId,
        int256 answer,
        uint256 startedAt,
        uint256 updatedAt,
        uint80 answeredInRound
    );
}
