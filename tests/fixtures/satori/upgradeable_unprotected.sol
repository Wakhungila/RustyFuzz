// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract UnprotectedUpgradeable {
    address public owner;

    function initialize(address newOwner) external {
        owner = newOwner;
    }

    function upgradeTo(address implementation) external {
        require(msg.sender == owner, "owner");
        implementation.delegatecall("");
    }
}
