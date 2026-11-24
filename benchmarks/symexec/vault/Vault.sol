// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;
interface IERC20 { function transferFrom(address,address,uint256) external returns (bool); }
contract Vault {
    mapping(uint256 => uint256) public __bugs;   // slot 0
    mapping(address => uint256) public bal;      // slot 1
    uint256 public total;                        // slot 2
    IERC20 public token;                         // slot 3
    constructor(address t) { token = IERC20(t); }
    function deposit(uint256 a) external {
        require(token.transferFrom(msg.sender, address(this), a), "xfer");
        bal[msg.sender] += a; total += a;
    }
    function withdraw(uint256 a) external {
        require(bal[msg.sender] >= a, "bal");
        bal[msg.sender] -= a; total -= a;
        if (a == 0xdeadbeef && total > 1000) __bugs[1] = 1;
    }
    function poke(uint256 k, uint256 v) external {
        if (bal[address(uint160(k))] == v && v == 777) __bugs[2] = 1;
    }
}
