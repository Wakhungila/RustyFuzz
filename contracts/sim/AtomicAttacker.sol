// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
}

interface IPoolTokens {
    function token0() external view returns (address);
    function token1() external view returns (address);
}

/// Atomic flash-loan attacker. One transaction: snapshot balances of the
/// borrowed tokens, execute an arbitrary call list, then require that every
/// borrowed token is returned with `feeBps` on the opening balance AND that at
/// least one token ended strictly above that line. Otherwise the whole
/// transaction reverts, so a successful `run` is itself proof of profit.
///
/// The borrowed amount is whatever the harness credited as a *virtual* balance
/// before the transaction (see sim_defi::credit_erc20); no lender contract is
/// involved, the end-of-transaction check plays the lender's repayment role.
contract AtomicAttacker {
    struct Call {
        address target;
        uint256 value;
        bytes data;
        bool optional; // a failing optional call is skipped instead of reverting
    }

    event Profit(address indexed token, uint256 opening, uint256 closing, uint256 fee);

    error NoProfit(address token, uint256 opening, uint256 closing, uint256 required);
    error CallFailed(uint256 index, bytes reason);

    receive() external payable {}

    function _bal(address token) internal view returns (uint256) {
        return token == address(0) ? address(this).balance : IERC20(token).balanceOf(address(this));
    }

    function run(address[] calldata tokens, uint256 feeBps, Call[] calldata calls) external {
        uint256 n = tokens.length;
        uint256[] memory opening = new uint256[](n);
        for (uint256 i; i < n; ++i) opening[i] = _bal(tokens[i]);

        for (uint256 i; i < calls.length; ++i) {
            Call calldata c = calls[i];
            (bool ok, bytes memory ret) = c.target.call{value: c.value}(c.data);
            if (!ok && !c.optional) revert CallFailed(i, ret);
        }

        bool profited;
        for (uint256 i; i < n; ++i) {
            uint256 fee = (opening[i] * feeBps) / 10_000;
            uint256 closing = _bal(tokens[i]);
            if (closing < opening[i] + fee) {
                revert NoProfit(tokens[i], opening[i], closing, opening[i] + fee);
            }
            if (closing > opening[i] + fee) {
                profited = true;
                emit Profit(tokens[i], opening[i], closing, fee);
            }
        }
        if (!profited) revert NoProfit(address(0), 0, 0, 1);
    }

    /// Runs a call list with no repayment or profit gate. Used by harness code
    /// and tests to drive pools directly; the fuzzer's profit oracle only
    /// counts `run`.
    function exec(Call[] calldata calls) external {
        for (uint256 i; i < calls.length; ++i) {
            Call calldata c = calls[i];
            (bool ok, bytes memory ret) = c.target.call{value: c.value}(c.data);
            if (!ok && !c.optional) revert CallFailed(i, ret);
        }
    }

    /// Uniswap V2 flash-swap callback: the call list is expected to repay the
    /// pair itself, so accepting the callback is enough.
    function uniswapV2Call(address, uint256, uint256, bytes calldata) external {}

    /// Uniswap V3 swap callback: pay whatever the pool is owed.
    function uniswapV3SwapCallback(int256 amount0Delta, int256 amount1Delta, bytes calldata) external {
        if (amount0Delta > 0) IERC20(IPoolTokens(msg.sender).token0()).transfer(msg.sender, uint256(amount0Delta));
        if (amount1Delta > 0) IERC20(IPoolTokens(msg.sender).token1()).transfer(msg.sender, uint256(amount1Delta));
    }
}
