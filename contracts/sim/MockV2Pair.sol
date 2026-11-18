// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20V2 {
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
}

interface IUniswapV2Callee {
    function uniswapV2Call(address sender, uint256 amount0, uint256 amount1, bytes calldata data) external;
}

/// Uniswap V2 pair semantics: constant product with a 0.3% fee enforced by the
/// post-swap invariant, flash swaps via callback, reentrancy lock. Pairs are
/// seeded by crediting token balances and calling `sync()`.
contract MockV2Pair {
    address public token0;
    address public token1;
    uint112 private reserve0;
    uint112 private reserve1;
    uint32 private blockTimestampLast;
    // Zero means unlocked: these contracts are installed as runtime code, so a
    // constructor-style `= 1` initialiser would never run.
    uint256 private locked;

    modifier lock() {
        require(locked == 0, "LOCKED");
        locked = 1;
        _;
        locked = 0;
    }

    function initialize(address a, address b) external {
        require(token0 == address(0), "INITIALIZED");
        token0 = a;
        token1 = b;
    }

    function getReserves() public view returns (uint112, uint112, uint32) {
        return (reserve0, reserve1, blockTimestampLast);
    }

    function sync() external lock {
        _update(IERC20V2(token0).balanceOf(address(this)), IERC20V2(token1).balanceOf(address(this)));
    }

    function _update(uint256 b0, uint256 b1) private {
        require(b0 <= type(uint112).max && b1 <= type(uint112).max, "OVERFLOW");
        reserve0 = uint112(b0);
        reserve1 = uint112(b1);
        blockTimestampLast = uint32(block.timestamp);
    }

    function swap(uint256 amount0Out, uint256 amount1Out, address to, bytes calldata data) external lock {
        require(amount0Out > 0 || amount1Out > 0, "INSUFFICIENT_OUTPUT_AMOUNT");
        (uint112 r0, uint112 r1,) = getReserves();
        require(amount0Out < r0 && amount1Out < r1, "INSUFFICIENT_LIQUIDITY");
        require(to != token0 && to != token1, "INVALID_TO");
        if (amount0Out > 0) IERC20V2(token0).transfer(to, amount0Out);
        if (amount1Out > 0) IERC20V2(token1).transfer(to, amount1Out);
        if (data.length > 0) IUniswapV2Callee(to).uniswapV2Call(msg.sender, amount0Out, amount1Out, data);
        uint256 b0 = IERC20V2(token0).balanceOf(address(this));
        uint256 b1 = IERC20V2(token1).balanceOf(address(this));
        uint256 in0 = b0 > r0 - amount0Out ? b0 - (r0 - amount0Out) : 0;
        uint256 in1 = b1 > r1 - amount1Out ? b1 - (r1 - amount1Out) : 0;
        require(in0 > 0 || in1 > 0, "INSUFFICIENT_INPUT_AMOUNT");
        uint256 adj0 = b0 * 1000 - in0 * 3;
        uint256 adj1 = b1 * 1000 - in1 * 3;
        require(adj0 * adj1 >= uint256(r0) * uint256(r1) * 1_000_000, "K");
        _update(b0, b1);
    }
}
