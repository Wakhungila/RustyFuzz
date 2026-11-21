// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20V3 {
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
}

interface IUniswapV3SwapCallback {
    function uniswapV3SwapCallback(int256 amount0Delta, int256 amount1Delta, bytes calldata data) external;
}

/// Uniswap V3 pool restricted to ONE liquidity range [sqrtLower, sqrtUpper]:
/// exact-input swaps use V3's real in-range step math (Q64.96 sqrt price,
/// liquidity L, fee in pips) with the swap callback. A swap that would leave the
/// range fills up to the boundary and returns the unfilled remainder, as V3
/// does when no liquidity is left. Exact-output swaps and tick crossing are not
/// modelled. `slot0()` returns the sqrt price first, as consumers read it.
contract MockV3Pool {
    uint256 internal constant Q96 = 1 << 96;

    address public token0;
    address public token1;
    uint24 public fee;
    uint160 public sqrtPriceX96;
    uint160 public sqrtLower;
    uint160 public sqrtUpper;
    uint128 public liquidity;
    // Zero means unlocked: these contracts are installed as runtime code, so a
    // constructor-style `= 1` initialiser would never run.
    uint256 private locked;

    modifier lock() {
        require(locked == 0, "LOK");
        locked = 1;
        _;
        locked = 0;
    }

    function initialize(address a, address b, uint24 feePips, uint160 price, uint160 lower, uint160 upper, uint128 l) external {
        require(token0 == address(0), "AI");
        require(lower < price && price < upper, "RANGE");
        token0 = a; token1 = b; fee = feePips;
        sqrtPriceX96 = price; sqrtLower = lower; sqrtUpper = upper; liquidity = l;
    }

    function slot0() external view returns (uint160, int24, uint16, uint16, uint16, uint8, bool) {
        return (sqrtPriceX96, 0, 0, 0, 0, 0, true);
    }

    function swap(address recipient, bool zeroForOne, int256 amountSpecified, uint160 sqrtPriceLimitX96, bytes calldata data)
        external
        lock
        returns (int256 amount0, int256 amount1)
    {
        require(amountSpecified > 0, "EXACT_IN_ONLY");
        uint256 amountIn = uint256(amountSpecified);
        uint160 p = sqrtPriceX96;
        uint256 L = liquidity;
        uint256 inLessFee = mulDiv(amountIn, 1_000_000 - fee, 1_000_000);
        uint160 target = zeroForOne
            ? (sqrtPriceLimitX96 > sqrtLower ? sqrtPriceLimitX96 : sqrtLower)
            : (sqrtPriceLimitX96 < sqrtUpper && sqrtPriceLimitX96 != 0 ? sqrtPriceLimitX96 : sqrtUpper);
        require(zeroForOne ? target < p : target > p, "SPL");

        uint256 newP;
        uint256 consumed; // gross input actually used
        uint256 out;
        if (zeroForOne) {
            // token0 in, price falls: P' = L*Q96*P / (L*Q96 + in*P)
            newP = mulDiv(L << 96, p, (L << 96) + inLessFee * p);
            if (newP < target) {
                newP = target;
                uint256 needNet = mulDivUp(mulDivUp(L << 96, p - newP, newP), 1, p);
                consumed = mulDivUp(needNet, 1_000_000, 1_000_000 - fee);
            } else {
                consumed = amountIn;
            }
            out = mulDiv(L, p - newP, Q96); // token1 out
        } else {
            // token1 in, price rises: P' = P + in*Q96/L
            newP = p + mulDiv(inLessFee, Q96, L);
            if (newP > target) {
                newP = target;
                uint256 needNet = mulDivUp(L, newP - p, Q96);
                consumed = mulDivUp(needNet, 1_000_000, 1_000_000 - fee);
            } else {
                consumed = amountIn;
            }
            out = mulDiv(mulDiv(L << 96, newP - p, newP), 1, p); // token0 out
        }
        sqrtPriceX96 = uint160(newP);

        if (zeroForOne) {
            amount0 = int256(consumed);
            amount1 = -int256(out);
            IERC20V3(token1).transfer(recipient, out);
            uint256 before0 = IERC20V3(token0).balanceOf(address(this));
            IUniswapV3SwapCallback(msg.sender).uniswapV3SwapCallback(amount0, amount1, data);
            require(IERC20V3(token0).balanceOf(address(this)) >= before0 + consumed, "IIA");
        } else {
            amount1 = int256(consumed);
            amount0 = -int256(out);
            IERC20V3(token0).transfer(recipient, out);
            uint256 before1 = IERC20V3(token1).balanceOf(address(this));
            IUniswapV3SwapCallback(msg.sender).uniswapV3SwapCallback(amount0, amount1, data);
            require(IERC20V3(token1).balanceOf(address(this)) >= before1 + consumed, "IIA");
        }
    }

    function mulDivUp(uint256 a, uint256 b, uint256 d) internal pure returns (uint256 r) {
        r = mulDiv(a, b, d);
        if (mulmod(a, b, d) > 0) r += 1;
    }

    /// Full-precision a*b/d (512-bit intermediate), as in Uniswap's FullMath.
    function mulDiv(uint256 a, uint256 b, uint256 d) internal pure returns (uint256 result) {
        unchecked {
            uint256 prod0;
            uint256 prod1;
            assembly {
                let mm := mulmod(a, b, not(0))
                prod0 := mul(a, b)
                prod1 := sub(sub(mm, prod0), lt(mm, prod0))
            }
            if (prod1 == 0) {
                require(d > 0, "DIV0");
                return prod0 / d;
            }
            require(d > prod1, "OVERFLOW");
            uint256 remainder;
            assembly {
                remainder := mulmod(a, b, d)
                prod1 := sub(prod1, gt(remainder, prod0))
                prod0 := sub(prod0, remainder)
            }
            uint256 twos = d & (~d + 1);
            assembly {
                d := div(d, twos)
                prod0 := div(prod0, twos)
                twos := add(div(sub(0, twos), twos), 1)
            }
            prod0 |= prod1 * twos;
            uint256 inv = (3 * d) ^ 2;
            inv *= 2 - d * inv;
            inv *= 2 - d * inv;
            inv *= 2 - d * inv;
            inv *= 2 - d * inv;
            inv *= 2 - d * inv;
            inv *= 2 - d * inv;
            result = prod0 * inv;
        }
    }
}
