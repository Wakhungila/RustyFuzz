// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20L {
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
    function transferFrom(address, address, uint256) external returns (bool);
}

interface IPairL {
    function getReserves() external view returns (uint112, uint112, uint32);
}

/// DELIBERATELY VULNERABLE: prices collateral from a spot AMM reserve ratio, so
/// a flash-loan-sized swap inflates the price within one transaction.
contract SpotOracleLender {
    IERC20L public collateral; // token0 of the pair
    IERC20L public debt;       // token1 of the pair
    IPairL public pair;

    constructor(address c, address d, address p) {
        collateral = IERC20L(c); debt = IERC20L(d); pair = IPairL(p);
    }

    function price() public view returns (uint256) {
        (uint112 r0, uint112 r1,) = pair.getReserves();
        return uint256(r1) * 1e18 / uint256(r0);
    }

    /// Deposit collateral and borrow up to 75% of its spot value, no repayment path.
    function borrow(uint256 collateralAmount) external {
        collateral.transferFrom(msg.sender, address(this), collateralAmount);
        uint256 amount = collateralAmount * price() / 1e18 * 75 / 100;
        uint256 cash = debt.balanceOf(address(this));
        debt.transfer(msg.sender, amount > cash ? cash : amount);
    }
}

/// Same lender with a fixed oracle: the negative control.
contract FixedOracleLender {
    IERC20L public collateral;
    IERC20L public debt;
    uint256 public immutable fixedPrice;

    constructor(address c, address d, uint256 p) {
        collateral = IERC20L(c); debt = IERC20L(d); fixedPrice = p;
    }

    function borrow(uint256 collateralAmount) external {
        collateral.transferFrom(msg.sender, address(this), collateralAmount);
        uint256 amount = collateralAmount * fixedPrice / 1e18 * 75 / 100;
        uint256 cash = debt.balanceOf(address(this));
        debt.transfer(msg.sender, amount > cash ? cash : amount);
    }
}
