// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

// Minimal executable mechanisms, not production protocol implementations.
contract BurnOnlyToken {
    mapping(address => uint256) public balanceOf; // slot 0
    mapping(address => mapping(address => uint256)) public allowance; // slot 1
    uint256 public totalSupply; // slot 2
    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount; return true;
    }
    function transfer(address to, uint256 amount) external returns (bool) {
        _transfer(msg.sender, to, amount); return true;
    }
    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(allowance[from][msg.sender] >= amount, "allowance");
        allowance[from][msg.sender] -= amount;
        _transfer(from, to, amount); return true;
    }
    function _transfer(address from, address to, uint256 amount) internal {
        require(balanceOf[from] >= amount, "balance");
        balanceOf[from] -= amount; balanceOf[to] += amount;
    }
    function burn(uint256 amount) external {
        require(balanceOf[msg.sender] >= amount, "balance");
        balanceOf[msg.sender] -= amount; totalSupply -= amount;
    }
}
contract OwnerMintToken is BurnOnlyToken {
    address constant OWNER = 0x1111111111111111111111111111111111111111;
    function mint(address to, uint256 amount) external {
        require(msg.sender == OWNER, "owner");
        balanceOf[to] += amount; totalSupply += amount;
    }
}
contract OffsetVault {
    BurnOnlyToken public asset; // slot 0
    uint256 public totalSupply; // slot 1
    mapping(address => uint256) public balanceOf; // slot 2
    function totalAssets() public view returns (uint256) { return asset.balanceOf(address(this)); }
    function convertToShares(uint256 assets) public view returns (uint256) {
        return assets * (totalSupply + 1_000_000) / (totalAssets() + 1);
    }
    function deposit(uint256 assets, address receiver) external returns (uint256 shares) {
        shares = convertToShares(assets); require(shares > 0, "zero shares");
        require(asset.transferFrom(msg.sender, address(this), assets));
        totalSupply += shares; balanceOf[receiver] += shares;
    }
    function redeem(uint256 shares, address receiver, address owner) external returns (uint256 assets) {
        require(msg.sender == owner && balanceOf[owner] >= shares, "owner/shares");
        assets = shares * (totalAssets() + 1) / (totalSupply + 1_000_000);
        balanceOf[owner] -= shares; totalSupply -= shares;
        require(asset.transfer(receiver, assets));
    }
}
contract NoFlashPool {
    BurnOnlyToken public token0; // slot 0
    BurnOnlyToken public token1; // slot 1
    uint256 public reserve0; // slot 2
    uint256 public reserve1; // slot 3
    function getReserves() external view returns (uint112, uint112, uint32) {
        return (uint112(reserve0), uint112(reserve1), 0);
    }
    function swap(uint256 out0, uint256 out1, address to, bytes calldata data) external {
        require(data.length == 0, "callbacks disabled");
        require(out0 < reserve0 && out1 < reserve1, "reserves");
        if (out0 > 0) require(token0.transfer(to, out0));
        if (out1 > 0) require(token1.transfer(to, out1));
        uint256 b0 = token0.balanceOf(address(this));
        uint256 b1 = token1.balanceOf(address(this));
        require(b0 * b1 >= reserve0 * reserve1, "invariant");
        reserve0 = b0; reserve1 = b1;
    }
    function flashLoan(uint256) external pure { revert("flash loans disabled"); }
}
contract CollateralizedLender {
    BurnOnlyToken public asset; // slot 0
    uint256 public debt; // slot 1
    uint256 public collateral; // slot 2
    address public borrower; // slot 3
    function borrow(uint256 amount) external {
        require(msg.sender == borrower && debt + amount <= collateral * 3 / 4, "collateral");
        debt += amount; require(asset.transfer(msg.sender, amount));
    }
    function repay(address token, uint256 amount, uint256, address onBehalf) external returns (uint256) {
        require(token == address(asset) && onBehalf == borrower && amount <= debt, "repay");
        require(asset.transferFrom(msg.sender, address(this), amount));
        debt -= amount; return amount;
    }
    function liquidationCall(address, address, address user, uint256 amount, bool) external {
        require(user == borrower && debt > collateral * 3 / 4, "healthy");
        require(amount <= debt, "amount");
        require(asset.transferFrom(msg.sender, address(this), amount));
        debt -= amount; collateral -= amount; require(asset.transfer(msg.sender, amount));
    }
}
contract GuardedGovernor {
    address constant PROPOSER = 0x1111111111111111111111111111111111111111;
    address constant VOTER = 0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB;
    uint256 public proposed; // slot 0
    uint256 public votes; // slot 1
    uint256 public eta; // slot 2
    bool public executed; // slot 3
    bool public voted; // slot 3, byte offset 1
    function propose(address[] calldata, uint256[] calldata, string[] calldata, bytes[] calldata, string calldata) external returns (uint256) {
        require(msg.sender == PROPOSER && proposed == 0, "proposer"); proposed = 1; return 1;
    }
    function castVote(uint256 id, uint8 support) external returns (uint256) {
        require(id == proposed && id != 0 && msg.sender == VOTER && !voted && support == 1, "vote");
        voted = true; votes = 2; return votes;
    }
    function queue(uint256 id) external {
        require(id == proposed && id != 0 && votes >= 2 && eta == 0, "quorum");
        eta = block.timestamp + 100;
    }
    function execute(uint256 id) external {
        require(id == proposed && id != 0 && votes >= 2 && eta != 0 && block.timestamp >= eta && !executed, "timelock/quorum");
        executed = true;
    }
}
