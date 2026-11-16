// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

// Deliberately vulnerable counterparts for the known_vulnerable benchmark pack.
// Compiled only by known_vulnerable/build_fixtures.py; never add these
// contracts to the negative controls pack.

// ---------------------------------------------------------------------------
// known-erc20-bad-mint-inflation
// Mirror of the gate2 OwnerMintToken witness: the minter authorization check
// is removed, so any caller can mint itself new supply (slots 0/1/2 identical
// to the negative pack's token layout: balances, allowance, totalSupply).
// ---------------------------------------------------------------------------
contract UnauthMintToken {
    mapping(address => uint256) public balanceOf; // slot 0
    mapping(address => mapping(address => uint256)) public allowance; // slot 1
    uint256 public totalSupply; // slot 2
    address constant OWNER = 0x1111111111111111111111111111111111111111;

    function canMint(address caller) external pure returns (bool) {
        return caller == OWNER;
    }

    function mint(address to, uint256 amount) external {
        // Deliberate defect: owner authorization removed.
        balanceOf[to] += amount;
        totalSupply += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

// ---------------------------------------------------------------------------
// known-flashloan-price-manipulation
// Mirror of the gate2 NoFlashPool witness: the reserve-product check is
// removed, so a swap can extract reserves without paying anything in.
// ---------------------------------------------------------------------------
interface MinimalToken {
    function balanceOf(address who) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
}

contract NoProductCheckPool {
    MinimalToken public token0; // slot 0
    MinimalToken public token1; // slot 1
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
        // Deliberate defect: reserve-product check removed.
        reserve0 = b0;
        reserve1 = b1;
    }

    function flashLoan(uint256) external pure {
        revert("flash loans disabled");
    }
}

// ---------------------------------------------------------------------------
// known-read-only-reentrancy
// A hook-carrying token, a vault whose withdraw() performs the interaction
// before the accounting effect, and an attacker contract whose ERC777-style
// callback reads the stale pre-callback balance via the vault's view and
// mints that stale value as unbacked profit.
// ---------------------------------------------------------------------------
interface VaultToken {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
}

contract HookToken {
    mapping(address => uint256) public balanceOf; // slot 0
    mapping(address => mapping(address => uint256)) public allowance; // slot 1
    uint256 public totalSupply; // slot 2

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        _transfer(msg.sender, to, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(allowance[from][msg.sender] >= amount, "allowance");
        allowance[from][msg.sender] -= amount;
        _transfer(from, to, amount);
        return true;
    }

    function _transfer(address from, address to, uint256 amount) internal {
        require(balanceOf[from] >= amount, "balance");
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        if (to.code.length > 0) {
            // ERC777-style hook is optional for the recipient: a contract that
            // does not implement onReceive (like the vault itself, which is a
            // plain transfer destination) skips the hook instead of reverting.
            (bool hookAccepted, ) = to.call(
                abi.encodeWithSignature("onReceive(address,address,uint256)", from, to, amount)
            );
            hookAccepted; // a skipped hook is not a failed transfer
        }
    }
}

contract ReentrantVault {
    VaultToken constant TOKEN = VaultToken(0x7000000000000000000000000000000000000003);
    mapping(address => uint256) public balances; // slot 0
    bool public withdrawing; // slot 1

    function deposit(uint256 amount) external {
        require(TOKEN.transferFrom(msg.sender, address(this), amount), "transferFrom");
        balances[msg.sender] += amount;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "balance");
        withdrawing = true;
        // Deliberate defect: interaction before effect. During the token
        // transfer's callback, balanceOf() still reports the pre-decrement
        // balance — the read-only reentrancy window.
        require(TOKEN.transfer(msg.sender, amount), "transfer");
        balances[msg.sender] -= amount;
        withdrawing = false;
    }

    function mintProfit(uint256 amount) external {
        require(withdrawing, "not withdrawing");
        // Credited from the stale view read inside the callback; the vault's
        // token holdings never back this credit.
        balances[msg.sender] += amount;
    }

    function balanceOf(address who) external view returns (uint256) {
        return balances[who];
    }
}

contract ReentrantAttacker {
    address constant VAULT = 0x6200000000000000000000000000000000000003;
    address constant TOKEN = 0x7000000000000000000000000000000000000003;

    // Entry points driven by the attacker EOA (transactions cannot originate
    // from a code account); the vault sees this contract as the depositor, so
    // the withdraw transfer fires this contract's hook.
    function enterDeposit(uint256 amount) external {
        (bool approved, ) = TOKEN.call(
            abi.encodeWithSignature("approve(address,uint256)", VAULT, amount)
        );
        require(approved, "approve");
        (bool deposited, ) = VAULT.call(
            abi.encodeWithSignature("deposit(uint256)", amount)
        );
        require(deposited, "deposit");
    }

    function enterWithdraw(uint256 amount) external {
        (bool withdrawn, ) = VAULT.call(
            abi.encodeWithSignature("withdraw(uint256)", amount)
        );
        require(withdrawn, "withdraw");
    }

    function onReceive(address, address, uint256) external {
        if (msg.sender != TOKEN) return;
        // Read the pool balance through the view while the withdraw is still
        // in flight: the reported value predates the accounting update.
        (bool ok, bytes memory ret) =
            VAULT.call(abi.encodeWithSignature("balanceOf(address)", address(this)));
        if (!ok || ret.length < 32) return;
        uint256 stale = abi.decode(ret, (uint256));
        // Mint the stale value as profit; reentrancy makes the credit unbacked.
        VAULT.call(abi.encodeWithSignature("mintProfit(uint256)", stale));
    }
}

// ---------------------------------------------------------------------------
// known-uninitialized-proxy-takeover
// A minimal proxy-shaped contract whose EIP-1967 implementation slot was
// never set and whose initializer is externally callable and unguarded: the
// first caller becomes owner and can point the implementation slot anywhere.
// ---------------------------------------------------------------------------
contract UninitializedProxy {
    address public owner; // slot 0
    bytes32 constant IMPLEMENTATION_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    function initialize(address _owner) external {
        // Deliberate defect: no initializer guard, so anyone can claim ownership.
        owner = _owner;
    }

    function upgradeTo(address newImplementation) external {
        require(msg.sender == owner, "UNAUTHORIZED");
        assembly {
            sstore(IMPLEMENTATION_SLOT, newImplementation)
        }
    }

    function implementation() external view returns (address impl) {
        assembly {
            impl := sload(IMPLEMENTATION_SLOT)
        }
    }
}

// ---------------------------------------------------------------------------
// known-bridge-nonce-replay
// A minimal bridge inbox: finalize() pays out a fixed release per message
// hash but never records the processed flag, so the same message hash can be
// finalized again and again (processed() stays false after a payout).
// ---------------------------------------------------------------------------
contract ReplayBridge {
    VaultToken constant TOKEN = VaultToken(0x7000000000000000000000000000000000000005);
    mapping(bytes32 => uint256) public released; // slot 0
    mapping(bytes32 => bool) public processed; // slot 1

    function finalize(bytes32 messageHash) external {
        require(!processed[messageHash], "already finalized");
        require(TOKEN.transfer(msg.sender, 1 ether), "transfer");
        released[messageHash] += 1 ether;
        // Deliberate defect: processed[messageHash] is never set, so the gate
        // above can never fire and the same hash finalizes repeatedly.
    }

    function claim(bytes32 messageHash) external {
        this.finalize(messageHash);
    }
}
