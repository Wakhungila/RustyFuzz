#!/usr/bin/env python3
"""Rebuild checked-in executable controls using solc 0.8.30 and Foundry cast (offline)."""
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
PACK = ROOT / 'benchmarks/historical/negative_controls'
SOURCE = PACK / 'contracts/Controls.sol'

def run(*args):
    return subprocess.check_output(args, cwd=ROOT, text=True).strip()

assert '0.8.30+' in run('solc', '--version'), 'solc 0.8.30 required'
compiled = json.loads(run('solc', '--optimize', '--evm-version', 'shanghai', '--combined-json',
                          'bin-runtime,storage-layout', str(SOURCE.relative_to(ROOT))))['contracts']
code = {key.rsplit(':', 1)[1]: '0x' + value['bin-runtime'] for key, value in compiled.items()}
A = '0x' + 'aa' * 20
V = '0x' + 'bb' * 20
O = '0x' + '11' * 20
T0 = '0x7000000000000000000000000000000000000001'
T1 = '0x7000000000000000000000000000000000000002'
E = 10**18

def storage(values):
    return [{'slot': hex(int(k, 0) if isinstance(k, str) else k),
             'value': hex(int(v, 0) if isinstance(v, str) else v)} for k, v in values.items()]

def account(address, contract=None, slots=None):
    return dict(address=address, balance=hex(10**24 if contract is None else 0), nonce=0,
                runtime_bytecode=code[contract] if contract else '0x', storage=storage(slots or {}))

def index(address, slot):
    return run('cast', 'index', 'address', address, str(slot))

def token(address, balances):
    return account(address, 'OwnerMintToken', {**{index(a, 0): n for a, n in balances.items()},
                                             2: sum(balances.values())})

def out(*words):
    return '0x' + ''.join(int(w).to_bytes(32, 'big').hex() for w in words)

def tx(to, sig, *args, caller=A, timestamp=1000, status='Success', output=None, slots=None):
    return dict(caller=caller, to=to, calldata=run('cast', 'calldata', sig, *map(str, args)),
                value='0x0', timestamp=timestamp, expected_status=status,
                expected_output=output, expected_storage=storage(slots or {}))

def write(name, target, accounts, transactions, behavior):
    fixture = dict(schema_version=1, bytecode_kind='runtime', target=target, attacker=A, victim=V,
                   environment=dict(chain_id=1, block_number=1, timestamp=1000,
                                    gas_limit=30_000_000, base_fee=0),
                   accounts=[account(A), account(V), account(O), *accounts], transactions=transactions,
                   expected_safe_behavior=behavior)
    (PACK / 'fixtures' / (name + '.json')).write_text(json.dumps(fixture, indent=2) + '\n')
    p = PACK / (name + '.toml')
    text = p.read_text()
    text = text.replace('mode = "local_fixture"', 'mode = "executable_evm"')
    p.write_text(text)
    print(name, 'transactions=', len(transactions), 'code_accounts=', len(accounts))

p = '0x6200000000000000000000000000000000000101'
write('erc20-owner-mint', p, [account(p, 'OwnerMintToken')], [
    tx(p, 'canMint(address)', O, output=out(1)),
    tx(p, 'mint(address,uint256)', V, 100*E, caller=O, slots={2: 100*E}),
    tx(p, 'canMint(address)', A, output=out(0)),
    tx(p, 'mint(address,uint256)', A, E, status='Revert', slots={2: 100*E}),
    tx(p, 'balanceOf(address)', V, output=out(100*E)),
    tx(p, 'balanceOf(address)', A, output=out(0)),
], 'Only OWNER can mint; unauthorized mint reverts; victim receives 100 tokens and attacker receives zero.')
p = '0x6200000000000000000000000000000000000102'
write('erc20-burn-only', p, [account(p, 'BurnOnlyToken', {index(A, 0): 100*E, 2: 100*E})], [
    tx(p, 'burn(uint256)', 10*E, slots={2: 90*E}),
    tx(p, 'mint(address,uint256)', A, E, status='Revert', slots={2: 90*E}),
    tx(p, 'balanceOf(address)', A, output=out(90*E)),
], 'Burn reduces caller balance and total supply equally; no mint entry point exists.')
for suffix, attack in [('zero-donation', False), ('virtual-offset', True)]:
    p = '0x620000000000000000000000000000000000020' + ('2' if attack else '1')
    amount = 1 if attack else 1000
    donation = 1000 if attack else 0
    victim_shares = 1000 * (amount * 1_000_000 + 1_000_000) // (amount + donation + 1)
    transactions = [
        tx(T0, 'approve(address,uint256)', p, 1_000_000, output=out(1)),
        tx(p, 'deposit(uint256,address)', amount, A, output=out(amount*1_000_000)),
        tx(T0, 'transfer(address,uint256)', p, donation, output=out(1)),
        tx(T0, 'approve(address,uint256)', p, 1_000_000, caller=V, output=out(1)),
        tx(p, 'deposit(uint256,address)', 1000, V, caller=V, output=out(victim_shares)),
        tx(p, 'balanceOf(address)', V, caller=V, output=out(victim_shares)),
    ]
    if attack:
        redeemed = 1_000_000 * (amount + donation + 1000 + 1) // (1_000_000 + victim_shares + 1_000_000)
        assert redeemed < amount + donation
        transactions += [tx(p, 'redeem(uint256,address,address)', 1_000_000, A, A, output=out(redeemed)),
                         tx(T0, 'balanceOf(address)', A, output=out(1_000_000 - amount - donation + redeemed))]
    write('erc4626-' + suffix, p, [account(p, 'OffsetVault', {0: T0}), token(T0, {A: 1_000_000, V: 1_000_000})],
          transactions, 'ERC20-backed share accounting with virtual assets=1 and virtual shares=1000000. ' +
          ('Donation attack leaves victim with nonzero shares and attacker with less than initial asset balance.' if attack else
           'Zero donation leaves both equal deposits with equal shares.'))
for suffix, no_flash in [('balanced-swap', False), ('no-flashloan', True)]:
    p = '0x620000000000000000000000000000000000030' + ('2' if no_flash else '1')
    if no_flash:
        transactions = [tx(p, 'flashLoan(uint256)', 100, status='Revert'),
                        tx(p, 'swap(uint256,uint256,address,bytes)', 0, 100, A, '0x01', status='Revert'),
                        tx(p, 'getReserves()', output=out(1_000_000, 1_000_000, 0))]
    else:
        assert 1_001_000 * 999_001 >= 1_000_000**2
        transactions = [tx(T0, 'transfer(address,uint256)', p, 1000, output=out(1)),
                        tx(p, 'swap(uint256,uint256,address,bytes)', 0, 999, A, '0x', slots={2: 1_001_000, 3: 999_001}),
                        tx(p, 'getReserves()', output=out(1_001_000, 999_001, 0))]
    write('amm-' + suffix, p, [account(p, 'NoFlashPool', {0:T0, 1:T1, 2:1_000_000, 3:1_000_000}),
          token(T0, {p:1_000_000, A:10_000}), token(T1, {p:1_000_000})], transactions,
          'Two real ERC20 reserves. ' + ('Flash loans and callback swaps revert without changing reserves.' if no_flash else
          'Prefunded swap pays 999 token1 for 1000 token0, and enforces nondecreasing reserve product.'))
for suffix, healthy in [('healthy-liquidation', True), ('repaid-borrow', False)]:
    p = '0x620000000000000000000000000000000000040' + ('1' if healthy else '2')
    debt = 100*E if healthy else 0
    if healthy:
        transactions = [tx(p, 'liquidationCall(address,address,address,uint256,bool)', T0,T0,V,10*E,'false',status='Revert',slots={1:debt,2:200*E}),
                        tx(p, 'debt()', output=out(debt)), tx(T0, 'balanceOf(address)', p, output=out(1200*E))]
    else:
        transactions = [tx(p, 'borrow(uint256)', 100*E, caller=V, slots={1:100*E}),
                        tx(T0, 'approve(address,uint256)', p,100*E,caller=V,output=out(1)),
                        tx(p, 'repay(address,uint256,uint256,address)',T0,100*E,2,V,caller=V,output=out(100*E),slots={1:0}),
                        tx(T0, 'balanceOf(address)',p,output=out(1200*E))]
    write('lending-' + suffix,p,[account(p,'CollateralizedLender',{0:T0,1:debt,2:200*E,3:V}),
          token(T0,{p:1200*E,V:500*E})],transactions,
          'ERC20-backed collateralized debt. ' + ('100 debt against 200 collateral is healthy at 75% LTV; liquidation reverts.' if healthy else
          'Borrow increases debt and transfers 100 tokens; repayment returns assets and restores debt to zero.'))
propose = 'propose(address[],uint256[],string[],bytes[],string)'
args = ['[]','[]','[]','[]','control']
for suffix, delay in [('delayed-execute',True),('quorum',False)]:
    p = '0x620000000000000000000000000000000000050' + ('1' if delay else '2')
    if delay:
        transactions = [tx(p,propose,*args,caller=O,output=out(1)),
            tx(p,'castVote(uint256,uint8)',1,1,caller=V,output=out(2)),
            tx(p,'queue(uint256)',1,slots={2:1100}),
            tx(p,'execute(uint256)',1,timestamp=1050,status='Revert',slots={3:256}),
            tx(p,'execute(uint256)',1,timestamp=1100,slots={3:257})]
    else:
        transactions = [tx(p,propose,*args,status='Revert',slots={0:0}),
            tx(p,propose,*args,caller=O,output=out(1)),
            tx(p,'castVote(uint256,uint8)',1,1,status='Revert',slots={1:0}),
            tx(p,'queue(uint256)',1,status='Revert',slots={2:0}),
            tx(p,'execute(uint256)',1,timestamp=1200,status='Revert',slots={3:0})]
    write('governance-'+suffix,p,[account(p,'GuardedGovernor')],transactions,
          'Proposal requires authorized proposer and quorum requires an authorized voter. ' +
          ('Execution reverts before ETA and succeeds only after the 100-second delay.' if delay else
           'Unauthorized propose/vote and quorum-free queue/execute all revert.'))
