#!/usr/bin/env python3
"""Compile deliberately broken counterparts; never add these to the negative pack."""
import copy
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
PACK = ROOT / 'benchmarks/historical/gate2_positive_controls'
NEGATIVE = ROOT / 'benchmarks/historical/negative_controls'
SOURCE = PACK / 'contracts/VulnerableControls.sol'

def run(*args):
    return subprocess.check_output(args, cwd=ROOT, text=True).strip()

assert '0.8.30+' in run('solc', '--version'), 'solc 0.8.30 required'
compiled = json.loads(run('solc', '--optimize', '--evm-version', 'shanghai',
                          '--combined-json', 'bin-runtime', str(SOURCE.relative_to(ROOT))))['contracts']
code = {key.rsplit(':', 1)[1]: '0x' + value['bin-runtime'] for key, value in compiled.items()}
A = '0x' + 'aa' * 20
V = '0x' + 'bb' * 20
T0 = '0x7000000000000000000000000000000000000001'
E = 10**18

def out(n):
    return '0x' + n.to_bytes(32, 'big').hex()

def tx(to, signature, *args, caller=A, output=None, slots=None):
    return dict(caller=caller, to=to, calldata=run('cast', 'calldata', signature, *map(str, args)),
                value='0x0', timestamp=1000, expected_status='Success', expected_output=output,
                expected_storage=[dict(slot=hex(k), value=hex(v)) for k,v in (slots or {}).items()])

cases = [
    ('erc20-owner-mint', 'OwnerMintToken', 'Unauthorized caller mints 100 tokens to itself.'),
    ('erc4626-virtual-offset', 'OffsetVault', 'No offset or zero-share check: victim receives zero shares and attacker steals victim deposit.'),
    ('amm-balanced-swap', 'NoFlashPool', 'No invariant check: attacker takes 100000 token0 without input.'),
    ('lending-repaid-borrow', 'CollateralizedLender', 'Borrow transfers 100 tokens without recording debt.'),
    ('governance-quorum', 'GuardedGovernor', 'Execute succeeds without proposal, vote, queue or delay.'),
]
for name, contract, behavior in cases:
    f = json.loads((NEGATIVE / 'fixtures' / (name + '.json')).read_text())
    p = f['target']
    for account in f['accounts']:
        if account['address'] == p:
            account['runtime_bytecode'] = code[contract]
    if name.startswith('erc20'):
        seq = [tx(p, 'canMint(address)', A, output=out(0)),
               tx(p, 'mint(address,uint256)', A, 100*E, slots={2:100*E}),
               tx(p, 'balanceOf(address)', A, output=out(100*E))]
    elif name.startswith('erc4626'):
        seq = copy.deepcopy(f['transactions'])
        seq[1]['expected_output'] = out(1)
        seq[4]['expected_output'] = out(0)
        seq[5]['expected_output'] = out(0)
        seq[6] = tx(p, 'redeem(uint256,address,address)', 1, A, A, output=out(2001))
        seq[7]['expected_output'] = out(1001000)
        seq.insert(4, tx(p, 'convertToShares(uint256)', 1000, output=out(0)))
    elif name.startswith('amm'):
        reserves = lambda a,b: '0x' + out(a)[2:] + out(b)[2:] + out(0)[2:]
        seq = [tx(p, 'getReserves()', output=reserves(1000000,1000000)),
               tx(p, 'swap(uint256,uint256,address,bytes)', 100000,0,A,'0x',slots={2:900000,3:1000000}),
               tx(p, 'getReserves()', output=reserves(900000,1000000)),
               tx(T0, 'balanceOf(address)', A, output=out(110000))]
    elif name.startswith('lending'):
        seq = [tx(p, 'borrow(uint256)', 100*E, caller=V, slots={1:0}),
               tx(T0, 'balanceOf(address)', V, output=out(600*E))]
    else:
        seq = [tx(p, 'execute(uint256)', 1, slots={0:0,1:0,2:0,3:1})]
    f['transactions'] = seq
    # Schema name is historical; this description is never passed to the oracle.
    f['expected_safe_behavior'] = 'DELIBERATELY VULNERABLE WITNESS: ' + behavior
    (PACK / 'fixtures' / (name + '.json')).write_text(json.dumps(f, indent=2) + '\n')
    manifest = (NEGATIVE / (name + '.toml')).read_text()
    manifest = manifest.replace('id = "negative-' + name + '"', 'id = "positive-' + name + '"')
    manifest = manifest.replace('benchmarks/historical/negative_controls/fixtures/', 'benchmarks/historical/gate2_positive_controls/fixtures/')
    lines = [line for line in manifest.splitlines() if not line.startswith('notes = ')]
    lines.append('notes = ' + json.dumps(behavior))
    (PACK / (name + '.toml')).write_text('\n'.join(lines) + '\n')
    print(name, 'transactions=', len(seq))
