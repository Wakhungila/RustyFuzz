#!/usr/bin/env python3
"""Rewrite a Daedaluzz maze so each `emit AssertionFailed("N"); assert(false);` becomes a
non-reverting `bug(N)` that (a) sets mapping slot __bugs[N] (read by RustyFuzz --invariants)
and (b) emits ItyFuzz's typed-bug event, so both tools report the same bug ids.
usage: instrument_maze.py in.sol out.sol"""
import re, sys
src = open(sys.argv[1]).read()
src, n = re.subn(r'emit AssertionFailed\("(\d+)"\);\s*assert\(false\);', lambda m: f'bug({m.group(1)});', src)
topic = '0x' + ('66757a7a6c616e64' + '00' * 24)
helper = f'''
  mapping(uint256 => uint256) internal __bugs;
  function __str(uint256 v) internal pure returns (bytes memory) {{
    if (v == 0) return "0";
    uint256 t = v; uint256 l;
    while (t != 0) {{ l++; t /= 10; }}
    bytes memory b = new bytes(l);
    while (v != 0) {{ l--; b[l] = bytes1(uint8(48 + v % 10)); v /= 10; }}
    return b;
  }}
  function bug(uint256 id) internal {{
    __bugs[id] = 1;
    bytes memory d = abi.encodePacked(bytes32(0), bytes32(0), __str(id));
    bytes32 topic = {topic};
    assembly {{ log1(add(d, 32), mload(d), topic) }}
  }}
'''
src = re.sub(r'(contract Maze\s*\{)', lambda m: m.group(1) + helper, src, count=1)
open(sys.argv[2], 'w').write(src)
print(f'{sys.argv[1]}: instrumented {n} bug sites')
