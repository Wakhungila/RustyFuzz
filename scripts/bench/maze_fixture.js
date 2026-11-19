const solc=require('solc');const fs=require('fs');
const [,, src, out]=process.argv;
const input={language:'Solidity',sources:{'Maze.sol':{content:fs.readFileSync(src,'utf8')}},settings:{optimizer:{enabled:true,runs:200},outputSelection:{'*':{'*':['abi','evm.deployedBytecode.object']}}}};
const o=JSON.parse(solc.compile(JSON.stringify(input)));
if(o.errors&&o.errors.some(e=>e.severity==='error')){console.error(o.errors);process.exit(1)}
const c=o.contracts['Maze.sol'].Maze;
const T='0x6200000000000000000000000000000000000001',A='0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'.padEnd(42,'a'),V='0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
const fx={schema_version:1,bytecode_kind:'runtime',target:T,attacker:'0x'+'aa'.repeat(20),victim:V,environment:{chain_id:1,block_number:1,timestamp:1000,gas_limit:30000000,base_fee:0},
accounts:[{address:'0x'+'aa'.repeat(20),balance:'0xd3c21bcecceda1000000',nonce:0,runtime_bytecode:'0x',storage:[]},{address:V,balance:'0x0',nonce:0,runtime_bytecode:'0x',storage:[]},{address:T,balance:'0x0',nonce:0,runtime_bytecode:'0x'+c.evm.deployedBytecode.object,storage:[]}],
transactions:[],expected_safe_behavior:'Daedaluzz maze (autonomous discovery benchmark)'};
fs.writeFileSync(out,JSON.stringify(fx));fs.writeFileSync(out.replace('.json','.abi.json'),JSON.stringify(c.abi));
