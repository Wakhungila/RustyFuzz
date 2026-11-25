const solc=require('solc');const fs=require('fs');
const [,, dir]=process.argv;
const src=fs.readFileSync(dir+'/Maze.sol','utf8');
const input={language:'Solidity',sources:{'Maze.sol':{content:src}},settings:{optimizer:{enabled:true,runs:200},outputSelection:{'*':{'*':['abi','evm.deployedBytecode.object','storageLayout']}}}};
const o=JSON.parse(solc.compile(JSON.stringify(input)));
if(o.errors&&o.errors.some(e=>e.severity==='error')){console.error(o.errors.filter(e=>e.severity==='error'));process.exit(1)}
const c=o.contracts['Maze.sol'].Maze;
const slot=c.storageLayout.storage.find(s=>s.label==='__bugs').slot;
const ids=[...src.matchAll(/bug\((\d+)\);/g)].map(m=>+m[1]);
const uniq=[...new Set(ids)].sort((a,b)=>a-b);
const T='0x6200000000000000000000000000000000000001';
const fx={schema_version:1,bytecode_kind:'runtime',target:T,attacker:'0x'+'aa'.repeat(20),victim:'0x'+'bb'.repeat(20),environment:{chain_id:1,block_number:1,timestamp:1000,gas_limit:30000000,base_fee:0},
accounts:[{address:'0x'+'aa'.repeat(20),balance:'0xd3c21bcecceda1000000',nonce:0,runtime_bytecode:'0x',storage:[]},{address:'0x'+'bb'.repeat(20),balance:'0x0',nonce:0,runtime_bytecode:'0x',storage:[]},{address:T,balance:'0x0',nonce:0,runtime_bytecode:'0x'+c.evm.deployedBytecode.object,storage:[]}],
transactions:[],expected_safe_behavior:'Daedaluzz maze'};
fs.writeFileSync(dir+'.json',JSON.stringify(fx));fs.writeFileSync(dir+'.abi.json',JSON.stringify(c.abi));
const symbols={},invariants=[];
for(const id of uniq){const k='0x'+id.toString(16).padStart(64,'0');symbols['b'+id]={kind:'mapping',slot:'0x'+(+slot).toString(16),offset_bits:0,width_bits:256,key_type:'uint256',keys:[k]};invariants.push({name:'bug'+id,predicate:`sum(b${id}) <= 0`});}
fs.writeFileSync(dir+'.invariants.json',JSON.stringify({target:T,symbols,invariants},null,1));
console.log(dir,'bugs',uniq.length,'slot',slot);
