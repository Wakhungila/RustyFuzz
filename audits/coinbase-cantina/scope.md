# Coinbase Cantina Scope Lock

- Source: `/home/pin0ccs/Desktop/Audits/audits/coinbase-cantina/scope_raw.txt`
- Program: Coinbase public bounty on Cantina
- Scope tier: Tier 1
- Rule: use only listed or otherwise Coinbase-controlled Tier 1 mainnet deployments; do not infer Tier 0/Tier 1 beyond supplied scope.
- Active testing boundary: local forks/read-only RPC only; no public transaction broadcast.

## Parsed Targets

- Total targets parsed: `206`
- By chain: Arbitrum=12, Avalanche=5, BNB Smart Chain=9, Base=133, Ethereum=22, Optimism=14, Polygon=7, Solana=2, ZKSync Era=2
- By product family: Account Policies=5, Base AppChains=2, Basenames=20, Base–Solana Bridge=7, Coinbase Attestations=5, Coinbase Smart Wallet Infrastructure=25, Coinbase Validator Staking Infrastructure=1, Commerce Payments=6, DEX Aggregator=2, EIP-7702=6, Echo=25, Flywheel Protocol=4, Liqufi=35, Recovery Signer=1, Spend Permissions=11, Verified Pools=6, Wrapped Token — ADA=2, Wrapped Token — DOGE=2, Wrapped Token — LTC=2, Wrapped Token — XRP=2, Wrapped Tokens Infrastructure=37

## Exclusions

- Contracts deployed on testnets or devnets.
- Contracts deployed on mainnet only for testing.
- Contracts deployed on mainnet for Coinbase internal use.
- Third-party dependencies of Coinbase contracts.
- Third-party contracts used by Coinbase to provide services unless directly controlled by Coinbase and expressly included.
- Issues already identified in previous security reviews.
- Third-party contracts not under Coinbase direct project control.
- Issues involving non-standard ERC-20 tokens unless the affected product explicitly supports that behavior.
- Rounding errors without significant security or financial impact.
- User errors requiring obviously incorrect parameters.
- Vulnerabilities manifesting only during extreme market conditions.
- Incorrect data supplied by third-party oracles.
- Theoretical exploits without a practical proof of concept.
- Issues requiring leaked, stolen, or compromised keys or credentials.
- Sybil attacks.
- Centralization risks.
- Basic economic or governance attacks, including 51% attacks.
- Protocol design choices without a concrete security failure.
- Gas optimization issues or high gas costs.
- Best-practice-only recommendations.
- Submissions generated using ChatGPT or other LLM tools.

## Practical Exception

- Oracle manipulation and flash-loan-assisted attacks require practical local proof of direct impact.
