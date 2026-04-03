import type { ScenarioTemplate, AttackPhase } from "./types.js";

export const NFT_SCENARIOS: ScenarioTemplate[] = [
  {
    id: "token-erc20-inflation",
    category: "Token & NFT Vulnerabilities",
    subcategory: "Token Inflation",
    title: "ERC-20 Token Inflation via Missing Supply Check in Mint Function",
    difficulty: "advanced",
    description:
      "The mint function in an ERC-20 token doesn't enforce a maxSupply cap, allowing unlimited minting by any address with the MINTER_ROLE. An attacker who compromises or is granted the MINTER_ROLE can inflate the token supply to arbitrary levels, diluting all holders and potentially draining liquidity pools.",
    target_description:
      "An ERC-20 token contract with a public mint() function gated only by a MINTER_ROLE that has no maxSupply limit. The role may be assigned to bridge contracts, staking rewards distributors, or team multisigs.",
    tools_involved: ["foundry", "cast", "slither", "semgrep", "anvil", "etherscan", "tenderly", "solc"],
    tags: ["erc20", "inflation", "unlimited-mint", "role-access", "token"],
    cve_references: [],
    attack_phases: [
      {
        phase: "Code Review & Architecture Analysis",
        description:
          "Map the token's mint function, role hierarchy, and any supply cap logic. Identify all addresses holding MINTER_ROLE and whether the role can be renounced or has a guardian.",
        tools: ["foundry", "etherscan", "solc"],
        commands: [
          "forge inspect TokenContract storage --json | jq '.types[] | select(.label == \"MINTER_ROLE\")'",
          "cast call $TOKEN_ADDRESS \"hasRole(bytes32,address)(bool)\" $MINTER_ROLE $TARGET_ADDRESS --rpc-url $RPC_URL",
          "cast storage $TOKEN_ADDRESS $MINTER_ROLE_SLOT --rpc-url $RPC_URL",
          "solc --ast-compact-json Token.sol | grep -E 'mint|_mint|maxSupply|totalSupply'",
        ],
        expected_output:
          "Confirmation that mint() lacks a maxSupply require statement. Output shows the MINTER_ROLE holder list and that no _maxSupply state variable exists. The AST grep reveals mint() only checks role membership with no supply cap condition.",
        thinking:
          "The mint function checks only for MINTER_ROLE but never enforces a totalSupply <= maxSupply. If any minter key is compromised or the minter is a multisig with a low threshold, an attacker can call mint() repeatedly. I need to check whether the token has a pause mechanism or a guardian that could intervene, and whether there are any rate limits on the bridge or staking contracts that hold this role.",
        analysis:
          "The absence of a supply cap in the mint function is a critical design flaw. Even if the current MINTER_ROLE holders are trusted, any future role grant or key compromise leads to unlimited inflation. The attack surface expands if the minter is a contract with its own vulnerabilities.",
        next_action:
          "Run Slither to confirm no implicit supply constraints exist through inherited contracts or modifiers, then proceed to static analysis of the mint call chain.",
      },
      {
        phase: "Static Analysis & Automated Scanning",
        description:
          "Use Slither and Semgrep to detect missing supply cap checks, unconstrained mint paths, and role-grant patterns that could lead to inflation.",
        tools: ["slither", "semgrep", "solhint"],
        commands: [
          "slither TokenContract --print human-summary --detect unchecked-transfer,erc20-interface",
          "slither TokenContract --detect unchecked-lowlevel,uninitialized-state --json slither-results.json",
          "semgrep --config auto Token.sol --json semgrep-output.json",
          "solhint Token.sol",
        ],
        expected_output:
          "Slither flags an unconstrained mint function and identifies the MINTER_ROLE pattern without a corresponding maxSupply check. Semgrep highlights the missing require(totalSupply + amount <= maxSupply) pattern. Solhint reports style issues but no severity findings.",
        thinking:
          "Slither's human-summary should directly call out the missing supply cap. I'll cross-reference with Semgrep's ERC-20 ruleset to see if it catches the same pattern. If both tools agree, the confidence in this finding is very high. I should also check if there are any inherited contracts that might impose a cap through a modifier.",
        analysis:
          "Both Slither and Semgrep independently identify the missing supply cap. The Slither detector for erc20-interface confirms the contract implements the full ERC-20 spec except for supply constraints. No inherited modifier enforces a cap.",
        next_action:
          "Develop a Proof of Concept that demonstrates unlimited minting from a MINTER_ROLE holder account on a local Anvil fork.",
      },
      {
        phase: "Proof of Concept Development",
        description:
          "Write a Foundry test that forks mainnet, impersonates a MINTER_ROLE holder, and calls mint() to create an arbitrarily large supply, then verifies the impact on totalSupply and balances.",
        tools: ["foundry", "anvil", "cast", "tenderly"],
        commands: [
          "anvil --fork-url $RPC_URL --fork-block-number $BLOCK_NUMBER &",
          "cast rpc anvil_impersonateAccount $MINTER_ADDRESS --rpc-url http://127.0.0.1:8545",
          "cast send $TOKEN_ADDRESS \"mint(address,uint256)(bool)\" $ATTACKER_ADDRESS 1000000000000000000000000 --from $MINTER_ADDRESS --rpc-url http://127.0.0.1:8545",
          "cast call $TOKEN_ADDRESS \"totalSupply()(uint256)\" --rpc-url http://127.0.0.1:8545",
          "forge test --match-test testUnlimitedMint -vvvv",
        ],
        expected_output:
          "The test passes, demonstrating that 1,000,000 tokens can be minted with no upper bound. totalSupply() reflects the inflated amount. The console output shows the balance of the attacker address increasing by the full minted amount with no revert.",
        thinking:
          "The PoC confirms that the mint function has no supply cap. I should also test whether an attacker could gain the MINTER_ROLE through a separate vulnerability (e.g., in a governance contract that grants roles), which would make this a two-step exploit. For now, the direct mint from an existing minter is sufficient to demonstrate the issue.",
        analysis:
          "The PoC successfully mints 1 million tokens without any revert. The totalSupply increases proportionally. In a real attack, this could be used to dump tokens into a DEX pool, draining all paired liquidity. The severity scales with the market cap and liquidity depth.",
        next_action:
          "Quantify the financial impact by simulating a dump into a Uniswap V2 pool and calculating the minimum amount of paired tokens the attacker could extract.",
      },
      {
        phase: "Impact Analysis",
        description:
          "Model the economic impact of unlimited minting on token holders, liquidity pools, and downstream DeFi integrations that accept the token as collateral.",
        tools: ["foundry", "tenderly", "dune", "cast"],
        commands:
          [
            "forge test --match-test testMintAndDump -vvvv --gas-report",
            "cast call $UNISWAP_PAIR_ADDRESS \"getReserves()(uint112,uint112,uint32)\" --rpc-url $RPC_URL",
            "tenderly simulate --network mainnet --from $ATTACKER_ADDRESS --to $TOKEN_ADDRESS --input $MINT_TX_DATA",
          ],
        expected_output:
          "Simulation shows that minting 10M tokens and swapping them through the Uniswap pair extracts approximately $X in WETH/USDC. The gas report shows the mint + swap costs ~300k gas. Dune query results show current token holder distribution and the dilution percentage post-mint.",
        thinking:
          "The economic impact depends on pool depth. If the token has $5M in liquidity, minting 10M tokens and dumping would crash the price by 80%+ due to the constant product formula. I need to also consider that downstream protocols using this token as collateral could face bad debt, amplifying the impact beyond a single pool.",
        analysis:
          "The attack is economically viable: minting costs near zero gas beyond a normal transfer, and the output scales linearly with the attacker's desired extraction. Protocols accepting the token as collateral are at secondary risk. The CVSS is 9.0+ due to the combination of trivial exploitability and catastrophic impact.",
        next_action:
          "Draft the audit report with severity Critical, include the PoC code, economic impact model, and recommend adding a maxSupply require statement to the mint function.",
      },
      {
        phase: "Audit Report Writing",
        description:
          "Document the finding with a clear title, description, attack path, impact assessment, and a secure code remediation snippet.",
        tools: ["report_generator"],
        commands: [
          "report_generator generate --finding critical --template erc20-inflation --output reports/erc20-inflation.md",
          "report_generator validate --report reports/erc20-inflation.md",
        ],
        expected_output:
          "A professionally formatted audit report with: Title 'Critical: Unlimited Token Minting via Missing Supply Cap', Severity: Critical, CVSS: 9.1, SWC-101, CWE-863. Includes the vulnerable code snippet, the PoC test, impact quantification, and a remediation snippet adding require(totalSupply + amount <= maxSupply, 'Exceeds max supply').",
        thinking:
          "The report needs to be actionable for the development team. I'll include the exact line of code to add, reference OpenZeppelin's AccessControl and ERC20Capped patterns, and suggest that the team audit all MINTER_ROLE holders for their own security posture.",
        analysis:
          "The finding is well-supported by static analysis results, a working PoC, and economic impact modeling. The remediation is straightforward: add a maxSupply cap. The report also recommends reviewing all role holders and implementing a timelock on role grants.",
        next_action:
          "Submit the report to the client, recommend immediate deployment of a capped mint function, and suggest a follow-up review of all role-based access controls across the protocol.",
      },
    ],
  },
  {
    id: "token-erc721-approval-bypass",
    category: "Token & NFT Vulnerabilities",
    subcategory: "Approval Bypass",
    title: "ERC-721 Approval Bypass via Missing Owner Check in transferFrom",
    difficulty: "intermediate",
    description:
      "A custom NFT contract's transferFrom function doesn't verify that msg.sender is the owner or approved, allowing anyone to transfer any token. This effectively makes every NFT freely movable by any address.",
    target_description:
      "A custom ERC-721 NFT contract with a hand-rolled transferFrom implementation that omits the require(msg.sender == ownerOf(tokenId) || isApprovedForAll(owner, msg.sender) || getApproved(tokenId) == msg.sender) check.",
    tools_involved: ["foundry", "slither", "semgrep", "cast", "anvil", "solc", "solhint"],
    tags: ["erc721", "nft", "approval-bypass", "access-control", "transfer"],
    cve_references: [],
    attack_phases: [
      {
        phase: "Code Review & Architecture Analysis",
        description:
          "Inspect the transferFrom implementation to confirm the missing owner/approval check. Review the contract's inheritance to determine if any parent contract provides the check.",
        tools: ["foundry", "solc", "cast"],
        commands: [
          "forge inspect NFTContract methods --json | jq '.[] | select(.name == \"transferFrom\")'",
          "solc --ast-compact-json NFTContract.sol | grep -A 20 'transferFrom'",
          "cast call $NFT_ADDRESS \"ownerOf(uint256)(address)\" 1 --rpc-url $RPC_URL",
        ],
        expected_output:
          "The transferFrom function body shows no access control check before the internal _transfer call. The AST confirms the function proceeds directly to balance updates and Transfer event emission without verifying msg.sender authorization.",
        thinking:
          "This is a textbook access control omission. The transferFrom function should be the most guarded function in an NFT contract. I need to verify that no parent contract (e.g., a custom ERC721 base) injects the check via a modifier or internal call. If the check is truly absent, any address can drain the entire NFT collection.",
        analysis:
          "The transferFrom function lacks the fundamental authorization check present in every standard ERC-721 implementation. This is likely a custom contract that didn't inherit from OpenZeppelin's ERC721 or manually reimplemented the function incorrectly.",
        next_action:
          "Run Slither to confirm the missing access control and scan for other functions with similar omissions.",
      },
      {
        phase: "Static Analysis & Automated Scanning",
        description:
          "Use Slither and Semgrep to detect the missing authorization check in transferFrom and scan for related access control issues across the contract.",
        tools: ["slither", "semgrep", "solhint"],
        commands: [
          "slither NFTContract --detect incorrect-modifier,erc721-interface --print human-summary",
          "semgrep --config 'p solidity' NFTContract.sol --json",
          "solhint NFTContract.sol",
        ],
        expected_output:
          "Slither flags transferFrom as missing the ERC-721 required authorization check. Semgrep's ERC-721 rule set identifies the non-compliant transferFrom. Solhint may flag style issues but the critical finding comes from Slither and Semgrep.",
        thinking:
          "Slither's erc721-interface detector should specifically flag the non-standard transferFrom. I'll also check if setApprovalForAll and approve functions have the same issue, which would compound the severity.",
        analysis:
          "Both tools confirm the missing check. Slither also flags that approve() has a similar issue, meaning the attack surface extends beyond transferFrom to any function that should require ownership verification.",
        next_action:
          "Write a PoC test demonstrating that an arbitrary address can transfer an NFT it does not own.",
      },
      {
        phase: "Proof of Concept Development",
        description:
          "Create a Foundry test that impersonates an unrelated address and successfully calls transferFrom on an NFT owned by a different address.",
        tools: ["foundry", "anvil", "cast"],
        commands: [
          "anvil --fork-url $RPC_URL &",
          "forge test --match-test testTransferAnyNFT -vvvv",
          "cast send $NFT_ADDRESS \"transferFrom(address,address,uint256)\" $OWNER $ATTACKER 1 --from $RANDOM_ADDR --rpc-url http://127.0.0.1:8545",
          "cast call $NFT_ADDRESS \"ownerOf(uint256)(address)\" 1 --rpc-url http://127.0.0.1:8545",
        ],
        expected_output:
          "The test passes: ownerOf(1) returns the ATTACKER address after the unauthorized transferFrom call. No revert occurs. The test confirms that any address can transfer any NFT without approval.",
        thinking:
          "The PoC is straightforward: call transferFrom from an address that is neither the owner nor approved. If it succeeds, the vulnerability is confirmed. I should also test the full drain scenario where an attacker sweeps all token IDs in a loop.",
        analysis:
          "The PoC confirms the vulnerability. A full-collection drain would cost roughly 50k gas per NFT transfer, making it economically feasible to sweep a 10k collection for ~0.5 ETH in gas. The impact is total loss of all NFTs.",
        next_action:
          "Quantify the impact by estimating the floor price of the collection and the total value at risk.",
      },
      {
        phase: "Impact Analysis",
        description:
          "Assess the total value at risk by analyzing the NFT collection's floor price, holder count, and any downstream DeFi integrations using the NFT as collateral.",
        tools: ["dune", "tenderly", "cast"],
        commands: [
          "cast call $NFT_ADDRESS \"totalSupply()(uint256)\" --rpc-url $RPC_URL",
          "tenderly simulate --network mainnet --from $RANDOM --to $NFT_ADDRESS --input $TRANSFER_TX_DATA",
        ],
        expected_output:
          "The collection has N tokens with a floor price of X ETH, totaling Y ETH at risk. Tenderly simulation confirms the transfer executes with standard gas costs and no revert. Dune data shows the holder distribution and the number of affected users.",
        thinking:
          "Every NFT in the collection is at risk. The attack can be executed in a single transaction that sweeps all tokens. The total economic impact equals the floor price multiplied by total supply, minus gas costs. If any lending protocol accepts these NFTs as collateral, the bad debt exposure is also significant.",
        analysis:
          "This is a Critical severity finding. The impact is total loss of all NFTs in the collection. Exploit cost is minimal (gas only), and the attack requires no capital beyond transaction fees. The vulnerability is trivially exploitable by anyone monitoring the mempool.",
        next_action:
          "Write the audit report with Critical severity, include the PoC, and recommend using OpenZeppelin's ERC721 base contract or adding the standard authorization checks.",
      },
      {
        phase: "Audit Report Writing",
        description:
          "Produce the final audit report with finding details, PoC, impact analysis, and remediation guidance.",
        tools: ["report_generator"],
        commands: [
          "report_generator generate --finding critical --template erc721-approval-bypass --output reports/erc721-bypass.md",
          "report_generator validate --report reports/erc721-bypass.md",
        ],
        expected_output:
          "Audit report with: Title 'Critical: ERC-721 Transfer Authorization Bypass', Severity: Critical, CVSS: 9.8, SWC-106, CWE-284. Includes vulnerable code, PoC, impact quantification, and remediation using the standard require pattern or OZ ERC721 inheritance.",
        thinking:
          "The report should emphasize that this is a fundamental ERC-721 compliance failure. The fix is simple but the impact is catastrophic. I'll recommend an immediate contract migration to OZ ERC721 and a bug bounty disclosure for any affected holders.",
        analysis:
          "The finding is unambiguous: the transferFrom function violates the ERC-721 specification. The report provides a clear path to remediation and should be escalated to the team immediately.",
        next_action:
          "Deliver the report and recommend an emergency pause or contract migration. Offer to review the fixed implementation.",
      },
    ],
  },
  {
    id: "token-proxy-storage-collision",
    category: "Token & NFT Vulnerabilities",
    subcategory: "Proxy Storage Collision",
    title: "Proxy Storage Collision via Incorrect Implementation Slot Declaration",
    difficulty: "expert",
    description:
      "An upgradeable proxy contract uses the same storage slot for the implementation address and a user-configurable parameter, causing writes to the parameter to change the implementation address. An attacker can hijack the proxy's logic by writing a malicious implementation address through a legitimate user function.",
    target_description:
          "A UUPS or Transparent proxy contract where the implementation address slot overlaps with a configurable parameter (e.g., a fee rate or admin address) due to incorrect EIP-1967 slot declaration or manual slot assignment in a custom proxy.",
    tools_involved: ["foundry", "cast", "slither", "anvil", "solc", "etherscan", "tenderly"],
    tags: ["proxy", "storage-collision", "upgradeable", "implementation-hijack"],
    cve_references: [],
    attack_phases: [
      {
        phase: "Code Review & Architecture Analysis",
        description:
          "Examine the proxy contract's storage layout, EIP-1967 slot constants, and any user-facing functions that write to storage. Identify slot overlaps between the implementation address and configurable parameters.",
        tools: ["foundry", "solc", "etherscan", "cast"],
        commands: [
          "solc --storage-layout ProxyContract.sol --json | jq '.contracts[].storage_layout.storage[]'",
          "cast storage $PROXY_ADDRESS $IMPLEMENTATION_SLOT --rpc-url $RPC_URL",
          "cast storage $PROXY_ADDRESS $PARAMETER_SLOT --rpc-url $RPC_URL",
          "forge inspect ProxyContract storage --json",
        ],
        expected_output:
          "Storage layout analysis reveals that both the implementation address and a user parameter (e.g., maxFee) are assigned to the same slot (e.g., slot 0x360894a13ba... for implementation and a custom variable also mapped there). The cast storage calls confirm that writing to the parameter changes the implementation address bytes.",
        thinking:
          "Storage collision in a proxy is one of the most dangerous vulnerabilities because it allows an attacker to redirect all proxy calls to a malicious implementation. I need to verify that the slot overlap is real and that a user-facing function can write to the colliding slot. If the EIP-1967 constant is incorrectly defined or the proxy uses a custom slot that overlaps, this is exploitable.",
        analysis:
          "The proxy's storage layout has a critical collision: the implementation address slot (EIP-1967: 0x360894a13ba1a9870c5fd05c4b1e3c1c7e9c5e5c...) overlaps with a user-configurable fee parameter. Any call to setFee() will overwrite the implementation address, allowing the caller to hijack the proxy.",
        next_action:
          "Run Slither to detect storage collision patterns and verify the overlap through static analysis of the contract's storage layout.",
      },
      {
        phase: "Static Analysis & Automated Scanning",
        description:
          "Use Slither to detect storage slot collisions, uninitialized implementation slots, and non-standard proxy patterns.",
        tools: ["slither", "semgrep"],
        commands: [
          "slither ProxyContract --detect storage-collision,uninitialized-state --json",
          "slither ProxyContract --print vars-and-auth --json slither-proxy.json",
          "semgrep --config 'p solidity' ProxyContract.sol --json",
        ],
        expected_output:
          "Slither detects a storage collision between the implementation slot and the fee parameter. The vars-and-auth printout shows both variables map to the same slot index. Semgrep flags the non-EIP-1967-compliant slot declaration.",
        thinking:
          "Slither's storage-collision detector should catch this if the variables are explicitly assigned to slots. If the collision arises from implicit layout ordering (packing), I need to verify through the compiler's storage layout JSON. The key is proving that a user call can write to the implementation slot.",
        analysis:
          "Both Slither and Semgrep confirm the collision. The proxy does not follow EIP-1967 slot constants correctly, using a hardcoded value that overlaps with a user parameter. This is a design-level flaw in the proxy's storage declaration.",
        next_action:
          "Develop a PoC on an Anvil fork that calls the user function to overwrite the implementation address and then interacts with the hijacked proxy.",
      },
      {
        phase: "Proof of Concept Development",
        description:
          "Deploy a malicious implementation contract, write its address to the proxy via the user function, and demonstrate that subsequent proxy calls execute the attacker's logic.",
        tools: ["foundry", "anvil", "cast", "tenderly"],
        commands: [
          "anvil --fork-url $RPC_URL &",
          "forge create MaliciousImpl --rpc-url http://127.0.0.1:8545",
          "cast send $PROXY_ADDRESS \"setFee(uint256)\" $MALICIOUS_IMPL_AS_UINT --rpc-url http://127.0.0.1:8545",
          "cast call $PROXY_ADDRESS \"someProxyFunction()(uint256)\" --rpc-url http://127.0.0.1:8545",
          "forge test --match-test testProxyHijack -vvvv",
        ],
        expected_output:
          "After calling setFee() with the malicious implementation address encoded as the fee value, the proxy delegates all calls to the attacker's contract. The test demonstrates that a function call through the proxy executes the malicious implementation's logic, potentially draining funds or minting tokens.",
        thinking:
          "The PoC writes the malicious implementation address into the slot by calling setFee() with the address encoded as a uint256. The proxy then delegates to the attacker's contract. I need to ensure the malicious implementation has a compatible function selector so the delegatecall succeeds. The impact is total control of the proxy's logic.",
        analysis:
          "The PoC confirms that any user can hijack the proxy by calling setFee() with a carefully crafted value. The proxy then delegates to the attacker's implementation, which can drain all proxied assets. This is a Critical vulnerability with trivial exploitation.",
        next_action:
          "Model the financial impact by simulating a drain of all proxied tokens through the hijacked implementation.",
      },
      {
        phase: "Impact Analysis",
        description:
          "Quantify the total value locked in the proxy contract and simulate a complete drain through the hijacked implementation.",
        tools: ["tenderly", "dune", "cast"],
        commands: [
          "cast balance $PROXY_ADDRESS --rpc-url $RPC_URL",
          "cast call $PROXY_ADDRESS \"totalAssets()(uint256)\" --rpc-url $RPC_URL",
          "tenderly simulate --network mainnet --from $ATTACKER --to $PROXY_ADDRESS --input $HIJACK_TX_DATA",
        ],
        expected_output:
          "The proxy holds X ETH/Y tokens. Tenderly simulation shows the attacker can drain 100% of assets in a single transaction after hijacking the implementation. Dune data shows the number of affected users and total TVL.",
        thinking:
          "The impact is total loss of all assets managed by the proxy. The attack requires only a single transaction to set the malicious implementation and a second to drain. The gas cost is minimal compared to the TVL.",
        analysis:
          "Critical severity. Total TVL at risk. The attack is a two-step process: hijack the proxy, then drain. No capital requirement beyond gas. Exploit complexity is moderate (requires encoding an address as a uint256), but the barrier is trivial for any attacker.",
        next_action:
          "Write the audit report recommending immediate migration to EIP-1967-compliant storage slots and a review of all proxy contracts in the protocol.",
      },
      {
        phase: "Audit Report Writing",
        description:
          "Document the storage collision finding, PoC, impact, and remediation with EIP-1967-compliant code.",
        tools: ["report_generator"],
        commands: [
          "report_generator generate --finding critical --template proxy-storage-collision --output reports/proxy-collision.md",
          "report_generator validate --report reports/proxy-collision.md",
        ],
        expected_output:
          "Audit report: 'Critical: Proxy Storage Collision Enables Implementation Hijack', Severity: Critical, CVSS: 9.5, SWC-124, CWE-787. Includes storage layout diagram, PoC code, drain simulation results, and a corrected EIP-1967 slot declaration snippet.",
        thinking:
          "The report must clearly explain the storage collision mechanism with a visual slot map. The remediation is to use the correct EIP-1967 constant for the implementation slot and ensure all user parameters use non-overlapping slots.",
        analysis:
          "The finding is well-documented with static analysis, a working PoC, and economic impact. The fix requires a proxy upgrade and migration to standard EIP-1967 slots.",
        next_action:
          "Deliver the report and recommend an emergency pause on the proxy while the storage layout is corrected.",
      },
    ],
  },
  {
    id: "token-unlimited-minting",
    category: "Token & NFT Vulnerabilities",
    subcategory: "Unlimited Minting",
    title: "Unlimited Minting via Missing Rate Limiter in Bridge Mint Path",
    difficulty: "advanced",
    description:
      "A bridge mint path that creates tokens on the destination chain has no rate limiting or maximum cap per epoch, allowing an attacker to mint arbitrary amounts by submitting multiple valid bridge messages.",
    target_description:
      "A cross-chain bridge contract on the destination chain that mints wrapped tokens upon receiving and verifying bridge messages from the source chain. The mint function has no per-epoch rate limit or cumulative cap.",
    tools_involved: ["foundry", "cast", "slither", "anvil", "semgrep", "etherscan", "tenderly"],
    tags: ["minting", "bridge", "rate-limit", "token-supply", "cross-chain"],
    cve_references: [],
    attack_phases: [
      {
        phase: "Code Review & Architecture Analysis",
        description:
          "Map the bridge's message verification and mint path. Identify whether there is any rate limiting, epoch-based cap, or cumulative supply check on minted tokens.",
        tools: ["foundry", "etherscan", "cast"],
        commands: [
          "forge inspect BridgeContract methods --json | jq '.[] | select(.name == \"mint\" or .name == \"completeBridge\")'",
          "cast call $BRIDGE_ADDRESS \"dailyMintLimit()(uint256)\" --rpc-url $RPC_URL",
          "cast storage $BRIDGE_ADDRESS $MINTED_THIS_EPOCH_SLOT --rpc-url $RPC_URL",
        ],
        expected_output:
          "The bridge's mint function has no dailyMintLimit or epoch tracking. Storage reads show no minted-this-epoch variable. The AST confirms that any verified bridge message triggers an unconstrained mint.",
        thinking:
          "The bridge relies on message verification (signatures/Merkle proofs) as the sole gate for minting. If an attacker can produce valid bridge messages (e.g., by compromising a validator key or exploiting the message generation on the source chain), there is no secondary defense. Even without compromised keys, if the bridge allows self-bridging (bridging tokens the attacker already controls), they can repeatedly bridge and unbridge to accumulate wrapped tokens.",
        analysis:
          "The bridge mint path lacks defense-in-depth. Message verification is the only control, and there is no rate limiting to bound damage from a compromised validator or a logic bug in the source chain. This is a systemic risk common in cross-chain bridges.",
        next_action:
          "Run Slither to detect unconstrained mint paths and verify the absence of rate limiting through static analysis.",
      },
      {
        phase: "Static Analysis & Automated Scanning",
        description:
          "Scan the bridge contract for missing rate limiters, unconstrained mint calls, and validator set management issues.",
        tools: ["slither", "semgrep", "solhint"],
        commands: [
          "slither BridgeContract --detect unchecked-transfer,erc20-interface --json",
          "semgrep --config 'p solidity' BridgeContract.sol --json",
          "solhint BridgeContract.sol",
        ],
        expected_output:
          "Slither flags the unconstrained mint in the bridge path. Semgrep identifies the missing rate-limit pattern. No epoch tracking or cumulative cap is detected in the codebase.",
        thinking:
          "The static analysis confirms the design gap. I should also check the validator set management to see if the bridge uses a multisig or threshold signature scheme, as a compromised validator would make this vulnerability trivially exploitable.",
        analysis:
          "The bridge has no rate limiting on the mint path. Combined with a validator set that may have a low threshold, this represents a critical systemic risk. The finding is compounded if the source chain has its own vulnerabilities.",
        next_action:
          "Develop a PoC demonstrating that multiple bridge messages can be submitted in a single block to mint beyond any reasonable bound.",
      },
      {
        phase: "Proof of Concept Development",
        description:
          "Simulate submitting multiple valid bridge messages in a single block and verify that the bridge mints tokens for each without rate limiting.",
        tools: ["foundry", "anvil", "cast", "tenderly"],
        commands: [
          "anvil --fork-url $RPC_URL &",
          "forge test --match-test testBridgeUnlimitedMint -vvvv",
          "cast send $BRIDGE_ADDRESS \"completeBridge(bytes)\" $BRIDGE_MSG_1 --rpc-url http://127.0.0.1:8545",
          "cast send $BRIDGE_ADDRESS \"completeBridge(bytes)\" $BRIDGE_MSG_2 --rpc-url http://127.0.0.1:8545",
          "cast call $TOKEN_ADDRESS \"totalSupply()(uint256)\" --rpc-url http://127.0.0.1:8545",
        ],
        expected_output:
          "Two bridge messages are processed successfully, minting tokens for each. totalSupply increases by the sum of both message amounts. No revert or rate-limit error occurs.",
        thinking:
          "The PoC shows that the bridge processes each message independently with no cumulative tracking. If the attacker controls or can forge bridge messages, the minting is unlimited. I should also test whether the bridge has a pause mechanism that could be activated in response.",
        analysis:
          "The PoC confirms unlimited minting through the bridge path. The absence of epoch tracking means there is no natural rate limit. An attacker with access to valid bridge messages can mint arbitrarily.",
        next_action:
          "Assess the economic impact by modeling the token supply inflation and downstream effects on DEX pools and lending protocols.",
      },
      {
        phase: "Impact Analysis",
        description:
          "Model the inflation impact of bridge minting on the wrapped token's price, liquidity pools, and any DeFi protocols accepting it as collateral.",
        tools: ["tenderly", "dune", "cast"],
        commands: [
          "tenderly simulate --network mainnet --from $ATTACKER --to $BRIDGE_ADDRESS --input $BRIDGE_TX_DATA",
          "cast call $UNISWAP_PAIR \"getReserves()(uint112,uint112,uint32)\" --rpc-url $RPC_URL",
        ],
        expected_output:
          "Simulation shows that minting 1M wrapped tokens and swapping through the DEX extracts significant liquidity. Dune data shows the current circulating supply and the inflation percentage post-attack.",
        thinking:
          "The wrapped token's value is backed by locked assets on the source chain. If the attacker mints more wrapped tokens than the source chain has locked, the bridge becomes undercollateralized. This creates a bank-run scenario where early redeemers get full value and later ones get nothing.",
        analysis:
          "The impact extends beyond simple inflation: the bridge's solvency is at risk. If the wrapped token is used as collateral in lending protocols, the bad debt could cascade. CVSS: 9.0+.",
        next_action:
          "Write the audit report with severity Critical, recommend implementing epoch-based rate limits and a cumulative mint cap.",
      },
      {
        phase: "Audit Report Writing",
        description:
          "Document the bridge mint vulnerability, PoC, impact model, and remediation with rate limiting code.",
        tools: ["report_generator"],
        commands: [
          "report_generator generate --finding critical --template bridge-unlimited-mint --output reports/bridge-mint.md",
          "report_generator validate --report reports/bridge-mint.md",
        ],
        expected_output:
          "Audit report: 'Critical: Unlimited Bridge Minting via Missing Rate Limiter', Severity: Critical, CVSS: 9.0, SWC-101, CWE-770. Includes the vulnerable mint path, PoC, impact model, and a remediation snippet adding epoch-based rate limiting.",
        thinking:
          "The report should recommend both technical fixes (rate limiting, cumulative caps) and operational improvements (validator set hardening, monitoring alerts for unusual mint volume).",
        analysis:
          "The finding is well-supported by code review, static analysis, and a PoC. The remediation is actionable and follows bridge security best practices.",
        next_action:
          "Deliver the report and recommend implementing the rate limiter as an urgent upgrade. Suggest a bug bounty increase for bridge-related findings.",
      },
    ],
  },
  {
    id: "token-transfer-reentrancy",
    category: "Token & NFT Vulnerabilities",
    subcategory: "Transfer Reentrancy",
    title: "ERC-20 Transfer Reentrancy via Callback in afterTokenTransfer Hook",
    difficulty: "advanced",
    description:
      "A token contract implements an afterTokenTransfer hook that calls an external contract before updating the balance mapping, enabling reentrancy attacks through a malicious receiver contract.",
    target_description:
      "An ERC-20 token with an afterTokenTransfer callback (similar to ERC-777's tokensReceived or a custom hook interface) that calls the receiver contract's hook function before updating internal balance state.",
    tools_involved: ["foundry", "slither", "anvil", "cast", "echidna", "tenderly", "solc"],
    tags: ["reentrancy", "erc20", "callback", "token-transfer", "external-call"],
    cve_references: [],
    attack_phases: [
      {
        phase: "Code Review & Architecture Analysis",
        description:
          "Identify the afterTokenTransfer hook invocation point and verify the order of operations: whether the external call occurs before or after balance updates.",
        tools: ["foundry", "solc", "cast"],
        commands: [
          "solc --ast-compact-json Token.sol | grep -B 5 -A 15 'afterTokenTransfer'",
          "forge inspect TokenContract methods --json | jq '.[] | select(.name == \"transfer\")'",
          "cast call $TOKEN_ADDRESS \"balanceOf(address)(uint256)\" $RECEIVER --rpc-url $RPC_URL",
        ],
        expected_output:
          "The AST shows the transfer function calls afterTokenTransferHook(receiver, sender, amount) before updating balances[sender] and balances[receiver]. This is the classic reentrancy pattern: external call precedes state change.",
        thinking:
          "This is a textbook reentrancy vulnerability. The hook call before balance update allows the receiver to call transfer() again in a loop, each time seeing the same pre-transfer balance. I need to verify that the hook is indeed called before the state update and that the receiver can be a malicious contract.",
        analysis:
          "The transfer function violates the checks-effects-interactions pattern. The external hook call precedes the balance update, creating a reentrancy window. An attacker can recursively transfer tokens to themselves, each time using the same balance as collateral or spending power.",
        next_action:
          "Run Slither's reentrancy detector to confirm the vulnerability and identify all affected functions.",
      },
      {
        phase: "Static Analysis & Automated Scanning",
        description:
          "Use Slither and Echidna to detect reentrancy in the transfer path and fuzz the hook interaction.",
        tools: ["slither", "echidna", "semgrep"],
        commands: [
          "slither TokenContract --detect reentrancy-eth,reentrancy-benign,reentrancy-no-eth --json",
          "echidna TokenContract.sol --test-precision 10000 --corpus-dir echidna-corpus",
          "semgrep --config 'p solidity' TokenContract.sol --json",
        ],
        expected_output:
          "Slither flags reentrancy in the transfer function due to the external call in afterTokenTransferHook before state update. Echidna may find a reentrancy invariant violation. Semgrep identifies the non-compliant checks-effects-interactions ordering.",
        thinking:
          "Slither's reentrancy detector should catch this immediately. Echidna's fuzzing may produce a concrete reentrant call sequence. The combination of static and dynamic analysis strengthens the finding.",
        analysis:
          "Both Slither and Echidna confirm the reentrancy. The hook call ordering is the root cause. This affects all transfer functions that invoke the hook.",
        next_action:
          "Develop a PoC with a malicious receiver contract that recursively calls transfer() within the hook to drain tokens.",
      },
      {
        phase: "Proof of Concept Development",
        description:
          "Deploy an attacker contract that receives the afterTokenTransfer callback and calls transfer() back to itself before the original transfer's balance update completes.",
        tools: ["foundry", "anvil", "cast", "tenderly"],
        commands: [
          "anvil --fork-url $RPC_URL &",
          "forge test --match-test testTransferReentrancy -vvvv",
          "cast send $TOKEN_ADDRESS \"transfer(address,uint256)\" $ATTACKER_CONTRACT 1000 --from $VICTIM --rpc-url http://127.0.0.1:8545",
        ],
        expected_output:
          "The attacker contract's hook triggers a recursive transfer that drains the victim's balance. After the outer transfer completes, the victim's balance is zero and the attacker holds all tokens. The test confirms the reentrancy exploit works end-to-end.",
        thinking:
          "The PoC follows the classic reentrancy pattern: the attacker's hook function calls transfer() again before the first call's state update. Since the balance hasn't been updated yet, the second transfer sees the same pre-transfer balance and succeeds. This can be looped to drain the entire balance.",
        analysis:
          "The reentrancy PoC is successful. The attacker drains the victim's full balance in a single transaction. The gas cost scales with the number of recursive calls but remains well below the block gas limit for meaningful balances.",
        next_action:
          "Quantify the maximum drainable amount and the gas cost for a full balance extraction.",
      },
      {
        phase: "Impact Analysis",
        description:
          "Model the maximum token drain via reentrancy and assess the impact on token holders and any downstream protocols.",
        tools: ["tenderly", "foundry", "dune"],
        commands: [
          "forge test --match-test testMaxDrain -vvvv --gas-report",
          "tenderly simulate --network mainnet --from $ATTACKER --to $TOKEN_ADDRESS --input $REENTRANT_TX_DATA",
        ],
        expected_output:
          "The maximum drain test shows the attacker can extract the victim's full balance in a single transaction. Gas cost is ~50k per recursive call. Tenderly confirms the simulation on mainnet state.",
        thinking:
          "The impact is total loss of the victim's token balance. Any address that receives tokens from this contract is at risk if it is a contract with a malicious hook implementation. The attack surface includes all token holders who interact with contracts.",
        analysis:
          "Critical severity. The reentrancy allows full balance extraction. The fix is straightforward: move the hook call after the balance update. CVSS: 9.0+.",
        next_action:
          "Write the audit report with the finding, PoC, and remediation implementing checks-effects-interactions.",
      },
      {
        phase: "Audit Report Writing",
        description:
          "Document the reentrancy finding with the vulnerable code, PoC, impact analysis, and a secure code snippet.",
        tools: ["report_generator"],
        commands: [
          "report_generator generate --finding critical --template transfer-reentrancy --output reports/transfer-reentrancy.md",
          "report_generator validate --report reports/transfer-reentrancy.md",
        ],
        expected_output:
          "Audit report: 'Critical: ERC-20 Transfer Reentrancy via afterTokenTransfer Hook', Severity: Critical, CVSS: 9.0, SWC-107, CWE-841. Includes the vulnerable transfer function, PoC code, and a corrected snippet moving the hook call after balance updates.",
        thinking:
          "The report should emphasize that this is a classic reentrancy pattern and the fix is well-known. I'll also recommend a reentrancy guard (OpenZeppelin's ReentrancyGuard) as a defense-in-depth measure.",
        analysis:
          "The finding is unambiguous: external call before state update. The fix is trivial but the impact is severe. The report includes both the immediate fix and a defense-in-depth recommendation.",
        next_action:
          "Deliver the report and recommend an immediate fix to reorder the operations. Offer to review the corrected implementation.",
      },
    ],
  },
  {
    id: "token-permit-replay",
    category: "Token & NFT Vulnerabilities",
    subcategory: "Permit Replay",
    title: "ERC-20 Permit Signature Replay via Missing Domain Separator Update",
    difficulty: "advanced",
    description:
      "The EIP-2612 permit function uses a static domain separator that doesn't account for chain ID changes after fork events, allowing signatures to be replayed across chain forks.",
    target_description:
      "An ERC-20 token implementing EIP-2612 (permit) with a domain separator computed once at deployment and cached, without updating on chain ID changes or accounting for chain ID in the separator.",
    tools_involved: ["foundry", "cast", "slither", "anvil", "etherscan", "semgrep", "solc"],
    tags: ["permit", "eip-2612", "signature-replay", "domain-separator", "erc20"],
    cve_references: [],
    attack_phases: [
      {
        phase: "Code Review & Architecture Analysis",
        description:
          "Examine the domain separator computation to verify whether it includes chainId and whether it is recomputed on each call or cached statically.",
        tools: ["foundry", "solc", "cast"],
        commands: [
          "solc --ast-compact-json Token.sol | grep -B 3 -A 10 'DOMAIN_SEPARATOR\\|domainSeparator'",
          "cast call $TOKEN_ADDRESS \"DOMAIN_SEPARATOR()(bytes32)\" --rpc-url $RPC_URL",
          "cast call $TOKEN_ADDRESS \"permit(address,address,uint256,uint256,uint8,bytes32,bytes32)\" $DATA --rpc-url $RPC_URL",
        ],
        expected_output:
          "The domain separator is cached at deployment time and does not include chainId, or includes a chainId that is hardcoded rather than fetched via block.chainid. The AST confirms no recomputation on fork events.",
        thinking:
          "If the domain separator doesn't include chainId or uses a cached value, a signature valid on one chain (or fork) is valid on another. This is particularly dangerous for tokens deployed on multiple chains or chains that have undergone fork events (e.g., Ethereum Classic, Polygon forks). The attacker can take a valid permit signature from mainnet and replay it on a fork where the nonce hasn't been consumed.",
        analysis:
          "The domain separator is static and doesn't account for chainId changes. A permit signature obtained on one chain can be replayed on any chain with the same contract address and chain ID, or on a fork where the nonce state differs.",
        next_action:
          "Run Slither to detect static domain separator patterns and EIP-2612 compliance issues.",
      },
      {
        phase: "Static Analysis & Automated Scanning",
        description:
          "Use Slither and Semgrep to detect EIP-2612 non-compliance, static domain separators, and missing chainId in the separator.",
        tools: ["slither", "semgrep"],
        commands: [
          "slither TokenContract --detect weak-prng,incorrect-modifier --json",
          "semgrep --config 'p solidity' TokenContract.sol --json",
        ],
        expected_output:
          "Slither flags the static domain separator and identifies the EIP-2612 non-compliance. Semgrep's signature rules catch the missing chainId in the domain separator computation.",
        thinking:
          "The static analysis should confirm that the domain separator is computed once and cached. I need to verify that the permit function doesn't recompute the separator on each call, which would mitigate the replay.",
        analysis:
          "Both tools confirm the issue. The domain separator is computed in the constructor and cached, with no mechanism to update it on chain ID changes. This is a known EIP-2612 implementation pitfall.",
        next_action:
          "Develop a PoC demonstrating signature replay across two chains/forks.",
      },
      {
        phase: "Proof of Concept Development",
        description:
          "Create a test that takes a valid permit signature from one chain and replays it on a fork, demonstrating that the signature is accepted due to the static domain separator.",
        tools: ["foundry", "anvil", "cast"],
        commands: [
          "anvil --fork-url $RPC_URL --chain-id 1 &",
          "forge test --match-test testPermitReplay -vvvv",
          "cast send $TOKEN_ADDRESS \"permit(address,address,uint256,uint256,uint8,bytes32,bytes32)\" $PERMIT_DATA --rpc-url http://127.0.0.1:8545",
        ],
        expected_output:
          "The permit signature is accepted on the fork, granting the attacker approval to spend the signer's tokens. The test shows that the same signature works on both chains because the domain separator is identical.",
        thinking:
          "The PoC shows that a signature from mainnet works on the fork because the domain separator doesn't include the chain ID. The attacker can use the replayed permit to call transferFrom and steal the signer's tokens.",
        analysis:
          "The replay attack is confirmed. Any valid permit signature can be replayed across chains with the same domain separator. The impact scales with the number of active permit signers and their token balances.",
        next_action:
          "Quantify the impact by analyzing the number of active permit signers and their total token balances.",
      },
      {
        phase: "Impact Analysis",
        description:
          "Assess the total value at risk from permit replay across chains and forks, and model the attacker's profit from draining signer balances.",
        tools: ["tenderly", "dune", "cast"],
        commands:
          [
            "cast call $TOKEN_ADDRESS \"nonces(address)(uint256)\" $SIGNER --rpc-url $RPC_URL",
            "tenderly simulate --network mainnet --from $ATTACKER --to $TOKEN_ADDRESS --input $REPLAY_TX_DATA",
          ],
        expected_output:
          "Analysis shows N active permit signers with a combined balance of X tokens. Tenderly simulation confirms the replayed permit is accepted and the attacker can drain the signer's full approved amount.",
        thinking:
          "The impact depends on the number of signers who have granted permits. Each valid signature can be replayed, and the attacker only needs to monitor the mempool for permit transactions to capture the signature data.",
        analysis:
          "High severity. The impact is bounded by the number of active permits and their approved amounts. The attack requires monitoring the mempool for permit signatures but is otherwise trivial. CVSS: 7.5+.",
        next_action:
          "Write the audit report with severity High, recommend recomputing the domain separator on each call and including chainId.",
      },
      {
        phase: "Audit Report Writing",
        description:
          "Document the permit replay finding, PoC, impact analysis, and remediation with EIP-2612-compliant domain separator code.",
        tools: ["report_generator"],
        commands: [
          "report_generator generate --finding high --template permit-replay --output reports/permit-replay.md",
          "report_generator validate --report reports/permit-replay.md",
        ],
        expected_output:
          "Audit report: 'High: ERC-20 Permit Signature Replay via Static Domain Separator', Severity: High, CVSS: 7.5, SWC-121, CWE-294. Includes the vulnerable domain separator code, PoC, and a corrected snippet using keccak256(abi.encode(..., block.chainid, ...)).",
        thinking:
          "The report should recommend the standard EIP-2612 pattern of recomputing the domain separator on each call with the current chainId. This is the approach used by OpenZeppelin and DAI.",
        analysis:
          "The finding is well-documented with static analysis and a PoC. The fix is standard and well-known in the EIP-2612 implementation community.",
        next_action:
          "Deliver the report and recommend updating the domain separator computation. Offer to review the corrected implementation.",
      },
    ],
  },
  {
    id: "nft-staking-double-spend",
    category: "Token & NFT Vulnerabilities",
    subcategory: "NFT Staking Double Spend",
    title: "NFT Staking Double Spend via Unchecked Stake State",
    difficulty: "advanced",
    description:
      "An NFT staking contract doesn't mark tokens as staked before transferring them to the staking vault, allowing the same NFT to be staked twice in a single transaction via reentrancy.",
    target_description:
      "An NFT staking contract where the stake() function transfers the NFT to a vault and then updates the staked mapping, without a reentrancy guard or proper state update ordering.",
    tools_involved: ["foundry", "anvil", "cast", "slither", "echidna", "tenderly", "solc"],
    tags: ["nft-staking", "double-spend", "reentrancy", "erc721", "staking"],
    cve_references: [],
    attack_phases: [
      {
        phase: "Code Review & Architecture Analysis",
        description:
          "Examine the stake() function to verify whether the staked mapping is updated before or after the NFT transfer, and whether a reentrancy guard is present.",
        tools: ["foundry", "solc", "cast"],
        commands: [
          "solc --ast-compact-json StakingContract.sol | grep -B 5 -A 20 'function stake'",
          "cast call $STAKING_ADDRESS \"isStaked(uint256)(bool)\" 1 --rpc-url $RPC_URL",
          "forge inspect StakingContract methods --json | jq '.[] | select(.name == \"stake\")'",
        ],
        expected_output:
          "The stake function transfers the NFT via safeTransferFrom (which calls onERC721Received on the receiver) before marking the token as staked. If the vault contract is attacker-controlled, onERC721Received can call stake() again for the same token.",
        thinking:
          "This is a reentrancy vulnerability similar to the DAO hack but specific to NFT staking. The safeTransferFrom call triggers a callback on the receiver, and if the staked mapping isn't updated before the call, the attacker can re-enter stake(). I need to verify that the vault can be attacker-controlled or that the staking contract itself is the receiver.",
        analysis:
          "The stake function violates checks-effects-interactions: the external call (safeTransferFrom) precedes the state update (staked[tokenId] = true). The attacker can exploit this via the onERC721Received callback.",
        next_action:
          "Run Slither to detect reentrancy in the stake function and verify the state update ordering.",
      },
      {
        phase: "Static Analysis & Automated Scanning",
        description:
          "Use Slither and Echidna to detect the reentrancy in the stake path and fuzz the staking interaction.",
        tools: ["slither", "echidna", "semgrep"],
        commands: [
          "slither StakingContract --detect reentrancy-eth,reentrancy-no-eth --json",
          "echidna StakingContract.sol --test-precision 5000 --corpus-dir echidna-corpus",
          "semgrep --config 'p solidity' StakingContract.sol --json",
        ],
        expected_output:
          "Slither flags reentrancy in the stake function due to the external call (safeTransferFrom) before the staked state update. Echidna may find an invariant where the same NFT is staked twice. Semgrep identifies the non-compliant ordering.",
        thinking:
          "Slither should catch this immediately. Echidna's fuzzing may find a concrete reentrant sequence. The combination confirms the vulnerability.",
        analysis:
          "Both tools confirm the reentrancy. The stake function's ordering allows the same NFT to be staked multiple times, generating duplicate staking rewards.",
        next_action:
          "Develop a PoC with a malicious vault contract that re-enters stake() via onERC721Received.",
      },
      {
        phase: "Proof of Concept Development",
        description:
          "Deploy an attacker-controlled vault contract that calls stake() again in its onERC721Received callback, double-staking the same NFT.",
        tools: ["foundry", "anvil", "cast", "tenderly"],
        commands: [
          "anvil --fork-url $RPC_URL &",
          "forge test --match-test testNFTStakingDoubleSpend -vvvv",
          "cast send $STAKING_ADDRESS \"stake(uint256)\" 1 --from $ATTACKER --rpc-url http://127.0.0.1:8545",
        ],
        expected_output:
          "The same NFT is staked twice: the staking contract records two stake entries for tokenId 1, each earning rewards. The test confirms the double-spend via reentrancy.",
        thinking:
          "The PoC demonstrates that the attacker can stake the same NFT twice, earning double rewards. The staking contract's state shows two entries for the same tokenId, both marked as staked. This is a direct financial loss to the protocol.",
        analysis:
          "The double-spend PoC is successful. The attacker earns 2x rewards for a single NFT. The impact scales with the reward rate and the number of NFTs the attacker can double-stake.",
        next_action:
          "Quantify the financial impact by calculating the total excess rewards extracted through double-staking.",
      },
      {
        phase: "Impact Analysis",
        description:
          "Model the excess rewards extracted through NFT double-staking and assess the impact on the staking pool's sustainability.",
        tools: ["tenderly", "dune", "foundry"],
        commands: [
          "forge test --match-test testExcessRewards -vvvv --gas-report",
          "tenderly simulate --network mainnet --from $ATTACKER --to $STAKING_ADDRESS --input $DOUBLE_STAKE_TX_DATA",
        ],
        expected_output:
          "The attacker extracts 2x rewards for each double-staked NFT. With N NFTs, the excess rewards total X tokens. Tenderly confirms the simulation on mainnet state.",
        thinking:
          "The impact is direct theft of staking rewards. If the reward pool is finite, the attacker's excess rewards reduce the honest stakers' share. If the pool is inflationary, the protocol mints extra tokens, diluting all holders.",
        analysis:
          "High severity. The impact is bounded by the number of NFTs the attacker controls and the reward rate. The fix is straightforward: update the staked mapping before the transfer. CVSS: 8.0+.",
        next_action:
          "Write the audit report with severity High, recommend reordering the operations and adding a reentrancy guard.",
      },
      {
        phase: "Audit Report Writing",
        description:
          "Document the double-spend finding, PoC, impact analysis, and remediation code.",
        tools: ["report_generator"],
        commands: [
          "report_generator generate --finding high --template nft-staking-double-spend --output reports/nft-double-spend.md",
          "report_generator validate --report reports/nft-double-spend.md",
        ],
        expected_output:
          "Audit report: 'High: NFT Staking Double Spend via Reentrancy', Severity: High, CVSS: 8.0, SWC-107, CWE-362. Includes the vulnerable stake function, PoC, and a corrected snippet updating the staked mapping before the transfer.",
        thinking:
          "The report should emphasize the checks-effects-interactions violation and recommend both reordering and a reentrancy guard for defense-in-depth.",
        analysis:
          "The finding is well-supported by static analysis and a working PoC. The fix is trivial: reorder the state update before the external call.",
        next_action:
          "Deliver the report and recommend the fix. Offer to review the corrected implementation.",
      },
    ],
  },
  {
    id: "nft-vesting-early-withdraw",
    category: "Token & NFT Vulnerabilities",
    subcategory: "Vesting Early Withdraw",
    title: "NFT Vesting Early Withdraw via Incorrect Timestamp Comparison",
    difficulty: "intermediate",
    description:
      "A vesting contract checks block.timestamp >= vestEndTime but uses a stored vestEndTime that can be overwritten by the contract owner through a missing access control on the setVestSchedule function.",
    target_description:
      "An NFT vesting contract with a setVestSchedule function that lacks an onlyOwner or role check, allowing any address to modify the vestEndTime and vestAmount for any beneficiary.",
    tools_involved: ["foundry", "cast", "slither", "anvil", "semgrep", "solc", "etherscan"],
    tags: ["vesting", "timestamp", "access-control", "early-withdraw", "nft"],
    cve_references: [],
    attack_phases: [
      {
        phase: "Code Review & Architecture Analysis",
        description:
          "Inspect the setVestSchedule function to confirm the missing access control. Verify that any address can modify vestEndTime and vestAmount.",
        tools: ["foundry", "solc", "cast"],
        commands: [
          "solc --ast-compact-json VestingContract.sol | grep -B 3 -A 10 'function setVestSchedule'",
          "cast call $VESTING_ADDRESS \"vestEndTime(address)(uint256)\" $BENEFICIARY --rpc-url $RPC_URL",
          "forge inspect VestingContract methods --json | jq '.[] | select(.name == \"setVestSchedule\")'",
        ],
        expected_output:
          "The setVestSchedule function has no onlyOwner or role modifier. The AST confirms that any caller can update vestEndTime and vestAmount for any beneficiary address.",
        thinking:
          "The missing access control on setVestSchedule means anyone can set the vestEndTime to a past timestamp, making the vest immediately claimable. An attacker can set the end time to 0, then call claim() to withdraw the NFT early.",
        analysis:
          "The setVestSchedule function is publicly callable with no access control. Any address can modify the vesting schedule, enabling early withdrawal of vested NFTs.",
        next_action:
          "Run Slither to detect the missing access control and scan for other publicly writable state variables.",
      },
      {
        phase: "Static Analysis & Automated Scanning",
        description:
          "Use Slither and Semgrep to detect publicly writable state variables and missing access controls in the vesting contract.",
        tools: ["slither", "semgrep", "solhint"],
        commands: [
          "slither VestingContract --detect incorrect-modifier,naming-convention --json",
          "semgrep --config 'p solidity' VestingContract.sol --json",
          "solhint VestingContract.sol",
        ],
        expected_output:
          "Slither flags setVestSchedule as a publicly writable function without access control. Semgrep identifies the missing onlyOwner pattern. Solhint may flag style issues.",
        thinking:
          "The static analysis confirms the access control gap. I should also check if the claim() function has proper validation that the vestEndTime hasn't been tampered with.",
        analysis:
          "Both tools confirm the missing access control. The vesting schedule can be modified by anyone, undermining the entire vesting mechanism.",
        next_action:
          "Develop a PoC where an attacker sets the vestEndTime to 0 and claims the NFT immediately.",
      },
      {
        phase: "Proof of Concept Development",
        description:
          "Call setVestSchedule to set the vestEndTime to 0 for a beneficiary, then call claim() to withdraw the NFT before the original vesting period.",
        tools: ["foundry", "anvil", "cast"],
        commands: [
          "anvil --fork-url $RPC_URL &",
          "cast send $VESTING_ADDRESS \"setVestSchedule(address,uint256,uint256)\" $BENEFICIARY 0 1 --rpc-url http://127.0.0.1:8545",
          "cast send $VESTING_ADDRESS \"claim()\" --from $BENEFICIARY --rpc-url http://127.0.0.1:8545",
          "forge test --match-test testEarlyWithdraw -vvvv",
        ],
        expected_output:
          "The attacker sets vestEndTime to 0, then successfully claims the NFT. The beneficiary receives the NFT immediately, bypassing the intended vesting schedule.",
        thinking:
          "The PoC is straightforward: set the end time to 0, then claim. The vesting contract's timestamp check passes because block.timestamp >= 0 is always true. The attacker can do this for any beneficiary.",
        analysis:
          "The early withdraw PoC is successful. Any beneficiary's NFT can be claimed immediately by modifying the vestEndTime. The impact is total circumvention of the vesting schedule.",
        next_action:
          "Quantify the impact by analyzing the total value of NFTs in the vesting contract and the number of affected beneficiaries.",
      },
      {
        phase: "Impact Analysis",
        description:
          "Assess the total value of NFTs at risk from early withdrawal and the impact on the vesting protocol's tokenomics.",
        tools: ["tenderly", "dune", "cast"],
        commands: [
          "cast call $VESTING_ADDRESS \"totalVested()(uint256)\" --rpc-url $RPC_URL",
          "tenderly simulate --network mainnet --from $ATTACKER --to $VESTING_ADDRESS --input $EARLY_WITHDRAW_TX_DATA",
        ],
        expected_output:
          "The vesting contract holds N NFTs with a total floor value of X ETH. Tenderly simulation confirms the early withdraw succeeds for any beneficiary.",
        thinking:
          "The impact is total circumvention of the vesting schedule. All NFTs in the contract can be claimed immediately. This undermines the tokenomics of the project if the vesting was designed to control supply release.",
        analysis:
          "High severity. The impact is total loss of vesting schedule integrity. The fix is trivial: add an onlyOwner modifier to setVestSchedule. CVSS: 8.5+.",
        next_action:
          "Write the audit report with severity High, recommend adding access control and making the vesting schedule immutable after deployment.",
      },
      {
        phase: "Audit Report Writing",
        description:
          "Document the early withdraw finding, PoC, impact analysis, and remediation code.",
        tools: ["report_generator"],
        commands: [
          "report_generator generate --finding high --template vesting-early-withdraw --output reports/vesting-early-withdraw.md",
          "report_generator validate --report reports/vesting-early-withdraw.md",
        ],
        expected_output:
          "Audit report: 'High: NFT Vesting Early Withdraw via Missing Access Control', Severity: High, CVSS: 8.5, SWC-116, CWE-863. Includes the vulnerable setVestSchedule function, PoC, and a remediation snippet adding the onlyOwner modifier.",
        thinking:
          "The report should recommend both the immediate fix (adding access control) and a design improvement (making vesting schedules immutable or governed by a timelock).",
        analysis:
          "The finding is well-documented with static analysis and a working PoC. The fix is straightforward.",
        next_action:
          "Deliver the report and recommend the access control fix. Offer to review the corrected implementation.",
      },
    ],
  },
  {
    id: "nft-governance-theft",
    category: "Token & NFT Vulnerabilities",
    subcategory: "Governance NFT Theft",
    title: "Governance NFT Theft via Missing Access Control on Batch Transfer",
    difficulty: "advanced",
    description:
      "A governance NFT contract has a batchTransfer function that lacks the onlyOwner or isApprovedForAll check, allowing anyone to transfer governance NFTs (which carry voting power) to themselves.",
    target_description:
      "A governance NFT contract where each NFT represents voting power in a DAO. The batchTransfer function allows transferring multiple NFTs in a single call but lacks authorization checks.",
    tools_involved: ["foundry", "cast", "slither", "anvil", "semgrep", "solc", "etherscan"],
    tags: ["governance-nft", "batch-transfer", "access-control", "erc721", "voting-power"],
    cve_references: [],
    attack_phases: [
      {
        phase: "Code Review & Architecture Analysis",
        description:
          "Inspect the batchTransfer function to confirm the missing authorization check. Verify that any address can transfer any NFT without ownership or approval verification.",
        tools: ["foundry", "solc", "cast"],
        commands: [
          "solc --ast-compact-json GovernanceNFT.sol | grep -B 3 -A 15 'function batchTransfer'",
          "cast call $GOVERNANCE_NFT_ADDRESS \"ownerOf(uint256)(address)\" 1 --rpc-url $RPC_URL",
          "forge inspect GovernanceNFT methods --json | jq '.[] | select(.name == \"batchTransfer\")'",
        ],
        expected_output:
          "The batchTransfer function has no onlyOwner, isApprovedForAll, or individual owner check per token ID. The AST confirms the function iterates over token IDs and transfers each without authorization verification.",
        thinking:
          "This is a critical access control omission in a governance contract. The batchTransfer function allows mass extraction of governance NFTs, which directly translates to voting power theft. An attacker can drain all governance NFTs and gain control of the DAO.",
        analysis:
          "The batchTransfer function lacks all authorization checks. Any address can transfer any NFT, making the entire governance system vulnerable to a hostile takeover.",
        next_action:
          "Run Slither to detect the missing access control and scan for other unprotected functions.",
      },
      {
        phase: "Static Analysis & Automated Scanning",
        description:
          "Use Slither and Semgrep to detect missing access controls in the batchTransfer and other governance functions.",
        tools: ["slither", "semgrep", "solhint"],
        commands: [
          "slither GovernanceNFT --detect incorrect-modifier,erc721-interface --json",
          "semgrep --config 'p solidity' GovernanceNFT.sol --json",
          "solhint GovernanceNFT.sol",
        ],
        expected_output:
          "Slither flags batchTransfer as missing authorization. Semgrep identifies the non-compliant access control pattern. The findings confirm that any address can transfer governance NFTs.",
        thinking:
          "The static analysis confirms the access control gap. I should also check if the governance contract's voting function relies on NFT ownership, which would make the impact even more severe.",
        analysis:
          "Both tools confirm the missing access control. The batchTransfer function is a direct vector for governance takeover.",
        next_action:
          "Develop a PoC demonstrating the mass transfer of governance NFTs to an attacker-controlled address.",
      },
      {
        phase: "Proof of Concept Development",
        description:
          "Call batchTransfer with all governance NFT token IDs and verify that they are transferred to the attacker without authorization.",
        tools: ["foundry", "anvil", "cast"],
        commands: [
          "anvil --fork-url $RPC_URL &",
          "forge test --match-test testGovernanceTheft -vvvv",
          "cast send $GOVERNANCE_NFT_ADDRESS \"batchTransfer(address[],uint256[])\" $ATTACKER $TOKEN_IDS --rpc-url http://127.0.0.1:8545",
        ],
        expected_output:
          "All governance NFTs are transferred to the attacker in a single transaction. The test confirms that the attacker now holds all voting power.",
        thinking:
          "The PoC demonstrates a complete governance takeover. The attacker now controls all voting power and can pass any proposal. This is the worst-case scenario for a DAO.",
        analysis:
          "The governance theft PoC is successful. The attacker gains full control of the DAO's governance in a single transaction. The impact is catastrophic.",
        next_action:
          "Quantify the impact by analyzing the governance proposals the attacker can now pass and the treasury value at risk.",
      },
      {
        phase: "Impact Analysis",
        description:
          "Assess the governance impact of the NFT theft: proposals the attacker can pass, treasury value at risk, and downstream protocol effects.",
        tools: ["tenderly", "dune", "cast"],
        commands: [
          "cast call $DAO_TREASURY_ADDRESS \"balance()(uint256)\" --rpc-url $RPC_URL",
          "tenderly simulate --network mainnet --from $ATTACKER --to $GOVERNANCE_NFT_ADDRESS --input $BATCH_TRANSFER_TX_DATA",
        ],
        expected_output:
          "The DAO treasury holds X ETH/tokens. With full governance control, the attacker can pass any proposal including treasury drains. Tenderly confirms the batch transfer succeeds on mainnet state.",
        thinking:
          "The impact extends beyond the NFTs themselves: the attacker controls the entire DAO. They can drain the treasury, change protocol parameters, and redirect all future development. This is an existential risk to the protocol.",
        analysis:
          "Critical severity. The impact is total governance takeover. The fix is trivial: add authorization checks to batchTransfer. CVSS: 9.8+.",
        next_action:
          "Write the audit report with severity Critical, recommend adding access control and implementing a timelock on governance changes.",
      },
      {
        phase: "Audit Report Writing",
        description:
          "Document the governance theft finding, PoC, impact analysis, and remediation code.",
        tools: ["report_generator"],
        commands: [
          "report_generator generate --finding critical --template governance-theft --output reports/governance-theft.md",
          "report_generator validate --report reports/governance-theft.md",
        ],
        expected_output:
          "Audit report: 'Critical: Governance NFT Theft via Missing Access Control on Batch Transfer', Severity: Critical, CVSS: 9.8, SWC-105, CWE-862. Includes the vulnerable batchTransfer function, PoC, and a remediation snippet adding isApprovedForAll checks.",
        thinking:
          "The report must emphasize the existential risk to the DAO. The fix is simple but the impact of not fixing it is total protocol loss.",
        analysis:
          "The finding is unambiguous: the batchTransfer function has no authorization. The report provides a clear remediation path and urgency assessment.",
        next_action:
          "Deliver the report with Critical severity and recommend an immediate emergency response.",
      },
    ],
  },
  {
    id: "token-erc4626-inflation-attack",
    category: "Token & NFT Vulnerabilities",
    subcategory: "ERC-4626 Inflation Attack",
    title: "ERC-4626 Vault Inflation Attack via Share Price Manipulation",
    difficulty: "expert",
    description:
      "An ERC-4626 vault calculates shares using totalAssets / totalSupply, which can be manipulated by an attacker who donates a tiny amount of assets before the first deposit, inflating the share price and preventing legitimate depositors from receiving shares.",
    target_description:
      "An ERC-4626 vault that uses the standard convertToShares(totalAssets * 10^18 / totalSupply) formula without a minimum share mint or virtual assets/shares mechanism to prevent inflation attacks.",
    tools_involved: ["foundry", "cast", "slither", "anvil", "semgrep", "etherscan", "tenderly", "solc"],
    tags: ["erc4626", "inflation-attack", "vault", "share-price", "defi"],
    cve_references: [],
    attack_phases: [
      {
        phase: "Code Review & Architecture Analysis",
        description:
          "Examine the vault's convertToShares and convertToAssets functions to verify whether they include virtual assets/shares or a minimum mint to prevent inflation attacks.",
        tools: ["foundry", "solc", "cast", "etherscan"],
        commands: [
          "solc --ast-compact-json Vault.sol | grep -B 3 -A 10 'convertToShares\\|convertToAssets'",
          "cast call $VAULT_ADDRESS \"totalAssets()(uint256)\" --rpc-url $RPC_URL",
          "cast call $VAULT_ADDRESS \"totalSupply()(uint256)\" --rpc-url $RPC_URL",
          "cast call $VAULT_ADDRESS \"convertToShares(uint256)(uint256)\" 1000000000000000000 --rpc-url $RPC_URL",
        ],
        expected_output:
          "The convertToShares function uses the standard formula without virtual assets/shares. When totalSupply is 0 (first depositor) or very small, a tiny asset donation can inflate the share price to the point where legitimate deposits receive 0 shares.",
        thinking:
          "The ERC-4626 inflation attack is a known vector: the attacker donates a small amount of assets to the vault before the first deposit, making the share price very high. When a legitimate user deposits, they receive 0 or near-0 shares because totalAssets / totalSupply rounds down. The attacker then withdraws the donated assets plus the legitimate user's deposit. This is prevented by virtual assets/shares (as in OpenZeppelin's ERC4626) or a minimum share mint.",
        analysis:
          "The vault uses the standard ERC-4626 conversion without inflation protection. A tiny asset donation can manipulate the share price to exclude legitimate depositors.",
        next_action:
          "Run Slither to detect missing virtual assets/shares and ERC-4626 inflation vulnerability patterns.",
      },
      {
        phase: "Static Analysis & Automated Scanning",
        description:
          "Use Slither and Semgrep to detect ERC-4626 inflation attack patterns, missing virtual assets, and share price manipulation vectors.",
        tools: ["slither", "semgrep"],
        commands: [
          "slither VaultContract --detect erc4626-inflation --json",
          "semgrep --config 'p solidity' VaultContract.sol --json",
        ],
        expected_output:
          "Slither flags the vault as vulnerable to ERC-4626 inflation attack due to missing virtual assets/shares. Semgrep identifies the non-protected convertToShares formula.",
        thinking:
          "Slither's erc4626-inflation detector should catch this. The key is whether the vault uses virtual shares/assets (a small initial deposit that is never withdrawable) to set a floor on the share price.",
        analysis:
          "Both tools confirm the inflation vulnerability. The vault has no protection against share price manipulation through asset donation.",
        next_action:
          "Develop a PoC demonstrating the inflation attack: donate assets, let a legitimate user deposit, then withdraw to steal their assets.",
      },
      {
        phase: "Proof of Concept Development",
        description:
          "Donate a small amount of assets to the vault, have a legitimate user deposit, then withdraw to capture the user's assets via share price manipulation.",
        tools: ["foundry", "anvil", "cast", "tenderly"],
        commands: [
          "anvil --fork-url $RPC_URL &",
          "forge test --match-test testERC4626Inflation -vvvv",
          "cast send $ASSET_ADDRESS \"transfer(address,uint256)\" $VAULT_ADDRESS 1 --rpc-url http://127.0.0.1:8545",
          "cast send $VAULT_ADDRESS \"deposit(uint256,address)\" 1000000000000000000 $USER --rpc-url http://127.0.0.1:8545",
          "cast send $VAULT_ADDRESS \"withdraw(uint256,address,address)\" $ATTACKER_SHARES $ATTACKER $ATTACKER --rpc-url http://127.0.0.1:8545",
        ],
        expected_output:
          "The attacker donates 1 wei of assets, the user deposits 1 ETH and receives 0 shares (due to rounding). The attacker withdraws and receives the user's 1 ETH minus the 1 wei donation. The test confirms the inflation attack.",
        thinking:
          "The PoC follows the classic ERC-4626 inflation attack: the attacker donates 1 wei, inflating the share price. The user's deposit of 1 ETH converts to 0 shares because (1e18 * 1e18) / (1e18 + 1) rounds down. The attacker then withdraws their 1 share (from the donation) and receives the user's full deposit.",
        analysis:
          "The inflation attack PoC is successful. The attacker steals the user's full deposit for a cost of 1 wei. The attack is economically devastating for the victim and trivially profitable for the attacker.",
        next_action:
          "Quantify the minimum capital required for the attack and the maximum stealable amount per transaction.",
      },
      {
        phase: "Impact Analysis",
        description:
          "Model the inflation attack economics: minimum donation, maximum stealable amount, and impact on vault users.",
        tools: ["tenderly", "dune", "foundry"],
        commands: [
          "forge test --match-test testInflationEconomics -vvvv --gas-report",
          "tenderly simulate --network mainnet --from $ATTACKER --to $VAULT_ADDRESS --input $INFLATION_TX_DATA",
        ],
        expected_output:
          "The minimum attack capital is 1 wei. The maximum stealable amount equals the user's deposit. Gas cost is ~200k for the full attack sequence (donate + withdraw). Tenderly confirms the simulation on mainnet.",
        thinking:
          "The attack requires virtually zero capital (1 wei) and steals the full deposit of any user. The gas cost is minimal. This is one of the most efficient attacks in DeFi. The only mitigation is virtual assets/shares or a minimum deposit.",
        analysis:
          "Critical severity. The attack requires 1 wei and steals the full deposit. CVSS: 9.0+. The fix is to use virtual shares/assets as recommended by the ERC-4626 specification.",
        next_action:
          "Write the audit report with severity Critical, recommend implementing virtual assets/shares per the ERC-4626 reference implementation.",
      },
      {
        phase: "Audit Report Writing",
        description:
          "Document the inflation attack finding, PoC, impact analysis, and remediation with virtual assets/shares code.",
        tools: ["report_generator"],
        commands: [
          "report_generator generate --finding critical --template erc4626-inflation --output reports/erc4626-inflation.md",
          "report_generator validate --report reports/erc4626-inflation.md",
        ],
        expected_output:
          "Audit report: 'Critical: ERC-4626 Vault Inflation Attack via Share Price Manipulation', Severity: Critical, CVSS: 9.0, SWC-128, CWE-682. Includes the vulnerable convertToShares function, PoC, and a remediation snippet implementing virtual assets/shares.",
        thinking:
          "The report should reference the ERC-4626 specification's own recommendation for virtual shares/assets and point to OpenZeppelin's implementation as the reference. The fix is well-established and should be adopted immediately.",
        analysis:
          "The finding is well-documented with static analysis and a working PoC. The fix is standard and follows the ERC-4626 spec.",
        next_action:
          "Deliver the report and recommend implementing virtual assets/shares. Offer to review the corrected vault implementation.",
      },
    ],
  },
];
