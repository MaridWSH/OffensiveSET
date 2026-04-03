import type { ScenarioTemplate, AttackPhase } from "./types.js";

export const CROSSCHAIN_SCENARIOS: ScenarioTemplate[] = [
  {
    id: "cross-bridge-replay-attack",
    category: "Cross-Chain & Bridge Vulnerabilities",
    subcategory: "Replay Attack",
    title: "Cross-Chain Bridge Replay Attack via Missing Nonce Tracking",
    difficulty: "expert",
    description: "A bridge's message verification doesn't track nonces per source chain, allowing a valid message from chain A to be replayed on chain B multiple times. The bridge contract verifies the relayer signature but fails to ensure that each signed message is processed exactly once per destination chain, enabling unlimited replay of a single signed message across chains.",
    target_description: "Cross-chain bridge contract that accepts signed messages from relayers to mint or release tokens on the destination chain. The contract uses ECDSA signature verification but lacks per-chain nonce tracking in its executed mapping.",
    attack_phases: [
      {
        phase: "Code Review & Architecture Analysis",
        description: "Analyze the bridge's message verification logic to understand how incoming cross-chain messages are authenticated and whether replay protection is implemented per source chain.",
        tools: ["solc", "sigint", "slither"],
        commands: [
          "sigint analyze Bridge.sol --focus 'verifyMessage,processMessage,executeBridge'",
          "slither Bridge.sol --print human-summary,calls-external,vars-written",
          "slither Bridge.sol --detect reentrancy-eth,reentrancy-no-eth",
          "grep -n 'nonce\\|_nonce\\|_usedHash\\|executed' Bridge.sol"
        ],
        expected_output: "Bridge.sol:verifyMessage() verifies ECDSA signatures but the executed mapping only stores hash => bool without chain ID. The processMessage() function checks executed[msgHash] but does not incorporate source chain ID or destination chain ID into the hash, making the same valid signature replayable on any chain the bridge is deployed to.",
        thinking: "The bridge uses msgHash = keccak256(abi.encodePacked(amount, recipient)) as the replay protection key. Critically, it does NOT include sourceChainId or destinationChainId in this hash computation. This means a signature that was valid for transferring 1000 tokens on Ethereum can be replayed on Polygon, Arbitrum, or any other chain the bridge supports. The executed[msgHash] check will only prevent replay on the same chain where the original message was processed, but the same hash will be computed identically on every chain since the chain IDs aren't part of the hash input.",
        analysis: "The root cause is that the message hash construction omits domain separators. EIP-712 domain separation would include chainId, but this bridge uses a custom hash that only encodes amount and recipient. This is a classic cross-chain replay vulnerability: the signature is cryptographically valid but semantically bound to the wrong domain. The fix would require adding sourceChainId, destinationChainId, and a per-chain nonce to the message hash.",
        next_action: "Develop a proof of concept by deploying the bridge on a local fork of Ethereum, capturing a valid message signature from transaction logs, and replaying it on a forked testnet chain to demonstrate duplicate minting."
      },
      {
        phase: "Static Analysis & Automated Scanning",
        description: "Run Slither and Semgrep rules targeting cross-chain replay patterns, missing domain separators, and improper nonce tracking.",
        tools: ["slither", "semgrep", "solhint"],
        commands: [
          "slither Bridge.sol --detect weak-prng,reentrancy-benign,missing-zero-check --solc-remaps '@openzeppelin/=node_modules/@openzeppelin/'",
          "semgrep --config p/cryptography Bridge.sol",
          "semgrep --pattern 'keccak256(abi.encodePacked($AMOUNT, $RECIPIENT))' Bridge.sol",
          "solhint Bridge.sol --config .solhint.json"
        ],
        expected_output: "Slither: Info - 'Bridge.verifyMessage() uses keccak256 without chainId in the hash input. Consider using EIP-712 domain separation.' Semgrep: Found 1 match - keccak256(abi.encodePacked(amount, recipient)) at line 142 does not include chainId. Solhint: Warning - 'Cross-chain message handling should include chain ID in message hash.'",
        thinking: "The automated tools are flagging exactly what manual review found: the hash computation lacks chain domain separation. Slither's custom detector for cross-chain patterns identified the weak-prng category (though it's more accurately a domain separation issue). Semgrep caught the specific encodePacked pattern that excludes chainId. This confirms the vulnerability is detectable by static analysis if the right rules are in place.",
        analysis: "Static analysis confirms the missing domain separator. The key insight is that standard security scanners don't have default rules for cross-chain replay specifically, so custom Semgrep patterns are needed. The solhint rule for cross-chain patterns also caught it. The consensus across tools strengthens confidence that this is a real vulnerability, not a false positive.",
        next_action: "Write a Foundry test that demonstrates the replay attack by deploying two bridge instances on different forked chains and replaying a signed message from one to the other."
      },
      {
        phase: "Proof of Concept Development",
        description: "Create a Foundry test that captures a valid bridge message signature from one chain and replays it on another chain to mint duplicate tokens.",
        tools: ["foundry", "cast", "anvil", "forge"],
        commands: [
          "anvil --fork-url $ETH_RPC_URL --fork-block-number 19000000 &",
          "cast call $BRIDGE_ADDR 'getLastProcessedMessage()(bytes32)' --rpc-url http://127.0.0.1:8545",
          "forge test --match-test testReplayAttackAcrossChains -vvvv",
          "cast logs --address $BRIDGE_ADDR --from-block 19000000 --to-block latest 'MessageProcessed(bytes32,uint256,address)' --rpc-url http://127.0.0.1:8545"
        ],
        expected_output: "forge test output:\n[FAIL] testReplayAttackAcrossChains() (gas: 1247832)\nLogs:\n  Original processing: minted 1000 tokens to 0xUser on chain 1\n  Replay processing: minted 1000 tokens to 0xUser on chain 2 (DUPLICATE)\n  Total minted: 2000 tokens from single signature\n  Bridge balance discrepancy: -1000 tokens\n\nReplay succeeded: same msgHash 0xabc123... was accepted on both chains.",
        thinking: "The PoC needs to: (1) Deploy the bridge on two anvil instances simulating different chains, (2) Create a signed message with the bridge's relayer key for a token transfer, (3) Process the message on chain A successfully, (4) Submit the identical signature on chain B and observe that it also succeeds. The test should verify that the recipient's balance increases by the transfer amount on BOTH chains, proving the replay. The bridge's internal balance tracking will show a discrepancy because it only accounted for one withdrawal on the source chain.",
        analysis: "The PoC demonstrates that a single relayer-signed message results in token minting on multiple destination chains. The bridge's accounting only deducts from the source chain once, but the destination chains each mint independently because the replay check (executed[msgHash]) is chain-local. The attacker effectively gets free tokens equal to (N-1) * transferAmount where N is the number of chains the message is replayed on.",
        next_action: "Quantify the financial impact by analyzing historical bridge transactions to estimate total value at risk from this replay vector."
      },
      {
        phase: "Impact Analysis",
        description: "Calculate the maximum potential loss from the replay attack by analyzing bridge TVL, historical transaction volume, and the number of supported chains.",
        tools: ["dune", "cast", "tenderly"],
        commands: [
          "cast call $BRIDGE_ADDR 'totalSupply()(uint256)' --rpc-url $ETH_RPC_URL",
          "cast call $BRIDGE_ADDR 'getSupportedChains()(uint256[])' --rpc-url $ETH_RPC_URL",
          "tenderly sim tx 0x... --network eth-mainnet --decode-state-changes",
          "dune query run --id replay-impact-estimate --params '{\"bridge_addr\": \"$BRIDGE_ADDR\"}'"
        ],
        expected_output: "Bridge TVL: $47.3M across 6 chains\nSupported chains: [1, 137, 42161, 10, 56, 8453]\nHistorical unique messages (30d): 12,847\nReplay-eligible messages (no chainId in hash): 12,847 (100%)\nMax theoretical loss per message: transferAmount * (numChains - 1)\nEstimated 30-day loss exposure: $14.2M (assuming average replay of 3 chains per message)\nActual exploitable: limited by relayer signature availability and bridge liquidity per chain",
        thinking: "The impact is bounded by two factors: (1) the attacker needs access to valid relayer signatures, which are publicly available on-chain since they're included in every bridge transaction, and (2) each destination chain has limited liquidity, so the attacker can only drain what's available on each chain. However, since signatures are public, anyone could replay them. The real-world impact depends on whether the bridge has sufficient liquidity on each chain to honor the replayed withdrawals. With $47.3M TVL across 6 chains and an average of $1,100 per transaction, the theoretical maximum is enormous, but practical impact is capped by per-chain liquidity pools.",
        analysis: "The severity is Critical. Every bridge transaction is publicly replayable on all other supported chains. The bridge has processed $200M+ in volume over its lifetime, meaning there are thousands of publicly available signatures that can be replayed. The fix is straightforward (add chainId to the message hash) but requires a contract upgrade and migration of the executed mapping. A coordinated attack could drain all liquidity from the bridge simultaneously across all chains.",
        next_action: "Draft the audit report with the replay attack finding as a Critical severity issue, including the PoC, impact analysis, and recommended fix using EIP-712 domain separation."
      },
      {
        phase: "Audit Report Writing",
        description: "Document the cross-chain replay vulnerability with severity classification, attack path, PoC evidence, and remediation steps.",
        tools: ["report_generator", "slither"],
        commands: [
          "report_generator generate --finding replay-attack --severity Critical --swc SWC-121 --cwe CWE-294",
          "slither Bridge.sol --print human-summary,calls-external > report/bridge-analysis.txt",
          "report_generator compile --output audit-report-crosschain-bridge.pdf"
        ],
        expected_output: "Audit Finding #1: CRITICAL - Cross-Chain Bridge Replay Attack\nSWC-121 (Arbitrary Call Risk), CWE-294 (Authentication Bypass by Capture-replay)\nSeverity: Critical (CVSS 9.8)\nAffected: Bridge.sol:verifyMessage(), processMessage()\nRoot Cause: Message hash excludes sourceChainId and destinationChainId\nImpact: Unlimited token minting on any supported chain via replay of public signatures\nPoC: Foundry test in test/ReplayAttack.t.sol - test passes, confirming vulnerability\nRecommendation: Implement EIP-712 domain separation with chainId, add per-chain nonce tracking, migrate executed mapping to include chainId in key",
        thinking: "The report needs to clearly explain why this is a Critical finding: the attack requires no special privileges, uses publicly available data (on-chain signatures), and results in unlimited token minting. The CVSS score should reflect the low attack complexity and high impact. The report should also note that this is not a theoretical vulnerability - the signatures are already on-chain and could be replayed by anyone at any time.",
        analysis: "The finding is well-supported with evidence from code review, static analysis, and a working PoC. The recommended fix using EIP-712 domain separation is industry-standard and would fully remediate the issue. The report should also recommend an emergency pause mechanism while the fix is deployed.",
        next_action: "Finalize the report, ensure all evidence is attached, and communicate the Critical finding to the development team for immediate remediation."
      }
    ],
    tools_involved: ["slither", "foundry", "cast", "anvil", "semgrep", "tenderly", "dune", "solc", "forge", "sigint", "solhint", "report_generator"],
    tags: ["replay-attack", "bridge", "nonce", "cross-chain", "message-verification"],
    cve_references: ["SWC-121", "CWE-294"]
  },
  {
    id: "cross-bridge-signature-replay",
    category: "Cross-Chain & Bridge Vulnerabilities",
    subcategory: "Signature Replay",
    title: "Bridge Signature Replay via Missing Message Hash Uniqueness",
    difficulty: "advanced",
    description: "The bridge uses ECDSA signatures on message hashes but doesn't include the destination chain or a unique nonce, allowing signatures to be replayed across different bridge instances. The relayer signs a message hash that only contains the transfer parameters (amount, recipient, token) without any chain-specific or time-specific uniqueness constraints.",
    target_description: "Multi-chain bridge contract with relayer-based message passing. The bridge uses a set of authorized relayers who sign messages authorizing cross-chain transfers. Signature verification uses ecrecover but the signed message lacks destination chain ID and unique nonce fields.",
    attack_phases: [
      {
        phase: "Code Review & Architecture Analysis",
        description: "Examine the bridge's signature verification flow to determine whether the signed message includes sufficient uniqueness constraints (chain ID, nonce, timestamp) to prevent replay across bridge instances.",
        tools: ["solc", "sigint", "slither"],
        commands: [
          "sigint analyze RelayerBridge.sol --focus 'verifySignature,ecrecover,_hashMessage'",
          "slither RelayerBridge.sol --print human-summary,inheritance",
          "grep -n 'ecrecover\\|_hashMessage\\|chainId\\|block.timestamp' RelayerBridge.sol",
          "slither RelayerBridge.sol --detect unchecked-transfer,weak-prng"
        ],
        expected_output: "RelayerBridge.sol:verifySignature() uses ecrecover(keccak256(abi.encodePacked(amount, recipient, token)), v, r, s). The message hash includes only amount, recipient, and token address - no chainId, no nonce, no timestamp. The signed data is identical regardless of which chain the bridge is deployed on, meaning any signature is valid on every chain.",
        thinking: "The signature scheme is fundamentally broken for cross-chain use. ECDSA signatures are deterministic - if you sign the same message hash with the same key, you get the same signature. Since the message hash doesn't include any chain-specific data, a signature produced for an Ethereum transfer is equally valid on Polygon, Arbitrum, BSC, or any other chain where this bridge contract is deployed. The relayer probably intended to authorize a single transfer on a specific chain, but the signature authorizes unlimited transfers on all chains.",
        analysis: "This is a domain separation failure at the cryptographic level. The signed message should use EIP-712 typed data with a domain that includes chainId and a nonce. Without this, the signature is a bearer token that can be used on any chain. The relayer may not even be aware their signature is being replayed, as the transactions would appear legitimate on the destination chain.",
        next_action: "Use Semgrep to verify the signature construction pattern and check whether any other bridge contracts in the codebase share this vulnerability."
      },
      {
        phase: "Static Analysis & Automated Scanning",
        description: "Scan for ECDSA signature patterns that lack domain separation, chain ID inclusion, or nonce tracking in the signed message.",
        tools: ["semgrep", "slither", "solhint"],
        commands: [
          "semgrep --pattern 'ecrecover(keccak256(abi.encodePacked($A, $B)))' -l solidity .",
          "slither RelayerBridge.sol --detect unauthorized-prng,reentrancy-benign",
          "semgrep --config ethereum/smart-contract Bridge.sol",
          "solhint 'contracts/**/*.sol' --rule 'no-simple-ecrecover'"
        ],
        expected_output: "Semgrep match found in RelayerBridge.sol:156:\necrecover(keccak256(abi.encodePacked(amount, recipient, token)), v, r, s)\n\nMissing: chainId in encodePacked\nMissing: nonce in encodePacked\nMissing: destination chain specification\n\nSlither: No direct ECDSA misuse detected (detector needs custom rule).\nSolhint: Warning - 'Simple ecrecover without domain separator detected at line 156.'",
        thinking: "Semgrep caught the pattern immediately - ecrecover with a simple encodePacked that lacks chain-specific data. Solhint also flagged it with the no-simple-ecrecover rule. The fact that multiple tools independently identified this pattern gives high confidence. However, Slither didn't flag it because its default detectors don't specifically target missing domain separators in cross-chain contexts - this would need a custom Slither detector.",
        analysis: "The automated scanning confirms the manual finding. The vulnerability pattern is: ecrecover + keccak256 + encodePacked without chainId or nonce. This pattern appears in the bridge's core verification function and affects all cross-chain transfers. The fix requires changing the signed message structure to include domain-specific fields.",
        next_action: "Develop a PoC test that demonstrates signature replay by taking a signature from one chain's test and replaying it on another chain's fork."
      },
      {
        phase: "Proof of Concept Development",
        description: "Build a Foundry test that demonstrates ECDSA signature replay across two bridge instances on different simulated chains.",
        tools: ["foundry", "cast", "anvil", "forge"],
        commands: [
          "anvil --fork-url $POLYGON_RPC_URL --fork-block-number 55000000 --port 8546 &",
          "forge test --match-test testSignatureReplayAcrossChains -vvvv --gas-report",
          "cast sign '0x$(cast keccak $(cast abi-encode \"hashMessage(uint256,address,address)\" 1000 0xUser 0xToken))' $RELAYER_KEY",
          "cast call $BRIDGE_ADDR 'relayerNonce()(uint256)' --rpc-url http://127.0.0.1:8545"
        ],
        expected_output: "forge test output:\n[PASS] testSignatureReplayAcrossChains() (gas: 987654)\nLogs:\n  Chain 1 (Ethereum fork): processed transfer 1000 tokens to 0xUser\n    Signature: 0x1a2b3c... (from relayer 0xRelayer)\n    msgHash: 0xdef456...\n  Chain 2 (Polygon fork): REPLAYED - same signature accepted\n    Signature: 0x1a2b3c... (identical to Chain 1)\n    msgHash: 0xdef456... (identical to Chain 1)\n  Recipient balance on Chain 1: +1000 tokens\n  Recipient balance on Chain 2: +1000 tokens (DUPLICATE)\n  Total extracted: 2000 tokens from 1 relayer signature",
        thinking: "The PoC creates two anvil forks simulating Ethereum and Polygon. I'll sign a message with the relayer's private key for a transfer on Ethereum, process it on the Ethereum fork, then submit the identical signature on the Polygon fork. Since the message hash is identical (no chainId in the hash), the ecrecover will return the same relayer address on both chains, and the signature will be accepted. The test verifies the recipient's balance increases on both chains.",
        analysis: "The PoC confirms that a single relayer signature authorizes transfers on all chains. This is more dangerous than the replay attack because the relayer may only have intended to authorize a transfer on one specific chain. The attacker doesn't need to wait for a message to be processed on the source chain - they can proactively submit the signature on any chain at any time.",
        next_action: "Analyze the impact by determining how many valid relayer signatures exist on-chain and how much value they could extract if replayed across all supported chains."
      },
      {
        phase: "Impact Analysis",
        description: "Assess the scope of the signature replay vulnerability by enumerating all on-chain relayer signatures and estimating extractable value across supported chains.",
        tools: ["dune", "cast", "tenderly"],
        commands: [
          "cast logs --address $BRIDGE_ADDR --from-block 0 --to-block latest 'MessageSigned(bytes32,bytes)' --rpc-url $ETH_RPC_URL | wc -l",
          "dune query run --id signature-replay-scope --params '{\"bridge\": \"$BRIDGE_ADDR\", \"chains\": \"[1,137,42161,10,56]\"}'",
          "tenderly sim tx 0x... --network eth-mainnet --trace",
          "cast call $BRIDGE_ADDR 'getRelayerBalance(address)(uint256)' $RELAYER --rpc-url $ETH_RPC_URL"
        ],
        expected_output: "Total relayer signatures on-chain: 8,432\nUnique message hashes: 8,432 (all unique on source chain)\nReplay-eligible on other chains: 8,432 (100%)\nSupported destination chains: 5\nMax extractable value: $8.7M (sum of all signed transfer amounts across all chains)\nRelayer liquidity per chain: $1.2M average\nPractical attack ceiling: $6M (limited by per-chain liquidity)",
        thinking: "The impact analysis reveals that every single relayer signature ever produced is replayable on all other chains. With 8,432 signatures on-chain, an attacker has a large catalog of valid signatures to replay. The total value signed across all transactions is $8.7M, but the practical limit is constrained by how much liquidity exists on each destination chain. Even at $1.2M average per chain, replaying across 5 chains could extract $6M. The attack is trivial to execute - anyone can copy signatures from Etherscan and submit them on other chains.",
        analysis: "The vulnerability is Critical with widespread impact. Every historical transaction provides a replayable signature. The attack requires zero special access - signatures are public data. The bridge's total value locked across all chains is at risk. The fix requires an urgent contract upgrade and potentially pausing the bridge during the upgrade window to prevent in-flight attacks.",
        next_action: "Write the audit report documenting the signature replay vulnerability as Critical, with PoC evidence, impact quantification, and EIP-712 remediation guidance."
      },
      {
        phase: "Audit Report Writing",
        description: "Document the signature replay finding with severity, attack methodology, evidence, and recommended fix using EIP-712 domain separation.",
        tools: ["report_generator", "slither"],
        commands: [
          "report_generator generate --finding signature-replay --severity Critical --swc SWC-117 --cwe CWE-347",
          "slither RelayerBridge.sol --print human-summary,calls-external > report/relayer-bridge-analysis.txt",
          "report_generator compile --output audit-report-signature-replay.pdf"
        ],
        expected_output: "Audit Finding #1: CRITICAL - Bridge Signature Replay via Missing Message Hash Uniqueness\nSWC-117 (Signature Malleability), CWE-347 (Improper Verification of Cryptographic Signature)\nSeverity: Critical (CVSS 9.4)\nAffected: RelayerBridge.sol:verifySignature()\nRoot Cause: ECDSA signed message excludes destination chainId and nonce\nImpact: Any relayer signature is valid on all supported chains, enabling duplicate token minting\nPoC: Foundry test testSignatureReplayAcrossChains - confirms replay succeeds\nRecommendation: Migrate to EIP-712 typed data signing with domain including chainId, contract address, and per-relayer nonce. Add replay protection mapping per chain.",
        thinking: "The report should emphasize that this vulnerability affects every signature ever produced by the relayer system. The fix isn't just a code change - it requires a protocol upgrade and potentially a migration period where old signatures are grandfathered in while new signatures use the EIP-712 format. The report should also recommend implementing an emergency pause function.",
        analysis: "The finding is well-documented with code analysis, static scanning evidence, a working PoC, and quantified impact. The EIP-712 recommendation is the industry standard fix. The report should be delivered immediately given the Critical severity and the fact that attack data (signatures) is already publicly available on-chain.",
        next_action: "Finalize the report with all supporting evidence and deliver to the development team with recommended emergency procedures."
      }
    ],
    tools_involved: ["slither", "foundry", "cast", "anvil", "semgrep", "tenderly", "dune", "solc", "forge", "sigint", "solhint", "report_generator"],
    tags: ["signature-replay", "ecdsa", "bridge", "cross-chain"],
    cve_references: ["SWC-117", "CWE-347"]
  },
  {
    id: "cross-bridge-fee-bypass",
    category: "Cross-Chain & Bridge Vulnerabilities",
    subcategory: "Fee Bypass",
    title: "Bridge Fee Bypass via Integer Underflow in Fee Calculation",
    difficulty: "advanced",
    description: "The bridge fee calculation subtracts a fee percentage from the transfer amount but doesn't check for underflow in the fee computation, allowing an attacker to craft transfer amounts that result in zero or negative fees. When the fee percentage exceeds 100% due to a manipulation of the fee basis points, the subtraction underflows and the attacker effectively receives more tokens than they deposited.",
    target_description: "Cross-chain bridge with a dynamic fee mechanism where fees are calculated as a percentage of the transfer amount. The feeBps (basis points) variable can be manipulated through governance or oracle feeds, and the fee calculation uses unchecked arithmetic in Solidity 0.8+ that doesn't revert on underflow when wrapped in an unchecked block.",
    attack_phases: [
      {
        phase: "Code Review & Architecture Analysis",
        description: "Review the bridge's fee calculation logic to identify integer underflow vulnerabilities in the fee computation, particularly in unchecked arithmetic blocks.",
        tools: ["solc", "sigint", "slither"],
        commands: [
          "sigint analyze BridgeFee.sol --focus 'calculateFee,transferWithFee,_computeFee'",
          "slither BridgeFee.sol --print human-summary,vars-written",
          "grep -n 'unchecked\\|feeBps\\|BASIS_POINTS\\|calculateFee' BridgeFee.sol",
          "slither BridgeFee.sol --detect unchecked-lowlevel,incorrect-equality"
        ],
        expected_output: "BridgeFee.sol:calculateFee() uses an unchecked block:\n  unchecked {\n    uint256 fee = (amount * feeBps) / 10000;\n    uint256 netAmount = amount - fee;\n  }\n\nWhen feeBps > 10000 (100%), the fee exceeds the amount, but the subtraction in the unchecked block wraps around, producing a massive netAmount. The feeBps variable is settable by governance with no upper bound check.",
        thinking: "The unchecked block in the fee calculation is dangerous. In Solidity 0.8+, arithmetic outside unchecked blocks reverts on overflow/underflow. But inside an unchecked block, the subtraction wraps. If feeBps can be set above 10000 (100%), then fee > amount, and amount - fee wraps to a very large number (2^256 - (fee - amount)). The attacker could potentially manipulate feeBps through a governance proposal or oracle manipulation to trigger this condition.",
        analysis: "The vulnerability exists in the unchecked arithmetic block that performs the fee subtraction. While the unchecked block may have been added to save gas, it removes the automatic overflow protection. The feeBps parameter lacks an upper bound check, meaning it can be set to values that cause the fee to exceed the transfer amount. The result is not just a fee bypass but a potential token minting exploit where the attacker receives far more tokens than they deposited.",
        next_action: "Use Semgrep to search for other unchecked arithmetic operations in the codebase that might have similar underflow vulnerabilities."
      },
      {
        phase: "Static Analysis & Automated Scanning",
        description: "Scan for unchecked arithmetic blocks and fee calculation patterns that lack bounds checking on fee parameters.",
        tools: ["semgrep", "slither", "solhint"],
        commands: [
          "semgrep --pattern 'unchecked { ... $AMOUNT - $FEE ... }' -l solidity .",
          "slither BridgeFee.sol --detect unchecked-send,arbitrary-send-eth",
          "semgrep --pattern '$X * $Y / 10000' --lang solidity .",
          "solhint BridgeFee.sol --rule 'no-unchecked-arithmetic'"
        ],
        expected_output: "Semgrep: Match found in BridgeFee.sol:89 - unchecked block with subtraction:\n  unchecked { uint256 netAmount = amount - fee; }\n  No bounds check on feeBps before calculation.\n\nSlither: Info - 'BridgeFee.calculateFee() uses unchecked arithmetic. Verify that fee <= amount.'\nSolhint: Warning - 'unchecked block at line 89 performs subtraction without bounds check on operands.'\n\nAdditional: No require() or assert() validating feeBps <= 10000.",
        thinking: "Multiple tools independently identified the unchecked arithmetic issue. Semgrep found the specific pattern, Slither flagged the unchecked usage, and Solhint warned about the lack of bounds checking. The consistent findings across tools confirm this is a real vulnerability. The critical detail is that feeBps has no maximum value constraint, so it can be set to trigger the underflow.",
        analysis: "The static analysis confirms that the fee calculation is vulnerable to integer underflow when feeBps > 10000. The unchecked block was likely added for gas optimization but removes the safety net of Solidity 0.8's built-in overflow protection. The feeBps parameter needs a maximum bound check (require(feeBps <= 10000)) and the unchecked block should be removed or the subtraction should be performed outside the unchecked scope.",
        next_action: "Build a Foundry PoC that demonstrates the fee bypass by setting feeBps above 10000 and showing that the netAmount calculation wraps to a very large value."
      },
      {
        phase: "Proof of Concept Development",
        description: "Create a Foundry test demonstrating the fee bypass via integer underflow, showing that an attacker can receive more tokens than deposited by manipulating the fee basis points.",
        tools: ["foundry", "cast", "anvil", "forge"],
        commands: [
          "anvil --fork-url $ETH_RPC_URL --fork-block-number 19000000 &",
          "cast send $GOV_ADDR 'setFeeBps(uint256)' 15000 --from $ATTACKER --rpc-url http://127.0.0.1:8545",
          "forge test --match-test testFeeBypassUnderflow -vvvv",
          "cast call $BRIDGE_ADDR 'calculateFee(uint256)(uint256)' 1000 --rpc-url http://127.0.0.1:8545"
        ],
        expected_output: "forge test output:\n[PASS] testFeeBypassUnderflow() (gas: 543210)\nLogs:\n  Transfer amount: 1000 tokens\n  Fee BPS set to: 15000 (150%)\n  Calculated fee: 1500 tokens\n  netAmount = 1000 - 1500 (in unchecked block)\n  netAmount (underflow): 115792089237316195423570985008687907853269984665640564039457584007913129638935\n  Attacker received: 115792089237316195423570985008687907853269984665640564039457584007913129638935 tokens\n  Expected: 0 tokens (transfer should have failed)\n  Bridge balance drained: true",
        thinking: "The PoC sets feeBps to 15000 (150%) which means the fee (1500) exceeds the transfer amount (1000). The subtraction in the unchecked block wraps around to 2^256 - 500, which is essentially the maximum uint256 value. The bridge then attempts to transfer this astronomical amount, which will either drain the entire bridge balance or fail due to insufficient balance. Either way, the fee bypass is demonstrated - the attacker pays no fee and potentially extracts all bridge liquidity.",
        analysis: "The PoC demonstrates a catastrophic vulnerability. The unchecked arithmetic causes the netAmount to wrap to near-max uint256, which would drain the bridge's entire balance if the token transfer doesn't revert due to insufficient balance. Even if the transfer reverts, the attacker has still bypassed the fee entirely. The fix is simple: add a bounds check (require(feeBps <= 10000)) before the calculation and remove the unchecked block from the subtraction.",
        next_action: "Quantify the financial impact by analyzing the bridge's current TVL and determining the maximum extractable value through this fee bypass mechanism."
      },
      {
        phase: "Impact Analysis",
        description: "Determine the maximum financial impact of the fee bypass by analyzing the bridge's TVL, fee configuration mechanisms, and potential attack vectors.",
        tools: ["dune", "cast", "tenderly"],
        commands: [
          "cast call $BRIDGE_ADDR 'totalLocked()(uint256)' --rpc-url $ETH_RPC_URL",
          "cast call $GOV_ADDR 'feeBps()(uint256)' --rpc-url $ETH_RPC_URL",
          "dune query run --id fee-bypass-impact --params '{\"bridge\": \"$BRIDGE_ADDR\"}'",
          "tenderly sim tx 0x... --network eth-mainnet --decode-state-changes"
        ],
        expected_output: "Bridge TVL: $23.1M\nCurrent feeBps: 30 (0.3%)\nGovernance authority: 3-of-5 multisig\nTime lock on governance: 48 hours\nMax extractable via underflow: $23.1M (entire TVL)\nAttack prerequisites: Control of governance multisig OR oracle manipulation to set feeBps > 10000\nIf governance compromised: Immediate full drain possible\nIf oracle manipulated: Partial drain depending on oracle update frequency",
        thinking: "The impact depends on how feeBps is controlled. If it's set by a governance multisig, the attacker would need to compromise the multisig first. If it's set by an oracle, the attacker might manipulate the oracle feed. The worst case is total TVL drain ($23.1M). Even in the best case (oracle manipulation), the attacker could set feeBps high enough during the oracle update window to bypass fees on multiple transactions. The 48-hour timelock on governance provides some protection, but if the multisig is compromised, the attacker can schedule the fee change and execute it after the timelock expires.",
        analysis: "The vulnerability is High severity (not Critical) if governance is well-secured, because the attacker needs to first compromise governance. However, it becomes Critical if the oracle feed can be manipulated or if there's a flash loan attack that temporarily controls the fee-setting mechanism. The fix is straightforward and low-risk: add a require(feeBps <= 10000) check and remove the unchecked block.",
        next_action: "Draft the audit report with the fee bypass finding, classifying severity based on the governance/oracle security model, and providing the simple remediation."
      },
      {
        phase: "Audit Report Writing",
        description: "Document the fee bypass vulnerability with severity assessment, PoC evidence, impact analysis, and recommended fix.",
        tools: ["report_generator", "slither"],
        commands: [
          "report_generator generate --finding fee-bypass --severity High --swc SWC-101 --cwe CWE-191",
          "slither BridgeFee.sol --print human-summary,vars-written > report/bridge-fee-analysis.txt",
          "report_generator compile --output audit-report-fee-bypass.pdf"
        ],
        expected_output: "Audit Finding #2: HIGH - Bridge Fee Bypass via Integer Underflow in Fee Calculation\nSWC-101 (Integer Overflow/Underflow), CWE-191 (Integer Underflow)\nSeverity: High (CVSS 8.2) - Critical if governance/oracle compromised\nAffected: BridgeFee.sol:calculateFee()\nRoot Cause: Unchecked arithmetic block allows fee subtraction to underflow when feeBps > 10000\nImpact: Attacker can receive near-max uint256 token amount, draining bridge liquidity\nPoC: Foundry test testFeeBypassUnderflow - confirms underflow produces massive netAmount\nRecommendation: Add require(feeBps <= 10000, 'Fee exceeds 100%') before calculation. Remove unchecked block from subtraction. Consider using SafeMath or Solidity 0.8 default checked arithmetic.",
        thinking: "The report should clearly explain the unchecked arithmetic mechanism and why it's dangerous in this context. The severity depends on the governance security model, so the report should document both scenarios. The recommended fix is simple and has minimal gas cost impact. The report should also recommend auditing the governance contract and oracle feed for additional attack vectors.",
        analysis: "The finding is well-supported with code analysis, static scanning results, and a working PoC. The fix is straightforward and non-breaking. The report should be delivered promptly so the development team can implement the fix before any governance compromise or oracle manipulation occurs.",
        next_action: "Finalize the report and deliver to the development team with the recommended fix code snippet."
      }
    ],
    tools_involved: ["slither", "foundry", "cast", "anvil", "semgrep", "tenderly", "dune", "solc", "forge", "sigint", "solhint", "report_generator"],
    tags: ["fee-bypass", "integer-underflow", "bridge", "cross-chain"],
    cve_references: ["SWC-101", "CWE-191"]
  },
  {
    id: "cross-message-spoofing",
    category: "Cross-Chain & Bridge Vulnerabilities",
    subcategory: "Message Spoofing",
    title: "Cross-Chain Message Spoofing via Insufficient Source Chain Verification",
    difficulty: "expert",
    description: "The bridge verifies the signature of the message relayer but doesn't verify the claimed source chain ID, allowing an attacker to submit a valid signature from a testnet as if it came from mainnet. The bridge trusts the sourceChainId parameter provided in the message without independently verifying it against the relayer's authorized chain list, enabling testnet signatures to be treated as mainnet signatures.",
    target_description: "Cross-chain bridge that accepts messages from relayers with a sourceChainId field. The bridge verifies the relayer's ECDSA signature but trusts the sourceChainId value provided in the message payload without validating that the relayer is authorized for that specific chain. Testnet and mainnet relayers may share the same signing key.",
    attack_phases: [
      {
        phase: "Code Review & Architecture Analysis",
        description: "Analyze the bridge's source chain verification logic to determine whether the sourceChainId in the message payload is independently verified or merely trusted from the relayer's submission.",
        tools: ["solc", "sigint", "slither"],
        commands: [
          "sigint analyze MessageBridge.sol --focus 'processMessage,verifySourceChain,_validateChainId'",
          "slither MessageBridge.sol --print human-summary,calls-external,vars-written",
          "grep -n 'sourceChainId\\|_sourceChain\\|authorizedChains\\|chainId' MessageBridge.sol",
          "slither MessageBridge.sol --detect missing-zero-check,incorrect-equality"
        ],
        expected_output: "MessageBridge.sol:processMessage() accepts sourceChainId as a message parameter:\n  function processMessage(uint256 sourceChainId, bytes calldata payload, bytes calldata signature)\n\nThe function verifies the signature but does NOT validate that sourceChainId matches the relayer's authorized chain list. There is no mapping of relayer => authorized chains. A relayer authorized for Goerli testnet can submit messages claiming to be from Ethereum mainnet (chain ID 1), and the bridge will accept them.",
        thinking: "The bridge's critical flaw is that it trusts the sourceChainId provided by the caller rather than independently determining it. The relayer signs a message that includes sourceChainId, but the bridge doesn't check whether this relayer is actually authorized to relay messages from that chain. If the same relayer key is used on both testnet and mainnet (a common operational mistake), an attacker can take a testnet relayer signature and submit it on the mainnet bridge claiming the message came from mainnet. The signature verifies correctly, and the sourceChainId is accepted without validation.",
        analysis: "This is a classic trust boundary violation. The bridge should independently verify the source chain through the relayer's authorization configuration, not trust the caller-provided value. The fix requires adding a mapping of relayer => authorized chain IDs and validating the sourceChainId against this mapping before processing the message. Additionally, relayer keys should be unique per chain to prevent cross-chain signature reuse.",
        next_action: "Use Semgrep to search for patterns where sourceChainId is accepted as a function parameter without validation against an authorization mapping."
      },
      {
        phase: "Static Analysis & Automated Scanning",
        description: "Scan for missing source chain validation patterns, untrusted input used for chain identification, and relayer authorization gaps.",
        tools: ["semgrep", "slither", "solhint"],
        commands: [
          "semgrep --pattern 'function processMessage(uint256 sourceChainId, ...)' -l solidity .",
          "slither MessageBridge.sol --detect unchecked-transfer,reentrancy-benign",
          "semgrep --pattern 'require($RELAYER in authorizedRelayers)' --lang solidity . | grep -v 'sourceChainId'",
          "solhint MessageBridge.sol --rule 'validate-external-input'"
        ],
        expected_output: "Semgrep: Found processMessage() accepting sourceChainId as untrusted input at MessageBridge.sol:78.\nNo validation of sourceChainId against relayer authorization found.\n\nSlither: Info - 'MessageBridge.processMessage() uses external input (sourceChainId) for access control decision without validation.'\n\nSolhint: Warning - 'External parameter sourceChainId used without validation at line 78. Consider validating against authorized chain mapping.'",
        thinking: "All three tools identified aspects of the vulnerability. Semgrep found the function accepting sourceChainId as input, Slither flagged the use of external input for access control decisions, and Solhint specifically warned about the unvalidated parameter. The key finding is that there's no require(sourceChainId in authorizedChains[relayer]) check anywhere in the codebase.",
        analysis: "The static analysis confirms that the sourceChainId is accepted without validation. This means any relayer can claim messages from any chain, and the bridge will process them as long as the signature is valid. Combined with the common practice of using the same relayer key across testnet and mainnet, this enables testnet-to-mainnet message spoofing.",
        next_action: "Develop a PoC that demonstrates mainnet token minting using a testnet relayer signature, showing that the bridge accepts the spoofed sourceChainId."
      },
      {
        phase: "Proof of Concept Development",
        description: "Create a Foundry test that demonstrates mainnet message spoofing by submitting a testnet relayer signature with a forged mainnet sourceChainId.",
        tools: ["foundry", "cast", "anvil", "forge"],
        commands: [
          "anvil --fork-url $GOERLI_RPC_URL --fork-block-number 10000000 --port 8545 &",
          "cast sign '0x$(cast keccak $(cast abi-encode \"message(uint256,uint256,address)\" 5 1000 0xUser))' $TESTNET_RELAYER_KEY",
          "forge test --match-test testMainnetSpoofViaTestnetSignature -vvvv",
          "cast call $BRIDGE_ADDR 'isRelayerAuthorized(address,uint256)(bool)' $RELAYER 1 --rpc-url http://127.0.0.1:8545"
        ],
        expected_output: "forge test output:\n[PASS] testMainnetSpoofViaTestnetSignature() (gas: 876543)\nLogs:\n  Testnet relayer signature: 0x7a8b9c... (signed on Goerli, chainId 5)\n  Forged sourceChainId: 1 (Ethereum mainnet)\n  Bridge verification: signature valid for relayer 0xRelayer\n  Source chain check: NONE (sourceChainId accepted as-is)\n  Message processed: minted 1000 tokens on mainnet bridge\n  Result: Testnet signature authorized mainnet token mint\n  Attacker balance increase: +1000 tokens",
        thinking: "The PoC signs a message on a Goerli fork using the testnet relayer key, then submits it to the mainnet bridge with sourceChainId set to 1 (mainnet). Since the bridge doesn't validate that the relayer is authorized for chain ID 1, and the signature is cryptographically valid, the message is processed as if it came from mainnet. The testnet relayer key being the same as the mainnet relayer key is the operational mistake that makes this attack possible.",
        analysis: "The PoC demonstrates that a testnet relayer signature can be used to mint tokens on the mainnet bridge. The attack requires: (1) knowledge of a relayer key used on testnet, (2) the ability to construct a valid message payload, and (3) submission to the mainnet bridge. The signature verification passes because the key is the same, and the sourceChainId is trusted. This is a Critical vulnerability because it enables unauthorized token minting on mainnet.",
        next_action: "Assess the impact by identifying all relayers that share keys between testnet and mainnet, and estimating the potential value extraction."
      },
      {
        phase: "Impact Analysis",
        description: "Determine the scope of the message spoofing vulnerability by enumerating relayers with shared testnet/mainnet keys and estimating extractable value.",
        tools: ["dune", "cast", "tenderly"],
        commands: [
          "cast logs --address $BRIDGE_ADDR --from-block 0 --to-block latest 'RelayerAdded(address)' --rpc-url $ETH_RPC_URL",
          "dune query run --id shared-relayer-keys --params '{\"bridge\": \"$BRIDGE_ADDR\"}'",
          "tenderly sim tx 0x... --network eth-mainnet --trace",
          "cast call $BRIDGE_ADDR 'totalSupply()(uint256)' --rpc-url $ETH_RPC_URL"
        ],
        expected_output: "Total active relayers: 7\nRelayers with shared testnet/mainnet keys: 4 (57%)\nBridge TVL (mainnet): $31.5M\nPer-relayer daily volume: $2.1M average\nSpoofable value per compromised relayer: $2.1M/day\nTotal daily spoofable value: $8.4M\nHistorical relayer signatures on testnet: publicly available\nAttack cost: Zero (testnet signatures are public data)",
        thinking: "The impact is severe. Over half of the active relayers share keys between testnet and mainnet, meaning an attacker can spoof messages from any of these relayers. With $31.5M TVL and $8.4M in daily spoofable value, the bridge is at significant risk. The attack cost is zero because testnet signatures are public data on Goerli/Sepolia. An attacker doesn't need to compromise any keys - they just need to copy public testnet transactions and replay them on mainnet with a forged sourceChainId.",
        analysis: "This is a Critical vulnerability. The combination of missing source chain validation and shared relayer keys between testnet and mainnet creates an easily exploitable attack vector. The fix requires both code changes (add sourceChainId validation) and operational changes (use unique keys per chain). The bridge should be paused immediately until the fix is deployed.",
        next_action: "Write the audit report documenting the message spoofing vulnerability as Critical, with PoC, impact analysis, and both code and operational remediation steps."
      },
      {
        phase: "Audit Report Writing",
        description: "Document the message spoofing vulnerability with severity, attack path, PoC evidence, and recommended code and operational fixes.",
        tools: ["report_generator", "slither"],
        commands: [
          "report_generator generate --finding message-spoofing --severity Critical --swc SWC-119 --cwe CWE-287",
          "slither MessageBridge.sol --print human-summary,calls-external > report/message-bridge-analysis.txt",
          "report_generator compile --output audit-report-message-spoofing.pdf"
        ],
        expected_output: "Audit Finding #1: CRITICAL - Cross-Chain Message Spoofing via Insufficient Source Chain Verification\nSWC-119 (Missing Origin Validation), CWE-287 (Improper Authentication)\nSeverity: Critical (CVSS 9.6)\nAffected: MessageBridge.sol:processMessage()\nRoot Cause: sourceChainId accepted as untrusted function parameter without validation against relayer authorization\nImpact: Testnet relayer signatures can be used to mint tokens on mainnet bridge\nPoC: Foundry test testMainnetSpoofViaTestnetSignature - confirms spoofing succeeds\nRecommendation: (1) Add require(authorizedChains[relayer][sourceChainId]) before processing. (2) Use unique relayer keys per chain. (3) Add chain ID to the signed message payload. (4) Pause bridge until fix is deployed.",
        thinking: "The report needs to emphasize that this is not just a code issue but also an operational one. Even after the code fix is deployed, relayers must use unique keys per chain to fully remediate the risk. The report should also recommend an audit of all relayer key management practices.",
        analysis: "The finding is Critical with clear evidence from code review, static analysis, and a working PoC. The fix requires both code changes and operational improvements. The report should be delivered immediately with a recommendation to pause the bridge.",
        next_action: "Finalize the report with all supporting evidence and deliver to the development team with emergency pause recommendation."
      }
    ],
    tools_involved: ["slither", "foundry", "cast", "anvil", "semgrep", "tenderly", "dune", "solc", "forge", "sigint", "solhint", "report_generator"],
    tags: ["message-spoofing", "source-chain-verification", "bridge", "testnet-exploit"],
    cve_references: ["SWC-119", "CWE-287"]
  },
  {
    id: "cross-adapter-exploit",
    category: "Cross-Chain & Bridge Vulnerabilities",
    subcategory: "Adapter Exploit",
    title: "Bridge Adapter Exploitation via Unvalidated Message Payload Structure",
    difficulty: "advanced",
    description: "The bridge adapter deserializes incoming cross-chain messages without validating the payload structure, allowing crafted payloads to trigger unintended code paths through field overlap. When the adapter uses abi.decode on untrusted message data without verifying the decoded structure matches the expected format, an attacker can craft payloads where fields overlap and trigger arbitrary function calls or state corruption.",
    target_description: "Bridge adapter contract that receives serialized messages from a cross-chain messaging protocol. The adapter uses abi.decode to deserialize the payload into a struct but does not validate that the decoded data matches the expected structure, version, or length before processing.",
    attack_phases: [
      {
        phase: "Code Review & Architecture Analysis",
        description: "Examine the bridge adapter's message deserialization logic to identify whether abi.decode is performed on untrusted input without structural validation of the decoded data.",
        tools: ["solc", "sigint", "slither"],
        commands: [
          "sigint analyze BridgeAdapter.sol --focus 'decodeMessage,processPayload,deserializeMessage'",
          "slither BridgeAdapter.sol --print human-summary,calls-external,vars-written",
          "grep -n 'abi.decode\\|abi.decodeWithSelector\\|payload.length\\|_payloadVersion' BridgeAdapter.sol",
          "slither BridgeAdapter.sol --detect arbitrary-send-eth,delegatecall"
        ],
        expected_output: "BridgeAdapter.sol:decodeMessage() decodes untrusted payload without validation:\n  function processMessage(bytes calldata payload) external {\n    Message memory msg = abi.decode(payload, (Message));\n    // No validation of msg.version, msg.payloadType, or payload.length\n    _handleMessage(msg);\n  }\n\nThe Message struct has a version field but it's never validated. The payload can be crafted to decode into different struct layouts, causing field overlap where one field's bytes are interpreted as a different field's type.",
        thinking: "The adapter blindly decodes any bytes payload into the Message struct without checking: (1) whether the payload length matches the expected struct size, (2) whether the version field is valid, (3) whether the payloadType is recognized. This means an attacker can craft a payload where the bytes are interpreted differently than intended. For example, if the Message struct has (uint256 amount, address recipient, bytes data), an attacker could craft a payload where the 'data' field overlaps with function selector bytes, potentially triggering arbitrary function calls if the adapter uses delegatecall or low-level calls based on the decoded data.",
        analysis: "The vulnerability is a classic deserialization issue. Without validating the payload structure, the adapter processes corrupted data as if it were legitimate. The most dangerous scenario is when the decoded message triggers external calls based on the decoded fields, as crafted payloads could redirect these calls to attacker-controlled contracts. The fix requires adding payload validation: check payload length, version, and payloadType before decoding, and validate the decoded fields after decoding.",
        next_action: "Use Semgrep to search for abi.decode patterns on untrusted input without subsequent validation of the decoded fields."
      },
      {
        phase: "Static Analysis & Automated Scanning",
        description: "Scan for unvalidated abi.decode patterns, missing payload length checks, and untrusted input used in external calls after deserialization.",
        tools: ["semgrep", "slither", "solhint"],
        commands: [
          "semgrep --pattern 'abi.decode($PAYLOAD, ...)' -l solidity .",
          "slither BridgeAdapter.sol --detect arbitrary-send-eth,controlled-delegatecall",
          "semgrep --pattern '$X = abi.decode($Y, ($STRUCT)); $Z.$FUNC($X)' --lang solidity .",
          "solhint BridgeAdapter.sol --rule 'validate-decoded-input'"
        ],
        expected_output: "Semgrep: Found abi.decode on untrusted payload at BridgeAdapter.sol:134.\nNo validation of decoded struct fields found before usage.\nMatch: decoded data used in external call at line 145: _handleMessage(msg)\n\nSlither: Warning - 'BridgeAdapter.processMessage() decodes external input and uses it in external call at line 145. Verify decoded data integrity.'\n\nSolhint: Warning - 'abi.decode without payload validation at line 134. Add length and version checks before decoding.'",
        thinking: "The tools consistently identified the unvalidated abi.decode pattern. Semgrep found both the decode and the subsequent external call, Slither flagged the external input flowing into an external call, and Solhint recommended adding validation. The chain of trust is broken at the decode step - the adapter trusts the payload structure without any verification.",
        analysis: "Static analysis confirms that the adapter processes untrusted payloads without structural validation. The decoded data flows directly into message handling logic that may trigger external calls. An attacker can craft payloads that decode into unexpected values, potentially redirecting calls, corrupting state, or extracting funds. The fix is to add validation before and after decoding.",
        next_action: "Build a Foundry PoC that crafts a malicious payload with overlapping fields to demonstrate unintended behavior in the adapter."
      },
      {
        phase: "Proof of Concept Development",
        description: "Create a Foundry test that crafts a malicious payload with overlapping fields to trigger unintended code paths in the bridge adapter.",
        tools: ["foundry", "cast", "anvil", "forge"],
        commands: [
          "anvil --fork-url $ETH_RPC_URL --fork-block-number 19000000 &",
          "cast abi-encode \"craftPayload(uint256,address,bytes32,bytes)\" 1 0xAttacker 0x... \"0x...\"",
          "forge test --match-test testAdapterPayloadExploit -vvvv",
          "cast call $ADAPTER_ADDR 'processMessage(bytes)(bool)' $CRAFTED_PAYLOAD --rpc-url http://127.0.0.1:8545"
        ],
        expected_output: "forge test output:\n[PASS] testAdapterPayloadExploit() (gas: 654321)\nLogs:\n  Crafted payload: 0x<crafted bytes with field overlap>\n  Decoded as Message: {version: 0, amount: 0x<attacker address as uint>, recipient: 0x<function selector>, data: 0x<calldata>}\n  Adapter processed: external call to attacker contract with crafted calldata\n  Result: Adapter executed arbitrary call controlled by attacker\n  State change: attackerBalance increased by 5000 tokens\n  Expected behavior: should have rejected invalid payload",
        thinking: "The PoC crafts a payload where the bytes are carefully constructed so that when abi.decode interprets them as a Message struct, the fields contain attacker-controlled values. The 'amount' field contains the attacker's address (as a uint256), the 'recipient' field contains a function selector, and the 'data' field contains calldata. When the adapter processes this decoded message, it makes an external call based on the decoded fields, effectively executing an attacker-controlled call. This demonstrates how unvalidated deserialization can lead to arbitrary call execution.",
        analysis: "The PoC demonstrates that unvalidated deserialization in the bridge adapter leads to arbitrary external call execution. The attacker crafts a payload that, when decoded, contains values that redirect the adapter's behavior to the attacker's benefit. This is a High severity finding because it requires knowledge of the adapter's internal struct layout to craft the exploit payload, but the struct definition is public.",
        next_action: "Quantify the impact by analyzing what external calls the adapter can make and what state changes an attacker could trigger through crafted payloads."
      },
      {
        phase: "Impact Analysis",
        description: "Assess the maximum impact of the adapter payload exploit by analyzing the adapter's external call capabilities, token approvals, and state modification potential.",
        tools: ["dune", "cast", "tenderly"],
        commands: [
          "cast call $ADAPTER_ADDR 'getApprovedSpender()(address)' --rpc-url $ETH_RPC_URL",
          "cast call $ADAPTER_ADDR 'getExternalCallTargets()(address[])' --rpc-url $ETH_RPC_URL",
          "dune query run --id adapter-impact --params '{\"adapter\": \"$ADAPTER_ADDR\"}'",
          "tenderly sim tx 0x... --network eth-mainnet --decode-state-changes"
        ],
        expected_output: "Adapter token approvals: $12.4M (USDC, WETH, DAI)\nExternal call targets: Bridge contract, Token contract, Oracle contract\nMax extractable via crafted payload: $12.4M (all approved tokens)\nAdapter state variables modifiable: 8 of 12\nCritical state: bridgePaused (can be set to false), relayerNonce (can be reset)\nAttack complexity: Medium (requires struct layout knowledge)\nExploitability: High (struct layout is public)",
        thinking: "The adapter has $12.4M in token approvals and can make external calls to critical contracts. A crafted payload could potentially: (1) redirect token transfers to the attacker, (2) modify the relayer nonce to enable replay attacks, (3) disable the bridge pause mechanism. The attack requires knowledge of the struct layout, but since the contract is open source, this information is publicly available. The complexity is Medium because the attacker needs to understand the struct layout and craft the payload bytes correctly.",
        analysis: "The vulnerability is High severity with potential for $12.4M in token extraction. The adapter's broad token approvals and external call capabilities make it a high-value target. The fix requires adding payload validation: check length, version, and payloadType before decoding, and validate all decoded fields after decoding before using them in external calls.",
        next_action: "Draft the audit report with the adapter exploit finding, including PoC evidence, impact quantification, and payload validation remediation steps."
      },
      {
        phase: "Audit Report Writing",
        description: "Document the adapter payload exploitation vulnerability with severity, attack methodology, PoC evidence, and recommended payload validation.",
        tools: ["report_generator", "slither"],
        commands: [
          "report_generator generate --finding adapter-exploit --severity High --swc SWC-109 --cwe CWE-20",
          "slither BridgeAdapter.sol --print human-summary,calls-external > report/bridge-adapter-analysis.txt",
          "report_generator compile --output audit-report-adapter-exploit.pdf"
        ],
        expected_output: "Audit Finding #3: HIGH - Bridge Adapter Exploitation via Unvalidated Message Payload Structure\nSWC-109 (Unchecked Input for Vulnerability), CWE-20 (Improper Input Validation)\nSeverity: High (CVSS 8.6)\nAffected: BridgeAdapter.sol:processMessage(), decodeMessage()\nRoot Cause: abi.decode on untrusted payload without structural validation (length, version, payloadType)\nImpact: Crafted payloads can trigger arbitrary external calls and state corruption, extracting up to $12.4M in approved tokens\nPoC: Foundry test testAdapterPayloadExploit - confirms crafted payload triggers unintended call execution\nRecommendation: (1) Add require(payload.length >= expectedStructSize) before decoding. (2) Validate version and payloadType fields. (3) Validate all decoded fields before use in external calls. (4) Consider using a versioned serialization format with explicit length prefixes.",
        thinking: "The report should clearly explain the deserialization vulnerability and how crafted payloads can manipulate the decoded struct fields. The PoC provides concrete evidence of arbitrary call execution. The recommended fixes are straightforward and have minimal gas cost impact.",
        analysis: "The finding is well-supported with code review, static analysis, and a working PoC. The fix is low-risk and adds necessary validation to the payload processing pipeline. The report should be delivered to the development team for implementation.",
        next_action: "Finalize the report with all supporting evidence and deliver to the development team."
      }
    ],
    tools_involved: ["slither", "foundry", "cast", "anvil", "semgrep", "tenderly", "dune", "solc", "forge", "sigint", "solhint", "report_generator"],
    tags: ["payload-validation", "bridge-adapter", "cross-chain", "serialization"],
    cve_references: ["SWC-109", "CWE-20"]
  },
  {
    id: "cross-nonce-reuse",
    category: "Cross-Chain & Bridge Vulnerabilities",
    subcategory: "Nonce Reuse",
    title: "Cross-Chain Nonce Reuse via Global Nonce Instead of Per-Chain Nonce",
    difficulty: "advanced",
    description: "The bridge uses a single global nonce counter for all source chains instead of per-chain tracking, allowing an attacker who observes a message on chain A to replay it on chain B before the global nonce increments. Because the nonce is shared across chains, a message from chain A with nonce N can be replayed on chain B as long as the global nonce hasn't advanced past N, which may take significant time if chain B has lower transaction volume.",
    target_description: "Cross-chain bridge with a global nonce counter stored in a single storage slot. All incoming messages from all source chains must include a nonce value that is greater than the current global nonce. The bridge does not track nonces per source chain, only a single monotonically increasing global nonce.",
    attack_phases: [
      {
        phase: "Code Review & Architecture Analysis",
        description: "Analyze the bridge's nonce tracking mechanism to determine whether nonces are tracked globally or per source chain, and identify replay windows created by the global nonce approach.",
        tools: ["solc", "sigint", "slither"],
        commands: [
          "sigint analyze GlobalNonceBridge.sol --focus 'processMessage,verifyNonce,_updateNonce'",
          "slither GlobalNonceBridge.sol --print human-summary,vars-written",
          "grep -n 'globalNonce\\|_nonce\\|nonces\\[' GlobalNonceBridge.sol",
          "slither GlobalNonceBridge.sol --detect reentrancy-benign,missing-zero-check"
        ],
        expected_output: "GlobalNonceBridge.sol uses a single global nonce:\n  uint256 public globalNonce;\n\n  function processMessage(uint256 sourceChainId, uint256 nonce, bytes calldata payload, bytes calldata signature) external {\n    require(nonce > globalNonce, \"Invalid nonce\");\n    globalNonce = nonce;\n    // Process message...\n  }\n\nNo per-chain nonce tracking exists. The global nonce is updated for ALL chains when ANY chain's message is processed. This creates a replay window: if chain A processes a message with nonce 100, and chain B hasn't yet processed a message with nonce > 100, the same message can be replayed on chain B.",
        thinking: "The global nonce design creates a fundamental race condition across chains. When a message with nonce N is processed on chain A, the global nonce updates to N. But on chain B, the global nonce might still be at a lower value (say, 50) because chain B hasn't received any messages yet. An attacker who observed the message on chain A can submit it on chain B with nonce N, and since N > 50, the bridge accepts it. The message is effectively replayed because chain B has no record that this nonce was already consumed on chain A.",
        analysis: "The root cause is the absence of per-chain nonce tracking. Each source chain should have its own nonce counter, and messages should be validated against the nonce for their specific source chain. The global nonce approach fails because chains operate independently and may have different message processing rates. The fix requires changing the storage from a single uint256 to a mapping(uint256 => uint256) nonces per sourceChainId.",
        next_action: "Use Semgrep to verify the global nonce pattern and check for any per-chain nonce tracking that might exist elsewhere in the codebase."
      },
      {
        phase: "Static Analysis & Automated Scanning",
        description: "Scan for global nonce patterns in cross-chain contracts, missing per-chain nonce mappings, and replay-eligible message processing flows.",
        tools: ["semgrep", "slither", "solhint"],
        commands: [
          "semgrep --pattern 'uint256 public globalNonce' -l solidity .",
          "slither GlobalNonceBridge.sol --detect reentrancy-no-eth,unchecked-transfer",
          "semgrep --pattern 'require($NONCE > globalNonce)' --lang solidity .",
          "solhint GlobalNonceBridge.sol --rule 'per-chain-nonce-tracking'"
        ],
        expected_output: "Semgrep: Found globalNonce declaration at GlobalNonceBridge.sol:23.\nFound nonce check 'require(nonce > globalNonce)' at line 67.\nNo per-chain nonce mapping found in the contract.\n\nSlither: Info - 'GlobalNonceBridge.processMessage() uses a shared nonce across all source chains. Messages from different chains may replay if nonce is not incremented between chains.'\n\nSolhint: Warning - 'Global nonce used for all chains at line 23. Consider using mapping(uint256 => uint256) for per-chain nonces.'",
        thinking: "All tools independently identified the global nonce issue. Semgrep found the declaration and the check, Slither flagged the cross-chain replay risk, and Solhint recommended the per-chain mapping fix. The consensus confirms this is a real vulnerability with a straightforward fix.",
        analysis: "The static analysis confirms that the bridge uses a global nonce without per-chain tracking. This creates replay windows that vary based on the relative message rates of different chains. High-volume chains will advance the global nonce quickly, but low-volume chains may have large replay windows. The fix is a simple storage change from uint256 to mapping(uint256 => uint256).",
        next_action: "Build a Foundry PoC demonstrating the nonce reuse attack by processing a message on one chain and replaying it on another chain before the global nonce advances."
      },
      {
        phase: "Proof of Concept Development",
        description: "Create a Foundry test that demonstrates nonce reuse by processing a message on a high-volume chain fork and replaying it on a low-volume chain fork before the global nonce advances.",
        tools: ["foundry", "cast", "anvil", "forge"],
        commands: [
          "anvil --fork-url $ETH_RPC_URL --fork-block-number 19000000 --port 8545 &",
          "anvil --fork-url $ARBITRUM_RPC_URL --fork-block-number 200000000 --port 8546 &",
          "forge test --match-test testGlobalNonceReuseAcrossChains -vvvv",
          "cast call $BRIDGE_ADDR 'globalNonce()(uint256)' --rpc-url http://127.0.0.1:8545",
          "cast call $BRIDGE_ADDR 'globalNonce()(uint256)' --rpc-url http://127.0.0.1:8546"
        ],
        expected_output: "forge test output:\n[PASS] testGlobalNonceReuseAcrossChains() (gas: 765432)\nLogs:\n  Chain A (Ethereum fork): globalNonce = 45\n  Processed message with nonce 100 on Chain A\n  Chain A globalNonce updated to: 100\n  Chain B (Arbitrum fork): globalNonce = 45 (not yet updated)\n  Replay message with nonce 100 on Chain B\n  Nonce check: 100 > 45 = true (ACCEPTED)\n  Chain B globalNonce updated to: 100\n  Message processed on Chain B: minted 500 tokens\n  Result: Same message (nonce 100) processed on both chains\n  Duplicate minted: 500 tokens",
        thinking: "The PoC sets up two anvil forks with different starting global nonce values. Chain A has processed more messages and has a higher global nonce. Chain B has processed fewer messages and has a lower global nonce. When a message with nonce 100 is processed on Chain A, Chain A's global nonce updates to 100. But on Chain B, the global nonce is still at 45, so the same message with nonce 100 is accepted on Chain B. The replay succeeds because Chain B has no knowledge that nonce 100 was already used on Chain A.",
        analysis: "The PoC demonstrates that the global nonce design enables cross-chain replay. The replay window exists whenever one chain's global nonce is behind another chain's. The size of the window depends on the difference in message processing rates between chains. The fix requires per-chain nonce tracking so that each chain's nonce is independent.",
        next_action: "Quantify the impact by analyzing the historical nonce progression across chains to estimate the total replay window duration and value at risk."
      },
      {
        phase: "Impact Analysis",
        description: "Assess the replay window size and value at risk by analyzing nonce progression across supported chains.",
        tools: ["dune", "cast", "tenderly"],
        commands: [
          "cast logs --address $BRIDGE_ADDR --from-block 0 --to-block latest 'MessageProcessed(uint256,uint256)' --rpc-url $ETH_RPC_URL | head -100",
          "dune query run --id nonce-reuse-impact --params '{\"bridge\": \"$BRIDGE_ADDR\", \"chains\": \"[1,137,42161,10]\"}'",
          "tenderly sim tx 0x... --network eth-mainnet --trace",
          "cast call $BRIDGE_ADDR 'getChainNonce(uint256)(uint256)' 1 --rpc-url $ETH_RPC_URL"
        ],
        expected_output: "Chain nonces (current): Ethereum=10,234, Polygon=3,891, Arbitrum=7,654, Optimism=2,103\nMax nonce gap: 10,234 - 2,103 = 8,131 (Ethereum vs Optimism)\nMessages in replay window on Optimism: 8,131 (all Ethereum messages with nonce > 2,103)\nAverage message value: $847\nTotal value in replay window: $6.9M\nReplay window duration: ~72 hours (time for Optimism to catch up)\nAttack window: Continuous (new messages from Ethereum always ahead of Optimism)",
        thinking: "The impact analysis reveals a persistent replay window of ~8,131 messages worth $6.9M. The window is continuous because Ethereum processes messages faster than Optimism, so there are always Ethereum messages that haven't been reflected in Optimism's global nonce. An attacker has a 72-hour window to replay any Ethereum message on Optimism before Optimism's nonce catches up. The attack is ongoing and doesn't require any special timing - the attacker just needs to monitor Ethereum for bridge messages and replay them on Optimism before the nonce advances.",
        analysis: "The vulnerability is High severity with $6.9M in continuous replay exposure. The replay window is a permanent feature of the global nonce design, not a transient condition. Every cross-chain message creates a replay opportunity on slower chains. The fix is straightforward (per-chain nonces) but requires a contract upgrade and careful migration of the nonce state.",
        next_action: "Write the audit report documenting the nonce reuse vulnerability with severity, PoC evidence, impact quantification, and per-chain nonce remediation."
      },
      {
        phase: "Audit Report Writing",
        description: "Document the nonce reuse vulnerability with severity, attack methodology, PoC evidence, impact quantification, and per-chain nonce remediation.",
        tools: ["report_generator", "slither"],
        commands: [
          "report_generator generate --finding nonce-reuse --severity High --swc SWC-121 --cwe CWE-672",
          "slither GlobalNonceBridge.sol --print human-summary,vars-written > report/global-nonce-bridge-analysis.txt",
          "report_generator compile --output audit-report-nonce-reuse.pdf"
        ],
        expected_output: "Audit Finding #4: HIGH - Cross-Chain Nonce Reuse via Global Nonce Instead of Per-Chain Nonce\nSWC-121 (Arbitrary Call Risk), CWE-672 (Operation on a Resource after Expiration or Release)\nSeverity: High (CVSS 8.4)\nAffected: GlobalNonceBridge.sol:processMessage(), globalNonce storage\nRoot Cause: Single global nonce shared across all source chains instead of per-chain nonce tracking\nImpact: $6.9M in continuous replay exposure across 4 supported chains, ~72-hour replay window per message\nPoC: Foundry test testGlobalNonceReuseAcrossChains - confirms replay succeeds on slower chain\nRecommendation: Replace uint256 globalNonce with mapping(uint256 => uint256) chainNonces. Update nonce check to require(nonce > chainNonces[sourceChainId]). Migrate existing global nonce to all chain nonces during upgrade.",
        thinking: "The report should clearly explain why the global nonce design is fundamentally broken for cross-chain use. Each chain operates independently, and a shared nonce creates permanent replay windows. The per-chain nonce fix is the industry-standard solution. The report should also recommend monitoring for replay attacks during the upgrade window.",
        analysis: "The finding is well-supported with code review, static analysis, PoC evidence, and quantified impact. The fix is straightforward and non-breaking from an API perspective. The report should be delivered promptly so the upgrade can be scheduled.",
        next_action: "Finalize the report and deliver to the development team with the recommended per-chain nonce migration plan."
      }
    ],
    tools_involved: ["slither", "foundry", "cast", "anvil", "semgrep", "tenderly", "dune", "solc", "forge", "sigint", "solhint", "report_generator"],
    tags: ["nonce-reuse", "global-state", "bridge", "cross-chain"],
    cve_references: ["SWC-121", "CWE-672"]
  },
  {
    id: "cross-chain-race-condition",
    category: "Cross-Chain & Bridge Vulnerabilities",
    subcategory: "Race Condition",
    title: "Cross-Chain Race Condition in Multi-Sig Validator Confirmation",
    difficulty: "expert",
    description: "The bridge requires M-of-N validator confirmations but processes each confirmation independently, allowing a race condition where an attacker submits a malicious confirmation after the threshold is reached but before the message is marked complete. The bridge's confirmation processing has a TOCTOU (Time-of-Check-Time-of-Use) gap where the confirmation count is checked, the threshold is met, but the message is not atomically marked as processed, allowing a conflicting confirmation to be accepted.",
    target_description: "Multi-sig validator bridge where messages require M-of-N validator signatures to be processed. The bridge processes validator confirmations sequentially, checking the threshold after each confirmation but not atomically marking the message as complete. This creates a race window between threshold detection and message finalization.",
    attack_phases: [
      {
        phase: "Code Review & Architecture Analysis",
        description: "Analyze the bridge's multi-sig confirmation flow to identify TOCTOU race conditions between threshold detection and message finalization.",
        tools: ["solc", "sigint", "slither"],
        commands: [
          "sigint analyze ValidatorBridge.sol --focus 'confirmMessage,executeMessage,_processConfirmations'",
          "slither ValidatorBridge.sol --print human-summary,calls-external,vars-written",
          "grep -n 'confirmations\\[\\]\\|confirmationCount\\|_executed\\|M_OF_N' ValidatorBridge.sol",
          "slither ValidatorBridge.sol --detect reentrancy-no-eth,reentrancy-benign"
        ],
        expected_output: "ValidatorBridge.sol:confirmMessage() has a TOCTOU race condition:\n  function confirmMessage(bytes32 msgHash, uint8 v, bytes32 r, bytes32 s) external {\n    require(!validators[msg.sender].used, \"Already confirmed\");\n    confirmations[msgHash].push(msg.sender);\n    uint256 count = confirmations[msgHash].length;\n    if (count >= THRESHOLD && !messages[msgHash].executed) {\n      // GAP: Another confirmation could be submitted here\n      messages[msgHash].executed = true;\n      _executeMessage(msgHash);\n    }\n  }\n\nThe check (count >= THRESHOLD && !executed) and the state update (executed = true) are not atomic. Between the check and the update, another validator's confirmation can also pass the check and trigger a second execution.",
        thinking: "The race condition is in the non-atomic check-then-act pattern. Two validators could submit confirmations in the same block (or consecutive blocks) that both see confirmationCount < THRESHOLD before either is processed, or both see count >= THRESHOLD && !executed before either sets executed = true. In a multi-block environment, the first confirmation sets count to M (meeting threshold), but before it sets executed = true, the second confirmation also sees count >= M && !executed and also triggers execution. The result is the message being executed twice.",
        analysis: "The TOCTOU vulnerability exists because the threshold check and the executed flag update are not performed atomically. In Ethereum, this race is exploitable through transaction ordering (MEV) or by submitting confirmations in the same block. The fix is to use a mutex or restructure the logic so that the executed flag is checked and set in a single atomic operation, or to use a confirmation bitmap that prevents double-execution.",
        next_action: "Use Semgrep to search for similar TOCTOU patterns in the codebase where a condition is checked and then state is modified non-atomically."
      },
      {
        phase: "Static Analysis & Automated Scanning",
        description: "Scan for TOCTOU patterns in multi-sig confirmation logic, non-atomic check-then-act sequences, and missing mutex protection.",
        tools: ["semgrep", "slither", "solhint"],
        commands: [
          "semgrep --pattern 'if ($COUNT >= $THRESHOLD && !$EXECUTED) { ... $EXECUTED = true; ... }' -l solidity .",
          "slither ValidatorBridge.sol --detect reentrancy-no-eth,reentrancy-benign,tx-origin",
          "semgrep --pattern 'confirmations[$HASH].push($V); ... if (confirmations[$HASH].length >= $T)' --lang solidity .",
          "solhint ValidatorBridge.sol --rule 'atomic-check-update'"
        ],
        expected_output: "Semgrep: Found TOCTOU pattern in ValidatorBridge.sol:112:\n  if (count >= THRESHOLD && !messages[msgHash].executed) {\n    messages[msgHash].executed = true;\n    _executeMessage(msgHash);\n  }\n  Non-atomic: the check and update are separate storage operations.\n\nSlither: Warning - 'ValidatorBridge.confirmMessage() has a race condition between threshold check and execution flag update.'\n\nSolhint: Warning - 'Non-atomic check-update pattern at line 112. Use mutex or atomic operation.'",
        thinking: "All three tools identified the TOCTOU pattern. Semgrep matched the specific if-check-then-update pattern, Slither flagged the race condition between the check and the state update, and Solhint recommended using a mutex. The consistent findings confirm this is a real vulnerability that could be exploited through MEV or transaction ordering.",
        analysis: "The static analysis confirms the TOCTOU race condition. The vulnerability is exploitable in two ways: (1) MEV bots can sandwich the confirmation transactions to submit a conflicting confirmation between the check and the update, or (2) two validators can submit confirmations in the same block, and the EVM will process them sequentially, with both potentially passing the threshold check before either sets the executed flag. The fix requires atomic check-and-set logic.",
        next_action: "Build a Foundry PoC that demonstrates the race condition by submitting two confirmations that both trigger message execution."
      },
      {
        phase: "Proof of Concept Development",
        description: "Create a Foundry test that demonstrates the race condition by submitting two validator confirmations that both pass the threshold check and trigger duplicate message execution.",
        tools: ["foundry", "cast", "anvil", "forge"],
        commands: [
          "anvil --fork-url $ETH_RPC_URL --fork-block-number 19000000 --block-time 1 &",
          "forge test --match-test testValidatorRaceCondition -vvvv",
          "cast send $BRIDGE_ADDR 'confirmMessage(bytes32,uint8,bytes32,bytes32)' $HASH $V $R $S --from $VALIDATOR1 --rpc-url http://127.0.0.1:8545",
          "cast call $BRIDGE_ADDR 'messages(bytes32)(bool,uint256,uint256)' $HASH --rpc-url http://127.0.0.1:8545"
        ],
        expected_output: "forge test output:\n[PASS] testValidatorRaceCondition() (gas: 1,123,456)\nLogs:\n  Confirmation 1 (Validator 3): count = 3/3 (THRESHOLD met)\n  Check: !executed = true -> passes\n  --- RACE WINDOW ---\n  Confirmation 2 (Validator 4): count = 4/3 (THRESHOLD met)\n  Check: !executed = true -> still passes (not yet set)\n  --- END RACE WINDOW ---\n  Message executed twice:\n    Execution 1: minted 2000 tokens to 0xUser\n    Execution 2: minted 2000 tokens to 0xUser (DUPLICATE)\n  Total minted: 4000 tokens (expected: 2000)\n  Bridge balance discrepancy: -2000 tokens",
        thinking: "The PoC simulates the race condition by having two validators submit confirmations in rapid succession. The first confirmation sees count = 3 (meeting the threshold of 3) and !executed = true, so it enters the execution block. But before it sets executed = true, the second confirmation also sees count = 4 (still >= 3) and !executed = true (because the first hasn't set it yet). Both confirmations trigger _executeMessage, resulting in duplicate token minting.",
        analysis: "The PoC confirms the TOCTOU race condition is exploitable. The race window exists because Solidity storage writes are not atomic with the condition check. The fix requires restructuring the logic to atomically check and set the executed flag, or using a confirmation counter that only allows exactly one execution per message hash.",
        next_action: "Quantify the impact by analyzing the validator confirmation patterns and estimating the value at risk from duplicate executions."
      },
      {
        phase: "Impact Analysis",
        description: "Assess the impact of the race condition by analyzing validator confirmation patterns, block-level MEV opportunities, and historical duplicate execution potential.",
        tools: ["dune", "cast", "tenderly"],
        commands: [
          "cast logs --address $BRIDGE_ADDR --from-block 0 --to-block latest 'ValidatorConfirmation(bytes32,address)' --rpc-url $ETH_RPC_URL | head -50",
          "dune query run --id race-condition-impact --params '{\"bridge\": \"$BRIDGE_ADDR\", \"threshold\": 3}'",
          "tenderly sim tx 0x... --network eth-mainnet --decode-state-changes",
          "cast call $BRIDGE_ADDR 'getValidatorCount()(uint256)' --rpc-url $ETH_RPC_URL"
        ],
        expected_output: "Total validators: 7\nThreshold: 3-of-7\nMessages with concurrent confirmations (same block): 234\nMessages with confirmations within 1 block: 1,847\nHistorical race-window opportunities: 2,081\nEstimated duplicate executions if exploited: 234 (same-block confirmations)\nAverage message value: $3,200\nTotal value at risk: $748,800\nMEV extraction potential: $748,800 (if bot frontruns confirmations)",
        thinking: "The impact analysis reveals 234 historical messages where confirmations arrived in the same block, creating a race window. With an average message value of $3,200, the total value at risk is $748,800. The attack is most feasible for MEV bots who can observe a confirmation in the mempool and submit their own conflicting confirmation in the same block. The bot would need to control or collude with a validator to submit the conflicting confirmation.",
        analysis: "The vulnerability is High severity. While the absolute value at risk ($748K) is lower than some other bridge vulnerabilities, the attack is sophisticated and requires validator collusion or MEV capability. The fix is straightforward: make the check-and-set atomic. The race condition has existed historically but may not have been exploited yet.",
        next_action: "Draft the audit report with the race condition finding, PoC evidence, impact analysis, and atomic check-and-set remediation."
      },
      {
        phase: "Audit Report Writing",
        description: "Document the race condition vulnerability with severity, TOCTOU analysis, PoC evidence, impact quantification, and atomic remediation.",
        tools: ["report_generator", "slither"],
        commands: [
          "report_generator generate --finding race-condition --severity High --swc SWC-114 --cwe CWE-362",
          "slither ValidatorBridge.sol --print human-summary,calls-external > report/validator-bridge-analysis.txt",
          "report_generator compile --output audit-report-race-condition.pdf"
        ],
        expected_output: "Audit Finding #5: HIGH - Cross-Chain Race Condition in Multi-Sig Validator Confirmation\nSWC-114 (Transaction Order Dependence), CWE-362 (Concurrent Execution using Shared Resource with Improper Synchronization)\nSeverity: High (CVSS 8.1)\nAffected: ValidatorBridge.sol:confirmMessage()\nRoot Cause: TOCTOU race condition between threshold check (count >= THRESHOLD && !executed) and state update (executed = true)\nImpact: Duplicate message execution, enabling duplicate token minting. Historical value at risk: $748,800\nPoC: Foundry test testValidatorRaceCondition - confirms duplicate execution via race condition\nRecommendation: Use atomic check-and-set: uint256 count = confirmations[msgHash].length++; if (count == THRESHOLD) { messages[msgHash].executed = true; _executeMessage(msgHash); }. This ensures only the confirmation that reaches the threshold triggers execution.",
        thinking: "The report should clearly explain the TOCTOU pattern and why it creates a race condition. The recommended fix uses a counter-increment-and-check pattern that ensures only the confirmation that reaches the exact threshold triggers execution. Subsequent confirmations will have count > THRESHOLD and won't trigger execution. The report should also recommend monitoring for duplicate executions in production.",
        analysis: "The finding is well-supported with code review, static analysis, PoC evidence, and quantified impact. The fix is a single-line change that eliminates the race window. The report should be delivered to the development team for implementation.",
        next_action: "Finalize the report and deliver to the development team with the recommended atomic check-and-set fix."
      }
    ],
    tools_involved: ["slither", "foundry", "cast", "anvil", "semgrep", "tenderly", "dune", "solc", "forge", "sigint", "solhint", "report_generator"],
    tags: ["race-condition", "multi-sig", "validator", "bridge", "concurrency"],
    cve_references: ["SWC-114", "CWE-362"]
  },
  {
    id: "cross-finality-assumption",
    category: "Cross-Chain & Bridge Vulnerabilities",
    subcategory: "Finality Assumption",
    title: "Bridge Finality Assumption Violated via Chain Reorg",
    difficulty: "expert",
    description: "The bridge processes messages from the source chain after a fixed number of confirmations (12 blocks) but doesn't account for chain reorganizations deeper than 12 blocks, allowing double-spend via reorg. The bridge listens to events on the source chain and processes the corresponding message on the destination chain after waiting 12 block confirmations. However, during periods of network congestion or consensus instability, chains can reorganize deeper than 12 blocks, invalidating the bridge's source transaction and enabling the user to double-spend their tokens.",
    target_description: "Cross-chain bridge that monitors source chain events and processes cross-chain messages after a fixed confirmation depth of 12 blocks. The bridge uses an off-chain relayer to detect events and submit them to the destination chain, but does not implement reorg detection or dynamic confirmation depth adjustment.",
    attack_phases: [
      {
        phase: "Code Review & Architecture Analysis",
        description: "Analyze the bridge's confirmation depth logic and reorg handling to determine whether the fixed 12-block confirmation depth is sufficient to prevent double-spend via chain reorganization.",
        tools: ["solc", "sigint", "slither"],
        commands: [
          "sigint analyze FinalityBridge.sol --focus 'waitForConfirmations,processEvent,handleReorg'",
          "slither FinalityBridge.sol --print human-summary,calls-external,vars-written",
          "grep -n 'CONFIRMATIONS\\|confirmationDepth\\|block.number\\|reorg' FinalityBridge.sol",
          "slither FinalityBridge.sol --detect timestamp,reentrancy-benign"
        ],
        expected_output: "FinalityBridge.sol:processEvent() uses fixed confirmation depth:\n  uint256 constant CONFIRMATION_DEPTH = 12;\n\n  function processEvent(bytes32 txHash, uint256 blockNumber) external {\n    require(block.number >= blockNumber + CONFIRMATION_DEPTH, \"Not enough confirmations\");\n    // No reorg detection or handling\n    // No dynamic confirmation depth based on network conditions\n    _executeBridgeMessage(txHash);\n  }\n\nThe bridge assumes 12 confirmations are sufficient for finality. It has no mechanism to detect or respond to chain reorganizations. If the source chain reorganizes beyond 12 blocks, the original transaction could be removed from the canonical chain while the bridge has already processed the message on the destination chain.",
        thinking: "The 12-block confirmation depth is based on the assumption that reorgs deeper than 12 blocks are economically infeasible. However, this assumption has been violated multiple times in practice (e.g., Ethereum PoW chain reorgs of 14+ blocks, BSC reorgs of 20+ blocks). The bridge has no reorg detection mechanism - it processes messages once the confirmation depth is met and never revisits them. If the source chain reorganizes and the original deposit transaction is excluded from the new canonical chain, the user still has their tokens on the source chain AND has received the bridged tokens on the destination chain - a classic double-spend.",
        analysis: "The vulnerability is a design-level finality assumption error. The bridge assumes a fixed confirmation depth is sufficient for probabilistic finality, but doesn't account for the possibility of deeper reorgs. The fix requires implementing reorg detection by monitoring source chain block hashes and re-executing or reverting bridge messages when the source transaction is no longer in the canonical chain. Alternatively, the confirmation depth should be dynamically adjusted based on network conditions.",
        next_action: "Use Semgrep to search for fixed confirmation depth patterns and check for any reorg detection logic in the codebase."
      },
      {
        phase: "Static Analysis & Automated Scanning",
        description: "Scan for fixed confirmation depth patterns, missing reorg detection, and static finality assumptions in cross-chain message processing.",
        tools: ["semgrep", "slither", "solhint"],
        commands: [
          "semgrep --pattern 'uint256 constant CONFIRMATION_DEPTH = 12' -l solidity .",
          "slither FinalityBridge.sol --detect timestamp,weak-prng",
          "semgrep --pattern 'block.number >= $BLOCK + $CONFIRMATIONS' --lang solidity . | grep -v 'reorg'",
          "solhint FinalityBridge.sol --rule 'dynamic-finality-check'"
        ],
        expected_output: "Semgrep: Found fixed CONFIRMATION_DEPTH = 12 at FinalityBridge.sol:15.\nNo reorg detection logic found in the contract.\nNo dynamic confirmation depth adjustment found.\n\nSlither: Info - 'FinalityBridge uses a fixed confirmation depth. This may be insufficient during network congestion or consensus instability.'\n\nSolhint: Warning - 'Fixed confirmation depth of 12 blocks at line 15. Consider implementing dynamic finality monitoring.'",
        thinking: "The tools consistently identified the fixed confirmation depth issue. Semgrep found the constant and noted the absence of reorg detection, Slither flagged the static finality assumption, and Solhint recommended dynamic finality monitoring. The consensus confirms this is a design-level vulnerability.",
        analysis: "The static analysis confirms that the bridge relies on a fixed confirmation depth without any reorg detection or dynamic adjustment. This is a systemic vulnerability - it can't be exploited through a single transaction but rather through manipulating chain consensus conditions. The attack requires the ability to cause or benefit from a chain reorg deeper than 12 blocks.",
        next_action: "Build a Foundry PoC that simulates a chain reorg deeper than 12 blocks and demonstrates the double-spend scenario."
      },
      {
        phase: "Proof of Concept Development",
        description: "Create a Foundry test that simulates a chain reorg deeper than 12 blocks and demonstrates how the bridge processes a message that is later invalidated by the reorg, resulting in a double-spend.",
        tools: ["foundry", "cast", "anvil", "forge"],
        commands: [
          "anvil --fork-url $ETH_RPC_URL --fork-block-number 19000000 --block-time 1 &",
          "forge test --match-test testReorgDoubleSpend -vvvv",
          "cast rpc evm_mine 12 --rpc-url http://127.0.0.1:8545",
          "cast rpc evm_reorg 15 --rpc-url http://127.0.0.1:8545"
        ],
        expected_output: "forge test output:\n[PASS] testReorgDoubleSpend() (gas: 2,345,678)\nLogs:\n  Block 100: User deposits 1000 tokens on source chain\n  Block 112: Bridge confirms (12 confirmations met)\n  Destination chain: minted 1000 bridged tokens to user\n  --- REORG TRIGGERED (depth: 15 blocks) ---\n  Block 100 transaction removed from canonical chain\n  User's 1000 source chain tokens NOT deducted (reorg)\n  User's 1000 destination chain tokens STILL held (no revert)\n  Result: Double-spend achieved\n  User balance on source chain: +1000 tokens (original)\n  User balance on destination chain: +1000 tokens (bridged)\n  Net gain: +1000 tokens (free mint)",
        thinking: "The PoC simulates a chain reorg by: (1) having a user deposit tokens on the source chain, (2) waiting 12 confirmations for the bridge to process the message on the destination chain, (3) triggering a reorg that removes the deposit transaction from the canonical chain. After the reorg, the user's deposit never happened on the source chain (their tokens are still there), but the bridge already minted tokens on the destination chain. The bridge has no mechanism to detect or revert the destination chain mint, resulting in a double-spend.",
        analysis: "The PoC demonstrates that the bridge's fixed confirmation depth is insufficient to prevent double-spend via chain reorg. The vulnerability is inherent in the design - the bridge assumes probabilistic finality is equivalent to absolute finality, which is false for proof-of-stake and proof-of-work chains. The fix requires reorg detection and a mechanism to revert or claw back destination chain tokens when the source transaction is invalidated.",
        next_action: "Quantify the impact by analyzing historical reorg depths on supported chains and estimating the value at risk from double-spend attacks."
      },
      {
        phase: "Impact Analysis",
        description: "Assess the impact of the finality assumption vulnerability by analyzing historical reorg depths on supported chains and the bridge's exposure to double-spend attacks.",
        tools: ["dune", "cast", "tenderly"],
        commands: [
          "cast rpc eth_getBlockByNumber 0x123456 false --rpc-url $ETH_RPC_URL | jq '.hash'",
          "dune query run --id reorg-depth-analysis --params '{\"chains\": \"[1,137,42161,10,56]\"}'",
          "tenderly sim tx 0x... --network eth-mainnet --trace",
          "cast call $BRIDGE_ADDR 'getTotalProcessed()(uint256)' --rpc-url $ETH_RPC_URL"
        ],
        expected_output: "Historical max reorg depths (last 12 months):\n  Ethereum: 14 blocks (during Shanghai upgrade congestion)\n  BSC: 22 blocks (validator consensus issue)\n  Polygon: 17 blocks (network partition)\n  Arbitrum: 8 blocks (sequencer restart)\n  Optimism: 6 blocks (batch submission delay)\n\nCurrent bridge confirmation depth: 12 blocks\nChains where reorg exceeded 12 blocks: Ethereum, BSC, Polygon\nBridge TVL on vulnerable chains: $38.7M\nMessages processed on reorg-vulnerable chains: 15,234\nEstimated double-spend exposure: $3.2M (based on average reorg frequency and message volume)",
        thinking: "The impact analysis reveals that 3 of the 5 supported chains have experienced reorgs deeper than 12 blocks in the past year. The bridge's fixed confirmation depth is insufficient for these chains. The total exposure is $3.2M based on the volume of messages processed on vulnerable chains during periods when reorgs exceeded 12 blocks. While the attack requires the ability to cause or benefit from a reorg (which is difficult for an individual attacker), the vulnerability is systemic - it exists whenever the chain experiences consensus instability.",
        analysis: "The vulnerability is High severity from a design perspective. It's not easily exploitable by an individual attacker but represents a systemic risk to the bridge's solvency. The fix requires implementing reorg detection and dynamic confirmation depth, which is a significant architectural change. The bridge should also consider increasing the confirmation depth to 30+ blocks for chains with a history of deep reorgs.",
        next_action: "Draft the audit report with the finality assumption finding, PoC evidence, impact analysis, and reorg detection remediation guidance."
      },
      {
        phase: "Audit Report Writing",
        description: "Document the finality assumption vulnerability with severity, reorg analysis, PoC evidence, impact quantification, and reorg detection remediation.",
        tools: ["report_generator", "slither"],
        commands: [
          "report_generator generate --finding finality-assumption --severity High --swc SWC-118 --cwe CWE-754",
          "slither FinalityBridge.sol --print human-summary,calls-external > report/finality-bridge-analysis.txt",
          "report_generator compile --output audit-report-finality-assumption.pdf"
        ],
        expected_output: "Audit Finding #6: HIGH - Bridge Finality Assumption Violated via Chain Reorg\nSWC-118 (Weak Finality Assumption), CWE-754 (Improper Check for Unusual or Exceptional Conditions)\nSeverity: High (CVSS 7.8)\nAffected: FinalityBridge.sol:processEvent(), CONFIRMATION_DEPTH constant\nRoot Cause: Fixed 12-block confirmation depth insufficient for chains that have experienced reorgs > 12 blocks\nImpact: Double-spend via chain reorg - user retains source chain tokens while holding bridged tokens on destination chain. Estimated exposure: $3.2M\nPoC: Foundry test testReorgDoubleSpend - confirms double-spend via simulated 15-block reorg\nRecommendation: (1) Implement reorg detection by monitoring source chain block hashes. (2) Increase confirmation depth to 30+ blocks for vulnerable chains. (3) Add dynamic confirmation depth based on network conditions. (4) Implement clawback mechanism for destination chain tokens when source transaction is invalidated.",
        thinking: "The report should clearly explain why fixed confirmation depths are insufficient for cross-chain bridges. The PoC demonstrates the double-spend scenario, and the impact analysis shows real-world reorg data. The recommended fixes range from simple (increase confirmation depth) to complex (implement reorg detection and clawback). The report should recommend the immediate fix (increase depth to 30+) while the long-term fix (reorg detection) is developed.",
        analysis: "The finding is well-supported with code review, static analysis, PoC evidence, and real-world reorg data. The fix has both immediate and long-term components. The report should be delivered to the development team with the recommended phased remediation approach.",
        next_action: "Finalize the report and deliver to the development team with the recommended phased fix approach."
      }
    ],
    tools_involved: ["slither", "foundry", "cast", "anvil", "semgrep", "tenderly", "dune", "solc", "forge", "sigint", "solhint", "report_generator"],
    tags: ["finality", "chain-reorg", "double-spend", "bridge", "confirmation-depth"],
    cve_references: ["SWC-118", "CWE-754"]
  }
];
