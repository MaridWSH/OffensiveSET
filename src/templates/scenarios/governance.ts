import type { ScenarioTemplate, AttackPhase } from "./types.js";

export const GOVERNANCE_SCENARIOS: ScenarioTemplate[] = [
  {
    id: "gov-vote-weight-manipulation",
    category: "Governance & Access Control",
    subcategory: "Vote Weight Manipulation",
    title: "Governance Vote Weight Manipulation via Repeated Staking/Unstaking",
    difficulty: "advanced",
    description: "An attacker manipulates voting weight by staking/unstaking NFTs repeatedly in OmnichainStaking, since PoolVoter uses balanceOf() directly without snapshot. A snapshot-based voting weight mechanism is absent, allowing instantaneous weight inflation at the time of vote casting.",
    target_description: "Omnichain governance protocol with OmnichainStaking.sol and PoolVoter.sol contracts. Users stake NFTs to earn veNFT positions which grant voting weight in PoolVoter. GitHub: https://github.com/omnichain-protocol/contracts. Scope includes OmnichainStaking.sol, PoolVoter.sol, VotingEscrow.sol. TVL: $80M.",
    attack_phases: [
      {
        phase: "Code Review & Architecture Analysis",
        description: "Analyze the staking contract architecture, vote weight calculation, and snapshot mechanism",
        tools: ["slither", "foundry", "etherscan"],
        commands: [
          "slither . --print human-summary",
          "forge inspect PoolVoter.sol ast",
          "cast call 0xPoolVoter 'getVoteWeight(address)' 0xAttacker --rpc-url $RPC_URL"
        ],
        expected_output: `Slither analysis complete. Found 3 High, 3 Medium, 5 Low severity findings.\nKey: PoolVoter.getVoteWeight() reads balanceOf() directly from OmnichainStaking -- no snapshot of voting weight at proposal creation time.`,
        thinking: "Let me trace the voting weight flow. PoolVoter.getVoteWeight(user) calls OmnichainStaking.balanceOf(user) to determine voting power. This is a live read -- no snapshot is taken when a proposal is created. If I can rapidly stake and unstake NFTs, my balanceOf() will fluctuate. The question is: can I stake NFTs to inflate my balance before a vote, then unstake them after voting to reuse them in another pool? Let me check the staking/unstaking timing constraints.",
        analysis: "PoolVoter uses live balanceOf() instead of snapshot-based weight. No epoch-based or proposal-creation-time snapshot exists. Staking/unstaking can manipulate instantaneous voting weight.",
        next_action: "Run Slither governance-specific detectors to confirm vote weight manipulation pattern"
      },
      {
        phase: "Static Analysis & Automated Scanning",
        description: "Run governance-focused Slither detectors and Semgrep rules",
        tools: ["slither", "semgrep"],
        commands: [
          "slither . --detect governance-voting,missing-zero-check --human-summary",
          "semgrep --config auto --lang solidity PoolVoter.sol OmnichainStaking.sol"
        ],
        expected_output: `Slither findings:\n  governance-voting (High): getVoteWeight() uses live balanceOf() without snapshot\n  missing-zero-check (Medium): no cooldown on stake/unstake cycle\nSemgrep findings:\n  [HIGH] balanceOf() used directly in vote weight calculation without snapshot\n  [MEDIUM] stake() and unstake() have no timing lock`,
        thinking: "Both tools confirm the vulnerability. The live balanceOf() read without a snapshot is the root cause. No cooldown exists between stake and unstake, meaning an attacker can cycle NFTs through the staking contract rapidly. If I have 10 NFTs, I could theoretically stake them, vote with weight 10, unstake, stake again, vote again -- repeating this across multiple proposals or even within a single proposal if the voting period allows multiple cast operations.",
        analysis: "Static analysis confirms High severity governance voting manipulation. Live balanceOf() without snapshot + no stake/unstake cooldown enables vote weight cycling.",
        next_action: "Develop Foundry PoC demonstrating vote weight manipulation via repeated staking"
      },
      {
        phase: "Proof of Concept Development",
        description: "Write Foundry test demonstrating vote weight manipulation through staking/unstaking cycles",
        tools: ["foundry"],
        commands: [
          "forge test --match-test test_POC_VoteWeightManipulation -vvv --fork-url $RPC_URL --fork-block-number 19000000"
        ],
        expected_output: `[PASS] test_POC_VoteWeightManipulation() (gas: 3456789)\nLogs:\n  Attacker owns 5 NFTs (total value: $50K)\n  Cycle 1: Stake 5 NFTs -> balanceOf = 5 -> cast vote with weight 5\n  Cycle 1: Unstake 5 NFTs -> balanceOf = 0\n  Cycle 2: Stake 5 NFTs -> balanceOf = 5 -> cast vote with weight 5 (if multiple votes allowed)\n  Effective voting weight: 25 (5x leverage through cycling)\n  Proposal outcome changed: 51% -> 49% (proposal defeated)`,
        thinking: "The PoC confirms the exploit. With just 5 NFTs worth $50K, the attacker achieved an effective voting weight of 25 through 5 cycles. This is sufficient to flip a close vote. In a real scenario, the attacker could deploy multiple contracts to cycle in parallel, further amplifying the effect. The key insight is that each cycle costs only the gas for stake() + unstake() -- a negligible cost compared to the governance influence gained.",
        analysis: "PoC confirmed. 5x vote weight leverage through staking cycles with minimal gas cost. Close votes can be deterministically flipped.",
        next_action: "Quantify worst-case governance impact across active proposals"
      },
      {
        phase: "Impact Analysis",
        description: "Calculate maximum governance impact of vote weight manipulation",
        tools: ["foundry", "tenderly"],
        commands: [
          "forge test --match-test test_WorstCaseGovernanceImpact -vvv --fork-url $RPC_URL",
          "cast call 0xPoolVoter 'totalVotingPower()' --rpc-url $RPC_URL"
        ],
        expected_output: `Worst case governance impact:\n  Total voting power: 500,000\n  Attacker effective weight (with cycling): 125,000 (25% of total)\n  With $500K in NFTs (50 NFTs): effective weight 1,250,000 (71% of total)\n  Proposal manipulation cost: ~$500K capital + ~50M gas\n  CVSS 9.1 -- Critical`,
        thinking: "The worst case is severe. With $500K in NFT capital, an attacker can achieve 71% effective voting weight through cycling. This means they can: 1) Pass malicious proposals (treasury drains, parameter changes), 2) Block legitimate proposals (security patches, emergency pauses), 3) Manipulate reward distribution parameters in their favor. The capital requirement is modest relative to the protocol's $80M TVL. CVSS 9.1 -- Critical.",
        analysis: "Critical governance impact. $500K attacker capital achieves 71% effective voting weight. Full governance control possible.",
        next_action: "Write audit report recommending snapshot-based voting weight with proposal-creation-time checkpoints"
      },
      {
        phase: "Audit Report Writing",
        description: "Document vote weight manipulation finding with PoC evidence and snapshot fix recommendation",
        tools: ["report_generator"],
        commands: [],
        expected_output: "",
        thinking: "The report needs to explain the missing snapshot mechanism, demonstrate the cycling attack with gas costs, quantify the governance control achievable with modest capital, and recommend implementing ERC-5805 votes + checkpoints or at minimum a proposal-creation-time snapshot with stake lockup.",
        analysis: "Compile vote weight manipulation report with snapshot-based voting weight fix and stake lockup recommendation.",
        next_action: "Submit report"
      }
    ],
    cve_references: ["SWC-107", "CWE-668"],
    tools_involved: ["slither", "foundry", "etherscan", "semgrep", "tenderly", "report_generator"],
    tags: ["vote-manipulation", "governance", "staking-nft", "balance-snapshot", "defi"]
  },
  {
    id: "gov-proposal-execution-bypass",
    category: "Governance & Access Control",
    subcategory: "Timelock Bypass",
    title: "Proposal Execution Bypass via Missing Timelock Check",
    difficulty: "advanced",
    description: "A governance proposal can be executed before the timelock delay expires because the execute function checks timelock.last_authorized_time against a hardcoded 24h instead of the configurable timelock.delay_ms, allowing the governance delay to be circumvented.",
    target_description: "Governance protocol GovDAO at 0xMno...345 with TimelockController.sol and Governor.sol. The timelock has a configurable delay_ms parameter but the Governor.execute() function uses a hardcoded 24-hour constant. GitHub: https://github.com/govdao/contracts. Scope includes Governor.sol, TimelockController.sol, ProposalManager.sol.",
    attack_phases: [
      {
        phase: "Code Review & Architecture Analysis",
        description: "Analyze the timelock-controller integration, proposal execution flow, and delay enforcement",
        tools: ["slither", "foundry", "etherscan"],
        commands: [
          "slither . --print human-summary",
          "forge inspect Governor.sol ast",
          "cast call 0xTimelockController 'delay()' --rpc-url $RPC_URL"
        ],
        expected_output: `Slither analysis complete. Found 3 High, 2 Medium, 4 Low severity findings.\nKey: Governor.execute() checks block.timestamp >= proposal.voteEnd + 24 hours (hardcoded) instead of reading timelock.delay_ms. Current timelock.delay_ms = 72 hours.`,
        thinking: "The Governor contract has an execute() function that checks if the timelock delay has passed. But it compares against a hardcoded 24h constant instead of reading timelock.delay_ms. The current timelock.delay_ms is set to 72 hours (3 days). This means any proposal can be executed after only 24 hours instead of the intended 72. An attacker who passes a malicious proposal can execute it 48 hours earlier than expected, giving the community less time to react or exit.",
        analysis: "Hardcoded 24h delay in Governor.execute() bypasses the configurable 72h timelock delay. Proposals execute 48 hours earlier than intended.",
        next_action: "Run Slither to verify timelock bypass pattern"
      },
      {
        phase: "Static Analysis & Automated Scanning",
        description: "Run timelock-specific Slither detectors and custom Semgrep rules",
        tools: ["slither", "semgrep"],
        commands: [
          "slither . --detect timelock,hardcoded-constant --human-summary",
          "semgrep --config auto --lang solidity Governor.sol"
        ],
        expected_output: `Slither findings:\n  timelock (High): execute() uses hardcoded 24h constant instead of timelock.delay_ms\n  hardcoded-constant (Medium): DELAY constant = 86400 shadows timelock.delay_ms = 259200\nSemgrep findings:\n  [HIGH] block.timestamp >= voteEnd + 86400 should use timelock.getDelay()`,
        thinking: "Both tools confirm the timelock bypass. The hardcoded DELAY constant of 86400 (24h) shadows the actual timelock delay of 259200 (72h). This is a classic governance configuration mismatch. If the DAO votes to increase the timelock delay to 7 days for security, this Governor.execute() would still use 24h -- completely undermining the governance decision.",
        analysis: "Static analysis confirms High severity timelock bypass. Hardcoded delay undermines configurable governance timelock.",
        next_action: "Develop Foundry PoC demonstrating early proposal execution"
      },
      {
        phase: "Proof of Concept Development",
        description: "Write Foundry test demonstrating proposal execution before timelock delay expires",
        tools: ["foundry"],
        commands: [
          "forge test --match-test test_POC_TimelockBypass -vvv --fork-url $RPC_URL --fork-block-number 19000000"
        ],
        expected_output: `[PASS] test_POC_TimelockBypass() (gas: 2345678)\nLogs:\n  Proposal created at block 19000000\n  Voting ends at block 19005000 (approx 24h later)\n  Timelock configured delay: 72 hours (259200 seconds)\n  Hardcoded delay in execute(): 24 hours (86400 seconds)\n  Attempt execute at T+36h: FAIL (correctly rejected)\n  Attempt execute at T+25h: SUCCESS (should have been rejected!)\n  Proposal executed 47 hours before intended timelock expiry`,
        thinking: "The PoC confirms the bypass. The proposal executed at T+25h when it should have waited until T+96h (24h voting + 72h timelock). That's 71 hours of extra time for the attacker's changes to take effect before the community can respond. In a real attack, this could be used to drain a treasury, change fee parameters, or upgrade contracts before users have time to withdraw.",
        analysis: "PoC confirmed. Proposal executes 71 hours early, bypassing timelock protection. Community has no time to react.",
        next_action: "Quantify impact of early execution on governance security"
      },
      {
        phase: "Impact Analysis",
        description: "Calculate security impact of timelock bypass on governance response time",
        tools: ["foundry", "tenderly"],
        commands: [
          "forge test --match-test test_TimelockImpactAnalysis -vvv --fork-url $RPC_URL",
          "cast call 0xGovernor 'state(uint256)' 1 --rpc-url $RPC_URL"
        ],
        expected_output: `Impact analysis:\n  Intended security window: 72 hours for community response\n  Actual window: 1 hour (24h voting + 1h execution margin)\n  Proposals affected: all proposals through Governor\n  Historical proposals executed early: 23 of 47 (48.9%)\n  CVSS 8.6 -- High`,
        thinking: "The impact is significant but not immediately catastrophic -- it depends on what the malicious proposal does. The real danger is that it removes the community's response window. Historical analysis shows 48.9% of past proposals would have executed early under this bug. If any of those were contentious, they effectively had no timelock protection. CVSS 8.6 -- High.",
        analysis: "High impact. 48.9% of historical proposals executed before intended timelock. Community response window eliminated.",
        next_action: "Write audit report recommending reading delay from timelock contract dynamically"
      },
      {
        phase: "Audit Report Writing",
        description: "Document timelock bypass finding with PoC evidence and dynamic delay fix",
        tools: ["report_generator"],
        commands: [],
        expected_output: "",
        thinking: "The report must explain how the hardcoded delay undermines the entire timelock mechanism, show the PoC evidence, quantify how many historical proposals were affected, and recommend reading timelock.delay_ms dynamically in execute().",
        analysis: "Compile timelock bypass report with dynamic delay reading fix and governance security recommendation.",
        next_action: "Submit report"
      }
    ],
    cve_references: ["SWC-114", "CWE-691"],
    tools_involved: ["slither", "foundry", "etherscan", "semgrep", "tenderly", "report_generator"],
    tags: ["timelock", "proposal-execution", "governance", "hardcoded-value"]
  },
  {
    id: "gov-initialization-missing",
    category: "Governance & Access Control",
    subcategory: "Initialization Vulnerability",
    title: "Proxy Initialization Skip Allows Implementation Hijack",
    difficulty: "expert",
    description: "A proxy contract's initialize() function can be called by anyone because _disableInitializers() was never called in the constructor, allowing an attacker to set themselves as admin and gain full control over the proxy.",
    target_description: "Upgradeable proxy protocol ProxySys at 0xPqr...678 using OpenZeppelin UUPSProxy pattern. The implementation contract MyContract.sol inherits from Initializable but the deployment script never called _disableInitializers() in the constructor. GitHub: https://github.com/proxysys/contracts. Scope includes MyContract.sol, ProxyAdmin.sol, UUPSUpgradeable.sol.",
    attack_phases: [
      {
        phase: "Code Review & Architecture Analysis",
        description: "Analyze proxy deployment, initialization flow, and initializer protection",
        tools: ["slither", "foundry", "etherscan"],
        commands: [
          "slither . --print human-summary",
          "forge inspect MyContract.sol ast",
          "cast call 0xMyContract 'initialized()' --rpc-url $RPC_URL"
        ],
        expected_output: `Slither analysis complete. Found 4 High, 2 Medium, 3 Low severity findings.\nKey: MyContract constructor does NOT call _disableInitializers(). The initialize() function is publicly callable and has not been called yet (initialized == 0).`,
        thinking: "The implementation contract MyContract uses OpenZeppelin's Initializable pattern. Per the docs, the constructor should call _disableInitializers() to prevent anyone from calling initialize() on the implementation contract directly. But the constructor is empty -- no _disableInitializers() call. This means: 1) The implementation contract itself is uninitialized, 2) Anyone can call initialize() on the implementation and set themselves as admin, 3) Once initialized on the implementation, the proxy's delegatecall would route to an already-initialized implementation. But more critically, if the proxy hasn't been initialized yet, an attacker can race to call initialize() first and claim admin rights.",
        analysis: "Missing _disableInitializers() in constructor allows anyone to call initialize() on the implementation contract. If the proxy is not yet initialized, attacker can claim admin before deployer.",
        next_action: "Run Slither initialization detectors to confirm vulnerability"
      },
      {
        phase: "Static Analysis & Automated Scanning",
        description: "Run initialization-focused Slither detectors and Semgrep rules",
        tools: ["slither", "semgrep"],
        commands: [
          "slither . --detect missing-in-call,uninitialized-state --human-summary",
          "semgrep --config auto --lang solidity MyContract.sol"
        ],
        expected_output: `Slither findings:\n  missing-in-call (Critical): _disableInitializers() not called in constructor\n  uninitialized-state (High): _initialized flag is 0, initialize() is callable\nSemgrep findings:\n  [CRITICAL] Initializable contract without _disableInitializers() in constructor\n  [HIGH] initialize() function has no additional access control beyond initializer modifier`,
        thinking: "Both tools flag this as Critical. The _disableInitializers() omission is a well-known footgun in OpenZeppelin upgradeable contracts. The initialize() function uses the initializer modifier which only checks that it hasn't been called before -- it doesn't restrict WHO can call it. The first caller becomes the de facto initializer and sets the admin address.",
        analysis: "Critical initialization vulnerability confirmed. Any caller can initialize the contract and set themselves as admin.",
        next_action: "Develop Foundry PoC demonstrating proxy initialization hijack"
      },
      {
        phase: "Proof of Concept Development",
        description: "Write Foundry test demonstrating proxy initialization hijack by unauthorized caller",
        tools: ["foundry"],
        commands: [
          "forge test --match-test test_POC_InitializationHijack -vvv --fork-url $RPC_URL"
        ],
        expected_output: `[PASS] test_POC_InitializationHijack() (gas: 1234567)\nLogs:\n  Deployer deploys implementation contract (MyContract)\n  Deployer deploys UUPSProxy pointing to implementation\n  Attacker calls initialize(attacker) on implementation BEFORE deployer calls it on proxy\n  Attacker is now admin of implementation contract\n  Attacker calls upgradeToAndCall() with malicious implementation\n  Proxy now points to attacker-controlled implementation\n  Attacker calls stealFunds() -> transfers all protocol assets to attacker\n  Attacker profit: $2.3M (entire protocol treasury)`,
        thinking: "The PoC demonstrates the full attack chain. The attacker calls initialize() on the implementation contract first, becoming admin. Then they use upgradeToAndCall() to point the proxy to a malicious implementation. Finally, they drain the entire treasury. This is a complete protocol takeover from a single missing function call in the constructor. The attack cost is minimal gas -- just the initialization and upgrade transactions.",
        analysis: "PoC confirmed. Complete protocol takeover via uninitialized implementation. $2.3M treasury drain with minimal gas cost.",
        next_action: "Quantify impact across all upgradeable contracts in scope"
      },
      {
        phase: "Impact Analysis",
        description: "Calculate impact of initialization hijack across all upgradeable contracts",
        tools: ["foundry", "tenderly"],
        commands: [
          "forge test --match-test test_InitializationImpactAnalysis -vvv --fork-url $RPC_URL",
          "cast call 0xProxyAdmin 'getProxyAdmin(address)' 0xMyContract --rpc-url $RPC_URL"
        ],
        expected_output: `Impact analysis:\n  Contracts affected: 12 upgradeable contracts in scope\n  Total value at risk: $15.7M (treasury + staking pools)\n  Attack cost: ~2M gas per contract ($100 at 50 gwei)\n  Time to full takeover: < 5 minutes\n  CVSS 10.0 -- Critical`,
        thinking: "The impact is maximum severity. All 12 upgradeable contracts in scope are vulnerable to the same initialization hijack. The total value at risk is $15.7M. The attack costs only ~2M gas per contract and can be completed in under 5 minutes. There is no defense once the attacker calls initialize() first. CVSS 10.0 -- Critical. This is the highest severity possible.",
        analysis: "Critical impact: $15.7M at risk across 12 contracts. Full protocol takeover in under 5 minutes. CVSS 10.0.",
        next_action: "Write audit report recommending immediate initialization and _disableInitializers() in all constructors"
      },
      {
        phase: "Audit Report Writing",
        description: "Document initialization hijack finding with PoC evidence and immediate remediation",
        tools: ["report_generator"],
        commands: [],
        expected_output: "",
        thinking: "The report must emphasize the CVSS 10.0 severity, provide the complete attack chain PoC, recommend immediate initialization of all contracts, and add _disableInitializers() to all constructors. Also recommend a deployment checklist to prevent recurrence.",
        analysis: "Compile initialization hijack report with CVSS 10.0 severity, immediate initialization recommendation, and deployment checklist.",
        next_action: "Submit report"
      }
    ],
    cve_references: ["SWC-112", "CWE-908"],
    tools_involved: ["slither", "foundry", "etherscan", "semgrep", "tenderly", "report_generator"],
    tags: ["proxy", "initialization", "access-control", "upgradeable", "hijack"]
  },
  {
    id: "gov-admin-key-exposure",
    category: "Governance & Access Control",
    subcategory: "Admin Key Exposure",
    title: "Admin Key Exposure via Hardcoded Private Key in Contract",
    difficulty: "intermediate",
    description: "A contract contains a hardcoded ECDSA private key used for signature verification, allowing anyone to forge valid signatures and perform admin operations without authorization.",
    target_description: "Admin-controlled protocol AdminSys at 0xStu...901 with SignatureVerifier.sol contract that validates admin actions via ECDSA signatures. The contract contains a hardcoded public key for verification, but the corresponding private key was committed in the deployment script and is recoverable from on-chain transactions. GitHub: https://github.com/adminsys/contracts. Scope includes SignatureVerifier.sol, AdminOps.sol, deployment scripts.",
    attack_phases: [
      {
        phase: "Code Review & Architecture Analysis",
        description: "Analyze signature verification mechanism, key management, and admin operation flow",
        tools: ["slither", "etherscan", "foundry"],
        commands: [
          "slither . --print human-summary",
          "cast call 0xSignatureVerifier 'adminPublicKey()' --rpc-url $RPC_URL",
          "etherscan txs --address 0xDeployer --rpc-url $RPC_URL | grep -i 'signature'"
        ],
        expected_output: `Slither analysis complete. Found 2 High, 3 Medium, 4 Low severity findings.\nKey: SignatureVerifier.sol uses a hardcoded ECDSA public key. The corresponding private key is recoverable from deployment transaction signature data.`,
        thinking: "The SignatureVerifier contract uses ecrecover() to validate admin signatures against a hardcoded public key. The public key is visible on-chain. But more importantly, the deployment script signed an initial admin message with the private key, and that signature is part of the deployment transaction. From the signature (r, s, v) and the message hash, the private key can be derived. Let me check the deployment transaction for the initial signature.",
        analysis: "Hardcoded ECDSA public key with recoverable private key from deployment transaction signature. Admin operations can be forged by anyone who extracts the private key.",
        next_action: "Run Slither to confirm hardcoded key vulnerability"
      },
      {
        phase: "Static Analysis & Automated Scanning",
        description: "Run key-exposure Slither detectors and Semgrep rules",
        tools: ["slither", "semgrep"],
        commands: [
          "slither . --detect hardcoded-constants,weak-prng --human-summary",
          "semgrep --config auto --lang solidity SignatureVerifier.sol"
        ],
        expected_output: `Slither findings:\n  hardcoded-constants (High): ADMIN_PUBKEY is a fixed ECDSA public key in contract storage\n  weak-prng (Medium): deployment script uses deterministic seed for key generation\nSemgrep findings:\n  [HIGH] ecrecover() with hardcoded public key -- no key rotation mechanism\n  [CRITICAL] Private key recoverable from deployment transaction`,
        thinking: "Both tools confirm the hardcoded key vulnerability. The ecrecover() with a fixed public key means there's no key rotation capability. The deployment script used a deterministic seed, making the private key predictable. Anyone can: 1) Extract the public key from the contract, 2) Find the deployment transaction signature, 3) Derive the private key, 4) Forge admin signatures. This is a complete admin bypass.",
        analysis: "Static analysis confirms High severity hardcoded key exposure. Private key is recoverable, enabling admin signature forgery.",
        next_action: "Develop Foundry PoC demonstrating forged admin signature"
      },
      {
        phase: "Proof of Concept Development",
        description: "Write Foundry test demonstrating forged admin signatures using extracted private key",
        tools: ["foundry"],
        commands: [
          "forge test --match-test test_POC_ForgedAdminSignature -vvv --fork-url $RPC_URL",
          "cast wallet private-key --mnemonic 'test test test test test test test test test test test junk'"
        ],
        expected_output: `[PASS] test_POC_ForgedAdminSignature() (gas: 567890)\nLogs:\n  Extracted private key from deployment tx: 0xabc...def\n  Forged signature for admin operation 'updateFeeBps(500)': valid\n  Forged signature for admin operation 'setTreasury(0xAttacker)': valid\n  Forged signature for admin operation 'upgradeTo(0xMalicious)': valid\n  All forged signatures pass ecrecover() verification`,
        thinking: "The PoC confirms that forged signatures pass verification. With the extracted private key, any admin operation can be performed: changing fee parameters, redirecting treasury, upgrading to malicious implementations. The ecrecover() verification has no way to distinguish legitimate admin signatures from forged ones because the same private key is used.",
        analysis: "PoC confirmed. All admin operations can be performed with forged signatures. Complete admin control compromised.",
        next_action: "Quantify impact of compromised admin key on protocol security"
      },
      {
        phase: "Impact Analysis",
        description: "Calculate impact of compromised admin key across all admin-controlled functions",
        tools: ["foundry", "tenderly"],
        commands: [
          "forge test --match-test test_AdminKeyImpact -vvv --fork-url $RPC_URL",
          "cast call 0xAdminOps 'isAdmin()' 0xAttacker --rpc-url $RPC_URL"
        ],
        expected_output: `Impact analysis:\n  Admin operations forgeable: updateFee, setTreasury, upgradeTo, pause, unpause, setSigner\n  Total value at risk: $8.5M (treasury + fee reserves)\n  Attack cost: Private key extraction (free, on-chain data)\n  Time to full compromise: < 10 minutes\n  CVSS 9.8 -- Critical`,
        thinking: "The impact is maximum. Every admin operation is forgeable: fees can be set to 100%, treasury can be redirected, contracts can be upgraded to malicious versions, and the signer can be changed to lock out the legitimate admin. The attack cost is essentially free -- just reading on-chain data. CVSS 9.8 -- Critical.",
        analysis: "Critical impact: $8.5M at risk. All admin operations forgeable. Attack cost is free. CVSS 9.8.",
        next_action: "Write audit report recommending multi-sig admin with hardware wallet key management"
      },
      {
        phase: "Audit Report Writing",
        description: "Document admin key exposure finding with PoC evidence and multi-sig recommendation",
        tools: ["report_generator"],
        commands: [],
        expected_output: "",
        thinking: "The report must explain the private key recovery from deployment transactions, show the forged signature PoC, recommend immediate key rotation to a multi-sig wallet, and provide a key management policy for future deployments.",
        analysis: "Compile admin key exposure report with multi-sig recommendation, immediate key rotation, and key management policy.",
        next_action: "Submit report"
      }
    ],
    cve_references: ["SWC-101", "CWE-798"],
    tools_involved: ["slither", "etherscan", "foundry", "semgrep", "tenderly", "report_generator"],
    tags: ["hardcoded-key", "signature-forgery", "admin-access", "ecdsa"]
  },
  {
    id: "gov-quorum-manipulation",
    category: "Governance & Access Control",
    subcategory: "Quorum Manipulation",
    title: "Quorum Calculation Manipulation via Inflated Total Supply",
    difficulty: "advanced",
    description: "The quorum for governance proposals is calculated as a percentage of total token supply, but the totalSupply() can be inflated through an unchecked mint path, raising the quorum threshold and preventing legitimate proposals from passing.",
    target_description: "Governance token protocol TokenGov at 0xVwx...234 with GovToken.sol and Governor.sol. The quorum is calculated as quorumNumerator * totalSupply() / quorumDenominator. An unchecked mint path in the rewards distributor allows inflating totalSupply(). GitHub: https://github.com/tokengov/contracts. Scope includes GovToken.sol, Governor.sol, RewardDistributor.sol.",
    attack_phases: [
      {
        phase: "Code Review & Architecture Analysis",
        description: "Analyze quorum calculation, token supply mechanics, and mint access controls",
        tools: ["slither", "foundry", "etherscan"],
        commands: [
          "slither . --print human-summary",
          "cast call 0xGovToken 'totalSupply()' --rpc-url $RPC_URL",
          "forge inspect RewardDistributor.sol ast"
        ],
        expected_output: `Slither analysis complete. Found 3 High, 2 Medium, 5 Low severity findings.\nKey: quorum() in Governor.sol uses totalSupply() which can be inflated via RewardDistributor.mintRewards() -- no cap or rate limit exists.`,
        thinking: "The quorum calculation is: quorumNumerator * totalSupply() / quorumDenominator. With quorumNumerator = 4 and quorumDenominator = 100, quorum is 4% of total supply. If totalSupply is 100M tokens, quorum is 4M tokens. But RewardDistributor.mintRewards() has no cap -- it mints tokens based on a formula that can be gamed. If an attacker can inflate totalSupply to 1B tokens, quorum becomes 40M tokens, making it nearly impossible for any proposal to reach quorum. This is a governance denial-of-service attack.",
        analysis: "Quorum depends on totalSupply() which can be inflated through unchecked RewardDistributor.mintRewards(). Attacker can raise quorum threshold to block all proposals.",
        next_action: "Run Slither to verify quorum manipulation via supply inflation"
      },
      {
        phase: "Static Analysis & Automated Scanning",
        description: "Run supply and quorum-focused Slither detectors and Semgrep rules",
        tools: ["slither", "semgrep"],
        commands: [
          "slither . --detect unchecked-transfer,unlimited-mint --human-summary",
          "semgrep --config auto --lang solidity Governor.sol RewardDistributor.sol"
        ],
        expected_output: `Slither findings:\n  unlimited-mint (Critical): mintRewards() has no cap or rate limit\n  unchecked-transfer (High): reward calculation uses unchecked arithmetic\nSemgrep findings:\n  [CRITICAL] totalSupply() used in quorum calculation without supply cap\n  [HIGH] mintRewards() callable by anyone with no access control`,
        thinking: "Both tools flag this as Critical. The unlimited mint in RewardDistributor combined with the quorum calculation using totalSupply() creates a governance denial-of-service vector. The attacker doesn't even need to hold the minted tokens -- they just need to inflate totalSupply to raise the quorum bar beyond what legitimate voters can reach.",
        analysis: "Critical quorum manipulation confirmed. Unlimited mint path allows inflating totalSupply to block governance.",
        next_action: "Develop Foundry PoC demonstrating quorum manipulation via supply inflation"
      },
      {
        phase: "Proof of Concept Development",
        description: "Write Foundry test demonstrating quorum manipulation via token supply inflation",
        tools: ["foundry"],
        commands: [
          "forge test --match-test test_POC_QuorumManipulation -vvv --fork-url $RPC_URL"
        ],
        expected_output: `[PASS] test_POC_QuorumManipulation() (gas: 2345678)\nLogs:\n  Initial totalSupply: 100,000,000 GOV\n  Initial quorum: 4,000,000 GOV (4%)\n  Attacker calls mintRewards() 100 times -> mints 900,000,000 GOV\n  New totalSupply: 1,000,000,000 GOV\n  New quorum: 40,000,000 GOV (4% of 1B)\n  Legitimate proposal votes: 5,000,000 GOV (1.25% of supply)\n  Proposal fails quorum check: 5M < 40M\n  Governance effectively paralyzed`,
        thinking: "The PoC confirms the governance paralysis. By inflating totalSupply from 100M to 1B, the quorum jumps from 4M to 40M tokens. Legitimate voters holding 5M tokens (5% of original supply) can't reach 40M quorum (4% of inflated supply). The governance is effectively frozen -- no proposal can pass. Meanwhile, the attacker can accumulate the inflated tokens at low cost since they were minted to their address.",
        analysis: "PoC confirmed. Governance paralyzed by 10x supply inflation. Quorum raised beyond legitimate voter capacity.",
        next_action: "Quantify impact of governance paralysis on protocol operations"
      },
      {
        phase: "Impact Analysis",
        description: "Calculate impact of governance paralysis on protocol operations",
        tools: ["foundry", "tenderly"],
        commands: [
          "forge test --match-test test_QuorumImpactAnalysis -vvv --fork-url $RPC_URL",
          "cast call 0xGovernor 'quorum(uint256)' 1 --rpc-url $RPC_URL"
        ],
        expected_output: `Impact analysis:\n  Governance functions blocked: all proposals, parameter changes, upgrades\n  Protocol cannot respond to emergencies (no emergency proposals)\n  Treasury funds frozen (no withdrawal proposals)\n  Token value impact: 60%+ devaluation from governance uncertainty\n  CVSS 9.3 -- Critical`,
        thinking: "The impact extends beyond just blocked proposals. The protocol cannot respond to emergencies, cannot upgrade vulnerable contracts, cannot adjust parameters, and cannot access treasury funds. This creates a governance deadlock that would likely cause a 60%+ token devaluation. CVSS 9.3 -- Critical.",
        analysis: "Critical impact: complete governance paralysis. Protocol frozen, treasury inaccessible, token value collapsing.",
        next_action: "Write audit report recommending quorum based on circulating supply with supply cap enforcement"
      },
      {
        phase: "Audit Report Writing",
        description: "Document quorum manipulation finding with PoC evidence and supply cap fix",
        tools: ["report_generator"],
        commands: [],
        expected_output: "",
        thinking: "The report must explain how supply inflation paralyzes governance, show the PoC with dollar impact, and recommend: 1) Using circulating supply (excluding minted-but-unvested tokens) for quorum, 2) Adding a hard supply cap, 3) Rate-limiting mintRewards() calls.",
        analysis: "Compile quorum manipulation report with circulating supply quorum, hard supply cap, and rate limiting recommendations.",
        next_action: "Submit report"
      }
    ],
    cve_references: ["SWC-107", "CWE-682"],
    tools_involved: ["slither", "foundry", "etherscan", "semgrep", "tenderly", "report_generator"],
    tags: ["quorum", "governance", "inflation", "token-supply"]
  },
  {
    id: "gov-delegate-exploit",
    category: "Governance & Access Control",
    subcategory: "Signature Replay",
    title: "Delegate Vote Power Exploitation via Cross-Chain Replay",
    difficulty: "expert",
    description: "A delegation signature intended for one chain can be replayed on another chain because the signed message doesn't include chainId, allowing an attacker to redirect voting power across chains.",
    target_description: "Multichain governance protocol MultiGov deployed on Ethereum (chainId 1), Arbitrum (chainId 42161), and Optimism (chainId 10). GovToken.sol supports off-chain delegation via typed signatures (EIP-712). The delegation signature does not include chainId in the domain separator. GitHub: https://github.com/multigov/contracts. Scope includes GovToken.sol on all chains, DelegateRegistry.sol.",
    attack_phases: [
      {
        phase: "Code Review & Architecture Analysis",
        description: "Analyze cross-chain delegation mechanism, EIP-712 domain separator, and replay protection",
        tools: ["slither", "foundry", "etherscan"],
        commands: [
          "slither . --print human-summary",
          "forge inspect GovToken.sol ast",
          "cast call 0xGovToken 'DOMAIN_SEPARATOR()' --rpc-url $RPC_URL"
        ],
        expected_output: `Slither analysis complete. Found 3 High, 3 Medium, 4 Low severity findings.\nKey: EIP-712 domain for delegation signature does NOT include chainId. Same delegation signature is valid on all deployed chains.`,
        thinking: "The delegation uses EIP-712 typed data. The domain separator includes name, version, and verifyingContract address -- but NOT chainId. This is a critical omission. If Alice signs a delegation on Ethereum mainnet delegating her votes to Bob, that exact same signature (r, s, v) is valid on Arbitrum and Optimism because the domain separator is identical (same contract address format, same name, same version). An attacker monitoring Alice's mainnet delegation can replay it on L2s to redirect her voting power there too.",
        analysis: "EIP-712 domain separator missing chainId. Delegation signatures are replayable across all deployed chains.",
        next_action: "Run Slither to confirm cross-chain replay vulnerability"
      },
      {
        phase: "Static Analysis & Automated Scanning",
        description: "Run replay-protection Slither detectors and cross-chain Semgrep rules",
        tools: ["slither", "semgrep"],
        commands: [
          "slither . --detect eip712,missing-zero-check --human-summary",
          "semgrep --config auto --lang solidity GovToken.sol"
        ],
        expected_output: `Slither findings:\n  eip712 (High): domain separator missing chainId -- signatures replayable across chains\n  missing-zero-check (Medium): no nonce-based replay protection for delegation\nSemgrep findings:\n  [HIGH] _buildDomainSeparator() does not include block.chainid\n  [CRITICAL] delegateBySig() accepts same signature on multiple chains`,
        thinking: "Both tools confirm the cross-chain replay vulnerability. The missing chainId in the domain separator means a single delegation signature is valid on every chain where the contract is deployed. Additionally, there's no nonce-based replay protection -- the same signature can be replayed infinitely on the same chain too if the delegation hasn't been changed.",
        analysis: "Critical cross-chain replay confirmed. Single delegation signature valid on all chains with no nonce protection.",
        next_action: "Develop Foundry fork test demonstrating cross-chain delegation replay"
      },
      {
        phase: "Proof of Concept Development",
        description: "Write Foundry fork test demonstrating cross-chain delegation replay attack",
        tools: ["foundry"],
        commands: [
          "forge test --match-test test_POC_CrossChainReplay -vvv --fork-url $ETH_RPC_URL --fork-block-number 19000000",
          "forge test --match-test test_POC_CrossChainReplay -vvv --fork-url $ARB_RPC_URL --fork-block-number 190000000"
        ],
        expected_output: `[PASS] test_POC_CrossChainReplay() (gas: 1234567)\nLogs:\n  Chain 1 (Ethereum): Alice delegates 100,000 GOV to Bob (sig: 0xabc...)\n  Chain 2 (Arbitrum): Attacker replays Alice's signature (0xabc...)\n  Replay SUCCESSFUL: Alice's 100,000 GOV now delegated to Attacker on Arbitrum\n  Alice's voting power on Arbitrum: 0 -> transferred to Attacker\n  Attacker controls governance on Arbitrum with Alice's voting power`,
        thinking: "The cross-chain replay PoC works perfectly. Alice's Ethereum delegation signature is replayed on Arbitrum, transferring her voting power to the attacker. Alice is completely unaware -- she only signed on Ethereum. On Arbitrum, the attacker now controls 100,000 GOV of voting power. This can be done for every delegator on every chain, effectively giving the attacker control of governance on all L2s.",
        analysis: "PoC confirmed. Cross-chain delegation replay transfers voting power to attacker on L2s without delegator consent.",
        next_action: "Quantify governance impact of cross-chain voting power theft"
      },
      {
        phase: "Impact Analysis",
        description: "Calculate governance impact of cross-chain voting power theft",
        tools: ["foundry", "tenderly"],
        commands: [
          "forge test --match-test test_CrossChainImpact -vvv --fork-url $ARB_RPC_URL",
          "cast call 0xGovToken 'getVotes(address)' 0xAttacker --rpc-url $ARB_RPC_URL"
        ],
        expected_output: `Impact analysis:\n  Delegations on Ethereum: 2,347 (total 5.2M GOV)\n  Replayable to Arbitrum: 5.2M GOV voting power\n  Replayable to Optimism: 5.2M GOV voting power\n  Attacker effective voting power on L2: 5.2M (68% of L2 supply)\n  CVSS 9.0 -- Critical`,
        thinking: "The impact is devastating. With 5.2M GOV replayed from Ethereum delegations, the attacker controls 68% of voting power on each L2 chain. They can pass any proposal on Arbitrum and Optimism unilaterally. The delegators on Ethereum are completely unaware their voting power has been stolen on L2s. CVSS 9.0 -- Critical.",
        analysis: "Critical impact: 68% L2 governance control via cross-chain replay. 5.2M GOV voting power stolen from unaware delegators.",
        next_action: "Write audit report recommending chainId in EIP-712 domain and per-chain nonce tracking"
      },
      {
        phase: "Audit Report Writing",
        description: "Document cross-chain delegation replay finding with PoC and EIP-712 fix",
        tools: ["report_generator"],
        commands: [],
        expected_output: "",
        thinking: "The report must explain the missing chainId in EIP-712 domain, demonstrate the cross-chain replay attack, quantify the governance control achievable on L2s, and recommend: 1) Adding chainId to domain separator, 2) Per-chain delegation nonce tracking, 3) Migration path for existing signatures.",
        analysis: "Compile cross-chain replay report with EIP-712 chainId fix and per-chain nonce recommendation.",
        next_action: "Submit report"
      }
    ],
    cve_references: ["SWC-121", "CWE-294"],
    tools_involved: ["slither", "foundry", "etherscan", "semgrep", "tenderly", "report_generator"],
    tags: ["signature-replay", "cross-chain", "delegation", "governance"]
  },
  {
    id: "gov-proposal-double-vote",
    category: "Governance & Access Control",
    subcategory: "Double Voting",
    title: "Double Voting via Governance Token Cloning on L2",
    difficulty: "advanced",
    description: "A governance token deployed on L2 with a bridge can be both bridged and cloned, allowing the same underlying asset to vote twice through separate token contracts on the same chain.",
    target_description: "L2 governance protocol LayerGov with GovToken on Ethereum L1 and a bridged version on Arbitrum. The protocol also deployed a cloned GovTokenClone on Arbitrum for a separate governance module. Both token contracts track the same underlying asset but maintain separate voting power ledgers. GitHub: https://github.com/layergov/contracts. Scope includes GovToken.sol (L1), BridgedGovToken.sol (L2), GovTokenClone.sol (L2), LayerGovGovernor.sol (L2).",
    attack_phases: [
      {
        phase: "Code Review & Architecture Analysis",
        description: "Analyze token bridging, cloning mechanism, and voting power accounting across contracts",
        tools: ["slither", "foundry", "etherscan"],
        commands: [
          "slither . --print human-summary",
          "forge inspect LayerGovGovernor.sol ast",
          "cast call 0xBridgedGovToken 'totalSupply()' --rpc-url $ARB_RPC_URL",
          "cast call 0xGovTokenClone 'totalSupply()' --rpc-url $ARB_RPC_URL"
        ],
        expected_output: `Slither analysis complete. Found 3 High, 2 Medium, 5 Low severity findings.\nKey: LayerGovGovernor sums voting power from BridgedGovToken AND GovTokenClone separately. Both tokens represent the same underlying bridged assets.`,
        thinking: "The LayerGovGovernor on Arbitrum calculates voting power by summing balances from two separate token contracts: BridgedGovToken (the official L2 bridge of the L1 token) and GovTokenClone (a cloned contract for a separate governance module). The problem: if I bridge 1000 tokens from L1 to L2, I get 1000 BridgedGovToken. But the GovTokenClone also tracks a mapping of the same addresses. If the clone's ledger was initialized with the same snapshot as the bridge, I effectively have 2000 voting power for 1000 underlying tokens. Let me check if there's a mechanism preventing double counting.",
        analysis: "Governor sums voting power from two token contracts representing the same underlying assets. No deduplication mechanism exists.",
        next_action: "Run Slither to confirm double voting via token cloning"
      },
      {
        phase: "Static Analysis & Automated Scanning",
        description: "Run double-voting-focused Slither detectors and Semgrep rules",
        tools: ["slither", "semgrep"],
        commands: [
          "slither . --detect governance-voting,incorrect-equality --human-summary",
          "semgrep --config auto --lang solidity LayerGovGovernor.sol"
        ],
        expected_output: `Slither findings:\n  governance-voting (High): getVoteWeight() sums balances from two token contracts without deduplication\n  incorrect-equality (Medium): totalVotingPower double-counts bridged tokens\nSemgrep findings:\n  [HIGH] getVoteWeight(user) = BridgedGovToken.balanceOf(user) + GovTokenClone.balanceOf(user)\n  [CRITICAL] No mechanism prevents same asset from existing in both token contracts`,
        thinking: "Both tools confirm the double voting vulnerability. The getVoteWeight function simply adds balances from both token contracts. If tokens exist in both (which they will after bridging + clone initialization), the user gets 2x voting power. There's no deduplication, no cross-contract synchronization, and no burn mechanism.",
        analysis: "High severity double voting confirmed. Same underlying assets counted twice through separate token contracts.",
        next_action: "Develop Foundry PoC demonstrating double voting via token cloning"
      },
      {
        phase: "Proof of Concept Development",
        description: "Write Foundry test demonstrating double voting through bridged and cloned tokens",
        tools: ["foundry"],
        commands: [
          "forge test --match-test test_POC_DoubleVote -vvv --fork-url $ARB_RPC_URL"
        ],
        expected_output: `[PASS] test_POC_DoubleVote() (gas: 2345678)\nLogs:\n  User bridges 10,000 GOV from L1 -> L2\n  BridgedGovToken balance: 10,000 GOV\n  GovTokenClone balance (initialized from L1 snapshot): 10,000 GOV\n  Governor.getVoteWeight(user): 20,000 GOV (double the actual)\n  User's effective voting power: 2x leverage\n  With $100K capital: 20,000 voting power (equivalent to $200K)\n  Proposal outcome flipped by double voting`,
        thinking: "The PoC confirms 2x voting power leverage. The user bridges 10,000 GOV, but the GovTokenClone also shows 10,000 because it was initialized from the same L1 snapshot. The Governor counts both, giving 20,000 effective voting power. This is a clean 2x amplification that works for every token holder. An attacker with $100K gets $200K worth of governance influence.",
        analysis: "PoC confirmed. 2x voting power amplification for all token holders. Double voting is systematic, not just an edge case.",
        next_action: "Quantify governance impact of systematic double voting"
      },
      {
        phase: "Impact Analysis",
        description: "Calculate governance impact of systematic double voting",
        tools: ["foundry", "tenderly"],
        commands: [
          "forge test --match-test test_DoubleVoteImpact -vvv --fork-url $ARB_RPC_URL",
          "cast call 0xLayerGovGovernor 'quorum()' --rpc-url $ARB_RPC_URL"
        ],
        expected_output: `Impact analysis:\n  Total bridged tokens: 5M GOV\n  Double-counted voting power: 10M effective (5M actual)\n  Quorum threshold (based on double-counted total): 400K\n  Actual quorum needed with deduplication: 200K\n  All historical proposals passed with artificially inflated participation\n  CVSS 8.8 -- High`,
        thinking: "The impact is that every proposal has had artificially inflated participation. The quorum threshold is also based on the double-counted total, so it's twice as high as it should be. This creates a paradox: legitimate voters need 2x the tokens to reach quorum, but the attacker benefits from the double counting. The governance outcomes are potentially illegitimate. CVSS 8.8 -- High.",
        analysis: "High impact: systematic double voting inflates all governance outcomes. Quorum threshold also doubled, creating asymmetric advantage.",
        next_action: "Write audit report recommending deduplication mechanism and single source of truth for voting power"
      },
      {
        phase: "Audit Report Writing",
        description: "Document double voting finding with PoC and deduplication fix",
        tools: ["report_generator"],
        commands: [],
        expected_output: "",
        thinking: "The report must explain the double counting mechanism, show the PoC with 2x leverage, quantify the impact on all historical proposals, and recommend: 1) Using a single token contract for voting power, 2) Adding a deduplication layer that checks if tokens exist in both contracts, 3) Recalculating quorum based on actual (not double-counted) supply.",
        analysis: "Compile double voting report with single-source voting power and deduplication fix recommendation.",
        next_action: "Submit report"
      }
    ],
    cve_references: ["SWC-107", "CWE-672"],
    tools_involved: ["slither", "foundry", "etherscan", "semgrep", "tenderly", "report_generator"],
    tags: ["double-voting", "l2-bridge", "token-cloning", "governance"]
  },
  {
    id: "gov-timelock-bypass",
    category: "Governance & Access Control",
    subcategory: "Timelock Bypass",
    title: "Timelock Bypass via Emergency Multisig Override",
    difficulty: "advanced",
    description: "An emergency multisig can override timelock restrictions without going through the normal delay period, effectively creating a backdoor for governance decisions.",
    target_description: "Emergency-enabled governance protocol EmergGov at 0xYza...567 with TimelockController.sol and EmergencyMultisig.sol. The EmergencyMultisig has a executeEmergency() function that bypasses the timelock delay when 3-of-5 signers approve. GitHub: https://github.com/emerggov/contracts. Scope includes TimelockController.sol, EmergencyMultisig.sol, Governor.sol.",
    attack_phases: [
      {
        phase: "Code Review & Architecture Analysis",
        description: "Analyze emergency override mechanism, multisig signer requirements, and timelock bypass flow",
        tools: ["slither", "foundry", "etherscan"],
        commands: [
          "slither . --print human-summary",
          "forge inspect EmergencyMultisig.sol ast",
          "cast call 0xEmergencyMultisig 'getSigners()' --rpc-url $RPC_URL"
        ],
        expected_output: `Slither analysis complete. Found 3 High, 2 Medium, 4 Low severity findings.\nKey: EmergencyMultisig.executeEmergency() calls timelock.executeTransaction() directly, bypassing the schedule() -> wait(delay) -> execute() flow.`,
        thinking: "The EmergencyMultisig has an executeEmergency() function that directly calls timelock.executeTransaction() without going through schedule() first. This bypasses the entire timelock delay. The function requires 3-of-5 signers, which seems safe -- but what if the 5 signers are controlled by the same entity? What if 2 signers are compromised? The emergency mechanism is intended for genuine emergencies, but the implementation doesn't define what constitutes an emergency. Any 3 signers can execute any transaction at any time.",
        analysis: "Emergency multisig bypasses timelock completely with no emergency criteria validation. 3-of-5 signers can execute any transaction instantly.",
        next_action: "Run Slither to confirm timelock bypass via emergency mechanism"
      },
      {
        phase: "Static Analysis & Automated Scanning",
        description: "Run timelock bypass Slither detectors and Semgrep rules",
        tools: ["slither", "semgrep"],
        commands: [
          "slither . --detect timelock,centralization-risk --human-summary",
          "semgrep --config auto --lang solidity EmergencyMultisig.sol"
        ],
        expected_output: `Slither findings:\n  timelock (High): executeEmergency() bypasses timelock schedule+wait flow\n  centralization-risk (High): 3-of-5 multisig has unlimited emergency power\nSemgrep findings:\n  [HIGH] executeEmergency() calls timelock.executeTransaction() without schedule()\n  [CRITICAL] No validation of emergency conditions or proposal scope`,
        thinking: "Both tools confirm the timelock bypass. The emergency mechanism has no constraints: no list of allowed emergency operations, no rate limiting, no post-execution review. Any 3 signers can execute any calldata at any time. This is effectively a parallel governance system with zero delay, making the timelock meaningless if the multisig signers are colluding or compromised.",
        analysis: "Critical timelock bypass confirmed. Emergency multisig is a parallel governance system with zero delay and unlimited scope.",
        next_action: "Develop Foundry PoC demonstrating timelock bypass via emergency multisig"
      },
      {
        phase: "Proof of Concept Development",
        description: "Write Foundry test demonstrating timelock bypass through emergency multisig",
        tools: ["foundry"],
        commands: [
          "forge test --match-test test_POC_EmergencyBypass -vvv --fork-url $RPC_URL"
        ],
        expected_output: `[PASS] test_POC_EmergencyBypass() (gas: 3456789)\nLogs:\n  Normal governance path: schedule() -> wait 72h -> execute()\n  Emergency path: 3 signers approve -> executeEmergency() -> instant execution\n  Malicious proposal: upgradeTo(0xMaliciousImplementation)\n  Emergency multisig executes: proposal completed in 1 block\n  Timelock bypassed: 0 hours delay instead of 72 hours\n  Protocol upgraded to attacker implementation`,
        thinking: "The PoC confirms the bypass. The emergency multisig executes the malicious upgrade in 1 block instead of the normal 72-hour delay. The community has zero time to react. The key insight is that this isn't a bug per se -- it's a design feature. But the implementation is flawed because there's no scope restriction on what emergency actions can do, no post-execution review, and no accountability mechanism.",
        analysis: "PoC confirmed. Emergency multisig bypasses timelock completely, enabling instant malicious upgrades.",
        next_action: "Quantify impact of emergency bypass on governance integrity"
      },
      {
        phase: "Impact Analysis",
        description: "Calculate impact of emergency bypass on governance integrity",
        tools: ["foundry", "tenderly"],
        commands: [
          "forge test --match-test test_EmergencyImpact -vvv --fork-url $RPC_URL",
          "cast call 0xEmergencyMultisig 'executeCount()' --rpc-url $RPC_URL"
        ],
        expected_output: `Impact analysis:\n  Historical emergency executions: 7 in past 6 months\n  Emergency actions that should have used timelock: 4 of 7\n  Average time saved by emergency bypass: 71.5 hours\n  Total value affected by emergency actions: $12M\n  CVSS 8.4 -- High`,
        thinking: "Historical analysis shows the emergency mechanism has been abused: 4 of 7 emergency executions should have gone through the normal timelock. The mechanism is being used as a convenience feature, not just for genuine emergencies. The $12M affected by emergency actions includes parameter changes and upgrades that would have been subject to community scrutiny under the normal timelock. CVSS 8.4 -- High.",
        analysis: "High impact: emergency bypass used for non-emergency actions. $12M affected without community review.",
        next_action: "Write audit report recommending emergency scope restrictions and post-execution timelock review"
      },
      {
        phase: "Audit Report Writing",
        description: "Document emergency timelock bypass finding with evidence and scope restriction fix",
        tools: ["report_generator"],
        commands: [],
        expected_output: "",
        thinking: "The report must explain the unlimited emergency power, show the PoC with instant execution, analyze historical abuse of the emergency mechanism, and recommend: 1) Whitelisting allowed emergency operations, 2) Requiring a minimum delay even for emergencies (e.g., 6 hours), 3) Post-execution community review and potential rollback mechanism.",
        analysis: "Compile emergency bypass report with scoped emergency operations, minimum delay, and rollback mechanism recommendations.",
        next_action: "Submit report"
      }
    ],
    cve_references: ["SWC-114", "CWE-284"],
    tools_involved: ["slither", "foundry", "etherscan", "semgrep", "tenderly", "report_generator"],
    tags: ["timelock-bypass", "multisig", "emergency", "backdoor"]
  },
  {
    id: "gov-treasury-drain",
    category: "Governance & Access Control",
    subcategory: "Treasury Drain",
    title: "Treasury Drain via Manipulated Reward Distribution Formula",
    difficulty: "expert",
    description: "The formula for distributing treasury rewards to stakers has a division-before-multiplication error that rounds each user's share to zero for small stakes, while the remainder accumulates in an admin-withdrawable pool.",
    target_description: "Treasury reward protocol TreasuryRewards at 0xBcd...890 with RewardDistributor.sol distributing protocol fees to stakers. The distribution formula calculates each user's share as: (userStake / totalStake) * rewards. Due to integer division, small stakers receive zero rewards while the remainder accumulates in a residual pool withdrawable by admin. GitHub: https://github.com/treasuryrewards/contracts. Scope includes RewardDistributor.sol, StakingPool.sol, AdminWithdraw.sol.",
    attack_phases: [
      {
        phase: "Code Review & Architecture Analysis",
        description: "Analyze reward distribution formula, integer arithmetic, and residual fund handling",
        tools: ["slither", "foundry", "etherscan"],
        commands: [
          "slither . --print human-summary",
          "forge inspect RewardDistributor.sol ast",
          "cast call 0xRewardDistributor 'residualBalance()' --rpc-url $RPC_URL"
        ],
        expected_output: `Slither analysis complete. Found 3 High, 3 Medium, 4 Low severity findings.\nKey: _calculateShare() uses userStake / totalStake * rewards (division before multiplication). For stakers with < 0.01% of total stake, share rounds to 0. Residual accumulates in admin-withdrawn pool.`,
        thinking: "The reward distribution formula is: share = (userStake / totalStake) * rewards. Due to Solidity integer division, if userStake is 100 and totalStake is 1,000,000, then userStake / totalStake = 0 (integer division truncates). 0 * rewards = 0. The user gets nothing. The correct formula should be: (userStake * rewards) / totalStake. With this bug, all small stakers (under 0.01% of total) get zero rewards. The unclaimed rewards accumulate in a residual pool that admin can withdraw. This is effectively a systematic wealth transfer from small stakers to the admin.",
        analysis: "Division-before-multiplication in reward formula rounds small staker shares to zero. Residual funds accumulate in admin-withdrawn pool.",
        next_action: "Run Slither to confirm arithmetic vulnerability"
      },
      {
        phase: "Static Analysis & Automated Scanning",
        description: "Run arithmetic-focused Slither detectors and Semgrep rules",
        tools: ["slither", "semgrep"],
        commands: [
          "slither . --detect incorrect-equality,divide-before-multiply --human-summary",
          "semgrep --config auto --lang solidity RewardDistributor.sol"
        ],
        expected_output: `Slither findings:\n  divide-before-multiply (Critical): _calculateShare() divides before multiplying\n  incorrect-equality (High): residualBalance() accumulates rounded-away rewards\nSemgrep findings:\n  [CRITICAL] userStake / totalStake * rewards should be userStake * rewards / totalStake\n  [HIGH] residual pool has no cap and is admin-withdrawable`,
        thinking: "Both tools confirm the division-before-multiply bug. This is a classic Solidity arithmetic error. The Semgrep rule catches it perfectly: the operands should be reordered to multiply first. The residual pool has no cap -- it can grow indefinitely as more distributions occur. And the admin can withdraw it at any time, creating a perverse incentive to keep the bug.",
        analysis: "Critical arithmetic vulnerability confirmed. Systematic wealth transfer from small stakers to admin-controlled residual pool.",
        next_action: "Develop Foundry PoC demonstrating treasury drain via rounding error"
      },
      {
        phase: "Proof of Concept Development",
        description: "Write Foundry test demonstrating treasury drain through division-before-multiplication",
        tools: ["foundry"],
        commands: [
          "forge test --match-test test_POC_TreasuryDrain -vvv --fork-url $RPC_URL"
        ],
        expected_output: `[PASS] test_POC_TreasuryDrain() (gas: 2345678)\nLogs:\n  Setup: 1000 stakers, total stake = 1,000,000 tokens\n  Distribution: 100,000 USDC rewards\n  Large staker (10% stake): receives 10,000 USDC (correct)\n  Small staker (0.001% stake): receives 0 USDC (should receive 1 USDC)\n  900 small stakers receive 0 USDC total loss: 900 USDC\n  Residual pool: 900 USDC accumulated\n  Admin withdraws residual: 900 USDC profit from rounding error`,
        thinking: "The PoC confirms the systematic drain. 900 small stakers collectively lose 900 USDC due to rounding. The admin withdraws this as residual. Over many distributions, this compounds: if 100,000 USDC is distributed daily, small stakers could lose 10-20% of their expected rewards to rounding. The admin-controlled residual pool becomes a hidden treasury drain.",
        analysis: "PoC confirmed. Systematic rounding error transfers 10-20% of small staker rewards to admin. Residual pool grows unboundedly.",
        next_action: "Quantify cumulative impact across historical distributions"
      },
      {
        phase: "Impact Analysis",
        description: "Calculate cumulative treasury drain impact across historical distributions",
        tools: ["foundry", "tenderly"],
        commands: [
          "forge test --match-test test_TreasuryImpact -vvv --fork-url $RPC_URL",
          "cast call 0xAdminWithdraw 'totalWithdrawn()' --rpc-url $RPC_URL"
        ],
        expected_output: `Impact analysis (180 days):\n  Total distributions: 180\n  Total rewards distributed: 18M USDC\n  Small staker losses to rounding: 2.7M USDC (15%)\n  Admin withdrawals from residual: 2.7M USDC\n  Affected stakers: 8,450 (84.5% of total)\n  CVSS 8.5 -- High`,
        thinking: "The historical analysis shows $2.7M systematically transferred from small stakers to admin over 180 days. 84.5% of stakers are affected (the majority are small stakers). The admin has been withdrawing these funds regularly, creating a $2.7M illicit profit. This is not a theoretical vulnerability -- it's an ongoing drain. CVSS 8.5 -- High.",
        analysis: "High impact: $2.7M drained from small stakers over 180 days. 84.5% of stakers affected. Ongoing systematic drain.",
        next_action: "Write audit report recommending multiplication-before-division and residual redistribution"
      },
      {
        phase: "Audit Report Writing",
        description: "Document treasury drain finding with historical evidence and arithmetic fix",
        tools: ["report_generator"],
        commands: [],
        expected_output: "",
        thinking: "The report must explain the division-before-multiplication bug, show the PoC with historical $2.7M impact, and recommend: 1) Reordering the formula to (userStake * rewards) / totalStake, 2) Using fixed-point arithmetic (e.g., WAD-based calculations), 3) Redistributing residual proportionally to all stakers rather than allowing admin withdrawal.",
        analysis: "Compile treasury drain report with multiplication-before-division fix, fixed-point arithmetic, and residual redistribution.",
        next_action: "Submit report"
      }
    ],
    cve_references: ["SWC-128", "CWE-682"],
    tools_involved: ["slither", "foundry", "etherscan", "semgrep", "tenderly", "report_generator"],
    tags: ["treasury", "reward-distribution", "rounding", "admin-access"]
  },
  {
    id: "gov-upgrade-hijack",
    category: "Governance & Access Control",
    subcategory: "Proxy Upgrade Hijack",
    title: "Proxy Upgrade Hijack via UUPS Self-Destruct Bypass",
    difficulty: "expert",
    description: "A UUPS proxy's upgrade function doesn't validate that the new implementation has the upgrade function, allowing deployment of a malicious implementation that removes the upgrade mechanism entirely.",
    target_description: "UUPS proxy protocol UUPSSys at 0xEfg...123 using ERC-1822 UUPS pattern. The upgradeToAndCall() function in the implementation does not verify that the new implementation contract also contains the upgrade function (ERC-1822 requirement). GitHub: https://github.com/uupssys/contracts. Scope includes UUPSImplementation.sol, ProxyContract.sol, ProxyAdmin.sol.",
    attack_phases: [
      {
        phase: "Code Review & Architecture Analysis",
        description: "Analyze UUPS upgrade mechanism, implementation validation, and ERC-1822 compliance",
        tools: ["slither", "foundry", "etherscan"],
        commands: [
          "slither . --print human-summary",
          "forge inspect UUPSImplementation.sol ast",
          "cast call 0xUUPSImplementation 'proxiableUUID()' --rpc-url $RPC_URL"
        ],
        expected_output: `Slither analysis complete. Found 3 High, 2 Medium, 4 Low severity findings.\nKey: upgradeToAndCall() does not verify that new implementation has the upgrade function or proxiableUUID(). ERC-1822 compliance check missing.`,
        thinking: "The UUPS pattern stores the upgrade logic in the implementation contract (unlike Transparent Proxy where it's in the proxy admin). The upgradeToAndCall() function changes the implementation address but doesn't verify that the new implementation also has upgradeToAndCall(). Per ERC-1822, the new implementation MUST have the upgrade function or the proxy becomes permanently unupgradeable. An attacker can deploy a malicious implementation without upgradeToAndCall(), upgrade to it, and the proxy is permanently locked -- no future upgrades possible. Worse, the malicious implementation can include a self-destruct or drain function.",
        analysis: "UUPS upgrade function missing ERC-1822 validation. New implementation can be deployed without upgrade capability, permanently locking the proxy.",
        next_action: "Run Slither to confirm UUPS upgrade hijack vulnerability"
      },
      {
        phase: "Static Analysis & Automated Scanning",
        description: "Run UUPS-specific Slither detectors and Semgrep rules",
        tools: ["slither", "semgrep"],
        commands: [
          "slither . --detect uupsi,missing-in-call --human-summary",
          "semgrep --config auto --lang solidity UUPSImplementation.sol"
        ],
        expected_output: `Slither findings:\n  uupsi (Critical): upgradeToAndCall() does not validate new implementation has upgrade function\n  missing-in-call (High): no ERC-1822 proxiableUUID() check on new implementation\nSemgrep findings:\n  [CRITICAL] upgradeToAndCall(newImpl, data) -- no validation that newImpl.proxiableUUID() exists\n  [HIGH] upgradeToAndCall can set implementation to any address including EOA`,
        thinking: "Slither confirms Critical UUPS vulnerability. The new implementation address is not validated at all -- it can be any address, including an EOA (which would brick the proxy) or a malicious contract without upgrade capability. The ERC-1822 requirement for proxiableUUID() is completely absent.",
        analysis: "Critical UUPS upgrade hijack confirmed. No validation of new implementation. Proxy can be permanently locked or hijacked.",
        next_action: "Develop Foundry PoC demonstrating UUPS upgrade hijack"
      },
      {
        phase: "Proof of Concept Development",
        description: "Write Foundry test demonstrating UUPS upgrade hijack with malicious implementation",
        tools: ["foundry"],
        commands: [
          "forge test --match-test test_POC_UUPSHijack -vvv --fork-url $RPC_URL"
        ],
        expected_output: `[PASS] test_POC_UUPSHijack() (gas: 4567890)\nLogs:\n  Deploy malicious implementation (MaliciousImpl) without upgradeToAndCall()\n  MaliciousImpl contains drainFunds() function\n  Attacker (as admin) calls upgradeToAndCall(address(MaliciousImpl), "")\n  Proxy now points to MaliciousImpl\n  Attempt to upgrade again: FAIL (no upgradeToAndCall in MaliciousImpl)\n  Proxy permanently locked\n  Attacker calls drainFunds() via delegatecall -> steals $3.1M\n  Total attack cost: deployment + 2 tx = ~3M gas`,
        thinking: "The PoC demonstrates the full attack. The malicious implementation has no upgrade function, permanently locking the proxy. It also has a drainFunds() function that, when called through the proxy's delegatecall, transfers all protocol assets to the attacker. The $3.1M treasury is drained, and the proxy can never be upgraded again to fix the issue. The attack cost is minimal gas.",
        analysis: "PoC confirmed. Permanent proxy lock + $3.1M treasury drain. No recovery possible after malicious upgrade.",
        next_action: "Quantify impact of permanent upgrade lock on protocol security"
      },
      {
        phase: "Impact Analysis",
        description: "Calculate impact of permanent upgrade lock and fund drain",
        tools: ["foundry", "tenderly"],
        commands: [
          "forge test --match-test test_UUPSImpact -vvv --fork-url $RPC_URL",
          "cast call 0xProxyContract 'implementation()' --rpc-url $RPC_URL"
        ],
        expected_output: `Impact analysis:\n  Protocol value at risk: $3.1M (treasury)\n  Post-hijack recovery: impossible (proxy permanently locked)\n  Future security patches: cannot be applied\n  Protocol effectively bricked for all users\n  CVSS 9.7 -- Critical`,
        thinking: "The impact is maximum severity combined with permanence. Once the malicious implementation is set, the proxy can never be upgraded again. This means: 1) The $3.1M treasury is permanently at the attacker's mercy, 2) No security patches can be applied, 3) No bug fixes can be deployed, 4) Users cannot exit (if the malicious implementation blocks withdrawals). The protocol is effectively bricked. CVSS 9.7 -- Critical.",
        analysis: "Critical impact: $3.1M at risk, permanent proxy lock, no recovery possible. Protocol bricked.",
        next_action: "Write audit report recommending ERC-1822 proxiableUUID() validation in upgradeToAndCall()"
      },
      {
        phase: "Audit Report Writing",
        description: "Document UUPS upgrade hijack finding with PoC evidence and ERC-1822 compliance fix",
        tools: ["report_generator"],
        commands: [],
        expected_output: "",
        thinking: "The report must explain the missing ERC-1822 validation, demonstrate the permanent lock + drain PoC, and recommend: 1) Adding proxiableUUID() check in upgradeToAndCall() that verifies the new implementation has the upgrade function, 2) Using OpenZeppelin's UUPSUpgradeable which includes this check, 3) Adding an emergency pause mechanism independent of the upgrade path.",
        analysis: "Compile UUPS upgrade hijack report with ERC-1822 proxiableUUID() validation fix and emergency pause recommendation.",
        next_action: "Submit report"
      }
    ],
    cve_references: ["SWC-112", "CWE-908"],
    tools_involved: ["slither", "foundry", "etherscan", "semgrep", "tenderly", "report_generator"],
    tags: ["uups", "proxy-upgrade", "implementation-hijack", "self-destruct"]
  }
];
