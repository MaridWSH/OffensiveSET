import type { ScenarioTemplate, AttackPhase } from "./types.js";

export const CORE_SCENARIOS: ScenarioTemplate[] = [
  // ─── 1. Rounding Precision Loss ───────────────────────────────────────────
  {
    id: "core-rounding-precision-loss",
    category: "Core Logic & Math Vulnerabilities",
    subcategory: "Rounding & Precision Loss",
    title: "Rounding Precision Loss in Reward Calculation Due to Division Before Multiplication",
    difficulty: "intermediate",
    description:
      "A reward distribution function calculates user shares as `amount / totalSupply * reward`, losing precision when amount < totalSupply. Integer division truncates the quotient to zero before the multiplication step, causing small stakers to receive zero rewards even though they are entitled to a proportional share.",
    target_description:
      "A staking rewards contract (Solidity ^0.8.0) with a `claimRewards()` function that computes each user's reward using the formula `userAmount / totalStaked * rewardPool`. When `userAmount < totalStaked`, the division truncates to 0, and the subsequent multiplication yields 0 regardless of the reward pool size.",
    tools_involved: ["slither", "foundry", "solc", "cast", "anvil", "semgrep"],
    tags: ["rounding", "precision-loss", "reward-calculation", "division", "math"],
    attack_phases: [
      {
        phase: "Code Review & Architecture Analysis",
        description:
          "Read the staking contract source, identify the reward calculation function, and trace the order of arithmetic operations.",
        tools: ["solc", "foundry"],
        commands: [
          "forge build --sizes",
          "cat src/StakingRewards.sol | grep -n 'function claimRewards' -A 20",
          "grep -rn 'totalSupply\\|totalStaked\\|reward' src/StakingRewards.sol",
        ],
        expected_output:
          "Identified `claimRewards()` at line 87. The calculation reads `uint256 reward = user.staked / totalStaked * rewardPool;`. When user.staked (e.g. 1e18) is much smaller than totalStaked (e.g. 1e24), the division yields 0 and the entire expression collapses to 0.",
        thinking:
          "The expression `a / b * c` in Solidity evaluates left-to-right with integer truncation. If a < b, a/b = 0 and the product is 0 regardless of c. The safe pattern is `a * c / b`. I need to verify whether the contract actually uses this dangerous ordering and quantify the loss for typical staker sizes.",
        analysis:
          "The vulnerable line uses division-before-multiplication. For a user staking 100 tokens out of 1,000,000 total, the correct reward should be 0.01% of the pool, but integer arithmetic truncates to 0. This affects all stakers whose proportional share is <1 (i.e., <0.01% of total stake).",
        next_action:
          "Run Slither to confirm the precision-loss pattern and then write a Foundry test that demonstrates the zero-reward outcome for small stakers.",
      },
      {
        phase: "Static Analysis & Automated Scanning",
        description:
          "Use Slither's divide-before-multiply detector and Semgrep rules to automatically flag the vulnerability.",
        tools: ["slither", "semgrep"],
        commands: [
          "slither . --detect divide-before-multiply --solc-remap '@openzeppelin=node_modules/@openzeppelin'",
          "slither . --print human-summary",
          "semgrep --config 'p/solidity' src/StakingRewards.sol",
        ],
        expected_output:
          "Slither reports: '[!] Divide-before-multiply vulnerability in StakingRewards.claimRewards (src/StakingRewards.sol:89): reward = user.staked / totalStaked * rewardPool'. Semgrep echoes a medium-severity finding for 'integer division before multiplication'.",
        thinking:
          "Slither's built-in detector catches this pattern quickly. I should also check whether there are other arithmetic expressions in the contract that might have the same issue — perhaps fee calculations or penalty computations.",
        analysis:
          "Slither confirms the finding with medium confidence. No other instances of divide-before-multiply were found in the codebase, making this an isolated but impactful bug.",
        next_action:
          "Write a Foundry PoC test that deploys the contract, seeds realistic state, and proves small stakers receive 0 rewards while large stakers are unaffected.",
      },
      {
        phase: "Proof of Concept Development",
        description:
          "Create a Forge test that deploys the staking contract, has a whale and a small staker deposit, distribute rewards, and assert the small staker gets 0.",
        tools: ["foundry", "anvil", "cast"],
        commands: [
          "forge test --match-test testRoundingPrecisionLoss -vvvv",
          "cast call $STAKING_ADDR 'claimRewards()(uint256)' --rpc-url http://127.0.0.1:8545",
        ],
        expected_output:
          "Test passes with assertion: smallStaker reward = 0 (expected 50), whale reward = 999950 (expected 1000000). The test logs show totalStaked = 1e24, smallStake = 1e18, rewardPool = 1e6, and the computed reward for the small staker is 0.",
        thinking:
          "The PoC proves the vulnerability with concrete numbers. The small staker loses 100% of their expected reward. Now I need to quantify the total value at risk — how many users are affected and what is the aggregate loss.",
        analysis:
          "The Foundry test demonstrates that any staker with < 0.1% of total stake receives 0 rewards. With current totalStaked of 1e24 and ~500 small stakers, the aggregate misdistributed rewards are approximately 500 * 50 = 25,000 tokens, worth roughly $25,000 at current prices.",
        next_action:
          "Perform impact analysis to calculate the full scope of affected users and the economic damage, then draft the audit finding.",
      },
      {
        phase: "Impact Analysis",
        description:
          "Quantify the number of affected addresses, total misdistributed rewards, and the economic impact on the protocol.",
        tools: ["dune", "cast", "foundry"],
        commands: [
          "cast logs --address $STAKING_ADDR --sig 'Staked(address,uint256)' --from-block 0 --to-block latest --rpc-url $RPC_URL | wc -l",
          "forge script script/AnalyzeAffectedStakers.s.sol --rpc-url $RPC_URL",
        ],
        expected_output:
          "Script output: 1,247 total stakers; 891 stakers (71.4%) receive 0 rewards due to precision loss. Total misdistributed rewards: 1,247,382 tokens ($1,247,382 at $1/token). Protocol TVL: $50M, so the bug affects ~2.5% of total reward budget.",
        thinking:
          "Over 70% of users are receiving zero rewards. This is a widespread user-facing bug that could trigger governance backlash. The fix is straightforward — reorder the arithmetic — but historical rewards cannot be retroactively distributed without a migration.",
        analysis:
          "Severity: Medium-High. The bug is deterministic and affects the majority of users. Economic impact exceeds $1M. The fix is a one-line change (`a / b * c` -> `a * c / b`) but historical losses are unrecoverable without governance intervention.",
        next_action:
          "Write the audit report with severity classification, affected code references, PoC evidence, and recommended fix.",
      },
      {
        phase: "Audit Report Writing",
        description:
          "Compile findings into a structured audit report following standard format: title, description, impact, PoC, recommendation, and remediated code.",
        tools: ["report_generator"],
        commands: [
          "forge fmt src/StakingRewards.sol",
          "echo 'Generating audit report...' && node scripts/generate-report.js core-rounding-precision-loss",
        ],
        expected_output:
          "Audit report generated: findings/core-rounding-precision-loss.md with severity Medium, SWC-128, CWE-682, CVSS 5.3. Report includes vulnerable code snippet, PoC test output, impact quantification, and fixed code using `user.staked * rewardPool / totalStaked`.",
        thinking:
          "The report is complete. The key recommendation is to use the multiply-then-divide pattern and consider using a library like PRBMath for fixed-point arithmetic to avoid precision loss entirely in future calculations.",
        analysis:
          "Final severity assessment: Medium (CVSS 5.3). The vulnerability is well-understood, easily exploitable, and affects a large user base. The fix is trivial to implement but historical damages are irreversible.",
        next_action:
          "Submit report to the protocol team and recommend an immediate patch plus a governance proposal for retroactive reward distribution.",
      },
    ],
  },

  // ─── 2. Integer Overflow ──────────────────────────────────────────────────
  {
    id: "core-integer-overflow",
    category: "Core Logic & Math Vulnerabilities",
    subcategory: "Integer Overflow",
    title: "Integer Overflow in Cumulative Reward Index Calculation",
    difficulty: "advanced",
    description:
      "A DeFi protocol's reward index calculation uses unchecked multiplication that overflows when total staked amount and reward rate are both large, causing the index to wrap around to a small value. Users who stake after the overflow receive massively inflated rewards at the expense of the protocol.",
    target_description:
      "A yield farming contract (Solidity ^0.7.6, pre-0.8 safe math not enabled) with an `updateRewardIndex()` function that computes `rewardIndex += (block.timestamp - lastUpdateTime) * rewardRate / totalStaked`. When totalStaked is small and the time delta is large, the intermediate product overflows uint256.",
    tools_involved: ["slither", "foundry", "mythril", "semgrep", "solc"],
    tags: ["integer-overflow", "unchecked-math", "reward-index", "solidity-0.7", "defi"],
    attack_phases: [
      {
        phase: "Code Review & Architecture Analysis",
        description:
          "Examine the reward index update logic, check the Solidity compiler version, and verify whether SafeMath is imported and used for the critical multiplication.",
        tools: ["solc", "foundry"],
        commands: [
          "head -5 src/YieldFarming.sol",
          "grep -n 'pragma\\|import\\|SafeMath\\|using.*for' src/YieldFarming.sol",
          "grep -n 'rewardIndex.*+=' -A 3 src/YieldFarming.sol",
        ],
        expected_output:
          "File uses `pragma solidity ^0.7.6;`. No SafeMath import found. Line 142: `rewardIndex += (block.timestamp - lastUpdateTime) * rewardRate / totalStaked;`. The multiplication `(block.timestamp - lastUpdateTime) * rewardRate` is performed in unchecked arithmetic on Solidity 0.7, which does not have built-in overflow protection.",
        thinking:
          "Solidity 0.7 has no automatic overflow checking. The intermediate product of a large time delta (e.g., 1e9 seconds ~ 31 years) and a large rewardRate (e.g., 1e20) can easily exceed 2^256. When this overflows, the index wraps to a small value, making it appear as though very few rewards have accrued. Users staking after the overflow get a cheap entry point.",
        analysis:
          "The unchecked overflow is a critical vulnerability. An attacker can wait for the index to overflow (or force it by pausing reward updates for a long period), then stake and claim rewards calculated against the artificially low index, effectively minting unlimited tokens.",
        next_action:
          "Run Mythril and Slither to detect integer overflow patterns, then build a PoC that triggers the overflow and demonstrates the exploit.",
      },
      {
        phase: "Static Analysis & Automated Scanning",
        description:
          "Run multiple static analyzers to detect the unchecked arithmetic in the reward index calculation.",
        tools: ["slither", "mythril", "semgrep"],
        commands: [
          "slither . --detect unchecked-transfer --solc-version 0.7.6",
          "slither . --print vars-and-auth 2>&1 | grep -i 'overflow\\|unchecked'",
          "myth analyze src/YieldFarming.sol --solver-timeout 30 --execution-timeout 60",
        ],
        expected_output:
          "Slither: '[!] Unchecked low-level call in updateRewardIndex — potential integer overflow on line 142.' Mythril: 'Exception state: integer overflow in MUL instruction at PC 0x2a4f. Reward index can wrap from 2^256-1 to 0.'",
        thinking:
          "Both tools confirm the overflow. Mythril found the exact PC where the MUL instruction wraps. I need to construct a test case where the overflow actually occurs — this requires specific values of time delta and reward rate.",
        analysis:
          "The overflow is reachable with realistic parameters. If rewardRate = 1e18 per second and the contract pauses for ~37 years (1.16e9 seconds), the product exceeds 2^256. More practically, if rewardRate is set very high by a governance exploit, the overflow can happen in hours.",
        next_action:
          "Write a Foundry test that either fast-forwards time or sets extreme rewardRate values to trigger the overflow, then demonstrates the exploit.",
      },
      {
        phase: "Proof of Concept Development",
        description:
          "Forge test that sets a high rewardRate, fast-forwards time past the overflow boundary, calls updateRewardIndex, and shows the index wraps to near-zero.",
        tools: ["foundry", "anvil", "cast"],
        commands: [
          "forge test --match-test testIntegerOverflowIndex -vvvv",
          "cast run $TX_HASH --rpc-url http://127.0.0.1:8545",
        ],
        expected_output:
          "Test output: Before overflow: rewardIndex = 1.1579e77 (near max uint256). After updateRewardIndex with dt=1e9 and rewardRate=1e20: rewardIndex = 340282366920938463463374607431768211455 (wrapped value). Attacker stakes 1e18 tokens, claims rewards of 1e59 tokens (effectively infinite).",
        thinking:
          "The PoC shows that after overflow, the attacker can claim rewards that exceed the entire token supply. This is effectively a mint vulnerability. The protocol's reward token balance in the contract cannot cover this, so the claim would either revert or drain the entire reserve.",
        analysis:
          "The overflow enables an attacker to claim rewards exceeding the protocol's total supply. This is a Critical severity issue. If the reward token is mintable, the attacker can mint effectively unlimited tokens. If it's a fixed-supply ERC20, the claim reverts and the protocol is permanently bricked.",
        next_action:
          "Quantify the maximum exploitable value and write the impact analysis.",
      },
      {
        phase: "Impact Analysis",
        description:
          "Determine the conditions under which the overflow is reachable, the maximum damage, and whether it requires privileged access.",
        tools: ["dune", "foundry"],
        commands: [
          "forge script script/AnalyzeOverflowImpact.s.sol --rpc-url $RPC_URL -vvv",
          "cast call $FARMING_ADDR 'rewardRate()(uint256)' --rpc-url $RPC_URL",
        ],
        expected_output:
          "Current rewardRate = 1e18 per block. At this rate, overflow occurs after ~1.16e59 seconds (~3.6e51 years) — not reachable naturally. However, if an attacker gains governance access and sets rewardRate to 1e50, overflow occurs in ~11 seconds. Governance compromise + overflow = unlimited mint.",
        thinking:
          "The overflow is not reachable under current parameters but becomes critical if the protocol's governance is compromised. This is a 'time-bomb' vulnerability — it doesn't require immediate patching for current parameters but must be fixed because parameter changes are within governance scope.",
        analysis:
          "Severity: High (CVSS 7.8). The vulnerability requires either an extreme governance misconfiguration or a governance takeover to be exploitable in practice. However, the consequences are catastrophic (unlimited mint). Fix: use SafeMath or upgrade to Solidity 0.8+.",
        next_action:
          "Draft the audit report with detailed overflow conditions, exploit path, and the SafeMath remediation.",
      },
      {
        phase: "Audit Report Writing",
        description:
          "Produce the audit finding with overflow analysis, exploit scenario, and fix recommendation using SafeMath or Solidity 0.8+.",
        tools: ["report_generator"],
        commands: [
          "echo 'Generating audit report...' && node scripts/generate-report.js core-integer-overflow",
        ],
        expected_output:
          "Audit report generated: findings/core-integer-overflow.md with severity High, SWC-101, CWE-190, CVSS 7.8. Report includes the overflow equation, the reachable exploit path via governance manipulation, PoC test output, and fixed code importing SafeMath for the critical multiplication.",
        thinking:
          "The report should emphasize that while the overflow is not immediately reachable, it represents a permanent risk tied to governance parameter changes. The recommended fix is straightforward and eliminates the risk entirely.",
        analysis:
          "Final severity: High. The fix is to wrap the multiplication in SafeMath or use Solidity 0.8+. Additionally, the protocol should cap the rewardRate parameter to prevent governance from accidentally creating overflow conditions.",
        next_action:
          "Submit findings and recommend upgrading to Solidity 0.8+ with parameter caps on rewardRate.",
      },
    ],
  },

  // ─── 3. Storage Collision ─────────────────────────────────────────────────
  {
    id: "core-storage-collision",
    category: "Core Logic & Math Vulnerabilities",
    subcategory: "Storage Collision",
    title: "Storage Collision Between Inherited Contract State Variables",
    difficulty: "expert",
    description:
      "Two contracts in an inheritance chain declare state variables with the same name but different types, causing writes to one variable to corrupt the other's storage slot. This is particularly dangerous in upgradeable proxy patterns where the implementation contract's storage layout must exactly match the proxy's expected layout.",
    target_description:
      "An upgradeable token contract (UUPS pattern, Solidity ^0.8.19) where the base contract declares `uint256 public totalSupply;` at slot 0 and the derived implementation declares `address public totalSupply;` at what it believes is a different slot, but Solidity's inheritance model places both at slot 0, causing type corruption.",
    tools_involved: ["slither", "foundry", "solc", "semgrep"],
    tags: ["storage-collision", "inheritance", "state-corruption", "upgradeable"],
    attack_phases: [
      {
        phase: "Code Review & Architecture Analysis",
        description:
          "Map the full inheritance hierarchy and storage layout of the upgradeable contract, looking for overlapping slot assignments between base and derived contracts.",
        tools: ["solc", "foundry", "slither"],
        commands: [
          "slither . --print storage-layout",
          "forge inspect UpgradableToken storage-layout --pretty",
          "grep -rn 'uint256\\|address\\|mapping' src/UpgradableToken.sol src/BaseToken.sol | head -40",
        ],
        expected_output:
          "Slither storage-layout output shows: BaseToken.slot[0] = totalSupply (uint256), UpgradableToken.slot[0] = totalSupply (address). Both occupy slot 0. The derived contract's address-typed totalSupply overwrites the base's uint256 at the same slot.",
        thinking:
          "This is a classic storage collision in upgradeable contracts. The proxy delegates calls to the implementation, but the implementation's storage layout doesn't match what the proxy expects. When the derived contract writes to what it thinks is its own variable, it corrupts the base contract's storage. In an UUPS pattern, this could allow an attacker to overwrite the implementation address itself.",
        analysis:
          "The collision at slot 0 means any read of totalSupply from the base returns a truncated/reinterpreted address value, and any write from the derived overwrites the actual supply counter. This corrupts all balance tracking and could be leveraged to manipulate the proxy's implementation address if the collision extends to critical slots.",
        next_action:
          "Run static analysis to confirm the collision and check if other slots are also affected.",
      },
      {
        phase: "Static Analysis & Automated Scanning",
        description:
          "Use Slither's inheritance checking and storage layout tools to identify all colliding slots across the inheritance chain.",
        tools: ["slither", "semgrep"],
        commands: [
          "slither . --detect shadowing-state --solc-remap '@openzeppelin=node_modules/@openzeppelin'",
          "slither . --print inheritance-graph",
          "semgrep --config 'p/solidity' src/",
        ],
        expected_output:
          "Slither: '[!] State variable shadowing detected: UpgradableToken.totalSupply shadows BaseToken.totalSupply at slot 0. Types differ: address vs uint256.' Additional findings: 3 more slots have shadowed variables with type mismatches.",
        thinking:
          "Four storage slots are colliding. This means the contract's entire state is corrupted. I need to understand which slots contain critical data like the implementation address, owner, and any access control mappings.",
        analysis:
          "Slots 0-3 are all affected. Slot 0 (totalSupply), Slot 1 (owner), Slot 2 (paused), Slot 3 (implementation in UUPS). An attacker who can write to any of the derived contract's shadowed variables can corrupt critical protocol state including the implementation address, effectively gaining upgrade control.",
        next_action:
          "Write a PoC that demonstrates storage corruption and shows how an attacker can hijack the proxy's implementation address.",
      },
      {
        phase: "Proof of Concept Development",
        description:
          "Forge test deploying the proxy, initializing state, writing to a derived variable, and reading the corrupted base variable to show the storage collision.",
        tools: ["foundry", "anvil", "cast"],
        commands: [
          "forge test --match-test testStorageCollision -vvvv",
          "cast storage $PROXY_ADDR 0 --rpc-url http://127.0.0.1:8545",
        ],
        expected_output:
          "Test output: After calling derived.setTotalSupply(0xdead...beef), reading base.totalSupply returns 160473799752787249540385876848670231785485805166447 (reinterpretation of the address as uint256). Storage slot 3 (implementation) shows corrupted value after writing to derived's shadowed implementation variable.",
        thinking:
          "The PoC proves the collision. Now I need to show the attack path: if the derived contract has any function that writes to a shadowed variable, an attacker can use it to corrupt the implementation address and point the proxy to a malicious implementation.",
        analysis:
          "The attack path is: (1) Attacker calls a derived function that writes to a shadowed variable, (2) This corrupts a critical slot (e.g., implementation address), (3) The proxy now delegates to attacker-controlled code, (4) Attacker drains all funds. This is Critical severity.",
        next_action:
          "Quantify the attack path and write the impact analysis.",
      },
      {
        phase: "Impact Analysis",
        description:
          "Map the full attack path from storage corruption to fund drainage and assess the conditions required for exploitation.",
        tools: ["foundry", "cast"],
        commands: [
          "forge test --match-test testFullStorageCollisionExploit -vvvv",
          "cast call $PROXY_ADDR 'implementation()(address)' --rpc-url http://127.0.0.1:8545",
        ],
        expected_output:
          "Full exploit test passes: attacker corrupts implementation slot via derived.writeImpl(attackerContract), proxy delegates to attacker's contract, attacker calls drain() and extracts 5,000,000 USDC from the proxy. Protocol TVL: $50M, all funds are drainable.",
        thinking:
          "This is a full protocol compromise. The storage collision in an upgradeable proxy gives the attacker a path to take complete control of the contract. The fix requires careful storage layout management using the Unstructured Storage pattern or OpenZeppelin's storage gap technique.",
        analysis:
          "Severity: Critical (CVSS 9.8). The vulnerability allows complete protocol takeover and fund drainage. Exploitation requires the attacker to call a function that writes to a shadowed variable — if such a function is public or externally accessible, exploitation is trivial.",
        next_action:
          "Write the audit report with the full attack chain and recommend the storage gap pattern as the fix.",
      },
      {
        phase: "Audit Report Writing",
        description:
          "Produce the audit report documenting the storage collision, the exploit chain, and the remediation using OpenZeppelin's storage gap pattern.",
        tools: ["report_generator"],
        commands: [
          "echo 'Generating audit report...' && node scripts/generate-report.js core-storage-collision",
        ],
        expected_output:
          "Audit report generated: findings/core-storage-collision.md with severity Critical, SWC-124, CWE-787, CVSS 9.8. Report includes storage layout diagrams, the exploit chain, PoC output, and fixed code using `uint256[50] private __gap;` to reserve storage slots.",
        thinking:
          "The report should emphasize that upgradeable contracts must never have state variable shadowing. The fix is structural — using storage gaps — and requires careful auditing of the entire inheritance chain.",
        analysis:
          "Final severity: Critical. This is a design-level vulnerability that fundamentally breaks the security model of the upgradeable proxy pattern. The fix requires restructuring the contract inheritance and redeploying with proper storage layout.",
        next_action:
          "Submit findings with an urgent recommendation to pause the contract and redeploy with proper storage layout.",
      },
    ],
  },

  // ─── 4. Logic Error in State Transition ───────────────────────────────────
  {
    id: "core-logic-error-state",
    category: "Core Logic & Math Vulnerabilities",
    subcategory: "Logic Error in State Transition",
    title: "Logic Error in State Transition Allows Bypass of Liquidity Lock",
    difficulty: "advanced",
    description:
      "A protocol's liquidity lock mechanism has a logic error where the unlock condition checks `block.timestamp > lockEndTime` instead of `>=`, allowing withdrawal one block early and front-running the lock renewal.",
    target_description:
      "A liquidity lock contract (Solidity ^0.8.12) that locks LP tokens until a specified unlock time. The `withdraw()` function uses `require(block.timestamp > lock.unlockTime, 'Still locked')` instead of `>=`, creating a one-block window where the lock can be bypassed.",
    tools_involved: ["slither", "foundry", "anvil", "cast", "tenderly"],
    tags: ["logic-error", "state-transition", "liquidity-lock", "off-by-one", "front-running"],
    attack_phases: [
      {
        phase: "Code Review & Architecture Analysis",
        description:
          "Review the liquidity lock contract's withdrawal logic, focusing on the time-check condition and state transition guards.",
        tools: ["solc", "foundry"],
        commands: [
          "cat src/LiquidityLock.sol | grep -n 'function withdraw' -A 15",
          "grep -n 'lockEndTime\\|unlockTime\\|block.timestamp' src/LiquidityLock.sol",
          "forge build",
        ],
        expected_output:
          "Line 64: `require(block.timestamp > lock.unlockTime, 'Still locked');`. The condition uses strict greater-than (`>`) instead of greater-than-or-equal (`>=`). This means at exactly `block.timestamp == lock.unlockTime`, the require passes and withdrawal is allowed one block (or more precisely, at the exact timestamp) before the intended unlock.",
        thinking:
          "This is an off-by-one logic error. The intent is to lock until lockEndTime inclusive, but the strict inequality allows withdrawal at lockEndTime. In practice, since block timestamps are in seconds, the attacker can withdraw at the exact unlock second. If the protocol relies on the lock persisting through that second (e.g., for a token launch or liquidity event), the attacker can withdraw and front-run.",
        analysis:
          "The vulnerability is subtle but impactful. If the lock is meant to ensure liquidity during a critical event at time T, and the attacker can withdraw at time T, they can remove liquidity right before the event and front-run other participants. The severity depends on what the lock is protecting.",
        next_action:
          "Run static analysis to confirm the logic error and then write a PoC test.",
      },
      {
        phase: "Static Analysis & Automated Scanning",
        description:
          "Use Slither and Semgrep to flag the off-by-one comparison in the time check.",
        tools: ["slither", "semgrep"],
        commands: [
          "slither . --detect timestamp --solc-remap '@openzeppelin=node_modules/@openzeppelin'",
          "semgrep --config 'p/solidity' src/LiquidityLock.sol 2>&1 | grep -i 'timestamp\\|comparison'",
        ],
        expected_output:
          "Slither: '[!] Timestamp comparison in LiquidityLock.withdraw (src/LiquidityLock.sol:64) uses strict inequality, may allow early withdrawal.' Semgrep: 'Warning: Off-by-one time comparison — consider using >= instead of > for lock expiry checks.'",
        thinking:
          "Both tools flag the issue. This is a known pattern that static analyzers can detect. The fix is trivial but the impact depends on the economic context of the lock. I need to model the attack scenario.",
        analysis:
          "The vulnerability is confirmed. The attack scenario: attacker locks liquidity until time T, protocol plans a token launch at T, attacker withdraws at T and sells their tokens before any other participants can buy, effectively rug-pulling the launch.",
        next_action:
          "Write a Foundry test that demonstrates withdrawal at the exact unlock timestamp.",
      },
      {
        phase: "Proof of Concept Development",
        description:
          "Forge test that locks LP tokens, warps to the exact unlock time, withdraws successfully (which should have been blocked), and shows the liquidity is removed.",
        tools: ["foundry", "anvil", "cast"],
        commands: [
          "forge test --match-test testLogicErrorLiquidityLock -vvvv",
          "cast call $LOCK_ADDR 'getLockInfo(uint256)(address,uint256,uint256,bool)' 0 --rpc-url http://127.0.0.1:8545",
        ],
        expected_output:
          "Test output: Lock created with unlockTime = 1700000000. vm.warp(1700000000). withdraw(0) succeeds (should fail). LP balance in lock contract goes from 1,000,000 to 0. Attacker now holds all LP tokens and can remove liquidity from the pool before the launch event.",
        thinking:
          "The PoC proves that withdrawal at the exact unlock timestamp succeeds. Now I need to model the full attack: attacker withdraws LP, removes liquidity from the pool, and sells at the peak price before the launch.",
        analysis:
          "The PoC demonstrates the bypass. The attacker can withdraw LP tokens at the exact unlock time and immediately remove liquidity from the AMM pool. If the pool has $1M in liquidity, the attacker captures all of it.",
        next_action:
          "Perform impact analysis quantifying the liquidity at risk and the profit from the front-run.",
      },
      {
        phase: "Impact Analysis",
        description:
          "Calculate the total locked liquidity value, the profit from the front-run attack, and the conditions under which the attack is profitable.",
        tools: ["dune", "tenderly", "foundry"],
        commands: [
          "cast call $LOCK_ADDR 'totalLocked()(uint256)' --rpc-url $RPC_URL",
          "forge script script/AnalyzeLockImpact.s.sol --rpc-url $RPC_URL",
        ],
        expected_output:
          "Total locked liquidity: 2,500,000 LP tokens worth $2.5M. The attacker can withdraw at the exact unlock time, remove liquidity from the pool, and profit approximately $400K from the price impact before other participants react. The attack is profitable as long as the pool has meaningful depth.",
        thinking:
          "The attack is highly profitable and requires no special capital beyond the locked tokens. The fix is a one-character change (> to >=), but the window of exploitation is the entire duration of the lock — the attacker can plan the withdrawal precisely.",
        analysis:
          "Severity: High (CVSS 7.5). The vulnerability allows an attacker to bypass a critical security control (liquidity lock) and profit significantly. The attack requires no privileged access and is deterministic.",
        next_action:
          "Write the audit report with the off-by-one finding, attack simulation, and the one-character fix.",
      },
      {
        phase: "Audit Report Writing",
        description:
          "Produce the audit report with the off-by-one logic error, the attack simulation, and the corrected comparison operator.",
        tools: ["report_generator"],
        commands: [
          "echo 'Generating audit report...' && node scripts/generate-report.js core-logic-error-state",
        ],
        expected_output:
          "Audit report generated: findings/core-logic-error-state.md with severity High, SWC-102, CWE-841, CVSS 7.5. Report includes the vulnerable comparison, the PoC demonstrating withdrawal at exact unlock time, attack profit simulation ($400K), and the fix: change `>` to `>=`.",
        thinking:
          "This is a textbook example of how a single-character logic error can undermine an entire security mechanism. The report should emphasize the importance of using >= for time-based comparisons and recommend comprehensive testing of boundary conditions.",
        analysis:
          "Final severity: High. The fix is trivial but the impact is significant. Recommend adding boundary condition tests to the CI pipeline to catch similar off-by-one errors in the future.",
        next_action:
          "Submit findings and recommend immediate patch plus regression tests for all time-based comparisons.",
      },
    ],
  },

  // ─── 5. Basic Reentrancy ──────────────────────────────────────────────────
  {
    id: "core-reentrancy-basic",
    category: "Core Logic & Math Vulnerabilities",
    subcategory: "Basic Reentrancy",
    title: "Basic Reentrancy in Withdraw Function via External Call Before State Update",
    difficulty: "intermediate",
    description:
      "A vault's withdraw function sends ETH to the user before updating their balance, enabling classic reentrancy to drain the entire vault. This is the original DAO-style reentrancy pattern.",
    target_description:
      "An ETH vault contract (Solidity ^0.8.10) with a `withdraw(uint256 amount)` function that: (1) checks balance, (2) sends ETH via `payable(msg.sender).transfer(amount)`, (3) updates balance. The external call happens before the state update, allowing a malicious contract to re-enter withdraw() before its balance is decremented.",
    tools_involved: ["slither", "foundry", "anvil", "cast", "echidna"],
    tags: ["reentrancy", "withdraw", "external-call", "checks-effects-interactions", "drain"],
    attack_phases: [
      {
        phase: "Code Review & Architecture Analysis",
        description:
          "Review the vault's withdraw function and verify the ordering of the checks-effects-interactions pattern.",
        tools: ["solc", "foundry"],
        commands: [
          "cat src/ETHVault.sol | grep -n 'function withdraw' -A 20",
          "grep -n 'transfer\\|send\\|call\\|balance' src/ETHVault.sol",
        ],
        expected_output:
          "Lines 45-55: withdraw() calls `payable(msg.sender).transfer(amount)` at line 49, then `balances[msg.sender] -= amount` at line 52. The external transfer precedes the state update, violating the checks-effects-interactions pattern.",
        thinking:
          "This is the classic reentrancy pattern. The transfer to msg.sender allows a malicious contract's receive() fallback to re-enter withdraw() before the balance is updated. On the second call, the balance check still passes because it hasn't been decremented yet. The attacker can drain the entire vault by calling withdraw repeatedly in a loop.",
        analysis:
          "The vulnerability is textbook reentrancy. Even though Solidity 0.8+ has built-in overflow protection and `transfer` has a 2300 gas stipend, the stipend is sufficient for calling back into the same contract's withdraw function (which only performs a balance check, a transfer, and a subtraction). The entire vault balance is at risk.",
        next_action:
          "Run Slither's reentrancy detector and then write the attack contract PoC.",
      },
      {
        phase: "Static Analysis & Automated Scanning",
        description:
          "Use Slither's reentrancy detectors to automatically identify the vulnerability.",
        tools: ["slither", "echidna"],
        commands: [
          "slither . --detect reentrancy-eth,reentrancy-no-eth --solc-remap '@openzeppelin=node_modules/@openzeppelin'",
          "slither . --print human-summary",
          "echidna . --test-limit 10000 --contract ETHVault",
        ],
        expected_output:
          "Slither: '[!] Reentrancy vulnerability in ETHVault.withdraw (src/ETHVault.sol:45-55): External call at line 49 can re-enter before state update at line 52. Consider applying the check-effects-interactions pattern.' Echidna: Found invariant violation — vault balance can go below total deposits.",
        thinking:
          "Slither's reentrancy-eth detector catches this because the external call involves ETH transfer. Echidna also found the invariant violation through fuzzing. This confirms the vulnerability is real and exploitable.",
        analysis:
          "Both static analysis and property-based fuzzing confirm the reentrancy. The attack is straightforward: deploy a malicious contract with a receive() fallback that calls withdraw() recursively until the vault is empty.",
        next_action:
          "Write the reentrancy attack contract and Foundry test.",
      },
      {
        phase: "Proof of Concept Development",
        description:
          "Forge test deploying the vault, an attacker contract, and demonstrating a full vault drain via reentrancy.",
        tools: ["foundry", "anvil", "cast"],
        commands: [
          "forge test --match-test testBasicReentrancy -vvvv",
          "cast balance $ATTACKER_ADDR --rpc-url http://127.0.0.1:8545",
        ],
        expected_output:
          "Test output: Vault initially holds 100 ETH. Attacker deposits 10 ETH, calls withdraw(10 ETH), receive() re-enters withdraw(10 ETH) 10 times. Vault balance goes from 100 ETH to 0 ETH. Attacker receives 100 ETH total (90 ETH profit). Test assertion: vault.balance == 0, attacker.balance == 100e18.",
        thinking:
          "The PoC drains the entire vault including other users' funds. The attack works because each recursive call sees the attacker's balance as still being 10 ETH (it hasn't been decremented yet). After 10 iterations, the vault is empty. This is the classic DAO attack.",
        analysis:
          "The PoC proves complete vault drainage. All user funds (100 ETH total) are stolen by the attacker who only deposited 10 ETH. The attack is fully automated and executes in a single transaction.",
        next_action:
          "Perform impact analysis and draft the audit report.",
      },
      {
        phase: "Impact Analysis",
        description:
          "Determine the total value at risk, number of affected users, and the attack cost.",
        tools: ["dune", "cast"],
        commands: [
          "cast call $VAULT_ADDR 'totalDeposits()(uint256)' --rpc-url $RPC_URL",
          "cast call $VAULT_ADDR 'depositorCount()(uint256)' --rpc-url $RPC_URL",
        ],
        expected_output:
          "Total deposits: 500 ETH across 47 depositors. A single attacker with a minimum deposit of 1 ETH can drain the entire vault. Attack cost: 1 ETH minimum deposit. Potential loss: 500 ETH ($1.5M at $3000/ETH).",
        thinking:
          "The attack is extremely cheap (1 ETH minimum) and the potential loss is 500 ETH. This is a Critical vulnerability — the entire protocol is one transaction away from total insolvency.",
        analysis:
          "Severity: Critical (CVSS 9.8). The reentrancy allows complete fund drainage with minimal capital. The fix is to apply the checks-effects-interactions pattern: update the balance before sending ETH, or use a ReentrancyGuard modifier.",
        next_action:
          "Write the audit report with the ReentrancyGuard fix recommendation.",
      },
      {
        phase: "Audit Report Writing",
        description:
          "Produce the audit report documenting the reentrancy vulnerability, the drain PoC, and the recommended fix.",
        tools: ["report_generator"],
        commands: [
          "echo 'Generating audit report...' && node scripts/generate-report.js core-reentrancy-basic",
        ],
        expected_output:
          "Audit report generated: findings/core-reentrancy-basic.md with severity Critical, SWC-107, CWE-841, CVSS 9.8. Report includes the vulnerable code ordering, the reentrancy attack contract, drain PoC (500 ETH stolen), and two fix options: (1) reorder to checks-effects-interactions, (2) add ReentrancyGuard modifier.",
        thinking:
          "The report provides two remediation paths. The simplest is reordering the statements (update balance before transfer). The defense-in-depth approach adds ReentrancyGuard as well. Both should be recommended.",
        analysis:
          "Final severity: Critical. The fix is straightforward and should be applied immediately. Recommend an emergency pause until the patch is deployed.",
        next_action:
          "Submit findings with an urgent recommendation to pause deposits and deploy the fix.",
      },
    ],
  },

  // ─── 6. DoS via Griefing ──────────────────────────────────────────────────
  {
    id: "core-dos-griefing",
    category: "Core Logic & Math Vulnerabilities",
    subcategory: "DoS via Griefing",
    title: "Denial of Service via Griefing Attack on Batch Processing Loop",
    difficulty: "intermediate",
    description:
      "A batch processing function loops over an array of user claims and reverts if any single claim fails, allowing an attacker to submit a malicious claim that blocks all other users from claiming.",
    target_description:
      "A Merkle airdrop contract (Solidity ^0.8.15) with a `batchClaim(address[] calldata users, bytes32[][] calldata proofs)` function that iterates over users and calls `_claim(user, proof)` for each. If any single claim reverts (e.g., due to an invalid proof), the entire batch reverts, blocking all claims in that batch.",
    tools_involved: ["slither", "foundry", "semgrep", "anvil"],
    tags: ["dos", "griefing", "batch-processing", "loop-revert", "availability"],
    attack_phases: [
      {
        phase: "Code Review & Architecture Analysis",
        description:
          "Review the batch claim function to understand the loop structure and error handling behavior.",
        tools: ["solc", "foundry"],
        commands: [
          "cat src/MerkleAirdrop.sol | grep -n 'function batchClaim' -A 25",
          "grep -n 'require\\|revert\\|try.*catch' src/MerkleAirdrop.sol",
        ],
        expected_output:
          "Lines 78-95: batchClaim() loops `for (uint i = 0; i < users.length; i++) { _claim(users[i], proofs[i]); }`. The _claim function has `require(verify(proof, root, leaf), 'Invalid proof')` which reverts on bad input. No try/catch wrapping. A single invalid proof causes the entire batch to revert.",
        thinking:
          "This is a classic DoS via griefing pattern. An attacker can insert their own address with an invalid proof into another user's batch claim, or a user can submit a batch with one intentionally invalid entry to prevent others from claiming. The lack of try/catch means there's no way to skip failed claims.",
        analysis:
          "The vulnerability enables an attacker to permanently block all batch claims by submitting a batch with one invalid entry. Since the batch is public (anyone can call it), the attacker can front-run legitimate batch claims and insert a bad entry.",
        next_action:
          "Run static analysis and write the griefing PoC.",
      },
      {
        phase: "Static Analysis & Automated Scanning",
        description:
          "Use Slither and Semgrep to detect the unhandled revert in the batch processing loop.",
        tools: ["slither", "semgrep"],
        commands: [
          "slither . --detect unchecked-send --solc-remap '@openzeppelin=node_modules/@openzeppelin'",
          "semgrep --config 'p/solidity' src/MerkleAirdrop.sol 2>&1 | grep -i 'loop\\|revert\\|dos'",
        ],
        expected_output:
          "Slither: '[!] Unhandled exception in loop body in batchClaim. A single failure reverts the entire batch.' Semgrep: 'Warning: Denial of Service — loop body contains reverting call without try/catch. Consider using a pull-over-push pattern or skipping failed entries.'",
        thinking:
          "Both tools flag the issue. The fix is to wrap each _claim call in a try/catch and emit an event for failed claims, allowing the batch to continue processing remaining users.",
        analysis:
          "The vulnerability is confirmed. An attacker can permanently block claims by repeatedly submitting batches with invalid entries. The fix requires restructuring the batch function to handle individual failures gracefully.",
        next_action:
          "Write the griefing PoC test.",
      },
      {
        phase: "Proof of Concept Development",
        description:
          "Forge test that demonstrates an attacker inserting an invalid proof into a batch, causing the entire batch to revert and blocking legitimate users.",
        tools: ["foundry", "anvil", "cast"],
        commands: [
          "forge test --match-test testDosGriefing -vvvv",
          "cast call $AIRDROP_ADDR 'claimed(address)(bool)' $VICTIM_ADDR --rpc-url http://127.0.0.1:8545",
        ],
        expected_output:
          "Test output: Batch of 10 users submitted with 1 invalid proof. Entire batch reverts with 'Invalid proof'. All 10 users' claims fail. Attacker repeats this 5 times, each time inserting a bad proof into a different position. No user can claim for 5 consecutive attempts.",
        thinking:
          "The PoC shows the attacker can persistently block all claims. The legitimate users have no recourse — they can't submit a batch without the attacker's bad entry, and individual claim functions don't exist. The protocol is effectively frozen.",
        analysis:
          "The griefing attack permanently blocks the batch claim function. The attacker only needs to submit one transaction per block to keep inserting bad entries. This is a High severity availability issue.",
        next_action:
          "Quantify the impact and draft the audit report.",
      },
      {
        phase: "Impact Analysis",
        description:
          "Assess the number of affected users, the duration of the DoS, and the economic impact.",
        tools: ["dune", "foundry"],
        commands: [
          "forge script script/AnalyzeDosImpact.s.sol --rpc-url $RPC_URL",
          "cast logs --address $AIRDROP_ADDR --sig 'Claimed(address,uint256)' --rpc-url $RPC_URL | wc -l",
        ],
        expected_output:
          "Analysis: 2,341 eligible claimants, 0 claims processed due to persistent griefing. Total unclaimed airdrop value: 500,000 tokens ($500K). The DoS has persisted for 48 hours across 12 attempted batch submissions. Each attempt was griefed by the attacker within the same block.",
        thinking:
          "The DoS is persistent and the attacker can maintain it indefinitely at minimal cost (one transaction per block). The economic impact is $500K in unclaimed tokens. The fix requires adding try/catch to the batch loop and/or adding an individual claim function as a fallback.",
        analysis:
          "Severity: High (CVSS 7.1). The attack is cheap to maintain, affects all users, and blocks a core protocol function. The fix is to add try/catch around each claim in the batch loop.",
        next_action:
          "Write the audit report with the try/catch fix and individual claim fallback recommendation.",
      },
      {
        phase: "Audit Report Writing",
        description:
          "Produce the audit report with the DoS analysis, griefing PoC, and recommended fixes.",
        tools: ["report_generator"],
        commands: [
          "echo 'Generating audit report...' && node scripts/generate-report.js core-dos-griefing",
        ],
        expected_output:
          "Audit report generated: findings/core-dos-griefing.md with severity High, SWC-113, CWE-400, CVSS 7.1. Report includes the vulnerable loop code, the griefing attack flow, impact data (2,341 blocked users, $500K unclaimed), and two fixes: (1) wrap _claim in try/catch, (2) add individual claim function.",
        thinking:
          "The report should recommend both the immediate fix (try/catch) and the architectural improvement (individual claim fallback). The try/catch approach emits events for failed claims so users can retry individually.",
        analysis:
          "Final severity: High. The DoS is persistent and affects all users. Immediate fix: add try/catch. Long-term improvement: add individual claim function.",
        next_action:
          "Submit findings and recommend the try/catch fix with event emission for failed claims.",
      },
    ],
  },

  // ─── 7. Signature Malleability ────────────────────────────────────────────
  {
    id: "core-signature-malleability",
    category: "Core Logic & Math Vulnerabilities",
    subcategory: "Signature Malleability",
    title: "ECDSA Signature Malleability Allowing Duplicate Claim",
    difficulty: "advanced",
    description:
      "A claim function uses ecrecover without checking for signature malleability (s-value high/low), allowing an attacker to submit the same claim twice with different but valid signature encodings.",
    target_description:
      "A signature-based claim contract (Solidity ^0.8.17) with a `claim(uint256 amount, uint8 v, bytes32 r, bytes32 s)` function that verifies `ecrecover(hash, v, r, s) == signer`. The function does not check that `uint256(s) <= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0` (the secp256k1 curve order half), allowing signature malleability.",
    tools_involved: ["slither", "foundry", "cast", "anvil", "solc"],
    tags: ["ecdsa", "signature-malleability", "duplicate-claim", "s-value", "cryptographic"],
    attack_phases: [
      {
        phase: "Code Review & Architecture Analysis",
        description:
          "Review the signature verification logic in the claim function and check for malleability protections.",
        tools: ["solc", "foundry"],
        commands: [
          "cat src/SignatureClaim.sol | grep -n 'function claim' -A 20",
          "grep -n 'ecrecover\\|s\\s*<\\|s\\s*>\\|malleability' src/SignatureClaim.sol",
        ],
        expected_output:
          "Lines 35-50: `address recovered = ecrecover(hash, v, r, s); require(recovered == signer, 'Invalid sig');` No check on the s-value range. The function uses the raw s parameter from the signature without verifying it's in the low-S range.",
        thinking:
          "ECDSA signatures are malleable: for any valid signature (r, s), the pair (r, N - s) is also valid where N is the secp256k1 curve order. EIP-2 requires checking `uint256(s) <= 0x7FFF...FF` to enforce low-S canonical form. Without this check, an attacker can take a valid signature, compute the alternative s' = N - s, and submit a second claim that passes ecrecover verification.",
        analysis:
          "The missing s-value check allows signature malleability. An attacker who observes a valid signature in the mempool can compute the malleated signature and submit a duplicate claim. The claim function only checks that the recovered address matches the signer, not that the specific signature encoding is unique.",
        next_action:
          "Run static analysis and write the malleability PoC.",
      },
      {
        phase: "Static Analysis & Automated Scanning",
        description:
          "Use Slither and Semgrep to detect the missing signature malleability check.",
        tools: ["slither", "semgrep"],
        commands: [
          "slither . --detect weak-prng,uninitialized-local --solc-remap '@openzeppelin=node_modules/@openzeppelin'",
          "slither . --human-summary",
          "semgrep --config 'p/solidity' src/SignatureClaim.sol 2>&1 | grep -i 'ecrecover\\|signature\\|malleability'",
        ],
        expected_output:
          "Slither: '[!] ecrecover used in SignatureClaim.claim (src/SignatureClaim.sol:37) without s-value range check. Signature malleability may allow duplicate verification.' Semgrep: 'Warning: ECDSA signature malleability — missing low-S check on s parameter.'",
        thinking:
          "Both tools flag the missing s-value check. The PoC needs to demonstrate taking a valid signature, computing the malleated s-value, and submitting a second successful claim.",
        analysis:
          "The vulnerability is confirmed. The attacker can duplicate any claim by malleating the signature. This doubles the claimed amount for any signature the attacker observes.",
        next_action:
          "Write the signature malleability PoC in Foundry.",
      },
      {
        phase: "Proof of Concept Development",
        description:
          "Forge test that takes a valid signature, computes the malleated s-value, and demonstrates a duplicate claim.",
        tools: ["foundry", "anvil", "cast"],
        commands: [
          "forge test --match-test testSignatureMalleability -vvvv",
          "cast call $CLAIM_ADDR 'hasClaimed(address)(bool)' $ATTACKER_ADDR --rpc-url http://127.0.0.1:8545",
        ],
        expected_output:
          "Test output: Original signature (v=27, r=0x1a2b..., s=0x3c4d...) claims 1000 tokens. Malleated signature (v=28, r=0x1a2b..., s=0xFFFFFFFF... - 0x3c4d...) also claims 1000 tokens. Total claimed: 2000 tokens (double the intended amount). ecrecover returns the same signer address for both signatures.",
        thinking:
          "The PoC proves the duplicate claim. The attacker claims twice with two different signatures that both verify to the same signer. The fix is to add `require(uint256(s) <= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0, 'Invalid s-value')` before ecrecover, or use OpenZeppelin's ECDSA library which handles this.",
        analysis:
          "The PoC demonstrates a 2x duplicate claim. For high-value claims, this represents significant fund loss. The attack can be repeated for every signature the attacker observes.",
        next_action:
          "Perform impact analysis and draft the audit report.",
      },
      {
        phase: "Impact Analysis",
        description:
          "Calculate the total value at risk from duplicate claims and assess the attack vector.",
        tools: ["dune", "cast"],
        commands: [
          "cast call $CLAIM_ADDR 'totalClaimed()(uint256)' --rpc-url $RPC_URL",
          "cast logs --address $CLAIM_ADDR --sig 'Claimed(address,uint256)' --rpc-url $RPC_URL | wc -l",
        ],
        expected_output:
          "Total claims processed: 347. With malleability, up to 347 additional fraudulent claims are possible. Total claim pool: 1,000,000 tokens ($1M). Maximum additional fraudulent claims: 1,000,000 tokens. The attacker only needs to observe signatures in the mempool to malleate them.",
        thinking:
          "The attacker can observe pending claim transactions in the mempool, extract the (v, r, s) values, compute the malleated s', and submit a front-run transaction with the duplicate signature. This is a front-running + malleability combo.",
        analysis:
          "Severity: High (CVSS 7.5). The attack is profitable and can be automated. The fix is to use OpenZeppelin's ECDSA.tryRecover or add the s-value range check.",
        next_action:
          "Write the audit report with the OpenZeppelin ECDSA recommendation.",
      },
      {
        phase: "Audit Report Writing",
        description:
          "Produce the audit report with the signature malleability finding, duplicate claim PoC, and remediation.",
        tools: ["report_generator"],
        commands: [
          "echo 'Generating audit report...' && node scripts/generate-report.js core-signature-malleability",
        ],
        expected_output:
          "Audit report generated: findings/core-signature-malleability.md with severity High, SWC-117, CWE-347, CVSS 7.5. Report includes the vulnerable ecrecover call, the malleated signature computation, duplicate claim PoC (2x claimed), and the fix: use OpenZeppelin's ECDSA library which enforces low-S canonical form.",
        thinking:
          "The report should recommend replacing raw ecrecover with OpenZeppelin's ECDSA.tryRecover, which handles malleability checks internally. This is the industry-standard approach.",
        analysis:
          "Final severity: High. The fix is to use OpenZeppelin's ECDSA library. Recommend auditing all signature verification code in the protocol.",
        next_action:
          "Submit findings and recommend migrating to OpenZeppelin ECDSA.",
      },
    ],
  },

  // ─── 8. Incorrect Fee Calculation ─────────────────────────────────────────
  {
    id: "core-incorrect-fee-calculation",
    category: "Core Logic & Math Vulnerabilities",
    subcategory: "Incorrect Fee Calculation",
    title: "Incorrect Fee Calculation Due to BPS Constant Mismatch",
    difficulty: "intermediate",
    description:
      "A protocol calculates fees using a basis points (BPS) constant of 10000 but the fee input is interpreted as a percentage (0-100), causing fees to be 100x lower than intended.",
    target_description:
      "A DEX aggregator contract (Solidity ^0.8.18) with a `swap(address tokenIn, address tokenOut, uint256 amount, uint256 feeBps)` function. The fee calculation uses `fee = amount * feeBps / 10000` but the governance-set feeBps value is stored as a percentage (0-100) instead of basis points (0-10000), causing fees to be 100x lower than intended.",
    tools_involved: ["slither", "foundry", "cast", "anvil", "semgrep"],
    tags: ["fee-calculation", "bps", "constant-mismatch", "math-error", "economic"],
    attack_phases: [
      {
        phase: "Code Review & Architecture Analysis",
        description:
          "Review the fee calculation logic and the constant definitions to identify any unit mismatches.",
        tools: ["solc", "foundry"],
        commands: [
          "grep -n 'BPS\\|feeBps\\|10000\\|100' src/DexAggregator.sol | head -20",
          "cat src/DexAggregator.sol | grep -n 'function swap' -A 20",
          "cat src/Governance.sol | grep -n 'feeBps\\|setFee' -A 10",
        ],
        expected_output:
          "DexAggregator.sol line 12: `uint256 constant BPS = 10000;`. Line 45: `fee = amount * feeBps / BPS;`. Governance.sol line 30: `function setFee(uint256 _feeBps)` — governance sets feeBps = 30 (intending 30 basis points = 0.3%), but the aggregator divides by 10000, so actual fee = amount * 30 / 10000 = 0.3% — wait, that's correct. Let me re-check. Governance sets feeBps = 30 (meaning 30%), aggregator divides by 10000: actual fee = 30/10000 = 0.003% instead of 30%. Fees are 10000x lower than intended.",
        thinking:
          "The mismatch is clear: governance thinks it's setting a percentage (30 = 30%), but the aggregator interprets it as basis points (30 bps = 0.3%). The actual fee charged is 0.003% instead of 30%. This means the protocol is collecting 10,000x less fee revenue than intended. For a protocol processing $10M/day in volume, the intended fee revenue is $3M/day but actual revenue is $300/day.",
        analysis:
          "The BPS mismatch causes massive revenue loss. The protocol is undercharging fees by a factor of 10,000. This is an economic vulnerability that benefits all swappers (who pay near-zero fees) at the expense of the protocol treasury.",
        next_action:
          "Run static analysis and quantify the revenue loss.",
      },
      {
        phase: "Static Analysis & Automated Scanning",
        description:
          "Use Slither and Semgrep to detect the constant mismatch in the fee calculation.",
        tools: ["slither", "semgrep"],
        commands: [
          "slither . --detect incorrect-equality --solc-remap '@openzeppelin=node_modules/@openzeppelin'",
          "semgrep --config 'p/solidity' src/ 2>&1 | grep -i 'fee\\|bps\\|constant'",
        ],
        expected_output:
          "Slither: '[!] Suspicious constant usage in DexAggregator.swap: feeBps divided by BPS (10000), but governance may set feeBps as percentage (0-100). Verify unit consistency.' Semgrep: 'Warning: Potential unit mismatch — fee parameter interpreted differently in setter vs. calculation.'",
        thinking:
          "The tools flag the inconsistency. The fix requires either: (1) governance stores fee in basis points (0-10000), or (2) the aggregator divides by 100 instead of 10000. Option 1 is cleaner as it matches industry convention.",
        analysis:
          "The mismatch is confirmed. The protocol has been undercharging fees since deployment. The total revenue loss depends on the trading volume processed.",
        next_action:
          "Quantify the revenue loss and write the PoC.",
      },
      {
        phase: "Proof of Concept Development",
        description:
          "Forge test that demonstrates the fee discrepancy by comparing intended vs. actual fee collection.",
        tools: ["foundry", "anvil", "cast"],
        commands: [
          "forge test --match-test testFeeCalculationMismatch -vvvv",
          "cast call $AGGREGATOR_ADDR 'feeBps()(uint256)' --rpc-url http://127.0.0.1:8545",
        ],
        expected_output:
          "Test output: Governance sets feeBps = 30 (intending 30%). Swap amount = 10000 tokens. Expected fee = 10000 * 30 / 100 = 3000 tokens (30%). Actual fee = 10000 * 30 / 10000 = 3 tokens (0.03%). Fee discrepancy: 2997 tokens per swap. Over 1000 swaps: 2,997,000 tokens lost.",
        thinking:
          "The PoC clearly demonstrates the 10,000x fee discrepancy. For every $10,000 swap, the protocol collects $3 instead of $3,000. The cumulative loss is enormous.",
        analysis:
          "The PoC proves the economic damage. The fix is to either change the divisor to 100 or require governance to set feeBps in basis points. The latter is better for consistency.",
        next_action:
          "Perform impact analysis and draft the audit report.",
      },
      {
        phase: "Impact Analysis",
        description:
          "Calculate the total revenue loss from deployment to present and project ongoing losses.",
        tools: ["dune", "cast"],
        commands: [
          "cast call $AGGREGATOR_ADDR 'totalVolume()(uint256)' --rpc-url $RPC_URL",
          "cast call $AGGREGATOR_ADDR 'totalFeesCollected()(uint256)' --rpc-url $RPC_URL",
        ],
        expected_output:
          "Total swap volume: $45M. Intended fees at 30%: $13.5M. Actual fees collected: $1,350. Revenue loss: $13,498,650. Ongoing daily volume: $500K, daily loss: $149,865. The protocol has been hemorrhaging revenue since deployment.",
        thinking:
          "The revenue loss is staggering — $13.5M lost. The fix is urgent and requires a governance proposal to correct the fee interpretation. Historical losses are unrecoverable but ongoing losses can be stopped immediately.",
        analysis:
          "Severity: Critical (CVSS 8.6). The protocol has lost $13.5M and continues to lose $150K/day. The fix is a parameter change that requires governance action.",
        next_action:
          "Write the audit report with the emergency governance recommendation.",
      },
      {
        phase: "Audit Report Writing",
        description:
          "Produce the audit report with the BPS mismatch finding, revenue loss quantification, and governance fix.",
        tools: ["report_generator"],
        commands: [
          "echo 'Generating audit report...' && node scripts/generate-report.js core-incorrect-fee-calculation",
        ],
        expected_output:
          "Audit report generated: findings/core-incorrect-fee-calculation.md with severity Critical, SWC-128, CWE-682, CVSS 8.6. Report includes the constant mismatch analysis, PoC showing 10,000x fee discrepancy, revenue loss of $13.5M, and governance fix: re-interpret feeBps as percentage by dividing by 100 instead of 10000.",
        thinking:
          "The report should recommend an emergency governance vote to correct the fee interpretation. The protocol should also add unit tests that verify fee calculations against expected values.",
        analysis:
          "Final severity: Critical. The fix requires governance action. Recommend adding a fee validation check that rejects obviously incorrect fee settings.",
        next_action:
          "Submit findings with an emergency governance recommendation.",
      },
    ],
  },

  // ─── 9. Timestamp Dependence ──────────────────────────────────────────────
  {
    id: "core-timestamp-dependence",
    category: "Core Logic & Math Vulnerabilities",
    subcategory: "Timestamp Dependence",
    title: "Timestamp Dependence in Random Number Generation Allows Prediction",
    difficulty: "advanced",
    description:
      "A lottery contract uses block.timestamp and block.prevrandao as entropy sources, allowing a validator to manipulate these values to predict and control the winning number.",
    target_description:
      "A lottery contract (Solidity ^0.8.19) with a `drawWinner()` function that computes the winning number as `uint256(keccak256(abi.encodePacked(block.timestamp, block.prevrandao, nonce))) % numTickets`. A validator who is also a ticket holder can manipulate block.timestamp (within 15-second window) and block.prevrandao to produce a favorable winning number.",
    tools_involved: ["slither", "foundry", "anvil", "cast", "tenderly"],
    tags: ["timestamp", "randomness", "miner-manipulation", "lottery", "entropy"],
    attack_phases: [
      {
        phase: "Code Review & Architecture Analysis",
        description:
          "Review the random number generation logic in the lottery contract and identify on-chain entropy sources.",
        tools: ["solc", "foundry"],
        commands: [
          "cat src/Lottery.sol | grep -n 'function drawWinner' -A 15",
          "grep -n 'block.timestamp\\|block.prevrandao\\|block.difficulty\\|keccak256' src/Lottery.sol",
        ],
        expected_output:
          "Lines 60-75: `uint256 winningNumber = uint256(keccak256(abi.encodePacked(block.timestamp, block.prevrandao, nonce))) % numTickets;`. The entropy relies entirely on manipulable block properties. No Chainlink VRF or commit-reveal scheme is used.",
        thinking:
          "This is a well-known anti-pattern. block.timestamp can be adjusted by the validator within a ~15 second window, and block.prevrandao (formerly block.difficulty) is directly set by the validator. A validator who holds a lottery ticket can try all valid combinations of timestamp and prevrandao to find a winning combination. With a small number of tickets (e.g., 100), the attacker has a very high probability of finding a winning block configuration.",
        analysis:
          "The attacker (validator + ticket holder) can precompute the winning number for each candidate timestamp/prevrandao combination and only propose a block when the outcome favors them. This gives them an unfair advantage proportional to the number of tickets they hold.",
        next_action:
          "Run static analysis and write the manipulation PoC.",
      },
      {
        phase: "Static Analysis & Automated Scanning",
        description:
          "Use Slither to detect timestamp-dependent randomness and weak entropy sources.",
        tools: ["slither", "semgrep"],
        commands: [
          "slither . --detect timestamp-dependence --solc-remap '@openzeppelin=node_modules/@openzeppelin'",
          "slither . --detect weak-prng",
          "semgrep --config 'p/solidity' src/Lottery.sol 2>&1 | grep -i 'random\\|timestamp\\|prevrandao\\|keccak'",
        ],
        expected_output:
          "Slither: '[!] Timestamp dependence in Lottery.drawWinner (src/Lottery.sol:62): block.timestamp used in randomness source.' '[!] Weak PRNG: keccak256 of block properties is predictable by the block proposer.' Semgrep: 'Warning: Predictable randomness — block.timestamp and block.prevrandao can be manipulated by the validator.'",
        thinking:
          "Both tools confirm the weakness. The fix is to use Chainlink VRF or a commit-reveal scheme. For the PoC, I'll simulate a validator trying different timestamp values to find a favorable outcome.",
        analysis:
          "The vulnerability is confirmed. A validator can manipulate the lottery outcome with high probability, especially when the ticket count is small.",
        next_action:
          "Write the manipulation PoC in Foundry.",
      },
      {
        phase: "Proof of Concept Development",
        description:
          "Forge test that simulates a validator trying different timestamp/prevrandao combinations to find a winning outcome for their ticket.",
        tools: ["foundry", "anvil", "cast"],
        commands: [
          "forge test --match-test testTimestampManipulation -vvvv",
          "cast call $LOTTERY_ADDR 'numTickets()(uint256)' --rpc-url http://127.0.0.1:8545",
        ],
        expected_output:
          "Test output: numTickets = 100. Validator holds ticket #42. Simulating 30 candidate timestamps (current + 0..30 seconds) and 10 prevrandao values: 300 combinations tested. Ticket #42 wins in 4 out of 300 combinations (1.33% per attempt). With 300 attempts, probability of at least one win = 98.7%. Validator wins the 50 ETH jackpot.",
        thinking:
          "The PoC shows that with only 300 candidate combinations, the validator has a 98.7% chance of winning. In practice, the validator has many more degrees of freedom (they can also influence prevrandao more broadly and have up to 15 seconds of timestamp flexibility). The attack is highly profitable.",
        analysis:
          "The PoC proves the validator can manipulate the lottery outcome with near certainty. The jackpot of 50 ETH is essentially guaranteed to the manipulating validator.",
        next_action:
          "Perform impact analysis and draft the audit report.",
      },
      {
        phase: "Impact Analysis",
        description:
          "Assess the total jackpot value, the probability of manipulation, and the attack requirements.",
        tools: ["dune", "cast"],
        commands: [
          "cast call $LOTTERY_ADDR 'jackpot()(uint256)' --rpc-url $RPC_URL",
          "cast call $LOTTERY_ADDR 'numTickets()(uint256)' --rpc-url $RPC_URL",
        ],
        expected_output:
          "Current jackpot: 50 ETH ($150K). Number of tickets: 100. Validator manipulation probability: 98.7% (with 300 candidate combinations). The attack requires validator status (achievable via MEV-Boost or running a validator) + holding one ticket ($1.5K investment for $150K expected return).",
        thinking:
          "The expected return on investment is enormous: $150K payout for $1.5K ticket cost = 100x ROI. The attack is economically rational for any validator. The fix is to use Chainlink VRF or a commit-reveal scheme.",
        analysis:
          "Severity: High (CVSS 7.4). The attack is profitable, requires only validator status and one ticket purchase, and can be repeated for every lottery round.",
        next_action:
          "Write the audit report with the Chainlink VRF recommendation.",
      },
      {
        phase: "Audit Report Writing",
        description:
          "Produce the audit report with the timestamp manipulation analysis, PoC, and Chainlink VRF recommendation.",
        tools: ["report_generator"],
        commands: [
          "echo 'Generating audit report...' && node scripts/generate-report.js core-timestamp-dependence",
        ],
        expected_output:
          "Audit report generated: findings/core-timestamp-dependence.md with severity High, SWC-116, CWE-330, CVSS 7.4. Report includes the vulnerable PRNG code, the validator manipulation simulation (98.7% win rate), the 100x ROI analysis, and the fix: replace on-chain randomness with Chainlink VRF or a commit-reveal scheme.",
        thinking:
          "The report should emphasize that on-chain randomness using block properties is fundamentally broken. The only safe approaches are Chainlink VRF (external oracle) or commit-reveal (two-phase scheme).",
        analysis:
          "Final severity: High. The fix requires integrating Chainlink VRF or a commit-reveal scheme. Recommend pausing the lottery until the fix is deployed.",
        next_action:
          "Submit findings and recommend migrating to Chainlink VRF.",
      },
    ],
  },

  // ─── 10. Token Decimal Mismatch ───────────────────────────────────────────
  {
    id: "core-decimal-mismatch",
    category: "Core Logic & Math Vulnerabilities",
    subcategory: "Decimal Mismatch",
    title: "Token Decimal Mismatch in Pool Calculation Causes Precision Loss",
    difficulty: "advanced",
    description:
      "A liquidity pool calculation assumes both tokens have 18 decimals but one token has 6 decimals, causing the pool ratio to be off by 10^12 and enabling profitable arbitrage at the pool's expense.",
    target_description:
      "An AMM pool contract (Solidity ^0.8.16) with a `getAmountOut(address tokenIn, uint256 amountIn)` function that uses the constant product formula `amountOut = (reserveOut * amountIn) / reserveIn`. The function assumes both reserves are in 18-decimal representation, but tokenB has 6 decimals (e.g., USDC), causing the pool ratio to be off by a factor of 10^12.",
    tools_involved: ["slither", "foundry", "cast", "anvil", "semgrep"],
    tags: ["decimal-mismatch", "token-precision", "pool-calculation", "arbitrage", "amm"],
    attack_phases: [
      {
        phase: "Code Review & Architecture Analysis",
        description:
          "Review the AMM pool's pricing formula and check whether token decimals are properly accounted for.",
        tools: ["solc", "foundry"],
        commands: [
          "cat src/AMMPool.sol | grep -n 'function getAmountOut' -A 10",
          "grep -n 'decimals\\|1e18\\|1e6' src/AMMPool.sol",
          "cast call $TOKENB_ADDR 'decimals()(uint8)' --rpc-url $RPC_URL",
        ],
        expected_output:
          "Line 42: `amountOut = (reserveOut * amountIn) / reserveIn;`. No decimal adjustment. TokenA has 18 decimals (standard ERC20). TokenB has 6 decimals (USDC-like). The reserves are stored in raw token amounts: reserveA = 1e24 (1M tokens * 1e18), reserveB = 1e12 (1M tokens * 1e6). The ratio reserveB/reserveA = 1e12/1e24 = 1e-12, making tokenB appear 10^12 times less valuable than it should be.",
        thinking:
          "The decimal mismatch means the pool prices tokenB at 10^-12 of its true value relative to tokenA. An attacker can buy tokenB from the pool at essentially zero cost and sell it elsewhere at the correct market price. The arbitrage profit is enormous because the pool will sell tokenB at a 10^12 discount.",
        analysis:
          "The pool's pricing is off by 12 orders of magnitude. An attacker can deposit a small amount of tokenA and withdraw essentially all of tokenB from the pool. If the pool holds 1M USDC (1e12 in 6-decimal form), the attacker can buy it for approximately 1e-12 tokenA — effectively free.",
        next_action:
          "Run static analysis and write the arbitrage PoC.",
      },
      {
        phase: "Static Analysis & Automated Scanning",
        description:
          "Use Slither and Semgrep to detect the missing decimal normalization in the pool calculation.",
        tools: ["slither", "semgrep"],
        commands: [
          "slither . --detect incorrect-equality --solc-remap '@openzeppelin=node_modules/@openzeppelin'",
          "slither . --print vars-and-auth 2>&1 | grep -i 'reserve\\|decimal'",
          "semgrep --config 'p/solidity' src/AMMPool.sol 2>&1 | grep -i 'decimal\\|precision'",
        ],
        expected_output:
          "Slither: '[!] Missing decimal normalization in AMMPool.getAmountOut. Reserves of tokens with different decimal places are used directly in calculations.' Semgrep: 'Warning: Token decimal mismatch — pool formula does not adjust for tokens with different decimal precision.'",
        thinking:
          "The tools confirm the mismatch. The fix is to normalize reserves to a common decimal representation before applying the constant product formula. The standard approach is to multiply the 6-decimal reserve by 1e12 to match the 18-decimal representation.",
        analysis:
          "The vulnerability is confirmed. The pool is massively mispriced and can be drained via arbitrage.",
        next_action:
          "Write the arbitrage PoC in Foundry.",
      },
      {
        phase: "Proof of Concept Development",
        description:
          "Forge test that exploits the decimal mismatch by depositing a tiny amount of tokenA and withdrawing the entire tokenB reserve.",
        tools: ["foundry", "anvil", "cast"],
        commands: [
          "forge test --match-test testDecimalMismatchArbitrage -vvvv",
          "cast call $POOL_ADDR 'getReserves()(uint256,uint256)' --rpc-url http://127.0.0.1:8545",
        ],
        expected_output:
          "Test output: Pool reserves: tokenA = 1e24 (1M tokens), tokenB = 1e12 (1M USDC). Attacker deposits 1e6 tokenA (0.000001 tokens). Calculated output: amountOut = (1e12 * 1e6) / 1e24 = 1e-6, which truncates to 0. But wait — the pool uses the inverted formula for tokenB->tokenA swaps. Attacker deposits 1 tokenB (1e6 in 6-decimal), gets amountOut = (1e24 * 1e6) / 1e12 = 1e18 tokenA (1 full tokenA, worth $3000). Attacker repeats, draining 1M tokenA for the cost of 1M USDC worth of tokenB — but the pool thinks 1M USDC = 1e12 units and 1M tokenA = 1e24 units, so the ratio is 1e-12. Attacker deposits 1e6 tokenB (1 USDC), gets (1e24 * 1e6) / 1e12 = 1e18 tokenA = $3000. Profit: $2999 per USDC invested.",
        thinking:
          "The arbitrage is extremely profitable: $3000 return per $1 invested. The attacker can drain the entire pool. The fix is to normalize decimals before the calculation: `reserveB_normalized = reserveB * 1e12` (to convert from 6 to 18 decimals).",
        analysis:
          "The PoC shows $3000 profit per $1 invested. The entire pool of 1M tokenA ($3B) can be drained for approximately 1M USDC ($1M). The net profit is approximately $3B - $1M = ~$3B.",
        next_action:
          "Perform impact analysis and draft the audit report.",
      },
      {
        phase: "Impact Analysis",
        description:
          "Calculate the total value drainable from the pool and the cost of the attack.",
        tools: ["dune", "cast"],
        commands: [
          "cast call $POOL_ADDR 'getReserves()(uint256,uint256)' --rpc-url $RPC_URL",
          "cast call $TOKENA_ADDR 'balanceOf(address)(uint256)' $POOL_ADDR --rpc-url $RPC_URL",
          "cast call $TOKENB_ADDR 'balanceOf(address)(uint256)' $POOL_ADDR --rpc-url $RPC_URL",
        ],
        expected_output:
          "Pool holds: 1,000,000 tokenA ($3B at $3000/token) and 1,000,000 tokenB ($1M USDC). Attacker can drain all 1M tokenA for approximately 1M USDC. Net profit: ~$3B. Attack cost: 1M USDC. The attack can be executed in a single transaction via flash loan.",
        thinking:
          "The decimal mismatch enables a flash-loan-attackable drain of the entire pool. The attacker needs no capital — they can flash loan the 1M USDC, execute the swap, repay the loan, and keep the $3B profit. This is a Critical vulnerability.",
        analysis:
          "Severity: Critical (CVSS 9.8). The pool can be fully drained via flash loan with zero capital requirement. The fix is to normalize token decimals before applying the constant product formula.",
        next_action:
          "Write the audit report with the decimal normalization fix.",
      },
      {
        phase: "Audit Report Writing",
        description:
          "Produce the audit report with the decimal mismatch finding, arbitrage PoC, and decimal normalization fix.",
        tools: ["report_generator"],
        commands: [
          "echo 'Generating audit report...' && node scripts/generate-report.js core-decimal-mismatch",
        ],
        expected_output:
          "Audit report generated: findings/core-decimal-mismatch.md with severity Critical, SWC-128, CWE-682, CVSS 9.8. Report includes the vulnerable pricing formula, the arbitrage PoC ($3B drain via flash loan), and the fix: normalize reserves to 18 decimals before calculation using `reserve * 10^(18 - token.decimals())`.",
        thinking:
          "The report should recommend an immediate pause of the pool and deployment of the decimal normalization fix. All AMM pools in the protocol should be audited for similar decimal assumptions.",
        analysis:
          "Final severity: Critical. The fix is to normalize decimals. Recommend auditing all pools and adding a decimals() check during pool initialization.",
        next_action:
          "Submit findings with an emergency pause recommendation.",
      },
    ],
  },

  // ─── 11. Missing Zero Address Check ───────────────────────────────────────
  {
    id: "core-missing-zero-check",
    category: "Core Logic & Math Vulnerabilities",
    subcategory: "Missing Zero Check",
    title: "Missing Zero Address Check in Constructor Causes Permanent Fund Lock",
    difficulty: "intermediate",
    description:
      "A contract constructor doesn't validate that critical address parameters (rewardToken, treasury) are non-zero, causing all reward distributions to be sent to address(0) and permanently locked.",
    target_description:
      "A reward distribution contract (Solidity ^0.8.14) with a `constructor(address _rewardToken, address _treasury, address _admin)` that stores the addresses without validation. When deployed with _treasury = address(0) (e.g., due to a deployment script bug), all reward distributions are sent to address(0) and permanently lost.",
    tools_involved: ["slither", "foundry", "semgrep", "solc"],
    tags: ["zero-address", "constructor", "fund-lock", "input-validation", "permanent-loss"],
    attack_phases: [
      {
        phase: "Code Review & Architecture Analysis",
        description:
          "Review the contract constructor and verify that all address parameters are validated against address(0).",
        tools: ["solc", "foundry"],
        commands: [
          "cat src/RewardDistributor.sol | grep -n 'constructor' -A 15",
          "grep -n 'require.*address\\|!= address(0)' src/RewardDistributor.sol",
        ],
        expected_output:
          "Lines 20-28: `constructor(address _rewardToken, address _treasury, address _admin) { rewardToken = _rewardToken; treasury = _treasury; admin = _admin; }`. No validation that any of the three addresses is non-zero. No `require(_treasury != address(0))` or similar guards.",
        thinking:
          "The missing zero-address checks are a deployment-time vulnerability. If the deployer passes address(0) for any critical parameter (a common mistake in deployment scripts or Hardhat configs), the contract is permanently misconfigured. Rewards sent to address(0) are irrecoverable. The treasury address being zero means all fee revenue goes to the null address.",
        analysis:
          "While this is a deployment-time issue rather than a runtime exploit, the consequences are permanent fund loss. The contract has no way to update the treasury after deployment (no setter function), so a zero-address deployment is bricked.",
        next_action:
          "Run static analysis to confirm the missing checks.",
      },
      {
        phase: "Static Analysis & Automated Scanning",
        description:
          "Use Slither and Semgrep to detect missing zero-address validation in the constructor.",
        tools: ["slither", "semgrep"],
        commands: [
          "slither . --detect unchecked-transfer --solc-remap '@openzeppelin=node_modules/@openzeppelin'",
          "slither . --print human-summary",
          "semgrep --config 'p/solidity' src/RewardDistributor.sol 2>&1 | grep -i 'zero\\|address(0)\\|constructor'",
        ],
        expected_output:
          "Slither: '[!] Missing zero-address check in RewardDistributor constructor. Critical addresses (rewardToken, treasury, admin) are not validated.' Semgrep: 'Warning: Constructor does not validate that address parameters are non-zero. Deployment with address(0) will cause permanent fund loss.'",
        thinking:
          "Both tools flag the missing validation. The fix is straightforward: add `require` statements for each critical address. I should also check if there's a setter function that could be used to fix a zero-address deployment.",
        analysis:
          "The vulnerability is confirmed. No setter exists for the treasury or admin addresses, so a zero-address deployment is permanently broken. The fix requires both adding constructor validation and adding a setter for emergency recovery.",
        next_action:
          "Write the PoC that deploys with address(0) and demonstrates fund loss.",
      },
      {
        phase: "Proof of Concept Development",
        description:
          "Forge test that deploys the contract with address(0) as treasury, distributes rewards, and shows the funds are sent to the zero address.",
        tools: ["foundry", "anvil", "cast"],
        commands: [
          "forge test --match-test testMissingZeroAddressCheck -vvvv",
          "cast balance 0x0000000000000000000000000000000000000000 --rpc-url http://127.0.0.1:8545",
        ],
        expected_output:
          "Test output: Contract deployed with treasury = address(0). distributeRewards(1000 tokens) sends 1000 tokens to address(0). Token balance of address(0) = 1000. The tokens are permanently locked — no private key exists for address(0). Test assertion: token.balanceOf(address(0)) == 1000.",
        thinking:
          "The PoC proves the permanent fund lock. Tokens sent to address(0) are unrecoverable. The fix requires constructor validation and an emergency setter.",
        analysis:
          "The PoC demonstrates irreversible fund loss. Any rewards distributed go to address(0) and are permanently locked. The contract cannot be recovered without redeployment.",
        next_action:
          "Perform impact analysis and draft the audit report.",
      },
      {
        phase: "Impact Analysis",
        description:
          "Check if the deployed contract has a zero-address treasury and calculate any losses.",
        tools: ["cast", "dune"],
        commands: [
          "cast call $DISTRIBUTOR_ADDR 'treasury()(address)' --rpc-url $RPC_URL",
          "cast call $REWARD_TOKEN_ADDR 'balanceOf(address)(uint256)' 0x0000000000000000000000000000000000000000 --rpc-url $RPC_URL",
        ],
        expected_output:
          "Production deployment: treasury = 0x742d35Cc6634C0532925a3b844Bc9e7595f2bD18 (non-zero — safe). However, the testnet deployment has treasury = address(0) and has distributed 500,000 tokens to address(0), permanently locked. The production contract has no setter to fix a future misconfiguration.",
        thinking:
          "The production deployment is safe but the testnet deployment lost 500K tokens. The risk is that a future production deployment could make the same mistake. The fix should prevent this at the constructor level and provide an emergency recovery mechanism.",
        analysis:
          "Severity: Medium (CVSS 5.9). The production contract is currently safe, but the missing validation makes future deployments vulnerable. The fix is preventive.",
        next_action:
          "Write the audit report with the constructor validation fix.",
      },
      {
        phase: "Audit Report Writing",
        description:
          "Produce the audit report with the missing zero-address check finding, fund lock PoC, and recommended validation.",
        tools: ["report_generator"],
        commands: [
          "echo 'Generating audit report...' && node scripts/generate-report.js core-missing-zero-check",
        ],
        expected_output:
          "Audit report generated: findings/core-missing-zero-check.md with severity Medium, SWC-104, CWE-476, CVSS 5.9. Report includes the missing validation in constructor, the PoC showing tokens sent to address(0), testnet loss of 500K tokens, and the fix: add `require(_treasury != address(0), 'Zero treasury')` and similar checks for all critical addresses, plus an emergency setter.",
        thinking:
          "The report should recommend both constructor validation and an emergency setter with timelock for recovery. This is a best practice for all contracts with critical address parameters.",
        analysis:
          "Final severity: Medium. The production contract is safe but future deployments are at risk. The fix is preventive and should be included in the next upgrade.",
        next_action:
          "Submit findings with the constructor validation fix and emergency setter recommendation.",
      },
    ],
  },

  // ─── 12. Gas Limit DoS ────────────────────────────────────────────────────
  {
    id: "core-gas-limit-dos",
    category: "Core Logic & Math Vulnerabilities",
    subcategory: "Gas Limit DoS",
    title: "Gas Limit DoS via Unbounded Array Iteration in Distribute Function",
    difficulty: "intermediate",
    description:
      "A reward distribution function iterates over an unbounded array of beneficiaries, and as the array grows past ~500 entries the transaction exceeds the block gas limit, permanently freezing reward distribution.",
    target_description:
      "A reward distributor contract (Solidity ^0.8.13) with a `distributeRewards()` function that loops over `address[] public beneficiaries` and sends rewards to each. The array is unbounded — new beneficiaries are added via `addBeneficiary(address)` with no cap. As the array grows, the gas cost of distributeRewards() increases linearly until it exceeds the block gas limit.",
    tools_involved: ["slither", "foundry", "anvil", "cast", "semgrep"],
    tags: ["gas-limit", "unbounded-loop", "dos", "array-iteration", "frozen-state"],
    attack_phases: [
      {
        phase: "Code Review & Architecture Analysis",
        description:
          "Review the distributeRewards function and the beneficiary management functions to identify unbounded iteration.",
        tools: ["solc", "foundry"],
        commands: [
          "cat src/RewardDistributor.sol | grep -n 'function distributeRewards' -A 15",
          "grep -n 'beneficiaries\\|addBeneficiary\\|for.*beneficiaries' src/RewardDistributor.sol",
          "cast call $DISTRIBUTOR_ADDR 'getBeneficiaryCount()(uint256)' --rpc-url $RPC_URL",
        ],
        expected_output:
          "Lines 50-65: `for (uint i = 0; i < beneficiaries.length; i++) { uint256 reward = calculateReward(beneficiaries[i]); rewardToken.transfer(beneficiaries[i], reward); }`. The loop iterates over the entire beneficiaries array. Current count: 1,247 beneficiaries. addBeneficiary() has no cap or validation.",
        thinking:
          "The gas cost of distributeRewards grows linearly with the number of beneficiaries. Each iteration costs approximately 25,000 gas (SLOAD, calculation, transfer). At 1,247 beneficiaries, the total gas is ~31M, which exceeds the current Ethereum block gas limit of 30M. The function is already unfreezable — it cannot be called successfully.",
        analysis:
          "The contract is already past the gas limit threshold. distributeRewards() will revert on every call due to out-of-gas. All reward distribution is permanently frozen. The fix requires pagination or a pull-based distribution pattern.",
        next_action:
          "Run static analysis and write the gas estimation test.",
      },
      {
        phase: "Static Analysis & Automated Scanning",
        description:
          "Use Slither and Semgrep to detect the unbounded loop and estimate gas costs.",
        tools: ["slither", "semgrep"],
        commands: [
          "slither . --detect calls-loop --solc-remap '@openzeppelin=node_modules/@openzeppelin'",
          "slither . --print human-summary",
          "semgrep --config 'p/solidity' src/RewardDistributor.sol 2>&1 | grep -i 'loop\\|gas\\|unbounded'",
        ],
        expected_output:
          "Slither: '[!] Unbounded loop in RewardDistributor.distributeRewards. The iteration over beneficiaries can exceed block gas limit as the array grows.' Semgrep: 'Warning: Denial of Service via gas limit — unbounded array iteration in distributeRewards. Consider using a pull pattern or pagination.'",
        thinking:
          "Both tools flag the unbounded loop. The current beneficiary count of 1,247 already makes the function uncallable. I need to write a gas estimation test to confirm.",
        analysis:
          "The vulnerability is confirmed and already active. The function cannot be called with the current beneficiary count.",
        next_action:
          "Write the gas estimation test in Foundry.",
      },
      {
        phase: "Proof of Concept Development",
        description:
          "Forge test that adds beneficiaries incrementally and measures the gas cost of distributeRewards, showing it exceeds the block gas limit.",
        tools: ["foundry", "anvil", "cast"],
        commands: [
          "forge test --match-test testGasLimitDoS -vvvv",
          "forge test --match-test testDistributeGasEstimate --gas-report",
        ],
        expected_output:
          "Test output: Gas cost per beneficiary: ~25,000 gas. At 100 beneficiaries: 2.5M gas (within limit). At 500 beneficiaries: 12.5M gas (within limit). At 1000 beneficiaries: 25M gas (near limit). At 1200 beneficiaries: 30M gas (exceeds 30M block gas limit). distributeRewards() reverts with out-of-gas. Current count 1,247: function is permanently frozen.",
        thinking:
          "The PoC confirms the function is frozen at the current beneficiary count. The fix requires a fundamental redesign — either pagination (process N beneficiaries per call) or a pull-based pattern (each beneficiary claims their own rewards).",
        analysis:
          "The DoS is permanent with the current code. No amount of gas will make the transaction succeed because it exceeds the block gas limit. The fix requires a pull-based distribution pattern.",
        next_action:
          "Perform impact analysis and draft the audit report.",
      },
      {
        phase: "Impact Analysis",
        description:
          "Calculate the total undistributed rewards, the number of affected beneficiaries, and the fix options.",
        tools: ["dune", "cast"],
        commands: [
          "cast call $DISTRIBUTOR_ADDR 'pendingRewards()(uint256)' --rpc-url $RPC_URL",
          "cast call $DISTRIBUTOR_ADDR 'getBeneficiaryCount()(uint256)' --rpc-url $RPC_URL",
          "cast call $REWARD_TOKEN_ADDR 'balanceOf(address)(uint256)' $DISTRIBUTOR_ADDR --rpc-url $RPC_URL",
        ],
        expected_output:
          "Undistributed rewards in contract: 2,500,000 tokens ($2.5M). Number of affected beneficiaries: 1,247. The contract holds enough rewards for all beneficiaries but cannot distribute them. The funds are not lost — they're stuck in the contract but inaccessible to beneficiaries.",
        thinking:
          "The $2.5M in rewards are trapped in the contract. They're not permanently lost (address(0)) but are inaccessible with the current code. The fix requires deploying a new distributor contract with a pull-based pattern and migrating the beneficiaries.",
        analysis:
          "Severity: High (CVSS 7.5). The reward distribution is permanently frozen, affecting 1,247 users and $2.5M in rewards. The fix requires a new contract deployment and migration.",
        next_action:
          "Write the audit report with the pull-based pattern fix.",
      },
      {
        phase: "Audit Report Writing",
        description:
          "Produce the audit report with the gas limit DoS finding, gas estimation data, and pull-based pattern recommendation.",
        tools: ["report_generator"],
        commands: [
          "echo 'Generating audit report...' && node scripts/generate-report.js core-gas-limit-dos",
        ],
        expected_output:
          "Audit report generated: findings/core-gas-limit-dos.md with severity High, SWC-132, CWE-400, CVSS 7.5. Report includes the unbounded loop code, gas cost analysis (25K gas per beneficiary, 30M+ at 1200 beneficiaries), the frozen state confirmation, and two fix options: (1) pull-based claim pattern, (2) paginated distribution processing N beneficiaries per call.",
        thinking:
          "The report should recommend the pull-based pattern as the primary fix — each beneficiary calls claim() to receive their rewards, bounded gas cost per transaction. Pagination is a secondary option for the existing contract but requires governance to migrate.",
        analysis:
          "Final severity: High. The pull-based pattern is the recommended fix. It eliminates the unbounded iteration entirely and gives each user control over their reward claim timing.",
        next_action:
          "Submit findings with the pull-based pattern recommendation and migration plan.",
      },
    ],
  },
];
