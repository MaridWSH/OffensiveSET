import type { ScenarioTemplate, AttackPhase } from "./types.js";

export const DEFI_SCENARIOS: ScenarioTemplate[] = [
  {
    id: "defi-staking-unauthorized-mint",
    category: "DeFi Protocol Vulnerabilities",
    subcategory: "Staking & Locking",
    title: "Unauthorized Minting via Missing Epoch Check in Staking Contract",
    difficulty: "advanced",
    description: "Missing modifier on poke() function allows unlimited reward accrual by repeated calls within the same epoch, leading to unlimited token minting.",
    target_description: "DeFi lending protocol at 0xAbc...123 with staking contract Voter.sol, reward token FLUX, veToken model (veALCX -> FLUX rewards). GitHub: https://github.com/protocol/contracts. Scope includes Voter.sol, RevenueHandler.sol, FLUX token contract.",
    attack_phases: [
      {
        phase: "Code Review & Architecture Analysis",
        description: "Analyze the staking contract architecture, reward distribution mechanism, and access controls",
        tools: ["slither", "foundry", "etherscan"],
        commands: [
          "slither . --print human-summary",
          "forge test --match-contract VoterTest -vvv",
          "cast code 0xVoterAddress@latest"
        ],
        expected_output: `Slither analysis complete. Found 3 High, 2 Medium, 4 Low severity findings.`,
        thinking: "Let me start by understanding the architecture. The Voter contract inherits from Ownable and ReentrancyGuard. The key function is poke() which accrues FLUX rewards. I notice it calls FLUX.accrueFlux() -- an external call. Does poke() have access control? The function shows external visibility with no modifiers. Anyone can call it. What happens if I call it repeatedly? Let me trace: poke() -> _vote() -> FLUX.accrueFlux() -> increases pending FLUX. Without an epoch check, I can inflate rewards infinitely.",
        analysis: "Identified unprotected poke() function with external call to FLUX token. No epoch-based rate limiting detected.",
        next_action: "Deep dive into poke() function and write Foundry PoC test"
      },
      {
        phase: "Static Analysis & Automated Scanning",
        description: "Run Slither detectors and Semgrep rules to identify vulnerability patterns",
        tools: ["slither", "semgrep"],
        commands: [
          "slither . --detect unprotected-function,reentrancy-eth --human-summary",
          "semgrep --config auto . --lang solidity"
        ],
        expected_output: `Slither findings:\n  unprotected-function (High): poke() missing access control\n  reentrancy-eth (Medium): external call in _vote() before state update`,
        thinking: "Slither confirmed the unprotected function finding. The reentrancy-eth medium finding is also notable -- the external call to FLUX.accrueFlux() happens inside _vote() which is called by poke(). Let me examine the call graph more carefully.",
        analysis: "Automated analysis confirms High severity unprotected function and Medium reentrancy.",
        next_action: "Develop Proof of Concept with Foundry fork test"
      },
      {
        phase: "Proof of Concept Development",
        description: "Write Foundry test to demonstrate unauthorized minting",
        tools: ["foundry"],
        commands: [
          "forge test --match-test test_POC_UnauthorizedMint -vvv --fork-url $RPC_URL"
        ],
        expected_output: `[PASS] test_POC_UnauthorizedMint() (gas: 234567)\nLogs:\n  Before attack: voting power = 300\n  After repeated poke(): voting power = 600\n  FLUX balance increased from 1000 to 2000`,
        thinking: "The Foundry test confirms the exploit. By calling poke() multiple times in the same epoch, I doubled the FLUX reward accrual. The test shows voting power went from 300 to 600 and FLUX balance doubled. This is a complete unauthorized mint -- the protocol has no mechanism to prevent repeated reward claims within the same epoch.",
        analysis: "PoC confirmed. Repeated poke() calls within same epoch double FLUX rewards. Unlimited minting possible.",
        next_action: "Quantify financial impact and write audit finding report"
      },
      {
        phase: "Impact Analysis",
        description: "Calculate maximum financial impact of the vulnerability",
        tools: ["foundry", "tenderly"],
        commands: [
          "forge test --match-test test_ImpactAnalysis -vvv --fork-url $RPC_URL",
          "cast call 0xFLUXAddress 'totalSupply()' --rpc-url $RPC_URL"
        ],
        expected_output: `Maximum exploit: 10,000 FLUX per epoch (unlimited epochs)\nProtocol TVL: $45M\nFLUX price: $1.23\nPotential damage: $12.3M+`,
        thinking: "The impact is severe. With protocol TVL of $45M and FLUX at $1.23, unlimited minting could cause: 1) Massive sell pressure on DEX (price crash to near zero), 2) FLUX used as collateral in lending -> bad debt cascade, 3) Governance manipulation via vote weight. The worst case is governance attack -- attacker could vote to drain the entire treasury. CVSS 9.8 -- Critical.",
        analysis: "Critical financial impact confirmed. Unlimited FLUX minting enables governance takeover and protocol insolvency.",
        next_action: "Write comprehensive audit finding with secure code recommendation"
      },
      {
        phase: "Audit Report Writing",
        description: "Document finding with severity, PoC evidence, and fix recommendation",
        tools: ["report_generator"],
        commands: [],
        expected_output: "",
        thinking: "I need to write a complete audit finding with: vulnerability description, attack path, impact analysis with dollar amounts, Proof of Concept code, and the secure code fix.",
        analysis: "Compile all evidence into structured audit report with CVSS scoring.",
        next_action: "Submit report"
      }
    ],
    cve_references: ["SWC-101", "CWE-863"],
    tools_involved: ["slither", "foundry", "etherscan", "semgrep", "tenderly", "report_generator"],
    tags: ["unauthorized-mint", "staking", "reward-distribution", "missing-check", "defi"]
  },
  {
    id: "defi-oracle-price-manipulation",
    category: "DeFi Protocol Vulnerabilities",
    subcategory: "Oracle Manipulation",
    title: "Oracle Price Manipulation via Flash Loan on Spot Price Oracle",
    difficulty: "expert",
    description: "Protocol uses a spot price from a single DEX pool as its oracle. Flash loan enables temporary price manipulation, allowing attacker to borrow against inflated collateral and drain the lending pool.",
    target_description: "Lending protocol LendFi at 0xDef...456 on Ethereum mainnet. Uses Uniswap V2 TWAP oracle with 1-block window for ETH/USDC price feed. GitHub: https://github.com/lendfi/contracts. Scope includes PriceOracle.sol, LendingPool.sol, CollateralManager.sol. TVL: $120M.",
    attack_phases: [
      {
        phase: "Code Review & Architecture Analysis",
        description: "Analyze oracle architecture, price source, and TWAP implementation",
        tools: ["slither", "foundry", "etherscan"],
        commands: [
          "slither . --print human-summary",
          "cast call 0xPriceOracle 'getPrice(address)' 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2 --rpc-url $RPC_URL",
          "forge inspect PriceOracle.sol ast"
        ],
        expected_output: `Slither analysis complete. Found 4 High, 3 Medium, 2 Low severity findings.\nKey: PriceOracle.sol uses single DEX pair with 1-block TWAP window -- vulnerable to flash loan manipulation.`,
        thinking: "The PriceOracle contract gets the ETH/USDC price from Uniswap V2 pair. It calculates a TWAP but only over a 1-block window. That means a single large swap in the same block can shift the TWAP significantly. The LendingPool uses this price to determine collateral value. If I flash loan 50,000 ETH, swap it for USDC to push the ETH price up 3x, then borrow against my overvalued ETH collateral... I can drain the pool. Let me check the consultation window size.",
        analysis: "Single-source DEX oracle with 1-block TWAP window is vulnerable to flash loan price manipulation. Attacker can inflate collateral value within one block.",
        next_action: "Run Slither oracle-specific detectors and verify manipulation feasibility"
      },
      {
        phase: "Static Analysis & Automated Scanning",
        description: "Run oracle-specific Slither detectors and custom Semgrep rules",
        tools: ["slither", "semgrep"],
        commands: [
          "slither . --detect oracle-manipulation,weak-pricing --human-summary",
          "semgrep --config p/security-audit --lang solidity PriceOracle.sol"
        ],
        expected_output: `Slither findings:\n  oracle-manipulation (High): single DEX source, 1-block TWAP\n  weak-pricing (High): no price deviation bounds\nSemgrep findings:\n  [HIGH] getPrice() lacks minimum observation count check`,
        thinking: "Both tools confirm the oracle vulnerability. The single DEX source with no deviation bounds means the price can be manipulated by a large trade. I need to calculate the exact flash loan size required to achieve a 3x price move on the Uniswap V2 pool. Let me check the pool reserves.",
        analysis: "Static analysis confirms High severity oracle manipulation. Single DEX source without price deviation bounds allows flash loan attack.",
        next_action: "Build Foundry fork test with flash loan manipulation PoC"
      },
      {
        phase: "Proof of Concept Development",
        description: "Write Foundry test demonstrating flash loan oracle manipulation",
        tools: ["foundry"],
        commands: [
          "forge test --match-test test_POC_OracleManipulation -vvv --fork-url $RPC_URL --fork-block-number 18500000"
        ],
        expected_output: `[PASS] test_POC_OracleManipulation() (gas: 4567890)\nLogs:\n  Flash loan: 50,000 ETH from Aave\n  Swap ETH -> USDC: manipulated price to $6,000/ETH (normal: $2,000)\n  Deposited 1,000 ETH as collateral (valued at $6,000,000)\n  Borrowed 4,500,000 USDC against inflated collateral\n  Repaid flash loan + fee: 50,075 ETH\n  Profit: 3,200,000 USDC`,
        thinking: "The PoC works perfectly. With 50,000 ETH flash loan, I pushed the Uniswap V2 TWAP to $6,000/ETH (3x the real price). Deposited 1,000 ETH valued at $6M instead of $2M, borrowed $4.5M USDC, repaid the flash loan with 75 ETH fee, and walked away with $3.2M profit. The 1-block TWAP window made this trivially exploitable.",
        analysis: "PoC confirmed. 50,000 ETH flash loan manipulates oracle 3x, enabling $3.2M profit from $120M pool. Attack is fully on-chain and MEV-extractable.",
        next_action: "Quantify worst-case impact across all collateral types"
      },
      {
        phase: "Impact Analysis",
        description: "Calculate maximum financial impact across all oracle-dependent functions",
        tools: ["foundry", "tenderly"],
        commands: [
          "forge test --match-test test_WorstCaseImpact -vvv --fork-url $RPC_URL",
          "cast call 0xLendingPool 'totalBorrows()' --rpc-url $RPC_URL"
        ],
        expected_output: `Worst case impact by collateral type:\n  ETH: $3.2M drain possible\n  WBTC: $1.8M drain possible (lower liquidity pool)\n  Total drainable: $5.0M of $120M TVL\n  Protocol insolvency threshold: 4.2%`,
        thinking: "The impact analysis shows $5M total drainable across all collateral types. Beyond direct drain, this oracle flaw also affects: liquidation thresholds (can liquidate healthy positions), borrow limits (can borrow against fake collateral), and any downstream protocols using LendFi's oracle. Chain reaction risk is significant. CVSS 9.5 -- Critical.",
        analysis: "Critical impact: $5M drainable, protocol insolvency at 4.2% TVL loss. Oracle affects multiple downstream protocols.",
        next_action: "Write audit report recommending Chainlink or multi-source oracle with deviation bounds"
      },
      {
        phase: "Audit Report Writing",
        description: "Document oracle manipulation finding with PoC evidence and Chainlink migration recommendation",
        tools: ["report_generator"],
        commands: [],
        expected_output: "",
        thinking: "The report needs to clearly explain why a 1-block TWAP on a single DEX pair is insufficient, provide the exact PoC with dollar amounts, and recommend migrating to Chainlink or at minimum a multi-source oracle with price deviation bounds and longer TWAP windows.",
        analysis: "Compile oracle manipulation report with Chainlink migration path, interim fix with deviation bounds, and emergency pause recommendation.",
        next_action: "Submit report"
      }
    ],
    cve_references: ["SWC-101", "SWC-114", "CWE-345"],
    tools_involved: ["slither", "foundry", "etherscan", "semgrep", "tenderly", "report_generator"],
    tags: ["oracle-manipulation", "flash-loan", "spot-price", "twap", "lending", "defi", "critical"]
  },
  {
    id: "defi-revenue-handler-insolvency",
    category: "DeFi Protocol Vulnerabilities",
    subcategory: "Reward & Yield Distribution",
    title: "Revenue Handler Insolvency via Unclaimed Revenue Accounting Error",
    difficulty: "advanced",
    description: "Revenue distribution logic fails to account for unclaimed rewards when distributing new revenue, causing insolvency for late stakers who cannot claim their full share due to depleted reserves.",
    target_description: "Yield protocol YieldMax at 0xGhi...789 with RevenueHandler.sol distributing protocol fees to stakers. GitHub: https://github.com/yieldmax/contracts. Scope includes RevenueHandler.sol, StakingPool.sol, RewardDistributor.sol. Protocol fees: ~$50K/day.",
    attack_phases: [
      {
        phase: "Code Review & Architecture Analysis",
        description: "Analyze revenue distribution flow, reward accounting, and claim mechanism",
        tools: ["slither", "foundry", "etherscan"],
        commands: [
          "slither . --print human-summary",
          "forge build --sizes",
          "cast logs --address 0xRevenueHandler --from-block 18000000 --to-block latest --rpc-url $RPC_URL | head -50"
        ],
        expected_output: `Slither analysis complete. Found 2 High, 4 Medium, 3 Low severity findings.\nKey: RevenueHandler._distributeRevenue() does not update pending rewards for non-participating stakers.`,
        thinking: "The RevenueHandler receives protocol fees and distributes them proportionally to stakers. When distributeRevenue() is called, it calculates each staker's share based on their staking weight. But I notice a critical issue: it only updates the rewardIndex for active participants. Stakers who don't interact with the contract between distributions have stale rewardIndex values. When they eventually claim, the reserve may be depleted by earlier claimers. Let me trace the accounting flow carefully.",
        analysis: "Revenue distribution does not update pending rewards for inactive stakers. Late claimers face depleted reserves due to stale rewardIndex.",
        next_action: "Run Slither to verify accounting vulnerability pattern"
      },
      {
        phase: "Static Analysis & Automated Scanning",
        description: "Run accounting-focused detectors to identify reward distribution flaws",
        tools: ["slither", "semgrep"],
        commands: [
          "slither . --detect incorrect-equality,missing-zero-check --human-summary",
          "semgrep --config auto --lang solidity RevenueHandler.sol"
        ],
        expected_output: `Slither findings:\n  incorrect-equality (High): _distributeRevenue() uses stale rewardIndex for non-participants\n  missing-zero-check (Medium): no reserve depletion guard\nSemgrep: revenue accounting mismatch in _calculatePendingRewards()`,
        thinking: "Slither confirms the incorrect equality -- the revenue distribution uses stale indices for non-participating stakers. The missing-zero-check on reserves means there's no guard against over-distribution. Semgrep also flags the reward calculation mismatch. This is a classic accounting insolvency pattern.",
        analysis: "Static analysis confirms High severity accounting error. Revenue reserves can be over-distributed to early claimers, leaving late stakers with nothing.",
        next_action: "Develop Foundry PoC demonstrating insolvency scenario"
      },
      {
        phase: "Proof of Concept Development",
        description: "Write Foundry test showing late staker insolvency",
        tools: ["foundry"],
        commands: [
          "forge test --match-test test_POC_RevenueInsolvency -vvv --fork-url $RPC_URL"
        ],
        expected_output: `[PASS] test_POC_RevenueInsolvency() (gas: 1234567)\nLogs:\n  Setup: 3 stakers (A: 100 tokens, B: 100 tokens, C: 100 tokens)\n  Distribution 1: 3000 USDC revenue distributed\n  Staker A claims: receives 1000 USDC (full share)\n  Staker B claims: receives 1000 USDC (full share)\n  Distribution 2: 3000 USDC revenue distributed\n  Staker C claims: receives only 1500 USDC (expected 2000 USDC)\n  DEFICIT: Staker C lost 500 USDC due to stale index`,
        thinking: "The PoC clearly demonstrates the insolvency. Staker C, who didn't interact between distributions, lost 500 USDC because the rewardIndex was stale. The reserve was depleted by A and B's claims, and C's stale index caused an incorrect calculation. Over many distributions, this compounds -- a staker inactive for 10 distributions could lose 20-30% of expected rewards.",
        analysis: "PoC confirmed. Late/inactive stakers lose 25%+ of expected rewards due to stale rewardIndex accounting. Compound effect worsens over time.",
        next_action: "Quantify impact across historical distribution data"
      },
      {
        phase: "Impact Analysis",
        description: "Calculate cumulative impact on inactive stakers across historical distributions",
        tools: ["foundry", "tenderly"],
        commands: [
          "forge test --match-test test_HistoricalImpact -vvv --fork-url $RPC_URL",
          "cast call 0xRevenueHandler 'totalUnclaimed()' --rpc-url $RPC_URL"
        ],
        expected_output: `Historical analysis (90 days):\n  Total revenue distributed: 4.5M USDC\n  Estimated unclaimed (stale index): 890K USDC\n  Affected stakers: 1,247 (23% of total)\n  Average loss per affected staker: 714 USDC`,
        thinking: "The historical analysis is damning. Over 90 days, 890K USDC was effectively stolen from inactive stakers due to the accounting error. 23% of stakers were affected. This isn't just a theoretical vulnerability -- real users have lost real money. The protocol has been effectively running a reverse Robin Hood scheme: active stakers getting rewards that belong to inactive ones. CVSS 8.2 -- High.",
        analysis: "High impact confirmed. 890K USDC misallocated over 90 days. 23% of stakers affected. Systematic accounting error.",
        next_action: "Write audit report with accounting fix recommendation"
      },
      {
        phase: "Audit Report Writing",
        description: "Document revenue insolvency finding with historical evidence and accounting fix",
        tools: ["report_generator"],
        commands: [],
        expected_output: "",
        thinking: "The report should include: the accounting flaw explanation, PoC evidence, historical impact analysis showing 890K USDC misallocated, and the fix which requires updating rewardIndex for all stakers (or using a global rewards-per-token-share accumulator pattern).",
        analysis: "Compile revenue insolvency report with global accumulator fix recommendation and retroactive compensation plan.",
        next_action: "Submit report"
      }
    ],
    cve_references: ["SWC-101", "SWC-110", "CWE-682"],
    tools_involved: ["slither", "foundry", "etherscan", "semgrep", "tenderly", "report_generator"],
    tags: ["revenue-distribution", "accounting-error", "insolvency", "reward-index", "yield", "defi", "high-severity"]
  },
  {
    id: "defi-liquidation-bot-front-run",
    category: "DeFi Protocol Vulnerabilities",
    subcategory: "MEV & Front-running",
    title: "Liquidation Bot Front-Running via MEV Extraction",
    difficulty: "advanced",
    description: "Liquidation transactions are predictable and front-runnable. MEV bots extract value by sandwiching liquidation calls, reducing protocol efficiency and causing unfair liquidation outcomes.",
    target_description: "Lending protocol CreditDAO at 0xJkl...012 on Ethereum. Uses off-chain keeper bots to trigger liquidations when collateral ratio drops below 110%. GitHub: https://github.com/creditdao/contracts. Scope includes Liquidator.sol, HealthChecker.sol, PriceFeed.sol. Daily liquidation volume: ~$2M.",
    attack_phases: [
      {
        phase: "Code Review & Architecture Analysis",
        description: "Analyze liquidation mechanism, keeper bot architecture, and MEV exposure",
        tools: ["foundry", "etherscan", "blocksec-phi"],
        commands: [
          "forge inspect Liquidator.sol ast",
          "cast logs --address 0xLiquidator --topic 'Liquidation(address,address,uint256)' --from-block 18500000 --to-block latest --rpc-url $RPC_URL | head -20",
          "blocksec-phi analyze 0xLiquidator --network ethereum"
        ],
        expected_output: `Liquidation analysis:\n  Total liquidations (30 days): 847\n  Average gas price: 45 gwei (15 gwei base + 30 gwei priority)\n  Front-run detected in 312/847 liquidations (36.8%)\n  Total MEV extracted: $187,000`,
        thinking: "The liquidation flow is: off-chain keeper monitors health factor -> when HF < 1.1, keeper calls Liquidator.liquidate(borrower). The liquidation reward is 10% of the collateral. MEV bots monitor the mempool for these transactions and front-run them with higher gas, capturing the 10% bonus themselves. The keeper's transaction then reverts or gets partial fill. This is a classic MEV extraction pattern. Let me quantify the loss.",
        analysis: "36.8% of liquidations are front-run by MEV bots. $187K extracted over 30 days. Keeper bots systematically lose liquidation bonuses to searchers.",
        next_action: "Run MEV analysis tools to map front-running patterns"
      },
      {
        phase: "Static Analysis & Automated Scanning",
        description: "Analyze transaction patterns and MEV exposure using blockchain analytics",
        tools: ["etherscan", "flashbots-protect", "tenderly"],
        commands: [
          "tenderly simulate --network mainnet --tx-hash 0xliquidation_tx --trace",
          "cast rpc eth_getBlockByNumber 18500100 true --rpc-url $RPC_URL | jq '.transactions[] | select(.to == \"0xLiquidator\")'",
          "flashbots-protect estimate --tx-data 0xliquidation_calldata"
        ],
        expected_output: `MEV Analysis:\n  Predictable liquidation calldata: liquidate(address)\n  Gas bidding pattern: linear (15 + 30 priority gwei)\n  Average front-run delay: 1 block\n  Successful front-runs: 312 of 847\n  Extracted value: $187,000 (avg $600/liquidation)`,
        thinking: "The MEV analysis reveals systematic front-running. The liquidate(address) function signature is predictable. Keepers use linear gas bidding which is easily outbid. The 1-block average front-run delay confirms searchers are monitoring the mempool. The $600 average per liquidation extracted is significant. This needs a commit-reveal or batch auction mechanism.",
        analysis: "Systematic MEV extraction confirmed. Predictable calldata and gas patterns enable front-running. 36.8% success rate for MEV bots.",
        next_action: "Develop PoC demonstrating MEV extraction via mempool monitoring"
      },
      {
        phase: "Proof of Concept Development",
        description: "Build MEV bot simulation demonstrating liquidation front-running",
        tools: ["foundry", "tenderly"],
        commands: [
          "forge test --match-test test_POC_MEVFrontrun -vvv --fork-url $RPC_URL",
          "tenderly simulate --network mainnet --from 0xMEVBot --to 0xLiquidator --calldata 0xliquidate"
        ],
        expected_output: `[PASS] test_POC_MEVFrontrun() (gas: 890123)\nLogs:\n  Block 18500100: Keeper submits liquidation(tx1) for 0xBorrowerA\n  Block 18500100: MEV bot detects tx1 in mempool\n  Block 18500100: MEV bot submits liquidation(tx2) with 50 gwei priority\n  MEV bot liquidates 0xBorrowerA first, earns 10% bonus: 5,200 USDC\n  Keeper tx1 reverts: position already liquidated\n  MEV profit: 5,200 USDC - 150 USDC gas = 5,050 USDC`,
        thinking: "The MEV PoC works exactly as predicted. The bot monitors the mempool, detects the keeper's liquidation call, outbids it with higher priority gas, and captures the 10% bonus. The keeper's transaction reverts because the position was already liquidated. This is a zero-sum game where MEV bots profit at the expense of the protocol's intended liquidation incentives.",
        analysis: "MEV front-running PoC confirmed. 5,050 USDC profit per liquidation for searchers. Keeper incentives systematically undermined.",
        next_action: "Quantify impact on protocol health and propose commit-reveal fix"
      },
      {
        phase: "Impact Analysis",
        description: "Calculate cumulative impact on protocol efficiency and keeper economics",
        tools: ["foundry", "tenderly", "dune"],
        commands: [
          "forge test --match-test test_ImpactOnProtocol -vvv --fork-url $RPC_URL",
          "cast call 0xLiquidator 'totalLiquidations()' --rpc-url $RPC_URL"
        ],
        expected_output: `Impact on protocol:\n  Monthly MEV extraction: $187,000\n  Keeper bot unprofitability: 36.8% of liquidations fail\n  Undercollateralized positions remaining: 23 (unliquidated)\n  Estimated bad debt from delayed liquidations: $340,000\n  Protocol health factor: 1.15 (target: 1.30)`,
        thinking: "The broader impact is significant. Because 36.8% of liquidations fail due to MEV front-running, keepers are becoming unprofitable and stopping their operations. This leaves 23 undercollateralized positions unliquidated, creating $340K in bad debt. The protocol health factor has dropped to 1.15 from a target of 1.30. This creates a death spiral: fewer keepers -> more bad debt -> lower HF -> more liquidations needed -> more MEV extraction. CVSS 7.5 -- High.",
        analysis: "High impact on protocol health. $340K bad debt from delayed liquidations. Keeper economics undermined by MEV.",
        next_action: "Write audit report recommending commit-reveal liquidation mechanism"
      },
      {
        phase: "Audit Report Writing",
        description: "Document MEV front-running finding with impact analysis and commit-reveal recommendation",
        tools: ["report_generator"],
        commands: [],
        expected_output: "",
        thinking: "The report should cover: MEV extraction mechanism, 30-day impact data ($187K extracted), keeper economics breakdown, bad debt analysis ($340K), and recommend a commit-reveal scheme or sealed-bid auction for liquidations to prevent front-running.",
        analysis: "Compile MEV report with commit-reveal fix, sealed-bid auction design, and keeper incentive realignment.",
        next_action: "Submit report"
      }
    ],
    cve_references: ["SWC-114", "SWC-115", "CWE-362"],
    tools_involved: ["foundry", "etherscan", "blocksec-phi", "tenderly", "flashbots-protect", "report_generator"],
    tags: ["mev", "front-running", "liquidation", "keeper-bot", "sandwich-attack", "defi", "high-severity"]
  },
  {
    id: "defi-amm-slippage-manipulation",
    category: "DeFi Protocol Vulnerabilities",
    subcategory: "Logic Error",
    title: "AMM Slippage Manipulation Leading to Fund Drain",
    difficulty: "expert",
    description: "AMM swap function uses incorrect slippage calculation that allows attackers to manipulate the price impact check, enabling extraction of funds beyond the intended swap amount through crafted input/output amounts.",
    target_description: "AMM protocol SwapDex at 0xMno...345 on Arbitrum. Custom AMM implementation with dynamic fee tier. GitHub: https://github.com/swapdex/contracts. Scope includes SwapRouter.sol, Pool.sol, Math.sol. TVL: $15M, daily volume: $3M.",
    attack_phases: [
      {
        phase: "Code Review & Architecture Analysis",
        description: "Analyze AMM swap logic, slippage calculation, and price impact enforcement",
        tools: ["slither", "foundry", "etherscan"],
        commands: [
          "slither . --print human-summary",
          "forge inspect Math.sol ast --json | jq '.nodes[] | select(.nodeType == \"FunctionDefinition\") | .name'",
          "cast call 0xPool 'getReserves()' --rpc-url $RPC_URL"
        ],
        expected_output: `Slither analysis complete. Found 5 High, 2 Medium, 1 Low severity findings.\nKey: Math._calculatePriceImpact() uses input amount instead of output amount for slippage check.`,
        thinking: "The core AMM logic is in Pool.sol. The swap() function takes amountIn, amountOutMin, and path. It calculates price impact using Math._calculatePriceImpact(). Let me examine this function carefully. The function computes priceImpact = (amountIn - expectedOut) / expectedOut * 100. Wait -- that's wrong. Price impact should be calculated on the OUTPUT side, not the input side. The slippage check compares against amountOutMin, but the price impact calculation uses amountIn. This means an attacker can craft a swap where amountIn is tiny but the price impact is massive, and the slippage check still passes because it's calculated on the wrong side.",
        analysis: "Critical math error in slippage calculation. Price impact computed on input amount instead of output amount allows manipulation.",
        next_action: "Run Slither math-specific detectors and verify calculation flaw"
      },
      {
        phase: "Static Analysis & Automated Scanning",
        description: "Run math and arithmetic detectors to confirm slippage calculation error",
        tools: ["slither", "semgrep", "manticore"],
        commands: [
          "slither . --detect incorrect-equality,divide-before-multiply --human-summary",
          "semgrep --config p/security-audit --lang solidity Math.sol",
          "manticore . --contract Pool --txlimit 100"
        ],
        expected_output: `Slither findings:\n  incorrect-equality (High): _calculatePriceImpact() divides by wrong variable\n  divide-before-multiply (Medium): precision loss in fee calculation\nManticore: found 3 exploitable states where slippage check passes but price impact exceeds 50%`,
        thinking: "Manticore found 3 exploitable states where the slippage check passes despite 50%+ price impact. The divide-before-multiply in fee calculation compounds the issue. The core problem: _calculatePriceImpact() calculates (amountIn - expectedOut) / expectedOut but should be (expectedOut - actualOut) / expectedOut. By manipulating amountIn to be small relative to the pool, the attacker can make price impact appear minimal while actually extracting a large percentage of the pool.",
        analysis: "Multiple tools confirm critical math error. Slippage check can be bypassed, enabling extraction of 50%+ of pool reserves.",
        next_action: "Build Foundry PoC demonstrating slippage manipulation attack"
      },
      {
        phase: "Proof of Concept Development",
        description: "Write Foundry test demonstrating AMM slippage manipulation",
        tools: ["foundry"],
        commands: [
          "forge test --match-test test_POC_SlippageManipulation -vvv --fork-url $RPC_URL"
        ],
        expected_output: `[PASS] test_POC_SlippageManipulation() (gas: 678901)\nLogs:\n  Pool reserves: 500 ETH / 1,000,000 USDC\n  Attack swap: amountIn = 10 USDC, amountOutMin = 0\n  Actual amountOut: 250 ETH (50% of pool)\n  Price impact (correct calc): 50%\n  Price impact (contract calc): 0.001% (PASSES slippage check)\n  Attacker profit: 250 ETH - 10 USDC cost = ~$499,990`,
        thinking: "The PoC is devastating. With just 10 USDC input, the attacker extracts 250 ETH (50% of the pool) because the slippage check is calculating on the wrong side. The contract thinks the price impact is 0.001% (because amountIn is tiny relative to pool) but the actual impact is 50%. This drains half the pool in a single transaction. CVSS 10.0 -- Critical.",
        analysis: "Critical PoC confirmed. 10 USDC input extracts 50% of pool reserves. Slippage check completely bypassed. Full fund drain possible.",
        next_action: "Calculate total drain potential and write emergency report"
      },
      {
        phase: "Impact Analysis",
        description: "Calculate maximum drain across all pools and assess protocol-wide impact",
        tools: ["foundry", "tenderly"],
        commands: [
          "forge test --match-test test_TotalDrainAnalysis -vvv --fork-url $RPC_URL",
          "cast call 0xSwapRouter 'getAllPools()' --rpc-url $RPC_URL"
        ],
        expected_output: `Total drain potential across all pools:\n  ETH/USDC pool: $500K (50% of $1M)\n  ARB/ETH pool: $250K (50% of $500K)\n  USDC/USDT pool: $750K (50% of $1.5M)\n  Total drainable: $1.5M of $15M TVL (10%)\n  Attack cost per pool: <$100`,
        thinking: "Every pool is drainable for 50% of its reserves. The total drainable is $1.5M across all pools, and each attack costs less than $100. This is the most severe type of vulnerability: trivial to execute, massive impact, affects all pools. The protocol would be insolvent after a single attacker drains multiple pools. CVSS 10.0 -- Critical.",
        analysis: "Critical: $1.5M drainable across all pools. Each pool can be drained 50% for <$100 cost. Protocol insolvency guaranteed.",
        next_action: "Write emergency audit report with immediate patch recommendation"
      },
      {
        phase: "Audit Report Writing",
        description: "Document critical slippage manipulation with emergency severity and patch",
        tools: ["report_generator"],
        commands: [],
        expected_output: "",
        thinking: "This is an emergency report. The vulnerability allows 50% drain of every pool for minimal cost. The fix requires: 1) Correct the price impact calculation to use output amounts, 2) Add a maximum price impact cap, 3) Implement a circuit breaker for large swaps. This needs to be reported immediately.",
        analysis: "Emergency critical report. Recommend immediate pause, correct price impact formula, add max impact cap, implement circuit breaker.",
        next_action: "Submit emergency report"
      }
    ],
    cve_references: ["SWC-101", "SWC-123", "CWE-682"],
    tools_involved: ["slither", "foundry", "etherscan", "semgrep", "manticore", "tenderly", "report_generator"],
    tags: ["slippage-manipulation", "amm", "price-impact", "math-error", "fund-drain", "defi", "critical"]
  },
  {
    id: "defi-bridge-fee-manipulation",
    category: "DeFi Protocol Vulnerabilities",
    subcategory: "Cross-Chain & Bridge",
    title: "Bridge Fee Manipulation via Token Decimal Mismatch",
    difficulty: "advanced",
    description: "Cross-chain bridge calculates fees based on token amount without normalizing for decimal differences between source and destination chains, allowing attackers to pay minimal fees while transferring large value.",
    target_description: "Bridge protocol CrossLink at 0xPqr...678 connecting Ethereum (18 decimals) to Optimism (6 decimals for bridged tokens). GitHub: https://github.com/crosslink/bridge. Scope includes BridgeRouter.sol, FeeCalculator.sol, TokenVault.sol. TVL: $35M, daily bridge volume: $5M.",
    attack_phases: [
      {
        phase: "Code Review & Architecture Analysis",
        description: "Analyze bridge architecture, fee calculation, and decimal handling across chains",
        tools: ["slither", "foundry", "etherscan"],
        commands: [
          "slither . --print human-summary",
          "forge inspect FeeCalculator.sol ast",
          "cast call 0xTokenVault 'getSupportedTokens()' --rpc-url $RPC_URL"
        ],
        expected_output: `Slither analysis complete. Found 3 High, 3 Medium, 2 Low severity findings.\nKey: FeeCalculator._calculateFee() uses raw token amount without decimal normalization.`,
        thinking: "The bridge transfers tokens between Ethereum (18 decimals) and Optimism (6 decimals for some tokens). The FeeCalculator._calculateFee() function calculates fee as amount * feeRate / 10000. But it uses the raw amount without normalizing for decimal differences. When bridging a 6-decimal token from Ethereum to Optimism, the fee is calculated on the 6-decimal amount, but the actual value transferred is 10^12x larger. An attacker can bridge tokens paying a tiny fee while transferring massive value.",
        analysis: "Bridge fee calculation does not normalize token decimals. 6-decimal tokens pay fees on normalized-down amount while transferring full 18-decimal value.",
        next_action: "Run Slither to verify decimal handling vulnerability"
      },
      {
        phase: "Static Analysis & Automated Scanning",
        description: "Run decimal-aware detectors and cross-chain vulnerability scanners",
        tools: ["slither", "semgrep"],
        commands: [
          "slither . --detect incorrect-decimal-handling,divide-before-multiply --human-summary",
          "semgrep --config auto --lang solidity FeeCalculator.sol BridgeRouter.sol"
        ],
        expected_output: `Slither findings:\n  incorrect-decimal-handling (High): _calculateFee() doesn't normalize decimals\n  divide-before-multiply (Medium): precision loss in fee computation\nSemgrep:\n  [HIGH] FeeCalculator uses raw amount for 6-decimal tokens\n  [HIGH] BridgeRouter doesn't verify decimal consistency`,
        thinking: "Both tools confirm the decimal handling vulnerability. The FeeCalculator treats a 1000000 USDC (6 decimals = 1 token) the same as 1000000 of an 18-decimal token (= 0.000000000000001 tokens). The fee for bridging 1 USDC would be calculated as if bridging 10^12 units of an 18-decimal token. But the actual value transferred is 1 USDC. Let me verify the exact exploitation path.",
        analysis: "Decimal mismatch confirmed. Fee calculation undercharges by 10^12x for 6-decimal tokens. Bridge fee revenue loss is systematic.",
        next_action: "Build Foundry PoC demonstrating decimal-based fee bypass"
      },
      {
        phase: "Proof of Concept Development",
        description: "Write Foundry test demonstrating decimal-based fee manipulation",
        tools: ["foundry"],
        commands: [
          "forge test --match-test test_POC_DecimalFeeBypass -vvv --fork-url $RPC_URL"
        ],
        expected_output: `[PASS] test_POC_DecimalFeeBypass() (gas: 345678)\nLogs:\n  Bridging 1,000,000 USDC (6 decimals = 1 USDC in 18-decimal terms)\n  Fee calculated: 1,000,000 * 0.03% = 300 (in 6-decimal units = 0.0003 USDC actual fee)\n  Value transferred: 1,000,000 USDC on destination\n  Actual fee paid: 0.0003 USDC\n  Fee evasion: 299.9997 USDC saved vs. correct fee of 300 USDC\n  For 1M USDC transfer: correct fee = $300, actual fee = $0.0003`,
        thinking: "The PoC demonstrates the decimal bypass perfectly. Bridging 1M USDC (which is 1M units in 6-decimal representation) should incur a $300 fee (0.03%), but the FeeCalculator calculates 300 units in 6-decimal terms = $0.0003 actual fee. The attacker saves $299.9997 per 1M USDC transfer. Scale this up: bridging $10M USDC costs $0.003 in fees instead of $3,000.",
        analysis: "PoC confirmed. Fee evasion of 99.9999% for 6-decimal tokens. $10M bridge costs $0.003 instead of $3,000.",
        next_action: "Calculate cumulative protocol revenue loss from decimal mismatch"
      },
      {
        phase: "Impact Analysis",
        description: "Calculate total fee revenue loss across all affected token pairs",
        tools: ["foundry", "tenderly"],
        commands: [
          "forge test --match-test test_RevenueLossAnalysis -vvv --fork-url $RPC_URL",
          "cast call 0xBridgeRouter 'getBridgeVolume()' --rpc-url $RPC_URL"
        ],
        expected_output: `Revenue loss analysis:\n  Affected tokens: USDC (6 dec on OP), USDT (6 dec on ARB), DAI (6 dec on Polygon)\n  30-day bridge volume (affected tokens): $45M\n  Expected fees at 0.03%: $13,500\n  Actual fees collected: $0.04\n  Fee revenue lost: $13,499.96 (99.9997% loss)\n  Exploitable by anyone: yes, no access control`,
        thinking: "The revenue loss is $13,500 over 30 days from the decimal mismatch alone. But the more concerning issue is that this creates a systematic incentive for arbitrageurs to use the bridge instead of paying proper fees, draining the fee revenue pool. If combined with the bridge's liquidity model, this could also lead to insolvency if the fee pool subsidizes cross-chain transfers. CVSS 8.0 -- High.",
        analysis: "High impact. $13.5K fee revenue lost over 30 days. Systematic decimal mismatch affects all 6-decimal tokens.",
        next_action: "Write audit report with decimal normalization fix"
      },
      {
        phase: "Audit Report Writing",
        description: "Document bridge fee decimal mismatch with revenue analysis and normalization fix",
        tools: ["report_generator"],
        commands: [],
        expected_output: "",
        thinking: "The report should cover: decimal mismatch explanation, PoC with exact fee evasion amounts, 30-day revenue loss analysis, and the fix which requires normalizing all token amounts to 18 decimals before fee calculation using a decimal adapter.",
        analysis: "Compile bridge fee report with decimal normalization adapter, per-token decimal registry, and retroactive fee adjustment mechanism.",
        next_action: "Submit report"
      }
    ],
    cve_references: ["SWC-101", "SWC-123", "CWE-682"],
    tools_involved: ["slither", "foundry", "etherscan", "semgrep", "tenderly", "report_generator"],
    tags: ["bridge", "decimal-mismatch", "fee-bypass", "cross-chain", "token-transfer", "defi", "high-severity"]
  },
  {
    id: "defi-vault-withdrawal-dos",
    category: "DeFi Protocol Vulnerabilities",
    subcategory: "Rounding & Precision",
    title: "Vault Withdrawal DoS via Rounding Precision Loss",
    difficulty: "intermediate",
    description: "Vault share calculation uses integer division that rounds down, causing small depositors to receive zero shares on deposit and unable to withdraw on redemption, effectively DoSing their funds.",
    target_description: "Yield vault VaultPro at 0xStu...901 on Ethereum. Single-asset vault depositing into a lending protocol. GitHub: https://github.com/vaultpro/contracts. Scope includes Vault.sol, ShareCalculator.sol. TVL: $8M, minimum deposit: 0 (no minimum enforced).",
    attack_phases: [
      {
        phase: "Code Review & Architecture Analysis",
        description: "Analyze vault share calculation, deposit/withdrawal logic, and rounding behavior",
        tools: ["slither", "foundry", "etherscan"],
        commands: [
          "slither . --print human-summary",
          "forge inspect ShareCalculator.sol ast",
          "cast call 0xVault 'totalSupply() totalAssets()' --rpc-url $RPC_URL"
        ],
        expected_output: `Slither analysis complete. Found 1 High, 2 Medium, 3 Low severity findings.\nKey: ShareCalculator._calcShares() uses totalAssets / totalSupply which rounds down to zero for small deposits.`,
        thinking: "The Vault follows the ERC-4626 standard. The share calculation is shares = assets * totalSupply / totalAssets. When totalAssets is much larger than totalSupply (e.g., after significant yield accrual), small deposits round to zero shares. For example: if totalAssets = 1,000,000 USDC and totalSupply = 100, a deposit of 1 USDC gives shares = 1 * 100 / 1,000,000 = 0 shares (integer division). The depositor's USDC is transferred but they receive zero shares -- their funds are permanently locked. Let me verify this.",
        analysis: "Integer division in share calculation rounds down to zero for small deposits when totalAssets >> totalSupply. Depositor funds locked with no recovery mechanism.",
        next_action: "Run precision-focused Slither detectors"
      },
      {
        phase: "Static Analysis & Automated Scanning",
        description: "Run rounding and precision detectors to confirm DoS vulnerability",
        tools: ["slither", "semgrep"],
        commands: [
          "slither . --detect divide-before-multiply,incorrect-equality --human-summary",
          "semgrep --config auto --lang solidity ShareCalculator.sol"
        ],
        expected_output: `Slither findings:\n  divide-before-multiply (High): shares = assets * totalSupply / totalAssets rounds to zero\n  incorrect-equality (Medium): no minimum shares enforcement\nSemgrep:\n  [HIGH] Small depositors receive zero shares\n  [MEDIUM] No inflation attack protection`,
        thinking: "Slither confirms the divide-before-multiply issue. The order of operations (multiply then divide) should prevent precision loss, but when the result is genuinely less than 1, Solidity's integer division rounds to zero. The fix would be to use a minimum share mint or to reorder the calculation. But there's also an inflation attack vector: someone could deposit a tiny amount first to set the exchange rate, then large deposits would give almost all shares to the first depositor.",
        analysis: "Precision loss confirmed. Small deposits result in zero shares. Additionally vulnerable to vault inflation attacks.",
        next_action: "Build Foundry PoC demonstrating both zero-share DoS and inflation attack"
      },
      {
        phase: "Proof of Concept Development",
        description: "Write Foundry test demonstrating zero-share DoS and vault inflation",
        tools: ["foundry"],
        commands: [
          "forge test --match-test test_POC_ZeroShareDoS -vvv --fork-url $RPC_URL",
          "forge test --match-test test_POC_VaultInflation -vvv --fork-url $RPC_URL"
        ],
        expected_output: `[PASS] test_POC_ZeroShareDoS() (gas: 234567)\nLogs:\n  Vault state: totalAssets = 1,000,000 USDC, totalSupply = 100 shares\n  Deposit 1 USDC: shares minted = 0\n  USDC transferred from depositor: 1 USDC\n  Depositor balance: 0 shares, 1 USDC lost permanently\n  [PASS] test_POC_VaultInflation() (gas: 345678)\n  Attacker deposits 1 wei -> gets 1 share\n  Attacker donates 1,000,000 USDC to vault (inflates totalAssets)\n  Victim deposits 1000 USDC: shares = 1000 * 1 / 1,000,001 = 0 shares\n  Victim loses 1000 USDC`,
        thinking: "Both PoCs work. The zero-share DoS locks small deposits permanently. The inflation attack is even worse: an attacker can donate USDC to inflate the share price, causing all subsequent deposits to round to zero. The minimum cost for the inflation attack is the donated amount, but if the attacker holds all shares, they can later withdraw the donated funds plus the victim's deposits.",
        analysis: "Both zero-share DoS and vault inflation attack confirmed. Small deposits permanently locked. Inflation attack enables fund theft.",
        next_action: "Quantify impact and write audit report with ERC-4626 compliance fix"
      },
      {
        phase: "Impact Analysis",
        description: "Calculate impact on small depositors and assess inflation attack feasibility",
        tools: ["foundry", "tenderly"],
        commands: [
          "forge test --match-test test_ImpactOnSmallDeposits -vvv --fork-url $RPC_URL",
          "cast call 0xVault 'convertToShares(uint256)' 1000000 --rpc-url $RPC_URL"
        ],
        expected_output: `Impact analysis:\n  Minimum deposit to receive 1 share: 10,000 USDC (current ratio)\n  Deposits below 10,000 USDC: DO NOT receive shares (funds locked)\n  Estimated affected users: 342 (avg deposit: 500 USDC)\n  Total locked funds: 171,000 USDC\n  Inflation attack cost: 1 wei (minimum) + donation amount\n  CVSS Score: 7.0 (High)`,
        thinking: "The current exchange rate means any deposit under 10,000 USDC receives zero shares. With 342 affected users and 171K USDC locked, this is a significant DoS. The inflation attack makes it even worse -- an attacker can raise the share price arbitrarily high, locking out all new deposits. CVSS 7.0 -- High.",
        analysis: "High impact. 342 users with 171K USDC locked. Inflation attack allows arbitrary fund theft.",
        next_action: "Write audit report with ERC-4626 minimum shares and inflation protection"
      },
      {
        phase: "Audit Report Writing",
        description: "Document vault withdrawal DoS with inflation attack analysis and ERC-4626 fix",
        tools: ["report_generator"],
        commands: [],
        expected_output: "",
        thinking: "The report should cover: zero-share DoS mechanism, vault inflation attack, affected users (342) and locked funds (171K USDC), and recommend ERC-4626 compliance fixes including minimum share minting and virtual shares/reserves to prevent inflation.",
        analysis: "Compile vault DoS report with minimum share enforcement, virtual shares/reserves pattern, and user remediation plan.",
        next_action: "Submit report"
      }
    ],
    cve_references: ["SWC-123", "SWC-128", "CWE-190"],
    tools_involved: ["slither", "foundry", "etherscan", "semgrep", "tenderly", "report_generator"],
    tags: ["rounding-error", "precision-loss", "vault", "dos", "inflation-attack", "erc4626", "defi", "medium-severity"]
  },
  {
    id: "defi-interest-rate-manipulation",
    category: "DeFi Protocol Vulnerabilities",
    subcategory: "Logic Error",
    title: "Interest Rate Manipulation via Missing Rate Limit Check",
    difficulty: "intermediate",
    description: "Interest rate model allows instantaneous rate changes without a maximum rate change limit, enabling manipulation of borrowing costs to extract value from the lending pool.",
    target_description: "Lending protocol RateFi at 0xVwx...234 on Base. Custom interest rate model with admin-updatable parameters. GitHub: https://github.com/ratefi/contracts. Scope includes InterestRateModel.sol, LendingPool.sol, RateGovernor.sol. TVL: $25M.",
    attack_phases: [
      {
        phase: "Code Review & Architecture Analysis",
        description: "Analyze interest rate model, rate update mechanism, and access controls",
        tools: ["slither", "foundry", "etherscan"],
        commands: [
          "slither . --print human-summary",
          "cast call 0xInterestRateModel 'getBorrowRate(uint256)' 500000000000000000 --rpc-url $RPC_URL",
          "cast logs --address 0xRateGovernor --topic 'RateUpdated' --from-block 17000000 --to-block latest --rpc-url $RPC_URL | head -20"
        ],
        expected_output: `Slither analysis complete. Found 2 High, 3 Medium, 2 Low severity findings.\nKey: RateGovernor.updateRate() has no maximum rate change limit per update.`,
        thinking: "The InterestRateModel calculates borrow rates based on utilization. The RateGovernor can update rate parameters via updateRate(). But there's no maximum rate change limit -- the owner can change the rate from 5% to 500% in a single transaction. If the owner account is compromised, or if governance is manipulated, this allows instant rate manipulation. Borrowers with open positions would face astronomical interest costs immediately. Let me check if there's a timelock.",
        analysis: "No rate change limits or timelock on interest rate updates. Owner can change rates instantaneously, creating manipulation vector.",
        next_action: "Run access control and rate-limit detectors"
      },
      {
        phase: "Static Analysis & Automated Scanning",
        description: "Run access control and governance-focused detectors",
        tools: ["slither", "semgrep"],
        commands: [
          "slither . --detect unprotected-function,centralization-risk --human-summary",
          "semgrep --config auto --lang solidity RateGovernor.sol"
        ],
        expected_output: `Slither findings:\n  unprotected-function (High): updateRate() callable by owner without timelock\n  centralization-risk (High): single EOA owns RateGovernor\n  timelock-missing (Medium): no delay on rate changes\nSemgrep:\n  [HIGH] updateRate() has no maxRateChange parameter\n  [HIGH] No rate change event includes previous rate for comparison`,
        thinking: "The centralization risk is severe. A single EOA owns the RateGovernor with no timelock. If that key is compromised (or the owner turns malicious), they can instantly spike rates to 500%+, causing massive interest accrual on all open borrows. Borrowers would need to repay immediately or face ruinous costs. There's no max rate change parameter either, so rates can jump arbitrarily.",
        analysis: "Centralization risk confirmed. Single EOA can instantly manipulate interest rates with no constraints.",
        next_action: "Build Foundry PoC demonstrating rate manipulation attack"
      },
      {
        phase: "Proof of Concept Development",
        description: "Write Foundry test demonstrating interest rate manipulation",
        tools: ["foundry"],
        commands: [
          "forge test --match-test test_POC_RateManipulation -vvv --fork-url $RPC_URL"
        ],
        expected_output: `[PASS] test_POC_RateManipulation() (gas: 567890)\nLogs:\n  Initial borrow rate: 5% APY\n  Owner updates rate to: 500% APY\n  Borrower A has 100,000 USDC borrowed\n  Interest accrued in 1 hour at 500% APY: 5,708 USDC\n  Interest accrued in 1 hour at 5% APY: 57 USDC\n  Excess interest extracted: 5,651 USDC per hour\n  Attacker (as rate manipulator) can drain via interest fee collection`,
        thinking: "The PoC shows the manipulation clearly. By spiking rates to 500%, a borrower with 100K USDC loan accrues 5,708 USDC in one hour instead of 57 USDC. The excess 5,651 USDC goes to the protocol's reserve, which the owner controls. This is effectively a forced extraction of borrower funds through rate manipulation. The attack cost is just the owner key (already compromised in this scenario).",
        analysis: "Rate manipulation PoC confirmed. 100x rate spike extracts 5,651 USDC/hour from borrowers. Owner-controlled reserve accumulates excess.",
        next_action: "Calculate total extractable value from all open borrows"
      },
      {
        phase: "Impact Analysis",
        description: "Calculate maximum extraction from all open borrowing positions",
        tools: ["foundry", "tenderly"],
        commands: [
          "forge test --match-test test_MaxExtractableValue -vvv --fork-url $RPC_URL",
          "cast call 0xLendingPool 'totalBorrows()' --rpc-url $RPC_URL"
        ],
        expected_output: `Maximum extractable value:\n  Total borrows: $8.5M USDC\n  At 500% APY for 24 hours: $1,164,384 excess interest\n  At 500% APY for 7 days: $8,500,000 (full drain)\n  Borrowers affected: 2,341\n  Time to full drain: 7 days at max rate\n  CVSS Score: 8.5 (High)`,
        thinking: "The worst case is devastating. At 500% APY for 7 days, the entire $8.5M in borrows would be consumed by interest alone. In practice, borrowers would try to repay, but the rate spike would push many into insolvency, triggering liquidations at unfavorable rates. The centralization risk (single EOA owner) combined with no rate limits makes this a critical governance vulnerability. CVSS 8.5 -- High.",
        analysis: "High impact. $8.5M extractable from borrowers via rate manipulation. Full protocol drain in 7 days.",
        next_action: "Write audit report with rate limits, timelock, and multi-sig recommendation"
      },
      {
        phase: "Audit Report Writing",
        description: "Document interest rate manipulation with centralization risk and governance fix",
        tools: ["report_generator"],
        commands: [],
        expected_output: "",
        thinking: "The report should cover: missing rate change limits, centralization risk (single EOA), PoC with extraction amounts, and recommend: 1) max rate change per update (e.g., 1% max change), 2) 48-hour timelock, 3) multi-sig or DAO governance, 4) rate change event with previous/new rate logging.",
        analysis: "Compile rate manipulation report with rate limits, timelock, multi-sig governance, and emergency pause mechanism.",
        next_action: "Submit report"
      }
    ],
    cve_references: ["SWC-101", "SWC-112", "CWE-863"],
    tools_involved: ["slither", "foundry", "etherscan", "semgrep", "tenderly", "report_generator"],
    tags: ["interest-rate", "rate-manipulation", "centralization-risk", "governance", "lending", "defi", "high-severity"]
  },
  {
    id: "defi-ve-token-voting-manipulation",
    category: "DeFi Protocol Vulnerabilities",
    subcategory: "Governance Attack",
    title: "veToken Voting Weight Manipulation via Repeated Delegation",
    difficulty: "advanced",
    description: "veToken delegation mechanism does not enforce a cooldown between delegation changes, allowing an attacker to repeatedly delegate voting power to themselves across multiple proposals, artificially inflating their governance weight.",
    target_description: "DAO governance protocol GovMax at 0xYza...567 on Ethereum. veTOKEN model with delegation. GitHub: https://github.com/govmax/contracts. Scope includes veTOKEN.sol, Governor.sol, DelegationManager.sol. Treasury: $50M, veTOKEN supply: 10M.",
    attack_phases: [
      {
        phase: "Code Review & Architecture Analysis",
        description: "Analyze veToken delegation mechanism, voting power calculation, and proposal lifecycle",
        tools: ["slither", "foundry", "etherscan"],
        commands: [
          "slither . --print human-summary",
          "forge inspect DelegationManager.sol ast",
          "cast call 0xGovernor 'quorum()' --rpc-url $RPC_URL",
          "cast call 0xveTOKEN 'delegates(address)' 0xAttacker --rpc-url $RPC_URL"
        ],
        expected_output: `Slither analysis complete. Found 2 High, 3 Medium, 2 Low severity findings.\nKey: DelegationManager.delegate() has no cooldown between delegation changes.`,
        thinking: "The veTOKEN delegation system allows token holders to delegate their voting power to another address. The DelegationManager.delegate() function can be called without any cooldown or state check. An attacker with a small amount of veTOKEN can: 1) Delegate to themselves before Proposal A vote, 2) After vote A snapshots, undelegate and re-delegate before Proposal B, 3) Repeat across multiple proposals. The key issue is that voting power is checked at vote creation time, not at delegation time. If the attacker can coordinate with allies to delegate/undelegate in sequence, they can accumulate effective voting power exceeding their actual holdings.",
        analysis: "No delegation cooldown allows repeated delegation changes. Voting power snapshot timing can be exploited across multiple proposals.",
        next_action: "Run governance-focused detectors"
      },
      {
        phase: "Static Analysis & Automated Scanning",
        description: "Run governance vulnerability detectors and delegation pattern analysis",
        tools: ["slither", "semgrep"],
        commands: [
          "slither . --detect governance-vote-manipulation,unprotected-function --human-summary",
          "semgrep --config auto --lang solidity DelegationManager.sol Governor.sol"
        ],
        expected_output: `Slither findings:\n  governance-vote-manipulation (High): no delegation cooldown, vote snapshot timing exploitable\n  unprotected-function (Medium): delegate() callable by anyone without limits\nSemgrep:\n  [HIGH] DelegationManager: no cooldown between delegation changes\n  [HIGH] Governor: votes snapshot taken at proposal creation, not at execution`,
        thinking: "The governance analysis confirms the manipulation vector. The combination of no delegation cooldown and vote snapshot at proposal creation (rather than execution) means an attacker can: borrow veTOKEN via flash loan, delegate to themselves, create a proposal (snapshot captures delegated power), then return the veTOKEN. The proposal passes with artificially inflated voting power. The attacker only needs to hold the veTOKEN during the snapshot block.",
        analysis: "Governance manipulation confirmed. Flash loan + delegation allows proposal creation with artificially inflated voting power.",
        next_action: "Build Foundry PoC demonstrating delegation-based voting manipulation"
      },
      {
        phase: "Proof of Concept Development",
        description: "Write Foundry test demonstrating veToken delegation manipulation",
        tools: ["foundry"],
        commands: [
          "forge test --match-test test_POC_VotingManipulation -vvv --fork-url $RPC_URL"
        ],
        expected_output: `[PASS] test_POC_VotingManipulation() (gas: 1234567)\nLogs:\n  Attacker holds: 100 veTOKEN (0.001% of supply)\n  Flash loan: 1,000,000 veTOKEN from lending pool\n  Delegate to self: voting power = 1,000,100 veTOKEN (10%)\n  Create Proposal: "Transfer 5M USDC to attacker address"\n  Snapshot voting power: 1,000,100 veTOKEN\n  Return flash loan: 1,000,000 veTOKEN\n  Vote on proposal: YES with 1,000,100 veTOKEN\n  Quorum required: 500,000 veTOKEN (5%)\n  Proposal PASSES with 10% voting power\n  Treasury drained: 5,000,000 USDC`,
        thinking: "The PoC is devastating. With just 100 veTOKEN (0.001% of supply), the attacker flash loans 1M veTOKEN, delegates to themselves, creates and votes on a malicious proposal, and drains $5M from the treasury. The flash loan costs ~$500 in gas, and the proposal passes because the snapshot captured the inflated voting power. This is a complete governance takeover. CVSS 9.8 -- Critical.",
        analysis: "Critical PoC confirmed. Flash loan delegation enables governance takeover. 100 veTOKEN controls $5M treasury drain.",
        next_action: "Calculate worst-case treasury exposure and write emergency report"
      },
      {
        phase: "Impact Analysis",
        description: "Calculate maximum treasury exposure from governance manipulation",
        tools: ["foundry", "tenderly"],
        commands: [
          "forge test --match-test test_TreasuryExposure -vvv --fork-url $RPC_URL",
          "cast call 0xGovernor 'proposalCount()' --rpc-url $RPC_URL",
          "cast call 0xTreasury 'balance()' --rpc-url $RPC_URL"
        ],
        expected_output: `Treasury exposure analysis:\n  Total treasury: $50M USDC + $15M in governance tokens\n  Timelock delay: 0 blocks (instant execution)\n  Max drain per proposal: $50M (full treasury)\n  Minimum veTOKEN required: 1 wei (flash loan)\n  Flash loan cost: ~$500 gas\n  ROI: 10,000,000%\n  CVSS Score: 9.8 (Critical)`,
        thinking: "The timelock is 0 blocks -- proposals execute instantly after passing. This means the attack is: flash loan -> delegate -> propose -> vote -> execute -> repay loan, all in one transaction if using a custom contract. The entire $65M treasury is drainable for $500 in gas. This is one of the most severe governance vulnerabilities possible. CVSS 9.8 -- Critical.",
        analysis: "Critical: $65M treasury drainable in single transaction. Zero timelock enables instant execution. Flash loan makes attack nearly free.",
        next_action: "Write emergency audit report with immediate governance freeze recommendation"
      },
      {
        phase: "Audit Report Writing",
        description: "Document critical governance manipulation with emergency severity and multi-fix recommendation",
        tools: ["report_generator"],
        commands: [],
        expected_output: "",
        thinking: "Emergency report needed. Fixes: 1) Add 7-day delegation cooldown, 2) Vote snapshots at proposal execution time (not creation), 3) Add 48-hour timelock for all proposals, 4) Exclude flash-loaned tokens from voting power via checkpoint-based balance tracking, 5) Implement multi-sig for treasury operations above $1M.",
        analysis: "Emergency critical report. Recommend immediate governance freeze, delegation cooldown, execution-time snapshots, and timelock.",
        next_action: "Submit emergency report"
      }
    ],
    cve_references: ["SWC-101", "SWC-112", "CWE-863"],
    tools_involved: ["slither", "foundry", "etherscan", "semgrep", "tenderly", "report_generator"],
    tags: ["governance-attack", "voting-manipulation", "delegation", "ve-token", "flash-loan", "dao", "defi", "critical"]
  },
  {
    id: "defi-yield-aggregator-fee-bypass",
    category: "DeFi Protocol Vulnerabilities",
    subcategory: "Fee & Slippage",
    title: "Yield Aggregator Fee Bypass via Incorrect Fee Recipient",
    difficulty: "intermediate",
    description: "Fee distribution logic in yield aggregator sends performance fees to a hardcoded address instead of the configured fee recipient, allowing any user to claim fees by deploying a contract at the expected address.",
    target_description: "Yield aggregator YieldMax Pro at 0xBcd...890 on Optimism. Auto-compounding vault strategy. GitHub: https://github.com/yieldmaxpro/contracts. Scope includes VaultStrategy.sol, FeeDistributor.sol, PerformanceTracker.sol. TVL: $12M, performance fee: 10%.",
    attack_phases: [
      {
        phase: "Code Review & Architecture Analysis",
        description: "Analyze fee distribution mechanism, recipient configuration, and claim flow",
        tools: ["slither", "foundry", "etherscan"],
        commands: [
          "slither . --print human-summary",
          "forge inspect FeeDistributor.sol ast",
          "cast call 0xFeeDistributor 'feeRecipient()' --rpc-url $RPC_URL"
        ],
        expected_output: `Slither analysis complete. Found 1 High, 2 Medium, 3 Low severity findings.\nKey: FeeDistributor._distributeFees() sends to hardcoded 0x00...dead instead of configured feeRecipient.`,
        thinking: "The FeeDistributor collects 10% performance fees from the vault strategy. The _distributeFees() function should send fees to the configured feeRecipient address. But looking at the code, it sends to address(0x000000000000000000000000000000000000dead) -- a hardcoded burn address. This means all performance fees are being burned instead of going to the protocol treasury. The feeRecipient variable is set correctly but never used in the distribution logic. This is a simple but costly bug.",
        analysis: "Performance fees sent to hardcoded burn address instead of configured feeRecipient. 10% of all yield is permanently burned.",
        next_action: "Run fee flow detectors to confirm misdirected fees"
      },
      {
        phase: "Static Analysis & Automated Scanning",
        description: "Run fee flow and hardcoded address detectors",
        tools: ["slither", "semgrep"],
        commands: [
          "slither . --detect hardcoded-address,dead-code --human-summary",
          "semgrep --config auto --lang solidity FeeDistributor.sol"
        ],
        expected_output: `Slither findings:\n  hardcoded-address (High): _distributeFees() uses hardcoded 0x00...dead instead of feeRecipient\n  dead-code (Low): feeRecipient variable set but never read\nSemgrep:\n  [HIGH] FeeDistributor: feeRecipient state variable unused in _distributeFees()\n  [MEDIUM] Fee calculation correct but distribution target wrong`,
        thinking: "Slither confirms the hardcoded address bug. The feeRecipient variable is set during initialization but never used in the distribution function. The fees go to 0x00...dead and are permanently lost. Over time, this burns 10% of all yield generated by the vault. Let me calculate the cumulative loss.",
        analysis: "Hardcoded burn address confirmed. 10% performance fees permanently burned. feeRecipient variable is dead code.",
        next_action: "Calculate cumulative fee loss and build PoC"
      },
      {
        phase: "Proof of Concept Development",
        description: "Write Foundry test demonstrating fee burn and calculate cumulative loss",
        tools: ["foundry"],
        commands: [
          "forge test --match-test test_POC_FeeBurn -vvv --fork-url $RPC_URL"
        ],
        expected_output: `[PASS] test_POC_FeeBurn() (gas: 234567)\nLogs:\n  Vault yield generated (30 days): 120,000 USDC\n  Performance fee (10%): 12,000 USDC\n  Fee recipient (configured): 0xProtocolTreasury\n  Fee sent to: 0x000000000000000000000000000000000000dead\n  Fees burned: 12,000 USDC\n  Daily burn rate: 400 USDC/day\n  Annual burn rate: 146,000 USDC/year`,
        thinking: "The PoC quantifies the loss clearly. 12,000 USDC burned over 30 days from performance fees alone. The annual burn rate is 146,000 USDC -- that's over $146K per year going to the burn address. The protocol is effectively subsidizing users by giving them 100% of yield instead of 90%. This makes the protocol unprofitable and unsustainable.",
        analysis: "PoC confirmed. 12K USDC burned in 30 days. Annual burn rate 146K USDC. Protocol unprofitable due to fee misdirection.",
        next_action: "Calculate total historical fee loss and write report"
      },
      {
        phase: "Impact Analysis",
        description: "Calculate total historical fee loss since deployment",
        tools: ["foundry", "tenderly"],
        commands: [
          "forge test --match-test test_HistoricalFeeLoss -vvv --fork-url $RPC_URL",
          "cast logs --address 0xVaultStrategy --topic 'YieldGenerated' --from-block 17000000 --to-block latest --rpc-url $RPC_URL | wc -l"
        ],
        expected_output: `Historical fee loss (since deployment):\n  Deployment block: 17,200,000\n  Current block: 18,500,000\n  Total yield generated: 1.2M USDC\n  Total fees burned (10%): 120,000 USDC\n  Protocol revenue lost: $120,000\n  Burn address balance: 120,000 USDC (permanently locked)\n  CVSS Score: 6.5 (Medium)`,
        thinking: "Since deployment, $120K in performance fees have been burned. While this is a medium severity issue (it doesn't enable theft, just revenue loss), it makes the protocol fundamentally unprofitable. The fix is straightforward: use feeRecipient instead of the hardcoded address. But the burned funds are unrecoverable. CVSS 6.5 -- Medium.",
        analysis: "Medium impact. $120K burned since deployment. Fix is simple code change but burned funds unrecoverable.",
        next_action: "Write audit report with fix and fee recovery assessment"
      },
      {
        phase: "Audit Report Writing",
        description: "Document fee bypass with historical loss analysis and one-line fix",
        tools: ["report_generator"],
        commands: [],
        expected_output: "",
        thinking: "The report should cover: hardcoded address bug, historical fee loss ($120K), the one-line fix (use feeRecipient instead of hardcoded address), and note that burned funds are unrecoverable. Recommend adding a fee recovery mechanism (e.g., emergency withdrawal from burn address if possible, or fee clawback from future yield).",
        analysis: "Compile fee bypass report with one-line fix, unrecoverable burn assessment, and future fee protection recommendation.",
        next_action: "Submit report"
      }
    ],
    cve_references: ["SWC-101", "SWC-123", "CWE-670"],
    tools_involved: ["slither", "foundry", "etherscan", "semgrep", "tenderly", "report_generator"],
    tags: ["fee-bypass", "hardcoded-address", "fee-distribution", "yield-aggregator", "revenue-loss", "defi", "medium-severity"]
  }
];
