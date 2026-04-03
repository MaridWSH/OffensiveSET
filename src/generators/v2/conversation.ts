// Conversation builder for Smart Contract Security Dataset Generator V2

import { ScenarioTemplate, AttackPhase } from "../../templates/scenarios/index.js";
import { SMARTCONTRACT_TOOLS, ToolDefinition } from "../../schemas/tools/index.js";
import { SmartContractOutputEngine, SeededRNG, ContractProfile, generateContractProfile } from "../outputs/index.js";
import { ThinkingEngine } from "../thinking-engine.js";
import { USER_PROMPTS_INITIAL, USER_PROMPTS_VULN_TESTING, USER_PROMPTS_EXPLOIT, USER_PROMPTS_FAILURE_FOLLOWUP, USER_PROMPTS_REPORT, USER_PROMPTS_DEEP_ANALYSIS, USER_PROMPTS_EVASION, DOMAINS } from "./prompts.js";
import { generateSystemPrompt } from "./system-prompts.js";
import { variateText, generateGroundedResponse } from "./responses.js";
import { generateUniqueAuditReport } from "./reports.js";
import { postProcessForQwen, estimateTokens } from "./post-processor.js";
import { ShareGPTConversation, ShareGPTMessage, ToolCall, ToolResult, GenerationConfig } from "./types.js";

export function countTurns(messages: ShareGPTMessage[]): number {
  return messages.filter(m => m.from === "human" || m.from === "gpt").length;
}

export function identifyToolFromCommand(cmd: string): string | undefined {
  const toolKeywords: Record<string, string[]> = {
    slither: ["slither "],
    mythril: ["mythril ", "myth "],
    semgrep: ["semgrep "],
    securify: ["securify "],
    foundry: ["forge ", "forge test", "forge build"],
    echidna: ["echidna "],
    hardhat: ["hardhat ", "npx hardhat"],
    cast: ["cast "],
    anvil: ["anvil"],
    solc: ["solc "],
    solhint: ["solhint "],
    etherscan: ["etherscan"],
    tenderly: ["tenderly"],
    dune: ["dune"],
    abi_encoder: ["abi_encode", "cast abi-encode"],
    sigint: ["4byte", "sigint"],
    report_generator: ["report"],
  };

  for (const [tool, keywords] of Object.entries(toolKeywords)) {
    if (keywords.some(kw => cmd.includes(kw))) return tool;
  }

  if (cmd.startsWith("node ") || cmd.startsWith("ts-node ")) return "script";
  if (cmd.includes("for ") && cmd.includes("do ")) return "bash_script";
  if (cmd.startsWith("export ") || cmd.startsWith("curl ")) return "cli";

  return undefined;
}

export function generateDynamicOutput(
  engine: SmartContractOutputEngine,
  toolName: string,
  profile: ContractProfile,
  phase: AttackPhase,
  rng: SeededRNG
): string {
  switch (toolName) {
    case "slither":
      return engine.generateSlitherOutput(profile);

    case "mythril":
      return engine.generateMythrilOutput(profile);

    case "semgrep": {
      const findingCount = rng.int(2, 8);
      const rules = rng.pickN(["sol-reentrancy", "sol-missing-modifier", "sol-unsafe-arithmetic", "sol-tx-origin", "sol-block-timestamp", "sol-unchecked-transfer", "sol-shadowing", "sol-unused-var"], rng.int(2, 4));
      return `Running Semgrep with smart contract rules against ${profile.contractName}.sol...
Found ${findingCount} findings:

${rules.map((r, i) => `  [${rng.pick(["HIGH", "MEDIUM", "LOW"])}] ${r}: ${profile.contractName}.sol:${rng.int(45, 380)}:${rng.int(1, 12)}
    ${rng.pick([
      "Function is missing an access control modifier",
      "External call before state update creates reentrancy window",
      "Arithmetic operation without overflow protection",
      "Using tx.origin for authorization is unsafe",
      "Block timestamp manipulation vulnerability",
      "Unchecked return value from low-level call",
      "Variable shadows inherited state variable",
      "Unused state variable increases gas cost",
    ])}`).join("\n")}

Analyzed ${rng.int(1, 5)} contracts, ${rng.int(200, 800)} functions.`;
    }

    case "securify": {
      const patterns = rng.pickN(["DAO", "TOD", "Untrusted", "Unhandled", "IOD", "Suicidal", "Leaky"], rng.int(2, 5));
      return `Securify v2 analysis of ${profile.contractName}.sol:

Contract: ${profile.contractName} (${rng.int(3, 12)} functions, ${rng.int(5, 15)} state variables)

Pattern Analysis:
${patterns.map(p => {
    const status = rng.pick(["safe", "violated", "warning"]);
    return `  ${p}: ${status.toUpperCase()}`;
  }).join("\n")}

Total patterns checked: ${rng.int(20, 40)}
Dependencies analyzed: ${profile.dependencies.length}
Solidity version: v${profile.solidityVersion}`;
    }

    case "foundry": {
      const testCount = rng.int(4, 12);
      const passingCount = rng.int(testCount - 2, testCount);
      const failingCount = testCount - passingCount;
      const gasValues = Array.from({ length: rng.int(2, 5) }, () =>
        `${profile.contractName}.${rng.pick(profile.externalFunctions).name} (runs: ${rng.int(1, 50)}, μ: ${rng.int(20000, 500000)}, ~: ${rng.int(20000, 500000)})`
      );

      return `Compiling ${rng.int(3, 15)} files with Solc v${profile.solidityVersion}...
Solc ${rng.int(3, 15)} files compiled successfully

Running ${testCount} tests for ${profile.contractName}
   Running ${profile.contractName}Test...
${Array.from({ length: passingCount }, (_, i) => `   [PASS] test_${rng.pick([
        "invariant_totalSupplyConsistent",
        "test_RevertWhen_UnauthorizedAccess",
        "test_StakeAndWithdraw",
        "test_RewardsAccrue",
        "invariant_NoUnrestrictedMint",
        "test_ReentrancyGuard",
        "test_AccessControlEnforced",
        "test_OraclePriceNotManipulated",
        "test_FeeCalculationCorrect",
        "test_UpgradePathSecure",
      ])}() (gas: ${rng.int(50000, 2000000)})`).join("\n")}
${failingCount > 0 ? Array.from({ length: failingCount }, () => `   [FAIL. Reason: ${rng.pick([
        "AssertionError: expected 0 to be greater than 0",
        "call reverted: AccessControl: account is missing role",
        "expected 1000000 to equal 999999 — rounding error",
        "revert: ReentrancyGuard: reentrant call",
      ])}] test_${rng.pick([
        "test_ExploitReentrancy",
        "test_UnauthorizedMint",
        "test_RoundingExploit",
        "test_OracleManipulation",
      ])}() (gas: ${rng.int(100000, 500000)})`).join("\n") : ""}

Suite result: ${rng.bool(0.6) ? "FAILED" : "ok"}. ${passingCount} passed; ${failingCount} failed; ${rng.int(0, 3)} skipped; finished in ${rng.float(0.05, 2.5).toFixed(2)}s

Ran ${testCount} test suites (${testCount} tests): ${passingCount} passed | ${failingCount} failed | ${rng.int(0, 3)} skipped

Gas report:
┌──────────────────────────────────────┬──────────────────┬──────────────────┐
│ Contract / Function                  │ Min              │ Avg              │
┼──────────────────────────────────────┼──────────────────┼──────────────────┤
${gasValues.map(g => {
        const parts = g.split(" (runs: ")[1]?.replace(")", "").split(", μ: ");
        return `│ ${g.split(" (")[0].padEnd(38)} │ ${rng.int(20000, 400000).toLocaleString().padStart(16)} │ ${(rng.int(20000, 500000)).toLocaleString().padStart(16)} │`;
      }).join("\n")}
└──────────────────────────────────────┴──────────────────┴──────────────────┘`;
    }

    case "echidna": {
      const invariantCount = rng.int(3, 8);
      const invariants = Array.from({ length: invariantCount }, () => {
        const status = rng.bool(0.7) ? "PASSED" : "FAILED";
        return `  ${status}: echidna_${rng.pick([
          "totalSupplyConsistent",
          "noUnauthorizedMint",
          "rewardsMatchDeposit",
          "priceNotManipulated",
          "balanceNeverNegative",
          "onlyOwnerCanPause",
          "feesCollectedCorrectly",
          "nonceAlwaysIncreases",
        ])}() (tests: ${rng.int(1000, 50000)}, calls: ${rng.int(50000, 500000)}, seq: ${rng.int(50, 200)})`;
      });

      return `Echidna v${rng.pick(["2.2.1", "2.2.2", "2.2.3"])} — property-based fuzzing for ${profile.contractName}

Configuration:
  Test contract: ${profile.contractName}Test
  Seed: ${rng.int(100000, 999999)}
  Test limit: ${rng.int(5000, 50000)} tests
  Chain ID: ${profile.chainId}

Starting fuzzing...
${invariants.join("\n")}

Results: ${invariants.filter(i => i.includes("PASSED")).length} passed, ${invariants.filter(i => i.includes("FAILED")).length} failed
Total time: ${rng.float(5, 120).toFixed(1)}s
Total calls: ${rng.int(50000, 500000).toLocaleString()}`;
    }

    case "cast":
      return engine.generateCastCallOutput(profile, phase.phase, undefined);

    case "anvil":
      return engine.generateAnvilOutput(profile);

    case "etherscan":
      return `[Source] Verified contract source code for ${profile.contractAddress} on ${profile.protocolName}
Compiler: solc v${profile.solidityVersion}
Optimization: ${rng.int(100, 1000000)} runs
License: ${rng.pick(["MIT", "GPL-3.0", "BUSL-1.1", "UNLICENSED"])}
Contract Name: ${profile.contractName}
Implementation Address: ${profile.contractAddress}
Proxy Type: ${rng.pick(["Transparent", "UUPS", "Beacon", "Minimal"])}
ABI: ${rng.int(10, 50)} functions detected
Verified on: ${rng.pick(["Etherscan", "Arbiscan", "Optimistic Etherscan", "Basescan", "Polygonscan", "BscScan"])} (Chain ID: ${profile.chainId})`;

    case "tenderly":
      return `[Simulation] Transaction simulated for ${profile.contractName}.${profile.affectedFunction}
Status: ${rng.pick(["Success", "Reverted"])}
Gas used: ${engine.generateGasUsed().toLocaleString()}
Block: ${rng.int(19000000, 21000000)}
From: ${engine.generateAddress()}
To: ${profile.contractAddress}
Value: ${rng.pick(["0", "0.001", "0.01", "0.1", "1"])} ETH
Trace: ${rng.int(5, 50)} internal calls
  ${profile.contractName}.${profile.affectedFunction}
  → ${rng.pick(profile.externalFunctions).name}
  → ${rng.pick(["IERC20.transfer", "IERC20.transferFrom", "IOracle.getPrice", "console.log"])}
Events emitted: ${rng.int(0, 5)}
State changes: ${rng.int(1, 10)} slots modified`;

    case "solc":
      return `Compiling ${profile.contractName}.sol with solc v${profile.solidityVersion}...
Compiled ${rng.int(3, 15)} contracts successfully
Gas report:
  ${profile.contractName}.${profile.affectedFunction}: ${rng.int(20000, 500000)} gas
  ${profile.contractName}.${rng.pick(profile.externalFunctions).name}: ${rng.int(20000, 500000)} gas
  ${profile.contractName}.${rng.pick(profile.externalFunctions).name}: ${rng.int(20000, 500000)} gas

Warning: Unused function parameter in ${profile.contractName}:${rng.int(50, 300)}.
Warning: Function state mutability can be restricted to view at ${profile.contractName}:${rng.int(100, 400)}.`;

    case "solhint":
      return `Linting ${profile.contractName}.sol...
${engine.generateHex(4).toUpperCase()}:${rng.int(1, 20)}  ${rng.pick(["error", "warning"])}  ${rng.pick(["Missing modifier", "Visibility not set", "Line too long"])}  ${rng.pick(["no-unused-vars", "explicit-types", "max-line-length"])}  (${profile.contractName}.sol)
${engine.generateHex(4).toUpperCase()}:${rng.int(1, 20)}  ${rng.pick(["error", "warning", "warn"])}  ${rng.pick(["Use ^ instead of =", "Explicitly mark visibility", "Avoid tx.origin"])}  ${rng.pick(["compiler-version", "explicit-types", "tx-origin"])}  (${profile.contractName}.sol)
${engine.generateHex(4).toUpperCase()}:${rng.int(1, 20)}  ${rng.pick(["warning", "warn"])}  ${rng.pick(["Consecutive blank lines", "Mixed case required", "Quotes style"])}  ${rng.pick(["no-empty-blocks", "func-param-name-mixedcase", "quotes"])}  (${profile.contractName}.sol)

${rng.int(2, 8)} problems (${rng.int(1, 3)} errors, ${rng.int(1, 5)} warnings)`;

    case "dune": {
      const metricCount = rng.int(3, 6);
      return `Querying ${profile.protocolName} analytics on Dune...

${Array.from({ length: metricCount }, () => `  ${rng.pick([
        "Total Value Locked (TVL)",
        "24h Volume",
        "Unique Active Users (7d)",
        "Average Gas Price (gwei)",
        "Protocol Revenue (30d)",
        "Token Holder Count",
        "Bridge Volume (cross-chain)",
        "Liquidation Rate",
      ])}: ${rng.pick([
        `$${rng.int(5, 500)}M`,
        `$${rng.int(1, 100)}M`,
        `${rng.int(500, 50000).toLocaleString()}`,
        `${rng.int(5, 100)} gwei`,
        `$${rng.int(100, 5000)}K`,
        `${rng.int(1000, 500000).toLocaleString()}`,
        `$${rng.int(1, 50)}M`,
        `${rng.float(0.1, 15).toFixed(1)}%`,
      ])}`).join("\n")}

Last updated: block ${rng.int(19000000, 21000000)}
Protocol: ${profile.protocolName} on ${rng.pick(["Ethereum", "Arbitrum", "Optimism", "Base", "Polygon"])}
Data freshness: ${rng.int(1, 60)} minutes ago`;
    }

    case "abi_encoder": {
      const func = rng.pick(profile.externalFunctions);
      return `ABI Encoding for ${profile.contractName}.${func.name}(${func.params.join(", ")})

Function selector: 0x${engine.generateHex(8)}
Encoded calldata: 0x${engine.generateHex(8)}${func.params.map(() => engine.generateHex(rng.int(10, 64)).padStart(64, "0")).join("")}

Decoded:
  Function: ${func.name}
  Parameters:
${func.params.map((p, i) => `    [${i}] ${p}: 0x${engine.generateHex(rng.int(8, 32))}`).join("\n")}`;
    }

    case "sigint":
      return `4byte.directory lookup for ${profile.protocolName}

Found ${rng.int(2, 8)} matching function selectors:
${Array.from({ length: rng.int(2, 6) }, () => `  0x${engine.generateHex(8)} → ${rng.pick([
        "stake(uint256)",
        "withdraw(uint256)",
        "claim()",
        "mint(address,uint256)",
        "bridge(uint256,address,uint256)",
        "setPrice(address,uint256)",
        "execute(address,uint256,bytes)",
        "receiveMessage(bytes,bytes)",
        "poke(uint256)",
        "delegate(address,uint256)",
        "liquidate(address,uint256)",
      ])}`).join("\n")}

Unknown selectors: ${rng.int(0, 5)}
Contract: ${profile.contractName} (${profile.externalFunctions.length} known functions)`;

    case "hardhat":
      return `Hardhat v${rng.pick(["2.19.0", "2.20.0", "2.21.0"])} — ${profile.protocolName}

Compiling ${rng.int(5, 20)} files...
Compiled ${rng.int(5, 20)} Solidity files successfully

Running tests...
  ${profile.contractName}
    ${rng.pick(["Deployment", "Staking", "Rewards", "Access Control", "Upgrades"])}
      ${rng.pick(["✓", "✓", "✓", "✓", "✓", "✗"])} should ${rng.pick([
        "deploy with correct initial state",
        "allow users to stake tokens",
        "accrue rewards over time",
        "restrict access to owner-only functions",
        "upgrade without state corruption",
        "handle zero-amount inputs gracefully",
        "emit events on state changes",
        "revert on unauthorized mint attempts",
      ])} (${rng.int(50, 5000)}ms)

  ${rng.int(15, 40)} passing (${rng.int(1, 8)}s)
  ${rng.int(0, 2)} failing`;

    case "anvil": {
      const blockNum = rng.int(19000000, 21000000);
      return `Anvil v${rng.pick(["0.2.0", "0.3.0"])} — Local testnet

Listening on 127.0.0.1:8545

Forking mainnet at block ${blockNum}
Chain ID: ${profile.chainId}
Base fee: ${rng.int(5, 50)} gwei
Gas limit: 30,000,000

Deployed ${profile.contractName} at ${profile.contractAddress}
Block number: ${blockNum}
Block timestamp: ${rng.int(1700000000, 1720000000)}
Balance: ${rng.int(9000, 10000)} ETH

Ready for interaction.`;
    }

    default: {
      // Dynamic fallback — generate output from profile data
      const customOutputs = [
        `Running ${toolName} analysis on ${profile.contractName}...

Contract: ${profile.contractName} (${profile.protocolName})
Solidity: v${profile.solidityVersion}
Functions analyzed: ${profile.externalFunctions.length}
State variables: ${profile.stateVariables.length}

Findings:
  [${rng.pick(["HIGH", "MEDIUM", "LOW"])}] ${profile.affectedFunction}: ${rng.pick([
        "Missing access control on privileged function",
        "External call before state update",
        "Unchecked arithmetic operation",
        "No input validation on user-supplied amount",
        "Oracle price can be manipulated",
      ])}
  [${rng.pick(["MEDIUM", "LOW", "INFO"])}] ${rng.pick(profile.externalFunctions).name}: ${rng.pick([
        "Missing event emission",
        "Function could be declared view",
        "Unused parameter",
        "Gas optimization opportunity",
      ])}

Total: ${rng.int(1, 5)} issues found`,
        `Analysis of ${profile.contractName}.sol complete.

Target: ${profile.contractName} @ ${profile.contractAddress}
Chain: ${rng.pick(["Ethereum", "Arbitrum", "Optimism", "Base"])} (ID: ${profile.chainId})
TVL: ${profile.tvl}

Scan results:
  - ${rng.int(3, 15)} functions scanned
  - ${rng.int(1, 8)} state variables checked
  - ${rng.int(0, 3)} potential issues
  - ${rng.int(0, 1)} confirmed vulnerabilities

Risk assessment: ${rng.pick(["Critical", "High", "Medium", "Low"])} severity
Vulnerability type: ${profile.vulnType}
Affected function: ${profile.affectedFunction}`,
      ];
      return rng.pick(customOutputs);
    }
  }
}

function generateDeepAnalysis(profile: ContractProfile, rng: SeededRNG): string {
  const analyses = [
    `### Extended Analysis\n\nLooking deeper at the ${profile.vulnType} finding in \`${profile.contractName}\`:\n\n**Attack Surface Expansion:**\nThe ${profile.protocolName} protocol has ${rng.int(3, 15)} contracts, of which I've audited ${rng.int(1, 5)}. The vulnerability pattern I found likely extends to:\n- \`${rng.pick(profile.externalFunctions).name}()\` on the same contract — similar logic with the same missing check\n- \`${rng.pick(["Voter", "RevenueHandler", "PoolVoter", "RewardDistributor", "Adapter"])}\` — related contracts in the inheritance chain\n\nThis is because the vulnerable code is likely shared across multiple contracts through ${rng.pick(["a common base contract", "a shared library function", "a copied implementation pattern", "an inherited modifier chain"])}.\n\n**Detection Difficulty:**\nFrom a defender's perspective, this attack would be ${rng.pick(["difficult to detect because the transactions appear as normal protocol usage", "moderately detectable through on-chain anomaly monitoring", "visible in transaction logs but easily missed without specific alerting rules", "nearly impossible to detect without off-chain monitoring of state variables"])}.\n\n**Recommended monitoring:**\n- ${rng.pick(["Monitor for abnormal state variable deltas in the vulnerable function", "Alert on large single-tx withdrawals exceeding protocol averages", "Track function call frequency and flag unusual patterns", "Implement an on-chain circuit breaker if state changes exceed safe thresholds"])}`,

    `### Risk Assessment Deep Dive\n\nFor ${profile.protocolName} (\`${profile.contractName}\`, Chain ID: ${profile.chainId}):\n\n**Quantified Risk:**\n- TVL at risk: ${profile.tvl}\n- Token exposure: ${profile.affectedToken} at ${profile.tokenPrice}\n- Attack capital required: ${profile.requiresCapital > 0 ? `$${profile.requiresCapital.toLocaleString()}` : "None — permissionless exploit"}\n- Estimated fix effort: ${rng.int(2, 40)} developer hours for the primary fix, ${rng.int(5, 80)} hours for comprehensive hardening\n\n**Compensating Controls (while fix is developed):**\n1. Pause the affected function via the protocol's emergency pause mechanism\n2. ${rng.pick(["Deploy a monitoring bot that watches for exploit patterns on-chain", "Add a timelock delay on the vulnerable function to allow human review", "Implement a per-user rate limit via the existing access control layer", "Add a secondary confirmation step requiring multi-sig approval"])}\n3. ${rng.pick(["Brief the protocol's security advisors and prepare a disclosure", "Review on-chain history for signs of prior exploitation", "Engage an external auditor to validate the proposed fix", "Coordinate with the chain's security team for potential MEV protection"])}`,

    `### Alternative Attack Paths\n\nBeyond the primary ${profile.vulnType} finding, I identified several related attack vectors on ${profile.protocolName}:\n\n**Path 1: ${rng.pick(["Upgrade Path Exploitation", "Oracle Price Feed Manipulation", "Cross-Chain Replay Attack", "Governance Proposal Injection"])}**\n${rng.pick(["The proxy implementation can be upgraded through a path that lacks proper access control checks.", "The price oracle relies on a single source that can be manipulated through a flash loan attack.", "Messages valid on one chain can be replayed on another due to missing chainId binding.", "The governance contract allows proposal creation without sufficient token lockup."])}\n\n**Path 2: ${rng.pick(["Flash Loan Amplification", "MEV Sandwich Attack", "State Variable Shadowing", "Timelock Circumvention"])}**\n${rng.pick(["A flash loan can amplify the attacker's capital enough to trigger the vulnerable condition in a single transaction.", "The transaction ordering dependency allows MEV extractors to sandwich user transactions for profit.", "Proxy and implementation storage layouts conflict, causing state variable overlap that corrupts critical data.", "The timelock mechanism can be bypassed through direct function calls on the implementation contract."])}\n\n**Chaining potential:** Combining the primary ${profile.vulnType} finding with ${rng.pick(["the oracle manipulation path", "the flash loan amplification", "the governance weakness", "the upgrade path issue"])} would escalate the impact from ${rng.pick(["single-function exploit to full protocol drain", "isolated loss to cross-protocol contagion", "data exposure to governance capture", "reentrancy to unlimited minting"])}.`,

    `### Post-Exploitation Impact Assessment\n\nAssuming an attacker successfully exploits the ${profile.vulnType} vulnerability in ${profile.contractName}:\n\n**Immediate capabilities:**\n${rng.pickN(["- Drain up to " + profile.tvl + " from the protocol's " + rng.pick(["liquidity pool", "vault", "staking contract", "treasury"]), "- Mint unlimited " + profile.affectedToken + " tokens, diluting all holders", "- Execute unauthorized state changes through the privileged function", "- Manipulate the oracle price to enable over-borrowing across the protocol", "- Bypass access controls and perform admin-level operations", "- Corrupt storage layout making recovery impossible without migration", profile.requiresCapital > 0 ? "- Leverage $" + profile.requiresCapital.toLocaleString() + " of capital to extract " + profile.tvl : "- Execute the exploit with zero upfront capital"], rng.int(3, 5)).join("\n")}\n\n**Persistence mechanisms an attacker could establish:**\n${rng.pickN(["- Modify critical state variables to maintain control over protocol functions", "- Plant a backdoor function that allows repeated exploitation", "- Drain rewards over multiple epochs before the vulnerability is detected", "- Use governance power gained from the exploit to pass malicious proposals", "- Corrupt the implementation address to redirect future upgrades"], rng.int(2, 4)).join("\n")}\n\n**Recommended incident response actions:**\n1. ${rng.pick(["Review all on-chain interactions with the vulnerable contract for the past 30 days", "Scan for abnormal state variable values that indicate prior exploitation", "Rotate all admin keys and multi-sig signers if privileged access was compromised", "Prepare a migration plan to a new implementation contract"])}\n2. ${rng.pick(["Engage whitehat services to recover funds if already exploited", "Coordinate with the chain's security team for potential transaction censoring", "Notify integrated protocols of potential cross-protocol risk", "Prepare a public disclosure following responsible disclosure practices"])}`,
  ];

  return rng.pick(analyses);
}

export function buildConversationV2(
  scenario: ScenarioTemplate,
  rng: SeededRNG,
  config: GenerationConfig,
  entryIndex: number
): ShareGPTConversation {
  const protocolName = rng.pick(DOMAINS);
  const profile = generateContractProfile(rng);
  profile.protocolName = protocolName;

  const outputEngine = new SmartContractOutputEngine(rng.int(0, 999999999));
  const thinkingEngineInstance = new ThinkingEngine(rng.int(0, 999999999));

  const includeThinking = rng.bool(config.thinkingRatio);
  const includeFailures = rng.bool(config.failureRatio);

  const messages: ShareGPTMessage[] = [];
  const toolsUsed: string[] = [];
  let hasFailures = false;

  // Build available tools list for system prompt
  const scenarioTools = scenario.tools_involved
    .map(name => SMARTCONTRACT_TOOLS.find(t => t.name === name))
    .filter((t): t is ToolDefinition => t !== undefined);
  const extraTools = rng.pickN(
    SMARTCONTRACT_TOOLS.filter(t => !scenario.tools_involved.includes(t.name)),
    rng.int(1, 3)
  );
  const allTools = [...scenarioTools, ...extraTools];
  const toolsList = allTools.map(t => `- ${t.name}: ${t.description.slice(0, 80)}`).join("\n");

  messages.push({
    from: "system",
    value: `${generateSystemPrompt(rng, profile as any)}\n\nAvailable tools:\n${toolsList}`,
  });

  // Initial user prompt — replace {protocol}, {contract}, {vulnType}
  const initialPrompt = rng.pick(USER_PROMPTS_INITIAL)
    .replace(/\{protocol\}/g, protocolName)
    .replace(/\{contract\}/g, profile.contractName)
    .replace(/\{vulnType\}/g, profile.vulnType);

  messages.push({
    from: "human",
    value: `${initialPrompt}\n\nContract: ${profile.contractName}\nChain: ${rng.pick(["Ethereum", "Arbitrum", "Optimism", "Base", "Polygon"])} (Chain ID: ${profile.chainId})\nSolidity: v${profile.solidityVersion}\nTVL: ${profile.tvl}`,
  });

  // Phase structure variation
  let phases = [...scenario.attack_phases];
  const structureVariant = rng.int(0, 4);
  if (structureVariant === 1 && phases.length > 3) {
    const skipIdx = rng.int(1, phases.length - 2);
    phases = phases.filter((_, i) => i !== skipIdx);
  } else if (structureVariant === 2 && phases.length > 2) {
    phases = [phases[0], ...phases.slice(2)];
  }

  const failurePhaseIdx = includeFailures ? rng.int(0, phases.length - 1) : -1;
  const softFailChance = 0.15;

  let lastToolOutputSummary = "";

  // Phase-by-phase conversation generation
  for (let phaseIdx = 0; phaseIdx < phases.length; phaseIdx++) {
    const phase = phases[phaseIdx];
    const isFailurePhase = phaseIdx === failurePhaseIdx;
    const isSoftFail = !isFailurePhase && rng.bool(softFailChance);

    const toolCalls: ToolCall[] = [];
    const toolResults: ToolResult[] = [];
    const toolOutputTexts: string[] = [];

    const cmdCount = rng.int(1, Math.min(phase.commands.length, rng.int(2, 5)));
    const filteredCommands = phase.commands.filter(c => !c.startsWith("#") && c.trim() !== "");
    const selectedCmds = rng.pickN(filteredCommands.length > 0 ? filteredCommands : [`slither ${profile.contractName}.sol`], Math.min(cmdCount, filteredCommands.length || 1));

    for (let cmdIdx = 0; cmdIdx < selectedCmds.length; cmdIdx++) {
      let cmd = variateText(selectedCmds[cmdIdx], protocolName, profile as any);
      // Add random flags/variations to commands
      if (rng.bool(0.3) && cmd.includes("slither")) {
        cmd += rng.pick([" --exclude-informational", " --triage-mode", " --filter-paths=node_modules", ` --solc-remaps @openzeppelin/=lib/openzeppelin-contracts/`]);
      }
      if (rng.bool(0.2) && cmd.includes("forge test")) {
        cmd += rng.pick([" -vvv", " --match-test Exploit", " --gas-report", ` --fork-url http://127.0.0.1:8545`]);
      }
      if (rng.bool(0.2) && cmd.includes("cast call")) {
        cmd += rng.pick([` --rpc-url https://${rng.pick(["eth", "arb", "opt"])}.llamarpc.com`, " --legacy", ` --block ${rng.int(19000000, 21000000)}`]);
      }

      const toolCallId = `call_${entryIndex}_${phaseIdx}_${cmdIdx}_${rng.int(10000, 99999)}`;
      const toolName = identifyToolFromCommand(cmd);
      if (toolName) toolsUsed.push(toolName);

      toolCalls.push({
        id: toolCallId,
        name: toolName || "bash",
        arguments: { command: cmd },
      });

      let output: string;
      if (isFailurePhase) {
        output = outputEngine.generateCompileError(profile);
        hasFailures = true;
      } else if (isSoftFail && cmdIdx === 0) {
        output = outputEngine.generateSlitherFalsePositive(profile);
      } else {
        output = generateDynamicOutput(outputEngine, toolName || "bash", profile, phase, rng);
      }

      toolOutputTexts.push(output.slice(0, 200));
      toolResults.push({ tool_call_id: toolCallId, name: toolName || "bash", output });
    }

    lastToolOutputSummary = toolOutputTexts.join(" | ").slice(0, 300);

    // Generate thinking block
    let thinkingBlock: string | undefined;
    if (includeThinking) {
      if (isFailurePhase) {
        thinkingBlock = thinkingEngineInstance.generateFailureThinking(
          rng.pick(["VM revert: AccessControl: account is missing role", "compilation failed: unresolved import", "fuzz test timed out after 300s", "invariant violated: unexpected revert", "gas estimation failed: out of gas"]),
          profile
        );
      } else if (phaseIdx === 0) {
        thinkingBlock = thinkingEngineInstance.generateCodeReviewThinking(profile);
      } else if (phase.phase.toLowerCase().includes("static") || phase.phase.toLowerCase().includes("analysis")) {
        thinkingBlock = thinkingEngineInstance.generateStaticAnalysisThinking(profile);
      } else if (phase.phase.toLowerCase().includes("hypothesis") || phase.phase.toLowerCase().includes("verify")) {
        thinkingBlock = thinkingEngineInstance.generateHypothesisThinking(profile);
      } else if (phase.phase.toLowerCase().includes("exploit") || phase.phase.toLowerCase().includes("poc")) {
        thinkingBlock = thinkingEngineInstance.generatePoCThinking(profile);
      } else if (phase.phase.toLowerCase().includes("impact")) {
        thinkingBlock = thinkingEngineInstance.generateImpactThinking(profile);
      } else {
        thinkingBlock = thinkingEngineInstance.generateHypothesisThinking(profile);
      }
    }

    // Generate assistant response
    const assistantResponse = generateGroundedResponse(
      rng,
      phase,
      profile,
      isFailurePhase || isSoftFail,
      lastToolOutputSummary,
      includeThinking
    );

    messages.push({
      from: "gpt",
      value: assistantResponse,
      thinking: thinkingBlock,
      tool_calls: toolCalls.length > 0 ? toolCalls : undefined,
    });

    // Tool results as separate message
    if (toolResults.length > 0) {
      if (rng.bool(0.3) && messages.length >= 2) {
        const gptMsg = messages.pop()!;
        messages.push({
          from: "tool",
          value: toolResults.map(r => `[${r.name}] Output:\n${r.output}`).join("\n\n---\n\n"),
          tool_results: toolResults,
        });
        messages.push(gptMsg);
      } else {
        messages.push({
          from: "tool",
          value: toolResults.map(r => `[${r.name}] Output:\n${r.output}`).join("\n\n---\n\n"),
          tool_results: toolResults,
        });
      }
    }

    // Contextual user follow-ups
    if (phaseIdx < phases.length - 1) {
      const nextPhase = phases[phaseIdx + 1];
      let followUp: string;

      if (isFailurePhase || isSoftFail) {
        followUp = rng.bool(0.4)
          ? rng.pick(USER_PROMPTS_EVASION)
              .replace(/\{vulnType\}/g, profile.vulnType)
              .replace(/\{missingCheck\}/g, profile.missingCheck)
              .replace(/\{contract\}/g, profile.contractName)
              .replace(/\{function\}/g, profile.affectedFunction.replace("()", ""))
          : rng.pick(USER_PROMPTS_FAILURE_FOLLOWUP)
              .replace(/\{vulnType\}/g, profile.vulnType)
              .replace(/\{contract\}/g, profile.contractName)
              .replace(/\{function\}/g, profile.affectedFunction.replace("()", ""));
      } else if (nextPhase.phase.toLowerCase().includes("exploit") || nextPhase.phase.toLowerCase().includes("poc")) {
        followUp = rng.pick(USER_PROMPTS_EXPLOIT)
          .replace(/\{vulnType\}/g, profile.vulnType)
          .replace(/\{contract\}/g, profile.contractName)
          .replace(/\{function\}/g, profile.affectedFunction.replace("()", ""));
      } else if (nextPhase.phase.toLowerCase().includes("report")) {
        followUp = rng.pick(USER_PROMPTS_REPORT)
          .replace(/\{vulnType\}/g, profile.vulnType)
          .replace(/\{contract\}/g, profile.contractName)
          .replace(/\{function\}/g, profile.affectedFunction.replace("()", ""));
      } else {
        followUp = rng.pick(USER_PROMPTS_VULN_TESTING)
          .replace(/\{vulnType\}/g, profile.vulnType)
          .replace(/\{contract\}/g, profile.contractName)
          .replace(/\{function\}/g, profile.affectedFunction.replace("()", ""));
      }

      messages.push({ from: "human", value: followUp });
    }
  }

  // Final reporting turn
  messages.push({
    from: "human",
    value: rng.pick(USER_PROMPTS_REPORT)
      .replace(/\{vulnType\}/g, profile.vulnType)
      .replace(/\{contract\}/g, profile.contractName)
      .replace(/\{function\}/g, profile.affectedFunction.replace("()", "")),
  });

  const reportThinking = includeThinking
    ? thinkingEngineInstance.generateReportThinking(profile)
    : undefined;

  messages.push({
    from: "gpt",
    value: generateUniqueAuditReport(scenario, profile, rng),
    thinking: reportThinking,
  });

  // Pad to minimum turns with deep analysis
  while (countTurns(messages) < config.minTurns) {
    const deepPrompt = rng.pick(USER_PROMPTS_DEEP_ANALYSIS)
      .replace(/\{function\}/g, profile.affectedFunction.replace("()", ""))
      .replace(/\{contract\}/g, profile.contractName)
      .replace(/\{vulnType\}/g, profile.vulnType);

    messages.push({ from: "human", value: deepPrompt });

    const addlThinking = includeThinking
      ? thinkingEngineInstance.generateImpactThinking(profile)
      : undefined;

    messages.push({
      from: "gpt",
      value: generateDeepAnalysis(profile, rng),
      thinking: addlThinking,
    });
  }

  // Post-process for Qwen compatibility
  const finalMessages = postProcessForQwen(messages, config);

  return {
    id: `pentesterflow-${scenario.id}-${rng.int(100000, 999999)}-${entryIndex}`,
    conversations: finalMessages,
    metadata: {
      scenario_id: scenario.id,
      category: scenario.category,
      subcategory: scenario.subcategory,
      difficulty: scenario.difficulty,
      tags: scenario.tags,
      tools_used: Array.from(new Set(toolsUsed)),
      has_thinking: includeThinking,
      has_failures: hasFailures,
      turn_count: countTurns(finalMessages),
      cve_references: scenario.cve_references || [],
      estimated_tokens: estimateTokens(finalMessages),
      generated_at: new Date().toISOString(),
    },
  };
}
