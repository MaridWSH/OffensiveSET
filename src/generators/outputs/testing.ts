// Dynamic output generators for testing tools (Forge test and Echidna)

import type { OutputContext, ContractProfile } from "./helpers.js";

// ============================================================
// Forge Test Output Generator
// ============================================================

interface ForgeTestCase {
  name: string;
  pass: boolean;
  gas: number;
  logs?: string[];
}

function generateForgeTestName(ctx: OutputContext, profile: ContractProfile, isPoc: boolean): string {
  if (isPoc) {
    const vulnSnippets = [
      `POC_${capitalize(profile.vulnType.replace(/-/g, "_"))}`,
      `test_Unauthorized_${profile.affectedFunction.replace("()", "")}`,
      `test_Exploit_${profile.vulnType.replace(/-/g, "")}`,
      `test_Reproduce_${profile.impactType.replace(/\s+/g, "")}`,
      `test_${capitalize(profile.vulnType.replace(/-/g, "_"))}_Vulnerability`,
    ];
    return ctx.rng.pick(vulnSnippets);
  }

  const negativeNames = [
    `test_RevertWhen_Paused`,
    `test_RevertWhen_InvalidInput`,
    `test_RevertWhen_Unauthorized`,
    `test_RevertWhen_InsufficientBalance`,
    `test_RevertWhen_ZeroAmount`,
    `test_RevertWhen_DeadlinePassed`,
  ];
  const positiveNames = [
    `test_${capitalize(ctx.rng.pick(profile.externalFunctions).name)}_Succeeds`,
    `test_StateUpdate_After${capitalize(ctx.rng.pick(profile.externalFunctions).name)}`,
    `test_Emit${ctx.rng.pick(profile.events)}`,
    `test_GasUsage_${capitalize(ctx.rng.pick(profile.externalFunctions).name)}`,
    `test_Initialization`,
    `test_OwnerPrivileges`,
    `test_Setter_UpdateState`,
  ];

  return ctx.rng.pick([...negativeNames, ...positiveNames]);
}

function capitalize(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

function generateForgeLogs(ctx: OutputContext, profile: ContractProfile): string[] {
  const affectedFunc = profile.affectedFunction.replace("()", "");
  const token = profile.affectedToken;
  const contractName = profile.contractName;

  const beforeValues = [
    `Before attack: ${ctx.rng.pick(["balance", "voting power", "staking amount", "reward index", "allowance"])} = ${ctx.rng.int(100, 10000)}`,
    `Initial ${token} balance: ${ctx.rng.int(100, 50000)}`,
    `Pre-exploit state: ${ctx.rng.pick(["epoch", "totalSupply", "lockedAmount"])} = ${ctx.rng.int(1, 5000)}`,
    `Before ${affectedFunc}(): attacker ${ctx.rng.pick(["balance", "allowance", "delegated amount"])} = ${ctx.rng.int(10, 1000)}`,
  ];

  const duringValues = [
    `Calling ${affectedFunc}() with params: {amount: ${ctx.rng.int(1000, 1000000)}, target: attacker}`,
    `Executing exploit via ${ctx.rng.pick(["reentrant call", "flash loan", "delegate call", "cross-chain replay", "manipulated oracle read"])}`,
    `Step ${ctx.rng.int(1, 3)}/3: ${ctx.rng.pick(["borrowing via flash loan", "manipulating price feed", "delegating voting power", "triggering overflow"])}`,
  ];

  const afterValues = [
    `After attack: ${ctx.rng.pick(["balance", "voting power", "staking amount", "reward index"])} = ${ctx.rng.int(10000, 1000000)}`,
    `${token} balance increased from ${ctx.rng.int(100, 1000)} to ${ctx.rng.int(50000, 500000)}`,
    `Profit: ${ctx.rng.pick(["$", ctx.rng.int(10, 500) + " " + token])} extracted`,
    `Post-exploit state: ${ctx.rng.pick(["totalSupply", "contract balance", "attacker balance"])} = ${ctx.rng.int(100000, 9999999)}`,
    `Attack successful: attacker gained ${ctx.rng.pick(["unlimited minting", "governance control", "fund access", "privileged role"])}`,
    `Invariant violated: ${ctx.rng.pick(["totalSupply > maxSupply", "balance[attacker] > totalLocked", "votingPower[attacker] > threshold", "rewardIndex overflowed"])}`,
  ];

  return [ctx.rng.pick(beforeValues), ctx.rng.pick(duringValues), ctx.rng.pick(afterValues)];
}

function generateForgeTestCases(ctx: OutputContext, profile: ContractProfile): ForgeTestCase[] {
  const totalTests = ctx.rng.int(3, 6);
  const cases: ForgeTestCase[] = [];

  // Always include the PoC test as PASS
  cases.push({
    name: generateForgeTestName(ctx, profile, true),
    pass: true,
    gas: ctx.rng.int(150000, 800000),
    logs: generateForgeLogs(ctx, profile),
  });

  // Generate remaining tests
  for (let i = 1; i < totalTests; i++) {
    const isPass = ctx.rng.bool(0.85);
    const testName = generateForgeTestName(ctx, profile, false);
    const gas = ctx.rng.int(20000, 500000);

    const testLogs: string[] = [];
    if (!isPass) {
      testLogs.push(`Error: ${ctx.rng.pick([
        "revert: Pausable: paused",
        "revert: Ownable: caller is not the owner",
        "revert: AccessControl: account is missing role",
        "revert: insufficient balance",
        "revert: deadline expired",
        "revert: zero address",
        "revert: amount must be greater than zero",
      ])}`);
    }

    cases.push({
      name: testName,
      pass: isPass,
      gas,
      logs: testLogs.length > 0 ? testLogs : undefined,
    });
  }

  return cases;
}

export function generateForgeTestOutput(ctx: OutputContext, profile: ContractProfile): string {
  const testCases = generateForgeTestCases(ctx, profile);
  const contractName = profile.contractName;
  const testName = `${contractName}Test`;
  const testFile = `test/${contractName}.t.sol:${testName}`;

  const passed = testCases.filter((t) => t.pass).length;
  const failed = testCases.filter((t) => !t.pass).length;
  const duration = (ctx.rng.float(0.1, 2.5)).toFixed(2);

  let output = "";

  // Header
  output += `Running ${testCases.length} tests for ${testFile}\n`;

  // Test results
  for (const tc of testCases) {
    const status = tc.pass ? "PASS" : "FAIL";
    output += `[${status}] ${tc.name}() (gas: ${tc.gas})\n`;

    if (tc.logs && tc.logs.length > 0) {
      output += `Logs:\n`;
      for (const log of tc.logs) {
        output += `  ${log}\n`;
      }
    }
  }

  // Summary
  if (failed === 0) {
    output += `\nTest result: ok. ${passed} passed; 0 failed; 0 skipped; finished in ${duration}s\n`;
  } else {
    output += `\nTest result: FAILED. ${passed} passed; ${failed} failed; 0 skipped; finished in ${duration}s\n`;
    output += `Failing tests:\n`;
    for (const tc of testCases) {
      if (!tc.pass) {
        output += `  FAIL ${tc.name}()\n`;
      }
    }
  }

  // Traces section (sometimes include)
  if (ctx.rng.bool(0.6)) {
    output += `\nSuite result: ok. ${passed} passed; ${failed} failed; 0 skipped\n`;
    output += `Ran ${testCases.length} test suites in ${duration}s (${duration}s CPU time): ${passed} passed; ${failed} failed\n`;
  }

  // Fork config info (if requiresFork)
  if (profile.requiresFork) {
    const chainNames: Record<number, string> = {
      1: "Ethereum",
      42161: "Arbitrum",
      10: "Optimism",
      8453: "Base",
      137: "Polygon",
      56: "BNB Chain",
    };
    const chainName = chainNames[profile.chainId] || "Ethereum";
    output += `\nFork mode: enabled (chain: ${chainName}, block: ${ctx.generateBlockNumber()})\n`;
  }

  return output.trimEnd();
}

// ============================================================
// Echidna Output Generator
// ============================================================

interface EchidnaProperty {
  name: string;
  status: "PASSED" | "BROKEN";
  calls?: string[];
  shrinkInfo?: string;
}

function generateEchidnaPropertyName(ctx: OutputContext, profile: ContractProfile, isBroken: boolean): string {
  if (isBroken) {
    const brokenSnippets = [
      `echidna_${profile.vulnType.replace(/-/g, "_")}_invariant`,
      `echidna_no_unauthorized_${profile.affectedFunction.replace("()", "")}`,
      `echidna_balance_invariant_${profile.affectedToken.toLowerCase()}`,
      `echidna_${profile.impactType.replace(/\s+/g, "_")}_prevention`,
      `echidna_totalSupply_bounded`,
      `echidna_access_control_${ctx.rng.pick(profile.externalFunctions).name}`,
      `echidna_state_consistency_after_${profile.affectedFunction.replace("()", "")}`,
    ];
    return ctx.rng.pick(brokenSnippets);
  }

  const passingNames = [
    `echidna_reentrancy_guard`,
    `echidna_owner_never_zero`,
    `echidna_pause_state_valid`,
    `echidna_no_self_transfer`,
    `echidna_max_supply_not_exceeded`,
    `echidna_ownership_not_lost`,
    `echidna_balances_sum_constant`,
    `echidna_initialized_flag_set`,
    `echidna_fee_rate_bounded`,
    `echidna_no_double_claim`,
    `echidna_epoch_monotonic`,
    `echidna_withdrawal_limit`,
  ];
  return ctx.rng.pick(passingNames);
}

function generateShrinkInfo(ctx: OutputContext, profile: ContractProfile): string {
  const affectedFunc = profile.affectedFunction.replace("()", "");
  const funcNames = profile.externalFunctions.map((f) => f.name);

  const shrinkSteps = ctx.rng.int(3, 12);
  const originalCalls = ctx.rng.int(20, 100);

  let info = `Shrunk: ${originalCalls} calls -> ${shrinkSteps} calls\n`;
  info += `Shrunk call sequence:\n`;

  const callSeq: string[] = [];

  // Setup calls
  const setupCalls = [
    `vm.prank(attacker)`,
    `vm.deal(attacker, ${ctx.rng.int(1, 100)} ether)`,
    `${ctx.rng.pick(funcNames)}(${ctx.rng.pick(["0", "1", ctx.rng.int(100, 10000).toString()])})`,
    `increaseTime(${ctx.rng.int(3600, 86400)})`,
  ];

  for (let i = 0; i < shrinkSteps - 1; i++) {
    callSeq.push(ctx.rng.pick(setupCalls));
  }

  // Final call is the exploit
  const exploitCall = `${affectedFunc}(${profile.externalFunctions.length > 0 ? ctx.rng.pick(profile.externalFunctions).params.map(() => ctx.rng.pick(["0", "1", "1000000", "attacker"])).join(", ") : ""})`;
  callSeq.push(exploitCall);

  for (let i = 0; i < callSeq.length; i++) {
    info += `  ${i + 1}. ${callSeq[i]}\n`;
  }

  return info;
}

export function generateEchidnaOutput(ctx: OutputContext, profile: ContractProfile): string {
  const contractName = profile.contractName;
  const properties: EchidnaProperty[] = [];
  const totalProps = ctx.rng.int(3, 6);

  // Decide which property will be broken (at least 1)
  const brokenCount = ctx.rng.int(1, Math.min(2, totalProps));
  const brokenIndices: Set<number> = new Set();
  while (brokenIndices.size < brokenCount) {
    brokenIndices.add(ctx.rng.int(0, totalProps - 1));
  }

  // Generate properties
  for (let i = 0; i < totalProps; i++) {
    const isBroken = brokenIndices.has(i);
    const prop: EchidnaProperty = {
      name: generateEchidnaPropertyName(ctx, profile, isBroken),
      status: isBroken ? "BROKEN" : "PASSED",
    };

    if (isBroken) {
      prop.shrinkInfo = generateShrinkInfo(ctx, profile);
    }

    properties.push(prop);
  }

  // Build output
  const mode = ctx.rng.pick(["property", "assertion", "overflow", "exploration", "diff"]);
  const seed = ctx.rng.int(0, 2 ** 31 - 1);
  const testCount = ctx.rng.int(50000, 500000);
  const elapsed = ctx.rng.float(5, 120).toFixed(1);
  const coverageFuncs = ctx.rng.int(40, 95);
  const coverageLines = ctx.rng.float(55, 92).toFixed(1);
  const coverageBranches = ctx.rng.float(30, 80).toFixed(1);

  let output = "";

  // Header
  output += `Echidna ${ctx.rng.pick(["v2.2.5", "v2.2.4", "v2.3.0", "v2.2.6"])}\n`;
  output += `Target contract: ${contractName}\n`;
  output += `Mode: ${mode}\n`;
  output += `Seed: ${seed}\n`;
  output += `Random testing\n`;
  output += `${"=".repeat(60)}\n`;

  // Properties
  output += `\nProperties tested:\n`;
  for (const prop of properties) {
    const icon = prop.status === "PASSED" ? "[PASS]" : "[FAIL]";
    output += `  ${icon} ${prop.name}`;
    if (prop.status === "BROKEN") {
      output += `\n  ${"─".repeat(58)}\n`;
      output += `  Call sequence that broke the property:\n`;
      if (prop.shrinkInfo) {
        output += `  ${prop.shrinkInfo.replace(/\n/g, "\n  ")}\n`;
      }
      output += `  ${"─".repeat(58)}\n`;
    } else {
      output += "\n";
    }
  }

  // Summary
  const passed = properties.filter((p) => p.status === "PASSED").length;
  const broken = properties.filter((p) => p.status === "BROKEN").length;

  output += `\n${"=".repeat(60)}\n`;
  output += `Results: ${passed}/${totalProps} passed, ${broken}/${totalProps} failed\n`;

  if (broken > 0) {
    output += `\n⚠ ${broken} property(ies) FAILED:\n`;
    for (const prop of properties) {
      if (prop.status === "BROKEN") {
        output += `  - ${prop.name}\n`;
      }
    }
  }

  // Coverage
  output += `\nCoverage:\n`;
  output += `  Functions: ${coverageFuncs}/${ctx.rng.int(50, 120)} (${((coverageFuncs / ctx.rng.int(50, 120)) * 100).toFixed(1)}%)\n`;
  output += `  Lines: ${coverageLines}%\n`;
  output += `  Branches: ${coverageBranches}%\n`;

  // Stats
  output += `\nStatistics:\n`;
  output += `  Total tests: ${testCount.toLocaleString()}\n`;
  output += `  Elapsed: ${elapsed}s\n`;
  output += `  Tests/sec: ${(testCount / parseFloat(elapsed)).toFixed(0).replace(/\B(?=(\d{3})+(?!\d))/g, ",")}\n`;
  output += `  Gas limit: ${ctx.rng.int(10000000, 30000000).toLocaleString()}\n`;
  output += `  Max block gas: ${ctx.rng.pick([30000000, 60000000, 50000000])}\n`;

  // Vuln context
  output += `\nVulnerability context:\n`;
  output += `  Affected function: ${profile.affectedFunction}\n`;
  output += `  Vulnerability type: ${profile.vulnType}\n`;
  output += `  Impact: ${profile.impactType}\n`;

  // Contract info
  if (ctx.rng.bool(0.5)) {
    output += `\nDeployment:\n`;
    output += `  Chain: ${profile.chainId}\n`;
    output += `  Contract: ${profile.contractAddress}\n`;
    output += `  Solidity: ${profile.solidityVersion}\n`;
  }

  return output.trimEnd();
}
