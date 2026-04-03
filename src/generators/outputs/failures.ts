import type { OutputContext, ContractProfile } from "./helpers.js";

// ============================================================
// Compile Error Templates
// ============================================================

const COMPILE_ERROR_TEMPLATES = {
  DeclarationError: [
    (profile: ContractProfile, func: string, ident: string, version: string) =>
      `CompilerError: DeclarationError: Identifier "${ident}" not found or not visible after function "${func}" in ${profile.contractName}.sol:${Math.floor(Math.random() * 200 + 50)}:${Math.floor(Math.random() * 20 + 5)}
  --> ${profile.contractName}.sol
   |
${Math.floor(Math.random() * 50 + 50)} |         ${ident}.transfer(msg.sender, amount);
   |         ^^^^^${".".repeat(ident.length - 1)}\n`,
    (profile: ContractProfile, func: string, ident: string, version: string) =>
      `DeclarationError: Undeclared identifier. Did you mean "${ident}_"?
  --> ${profile.contractName}.sol:${Math.floor(Math.random() * 150 + 80)}:${Math.floor(Math.random() * 30 + 10)}
   |
${Math.floor(Math.random() * 80 + 80)} |             uint256 result = ${ident}.balanceOf(address(this));
   |                                ^^^^^\n`,
    (profile: ContractProfile, func: string, ident: string, version: string) =>
      `ParserError: Undeclared identifier "${ident}".
  --> ${profile.contractName}.sol
   |
${Math.floor(Math.random() * 100 + 100)} |         require(${ident}.isWhitelisted(msg.sender), "not whitelisted");
   |                 ^^^^^\n`,
  ],
  TypeError: [
    (profile: ContractProfile, func: string, ident: string, version: string) =>
      `TypeError: Member "${ident}" not found or not visible after function "${func}" in ${profile.contractName}.sol:${Math.floor(Math.random() * 200 + 30)}:${Math.floor(Math.random() * 25 + 5)}
  --> ${profile.contractName}.sol
   |
${Math.floor(Math.random() * 80 + 60)} |         ${profile.contractName}.${ident}(_amount);
   |         ^^^^^^^^^^^^^^^^^^^^^^^^\n`,
    (profile: ContractProfile, func: string, ident: string, version: string) =>
      `TypeError: Invalid type for argument in function call. Invalid implicit conversion from uint256 to int256 requested.
  --> ${profile.contractName}.sol:${Math.floor(Math.random() * 180 + 40)}:${Math.floor(Math.random() * 40 + 5)}
   |
${Math.floor(Math.random() * 90 + 70)} |             _updateBalance(${profile.stateVariables[0]?.name || "balance"}, total - ${ident});
   |                             ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n`,
    (profile: ContractProfile, func: string, ident: string, version: string) =>
      `TypeError: Operator - not compatible with types uint256 and mapping(address => uint256)
  --> ${profile.contractName}.sol:${Math.floor(Math.random() * 200 + 20)}:${Math.floor(Math.random() * 30 + 10)}
   |
${Math.floor(Math.random() * 100 + 50)} |         uint256 remaining = ${profile.stateVariables[0]?.name || "totalSupply"} - ${profile.stateVariables[1]?.name || "balances"};
   |                             ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n`,
  ],
  ParserError: [
    (profile: ContractProfile, func: string, ident: string, version: string) =>
      `ParserError: Expected primary expression name but got 'function'
  --> ${profile.contractName}.sol:${Math.floor(Math.random() * 200 + 60)}:${Math.floor(Math.random() * 20 + 5)}
   |
${Math.floor(Math.random() * 80 + 90)} |         function ${func}(uint256 _amount) external nonReentrant {
   |         ^^^^^^^^\n`,
    (profile: ContractProfile, func: string, ident: string, version: string) =>
      `ParserError: Expected ';' but got '{'
  --> ${profile.contractName}.sol:${Math.floor(Math.random() * 150 + 40)}:${Math.floor(Math.random() * 35 + 10)}
   |
${Math.floor(Math.random() * 70 + 80)} |             emit ${profile.events[0] || "Transfer"}(msg.sender, address(this), amount)
   |                                                                                    ^\n`,
  ],
  TypeErrorArithmetic: [
    (profile: ContractProfile, func: string, ident: string, version: string) =>
      `TypeError: Operator * not compatible with types uint256 and bytes memory
  --> ${profile.contractName}.sol:${Math.floor(Math.random() * 180 + 30)}:${Math.floor(Math.random() * 30 + 5)}
   |
${Math.floor(Math.random() * 90 + 50)} |         uint256 fee = _amount * abi.encodePacked(${ident});
   |                       ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n`,
    (profile: ContractProfile, func: string, ident: string, version: string) =>
      `TypeError: Unary operator - cannot be applied to type uint256
  --> ${profile.contractName}.sol:${Math.floor(Math.random() * 160 + 50)}:${Math.floor(Math.random() * 25 + 8)}
   |
${Math.floor(Math.random() * 80 + 70)} |         int256 delta = -${profile.stateVariables[0]?.name || "totalSupply"};
   |                        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n`,
  ],
};

// ============================================================
// Test Failure Templates
// ============================================================

const TEST_FAILURE_TEMPLATES = [
  (profile: ContractProfile, ctx: OutputContext) => {
    const amount = ctx.rng.int(1, 1000);
    return `Running 1 test for test_${profile.vulnType.replace(/-/g, "_")}_should_revert
[FAIL: revert] test_${profile.vulnType.replace(/-/g, "_")}_should_revert() (gas: ${ctx.rng.int(150000, 800000)})
Traces:
  [${ctx.rng.int(50000, 500000)}] ${profile.contractName}::${profile.affectedFunction.replace("()", "")}(${amount})
    ├─ [0] VM::expectRevert()
    │   └─ ← [Return] 0x
    └─ ← [Revert] vm::expectRevert did not revert

Failure reason: Expected revert but execution succeeded.
The call to \`${profile.affectedFunction}\` with amount \`${amount}\` was expected to revert due to missing ${profile.missingCheck}, but it completed successfully.

Logs:
  ${profile.affectedToken} balance before: ${ctx.rng.int(1000, 999999)}
  ${profile.affectedToken} balance after:  ${ctx.rng.int(1000000, 99999999)}
  Profit: ${ctx.rng.int(100000, 9999999)} wei

Test result: FAILED. 0 passed; 1 failed; 0 skipped
`;
  },
  (profile: ContractProfile, ctx: OutputContext) => {
    const attacker = `0x${ctx.generateHex(40)}`;
    const expectedRevert = ctx.rng.pick(["Ownable: caller is not the owner", "AccessControl: missing role", "Pausable: paused", "ReentrancyGuard: reentrant call"]);
    return `Running 1 test for test_unauthorized_access_in_${profile.affectedFunction.replace("()", "")}
[FAIL: != expected revert] test_unauthorized_access() (gas: ${ctx.rng.int(200000, 600000)})
Traces:
  [${ctx.rng.int(100000, 400000)}] ${profile.contractName}::${profile.affectedFunction.replace("()", "")}(0x${ctx.generateHex(64)})
    ├─ [0] VM::expectRevert("${expectedRevert}")
    │   └─ ← [Return] 0x
    └─ ← [Revert] EvmError: Revert

Failure: \`expectRevert\` expected revert reason "${expectedRevert}" but got different revert data.
Expected: ${expectedRevert}
Actual:   (empty revert data)

The unauthorized call from \`${attacker}\` to \`${profile.affectedFunction}\` reverted but without the expected error message.

Test result: FAILED. 0 passed; 1 failed; 0 skipped
`;
  },
  (profile: ContractProfile, ctx: OutputContext) => {
    const balanceBefore = ctx.rng.int(100, 50000);
    const balanceAfter = ctx.rng.int(balanceBefore + 1000, balanceBefore + 1000000);
    return `Running 1 test for test_invariant_${profile.vulnType.replace(/-/g, "_")}_balance_never_decreases
[FAIL: assertion failed] test_invariant_balance() (runs: ${ctx.rng.int(256, 4096)}, calls: ${ctx.rng.int(50000, 200000)})
Traces:
  [${ctx.rng.int(50000, 300000)}] ${profile.contractName}::${profile.affectedFunction.replace("()", "")}()
    └─ ← [Return] 0x

Failure: assertion \`balances[attacker] >= 0\` violated
  counterexample:
    attacker: 0x${ctx.generateHex(40)}
    initial_balance: ${balanceBefore}
    final_balance: ${balanceAfter}
    delta: +${balanceAfter - balanceBefore}

The invariant \`${profile.contractName}.totalSupply() >= sum(all balances)\` was violated after ${ctx.rng.int(10, 200)} calls.
${profile.impactType} detected — protocol solvency compromised.

Test result: FAILED. 0 passed; 1 failed; 0 skipped
`;
  },
  (profile: ContractProfile, ctx: OutputContext) => {
    return `Running 1 test for test_fork_${profile.protocolName.toLowerCase().replace(/\s+/g, "_")}_${profile.vulnType.replace(/-/g, "_")}
[FAIL] test_fork_exploit() (gas: ${ctx.rng.int(500000, 2000000)})
Traces:
  [${ctx.rng.int(300000, 1500000)}] ${profile.contractName}::${profile.affectedFunction.replace("()", "")}()
    ├─ emit ${profile.events[0] || "Transfer"}(0x${ctx.generateHex(40)}, 0x${ctx.generateHex(40)}, ${ctx.rng.int(1e15, 1e20)})
    └─ ← [Return] 0x

Failure: State after fork differs from expected.
  Expected protocol TVL: ${profile.tvl}
  Actual protocol TVL: $${ctx.rng.int(0, 100000).toLocaleString()}
  Funds drained: ${ctx.rng.int(1, 99)}% of ${profile.affectedToken} reserves

The fork test on chain ${profile.chainId} confirms the ${profile.vulnType} vulnerability is exploitable in production.
${profile.affectedFunction} allows ${profile.impactType} without ${profile.missingCheck}.

Test result: FAILED. 0 passed; 1 failed; 0 skipped
`;
  },
];

// ============================================================
// Slither False Positive Templates
// ============================================================

const SLITHER_FALSE_POSITIVE_TEMPLATES = [
  (profile: ContractProfile, ctx: OutputContext) => {
    const detector = ctx.rng.pick([
      "reentrancy-eth", "reentrancy-no-eth", "arbitrary-send-erc20",
      "unchecked-transfer", "incorrect-equality", "timestamp",
      "divide-before-multiply", "low-level-calls", "unchecked-send",
    ]);
    const confidence = ctx.rng.pick(["High", "Medium"]);
    const impact = ctx.rng.pick(["High", "Medium", "Low"]);
    return `INFO:Detectors:
Reentrancy in ${profile.contractName}.${profile.affectedFunction.replace("()", "")} (${profile.contractName}.sol:${ctx.rng.int(50, 300)}):
\tExternal call: ${profile.dependencies[0] || "IERC20"}.transfer(msg.sender, amount) (${profile.contractName}.sol:${ctx.rng.int(50, 300)})
\tState variables written after external call:
\t- ${profile.stateVariables[0]?.name || "balances"} (${profile.contractName}.sol:${ctx.rng.int(60, 310)})

${detector} (${confidence}, ${impact}) allows attackers to:
  - Re-enter the contract before state is updated
  - Drain funds via recursive calls to ${profile.affectedFunction}

Reference: https://github.com/crytic/slither/wiki/Detector-Documentation#${detector}
`;
  },
  (profile: ContractProfile, ctx: OutputContext) => {
    const detector = ctx.rng.pick([
      "reentrancy-eth", "reentrancy-no-eth", "reentrancy-benign",
      "reentrancy-events", "reentrancy-unlimited-gas",
    ]);
    return `INFO:Detectors:
Reentrancy in ${profile.contractName}.${profile.affectedFunction.replace("()", "")} (${profile.contractName}.sol):
\tExternal call: ${profile.stateVariables[0]?.name || "stakingToken"}.transferFrom(msg.sender, address(this), _amount)
\tState variables written after call:
\t- ${profile.stateVariables[1]?.name || "totalStaked"} (${profile.contractName}.sol:${ctx.rng.int(80, 250)})

${detector} (High, High) detected in ${profile.protocolName}'s ${profile.contractName}.
Potential reentrancy via ${profile.affectedFunction} — state updated after external call.

Reference: https://github.com/crytic/slither/wiki/Detector-Documentation#${detector}
`;
  },
];

// ============================================================
// Public API
// ============================================================

export function generateCompileError(ctx: OutputContext, profile: ContractProfile): string {
  const errorCategory = ctx.rng.pick(Object.keys(COMPILE_ERROR_TEMPLATES) as Array<keyof typeof COMPILE_ERROR_TEMPLATES>);
  const templates = COMPILE_ERROR_TEMPLATES[errorCategory];
  const template = ctx.rng.pick(templates);
  const ident = ctx.rng.pick([
    "safeTransfer", "balanceOf", "totalSupply", "permit",
    "flashLoan", "swap", "mint", "burn", "withdraw",
    "_updateReward", "_claimRewards", "bridgeTokens",
  ]);

  return `Error: Compilation failed for ${profile.contractName}.sol (Solidity ${profile.solidityVersion})

${template(profile, profile.affectedFunction.replace("()", ""), ident, profile.solidityVersion)}
Compiled with ${profile.solidityVersion}+commit on ${ctx.generateDate()}.
Contract: ${profile.contractName} (inherited from [${profile.inheritanceChain.join(", ")}])
Affected function: ${profile.affectedFunction}
`;
}

export function generateTestFailure(ctx: OutputContext, profile: ContractProfile): string {
  const template = ctx.rng.pick(TEST_FAILURE_TEMPLATES);
  return template(profile, ctx);
}

export function generateSlitherFalsePositive(ctx: OutputContext, profile: ContractProfile): string {
  const template = ctx.rng.pick(SLITHER_FALSE_POSITIVE_TEMPLATES);
  const slitherOutput = template(profile, ctx);

  return `${slitherOutput}
${"=".repeat(80)}
AUDITOR ANALYSIS: False Positive Dismissed
${"=".repeat(80)}

Finding: Slither ${ctx.rng.pick(["reentrancy-eth", "reentrancy-no-eth", "unchecked-transfer", "arbitrary-send-erc20"])} flagged in ${profile.contractName}::${profile.affectedFunction}
Auditor: ${ctx.generateRandomAuditor().firm}
Verdict: FALSE POSITIVE — Dismissed

Rationale:
The Slither detector flagged a potential ${ctx.rng.pick(["reentrancy", "unchecked return value", "arbitrary send"])} issue in ${profile.affectedFunction}.
However, manual review confirms this is a false positive because:

1. The external call is to a trusted ${ctx.rng.pick(["internal helper", "protocol-owned contract", "immutable dependency", "core module"])} that cannot be controlled by an attacker.
2. The state variable ${profile.stateVariables[0]?.name || "balances"} is protected by a ${profile.missingCheck} check that Slither does not model.
3. The function ${profile.affectedFunction} follows the ${ctx.rng.pick(["checks-effects-interactions", "pull-over-push", "two-step withdrawal"])} pattern correctly.
4. Even if reentrancy were possible, the ${ctx.rng.pick(["max withdrawal limit", "cooldown period", "epoch-based restrictions", "snapshot mechanism"])} prevents any meaningful exploit.

This finding was reviewed and dismissed during the ${profile.protocolName} audit by ${ctx.generateRandomAuditor().firm}.
`;
}
