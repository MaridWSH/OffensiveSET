// Smart Contract Audit Thinking Engine
// Generates unique, detailed chain-of-thought reasoning blocks
// Models real auditor cognitive process: observe -> hypothesize -> test -> analyze -> conclude

import { SeededRNG, ContractProfile } from "./outputs/index.js";

export class ThinkingEngine {
  private rng: SeededRNG;

  constructor(seed: number) {
    this.rng = new SeededRNG(seed);
  }

  // ============================================================
  // Phase-specific thinking generators
  // ============================================================

  generateCodeReviewThinking(profile: ContractProfile): string {
    const approach = this.rng.pick(CODE_REVIEW_TEMPLATES);
    return this.fillTemplate(approach, {
      contractName: profile.contractName,
      inheritance: profile.inheritanceChain.join(", "),
      solidityVersion: profile.solidityVersion,
      affectedFunction: profile.affectedFunction,
      vulnType: profile.vulnType,
      protocolName: profile.protocolName,
      missingCheck: profile.missingCheck,
      stateVarNames: profile.stateVariables.map((s) => s.name).join(", "),
      funcNames: profile.externalFunctions.map((f) => f.name + "()").join(", "),
      dependencies: profile.dependencies.join(", "),
    });
  }

  generateStaticAnalysisThinking(profile: ContractProfile): string {
    const approach = this.rng.pick(STATIC_ANALYSIS_TEMPLATES);
    return this.fillTemplate(approach, {
      contractName: profile.contractName,
      vulnType: profile.vulnType,
      affectedFunction: profile.affectedFunction,
      protocolName: profile.protocolName,
      severity: profile.severity,
      highCount: String(this.rng.int(1, 4)),
      medCount: String(this.rng.int(2, 6)),
      lowCount: String(this.rng.int(3, 8)),
      infoCount: String(this.rng.int(1, 5)),
      detectorName: this.rng.pick([
        "Arbitrary-TransferFrom",
        "Reentrancy-Events",
        "Unindexed-Event",
        "Missing-Checks",
        "Incorrect-Ordering",
        "State-Shadowing",
        "Controlled-Delegatecall",
        "Unprotected-Initializer",
        "Weak-PRNG",
        "Unchecked-Return",
        "Tx-Origin",
        "Unused-Return",
        "Missing-Indexer",
        "Deprecated-Stdlib",
        "Incorrect-Interface",
      ]),
      contractFile: profile.contractName + ".sol",
    });
  }

  generateHypothesisThinking(profile: ContractProfile): string {
    const approach = this.rng.pick(HYPOTHESIS_TEMPLATES);
    const primaryState = profile.stateVariables[0]?.name ?? "totalSupply";
    const secondaryState = profile.stateVariables[1]?.name ?? "balances";
    const primaryFunc = profile.externalFunctions[0]?.name ?? "stake";
    return this.fillTemplate(approach, {
      contractName: profile.contractName,
      affectedFunction: profile.affectedFunction,
      vulnType: profile.vulnType,
      missingCheck: profile.missingCheck,
      stateVar: primaryState,
      stateVar2: secondaryState,
      function: primaryFunc,
      protocolName: profile.protocolName,
      exploitComplexity: profile.exploitComplexity,
      inheritance: profile.inheritanceChain.join(", "),
      impactType: profile.impactType,
    });
  }

  generatePoCThinking(profile: ContractProfile): string {
    const approach = this.rng.pick(POC_TEMPLATES);
    const forkText = profile.requiresFork
      ? "needs to fork mainnet at a specific block to reproduce realistic conditions. I'll use vm.createSelectFork() with the appropriate RPC and block number"
      : "can run as a self-contained unit test. No forking needed -- I'll deploy mock dependencies";
    const capitalText = profile.requiresCapital === 0
      ? "no upfront capital -- the exploit is free to execute"
      : profile.requiresCapital < 1000
        ? `a small amount (${profile.requiresCapital} tokens) which is easily accessible`
        : `significant capital (${profile.requiresCapital} tokens), which may require flash loans or accumulated positions`;
    const pocTypeText = profile.pocType === "unit"
      ? "write a self-contained test with mock dependencies"
      : profile.pocType === "fork"
        ? "fork mainnet and test against the live protocol state"
        : profile.pocType === "fuzz"
          ? "set up fuzz handlers that try random inputs against the vulnerable function"
          : "define invariants that the protocol should always satisfy and test with Echidna";
    const complexityText = profile.exploitComplexity === "trivial"
      ? "is straightforward -- just call the function and observe"
      : profile.exploitComplexity === "moderate"
        ? "requires some state manipulation before the attack"
        : "needs a multi-step setup with flash loans, oracle manipulation, or cross-chain coordination";
    const ob = "\x7b";
    const cb = "\x7d";
    return this.fillTemplate(approach, {
      contractName: profile.contractName,
      affectedFunction: profile.affectedFunction,
      impactType: profile.impactType,
      pocType: profile.pocType,
      pocTypeText,
      vulnType: profile.vulnType,
      protocolName: profile.protocolName,
      requiresFork: profile.requiresFork ? "true" : "false",
      forkText,
      requiresCapital: String(profile.requiresCapital),
      capitalText,
      exploitComplexity: profile.exploitComplexity,
      complexityText,
      funcNames: profile.externalFunctions.map((f) => f.name + "()").join(", "),
      stateVarNames: profile.stateVariables.map((s) => s.name).join(", "),
      beforeState: this.rng.pick([
        "attacker holds zero tokens",
        "vault balance is at expected level",
        "governance proposal is in pending state",
        "price oracle returns fair market value",
        "user has deposited their normal stake",
      ]),
      afterState: this.rng.pick([
        "attacker drains the entire vault",
        "attacker mints unlimited tokens",
        "attacker passes a malicious proposal",
        "price oracle is manipulated to allow over-borrowing",
        "attacker withdraws more than they deposited",
      ]),
      foundryAssert: this.rng.pick([
        "assertEq(attacker.balance, expectedDrainAmount)",
        "assertTrue(vault.totalAssets() < attackerBalance)",
        "assertEq(token.balanceOf(attacker), mintedAmount)",
        "assertTrue(proposal.state() == ProposalState.Succeeded)",
        "assertLt(pool.getCollateralRatio(), liquidationThreshold)",
      ]),
      ob,
      cb,
    });
  }

  generateImpactThinking(profile: ContractProfile): string {
    const approach = this.rng.pick(IMPACT_TEMPLATES);
    const scopeText = profile.impactType === "fund drainage" || profile.impactType === "unlimited minting"
      ? "Changed (affects other users' assets)"
      : "Unchanged";
    const availabilityText = profile.impactType === "denial of service" ? "High" : "Low";
    const complexityDesc = profile.exploitComplexity === "trivial"
      ? "minimal technical knowledge"
      : profile.exploitComplexity === "moderate"
        ? "some DeFi experience and modest capital"
        : "significant technical skill and substantial capital, but still profitable";
    return this.fillTemplate(approach, {
      contractName: profile.contractName,
      protocolName: profile.protocolName,
      tvl: profile.tvl,
      affectedToken: profile.affectedToken,
      tokenPrice: profile.tokenPrice,
      vulnType: profile.vulnType,
      impactType: profile.impactType,
      severity: profile.severity,
      scopeText,
      availabilityText,
      complexityDesc,
      impact1: this.rng.pick([
        "drain all user deposits from the vault",
        "mint arbitrary amounts of the protocol token",
        "bypass the governance timelock and execute immediate actions",
        "liquidate healthy positions without cause",
        "redirect protocol fees to an attacker-controlled address",
      ]),
      impact2: this.rng.pick([
        "manipulate the oracle to create bad debt across the protocol",
        "steal voting power from legitimate delegators",
        "freeze all withdrawals causing a bank run scenario",
        "inflate reward distributions diluting all participants",
        "extract MEV from pending transaction ordering",
      ]),
      impact3: this.rng.pick([
        "render the protocol permanently insolvent",
        "corrupt state making recovery impossible without migration",
        "trigger cascading liquidations across integrated protocols",
        "steal admin keys through privileged function access",
        "cause permanent loss of user funds with no recourse",
      ]),
      worstCase: this.rng.pick([
        "total loss of all deposited funds (~" + profile.tvl + ")",
        "complete governance capture and protocol hijacking",
        "a death spiral of the " + profile.affectedToken + " token",
        "cross-protocol contagion affecting all integrated money legos",
        "irreversible state corruption requiring a full contract migration",
      ]),
      usersAffected: this.rng.pick([
        "all depositors and liquidity providers",
        "governance participants and delegates",
        "users with active loan positions",
        "bridgers moving assets across chains",
        "stakers earning yield through the protocol",
      ]),
    });
  }

  generateReportThinking(profile: ContractProfile): string {
    const approach = this.rng.pick(REPORT_TEMPLATES);
    return this.fillTemplate(approach, {
      contractName: profile.contractName,
      vulnType: profile.vulnType,
      affectedFunction: profile.affectedFunction,
      severity: profile.severity,
      protocolName: profile.protocolName,
      missingCheck: profile.missingCheck,
      impactType: profile.impactType,
      swcId: this.rng.pick(["SWC-107", "SWC-105", "SWC-114", "SWC-128", "SWC-123", "SWC-113", "SWC-112"]),
      cweId: this.rng.pick(["CWE-284", "CWE-693", "CWE-841", "CWE-362", "CWE-347", "CWE-670", "CWE-682", "CWE-20"]),
      cvssVector: `AV:N/AC:${this.rng.pick(["L", "H"])}/PR:${this.rng.pick(["N", "L", "H"])}/UI:${this.rng.pick(["N", "R"])}/S:${this.rng.pick(["U", "C"])}/C:${this.rng.pick(["H", "L", "N"])}/I:${this.rng.pick(["H", "L", "N"])}/A:${this.rng.pick(["H", "L", "N"])}`,
      fixDescription: this.rng.pick([
        "Add the missing modifier to restrict unauthorized access",
        "Implement the checks-effects-interactions pattern to prevent reentrancy",
        "Add input validation for the function parameters before state mutation",
        "Bind the signature to chainId and nonce to prevent replay attacks",
        "Use SafeCast and SafeMath to prevent integer overflow/underflow",
        "Add rate-limiting with a cooldown period between calls",
      ]),
    });
  }

  generateFailureThinking(finding: string, profile: ContractProfile): string {
    const approach = this.rng.pick(FAILURE_TEMPLATES);
    return this.fillTemplate(approach, {
      contractName: profile.contractName,
      affectedFunction: profile.affectedFunction,
      vulnType: profile.vulnType,
      finding,
      error: this.rng.pick([
        "VM revert: AccessControl: account is missing role",
        "VM revert: ReentrancyGuard: reentrant call",
        "VM revert: Pausable: paused",
        "VM revert: Ownable: caller is not the owner",
        "Error: execution reverted with no data",
        "VM revert: SafeERC20: low-level call failed",
        "Panic error: arithmetic underflow/overflow (0x11)",
        "VM revert: ERC20: transfer amount exceeds balance",
        "Error: call reverted without a reason string",
        "VM revert: Timelock: insufficient delay",
      ]),
      location: this.rng.pick([
        "the require statement checking msg.sender permissions",
        "the _nonReentrant modifier in the call chain",
        "the token transfer revert on insufficient balance",
        "the initializer already-executed guard",
        "the paused state check at function entry",
        "the timelock delay validation",
        "the signature replay detection mapping",
        "the cross-chain message hash validation",
      ]),
      hypothesis: this.rng.pick([
        "the vulnerability doesn't exist in this version -- the check I thought was missing is actually enforced upstream",
        "my test setup didn't correctly initialize the contract state to match the post-deployment scenario",
        "the exploit requires a specific fork condition (block timestamp, oracle price) that my unit test doesn't simulate",
        "the affected function has a modifier chain I overlooked -- one of the inherited contracts adds a guard",
        "the Solidity version (0.8+) has built-in overflow protection that prevents this particular vector",
        "the state variable I assumed was uninitialized is actually set in the constructor or initializer",
        "this is actually a false positive from the static analyzer -- the code path is unreachable in practice",
      ]),
      nextStep: this.rng.pick([
        "re-read the modifier chain and inherited contracts more carefully",
        "set up a fork test with real mainnet state to see if the condition changes",
        "trace the full external call path to find where the check actually lives",
        "test a different vulnerability class on this same function",
        "examine the deployment/initialization sequence for missed setup steps",
        "check if the finding applies to a different function in the contract",
        "move on -- this finding doesn't hold and my time is better spent elsewhere",
      ]),
    });
  }

  // ============================================================
  // Template filling
  // ============================================================

  private fillTemplate(template: string, vars: Record<string, string>): string {
    let result = template;
    for (const [key, value] of Object.entries(vars)) {
      result = result.replace(new RegExp("\\{" + key + "\\}", "g"), value);
    }
    return result;
  }
}

// ============================================================
// Thinking Templates -- Smart Contract Audit Reasoning
// ============================================================

const CODE_REVIEW_TEMPLATES = [
  `Let me start by understanding the architecture. The {contractName} contract inherits from {inheritance}, which tells me a lot about the security assumptions baked in. The protocol is {protocolName}, deployed with Solidity {solidityVersion}.

First, I'm scanning the inheritance chain for what each parent brings. {inheritance} -- so we have access control primitives and likely reentrancy protection. But inheriting ReentrancyGuard doesn't mean every function uses it. I need to check which functions actually have the nonReentrant modifier.

The key function I want to focus on is {affectedFunction}. This is where {vulnType} could manifest. Let me trace through it line by line:

1. What are the function modifiers? If {missingCheck} is not present on this function, that's the first red flag.
2. What state variables does it read and write? I see references to {stateVarNames}. I need to verify the Checks-Effects-Interactions pattern: are all state updates done BEFORE any external calls?
3. What external calls does it make? Any call to an untrusted external contract (ERC20 transfer, oracle read, cross-chain message) is a potential reentrancy entry point.
4. Are there authorization checks? If this function can change protocol state but only has a lightweight or missing access control, that's an immediate finding.

Looking at the broader contract, the external functions are: {funcNames}. I need to understand how they interact -- does one function's output become another function's trusted input? Function chaining is where subtle bugs hide.

The dependencies ({dependencies}) tell me what standards the code follows. If this uses OpenZeppelin's Ownable, I should verify the ownership model. If it uses ReentrancyGuard, I should check whether every function with external calls is protected.

My initial read: the architecture looks like it has the right building blocks, but the devil is in the details. Let me dig into the specific function logic now.`,

  `Starting my manual code review of {contractName} from {protocolName}. Solidity {solidityVersion}, inheriting from {inheritance}.

My review methodology: I read contracts top to bottom, tracking three things simultaneously:
1. Data flow -- how does user input propagate through state variables?
2. Control flow -- what are the authorization gates at each step?
3. Asset flow -- where do tokens/ETH enter, move within, and exit the protocol?

The contract structure:
- State variables: {stateVarNames}
- External functions: {funcNames}
- Dependencies: {dependencies}

I'm particularly interested in {affectedFunction} because it handles logic related to {vulnType}. Let me examine it closely.

The function signature, its modifiers, and its body tell a story. If the story goes: "read user input -> validate access control -> update state -> call external contract -> emit event", that's well-structured. But if the order is: "read user input -> call external contract -> update state", then we have a classic reentrancy window between the external call and the state update.

What also concerns me is the {missingCheck} aspect. If this check should exist but doesn't, it means the function operates on assumptions that aren't enforced by the code itself. For instance, if it assumes a valid epoch, a valid signer, or a non-zero amount -- but doesn't actually validate these -- then an attacker can violate those assumptions.

The inheritance from {inheritance} gives the contract its security foundation, but inherited modifiers can create a false sense of security. Just because Ownable is inherited doesn't mean every privileged function has onlyOwner. I need to verify each function individually.

Let me continue with a deeper dive into the specific logic of {affectedFunction}.`,

  `Alright, reading through {contractName} from {protocolName}. This is a {solidityVersion} contract, so I know I'm working with at least some of the safety improvements from 0.8.x (built-in overflow checks, custom errors, etc.).

Architecture overview:
- Inherits: {inheritance}
- Core state variables: {stateVarNames}
- External entry points: {funcNames}

My mental model of this contract's purpose is forming. It appears to manage some kind of {vulnType}-related logic, likely involving state transitions between the variables I listed above.

The function I'm zeroing in on: {affectedFunction}.

Let me think about what could go wrong here. I'm looking for the classic smart contract vulnerability patterns:
1. Reentrancy -- external call before state update
2. Access control -- missing or insufficient authorization check
3. Logic error -- incorrect math, wrong condition, off-by-one
4. Oracle manipulation -- trusting an easily-manipulated price source
5. Rounding/precision -- losses that favor the protocol (or the attacker)
6. Initialization -- upgradeable proxy not properly initialized
7. Signature replay -- EIP-712 signatures not bound to chain/nonce

The specific concern with {vulnType} is that {missingCheck}. If this check is genuinely missing, then any caller can invoke {affectedFunction} under conditions the protocol never intended.

One thing I always check: does this function interact with any external contracts that might be malicious? If it calls transfer(), transferFrom(), or any function on a user-supplied contract address, that contract could call back into {contractName} before the state is updated. The {inheritance} inheritance provides ReentrancyGuard, but only if the nonReentrant modifier is actually applied to {affectedFunction}.

Let me also think about upgradeability. If this is a UUPS or transparent proxy pattern, I need to check the initializer and the _authorizeUpgrade function. An uninitialized implementation is a classic critical finding.

Moving on to static analysis to catch what I might have missed in manual review.`,
];

const STATIC_ANALYSIS_TEMPLATES = [
  `Running Slither with the full detector suite against {contractFile}. Results are in: {highCount} High, {medCount} Medium, {lowCount} Low, {infoCount} Informational findings.

Let me triage these systematically, starting with the Highs.

The {vulnType} finding stands out -- let me examine the detector's reasoning. The detector ({detectorName}) flagged {affectedFunction} in {contractName}. The reasoning is that the function performs an operation without adequate validation, which could allow an attacker to cause {impactType}.

But I don't blindly trust automated findings. Static analyzers produce false positives. I need to verify each one manually:

For the {detectorName} finding specifically:
- Does the detector correctly understand the control flow? Slither uses static analysis, which means it explores all possible paths -- but it can't reason about runtime conditions like oracle prices or governance timelocks.
- Is the flagged code path actually reachable? If there's a guard earlier in the call chain that Slither didn't trace through, this could be a false positive.
- Does the finding assume the external contract is malicious? In many cases, the protocol trusts specific deployed addresses (like a known ERC20). The detector might flag interactions with trusted contracts unnecessarily.

The Medium findings are also worth reviewing. These are often gas optimizations or code quality issues, but sometimes they mask real vulnerabilities. A "missing zero-address check" Medium might actually be Critical if a zero-address in a mapping key causes a storage collision.

The Low and Informational findings are mostly noise for security purposes -- naming conventions, unused variables, external function declarations that could be external. I'll skim them but won't spend much time here.

Key takeaway from Slither: the {vulnType} finding on {affectedFunction} is worth investigating manually. Let me switch to manual verification to confirm or dismiss it.

I should also run Mythril or Echidna for deeper symbolic execution and fuzzing, especially on the math-heavy functions. If there are arithmetic operations in {contractName}, fuzzing can find edge cases that static analysis misses.`,

  `Slither analysis complete on {protocolName}/{contractFile}. Let me process the results.

High severity ({highCount} findings):
The most interesting one is {detectorName} targeting {affectedFunction}. This detector looks for {vulnType} patterns -- specifically cases where the function allows {vulnType} without proper guards.

Let me trace through the Slither output more carefully. The detector identified:
- A data flow from user-controlled input to a sensitive state operation
- Missing validation at the function entry point
- An external call that could be exploited for {impactType}

This is a strong signal, but I need to manually verify. My process:
1. Read the source code of {affectedFunction} in full context
2. Check if the Slither-reported data flow is accurate
3. Test whether the missing check can actually be exploited
4. Determine if there are mitigating factors Slither couldn't detect

Medium severity ({medCount} findings):
These include things like unchecked return values from low-level calls, missing event emissions on privileged functions, and potentially dangerous function naming. Most of these are code quality issues, but some could escalate. For example, if a function changes a critical parameter but doesn't emit an event, that's a governance transparency issue even if not directly exploitable.

Low severity ({lowCount} findings):
Mostly style and gas optimization. Not security-relevant in the immediate sense, but I'll note any that indicate developer inexperience (e.g., using tx.origin for auth, which is an anti-pattern even if not directly exploitable in this specific case).

Informational ({infoCount} findings):
Unused imports, functions that could be declared external, pragma statements. Zero security impact.

My conclusion from the automated analysis: the {vulnType} finding on {affectedFunction} is the one worth pursuing. Everything else is either a false positive or too low-impact. Time to formulate a hypothesis and test it.`,

  `Running the full static analysis pipeline on {protocolName}'s {contractName} contract.

Tool chain:
1. Slither -- for pattern-based vulnerability detection
2. Slither-printers -- for human-readable analysis of authorization, inheritance, and external calls
3. Custom regex searches -- for specific patterns like tx.origin, block.timestamp usage, unchecked arithmetic (if <0.8.0)

Slither results: {highCount} High, {medCount} Medium, {lowCount} Low, {infoCount} Informational.

The {vulnType} flag from {detectorName} is the one that catches my eye. Let me look at the specific detector output:

The detector reports that {affectedFunction} has a {vulnType} vulnerability. Specifically, it identified a path where user input reaches a sensitive operation without adequate validation. In {contractFile}, the function {affectedFunction} ...

Now, I need to validate this finding. Here's my validation checklist:
- Does the function accept untrusted input? Yes, if it has external/public visibility and takes parameters.
- Is the input used in a sensitive operation? This depends on what {vulnType} means in context.
- Is there a missing {missingCheck}? This is the critical question. If the check is missing, the finding is confirmed.
- Can this be exploited in practice? I need to check if there are runtime conditions that prevent exploitation even if the code path is technically vulnerable.

One thing I've learned from audits: the static analyzer is a starting point, not the conclusion. The real analysis begins when I read the code myself.

Let me now formulate a specific hypothesis about this vulnerability and plan how to test it.`,
];

const HYPOTHESIS_TEMPLATES = [
  `I suspect the {affectedFunction} function is vulnerable to {vulnType} because {missingCheck}. Let me trace the execution path carefully.

Here's my hypothesis:
When a user calls {affectedFunction}, the function first reads {stateVar}, then makes an external call to {function}, but I don't see any {missingCheck} before the state mutation happens. This creates a window where an attacker can exploit the gap.

Let me walk through the execution flow step by step:

Step 1 -- Entry: The caller invokes {affectedFunction} on {contractName}. The function checks... nothing, if {missingCheck} is truly absent. Any address can call it.

Step 2 -- State read: The function reads {stateVar} to determine the current protocol state. If this value can be manipulated by the attacker before the function executes, that's an oracle/data integrity issue.

Step 3 -- External interaction: The function calls {function} (or interacts with an external contract). This is where things get interesting. If the external contract is user-controlled, it could call back into {contractName} before the state is finalized -- classic reentrancy.

Step 4 -- State mutation: After the external call, the function updates {stateVar2}. But by this point, if reentrancy occurred, the state is already corrupted. The attacker called in twice, and the second call saw stale state from the first call.

My confidence level: Moderate to High. The inheritance chain ({inheritance}) suggests the developers intended to have security controls, but {missingCheck} being absent on {affectedFunction} means those controls aren't applied here.

Before I jump to writing a PoC, let me consider alternative hypotheses:
- Maybe the check exists in a modifier I overlooked. Let me re-examine the full modifier chain.
- Maybe the external contract is guaranteed safe by protocol design (e.g., it's a deployed OpenZeppelin contract). In that case, reentrancy is theoretical only.
- Maybe the Solidity 0.8.x built-in checks prevent the overflow/underflow I'm assuming.

But even if one hypothesis falls, others may still hold. The key question is: can an attacker cause {impactType} through this function? Let me try to prove it.`,

  `Let me formulate my hypothesis more precisely.

Working hypothesis: {contractName}.{affectedFunction} is vulnerable to {vulnType} due to {missingCheck}.

Attack scenario:
1. Attacker identifies that {affectedFunction} lacks {missingCheck}
2. Attacker crafts a transaction that exploits this gap by causing {impactType}
3. The exploit complexity is {exploitComplexity}
4. The outcome is {impactType}, which directly affects {stateVar}

Let me trace the data flow to verify:
- Input: Caller provides parameters to {affectedFunction}
- Processing: The function computes a result based on {stateVar} and {stateVar2}
- Output: The function transfers tokens, updates state, or emits events

Where is the gap? The function assumes {missingCheck} but never enforces it. This means:
- If {missingCheck} is an access control issue: any address can invoke privileged logic
- If {missingCheck} is a reentrancy issue: the function can be called recursively before state finalizes
- If {missingCheck} is a validation issue: invalid inputs produce undefined/advantageous behavior
- If {missingCheck} is an oracle issue: the function trusts data that can be manipulated

The protocol is {protocolName}, which inherits {inheritance}. The fact that it inherits these contracts but still has {vulnType} suggests a developer oversight -- the security primitives exist but weren't applied to this specific function.

I need to write a test to confirm this hypothesis. Let me think about the test setup.`,

  `Okay, I've spent enough time reading the code. Here's my analysis:

The {affectedFunction} function in {contractName} has a suspicious pattern. Let me explain.

What the function does:
It's an {exploitComplexity}-complexity function that interacts with {stateVar}. Under normal circumstances, it works fine. But the missing {missingCheck} means that under specific conditions -- conditions an attacker can control -- the function behaves incorrectly.

The vulnerability class is {vulnType}. Here's why I believe this:

Evidence 1: The function {affectedFunction} is external and callable by any address (or at least a broader set of addresses than intended). No {missingCheck} restricts who can call it.

Evidence 2: The function reads and writes {stateVar} and {stateVar2} without validating the intermediate state. If an attacker can manipulate these values between reads and writes, the computation is compromised.

Evidence 3: The contract inherits {inheritance}, which provides security mechanisms. But inheritance alone doesn't protect you -- each function must explicitly use the modifiers. If {affectedFunction} doesn't have the right modifiers, the inherited protections don't apply.

My attack hypothesis:
An attacker can call {affectedFunction} under conditions that trigger {impactType}. The key enabler is the missing {missingCheck}. Without it, the function processes requests it should reject.

Alternative explanations I've considered and ruled out:
- Could this be intentional? Unlikely. The inherited contracts suggest the developers knew about the need for {missingCheck}. Its absence from {affectedFunction} is most plausibly an oversight.
- Is it mitigated elsewhere? I've checked the call chain and found no upstream validation that would prevent this exploit.

Next step: write a Foundry test to prove this hypothesis is correct.`,
];

const POC_TEMPLATES = [
  `Writing a Foundry test to prove this vulnerability. I'll structure the test to clearly show the before and after state.

Test plan:
1. Set up the initial state with a depositor holding normal amounts of the protocol token
2. Call {affectedFunction} as the attacker, exploiting the {vulnType}
3. Verify the exploit succeeded by checking state changes
4. The test should show: {beforeState} -> {afterState}

Solidity test structure:

  contract {contractName}ExploitTest is Test {ob}
      {contractName} public target;

      function setUp() public {ob}
          // Deploy or fork the {protocolName} protocol
          target = new {contractName}();
          // Initialize with realistic state
      {cb}

      function testExploit_{vulnType}() public {ob}
          // Phase 1: Setup - normal protocol state
          // {beforeState}

          // Phase 2: Attacker calls {affectedFunction} exploiting {vulnType}
          // The missing {missingCheck} allows this

          // Phase 3: Verify exploit
          // {afterState}
          // {foundryAssert}
      {cb}
  {cb}

The test complexity is {exploitComplexity}, so:
- If trivial: A simple direct call to {affectedFunction} with no special setup
- If moderate: Requires setting up specific state conditions (e.g., epoch boundaries, price feeds)
- If complex: Requires fork testing with mainnet state, flash loans, or multi-contract orchestration

Since requiresFork = {requiresFork}, this test {forkText}.

The capital requirement is {requiresCapital}, meaning the attacker needs {capitalText}.

Let me refine the test to be maximally clear about the exploit mechanics.`,

  `Building the PoC test. I'm using Foundry (Forge) since it's the standard for smart contract testing.

The test needs to demonstrate {impactType} through {vulnType} in {contractName}.{affectedFunction}.

My approach:
1. Deploy the {protocolName} contracts (or fork mainnet if requiresFork = {requiresFork})
2. Set up honest users with normal positions
3. Execute the attack via {affectedFunction}
4. Assert the damage matches expectations

Key test functions I'll need:
- setUp(): Deploy contracts, fund test addresses, establish baseline state
- test_{vulnType}(): The actual exploit demonstration
- Helper functions for token minting, position setup, etc.

The critical assertion: {foundryAssert}

This assertion captures the core impact -- if it passes, the vulnerability is confirmed. If it fails, either the vulnerability doesn't exist or my test setup is wrong.

For {pocType} testing:
- If unit: I deploy mock contracts and test in isolation
- If fork: I fork mainnet at a specific block where {protocolName} is deployed and test against real state
- If fuzz: I use invariant testing with {funcNames} as entry points, running thousands of random sequences
- If invariant: I define protocol invariants (e.g., "total supply must equal sum of all balances") and let Echidna/Foundry try to break them

The test should compile and run cleanly. Let me also think about edge cases -- what if the attacker tries to exploit this multiple times? Does the first exploit prevent subsequent ones? Or can it be repeated infinitely?

An infinite repeat exploit is always worse than a one-time exploit. Let me make sure the test captures the worst case.`,

  `Time to write the exploit test. I want this test to be so clear that anyone reading the audit report can immediately understand the vulnerability.

Test structure (Foundry/Forge):

  setUp() -> Deploy {contractName}, initialize state, fund attacker
  test_{vulnType}() ->
      1. Record attacker's balance (before)
      2. Attacker calls {affectedFunction} exploiting {missingCheck}
      3. Record attacker's balance (after)
      4. {foundryAssert}

The beauty of a good PoC test is that it tells the story without words. The code itself is the proof.

Now, for this specific {vulnType} in {protocolName}, the test needs to show:
- The attack vector: calling {affectedFunction} without {missingCheck}
- The attack outcome: {impactType}
- The quantifiable damage: {beforeState} -> {afterState}

Since pocType = {pocType}, I'll {pocTypeText}.

The {exploitComplexity} complexity rating means the test {complexityText}.

Let me write the full test now with all the realistic state setup.`,
];

const IMPACT_TEMPLATES = [
  `The exploit works in isolation. Now I need to quantify the real-world impact on {protocolName}.

Protocol context:
- TVL: {tvl}
- {affectedToken} price: {tokenPrice}
- Vulnerability: {vulnType} in {affectedFunction}

Let me think about this from an attacker's perspective. What's the maximum profit they can extract?

Attack Scenario 1 -- Direct drain:
The attacker can {impact1}. With {tvl} in the protocol, even a partial drain could yield millions in profit. The limiting factors are:
- Capital required: the attacker needs some initial position to exploit
- Speed: how many blocks before the protocol or community notices and reacts
- MEV: would searchers front-run the exploit, reducing the attacker's profit but amplifying the total damage

Attack Scenario 2 -- Protocol manipulation:
Beyond direct theft, the attacker could {impact2}. This is harder to quantify but potentially more damaging. If {affectedToken} crashes due to loss of confidence, all holders are affected, not just those directly exploited.

Attack Scenario 3 -- Cascading failure:
In the worst case, the attacker could {impact3}. Given that {protocolName} likely integrates with other DeFi protocols (lending platforms, AMMs, aggregators), a failure here could propagate.

Worst-case scenario: {worstCase}

Severity assessment:
Given the {tvl} at risk and the ability to cause {impactType}, this finding rates as {severity}. The CVSS factors:
- Attack Vector: Network (anyone with an EOA can exploit)
- Attack Complexity: Depends on {complexityDesc}
- Privileges Required: None (or minimal, depending on the specific access control gap)
- User Interaction: None
- Scope: {scopeText}
- Confidentiality: High (if sensitive state is exposed)
- Integrity: High (protocol state is corrupted)
- Availability: {availabilityText}

Users affected: {usersAffected}. This is not a theoretical risk -- real user funds are on the line.`,

  `Impact quantification for the {vulnType} finding in {contractName}.

Let me be precise about the numbers.

Protocol TVL: {tvl}. This is the total value at risk. Even if the attacker can't drain everything, any amount above zero is unacceptable for a vulnerability of this nature.

The {affectedToken} token is trading at {tokenPrice}. If the exploit affects token supply dynamics (minting, burning, transferring), the market impact could far exceed the direct theft amount. Confidence-driven sell pressure can wipe out billions in market cap even from a relatively small direct exploit.

The attack chain:
1. {impact1}
2. {impact2}
3. {impact3}

Each step compounds the damage. Step 1 gives the attacker initial profit. Step 2 amplifies it by manipulating protocol mechanics. Step 3 is the cascading failure that affects the broader ecosystem.

Worst case: {worstCase}

I also need to consider:
- Can the attacker do this repeatedly? If the vulnerability doesn't self-close after exploitation, the total damage could be unlimited.
- Can other attackers copy the exploit? Once public, anyone can replicate it, turning a single-attacker scenario into a free-for-all.
- Is there a recovery path? If the protocol has a pause mechanism, timelock, or multisig that could respond, the damage is bounded by response time. If not, the damage is irreversible.

Final severity: {severity}. The combination of {tvl} at risk, {impactType} as the mechanism, and irreversible state corruption puts this at the top of the severity scale.

Recommendation priority: P0 -- fix before any further deployments or upgrades.`,

  `Now for the most important part of any audit finding: what's the actual damage?

With {protocolName} holding {tvl} in TVL, the {vulnType} vulnerability in {affectedFunction} is not an academic concern.

Direct financial impact:
An attacker exploiting this vulnerability could {impact1}. At current prices ({affectedToken} at {tokenPrice}), this translates to a direct loss of user funds that may or may not be recoverable.

Secondary impact:
The attacker could also {impact2}. This is significant because it affects the protocol's core mechanics, not just individual user balances. If the protocol can't perform its basic function correctly, it's fundamentally broken.

Tertiary impact (ecosystem):
The attacker could {impact3}. For DeFi protocols, this is the nightmare scenario. Composable protocols create implicit dependencies -- a failure in one protocol can cascade to all protocols that depend on it.

Who is affected: {usersAffected}

The {severity} rating is justified by:
1. Direct financial loss potential: {tvl} is at risk
2. Number of affected users: potentially all protocol users
3. Irreversibility: blockchain state changes cannot be undone without governance intervention
4. Exploit accessibility: the vulnerability can be exploited by anyone with {complexityDesc}

Worst case: {worstCase}

This finding requires immediate remediation. No new deployments should proceed until this is fixed.`,
];

const REPORT_TEMPLATES = [
  `Compiling the full audit finding for {protocolName}.

Finding title: {vulnType} in {affectedFunction} allows {impactType}
Severity: {severity}
SWC Reference: {swcId}
CWE Reference: {cweId}
CVSS 3.1 Vector: {cvssVector}

Report structure:

1. Overview
   The {contractName} contract in the {protocolName} protocol contains a {severity}-severity vulnerability. The {vulnType} issue in {affectedFunction} allows an attacker to achieve {impactType}.

2. Vulnerability Description
   The {affectedFunction} function does not implement {missingCheck}. This allows any caller to trigger {vulnType}, resulting in {impactType}. The vulnerability exists because the function assumes conditions that are never enforced by the code.

3. Impact Assessment
   An attacker can exploit this vulnerability to cause {impactType}. With the protocol's current TVL, the potential financial impact is significant. The vulnerability affects all users who interact with the protocol through {affectedFunction}.

4. Proof of Concept
   I've included a Foundry test that demonstrates the exploit. The test shows the protocol state before the attack, executes the exploit, and verifies the damage. Running "forge test --match testExploit_{vulnType} -vvv" will reproduce the finding.

5. Recommended Fix
   {fixDescription}. The corrected function should:
   - Validate all inputs at the function entry point
   - Apply appropriate access control modifiers
   - Follow the Checks-Effects-Interactions pattern
   - Emit events for all state-changing operations

6. Secure Code Snippet
   I'll include the corrected version of {affectedFunction} with {missingCheck} properly implemented.

7. References
   - SWC Registry: {swcId}
   - CWE: {cweId}
   - CVSS: {cvssVector}

Let me make sure the report is clear enough for both technical and non-technical readers. The severity rating, impact description, and fix recommendation need to be unambiguous.`,

  `Writing up the audit report for {protocolName} -- {contractName} {vulnType} finding.

Severity: {severity}

This is one of the most impactful findings from this audit. Let me structure it properly.

Title: {impactType} via {vulnType} in {contractName}.{affectedFunction}

The finding has four components:
1. WHAT: The {affectedFunction} function is vulnerable to {vulnType}
2. WHY: {missingCheck} is not enforced, allowing exploitation
3. HOW: An attacker calls {affectedFunction} under conditions that trigger {impactType}
4. IMPACT: {impactType}, affecting protocol users and deposited funds

The fix is straightforward: {fixDescription}. This is a low-effort, high-impact remediation -- the code change is minimal (a modifier addition or input validation check), but it closes the vulnerability completely.

I'll reference the following standards:
- {swcId} (Smart Contract Weakness Classification)
- {cweId} (Common Weakness Enumeration)
- CVSS 3.1: {cvssVector}

The PoC test is included as supplementary material. Running it should produce a clear pass/fail: pass = vulnerability confirmed, fail = either fixed or false positive.

For the secure code snippet, I'll show the before (vulnerable) and after (fixed) versions side by side so the development team can see exactly what changed.

This finding, combined with any other findings from the audit, should be prioritized by severity. {severity} findings are P0 -- they block deployment until resolved.`,

  `Finalizing the audit report for {protocolName}.

The {vulnType} finding in {affectedFunction} is rated {severity}. Here's the complete writeup:

Executive Summary (for non-technical readers):
A security vulnerability was discovered in the {contractName} smart contract. The vulnerability could allow an attacker to cause {impactType}. We recommend fixing this issue before deploying to production.

Technical Details (for developers):
- Contract: {contractName} ({protocolName})
- Function: {affectedFunction}
- Vulnerability: {vulnType}
- Root cause: {missingCheck}
- Attack path: Any caller -> {affectedFunction} -> {impactType}
- References: {swcId}, {cweId}, {cvssVector}

Impact:
The vulnerability enables {impactType}. The severity is {severity} because the vulnerability is directly exploitable and affects core protocol functionality.

Remediation:
{fixDescription}. The fix involves minimal code changes but has significant security impact. We recommend implementing this fix and running the full test suite before redeploying.

PoC:
A Foundry test is provided that demonstrates the vulnerability. The test deploys the contract, sets up realistic state, executes the exploit, and verifies the damage.

I'm satisfied this finding is accurate, reproducible, and clearly communicated. Moving to the next finding.`,
];

const FAILURE_TEMPLATES = [
  `The test reverted with {error}. Let me analyze: is this a legitimate block (the vulnerability doesn't exist) or a test setup issue?

Looking at the trace, the revert happens at {location}. This could mean {hypothesis}.

Let me work through this methodically:

Possibility 1: My test setup is wrong
- Did I correctly deploy and initialize the {contractName} contract?
- Did I fund the attacker address with enough tokens/ETH?
- Did I set the right function parameters?
- Is the fork block number correct (if fork testing)?

If any of these are wrong, the revert is a test artifact, not a protocol behavior.

Possibility 2: The vulnerability doesn't exist
- The revert at {location} suggests the protocol has a check I didn't account for
- If {hypothesis}, then my analysis was incorrect and this finding should be dismissed
- But I should double-check before dismissing -- maybe the check is incomplete and can be bypassed differently

Possibility 3: Partial vulnerability
- The check at {location} prevents my specific attack vector, but a variant might still work
- For example, if the check validates amount > 0, I could try amount = 0 to see if that bypasses the logic
- Or if the check is on msg.sender, I could try calling through a different contract

Next step: {nextStep}. I won't give up on this finding until I've exhausted all reasonable approaches.`,

  `Test failed. {error} at {location}. Let me debug.

First question: did I set up the test correctly? Let me check:
- Contract deployment: verified
- Initial state: matches expected preconditions
- Function call: correct signature and parameters
- Attacker setup: has necessary tokens/approvals

If the setup is correct, then the revert tells me something about the protocol's actual behavior:
- {hypothesis}

This is an important learning moment. If the vulnerability doesn't exist, I need to understand why I thought it did. Was it a misreading of the code? A false positive from static analysis? An assumption about missing checks that turned out to be wrong?

Let me re-examine the source code of {affectedFunction} with fresh eyes, knowing that {location} is enforcing a check I didn't account for.

Alternatively: {nextStep}.

I'll document this failed attempt in my notes -- even negative results are valuable. They tell me what doesn't work, which narrows the search space.`,

  `Hmm, the exploit test didn't work as expected. Revert: {error}.

Location: {location}.

Analysis:
This revert means one of two things:

Scenario A -- The vulnerability is real but my exploit is wrong:
Maybe {hypothesis}. In this case, the vulnerability exists but my specific attack vector is blocked by {location}. I need to find an alternative path -- perhaps calling through an intermediate contract, or manipulating state through a different function first.

Scenario B -- The vulnerability doesn't exist:
The check at {location} legitimately prevents the exploit. If this check was in the code all along and I missed it, this is a false positive. If the check was added in a recent commit, maybe the vulnerability existed in an earlier version.

Let me check the git history for {contractName} to see if {affectedFunction} was recently modified. If it was, the vulnerability might have already been fixed.

Either way: {nextStep}.

I'll either document this as a dismissed finding with reasoning and continue, or investigate further and update my assessment.`,
];
