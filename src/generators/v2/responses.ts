// Response generation for Dataset Generator V2 — smart contract security context

import { SeededRNG, ContractProfile } from "../outputs/index.js";
import { AttackPhase } from "../../templates/scenarios/index.js";

// ============================================================
// Text Variation — replaces web-specific patterns with smart contract patterns
// ============================================================

export function variateText(text: string, protocolName: string, profile: ContractProfile): string {
  const chainName = getChainName(profile.chainId);
  const contractAddr = profile.contractAddress;
  const tokenName = profile.affectedToken;
  const solidityVer = profile.solidityVersion;

  return text
    // Protocol / domain replacements
    .replace(/target\.com/g, protocolName.toLowerCase().replace(/\s+/g, ""))
    .replace(/shop\.target\.com/g, `app.${protocolName.toLowerCase().replace(/\s+/g, "")}`)
    .replace(/api\.target\.com/g, `api.${protocolName.toLowerCase().replace(/\s+/g, "")}`)
    .replace(/admin\.target\.com/g, `admin.${protocolName.toLowerCase().replace(/\s+/g, "")}`)
    .replace(/www\.target\.com/g, `app.${protocolName.toLowerCase().replace(/\s+/g, "")}`)
    // Web endpoint to function references
    .replace(/\/api\/v1\/users/g, `function ${profile.externalFunctions[0]?.name || "stake"}()`)
    .replace(/\/api\/search/g, `function ${profile.externalFunctions[1]?.name || "withdraw"}()`)
    .replace(/\/api\/data/g, `function ${profile.externalFunctions[0]?.name || "claim"}()`)
    .replace(/\/api\/query/g, `function ${profile.externalFunctions[2]?.name || "poke"}()`)
    .replace(/\/api\/orders/g, "function execute()")
    .replace(/\/api\/products/g, "function liquidate()")
    .replace(/\/api\/settings/g, "function setFeeRate()")
    .replace(/\/api\/admin/g, "function setOwner()")
    .replace(/\/api\/reports/g, "function getReserves()")
    .replace(/\/api\/transactions/g, "function bridge()")
    .replace(/\/api\/auth\/login/g, "function initialize()")
    // IP addresses to contract addresses
    .replace(/10\.10\.10\.1/g, contractAddr)
    .replace(/10\.0\.1\.50/g, contractAddr)
    .replace(/192\.168\.1\.\d+/g, contractAddr)
    .replace(/192\.168\.100\.\d+/g, contractAddr)
    .replace(/172\.16\.0\.\d+/g, contractAddr)
    // Database names to token / protocol names
    .replace(/PostgreSQL/g, tokenName)
    .replace(/postgresql/g, tokenName.toLowerCase())
    .replace(/MySQL/g, profile.protocolName)
    .replace(/mysql/g, profile.protocolName.toLowerCase())
    .replace(/MongoDB/g, profile.stateVariables[0]?.name || "totalSupply")
    .replace(/Redis/g, profile.stateVariables[1]?.name || "balances")
    // Tech headers / frameworks to Solidity / chain context
    .replace(/nginx/g, `${chainName} node`)
    .replace(/apache/g, `Solidity ${solidityVer}`)
    .replace(/tomcat/g, `Hardhat / Foundry`)
    // CWE references — replace with SC-relevant SWC IDs
    .replace(/CWE-89/g, "SWC-101")
    .replace(/CWE-79/g, "SWC-103")
    .replace(/CWE-918/g, "SWC-114")
    .replace(/CWE-639/g, "SWC-115")
    .replace(/CWE-94/g, "SWC-106")
    .replace(/CWE-502/g, "SWC-119")
    .replace(/CWE-287/g, "SWC-105");
}

// Helper — chain name from chainId
function getChainName(chainId: number): string {
  const chains: Record<number, string> = {
    1: "Ethereum",
    42161: "Arbitrum",
    10: "Optimism",
    8453: "Base",
    137: "Polygon",
    56: "BNB Chain",
  };
  return chains[chainId] || "Ethereum";
}

// ============================================================
// Grounded Response Generator
// Generates assistant responses grounded in tool output data
// ============================================================

export function generateGroundedResponse(
  rng: SeededRNG,
  phase: AttackPhase,
  profile: ContractProfile,
  isFailure: boolean,
  toolOutputSummary: string,
  includeThinking: boolean
): string {
  // 40% with headers, 60% without — natural conversation variation
  const useHeader = rng.bool(0.4);
  let response = "";

  if (useHeader) {
    response += rng.pick([
      `## ${phase.phase}\n\n`,
      `### ${phase.phase}\n\n`,
      `**${phase.phase}:**\n\n`,
      `**${phase.phase} Results**\n\n`,
    ]);
  }

  // Build opening that references actual tool output
  const opening = generateAnalysisResponse(rng, phase, profile, isFailure);

  // Add grounding paragraph that references tool output data
  let grounding = "";
  if (toolOutputSummary.length > 20 && rng.bool(0.7)) {
    const refs: string[] = [];

    // SC-specific extraction patterns
    const selectorMatch = toolOutputSummary.match(/0x([0-9a-f]{8})\b/i);
    const gasMatch = toolOutputSummary.match(/\bgas[=:\s]+(\d{4,})\b/i);
    const revertMatch = toolOutputSummary.match(/revert(ed)?[:\s]+(.{5,60})/i);
    const funcMatch = toolOutputSummary.match(/function\s+(\w+)/i);
    const lineMatch = toolOutputSummary.match(/line[=:\s]+(\d+)/i);
    const severityMatch = toolOutputSummary.match(/\b(critical|high|medium|low|informational)\b/i);
    const detectorMatch = toolOutputSummary.match(/\b(\w+Detector|optimization|informational)\b/i);

    if (selectorMatch) refs.push(`selector 0x${selectorMatch[1]}`);
    if (gasMatch) refs.push(`gas usage of ${gasMatch[1]}`);
    if (revertMatch) refs.push(`revert: "${revertMatch[2].trim()}"`);
    if (funcMatch) refs.push(`function ${funcMatch[1]}`);
    if (lineMatch) refs.push(`line ${lineMatch[1]}`);
    if (severityMatch) refs.push(`${severityMatch[1].toLowerCase()} severity detector`);
    if (detectorMatch) refs.push(`${detectorMatch[1]} finding`);

    if (refs.length > 0) {
      grounding = `\n\nSpecifically, the tool output shows ${refs.join(", ")} — ${rng.pick([
        "this confirms my initial assessment of the vulnerability pattern",
        "this is consistent with the attack vector I identified",
        "this narrows down the exact code path affected",
        "this gives me a concrete target for the PoC test",
        "this data is key evidence for the audit report",
        "I can use this to craft a more targeted exploit",
        "this aligns with the expected behavior for this vulnerability class",
      ])}.`;
    }
  }

  // For failure/soft-fail, include explicit "not vulnerable" language
  let failureNote = "";
  if (isFailure) {
    failureNote = `\n\n${rng.pick([
      "**Result: Not vulnerable.** The function properly handles this attack class.",
      "This code path appears to be safely implemented. The contract is not vulnerable to this specific technique.",
      "**Negative result** — the contract's defenses are effective here. Moving on to alternative approaches.",
      "No exploitable behavior detected. The input validation is working correctly on this function.",
      "The test confirms this function is **not vulnerable** to this attack. I'll document this as a positive defense.",
      "After thorough testing, I can confirm this specific vector is blocked. The security control is effective.",
    ])}`;
  }

  // Longer response when thinking is present (thinking should produce deeper analysis)
  let deeperAnalysis = "";
  if (includeThinking && !isFailure && rng.bool(0.6)) {
    const funcName = rng.pick(profile.externalFunctions).name;
    const stateVar = rng.pick(profile.stateVariables);
    deeperAnalysis = `\n\n${rng.pick([
      `**Technical depth:** The root cause is that the \`${funcName}()\` function ${rng.pick([
        `updates \`${stateVar.name}\` after making an external call, enabling reentrancy`,
        `does not validate the \`msg.sender\` against the authorized role before executing critical logic`,
        `uses a stale price from the oracle without checking the staleness threshold`,
        `trusts user-supplied values for calculating shares without rounding in favor of the protocol`,
        `fails to enforce a lock or timelock before allowing privileged state changes`,
        `performs a low-level call without checking the return value`,
      ])}. The fix requires changes at the ${rng.pick(["function-level validation", "state update ordering", "oracle integration layer", "access control modifier", "reentrancy guard"])} level.`,
      `**Exploitation path:** From this finding, the attack chain is: call \`${funcName}()\` with crafted arguments → ${rng.pick([
        "drain funds from the contract",
        "mint unlimited tokens",
        "bypass access controls to call admin functions",
        "manipulate the internal accounting to withdraw more than deposited",
        "trigger a griefing attack that locks user funds",
        "front-run the transaction to extract MEV",
      ])} → ${rng.pick([
        "full contract drain",
        "governance takeover via token minting",
        "permanent denial of service for other users",
        "cross-protocol contagion via price oracle manipulation",
        "complete loss of protocol solvency",
      ])}. Each step increases the severity.`,
      `**Scope assessment:** This isn't isolated to \`${funcName}()\`. The ${profile.inheritanceChain[0] || "base contract"} likely has ${rng.int(2, 8)} other functions using the same vulnerable pattern because they share ${rng.pick([
        "the same internal _updateBalance helper",
        "a common modifier that doesn't cover this edge case",
        "the same oracle price fetch pattern",
        "an inherited access control pattern from " + (profile.inheritanceChain[0] || "Ownable"),
      ])}. I should test ${rng.pickN(profile.externalFunctions.map(f => f.name), 2).join(" and ")} as well.`,
    ])}`;
  }

  return `${response}${opening}${grounding}${failureNote}${deeperAnalysis}`;
}

// ============================================================
// Analysis Response Builder
// ============================================================

function generateAnalysisResponse(
  rng: SeededRNG,
  phase: AttackPhase,
  profile: ContractProfile,
  isFailure: boolean
): string {
  const funcName = rng.pick(profile.externalFunctions).name;
  const stateVar = rng.pick(profile.stateVariables);
  const solidityVer = profile.solidityVersion;
  const chainName = getChainName(profile.chainId);
  const toolName = rng.pick(phase.tools);
  const payloadCount = rng.int(3, 50);
  const gasUsed = rng.int(50000, 2000000);
  const blockNum = rng.int(19000000, 20500000);

  const headerStyles = [
    `## ${phase.phase}\n\n${phase.description}`,
    `### ${phase.phase}\n\nObjective: ${phase.description}`,
    `**Phase: ${phase.phase}**\n\nGoal: ${phase.description}`,
    `## ${phase.phase} — ${profile.contractName} (${profile.protocolName})`,
    `### ${phase.phase} on ${profile.protocolName}'s ${profile.contractName}`,
    `## ${rng.pick(["Executing", "Running", "Performing", "Conducting", "Initiating"])} ${phase.phase}`,
    `### ${phase.phase} — ${rng.pick(["Results and Analysis", "Findings Summary", "Assessment Results", "Testing Output"])}`,
    `## ${phase.phase}\n\nTarget: ${profile.contractName} at ${profile.contractAddress} (${chainName}, Solidity ${solidityVer})`,
  ];

  let opening: string;
  if (!isFailure) {
    // Fragment A: How the test was conducted
    const fragA = rng.pick([
      `${toolName} analysis of ${profile.contractName} on ${chainName}`,
      `sending ${payloadCount} crafted calldata sequences to \`${funcName}()\``,
      `my ${toolName} scan of ${profile.contractAddress} (gas: ${gasUsed})`,
      `probing the \`${funcName}()\` function in ${profile.contractName} on ${chainName}`,
      `testing the \`${stateVar.name}\` state variable interaction via \`${funcName}()\``,
      `a targeted ${toolName} assessment of the ${profile.protocolName} contract`,
      `fuzzing \`${funcName}()\` and adjacent functions with ${payloadCount} test cases`,
      `analyzing ${payloadCount} transaction traces on ${chainName} at block ${blockNum}`,
      `${toolName} enumeration of the ${profile.contractName} (${profile.inheritanceChain.join(" → ")}) stack`,
      `the ${toolName} probe of ${profile.contractAddress} (${payloadCount} calls, ${gasUsed} gas)`,
      `manual testing of \`${funcName}()\` on ${chainName} via ${toolName}`,
      `a ${gasUsed}-gas ${toolName} sweep across the ${profile.protocolName} protocol`,
      `comparing baseline vs malicious calls to \`${funcName}()\``,
      `injecting ${payloadCount} variants into \`${funcName}()\` on ${profile.contractAddress}`,
      `the ${payloadCount}-call ${toolName} barrage against ${profile.contractName}`,
      `fingerprinting ${profile.contractAddress} and then targeting \`${funcName}()\``,
      `piping ${toolName} output through custom Foundry assertions on ${profile.contractName}`,
      `a time-based analysis of \`${funcName}()\` across ${rng.int(5, 20)} blocks`,
      `${toolName} with ${payloadCount} crafted payloads against ${profile.contractName}`,
      `probing both \`${funcName}()\` and \`${rng.pick(profile.externalFunctions.filter(f => f.name !== funcName)).name}()\``,
      `a differential analysis between normal and malicious calls to ${profile.contractName}:${funcName}`,
      `the ${profile.contractName} contract's \`${funcName}()\` handler on ${chainName}`,
      `${payloadCount} mutation tests via ${toolName} against ${profile.contractName}`,
      `sequential testing of ${profile.contractAddress} functions starting with \`${funcName}()\``,
      `${toolName} running at ${rng.int(10, 200)} calls/sec against ${profile.contractName}`,
      `targeting the ${stateVar.type} \`${stateVar.name}\` variable via \`${funcName}()\``,
      `a ${rng.pick(["comprehensive", "systematic", "focused", "thorough", "methodical"])} ${toolName} assessment of ${profile.contractName}`,
      `cross-function testing of \`${funcName}()\` across ${profile.contractName} interfaces`,
      `the initial ${toolName} reconnaissance of ${profile.contractName}`,
      `correlating ${toolName} findings with the Solidity ${solidityVer} compilation output`,
    ]);

    // Fragment B: What was observed
    const vulnDetail = rng.pick([
      "a state change inconsistent with the expected invariant",
      `a reentrancy opportunity through the \`${funcName}()\` external call`,
      "an unauthorized state modification without proper access control",
      `a rounding error in the share calculation that benefits the caller`,
      "a price manipulation vector via the oracle integration",
      `an integer overflow in the \`${stateVar.name}\` update path`,
      "a signature replay vulnerability in the permit flow",
      `a storage collision with the upgradeable proxy slot`,
      "an unchecked return value from a low-level call",
      "a missing zero-address check allowing fund lock",
    ]);

    const fragB = rng.pick([
      `revealed ${vulnDetail}`,
      `confirmed the \`${funcName}()\` function is exploitable`,
      `produced ${vulnDetail} consuming ${gasUsed} gas`,
      `triggered ${rng.pick(["a revert with a revealing error message", "an unexpected state change", "a successful unauthorized call", "a balance manipulation"])} via \`${funcName}()\``,
      `exposed a clear vulnerability in the ${profile.protocolName} protocol`,
      `showed the ${solidityVer} contract fails to properly guard \`${funcName}()\``,
      `returned ${payloadCount} anomalous traces showing ${vulnDetail}`,
      `detected unsanitized input reaching the ${stateVar.name} update path`,
      `flagged ${vulnDetail} in the \`${funcName}()\` handler`,
      `demonstrated that \`${funcName}()\` can be called without ${rng.pick(["proper authorization", "the expected modifier", "valid input bounds", "the reentrancy lock"])}`,
      `immediately highlighted ${vulnDetail}`,
      `uncovered ${vulnDetail} — a strong positive signal`,
      `yielded ${payloadCount} failing invariant tests showing ${vulnDetail}`,
      `proved the \`${funcName}()\` endpoint lacks proper ${rng.pick(["access control", "input validation", "reentrancy protection", "oracle staleness check"])}`,
      `exposed the ${profile.contractName} contract's failure to ${rng.pick(["check msg.sender", "enforce nonReentrant", "validate the oracle price", "round in protocol's favor"])}`,
      `confirmed exploitability with ${vulnDetail}`,
      `produced definitive evidence: ${vulnDetail}`,
      `pinpointed ${vulnDetail} in the ${stateVar.name}-modifying function`,
      `showed a ${rng.int(1, 50)}-unit state differential between normal and injected calls`,
      `found that ${rng.int(60, 95)}% of payloads bypassed the expected guard`,
    ]);

    // Fragment C: Conclusion
    const fragC = rng.pick([
      `This confirms the vulnerability is real and exploitable.`,
      `The ${solidityVer} / ${profile.inheritanceChain.join(" / ")} stack is clearly handling \`${funcName}()\` unsafely.`,
      `This is a confirmed true positive requiring immediate remediation.`,
      `Exploitation is straightforward from this point.`,
      `The finding affects all callers of this function on ${chainName}.`,
      `This validates my initial hypothesis about the ${funcName} vulnerability.`,
      `The evidence is conclusive — this function is vulnerable.`,
      `I can reliably reproduce this across multiple transaction patterns.`,
      `This is consistent with ${rng.pick(["SWC-101", "SWC-103", "SWC-105", "SWC-106", "SWC-107", "SWC-114", "SWC-115", "SWC-119"])} exploitation.`,
      `Further exploitation should yield ${rng.pick(["fund drainage", "unauthorized minting", "governance takeover", "permanent DoS", "price manipulation"])}.`,
      `The vulnerable code path is reachable by any ${rng.pick(["external caller", "token holder", "governance participant", "unauthenticated address"])}.`,
      `This warrants immediate testing for escalation potential.`,
      `Combined with the recon data, this opens several exploitation paths.`,
      `I verified this is not a false positive by testing ${rng.int(3, 10)} call variants.`,
      `The Solidity ${solidityVer} compiler's default behavior appears to lack protection here.`,
    ]);

    opening = `${rng.pick(["After", "Running", "Based on", "Through", "Via", "Following", "During", "From", "With"])} ${fragA}, I ${rng.pick(["found that the results", "confirmed that the output", "observed that the trace", "determined that the behavior", "noted that the results"])} ${fragB}. ${fragC}`;
  } else {
    // Failure opening
    const defenseType = rng.pick([
      "reentrancy guard",
      "access control modifier",
      "input validation",
      "oracle staleness check",
      "signature verification",
      "rate limiter",
      "timelock enforcement",
    ]);
    const defenseDetail = rng.pick([
      `reverted all ${payloadCount} test calls consistently`,
      `blocked ${payloadCount} of my crafted calldata sequences`,
      `rejected unauthorized calls to \`${funcName}()\``,
      `responded with proper revert messages hiding implementation details`,
      `enforced strict access control on every call`,
      `rate-limited my ${toolName} scan after ${rng.int(3, 25)} calls`,
      `showed identical state outcomes across all ${payloadCount} payloads`,
      `rejected all malformed input in the \`${funcName}()\` function`,
    ]);
    const failFragA = rng.pick([
      `${toolName} against ${profile.contractName} on ${chainName}`,
      `sending ${payloadCount} payloads to \`${funcName}()\` on ${profile.contractAddress}`,
      `my ${toolName} assessment of ${profile.contractName}`,
      `testing the \`${funcName}()\` function via ${toolName} with ${gasUsed} gas`,
      `a ${payloadCount}-call ${toolName} probe of ${profile.contractAddress}`,
      `probing the \`${funcName}()\` handler at ${profile.contractAddress}`,
      `fuzzing \`${funcName}()\` on ${chainName} with ${toolName}`,
      `${toolName} enumeration of ${profile.contractAddress} targeting \`${funcName}()\``,
    ]);
    const failFragB = rng.pick([
      `the ${defenseType} ${defenseDetail}`,
      `the \`${funcName}()\` function proved resilient because the ${defenseType} ${defenseDetail}`,
      `the ${profile.contractName} contract's ${defenseType} effectively ${defenseDetail}`,
      `the function's ${defenseType} on ${chainName} ${defenseDetail}`,
    ]);
    const failFragC = rng.pick([
      `This is a dead end for this specific technique — I need to pivot.`,
      `The ${defenseType} is effective, but there may be bypass methods I haven't tried.`,
      `Good defense here, but I'll look for gaps in adjacent functions.`,
      `This tells me the developers are security-aware — I need a more creative approach.`,
      `The defense blocks this vector, but the revert reveals useful information about the ${defenseType} implementation.`,
      `I'll document this as a positive finding for the protocol's security posture and try alternative techniques.`,
    ]);
    opening = `${rng.pick(["After", "Running", "Based on", "Through", "Via", "Following", "During", "From"])} ${failFragA}, I found that ${failFragB}. ${failFragC}`;
  }

  // Generate body
  const body = isFailure
    ? generateFailureAnalysis(rng, phase, profile)
    : generateSuccessAnalysis(rng, phase, profile);

  // Dynamic next steps
  const nextAction = variateText(phase.next_action, profile.protocolName, profile);
  const nextStepFormats = [
    `**Next step:** ${nextAction}`,
    `**Moving forward:** Based on these results, I'll ${nextAction.charAt(0).toLowerCase() + nextAction.slice(1)}.`,
    `**Action plan:** ${nextAction}. I'll also ${rng.pick(["check for related issues on adjacent functions", "verify the finding with an alternative tool", "look for ways to chain this with other findings", "document the evidence for the audit report"])}.`,
    `**What I'll do next:** ${nextAction}. My hypothesis is that ${rng.pick(["the same pattern exists in other functions", "this can be escalated further", "combining this with the earlier finding will increase severity", "the development team reused this vulnerable pattern in other contracts"])}.`,
    `**Recommended next action:** ${nextAction}`,
    `I'll proceed to ${nextAction.charAt(0).toLowerCase() + nextAction.slice(1)}. Based on the ${profile.inheritanceChain.join(" / ")} architecture, ${rng.pick(["the most promising next target is the admin function", "I expect the internal helpers will share this vulnerability", "the linked contracts are likely reachable from here", "there may be additional state I can manipulate"])}.`,
  ];

  return `${rng.pick(headerStyles)}\n\n${opening}\n\n${body}\n\n${rng.pick(nextStepFormats)}`;
}

// ============================================================
// Success Analysis
// ============================================================

export function generateSuccessAnalysis(
  rng: SeededRNG,
  phase: AttackPhase,
  profile: ContractProfile
): string {
  const funcName = rng.pick(profile.externalFunctions).name;
  const stateVar = rng.pick(profile.stateVariables);
  const solidityVer = profile.solidityVersion;
  const chainName = getChainName(profile.chainId);

  let analysis = phase.analysis
    .replace(/\{contractName\}/g, profile.contractName)
    .replace(/\{protocolName\}/g, profile.protocolName)
    .replace(/\{funcName\}/g, funcName)
    .replace(/\{stateVar\}/g, stateVar.name)
    .replace(/\{solidityVersion\}/g, solidityVer)
    .replace(/\{chainName\}/g, chainName)
    .replace(/\{contractAddress\}/g, profile.contractAddress)
    .replace(/\{tvl\}/g, profile.tvl)
    .replace(/\{tokenPrice\}/g, profile.tokenPrice)
    .replace(/\{affectedToken\}/g, profile.affectedToken)
    .replace(/\{vulnType\}/g, profile.vulnType)
    .replace(/\{severity\}/g, profile.severity);

  const extras: string[] = [];

  // Hypothesis-driven reasoning
  if (rng.bool(0.65)) {
    extras.push(
      `\n\n**Hypothesis validation:** I initially hypothesized that \`${funcName}()\` would be vulnerable because ${rng.pick([
        "the state transition logic suggested unchecked external calls",
        "the gas pattern varied with different input sizes indicating non-standard computation",
        "the contract reflects caller-supplied values in state without intermediate validation",
        `Solidity ${solidityVer} contracts commonly have this issue when using unchecked blocks`,
        "the interface documentation mentioned this function interacts with external oracles",
      ])}. The test results confirm this hypothesis — the function is indeed ${rng.pick([
        "exploitable via reentrancy",
        "missing critical access control",
        "susceptible to price manipulation",
        "passing user values directly to the state update without bounds checking",
      ])}.`,
    );
  }

  // Technical context
  if (rng.bool(0.5)) {
    extras.push(
      `\n\nThe ${profile.inheritanceChain.join(" / ")} inheritance chain is relevant because ${rng.pick([
        `this inheritance pattern has known edge cases in how modifiers are applied during external calls`,
        `the default access control in ${profile.inheritanceChain[0] || "Ownable"} doesn't cover all privileged paths`,
        `error handling in this pattern tends to expose internal state on revert`,
        `the modifier chain can be bypassed using specific call patterns`,
        `${chainName}'s block structure makes this exploitable within a single transaction`,
        `the upgradeable proxy pattern introduces additional storage slots that may collide`,
      ])}.`,
    );
  }

  // Inline PoC code
  if (rng.bool(0.45)) {
    const otherFunc = rng.pick(profile.externalFunctions.filter(f => f.name !== funcName) || profile.externalFunctions).name;
    const exploitBlocks = [
      `\n\nI wrote a quick Foundry PoC to confirm the finding:\n\n\`\`\`solidity\n// SPDX-License-Identifier: MIT\npragma solidity ^${solidityVer};\n\nimport "forge-std/Test.sol";\nimport "../src/${profile.contractName}.sol";\n\ncontract ${profile.contractName}_PoC is Test {\n    ${profile.contractName} public target;\n    address public attacker = address(0xdead);\n\n    function setUp() public {\n        target = new ${profile.contractName}();\n        vm.deal(attacker, ${rng.int(1, 100)} ether);\n        vm.prank(attacker);\n    }\n\n    function testExploit() public {\n        uint256 before = target.${stateVar.name}();\n        \n        // Exploit: call \`${funcName}()\` with crafted args\n        vm.prank(attacker);\n        target.${funcName}(${rng.int(0, 999)});\n        \n        uint256 after = target.${stateVar.name}();\n        assertGt(after, before, "State should change in attacker's favor");\n        \n        console.log("Before:", before);\n        console.log("After:", after);\n        console.log("Profit:", after - before);\n    }\n}\n\`\`\`\n\nThe test confirmed the invariant violation.`,

      `\n\nTo automate the extraction, I wrote an Echidna property:\n\n\`\`\`solidity\n// Echidna invariant test\nfunction echidna_noUnlimitedMint() public view returns (bool) {\n    uint256 totalSupply = target.${stateVar.name}();\n    // ${profile.protocolName} should not allow minting beyond ${profile.tvl}\n    return totalSupply <= ${rng.int(1000, 100000)} ether;\n}\n\`\`\`\n\nEchidna found ${rng.int(3, 20)} counterexamples in under ${rng.int(1, 30)} seconds, confirming the ${profile.vulnType} vulnerability.`,

      `\n\nCast call to reproduce on-chain:\n\n\`\`\`bash\n# Fork ${chainName} at latest block\nforge test --match-contract ${profile.contractName}_PoC \\\n  --fork-url https://${chainName.toLowerCase().replace(" ", "-")}.llamarpc.com \\\n  --fork-block-number ${rng.int(19000000, 20500000)} \\\n  -vvv\n\n# Direct cast call to verify\ncast call ${profile.contractAddress} \\\n  "${funcName}(${rng.pick(profile.externalFunctions).params.join(",")})" \\\n  --rpc-url https://${chainName.toLowerCase().replace(" ", "-")}.llamarpc.com\n\`\`\`\n\nThis confirmed the vulnerability on the live ${chainName} state.`,

      `\n\nQuick PoC demonstrating the impact:\n\n\`\`\`solidity\nfunction testFullExploit() public {\n    // 1. Setup: Attacker deposits minimal amount\n    vm.prank(attacker);\n    target.${funcName}(${rng.pick(["1", "0.001 ether", "100"])});\n    \n    // 2. Exploit: Drain via ${profile.vulnType}\n    vm.prank(attacker);\n    target.${otherFunc}(${rng.pick(["type(uint256).max", "attacker.balance", "1"])});\n    \n    // 3. Verify: Attacker gained funds\n    uint256 attackerBalance = target.balances(attacker);\n    assertGt(attackerBalance, ${rng.int(100, 10000)} ether);\n    \n    console.log("Protocol TVL:", ${profile.tvl});\n    console.log("Attacker extracted:", attackerBalance);\n}\n\`\`\``,
    ];
    extras.push(rng.pick(exploitBlocks));
  }

  // Risk context
  if (rng.bool(0.4)) {
    extras.push(
      `\n\n${rng.pick([
        `From a risk perspective, this finding affects approximately ${profile.tvl} in TVL. The attack complexity is ${profile.exploitComplexity} and requires ${profile.requiresCapital > 0 ? profile.requiresCapital.toLocaleString() + " wei" : "no upfront capital"}.`,
        `This is a systemic issue — the same vulnerable pattern likely exists across ${rng.int(2, 8)} other functions that use the same ${rng.pick(["internal helper", "modifier chain", "oracle fetch pattern", "state update logic"])}.`,
        `The combination of Solidity ${solidityVer} and the ${profile.inheritanceChain.join(" / ")} pattern makes this exploitable with standard Foundry tooling. No custom exploit development is needed.`,
        `Without remediation, an attacker could drain the contract — I estimate full extraction of the ${profile.tvl} TVL would take a single transaction on ${chainName}.`,
        `This vulnerability has been present since the contract was deployed. Based on the current ${profile.tokenPrice} ${profile.affectedToken} price and ${profile.tvl} TVL, the maximum extractable value is significant.`,
      ])}`,
    );
  }

  // Tool verification
  if (rng.bool(0.35)) {
    const toolMention = rng.pick(phase.tools);
    extras.push(
      `\n\n${rng.pick([
        `I verified this using both ${toolMention} (automated) and manual Foundry tests. Both approaches produced consistent results, confirming this is a true positive.`,
        `The ${toolMention} scanner initially flagged this. I then manually confirmed it by crafting ${rng.int(3, 10)} targeted test cases to rule out false positives.`,
        `${toolMention} reported ${rng.int(1, 5)} findings on this contract. After manual triage, ${rng.int(1, 3)} are confirmed exploitable vulnerabilities.`,
      ])}`,
    );
  }

  return analysis + extras.join("");
}

// ============================================================
// Failure Analysis
// ============================================================

export function generateFailureAnalysis(
  rng: SeededRNG,
  phase: AttackPhase,
  profile: ContractProfile
): string {
  const funcName = rng.pick(profile.externalFunctions).name;
  const chainName = getChainName(profile.chainId);

  const failureReasons = [
    `The contract's access control caught my test calls. The ${profile.inheritanceChain.join(" / ")} pattern appears to have proper protection against this specific attack class.`,
    `A reentrancy guard or modifier is blocking/blocking my crafted calls before they reach the vulnerable logic. I observed ${rng.pick([
      "revert with 'ReentrancyGuard: reentrant call'",
      "revert with 'AccessControl: access denied'",
      "revert with 'Ownable: caller is not the owner'",
      "revert with 'Pausable: paused'",
    ])}.`,
    `The function returned consistent state regardless of my crafted calldata, suggesting the parameters are properly ${rng.pick([
      "validated before use",
      "bounded by checks",
      "verified against expected ranges",
      "guarded by a modifier",
    ])}.`,
    `The ${chainName} fork simulation showed the transaction reverts for all my test inputs. The contract implements proper ${rng.pick([
      "input validation",
      "oracle staleness checks",
      "signature verification",
      "slippage protection",
    ])}.`,
    `The gas usage is consistent across all test calls, ruling out path-dependent execution. The contract appears to use ${rng.pick([
      "proper bounds checking",
      "safe math operations",
      "a well-audited library",
      "a security middleware layer",
    ])}.`,
    `The contract correctly validates \`msg.sender\` and rejects unauthorized calls. The security modifiers (${rng.pick([
      "onlyOwner",
      "onlyRole",
      "nonReentrant",
      "whenNotPaused",
    ])}) are also properly applied.`,
    `No exploitable state change was found. The contract appears to use a modern ${profile.inheritanceChain.join(" / ")} pattern with proper safeguards.`,
  ];

  let analysis = rng.pick(failureReasons);

  analysis += `\n\n${rng.pick([
    "This doesn't mean the contract is fully secure — it means this specific attack vector is mitigated. I'll adjust my approach and try alternative techniques.",
    "The failure is informative. It tells me the developers have implemented at least basic security controls. I need to find gaps in their coverage.",
    "I'll document this negative result in the audit report. It's important to note what defenses ARE working, not just what's broken.",
    "This is a good sign for the protocol's security posture, but I'll continue testing with more creative approaches.",
    "The defense is effective against this specific technique, but there may be bypass methods I haven't tried yet.",
  ])}`;

  analysis += `\n\n**Pivot plan:** ${rng.pick([
    "I'll try the same vulnerability class with different call patterns to bypass the modifier.",
    "I'll test adjacent functions that might share vulnerable code but lack the same protection.",
    "I'll switch to manual invariant testing with Foundry instead of automated scanning.",
    `I'll write a custom Foundry test to test edge cases that ${rng.pick(phase.tools)} might miss.`,
    "I'll test using different function selectors — sometimes only one code path is properly guarded.",
    "I'll look for second-order vulnerabilities where the state change is triggered in a different context.",
    `I'll check if the ${rng.pick(["governance contract", "treasury", "bridge adapter", "oracle aggregator"])} has the same protection.`,
  ])}`;

  return analysis;
}

// ============================================================
// Deep Analysis Generator (for padding conversations)
// ============================================================

export function generateDeepAnalysis(profile: ContractProfile, rng: SeededRNG): string {
  const funcName = rng.pick(profile.externalFunctions).name;
  const stateVar = rng.pick(profile.stateVariables);
  const chainName = getChainName(profile.chainId);
  const solidityVer = profile.solidityVersion;

  const sections: string[] = [];

  // Section 1: Architectural observation
  sections.push(
    `Looking at ${profile.contractName}'s architecture, the ${profile.inheritanceChain.join(" → ")} inheritance chain reveals the security model. The contract manages ${profile.stateVariables.length} state variables and exposes ${profile.externalFunctions.length} external functions. With ${profile.tvl} TVL and ${profile.affectedToken} trading at ${profile.tokenPrice}, any vulnerability here carries significant financial risk.`,
  );

  // Section 2: Function-level analysis
  sections.push(
    `The \`${funcName}()\` function (visibility: external, modifiers: [${rng.pick(profile.externalFunctions).modifiers.join(", ")}]) is a prime candidate for deeper analysis. It operates on \`${stateVar.name}\` (${stateVar.type}, ${stateVar.visibility}) and the ${profile.vulnType} pattern suggests ${rng.pick([
      "the state update ordering may allow reentrancy between the external call and the balance update",
      "the access control modifier may not cover all code paths that modify critical state",
      "the oracle price fetch may be manipulable within a single block on " + chainName,
      "the signature verification may be missing chainId binding, enabling cross-chain replay",
      "the rounding in the share calculation may systematically favor the caller over the protocol",
    ])}.`,
  );

  // Section 3: Exploitation assessment
  sections.push(
    `Exploitation complexity: **${profile.exploitComplexity}**. ${profile.exploitComplexity === "trivial"
      ? "Any external caller can trigger this in a single transaction."
      : profile.exploitComplexity === "moderate"
        ? "Requires crafting specific input sequences but no flash loan or complex setup."
        : "Requires multi-transaction setup, possibly involving a flash loan and multiple contract interactions."
    } Required capital: ${profile.requiresCapital > 0 ? profile.requiresCapital.toLocaleString() + " wei" : "none"}. PoC type: **${profile.pocType}**.`,
  );

  // Section 4: Impact assessment
  sections.push(
    `If exploited, the ${profile.impactType} could affect the entire ${profile.protocolName} protocol. Given the ${profile.tvl} TVL on ${chainName}, a successful exploit could result in losses exceeding ${rng.pick(["$100K", "$500K", "$1M", "$5M", "$10M", "$50M"])}. The ${profile.severity.toLowerCase()} severity is justified by the combination of impact and exploitability.`,
  );

  // Section 5: Remediation
  const fixOptions = [
    `Add a \`${rng.pick(["nonReentrant", "onlyOwner", "onlyRole(ADMIN_ROLE)", "whenNotPaused"])}\` modifier to \`${funcName}()\` and reorder state updates to follow the checks-effects-interactions pattern.`,
    `Implement proper input validation for the \`${stateVar.name}\` parameter, ensuring values are within expected bounds before state modification.`,
    `Add oracle staleness checks before using price data, and implement a time-weighted average price (TWAP) to resist manipulation.`,
    `Bind signatures to \`block.chainid\` to prevent cross-chain replay attacks, and ensure each signature can only be consumed once.`,
    `Use SafeCast or explicit overflow checks for all arithmetic operations involving user-supplied values.`,
  ];
  sections.push(`Recommended fix: ${rng.pick(fixOptions)}`);

  return sections.join("\n\n");
}
