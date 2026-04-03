// Smart contract audit report generation for Dataset Generator V2

import { SeededRNG, ContractProfile, generateContractProfile } from "../outputs/index.js";
import { ScenarioTemplate } from "../../templates/scenarios/index.js";
import { variateText } from "./responses.js";

/* ============================================================
   Severity mapping — difficulty maps to realistic CVSS scores
   ============================================================ */
const severityMap: Record<string, string[]> = {
  beginner: ["Medium (5.3)", "Medium (4.7)"],
  intermediate: ["High (7.5)", "High (7.2)", "High (8.1)"],
  advanced: ["Critical (9.1)", "Critical (8.8)", "Critical (9.4)"],
  expert: ["Critical (9.8)", "Critical (9.6)", "Critical (10.0)"],
};

/* ============================================================
   SWC / CWE reference tables by vulnerability type
   ============================================================ */
const swcMap: Record<string, string[]> = {
  "reentrancy": ["SWC-107"],
  "unauthorized-mint": ["SWC-105"],
  "access-control-bypass": ["SWC-105", "SWC-119"],
  "integer-overflow": ["SWC-101"],
  "rounding-precision": ["SWC-118", "SWC-128"],
  "signature-replay": ["SWC-121", "SWC-117"],
  "storage-collision": ["SWC-124"],
  "oracle-manipulation": ["SWC-132"],
  "logic-error": ["SWC-102"],
  "fee-bypass": ["SWC-118", "SWC-131"],
  "initialization-missing": ["SWC-100", "SWC-112"],
  "timelock-bypass": ["SWC-114", "SWC-116"],
  "cross-chain-replay": ["SWC-121", "SWC-120"],
  "dos-griefing": ["SWC-113"],
  "mev-front-running": ["SWC-114"],
  "decimal-mismatch": ["SWC-118", "SWC-128"],
};

const cweMap: Record<string, string[]> = {
  "reentrancy": ["CWE-841"],
  "unauthorized-mint": ["CWE-863", "CWE-284"],
  "access-control-bypass": ["CWE-863", "CWE-284"],
  "integer-overflow": ["CWE-190"],
  "rounding-precision": ["CWE-682", "CWE-1339"],
  "signature-replay": ["CWE-344", "CWE-841"],
  "storage-collision": ["CWE-1242"],
  "oracle-manipulation": ["CWE-345", "CWE-916"],
  "logic-error": ["CWE-840", "CWE-682"],
  "fee-bypass": ["CWE-682", "CWE-1339"],
  "initialization-missing": ["CWE-908", "CWE-909"],
  "timelock-bypass": ["CWE-362", "CWE-667"],
  "cross-chain-replay": ["CWE-344", "CWE-841"],
  "dos-griefing": ["CWE-400", "CWE-664"],
  "mev-front-running": ["CWE-362", "CWE-367"],
  "decimal-mismatch": ["CWE-682", "CWE-1339"],
};

const defaultSWC = ["SWC-102"];
const defaultCWE = ["CWE-840"];

/* ============================================================
   Financial quantification helper
   ============================================================ */
function quantifiedImpact(rng: SeededRNG, tvl: string, tokenPrice: string, vulnType: string): { dollarAmount: string; impactDescription: string } {
  const tvlNum = parseFloat(tvl.replace(/[$MB]/g, "").replace(/B/g, "")) * (tvl.includes("B") ? 1000 : tvl.includes("M") ? 1 : 1);
  const priceNum = parseFloat(tokenPrice.replace(/[$,]/g, ""));

  const theftPct = rng.pick([1.0, 2.5, 5.0, 8.3, 12.5, 15.0, 25.0, 50.0, 75.0, 100.0]);
  const dollarLoss = (tvlNum * theftPct / 100);
  const formattedLoss = dollarLoss >= 1000
    ? `$${(dollarLoss / 1000).toFixed(1)}B`
    : `$${Math.round(dollarLoss)}M`;

  const impactDescriptions = rng.pick([
    `An attacker could drain approximately ${formattedLoss} in TVL from the protocol, representing ${theftPct.toFixed(1)}% of total locked value. At current ${rng.pick(["token", "LP", "staking"])} prices, this equates to ~${Math.round(dollarLoss / priceNum).toLocaleString()} tokens stolen.`,
    `The vulnerability allows extraction of ${formattedLoss} from the ${rng.pick(["liquidity pool", "vault", "staking contract", "bridge"])} — roughly ${theftPct.toFixed(1)}% of protocol TVL. Given the ${tokenPrice} token price, the attack yields approximately ${Math.round(dollarLoss / priceNum).toLocaleString()} tokens.`,
    `Full exploitation results in a loss of ${formattedLoss}, equivalent to ${theftPct.toFixed(1)}% of the protocol's ${tvl} TVL. The attacker would receive ~${Math.round(dollarLoss / priceNum).toLocaleString()} ${rng.pick(["tokens", "assets"])} at the current price of ${tokenPrice}.`,
    `Estimated maximum extractable value: ${formattedLoss} (${theftPct.toFixed(1)}% of ${tvl} TVL). Converted at ${tokenPrice}/token, the attacker gains ~${Math.round(dollarLoss / priceNum).toLocaleString()} tokens.`,
  ]);

  return { dollarAmount: formattedLoss, impactDescription: impactDescriptions };
}

/* ============================================================
   CVSS 3.1 vector generator for smart contracts
   ============================================================ */
function generateCVSSVector(rng: SeededRNG, vulnType: string, complexity: string): string {
  const av = "N"; // always network-accessible
  const ac = (complexity === "complex" || vulnType === "mev-front-running") ? "H" : "L";
  const pr = rng.pick(["N", "L", "L"]);
  const ui = rng.pick(["N", "N", "N", "R"]);
  const s = rng.pick(["C", "C", "U"]);
  const c = rng.pick(["H", "H", "L"]);
  const i = rng.pick(["H", "H", "L"]);
  const a = rng.pick(["H", "H", "L"]);
  return `CVSS:3.1/AV:${av}/AC:${ac}/PR:${pr}/UI:${ui}/S:${s}/C:${c}/I:${i}/A:${a}`;
}

/* ============================================================
   SWC description generator
   ============================================================ */
function swcDescription(vulnType: string): string {
  const descriptions: Record<string, string> = {
    "reentrancy": "External call made before state update allows recursive re-entry, enabling the attacker to repeatedly invoke the function and drain funds.",
    "unauthorized-mint": "The mint function lacks proper access control, allowing any address to call it and inflate the token supply without authorization.",
    "access-control-bypass": "Missing or incorrectly implemented access control modifier permits unauthorized addresses to execute privileged functions.",
    "integer-overflow": "Arithmetic operations lack overflow protection (Solidity <0.8.0 without SafeMath), enabling wraparound to manipulate balances or totals.",
    "rounding-precision": "Integer division truncation causes systematic rounding errors that can be exploited to extract excess value on each operation.",
    "signature-replay": "ECDSA signature verification does not enforce uniqueness via nonce or tracking, allowing the same signature to be replayed for multiple operations.",
    "storage-collision": "Proxy and implementation contract storage layouts conflict, causing state variable overlap that can corrupt critical data or bypass access controls.",
    "oracle-manipulation": "The price oracle uses a manipulable data source (e.g., spot price from a low-liquidity pool), allowing the attacker to artificially inflate or deflate asset valuations.",
    "logic-error": "A flaw in the business logic creates an unintended code path that bypasses expected invariants, enabling unauthorized operations.",
    "fee-bypass": "The fee calculation or collection mechanism can be circumvented through specific input patterns or arithmetic edge cases, causing protocol revenue loss.",
    "initialization-missing": "The proxy or upgradeable contract's initialize() function is not called or lacks proper access control, leaving the contract in an uninitialized state exploitable by any caller.",
    "timelock-bypass": "The timelock mechanism can be bypassed through direct function calls, proposal cancellation, or exploiting the governance upgrade path.",
    "cross-chain-replay": "Messages or signatures valid on one chain can be replayed on another chain due to missing chainId binding or per-chain nonce tracking.",
    "dos-griefing": "An attacker can cause a denial of service or grief other users by exploiting unbounded loops, block gas limits, or forced Ether sends.",
    "mev-front-running": "Transaction ordering dependency allows miners/validators or MEV bots to front-run or sandwich user transactions for profit.",
    "decimal-mismatch": "Token decimal places are incorrectly assumed or mismatched between contracts, causing calculations to be off by orders of magnitude.",
  };
  return descriptions[vulnType] || `A security-critical check is missing in the contract's logic, allowing an attacker to exploit the ${vulnType} vulnerability to bypass intended behavior.`;
}

/* ============================================================
   Public API: generateUniqueAuditReport
   ============================================================ */
export function generateUniqueAuditReport(scenario: ScenarioTemplate, profile: ContractProfile, rng: SeededRNG): string {
  const severity = rng.pick(severityMap[scenario.difficulty] || ["High (7.5)"]);
  const severityLabel = severity.split(" (")[0];
  const severityNum = parseFloat(severity.split("(")[1]?.replace(")", "") || "7.5");
  const vulnType = profile.vulnType;
  const swcs = swcMap[vulnType] || defaultSWC;
  const cwes = cweMap[vulnType] || defaultCWE;
  const cvssVector = generateCVSSVector(rng, vulnType, profile.exploitComplexity);
  const impact = quantifiedImpact(rng, profile.tvl, profile.tokenPrice, vulnType);

  const attackChainLines = scenario.attack_phases.map(
    (p, i) => `${i + 1}. **${p.phase}:** ${p.description}`
  ).join("\n");

  const reportStyles = [
    // Style 1: Full Professional Audit Report
    generateProfessionalReport(scenario, profile, severity, severityLabel, severityNum, cvssVector, swcs, cwes, vulnType, impact, attackChainLines, rng),
    // Style 2: Technical/Developer Report
    generateTechnicalReport(scenario, profile, severity, severityLabel, severityNum, cvssVector, swcs, cwes, vulnType, impact, attackChainLines, rng),
    // Style 3: Concise Bug Bounty Style
    generateBugBountyReport(scenario, profile, severity, severityLabel, severityNum, cvssVector, swcs, cwes, vulnType, impact, attackChainLines, rng),
  ];

  return rng.pick(reportStyles);
}

/* ============================================================
   Style 1: Full Professional Audit Report
   ============================================================ */
function generateProfessionalReport(
  scenario: ScenarioTemplate,
  profile: ContractProfile,
  severity: string,
  severityLabel: string,
  severityNum: number,
  cvssVector: string,
  swcs: string[],
  cwes: string[],
  vulnType: string,
  impact: { dollarAmount: string; impactDescription: string },
  attackChainLines: string,
  rng: SeededRNG,
): string {
  const pocCode = generatePoCSolidity(scenario, profile, vulnType, rng);
  const codeFix = generateSecureCodeFix(vulnType, rng);
  const affectedFunc = profile.externalFunctions.length > 0
    ? rng.pick(profile.externalFunctions)
    : { name: rng.pick(["stake", "withdraw", "claim", "mint", "bridge"]), visibility: "external", modifiers: [], params: [] };
  const stateVar = profile.stateVariables.length > 0 ? rng.pick(profile.stateVariables) : { name: "totalSupply", type: "uint256", visibility: "public" };

  return `**Smart Contract Audit Finding**

| Attribute | Detail |
|-----------|--------|
| **Severity** | ${severity} |
| **CVSS 3.1 Vector** | \`${cvssVector}\` |
| **SWC Reference** | ${swcs.join(", ")} |
| **CWE Reference** | ${cwes.join(", ")} |
| **Contract** | \`${profile.contractName}\` at \`0x${profile.contractAddress.slice(0, 10)}...\` |
| **Vulnerable Function** | \`${affectedFunc.name}()\` (${affectedFunc.visibility}) |
| **Affected State Variable** | \`${stateVar.name}\` (${stateVar.type}) |
| **Protocol** | ${profile.protocolName} (${rng.pick(["Ethereum", "Arbitrum", "Optimism", "Base", "Polygon", "BNB Chain"])} Chain ID: ${profile.chainId}) |
| **Solidity Version** | v${profile.solidityVersion} |
| **Protocol TVL** | ${profile.tvl} |
| **Token Price** | ${profile.tokenPrice} |

**Description:** ${variateText(swcDescription(vulnType), profile.protocolName, profile as any)}

The \`${affectedFunc.name}()\` function in \`${profile.contractName}\` is missing a ${profile.missingCheck}. This allows an attacker to ${rng.pick(["exploit the vulnerability", "bypass the intended access restrictions", "manipulate the contract state", "extract funds from the protocol"])}.

**Attack Chain:**

${attackChainLines}

**Evidence / Proof of Concept:**

\`\`\`solidity
${pocCode}
\`\`\`

**Impact:**

${impact.impactDescription}

- **Protocol TVL at Risk:** ${profile.tvl}
- **Token Price:** ${profile.tokenPrice}
- **Attack Capital Required:** ${profile.requiresCapital > 0 ? `$${profile.requiresCapital.toLocaleString()}` : "No capital required — anyone can trigger this"}
- **Exploit Complexity:** ${profile.exploitComplexity}
- **Reproducibility:** ${rng.pick(["100% reproducible", "Deterministic with no external dependencies", "Reproducible on a mainnet fork"])}

**Remediation:**

${codeFix}

\`\`\`solidity
${generateSecureCodeFix(vulnType, rng)}
\`\`\`

**Additional Recommendations:**

1. ${rng.pick([`Add comprehensive unit tests covering the \`${affectedFunc.name}()\` function with edge cases for ${vulnType} scenarios.`, `Implement an invariant test using Echidna or Foundry to verify that the protocol's core invariants hold after this fix.`, `Add a Foundry fork test against mainnet state to confirm the fix prevents exploitation under realistic conditions.`])}
2. ${rng.pick(["Engage an external auditor to verify the remediation before deploying to mainnet.", "Run the fix through Slither, Mythril, and other automated analysis tools to confirm no regressions.", "Consider adding a formal verification layer using Certora or the Solidity SMTChecker for critical invariants."])}
3. ${rng.pick(["Deploy the fix through the protocol's timelock and governance process with a 48-hour delay for community review.", "Coordinate the upgrade with the protocol's multi-sig signers and ensure all stakeholders are aware of the security implications.", "Implement the fix as a minimal proxy patch if the contract is upgradeable, avoiding a full redeployment where possible."])}`;
}

/* ============================================================
   Style 2: Technical/Developer Report
   ============================================================ */
function generateTechnicalReport(
  scenario: ScenarioTemplate,
  profile: ContractProfile,
  severity: string,
  severityLabel: string,
  severityNum: number,
  cvssVector: string,
  swcs: string[],
  cwes: string[],
  vulnType: string,
  impact: { dollarAmount: string; impactDescription: string },
  attackChainLines: string,
  rng: SeededRNG,
): string {
  const affectedFunc = profile.externalFunctions.length > 0 ? rng.pick(profile.externalFunctions) : { name: rng.pick(["stake", "withdraw", "claim", "mint"]), visibility: "external", modifiers: [], params: [] };
  const foundryTest = generateFoundryTest(scenario, profile, vulnType, rng);
  const gasAnalysis = generateGasAnalysis(vulnType, rng);
  const lineRefStart = rng.int(45, 320);
  const lineRefEnd = lineRefStart + rng.int(8, 45);

  return `## ${scenario.title} — ${severity}

**Contract:** \`${profile.contractName}.sol\` | **Function:** \`${affectedFunc.name}()\` | **Lines:** ${lineRefStart}-${lineRefEnd}

**CVSS 3.1:** \`${cvssVector}\` → Score: ${severityNum} (${severityLabel})
**SWC:** ${swcs.join(", ")} | **CWE:** ${cwes.join(", ")}
**Chain:** ${rng.pick(["Ethereum", "Arbitrum", "Optimism", "Base"])} (Chain ID: ${profile.chainId}) | **Solidity:** v${profile.solidityVersion}

### Vulnerability

The \`${affectedFunc.name}()\` function (line ${lineRefStart}) is missing ${profile.missingCheck}. The function performs ${rng.pick(["an external call before updating the relevant state", "no access control check on the caller", "an unchecked arithmetic operation that can overflow", "a division before multiplication causing precision loss", "signature verification without replay protection"])} at line ${rng.int(lineRefStart + 2, lineRefEnd - 5)}.

Key state variables involved:
${profile.stateVariables.slice(0, 4).map(sv => `- \`${sv.name}\` (\`${sv.type}\`, ${sv.visibility}, slot ${rng.int(0, 25)})`).join("\n")}

### Reproduction Steps

1. **Setup:** Deploy \`${profile.contractName}\` on a ${profile.pocType === "fork" ? "mainnet fork at block " + rng.int(19000000, 20000000) : "local testnet"} with ${profile.tvl} TVL simulation.
2. **Precondition:** ${rng.pick(["Ensure the caller is not the owner or authorized address", "Fund the attacker address with a minimal amount of ETH", "Set up the oracle to return a manipulated price", "Prepare a valid but reusable ECDSA signature"])}
3. **Exploit:** Call \`${affectedFunc.name}(${affectedFunc.params.join(", ")})\` ${rng.pick(["with crafted input parameters", "from an unauthorized address", "multiple times in the same transaction", "with a specially crafted calldata payload"])}.
4. **Verify:** Assert that ${rng.pick(["the attacker's balance has increased beyond their deposit", "the total supply has been inflated without authorization", "the contract state has been corrupted", "the attacker gained unauthorized access"])} using \`assertGt\`.

### Foundry Test Output

\`\`\`solidity
${foundryTest}
\`\`\`

### Gas Analysis

${gasAnalysis}

### Attack Chain

${attackChainLines}

### Impact

${impact.impactDescription}

- **Max Extractable Value:** ${impact.dollarAmount}
- **Required Capital:** ${profile.requiresCapital > 0 ? `${profile.requiresCapital.toLocaleString()} USD` : "None"}
- **Gas Cost of Attack:** ~${rng.int(500000, 5000000).toLocaleString()} gas (${rng.int(15, 120)} ETH at current prices)

### Remediation

\`\`\`solidity
${generateSecureCodeFix(vulnType, rng)}
\`\`\`

**Fix Details:**
1. Add ${profile.missingCheck} to the \`${affectedFunc.name}()\` function signature.
2. Reorder operations to follow the ${vulnType === "reentrancy" ? "Checks-Effects-Interactions pattern" : "principle of least privilege"} — update state before external calls.
3. Add invariant tests: \`invariant totalSupplyConsistent()\` to prevent regression.
4. Run \`forge test --match-contract ${profile.contractName}Test -vvv\` to verify no tests break after the fix.`;
}

/* ============================================================
   Style 3: Concise Bug Bounty Style
   ============================================================ */
function generateBugBountyReport(
  scenario: ScenarioTemplate,
  profile: ContractProfile,
  severity: string,
  severityLabel: string,
  severityNum: number,
  cvssVector: string,
  swcs: string[],
  cwes: string[],
  vulnType: string,
  impact: { dollarAmount: string; impactDescription: string },
  attackChainLines: string,
  rng: SeededRNG,
): string {
  const affectedFunc = profile.externalFunctions.length > 0 ? rng.pick(profile.externalFunctions) : { name: rng.pick(["stake", "withdraw", "claim", "mint"]), visibility: "external", modifiers: [], params: [] };
  const minimalPoC = generateMinimalPoC(profile, vulnType, rng);

  return `**${scenario.title}**

| Field | Value |
|-------|-------|
| Severity | ${severity} |
| CVSS 3.1 | ${severityNum} (${cvssVector}) |
| SWC | ${swcs.join(", ")} |
| CWE | ${cwes.join(", ")} |
| Target | \`${profile.contractName}\` @ \`0x${profile.contractAddress.slice(0, 10)}...\` |
| Function | \`${affectedFunc.name}()\` |
| TVL | ${profile.tvl} |

**Brief:** ${variateText(swcDescription(vulnType), profile.protocolName, profile as any)}

**PoC:**

\`\`\`solidity
${minimalPoC}
\`\`\`

**Attack Chain:**

${scenario.attack_phases.map((p, i) => `${i + 1}. ${p.phase}`).join(" → ")}

**Impact:** ${impact.impactDescription} Estimated ${impact.dollarAmount} at risk from ${profile.tvl} TVL.

**Fix:** Add ${profile.missingCheck} to \`${affectedFunc.name}()\`:

\`\`\`solidity
${generateSecureCodeFix(vulnType, rng)}
\`\`\``;
}

/* ============================================================
   PoC code generators
   ============================================================ */
function generatePoCSolidity(scenario: ScenarioTemplate, profile: ContractProfile, vulnType: string, rng: SeededRNG): string {
  const affectedFunc = profile.externalFunctions.length > 0 ? rng.pick(profile.externalFunctions) : { name: "stake", visibility: "external", modifiers: [], params: ["uint256 amount"] };

  const pocTemplates: Record<string, () => string> = {
    "reentrancy": () => `// Foundry PoC: Reentrancy on ${profile.contractName}.${affectedFunc.name}()
function testReentrancyExploit() public {
    // Deploy the vulnerable contract
    ${profile.contractName} target = new ${profile.contractName}();
    
    // Deploy attacker contract with reentrancy callback
    ReentrancyExploiter exploiter = new ReentrancyExploiter(address(target));
    
    // Attacker deposits initial funds
    exploiter.deposit{value: 1 ether}();
    
    // Trigger the exploit — recursive withdraw
    exploiter.exploit();
    
    // Verify: attacker drained more than they deposited
    assertGt(address(exploiter).balance, 1 ether);
}

contract ReentrancyExploiter {
    ${profile.contractName} public target;
    bool private entered = false;
    
    constructor(address _target) {
        target = ${profile.contractName}(_target);
    }
    
    function deposit() external payable {
        target.stake{value: msg.value}();
    }
    
    function exploit() external {
        target.withdraw(1 ether);
    }
    
    // Callback — re-enter withdraw before state update
    receive() external payable {
        if (!entered && address(target).balance >= 1 ether) {
            entered = true;
            target.withdraw(1 ether);
        }
    }
}`,
    "unauthorized-mint": () => `// Foundry PoC: Unauthorized Mint on ${profile.contractName}
function testUnauthorizedMint() public {
    ${profile.contractName} target = new ${profile.contractName}();
    address attacker = address(0xBEEF);
    
    uint256 initialSupply = target.totalSupply();
    
    // Attacker calls mint without authorization
    vm.prank(attacker);
    target.mint(attacker, 1_000_000e18);
    
    // Verify: supply inflated without authorization
    assertGt(target.totalSupply(), initialSupply);
    assertEq(target.balanceOf(attacker), 1_000_000e18);
}`,
    "access-control-bypass": () => `// Foundry PoC: Access Control Bypass on ${profile.contractName}
function testAccessControlBypass() public {
    ${profile.contractName} target = new ${profile.contractName}();
    address attacker = makeAddr("attacker");
    
    // Attacker calls privileged function without role
    vm.prank(attacker);
    target.${affectedFunc.name}(${affectedFunc.params.map((_, i) => `param${i}`).join(", ")});
    
    // Verify: unauthorized state change occurred
    assertTrue(target.${rng.pick(["paused()", "owner() == attacker", "feeRate() == type(uint256).max"])});
}`,
    "integer-overflow": () => `// Foundry PoC: Integer Overflow on ${profile.contractName}
function testIntegerOverflow() public {
    ${profile.contractName} target = new ${profile.contractName}();
    
    // Craft input that causes overflow
    uint256 maxUint = type(uint256).max;
    target.${affectedFunc.name}(maxUint, 1);
    
    // Verify: overflow caused wraparound
    assertLt(target.${rng.pick(["totalSupply()", "balances(address(this))", "rewardIndex()"])}, maxUint);
}`,
    "rounding-precision": () => `// Foundry PoC: Rounding Precision on ${profile.contractName}
function testRoundingExploit() public {
    ${profile.contractName} target = new ${profile.contractName}();
    
    // Exploit rounding: deposit small amounts repeatedly
    for (uint256 i = 0; i < 100; i++) {
        target.${affectedFunc.name}(1);
        target.${rng.pick(["withdraw", "claim", "redeem"])}(1);
    }
    
    // Extracted excess through rounding accumulation
    uint256 profit = address(this).balance;
    assertGt(profit, 0, "Rounding error should accumulate");
}`,
    "signature-replay": () => `// Foundry PoC: Signature Replay on ${profile.contractName}
function testSignatureReplay() public {
    ${profile.contractName} target = new ${profile.contractName}();
    (address signer, uint256 key) = makeAddrAndKey("signer");
    
    // Build valid signature
    bytes32 digest = keccak256(abi.encodePacked(
        "\\x19Ethereum Signed Message:\\n32",
        keccak256(abi.encode(address(this), 1000e18, 1))
    ));
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, digest);
    bytes memory sig = abi.encodePacked(r, s, v);
    
    // Use signature once
    target.${affectedFunc.name}(1000e18, 1, sig);
    
    // Replay the SAME signature
    target.${affectedFunc.name}(1000e18, 2, sig);
    
    // Verify: replay succeeded (should have been blocked)
    assertEq(target.${rng.pick(["balanceOf(address(this))", "nonceOf(address(this))"])}, 2000e18);
}`,
    "storage-collision": () => `// Foundry PoC: Storage Collision on ${profile.contractName}
function testStorageCollision() public {
    // Deploy implementation and proxy
    Implementation impl = new Implementation();
    ${profile.contractName} proxy = ${profile.contractName}(
        address(new ERC1967Proxy(address(impl), ""))
    );
    
    // Slot 0 in proxy overlaps with slot 0 in implementation
    // Proxy's 'initialized' flag corrupts impl's 'owner'
    vm.store(address(proxy), bytes32(uint256(0)), bytes32(uint256(1)));
    
    // Verify: storage collision allows attacker to become owner
    assertEq(proxy.owner(), address(this));
}`,
    "oracle-manipulation": () => `// Foundry PoC: Oracle Manipulation on ${profile.contractName}
function testOracleManipulation() public {
    ${profile.contractName} target = new ${profile.contractName}();
    MockOracle oracle = new MockOracle();
    target.setOracle(address(oracle));
    
    // Manipulate oracle price
    oracle.setPrice(1_000_000e18); // Inflate price 1000x
    
    // Borrow against inflated collateral
    target.${affectedFunc.name}(1e18);
    
    // Verify: borrowed more than collateral warrants
    assertGt(target.${rng.pick(["debtOf(address(this))", "borrowedAmount()"])}, 1e18 * 100);
}`,
  };

  const generator = pocTemplates[vulnType];
  return generator ? generator() : `// Foundry PoC: ${vulnType} on ${profile.contractName}.${affectedFunc.name}()
function test${vulnType.split("-").map(s => s[0].toUpperCase() + s.slice(1)).join("")}Exploit() public {
    ${profile.contractName} target = new ${profile.contractName}();
    
    // Setup exploit conditions
    ${rng.pick([
      `address attacker = makeAddr("attacker");\n    vm.prank(attacker);`,
      `vm.warp(block.timestamp + ${rng.int(1, 365)} days);`,
      `deal(address(this), ${rng.int(1, 100)} ether);`,
    ])}
    
    // Trigger vulnerability
    target.${affectedFunc.name}(${affectedFunc.params.map((_, i) => `${rng.int(1, 100)}e18`).join(", ") || ""});
    
    // Verify exploit succeeded
    assertTrue(${rng.pick([
      "address(this).balance > initialBalance",
      "target.totalSupply() > initialSupply",
      "target.owner() == attacker",
      "target.paused() == true",
    ])});
}`;
}

function generateMinimalPoC(profile: ContractProfile, vulnType: string, rng: SeededRNG): string {
  const affectedFunc = profile.externalFunctions.length > 0 ? rng.pick(profile.externalFunctions) : { name: "stake", visibility: "external", modifiers: [], params: [] };

  const minimal: Record<string, string> = {
    "reentrancy": `// Call withdraw() — recursive call via receive()
attacker.withdraw(); // drains ${rng.int(100, 10000)}x deposit
require(attacker.balance > 100 ether);`,
    "unauthorized-mint": `// No modifier — anyone can mint
target.mint(attacker, 1_000_000e18);
assertGt(target.totalSupply(), initialSupply);`,
    "access-control-bypass": `// Missing access check
vm.prank(attacker);
target.${affectedFunc.name}();
// State changed without authorization`,
    "integer-overflow": `// Overflow: type(uint256).max + 1 = 0
target.${affectedFunc.name}(type(uint256).max, 1);
assertEq(target.balance(), 0); // wrapped`,
    "rounding-precision": `// Exploit truncation: (1 * 1e18) / 3 = 333... (loss per call)
for (uint i = 0; i < 100; i++) target.${affectedFunc.name}(1);
assertGt(attacker.balance, 100 ether);`,
    "signature-replay": `// Replay same sig — no nonce check
target.${affectedFunc.name}(1000e18, sig);
target.${affectedFunc.name}(2000e18, sig); // same sig, 2nd time succeeds`,
    "oracle-manipulation": `// Flash loan → manipulate spot price → borrow
oracle.setPrice(1_000_000e18);
target.borrow(1e18); // over-collateralized at fake price`,
  };

  return minimal[vulnType] || `// Exploit ${vulnType}
target.${affectedFunc.name}(${affectedFunc.params.map((_, i) => `arg${i}`).join(", ") || ""});
assertGt(attacker.${rng.pick(["balance", "balanceOf()", "tokensWithdrawn()"])}, initial);`;
}

/* ============================================================
   Foundry test output generator
   ============================================================ */
function generateFoundryTest(scenario: ScenarioTemplate, profile: ContractProfile, vulnType: string, rng: SeededRNG): string {
  const affectedFunc = profile.externalFunctions.length > 0 ? rng.pick(profile.externalFunctions) : { name: "stake", visibility: "external", modifiers: [], params: [] };
  const gasUsed = rng.int(150000, 2500000);
  const blockNumber = rng.int(19000000, 20500000);

  return `// forge test --match-contract ${profile.contractName}Test -vvv
// Foundry ${rng.pick(["v0.2.0", "v0.1.5", "v0.2.2"])} | solc ${profile.solidityVersion}

contract ${profile.contractName}Test is Test {
    ${profile.contractName} public target;
    address public attacker;
    
    function setUp() public {
        target = new ${profile.contractName}();
        attacker = makeAddr("attacker");
        deal(attacker, ${rng.int(10, 1000)} ether);
    }
    
    function test_${vulnType.replace(/-/g, "_")}_exploit() public {
        uint256 initial = address(this).balance;
        
        // ${rng.pick(["Step 1: Setup attack conditions", "Step 1: Prepare exploit calldata", "Step 1: Fund attacker contract"])}
        ${rng.pick([
          `vm.prank(attacker);`,
          `vm.warp(block.timestamp + ${rng.int(1, 7)} days);`,
          `vm.mockCall(address(target.oracle()), abi.encodeWithSelector(0x...), abi.encode(1_000_000e18));`,
        ])}
        
        // ${rng.pick(["Step 2: Execute the vulnerable function", "Step 2: Call the target function", "Step 2: Trigger the exploit"])}
        target.${affectedFunc.name}(${affectedFunc.params.map((p, i) => {
          if (p.includes("uint256")) return `${rng.int(1, 1000)}e18`;
          if (p.includes("address")) return `address(this)`;
          if (p.includes("bytes")) return `hex""`;
          return `"0"`;
        }).join(", ") || ""});
        
        // ${rng.pick(["Step 3: Verify the exploit succeeded", "Step 3: Assert profit extracted"])}
        uint256 profit = address(this).balance - initial;
        assertGt(profit, 0, "Exploit should extract value");
        emit log_named_uint("Profit extracted (wei)", profit);
    }
}

// === Test Output ===
// [PASS] test_${vulnType.replace(/-/g, "_")}_exploit() (gas: ${gasUsed.toLocaleString()})
// Logs:
//   Profit extracted (wei): ${rng.int(1e15, 1e20)}
// 
// Suite result: ok. 1 passed; 0 failed; 0 skipped
// Ran 1 test for ${profile.contractName}Test: 1 passed
// Finished in ${rng.int(1, 120)}ms
// Block: ${blockNumber.toLocaleString()}`;
}

/* ============================================================
   Gas analysis generator
   ============================================================ */
function generateGasAnalysis(vulnType: string, rng: SeededRNG): string {
  const normalGas = rng.int(45000, 250000);
  const exploitGas = normalGas + rng.int(50000, 1500000);

  const analyses: Record<string, string> = {
    "reentrancy": `- Normal \`${rng.pick(["withdraw", "claim", "redeem"])}()\`: ~${normalGas.toLocaleString()} gas
- Exploited reentrant call: ~${exploitGas.toLocaleString()} gas (${((exploitGas / normalGas - 1) * 100).toFixed(0)}% overhead from recursion)
- The gas overhead comes from repeated SSTORE/SLOAD operations on the same storage slot during recursive calls.`,
    "oracle-manipulation": `- Normal price query: ~${normalGas.toLocaleString()} gas
- Flash loan + price manipulation: ~${exploitGas.toLocaleString()} gas
- The attack gas cost is dominated by the flash loan callback and multiple swap operations.`,
  };

  return analyses[vulnType] || `- Normal function call: ~${normalGas.toLocaleString()} gas
- Exploited call: ~${exploitGas.toLocaleString()} gas
- Gas differential: +${(exploitGas - normalGas).toLocaleString()} gas from ${rng.pick(["additional SSTORE operations", "external contract calls", "loop iterations", "storage reads"])}

The gas cost is ${rng.pick(["well within the block gas limit, making the exploit practical", "low enough to be profitable even at high gas prices", "dominated by external calls rather than computation"])} at current ${rng.pick(["15", "25", "50"])} gwei.`;
}

/* ============================================================
   Public API: generateSecureCodeFix
   ============================================================ */
export function generateSecureCodeFix(vulnType: string, rng: SeededRNG): string {
  const fixes: Record<string, string[]> = {
    "reentrancy": [
      `// Fix: Apply Checks-Effects-Interactions pattern + ReentrancyGuard
contract ${rng.pick(["FixedContract", "SecureContract"])} is ReentrancyGuard {
    mapping(address => uint256) public balances;

    function withdraw(uint256 amount) external nonReentrant {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // EFFECTS: Update state BEFORE external call
        balances[msg.sender] -= amount;
        
        // INTERACTIONS: External call last
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
    }
}`,
      `// Fix: ReentrancyGuard with mutex
contract FixedContract {
    uint256 private _status;
    mapping(address => uint256) public balances;

    modifier nonReentrant() {
        require(_status == 0, "Reentrant call");
        _status = 1;
        _;
        _status = 0;
    }

    function withdraw(uint256 amount) external nonReentrant {
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }
}`,
    ],
    "unauthorized-mint": [
      `// Fix: Add onlyNewEpoch or role-based access control
contract FixedContract is AccessControl {
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    uint256 public lastMintEpoch;

    modifier onlyNewEpoch() {
        uint256 currentEpoch = block.timestamp / 1 weeks;
        require(currentEpoch > lastMintEpoch, "Already minted this epoch");
        _;
    }

    function mint(address to, uint256 amount) 
        external 
        onlyRole(MINTER_ROLE) 
        onlyNewEpoch 
    {
        lastMintEpoch = block.timestamp / 1 weeks;
        _mint(to, amount);
    }
}`,
      `// Fix: Only owner can mint with rate limit
contract FixedContract is Ownable {
    uint256 public constant MAX_MINT_PER_EPOCH = 1_000_000e18;
    uint256 public mintedThisEpoch;
    uint256 public epochTimestamp;

    function mint(address to, uint256 amount) external onlyOwner {
        require(block.timestamp >= epochTimestamp + 1 weeks, "Wait for next epoch");
        require(amount <= MAX_MINT_PER_EPOCH, "Exceeds epoch cap");
        
        if (block.timestamp > epochTimestamp + 1 weeks) {
            epochTimestamp = block.timestamp;
            mintedThisEpoch = 0;
        }
        mintedThisEpoch += amount;
        _mint(to, amount);
    }
}`,
    ],
    "integer-overflow": [
      `// Fix: Use Solidity 0.8+ built-in overflow checks or SafeMath
pragma solidity ^0.8.0;

contract FixedContract {
    function safeCalculation(uint256 a, uint256 b) external pure returns (uint256) {
        // Solidity 0.8+ automatically reverts on overflow
        return a + b;
    }

    function safeMultiply(uint256 a, uint256 b) external pure returns (uint256) {
        require(b == 0 || a <= type(uint256).max / b, "Overflow");
        return a * b;
    }
}`,
      `// Fix: For Solidity <0.8.0, use SafeMath
pragma solidity ^0.7.6;

import "@openzeppelin/contracts/math/SafeMath.sol";

contract FixedContract {
    using SafeMath for uint256;

    function safeCalculation(uint256 a, uint256 b) external pure returns (uint256) {
        return a.add(b); // Reverts on overflow
    }
}`,
    ],
    "rounding-precision": [
      `// Fix: Multiply before divide to minimize truncation
contract FixedContract {
    function calculateShare(uint256 amount, uint256 total, uint256 reward) 
        external 
        pure 
        returns (uint256) 
    {
        // WRONG: (amount / total) * reward  → truncates to 0
        // CORRECT: (amount * reward) / total
        return (amount * reward) / total;
    }

    function calculateShareWithPrecision(
        uint256 amount,
        uint256 total,
        uint256 reward
    ) external pure returns (uint256) {
        // Use higher precision intermediate calculation
        return (amount * reward * 1e18) / total;
    }
}`,
      `// Fix: Accumulate rounding errors and distribute remainder
contract FixedContract {
    uint256 public remainder;

    function distribute(uint256 total, uint256 recipients) external returns (uint256) {
        uint256 share = (total + remainder) / recipients;
        uint256 used = share * recipients;
        remainder = (total + remainder) - used;
        return share;
    }
}`,
    ],
    "signature-replay": [
      `// Fix: Add nonce tracking and used signatures mapping
contract FixedContract {
    mapping(address => uint256) public nonces;
    mapping(bytes32 => bool) public usedSignatures;

    function executeWithSig(
        address user,
        uint256 amount,
        uint256 nonce,
        bytes calldata signature
    ) external {
        require(nonce == nonces[user], "Invalid nonce");
        
        bytes32 digest = keccak256(abi.encodePacked(
            "\\x19Ethereum Signed Message:\\n32",
            keccak256(abi.encode(address(this), user, amount, nonce, block.chainid))
        ));
        
        require(!usedSignatures[digest], "Signature already used");
        
        address signer = recoverSigner(digest, signature);
        require(signer == user, "Invalid signature");
        
        usedSignatures[digest] = true;
        nonces[user]++;
        
        _execute(user, amount);
    }
}`,
    ],
    "storage-collision": [
      `// Fix: Use UUPSUpgradeable with proper storage layout
contract FixedContract is UUPSUpgradeable, AccessControlUpgradeable {
    // Use a storage prefix to avoid collisions
    bytes32 private constant STORAGE_SLOT = keccak256("FixedContract.storage.v1");

    struct Storage {
        address owner;
        uint256 totalSupply;
        mapping(address => uint256) balances;
        bool initialized;
    }

    function _getStorage() internal pure returns (Storage storage $) {
        bytes32 slot = STORAGE_SLOT;
        assembly { $.slot := slot }
    }

    function initialize() external initializer {
        __AccessControl_init();
        Storage storage s = _getStorage();
        s.owner = msg.sender;
        s.initialized = true;
    }
}`,
      `// Fix: Reserve storage slots in base contract
abstract contract BaseStorage {
    // Reserve slots to prevent collision with future upgrades
    uint256[50] private __gap;
}

contract FixedContract is BaseStorage, OwnableUpgradeable {
    uint256 public totalSupply;
    mapping(address => uint256) public balances;
    
    // Always add new variables at the END
    // Never remove or reorder existing variables
}`,
    ],
    "oracle-manipulation": [
      `// Fix: Use Time-Weighted Average Price (TWAP) instead of spot price
contract FixedContract {
    IUniswapV3Pool public constant pool = IUniswapV3Pool(0x...);

    function getSafePrice() public view returns (uint256) {
        // Use TWAP over 30 minutes — resistant to flash loan manipulation
        uint32[] memory secondsAgos = new uint32[](2);
        secondsAgos[0] = 1800; // 30 min ago
        secondsAgos[1] = 0;    // now

        (int56[] memory tickCumulatives, ) = pool.observe(secondsAgos);
        int24 tick = int24((tickCumulatives[1] - tickCumulatives[0]) / int56(uint56(1800)));
        
        return uint256(uint160(SqrtPriceMath.getSqrtRatioAtTick(tick)));
    }

    function borrow(uint256 amount) external {
        uint256 price = getSafePrice();
        require(price > 0, "Invalid price");
        // ... use TWAP price for collateral calculation
    }
}`,
    ],
    "logic-error": [
      `// Fix: Correct the business logic with proper invariant checks
contract FixedContract {
    function process(uint256 amount) external {
        require(amount > 0, "Amount must be positive");
        require(amount <= maxAllowed(), "Exceeds limit");
        
        // Correct logic flow:
        // 1. Validate inputs
        // 2. Check invariants
        // 3. Update state
        // 4. Emit events
        
        uint256 before = stateVariable;
        _unsafeProcess(amount);
        require(stateVariable >= before, "Invariant violated");
        
        emit Processed(msg.sender, amount);
    }
}`,
    ],
    "fee-bypass": [
      `// Fix: Enforce fee collection at the protocol level
contract FixedContract {
    uint256 public constant FEE_BPS = 25; // 0.25%
    uint256 public constant FEE_DENOMINATOR = 10000;

    function execute(uint256 amount) external {
        uint256 fee = (amount * FEE_BPS) / FEE_DENOMINATOR;
        require(fee > 0, "Fee too small");
        
        uint256 netAmount = amount - fee;
        
        // Collect fee BEFORE processing
        feeToken.transferFrom(msg.sender, treasury, fee);
        
        // Process net amount
        _process(netAmount);
    }
}`,
    ],
    "initialization-missing": [
      `// Fix: Add initializer with proper access control
contract FixedContract is Initializable, OwnableUpgradeable {
    function initialize(address _admin) external initializer {
        __Ownable_init();
        transferOwnership(_admin);
        _setupRole(DEFAULT_ADMIN_ROLE, _admin);
    }

    // Disable constructor for upgradeable contracts
    constructor() {
        _disableInitializers();
    }
}`,
    ],
    "timelock-bypass": [
      `// Fix: Enforce timelock on all privileged operations
contract FixedContract {
    ITimelock public immutable timelock;

    modifier onlyTimelock() {
        require(msg.sender == address(timelock), "Only timelock");
        _;
    }

    function executeUpgrade(address newImplementation) external onlyTimelock {
        _upgradeTo(newImplementation);
    }

    // All governance actions must go through timelock
    function propose(address target, uint256 value, bytes calldata data) external {
        require(msg.sender == address(governance), "Only governance");
        timelock.scheduleTransaction(target, value, data, delay);
    }
}`,
    ],
    "cross-chain-replay": [
      `// Fix: Include chainId and per-chain nonce in message hash
contract FixedContract {
    mapping(uint256 => mapping(address => uint256)) public chainNonces;

    function executeCrossChain(
        bytes calldata data,
        uint256 sourceChainId,
        bytes calldata signature
    ) external {
        // Bind to current chain to prevent replay
        uint256 nonce = chainNonces[sourceChainId][msg.sender]++;
        
        bytes32 digest = keccak256(abi.encodePacked(
            "\\x19Ethereum Signed Message:\\n32",
            keccak256(abi.encode(data, sourceChainId, block.chainid, nonce))
        ));
        
        address signer = recoverSigner(digest, signature);
        require(signer != address(0), "Invalid signature");
        
        _execute(data, signer);
    }
}`,
    ],
    "dos-griefing": [
      `// Fix: Add gas limits and pull-over-push pattern
contract FixedContract {
    mapping(address => uint256) public pendingWithdrawals;

    // Pull pattern — recipient claims their own funds
    function claim() external {
        uint256 amount = pendingWithdrawals[msg.sender];
        require(amount > 0, "Nothing to claim");
        pendingWithdrawals[msg.sender] = 0;
        payable(msg.sender).transfer(amount);
    }

    // Bounded loop — cap iterations
    function processBatch(uint256 maxItems) external {
        uint256 limit = maxItems > 50 ? 50 : maxItems;
        for (uint256 i = 0; i < limit; i++) {
            _process(i);
        }
    }
}`,
    ],
    "mev-front-running": [
      `// Fix: Commit-reveal pattern to prevent front-running
contract FixedContract {
    mapping(bytes32 => bool) public commitments;

    function commit(bytes32 commitment) external {
        require(!commitments[commitment], "Already committed");
        commitments[commitment] = true;
    }

    function reveal(
        uint256 amount,
        address target,
        bytes32 salt
    ) external {
        bytes32 commitment = keccak256(abi.encodePacked(amount, target, salt));
        require(commitments[commitment], "No matching commitment");
        
        commitments[commitment] = false;
        _execute(amount, target);
    }
}`,
    ],
    "decimal-mismatch": [
      `// Fix: Explicitly read and use token decimals
contract FixedContract {
    IERC20 public token;
    uint8 public tokenDecimals;

    function initialize(address _token) external initializer {
        token = IERC20(_token);
        // Read actual decimals — never hardcode
        try IERC20Metadata(_token).decimals() returns (uint8 d) {
            tokenDecimals = d;
        } catch {
            tokenDecimals = 18; // Safe default
        }
    }

    function calculate(uint256 amount) external view returns (uint256) {
        // Scale to 18 decimals for internal math
        if (tokenDecimals < 18) {
            amount *= 10 ** (18 - tokenDecimals);
        } else if (tokenDecimals > 18) {
            amount /= 10 ** (tokenDecimals - 18);
        }
        return amount;
    }
}`,
    ],
  };

  const options = fixes[vulnType];
  if (options && options.length > 0) {
    return rng.pick(options);
  }

  // Generic fallback
  return `// Fix for ${vulnType}
contract FixedContract {
    // Add proper validation and access control
    function securedFunction() external {
        require(msg.sender != address(0), "Invalid caller");
        // Implement the fix for ${vulnType}
        _applyFix();
    }
}`;
}
