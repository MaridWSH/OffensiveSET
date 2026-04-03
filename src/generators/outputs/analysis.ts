import type { OutputContext, ContractProfile, SeededRNG } from "./helpers.js";

// ============================================================
// Slither detector pools by severity
// ============================================================

const SLITHER_HIGH = [
  "reentrancy-no-eth",
  "reentrancy-benign",
  "reentrancy-events",
  "arbitrary-send-eth",
  "controlled-array-length",
  "controlled-delegatecall",
  "dangerous-strict-equality",
  "missing-zero-check",
  "suicidal",
  "tx-origin",
  "unchecked-transfer",
  "uninitialized-state",
  "unchecked-send",
  "incorrect-shift-order",
  "incorrect-return-value",
  "delegatecall-loop",
  "msg-value-loop",
];

const SLITHER_MEDIUM = [
  "reentrancy-unlimited-gas",
  "calls-loop",
  "deprecated-standalone",
  "domain-separator-collision",
  "erc20-indexed",
  "incorrect-equality",
  "mapping-deletion",
  "missing-inheritance",
  "shadowing-abstract",
  "tautology",
  "timestamp",
  "weak-prng",
  "divide-before-multiply",
  "assembly",
  "low-level-calls",
  "solc-version",
  "pragma",
];

const SLITHER_LOW = [
  "boolean-cst",
  "constable-states",
  "dead-code",
  "external-function",
  "immutable-states",
  "named-return-values",
  "naming-convention",
  "redundant-statements",
  "similar-names",
  "too-many-digits",
  "unimplemented-functions",
  "unused-import",
  "unused-state",
  "missing-inheritance",
];

const SLITHER_INFO = [
  "pragma",
  "solc-version",
  "assembly",
  "low-level-calls",
  "unused-return",
  "costly-operations",
  "events-access",
  "events-maths",
  "functions-order",
  "variables-written",
  "nft-mapping",
];

// ============================================================
// Mythril SWC data
// ============================================================

interface SwcEntry {
  swc: string;
  title: string;
  desc: string;
  severity: string;
}

const MYTHRIL_SWC: SwcEntry[] = [
  {
    swc: "SWC-101",
    title: "Integer Overflow and Underflow",
    desc:
      "The arithmetic operator is used without" +
      " checking for overflow in {func}.",
    severity: "High",
  },
  {
    swc: "SWC-107",
    title: "External Call To Untrusted Contract",
    desc:
      "The contract makes an external call to an" +
      " address derived from user input in {func}.",
    severity: "Medium",
  },
  {
    swc: "SWC-108",
    title: "State Variable Default Visibility",
    desc: "State variable '{var}' is implicitly public.",
    severity: "Low",
  },
  {
    swc: "SWC-114",
    title: "Transaction Order Dependence",
    desc:
      "The state change in {func} depends on the order" +
      " of transactions in a block.",
    severity: "Medium",
  },
  {
    swc: "SWC-118",
    title: "Uninitialized State Variables",
    desc:
      "State variable '{var}' is used before" +
      " being initialized.",
    severity: "High",
  },
  {
    swc: "SWC-120",
    title: "Weak Sources of Randomness",
    desc:
      "Block timestamp is used as a source of" +
      " randomness in {func}.",
    severity: "Medium",
  },
  {
    swc: "SWC-124",
    title: "Assert Violation",
    desc:
      "A reachable exception in {func} causes a revert" +
      " when constraint {constraint} is violated.",
    severity: "High",
  },
  {
    swc: "SWC-128",
    title: "State Re-initialization",
    desc:
      "The function {func} can be called multiple" +
      " times to reinitialize critical state.",
    severity: "High",
  },
  {
    swc: "SWC-129",
    title: "ERC-20 Balance/Allowance Interface Issue",
    desc:
      "Insufficient balance check is missing in {func}.",
    severity: "Medium",
  },
  {
    swc: "SWC-131",
    title: "Arbitrary Jump Destination",
    desc:
      "The function {func} uses inline assembly with" +
      " an unvalidated jump destination.",
    severity: "High",
  },
  {
    swc: "SWC-132",
    title: "Type Confusion",
    desc:
      "Function selector collision detected between" +
      " {func} and another function.",
    severity: "Low",
  },
  {
    swc: "SWC-135",
    title: "Unchecked Call Return Value",
    desc:
      "The return value of an external call in" +
      " {func} is not checked.",
    severity: "Medium",
  },
  {
    swc: "SWC-137",
    title: "Unprotected Ether Withdraw",
    desc:
      "The function {func} allows unauthorized" +
      " withdrawal of Ether.",
    severity: "High",
  },
  {
    swc: "SWC-100",
    title: "Default Usage of tx.origin",
    desc:
      "The function {func} uses tx.origin" +
      " for authentication.",
    severity: "Medium",
  },
  {
    swc: "SWC-113",
    title: "Floating Pragma",
    desc:
      "Contract uses a floating pragma" +
      " version '{version}'.",
    severity: "Low",
  },
  {
    swc: "SWC-105",
    title: "Unprotected Ether Withdrawal",
    desc:
      "Any sender can trigger a withdrawal path" +
      " in {func} via fallback.",
    severity: "High",
  },
  {
    swc: "SWC-123",
    title: "Storage Collision",
    desc:
      "Storage slot collision possible between" +
      " inherited contracts in {func}.",
    severity: "Medium",
  },
];

// ============================================================
// Description templates
// ============================================================

const HIGH_DESC = [
  "{func} allows an attacker to {impact} by exploiting {vuln}",
  "{func} lacks proper access control, enabling unauthorized {impact}",
  "Critical reentrancy in {func} allows draining of funds",
  "{func} can be called by any address to trigger {impact}",
  "Missing validation in {func} permits {vuln} leading to {impact}",
  "{func} does not enforce {missing}, allowing {impact}",
  "State manipulation via {func} results in {impact}",
  "{func} permits unrestricted {vuln} which causes {impact}",
];

const MEDIUM_DESC = [
  "{func} relies on block timestamp which can be manipulated by miners",
  "External call in {func} should check return value",
  "{func} performs a low-level call without proper error handling",
  "Division before multiplication in {func} causes precision loss",
  "{func} uses deprecated OpenZeppelin patterns",
  "Inline assembly in {func} should be audited carefully",
  "{func} may suffer from front-running due to pending state changes",
  "Gas optimization: {func} performs expensive SSTORE in a loop",
];

const LOW_DESC = [
  "State variable '{var}' could be declared as constant",
  "{func} should be declared as external instead of public",
  "Variable name '{var1}' is too similar to '{var2}' in {func}",
  "{func} contains unused return values from external calls",
  "Redundant statement in {func} at line {line}",
  "Contract does not follow the {convention} naming convention",
];

const INFO_DESC = [
  "{func} writes to state variables: {vars}",
  "Event emission for {vars} is missing in {func}",
  "{func} contains a costly operation in a loop",
  "Function ordering in {contract} does not follow best practices",
  "{func} uses {count} SLOAD operations -- consider caching",
];

// ============================================================
// Mythril constraint templates
// ============================================================

const MYTHRIL_CONSTRAINTS = [
  "calldatasize >= 36 AND caller = ANY",
  "storage[1] > calldata[4:36] AND msg.value > 0",
  "block.timestamp >= state.lockEndTime" +
    " AND caller != state.owner",
  "storage[slot] = 0 OR storage[slot] = caller",
  "calldata[0:4] = selector({func}) AND gas() > 2300",
  "tx.origin != state.admin AND caller = address(this)",
  "storage[account] > 0 AND" +
    " allowance[account][spender] = MAX_UINT256",
  "block.number % state.epoch == 0",
  "keccak256(sig) == keccak256(state.pendingSignature)" +
    " AND nonce = state.nonce",
  "storage[totalSupply] + amount <= MAX_SUPPLY",
];

// ============================================================
// Helpers
// ============================================================

function fillTpl(tpl: string, p: ContractProfile, rng: SeededRNG): string {
  let r = tpl;
  const funcs = p.externalFunctions;
  const f0 = funcs.length > 0 ? funcs[0] : null;
  const funcSig = f0
    ? f0.name + "(" + f0.params.join(", ") + ")"
    : p.affectedFunction;

  r = r.replace(/\{func\}/g, funcSig);
  r = r.replace(/\{contract\}/g, p.contractName);
  r = r.replace(/\{impact\}/g, p.impactType);
  r = r.replace(/\{vuln\}/g, p.vulnType);
  r = r.replace(/\{missing\}/g, p.missingCheck);

  const sv = p.stateVariables;
  if (sv.length >= 1) r = r.replace(/\{var\}/g, sv[0].name);
  if (sv.length >= 2) {
    r = r.replace(/\{var1\}/g, sv[0].name);
    r = r.replace(/\{var2\}/g, sv[1].name);
  }
  if (sv.length >= 3) {
    r = r.replace(
      /\{vars\}/g,
      sv.slice(0, 3).map((v) => v.name).join(", "),
    );
  } else if (sv.length > 0) {
    r = r.replace(
      /\{vars\}/g,
      sv.map((v) => v.name).join(", "),
    );
  }

  r = r.replace(/\{version\}/g, p.solidityVersion);
  r = r.replace(/\{line\}/g, String(rng.int(15, 320)));
  r = r.replace(
    /\{convention\}/g,
    rng.pick(["function", "variable", "parameter", "event"]),
  );
  r = r.replace(/\{count\}/g, String(rng.int(3, 12)));
  return r;
}

function pickN<T>(ctx: OutputContext, arr: T[], n: number): T[] {
  return ctx.rng.pickN(arr, Math.min(n, arr.length));
}

// ============================================================
// Public API
// ============================================================

export function generateSlitherOutput(
  ctx: OutputContext,
  profile: ContractProfile,
): string {
  const L: string[] = [];

  // Header
  L.push("========================================================");
  L.push("                    Slither Analysis                    ");
  L.push("========================================================");
  L.push("");
  L.push("Protocol:   " + profile.protocolName);
  L.push("Contract:   " + profile.contractName + ".sol");
  L.push("Solidity:   ^" + profile.solidityVersion);
  L.push("Chain:      " + profile.chainId);
  L.push("Address:    " + profile.contractAddress);
  L.push("");
  L.push("Inheritance: " + profile.inheritanceChain.join(" -> "));
  L.push("");
  L.push("-".repeat(56));
  L.push("Results");
  L.push("-".repeat(56));
  L.push("");

  // Number of findings per severity
  const nHigh = ctx.rng.int(1, 2);
  const nMed = ctx.rng.int(1, 3);
  const nLow = ctx.rng.int(1, 3);
  const nInfo = ctx.rng.int(0, 2);
  const total = nHigh + nMed + nLow + nInfo;

  // Map vulnType to most relevant detector
  const vulnMap: Record<string, string> = {
    reentrancy: "reentrancy-no-eth",
    "unauthorized-mint": "controlled-array-length",
    "oracle-manipulation": "weak-prng",
    "access-control-bypass": "tx-origin",
    "integer-overflow": "dangerous-strict-equality",
    "rounding-precision": "divide-before-multiply",
    "signature-replay": "controlled-delegatecall",
    "storage-collision": "uninitialized-state",
    "logic-error": "incorrect-return-value",
    "fee-bypass": "arbitrary-send-eth",
    "initialization-missing": "uninitialized-state",
    "timelock-bypass": "delegatecall-loop",
    "cross-chain-replay": "controlled-array-length",
    "dos-griefing": "reentrancy-no-eth",
    "mev-front-running": "timestamp",
    "decimal-mismatch": "divide-before-multiply",
  };

  // High findings
  const highDetectors = pickN(ctx, SLITHER_HIGH, nHigh);
  if (highDetectors.length > 0) {
    highDetectors[0] =
      vulnMap[profile.vulnType] || ctx.rng.pick(SLITHER_HIGH);
  }

  const medDetectors = pickN(ctx, SLITHER_MEDIUM, nMed);
  const lowDetectors = pickN(ctx, SLITHER_LOW, nLow);
  const infoDetectors = pickN(ctx, SLITHER_INFO, nInfo);

  let lineOff = 10;
  const rng = ctx.rng;

  function renderFinding(
    sev: string,
    detector: string,
    descTpl: string,
  ): string {
    const desc = fillTpl(descTpl, profile, rng);
    const sLine = lineOff + rng.int(1, 5);
    const eLine = sLine + rng.int(2, 8);
    const funcs = profile.externalFunctions;
    const fn = funcs.length > 0 ? funcs[0].name : "unknown";
    lineOff += 30;

    const parts: string[] = [];
    parts.push(fn + " (" + profile.contractName + ".sol#" + sLine + ")");
    parts.push("Description: " + desc);
    parts.push("Severity: " + sev);
    parts.push("Detector: " + detector);
    parts.push("");
    parts.push("    " + profile.contractName + ".sol:" + sLine + "-" + eLine + ":");
    parts.push("    # " + sev + " finding in " + fn);
    parts.push("");
    return parts.join("\n");
  }

  for (const d of highDetectors) {
    L.push(renderFinding("High", d, rng.pick(HIGH_DESC)));
  }
  for (const d of medDetectors) {
    L.push(renderFinding("Medium", d, rng.pick(MEDIUM_DESC)));
  }
  for (const d of lowDetectors) {
    L.push(renderFinding("Low", d, rng.pick(LOW_DESC)));
  }
  for (const d of infoDetectors) {
    L.push(renderFinding("Informational", d, rng.pick(INFO_DESC)));
  }

  // Summary
  L.push("-".repeat(56));
  L.push("Summary");
  L.push("-".repeat(56));
  L.push("");
  L.push("Total findings: " + total);
  L.push("  High:           " + nHigh);
  L.push("  Medium:         " + nMed);
  L.push("  Low:            " + nLow);
  L.push("  Informational:  " + nInfo);
  L.push("");

  const nContracts = rng.int(1, 3);
  const nFunctions = rng.int(5, 20);
  L.push(nContracts + " contracts analyzed");
  L.push(nFunctions + " functions analyzed");
  L.push(rng.int(100, 500) + " source lines analyzed");
  const slitherVer = rng.pick([
    "0.10.0",
    "0.10.1",
    "0.10.2",
    "0.10.3",
  ]);
  L.push("Slither version: " + slitherVer);

  return L.join("\n");
}

export function generateMythrilOutput(
  ctx: OutputContext,
  profile: ContractProfile,
): string {
  const L: string[] = [];
  const rng = ctx.rng;

  // Header
  const ver = rng.pick([
    "0.24.0",
    "0.24.1",
    "0.24.2",
    "0.24.4",
    "0.25.0",
  ]);
  L.push("mythril v" + ver + " - " + ctx.generateDate());
  L.push("");
  L.push("=".repeat(60));
  L.push("Contract: " + profile.contractName);
  L.push("File:     " + profile.contractName + ".sol");
  L.push("Address:  " + profile.contractAddress);
  L.push("Chain:    " + profile.chainId);
  L.push("=".repeat(60));
  L.push("");
  L.push(
    "Analyzing contract: " +
      profile.contractName +
      ".sol:{contract}",
  );
  L.push("");

  // Select SWC findings
  const nFindings = rng.int(3, 8);

  // Map vulnType to most relevant SWC entry
  const vulnSwcMap: Record<string, string> = {
    reentrancy: "SWC-107",
    "unauthorized-mint": "SWC-128",
    "oracle-manipulation": "SWC-120",
    "access-control-bypass": "SWC-105",
    "integer-overflow": "SWC-101",
    "rounding-precision": "SWC-129",
    "signature-replay": "SWC-100",
    "storage-collision": "SWC-123",
    "logic-error": "SWC-124",
    "fee-bypass": "SWC-135",
    "initialization-missing": "SWC-118",
    "timelock-bypass": "SWC-128",
    "cross-chain-replay": "SWC-107",
    "dos-griefing": "SWC-114",
    "mev-front-running": "SWC-114",
    "decimal-mismatch": "SWC-129",
  };

  const pool = [...MYTHRIL_SWC];
  const findings: { entry: SwcEntry; lineNo: number }[] = [];

  // Primary finding tied to vulnType
  const primaryId =
    vulnSwcMap[profile.vulnType] || rng.pick(MYTHRIL_SWC).swc;
  const primaryEntry =
    pool.find((s) => s.swc === primaryId) || rng.pick(pool);
  const primaryLine = rng.int(15, 200);
  findings.push({ entry: primaryEntry, lineNo: primaryLine });

  // Additional findings
  const rest = pool.filter((s) => s.swc !== primaryEntry.swc);
  const additional = rng.pickN(rest, nFindings - 1);
  for (const swc of additional) {
    const ln = primaryLine + rng.int(5, 150);
    findings.push({ entry: swc, lineNo: ln });
  }

  // Sort by line number
  findings.sort((a, b) => a.lineNo - b.lineNo);

  // Render each finding
  for (let i = 0; i < findings.length; i++) {
    const f = findings[i];
    const entry = f.entry;
    const lineNo = f.lineNo;
    const funcs = profile.externalFunctions;
    const fi = funcs[i % Math.max(funcs.length, 1)];
    const fname = fi ? fi.name : profile.affectedFunction.replace("()", "");
    const fparams = fi ? fi.params : [];
    const psig = fparams.length > 0 ? fparams.join(", ") : "";

    const desc = entry.desc
      .replace("{func}", fname + "(" + psig + ")")
      .replace(
        "{var}",
        profile.stateVariables.length > 0
          ? profile.stateVariables[0].name
          : "unknown",
      )
      .replace(
        "{constraint}",
        rng.pick(MYTHRIL_CONSTRAINTS).replace("{func}", fname),
      );

    const endLine = lineNo + rng.int(3, 10);
    const constraint = rng
      .pick(MYTHRIL_CONSTRAINTS)
      .replace("{func}", fname);
    const exploitability = rng.pick([
      "feasible",
      "possible",
      "unlikely",
      "theoretical",
    ]);

    L.push("=" .repeat(60));
    L.push("[" + entry.severity.toUpperCase() + "] " + entry.title);
    L.push("-".repeat(60));
    L.push("SWC ID:       " + entry.swc);
    L.push("Title:        " + entry.title);
    L.push("");
    L.push("Contract:     " + profile.contractName + ".sol");
    L.push("Function:     " + fname + "(" + psig + ")");
    L.push("Line:         " + lineNo);
    L.push("");
    L.push("Description:");
    L.push("  " + desc);
    L.push("");
    L.push("Constraint:");
    L.push("  " + constraint);
    L.push("");
    L.push("Exploitability: " + exploitability);
    L.push("=".repeat(60));
    L.push("");
  }

  // Analysis summary
  L.push("-".repeat(60));
  L.push("Analysis Summary");
  L.push("-".repeat(60));
  L.push("");

  const highCount = findings.filter(
    (f) => f.entry.severity === "High",
  ).length;
  const medCount = findings.filter(
    (f) => f.entry.severity === "Medium",
  ).length;
  const lowCount = findings.filter(
    (f) => f.entry.severity === "Low",
  ).length;
  const infoCount = findings.filter(
    (f) => f.entry.severity === "Informational",
  ).length;

  const nFuncs = rng.int(5, 25);
  const nInstr = rng.int(50, 500);
  const timeSec = rng.float(1.2, 45.8).toFixed(1);

  L.push("Contract:            " + profile.contractName + ".sol");
  L.push("Functions analyzed:  " + nFuncs);
  L.push("States explored:     " + rng.int(100, 5000));
  L.push("Transactions:        " + rng.int(20, 200));
  L.push("Instructions:        " + nInstr);
  L.push("Analysis time:       " + timeSec + "s");
  L.push("");
  L.push("Issues found:        " + findings.length);
  L.push("  High:              " + highCount);
  L.push("  Medium:            " + medCount);
  L.push("  Low:               " + lowCount);
  L.push("  Informational:     " + infoCount);
  L.push("");

  if (highCount > 0) {
    L.push(
      "!  High severity issues detected",
    );
    L.push(
      "   Manual review recommended.",
    );
  } else {
    L.push("OK  No high severity issues found.");
  }

  return L.join("\n");
}
