import type { ToolDefinition } from "./types.js";

export const ANALYSIS_TOOLS: ToolDefinition[] = [
  {
    name: "slither",
    description:
      "Static analysis framework for Solidity. Runs 70+ detectors for security vulnerabilities, optimization issues, and code quality. Industry standard for automated smart contract auditing.",
    category: "scanning",
    parameters: {
      target: {
        type: "string",
        description: "Path to the Solidity source file, directory, or Hardhat/Foundry project root.",
        required: true,
        examples: ["contracts/Token.sol", "src/", "."],
      },
      detectors: {
        type: "string",
        description:
          "Comma-separated list of detector names to run. Use 'printers' to list available detectors. Omit to run all detectors.",
        required: false,
        examples: ["reentrancy-eth", "uninitialized-state", "arbitrary-send-eth", "naming-convention"],
      },
      output: {
        type: "string",
        description: "Output format for results.",
        required: false,
        default: "text",
        examples: ["text", "json", "sarif", "csv"],
      },
      flags: {
        type: "string",
        description:
          "Additional CLI flags passed to Slither. Multiple flags can be space-separated.",
        required: false,
        examples: [
          "--exclude-dependencies",
          "--filter-paths 'node_modules|test|mocks'",
          "--solc-remaps '@openzeppelin/=node_modules/@openzeppelin/'",
          "--compile-force-framework hardhat",
        ],
      },
    },
    example_commands: [
      "slither . --detect reentrancy-eth,reentrancy-no-eth,reentrancy-benign",
      "slither contracts/Vault.sol --detect uninitialized-state,uninitialized-local-variables --json slither-report.json",
      "slither . --exclude-informational --exclude-low --filter-paths 'node_modules|test'",
      "slither . --solc-remaps '@openzeppelin/=node_modules/@openzeppelin/' --exclude-dependencies --json-output sarif",
      "slither . --print human-summary --filter-paths 'node_modules' --compile-force-framework foundry",
    ],
    typical_output: `Slither analysis complete
Contract: Vault (contracts/Vault.sol)

HIGH: Reentrancy vulnerability in Vault.withdraw() (contracts/Vault.sol#45-62)
  External call: token.transfer(msg.sender, amount) (contracts/Vault.sol#55)
  State update after external call: balances[msg.sender] -= amount (contracts/Vault.sol#58)
  Recommendation: Apply checks-effects-interactions pattern or use ReentrancyGuard.

HIGH: Arbitrary send from ETH in Vault.deposit() (contracts/Vault.sol#30-38)
  msg.value is used without checking for success
  Recommendation: Use SafeERC20 or check transfer return value.

MEDIUM: Uninitialized state variable (contracts/Vault.sol#12)
  owner is never initialized in constructor
  Recommendation: Initialize owner in constructor or via initializer.

MEDIUM: Missing events access control (contracts/Vault.sol#70)
  function setFeePercent() should emit an event
  Recommendation: Emit FeeUpdated event when fee is changed.

LOW: Costly operations inside a loop (contracts/Vault.sol#88-95)
  Loop iterates over all depositors; gas cost scales linearly
  Recommendation: Use pull-over-push pattern or bounded pagination.

INFO: Naming convention violation (contracts/Vault.sol#22)
  Function get_TotalAssets() should be in mixedCase
  Recommendation: Rename to getTotalAssets().

Results: 6 findings (2 HIGH, 2 MEDIUM, 1 LOW, 1 INFO)`,
  },
  {
    name: "mythril",
    description:
      "Symbolic execution and SMT-based analysis tool for EVM bytecode. Detects integer overflows, reentrancy, transaction order dependencies, and other vulnerabilities through constraint solving.",
    category: "scanning",
    parameters: {
      target: {
        type: "string",
        description:
          "Solidity source file, compiled bytecode (0x-prefixed hex), or contract address on a live network.",
        required: true,
        examples: ["contracts/Token.sol", "0x6080604052...", "0x1234...abcd"],
      },
      rpc: {
        type: "string",
        description:
          "Ethereum JSON-RPC endpoint for on-chain contract analysis. Required when target is a contract address.",
        required: false,
        examples: ["https://eth.llamarpc.com", "https://rpc.ankr.com/eth"],
      },
      detection_modules: {
        type: "string",
        description:
          "Comma-separated list of detection module names (SWC IDs). Omit to run all modules.",
        required: false,
        examples: ["SWC-107", "SWC-101", "SWC-105,SWC-114,SWC-128"],
      },
      flags: {
        type: "string",
        description:
          "Additional CLI flags passed to Mythril.",
        required: false,
        examples: [
          "--execution-timeout 60",
          "--loop-bound 3",
          "--solv 0.8.20",
          "--enable-experimental-features",
        ],
      },
    },
    example_commands: [
      "myth analyze contracts/Vault.sol --execution-timeout 120",
      "myth analyze 0x1234567890abcdef1234567890abcdef12345678 --rpc https://eth.llamarpc.com -o json",
      "myth analyze contracts/Token.sol --execution-timeout 60 --loop-bound 2 --solv 0.8.20",
      "myth analyze contracts/Vault.sol -t SWC-107,SWC-101,SWC-105 --execution-timeout 300",
    ],
    typical_output: `mythril v0.24.7
Analyzing contracts/Vault.sol...

==== External Call To User-Supplied Address ====
SWC ID: 107
Severity: High
Contract: Vault
Function name: withdraw(address)
PC address: 0x2a3
Location: contracts/Vault.sol:55:9

The contract calls an external function with a user-supplied address without
proper validation. An attacker can supply a malicious contract address that
drains funds on behalf of the caller.

In contracts/Vault.sol:55:9:
    token.transfer(msg.sender, amount)

==== Integer Overflow ====
SWC ID: 101
Severity: High
Contract: Vault
Function name: deposit()
PC address: 0x1f8
Location: contracts/Vault.sol:33:9

The arithmetic operator can underflow/overflow. Use OpenZeppelin's SafeMath
library or Solidity 0.8+ built-in overflow checks.

In contracts/Vault.sol:33:9:
    balances[msg.sender] += amount

==== Transaction-Order Dependence ====
SWC ID: 114
Severity: Medium
Contract: Vault
Function name: claimRewards()
PC address: 0x4b1
Location: contracts/Vault.sol:78:5

The value and direction of the ether transfer depends on the order of
transactions. A front-running attacker can manipulate the state before the
transaction is executed.

In contracts/Vault.sol:78:5:
    uint reward = calculateReward(msg.sender)

Found 3 issues across 3 functions.`,
  },
  {
    name: "semgrep",
    description:
      "Pattern-based static analysis tool supporting Solidity. Uses YAML rule files to detect vulnerability patterns, best practice violations, and custom security rules across smart contract codebases.",
    category: "scanning",
    parameters: {
      target: {
        type: "string",
        description: "Path to the Solidity source file or directory to scan.",
        required: true,
        examples: ["contracts/", "src/**/*.sol", "."],
      },
      config: {
        type: "string",
        description:
          "Rule configuration source. Can be a registry ID (p/), local YAML file path, or URL.",
        required: false,
        default: "p/solidity",
        examples: [
          "p/solidity",
          "p/smartyaml",
          "rules/custom-findings.yaml",
          "https://example.com/rules/sol-rules.yaml",
        ],
      },
      lang: {
        type: "string",
        description: "Language filter to restrict scanning to Solidity files only.",
        required: false,
        default: "solidity",
        examples: ["solidity"],
      },
      flags: {
        type: "string",
        description:
          "Additional CLI flags passed to Semgrep.",
        required: false,
        examples: [
          "--severity CRITICAL",
          "--json -o semgrep-report.json",
          "--exclude 'test/**' --exclude 'node_modules/**'",
          "--verbose",
        ],
      },
    },
    example_commands: [
      "semgrep --config p/solidity --lang solidity contracts/",
      "semgrep --config rules/custom-security.yaml --severity CRITICAL,HIGH --json -o semgrep-report.json contracts/",
      "semgrep --config p/solidity --exclude 'test/**' --exclude 'node_modules/**' --verbose .",
      "semgrep --config auto --lang solidity --metrics off --quiet contracts/",
    ],
    typical_output: `Running 45 rules from p/solidity...
┌─────────────┐
│ Scan Status │
└─────────────┘
  Scanning 23 files (Solidity) with 45 rules.

  ┌──────────────────────────────────────────────────────────────────┐
  │ 3 Code Findings                                                  │
  │    1 Critical, 1 Error, 1 Warning                                │
  └──────────────────────────────────────────────────────────────────┘

    contracts/Vault.sol
    solidity.security.reentrancy.reentrancy-on-external-call
    CRITICAL: External call followed by state update (reentrancy risk)

    53 │     (bool success, ) = msg.sender.call{value: amount}("");
    54 │     require(success, "transfer failed");
  > 55 │     balances[msg.sender] -= amount;
       │     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    56 │

    https://semgrep.dev/r/solidity.security.reentrancy.reentrancy-on-external-call

    ─────────────────────────────────────────────────────────────────

    contracts/Vault.sol
    solidity.best-practices.missing-event-for-state-change
    WARNING: State-modifying function setFeePercent() does not emit an event

    70 │     function setFeePercent(uint256 _fee) external onlyOwner {
  > 71 │         feePercent = _fee;
       │         ^^^^^^^^^^^^^^^^^
    72 │     }

    https://semgrep.dev/r/solidity.best-practices.missing-event-for-state-change

    ─────────────────────────────────────────────────────────────────

    contracts/Token.sol
    solidity.security.approval.approve-race-condition
    ERROR: approve() is vulnerable to race condition; use increaseAllowance/decreaseAllowance

    28 │     function approve(address spender, uint256 amount) external returns (bool) {
  > 29 │         allowances[msg.sender][spender] = amount;
       │         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    30 │         return true;
    31 │     }

    https://semgrep.dev/r/solidity.security.approval.approve-race-condition

    ─────────────────────────────────────────────────────────────────

Ran 45 rules on 23 files: 3 findings.`,
  },
  {
    name: "securify",
    description:
      "Formal verification tool for Solidity smart contracts. Uses dependency analysis and SMT solving to prove or disprove security properties like reentrancy-freedom, access control correctness, and transaction ordering.",
    category: "scanning",
    parameters: {
      target: {
        type: "string",
        description:
          "Path to the Solidity source file, directory, or compiled JSON artifact to analyze.",
        required: true,
        examples: ["contracts/Vault.sol", "contracts/", "out/Vault.sol/Vault.json"],
      },
      properties: {
        type: "string",
        description:
          "Comma-separated list of security properties to verify. Omit to check all properties.",
        required: false,
        examples: [
          "REENTRANCY",
          "TxOrigin,UnrestrictedSelfdestruct",
          "REENTRANCY,ACCESS_CONTROL,UNCONTROLLED_ETHER",
        ],
      },
      output: {
        type: "string",
        description: "Output format for verification results.",
        required: false,
        default: "text",
        examples: ["text", "json"],
      },
      flags: {
        type: "string",
        description:
          "Additional CLI flags passed to Securify.",
        required: false,
        examples: [
          "--solc-version 0.8.20",
          "--timeout 300",
          "--include-dependencies",
          "--live --solc-remaps '@openzeppelin/=node_modules/@openzeppelin/'",
        ],
      },
    },
    example_commands: [
      "securify contracts/Vault.sol",
      "securify contracts/Vault.sol --properties REENTRANCY,TxOrigin,ACCESS_CONTROL --json",
      "securify contracts/ --solc-version 0.8.20 --timeout 300 --include-dependencies",
    ],
    typical_output: `Securify v2.0 - Formal Verification Results
========================================

Contract: Vault (contracts/Vault.sol)
Compiler: solc 0.8.20
Analysis time: 12.4s

Property                        | Status       | Confidence
--------------------------------|--------------|------------
REENTRANCY                      | VIOLATION    | High
TxOrigin                        | SAFE         | High
TODReceiver                     | SAFE         | Medium
UnrestrictedSelfdestruct        | SAFE         | High
ACCESS_CONTROL                  | VIOLATION    | Medium
UNCONTROLLED_ETHER              | SAFE         | High
DeprecatedEncodingKeccak256     | SAFE         | High

Detailed Findings:
──────────────────

[VIOLATION] REENTRANCY
  Function: withdraw(address,uint256)
  Location: contracts/Vault.sol:45-62
  The function performs an external call before updating storage state.
  This violates the reentrancy property: a reentrant call can drain funds
  before the balance is deducted.
  Fix: Move state updates before external calls or apply ReentrancyGuard.

[VIOLATION] ACCESS_CONTROL
  Function: setFeePercent(uint256)
  Location: contracts/Vault.sol:70-72
  The function modifies critical state (feePercent) without adequate
  access control. While onlyOwner modifier is present, the owner can be
  changed via transferOwnership() without a two-step process.
  Fix: Use Ownable2Step or add a timelock for fee changes.

Summary: 5 safe, 2 violations (out of 7 properties checked)
Contracts with violations: Vault (2/7 properties)`,
  },
];
