import type { ToolDefinition } from "./types.js";

export const UTILITY_TOOLS: ToolDefinition[] = [
  {
    name: "solc",
    description:
      "Solidity compiler CLI. Compiles .sol files to EVM bytecode and ABI JSON. Supports multiple versions, optimization levels, and gas analysis.",
    category: "utility",
    parameters: {
      version: {
        type: "string",
        description:
          "Solidity compiler version to use. Can be a full version string, a version range, or 'auto' to detect from pragma.",
        required: false,
        default: "auto",
        examples: ["0.8.20", "0.7.6", "0.6.12", "auto"],
      },
      optimize: {
        type: "string",
        description:
          "Enable optimizer with a specified number of runs. Higher runs = more gas optimization but larger bytecode. Use 'off' to disable.",
        required: false,
        default: "200",
        examples: ["200", "10000", "999999", "off"],
      },
      input: {
        type: "string",
        description:
          "Path to the Solidity source file or directory to compile. Supports glob patterns for multiple files.",
        required: true,
        examples: ["contracts/Token.sol", "src/**/*.sol", "contracts/"],
      },
      flags: {
        type: "string",
        description:
          "Additional solc CLI flags. Supports all standard solc options including output selection, remappings, and base paths.",
        required: false,
        examples: [
          "--abi --bin",
          "--combined-json abi,bin,srcmap,devdoc",
          "--base-path contracts/ --include-path node_modules/",
          "--solc-remaps '@openzeppelin/=node_modules/@openzeppelin/'",
        ],
      },
    },
    example_commands: [
      "solc --optimize --optimize-runs 200 --abi --bin contracts/Vault.sol",
      "solc --combined-json abi,bin,devdoc,userdoc --optimize --optimize-runs 10000 src/",
      "solc --solc-version 0.8.20 --base-path contracts/ --include-path node_modules/ --overwrite --abi --bin -o build/",
      "solc --combined-json abi,bin,srcmap,devdoc --optimize --optimize-runs 200 --gas contracts/Token.sol",
    ],
    typical_output: `Compiler run successful. Artifact(s) can be found in directory "build".
SyntaxError: Warning: SPDX license identifier not provided in source file.
 --> contracts/Vault.sol

Contract: Vault
Binary:
608060405234801561001057600080fd5b50600436106100a95760003560e01c8063...

Contract: Vault
Binary Validation:
  Binary: Valid
  Metadata: {"compiler":{"version":"0.8.20"},"language":"Solidity","output":{"abi":[{"inputs":[],"name":"deposit","outputs":[],"stateMutability":"payable","type":"function"},{"inputs":[],"name":"withdraw","outputs":[],"stateMutability":"nonpayable","type":"function"}],"devdoc":{"methods":{}},"userdoc":{"methods":{}}},"settings":{"compilationTarget":{"contracts/Vault.sol":"Vault"},"evmVersion":"paris","libraries":{},"metadata":{"bytecodeHash":"ipfs"},"optimizer":{"enabled":true,"runs":200},"remappings":[]},"sources":{"contracts/Vault.sol":{"keccak256":"0xabc123...","urls":["bzz-raw://def456..."]}},"version":1}

Gas estimates:
  deposit():       45231 gas
  withdraw():      187432 gas
  totalSupply():   2357 gas
  balanceOf():     2483 gas

Compiled 1 Solidity file successfully.
  Vault (contracts/Vault.sol)          - 15.2 KB bytecode, 4 functions, 8 events`,
  },
  {
    name: "solhint",
    description:
      "Solidity linter for style guide enforcement and best practice checking. Detects code style issues, security anti-patterns, and convention violations in smart contract codebases.",
    category: "utility",
    parameters: {
      target: {
        type: "string",
        description:
          "Path to the Solidity source file or directory to lint. Supports glob patterns for multiple files.",
        required: true,
        examples: ["contracts/", "src/**/*.sol", "contracts/Vault.sol"],
      },
      config: {
        type: "string",
        description:
          "Path to the .solhint.json configuration file. If not specified, Solhint searches for config in the project root.",
        required: false,
        examples: [".solhint.json", "config/solhint-config.json"],
      },
      rules: {
        type: "string",
        description:
          "Comma-separated list of specific rule names to enable or disable. Prefix with '!' to disable a rule.",
        required: false,
        examples: ["no-unused-vars,naming-convention", "!not-rely-on-time", "avoid-low-level-calls"],
      },
      flags: {
        type: "string",
        description:
          "Additional Solhint CLI flags. Common flags: --fix (auto-fix), --formatter (output format), --quiet (suppress warnings), --max-warnings N.",
        required: false,
        examples: ["--fix", "--formatter table", "--quiet", "--max-warnings 0"],
      },
    },
    example_commands: [
      "solhint 'contracts/**/*.sol'",
      "solhint 'src/**/*.sol' --config .solhint.json --formatter table",
      "solhint 'contracts/Vault.sol' --fix --max-warnings 0",
      "solhint 'contracts/**/*.sol' --rules no-unused-vars,naming-convention,avoid-low-level-calls --formatter unix",
    ],
    typical_output: `Solhint report for contracts/Vault.sol
  12:3  error    Avoid low-level calls: use SafeERC20 instead of raw .call()      avoid-low-level-calls
  28:5  warning  Function is missing a 'returns' specification                    func-visibility
  45:9  error    Reentrancy risk: external call before state update                reentrancy-no-eth
  55:3  warning  Variable name 'total_Assets' does not follow mixedCase convention  naming-convention
  70:1  error    State-changing function 'setFeePercent' missing event emission     no-complex-fallback
  88:14 warning  Costly iteration over dynamic array - consider pagination         gas-custom-errors
  95:3  error    Missing 'override' keyword on function that overrides base        override
 102:7  warning  Use '>= 0.8.20' instead of '>= 0.8.0' for latest compiler fixes  compiler-version

✖ 8 problems (4 errors, 4 warnings)
  2 errors and 1 warning potentially fixable with the --fix option.

Solhint report for contracts/Token.sol
  15:1  error    Missing SPDX license identifier                                 no-spdx-license-identifier
  33:9  warning  Use 'require(condition, "error message")' with reason string    reason-string
  67:5  error    Unused local variable 'tempBalance'                             no-unused-vars

✖ 3 problems (2 errors, 1 warning)

Total: 11 problems (6 errors, 5 warnings) across 2 files`,
  },
  {
    name: "abi_encoder",
    description:
      "ABI encoding/decoding utility for Solidity function signatures and data structures. Encodes function calls with arguments, decodes calldata, and handles complex type encoding for smart contract interactions.",
    category: "utility",
    parameters: {
      action: {
        type: "string",
        description:
          "Operation mode: 'encode' to generate calldata from function signature and arguments, 'decode' to parse calldata into human-readable parameters.",
        required: true,
        examples: ["encode", "decode"],
      },
      function_sig: {
        type: "string",
        description:
          "Solidity function signature in the format 'name(type1,type2,...)'. Required for encoding; optional for decoding (auto-detected from 4byte selector).",
        required: false,
        examples: ["transfer(address,uint256)", "approve(address,uint256)", "swap(uint256,address[],bytes)"],
      },
      args: {
        type: "string",
        description:
          "Comma-separated arguments matching the function signature. For encoding: values to encode. For decoding: the calldata hex string to decode.",
        required: true,
        examples: [
          "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045,1000000000000000000",
          "0xa9059cbb000000000000000000000000d8da6bf26964af9d7eed9e03e53415d37aa960450000000000000000000000000000000000000000000000056bc75e2d63100000",
        ],
      },
      flags: {
        type: "string",
        description:
          "Additional flags for encoding/decoding behavior.",
        required: false,
        examples: ["--with-selector", "--no-selector", "--humanize", "--json", "--packed"],
      },
    },
    example_commands: [
      "abi_encoder encode transfer(address,uint256) 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045,1000000000000000000",
      "abi_encoder decode 0xa9059cbb000000000000000000000000d8da6bf26964af9d7eed9e03e53415d37aa960450000000000000000000000000000000000000000000000056bc75e2d63100000",
      "abi_encoder encode \"multicall(bytes[])\",\"[0xa9059cbb...,0x095ea7b3...]\" --with-selector --json",
      "abi_encoder encode \"deposit(uint256,address,bytes)\" 500000000000000000,0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D,0x --packed",
    ],
    typical_output: `$ abi_encoder encode transfer(address,uint256) 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045,1000000000000000000

Function: transfer(address,uint256)
Selector: 0xa9059cbb
Calldata: 0xa9059cbb000000000000000000000000d8da6bf26964af9d7eed9e03e53415d37aa960450000000000000000000000000000000000000000000000056bc75e2d63100000

Encoded parameters:
  [0] address: 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045
  [1] uint256: 1000000000000000000 (1.0 ether)

Calldata length: 136 bytes (68 words)

$ abi_encoder decode 0xa9059cbb000000000000000000000000d8da6bf26964af9d7eed9e03e53415d37aa960450000000000000000000000000000000000000000000000056bc75e2d63100000

4-byte selector: 0xa9059cbb
Resolved function: transfer(address,uint256)

Decoded parameters:
  to:    0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045
  value: 1000000000000000000 (1.0 ether)

Calldata breakdown:
  Selector (4 bytes): 0xa9059cbb
  Param 1 (32 bytes): 0x000000000000000000000000d8da6bf26964af9d7eed9e03e53415d37aa96045
  Param 2 (32 bytes): 0x0000000000000000000000000000000000000000000000056bc75e2d63100000`,
  },
  {
    name: "sigint",
    description:
      "Function signature database and selector lookup tool. Resolves 4-byte function selectors to human-readable signatures using the 4byte.directory database and local signature collections.",
    category: "utility",
    parameters: {
      action: {
        type: "string",
        description:
          "Operation mode: 'lookup' to resolve a 4-byte selector to function signatures, 'submit' to add a new signature to the local database.",
        required: true,
        examples: ["lookup", "submit"],
      },
      selector: {
        type: "string",
        description:
          "4-byte function selector to look up. Can be provided with or without the '0x' prefix. Required for lookup mode.",
        required: false,
        examples: ["0xa9059cbb", "0x23b872dd", "0x095ea7b3", "0x2e1a7d4d"],
      },
      signature: {
        type: "string",
        description:
          "Full function signature string to submit or search for. Required for submit mode.",
        required: false,
        examples: ["transfer(address,uint256)", "transferFrom(address,address,uint256)", "flashLoan(address,uint256,bytes)"],
      },
      flags: {
        type: "string",
        description:
          "Additional flags for lookup behavior. Common flags: --local-only (skip 4byte.directory), --all (show all matches), --verify (compute and verify selector).",
        required: false,
        examples: ["--local-only", "--all", "--verify", "--json"],
      },
    },
    example_commands: [
      "sigint lookup 0xa9059cbb",
      "sigint lookup 0x2e1a7d4d --all",
      "sigint submit transfer(address,uint256) --verify",
    ],
    typical_output: `$ sigint lookup 0xa9059cbb

Selector: 0xa9059cbb
Source: 4byte.directory + local database (cache updated 2h ago)

Matches:
  transfer(address,uint256)                    ← most likely (ERC20 standard)
  transfer(address,uint256,bytes)              ← variant with callback data

Computed selector check:
  keccak256("transfer(address,uint256)")[:4] = 0xa9059cbb ✓

$ sigint lookup 0x2e1a7d4d --all

Selector: 0x2e1a7d4d
Source: 4byte.directory + local database

Matches:
  withdraw(uint256)                            ← most likely
  withdraw(uint256,address)
  _withdraw(uint256)
  withdraw(uint256,uint256)
  emergencyWithdraw(uint256)

Computed selector check:
  keccak256("withdraw(uint256)")[:4] = 0x2e1a7d4d ✓

5 signatures found for selector 0x2e1a7d4d

$ sigint submit transfer(address,uint256) --verify

Signature: transfer(address,uint256)
Selector:  0xa9059cbb
Status:    Already exists in database
Source:    ERC-20 Token Standard (EIP-20)
Hash:      keccak256("transfer(address,uint256)") = 0xa9059cbb...`,
  },
  {
    name: "report_generator",
    description:
      "Smart contract audit report generator. Produces structured audit findings with severity scoring, CVSS calculation, SWC/CWE references, secure code recommendations, and executive summaries.",
    category: "utility",
    parameters: {
      findings: {
        type: "string",
        description:
          "Path to a JSON file containing an array of audit findings, each with title, severity, description, affected code, and remediation steps.",
        required: true,
        examples: ["findings.json", "output/slither-report.json", "audit-data/findings.yaml"],
      },
      protocol_name: {
        type: "string",
        description:
          "Name of the audited smart contract protocol or project. Used in report headers, executive summary, and document metadata.",
        required: true,
        examples: ["VaultProtocol", "LendingPlatform", "DEXAggregator"],
      },
      scope: {
        type: "string",
        description:
          "Comma-separated list of contracts or files that were in scope for the audit. Used to generate the scope summary section.",
        required: false,
        examples: ["contracts/Vault.sol,contracts/Token.sol", "src/**/*.sol"],
      },
      flags: {
        type: "string",
        description:
          "Additional report generation flags.",
        required: false,
        examples: ["--format markdown", "--format pdf", "--include-gas-reports", "--swc-references", "--cwe-references"],
      },
    },
    example_commands: [
      "report_generator --findings findings.json --protocol-name VaultProtocol --scope 'contracts/Vault.sol,contracts/Token.sol'",
      "report_generator --findings output/slither-report.json --protocol-name LendingPlatform --format pdf --swc-references",
      "report_generator --findings audit-data/findings.json --protocol-name DEXAggregator --include-gas-reports --cwe-references --format markdown",
    ],
    typical_output: `╔══════════════════════════════════════════════════════════╗
║       Smart Contract Audit Report - VaultProtocol        ║
║       Generated: 2026-04-03 | Auditor: OffensiveSET      ║
╚══════════════════════════════════════════════════════════╝

SCOPE
─────
  contracts/Vault.sol          - 312 lines, 8 functions
  contracts/Token.sol          - 187 lines, 6 functions

EXECUTIVE SUMMARY
─────────────────
  Total findings: 7
  Critical: 1  |  High: 2  |  Medium: 2  |  Low: 1  |  Info: 1

  Overall risk assessment: HIGH
  Recommendation: Address Critical and High findings before deployment.

  ┌────────────┬───────────┬──────────────────────────────────────────┐
  │ Severity   │  Count    │ Findings                                  │
  ├────────────┼───────────┼──────────────────────────────────────────┤
  │ Critical   │     1     │ Reentrancy in withdraw()                  │
  │ High       │     2     │ Access control bypass, Oracle manipulation │
  │ Medium     │     2     │ Missing input validation, Event omission  │
  │ Low        │     1     │ Naming convention violation               │
  │ Info       │     1     │ Optimization: costly loop iteration       │
  └────────────┴───────────┴──────────────────────────────────────────┘

FINDINGS
─────────

  [CRITICAL] C-01: Reentrancy in withdraw()
  ──────────────────────────────────────────
  SWC-107 | CWE-841
  CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H → 9.8 (Critical)

  The withdraw() function performs an external call (token.transfer)
  before updating the caller's balance. An attacker can recursively call
  withdraw() from their receive() fallback, draining all vault funds
  before any balance updates occur.

  Affected: contracts/Vault.sol:45-62
  Fix: Apply checks-effects-interactions pattern or use ReentrancyGuard.

  [HIGH] H-01: Missing Access Control on setFeePercent()
  ──────────────────────────────────────────────────────
  SWC-105 | CWE-284
  CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N → 7.5 (High)

  The setFeePercent() function can be called by any user with the
  OWNER_ROLE, but role assignment lacks a two-step transfer process.
  A compromised owner key allows immediate fee manipulation.

  Affected: contracts/Vault.sol:70-72
  Fix: Use Ownable2Step or add a timelock for fee parameter changes.

  [HIGH] H-02: Price Oracle Manipulation via Flash Loan
  ─────────────────────────────────────────────────────
  SWC-114 | CWE-841
  CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H → 8.1 (High)

  The protocol uses a spot price oracle that can be manipulated within
  a single transaction via flash loan. An attacker can borrow sufficient
  liquidity, manipulate the oracle price, and profit from liquidations.

  Affected: contracts/Vault.sol:112-145
  Fix: Use TWAP (Time-Weighted Average Price) or Chainlink oracle.

  [MEDIUM] M-01: Missing Input Validation in deposit()
  ───────────────────────────────────────────────────
  SWC-101 | CWE-20
  CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N → 5.3 (Medium)

  The deposit() function does not validate the deposit amount against
  minimum thresholds. Dust deposits can be used to manipulate internal
  accounting and gas costs scale linearly with depositor count.

  Affected: contracts/Vault.sol:30-38
  Fix: Add require(amount >= MIN_DEPOSIT, "Below minimum").

  [MEDIUM] M-02: Missing Event on State Change
  ─────────────────────────────────────────────
  SWC-103 | CWE-778
  CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:N/A:N → 3.7 (Medium)

  The setFeePercent() function modifies critical protocol state without
  emitting an event. Off-chain monitoring cannot track fee changes.

  Affected: contracts/Vault.sol:71
  Fix: Emit FeeUpdated(feePercent) event.

  [LOW] L-01: Naming Convention Violation
  ───────────────────────────────────────
  SWC-108 | CWE-479
  Function get_TotalAssets() should use mixedCase (getTotalAssets).

  [INFO] I-01: Costly Iteration in distributeRewards()
  ─────────────────────────────────────────────────────
  The function iterates over all depositors; consider bounded pagination.

SEVERITY DISTRIBUTION
─────────────────────

  Critical  ████░░░░░░░░░░░░░░░░  1 (14.3%)
  High      ████████░░░░░░░░░░░░  2 (28.6%)
  Medium    ████████░░░░░░░░░░░░  2 (28.6%)
  Low       ████░░░░░░░░░░░░░░░░  1 (14.3%)
  Info      ████░░░░░░░░░░░░░░░░  1 (14.3%)

Report generated in 1.2s. Output: reports/VaultProtocol-audit-2026-04-03.md`,
  },
];
