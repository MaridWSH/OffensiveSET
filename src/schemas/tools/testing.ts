import type { ToolDefinition } from "./types.js";

export const TESTING_TOOLS: ToolDefinition[] = [
  {
    name: "foundry",
    description:
      "Solidity development toolkit. Includes forge (testing/building), cast (RPC interaction), and anvil (local fork). Industry standard for smart contract testing with fuzzing, invariant testing, and mainnet fork testing.",
    category: "exploitation",
    parameters: {
      mode: {
        type: "string",
        description:
          "Operation mode: 'test' for running test suites, 'build' for compiling contracts, 'script' for deploying/executing scripts, 'fuzz' for property-based fuzzing.",
        required: true,
        examples: ["test", "build", "script", "fuzz"],
      },
      match: {
        type: "string",
        description:
          "Filter tests or contracts to run. Supports --match-test for specific test functions and --match-contract for targeting specific contract test suites.",
        required: false,
        examples: ["--match-test testExploit", "--match-contract VaultExploitTest"],
      },
      flags: {
        type: "array",
        description:
          "Additional CLI flags. Common flags: -vvv (verbose output with traces), --gas-report (gas usage analysis), --fuzz-runs N (number of fuzz iterations), --fork-url URL (mainnet fork endpoint), --show-logs (emit console logs during tests).",
        required: false,
        examples: ["-vvv", "--gas-report", "--fuzz-runs", "10000", "--fork-url", "http://127.0.0.1:8545", "--show-logs"],
      },
    },
    example_commands: [
      "forge test --match-contract VaultExploitTest -vvv --show-logs",
      "forge test --match-test testFuzz_WithdrawReentrancy --fuzz-runs 10000 -vvv",
      "forge test --fork-url https://eth-mainnet.g.alchemy.com/v2/KEY --match-contract MainnetForkTest -vvv",
      "forge test --gas-report --match-contract GasAnalysisTest",
      "forge build --sizes",
      "forge test --match-test invariant_withdrawFuzz --fuzz-runs 50000 --show-logs",
    ],
    typical_output: `Running 6 tests for test/VaultExploitTest.t.sol:VaultExploitTest
[PASS] testDeploy() (gas: 45231)
[PASS] testExploit_Reentrancy() (gas: 187432)
Logs:
  [Before] Vault balance: 1000.0 ETH
  [Step 1] Attacker deposits 10.0 ETH
  [Step 2] Attacker calls withdraw() - reentrancy triggered
  [Step 3] Recursive drain complete: 990.0 ETH extracted
  [After] Vault balance: 0.0001 ETH | Attacker profit: 980.0 ETH

[PASS] testExploit_FlashLoanManipulation() (gas: 342891)
Logs:
  Flash loan: 5000 WETH borrowed
  Oracle price manipulated: 2500 -> 0.05
  Liquidation profit: 127.3 WETH
  Loan repaid. Net profit: 127.3 WETH

[FAIL] testExploit_AccessControl()
Error: a == b not satisfied [address]
      Left: 0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496
     Right: 0x0000000000000000000000000000000000000000

[PASS] testExploit_PriceOracleSpoof() (gas: 256104)
[FAIL] testExploit_SignatureReplay()
Error: EvmError: Revert
    at src/Vault.sol:142

Traces:
  [256104] VaultExploitTest::testExploit_SignatureReplay()
    ├─ [0] VM::expectRevert()
    │   └─ ← ()
    ├─ [23451] Vault::withdrawWithSignature(0xAbC...123, 100e18, 0xSig...)
    │   ├─ [23451] Vault::_verifySignature()
    │   │   └─ ← Revert
    └─ ← Revert

Suite result: FAILED. 4 passed; 2 failed; 0 skipped; finished in 245.67ms

Ran 2 test suites: 4 tests passed, 2 failed, 6 total (1 skipped)

Summary of gas usage:
  testDeploy                        min: 45231    avg: 45231    max: 45231
  testExploit_Reentrancy            min: 187432   avg: 187432   max: 187432
  testExploit_FlashLoanManipulation min: 342891   avg: 342891   max: 342891
  testExploit_PriceOracleSpoof      min: 256104   avg: 256104   max: 256104`,
  },
  {
    name: "echidna",
    description:
      "Property-based fuzzing tool for Solidity smart contracts. Uses randomized input generation and property assertions to discover edge cases, invariant violations, and unexpected contract behavior.",
    category: "exploitation",
    parameters: {
      target: {
        type: "string",
        description:
          "Path to the Solidity contract file or directory to fuzz. Can target a specific contract name within the file.",
        required: true,
        examples: ["src/Vault.sol", "src/Vault.sol:Vault"],
      },
      config: {
        type: "string",
        description:
          "Path to Echidna YAML configuration file specifying test mode, coverage, corpus directory, and seed values.",
        required: false,
        examples: ["echidna-config.yaml", ".echidna/config.yaml"],
      },
      test_mode: {
        type: "string",
        description:
          "Echidna testing strategy: 'assertion' checks Solidity assert/require/revert, 'property' runs functions prefixed with echidna_, 'overflow' detects arithmetic overflows, 'exploration' maximizes code coverage.",
        required: false,
        default: "assertion",
        examples: ["assertion", "property", "overflow", "exploration"],
      },
      flags: {
        type: "array",
        description:
          "Additional CLI flags. Common flags: --corpus-dir DIR (save interesting inputs), --seed N (reproducible runs), --test-limit N (max transactions), --shrink-limit N (minimize failing input), --format text (output format).",
        required: false,
        examples: [
          "--corpus-dir corpus",
          "--seed 12345",
          "--test-limit 100000",
          "--shrink-limit 5000",
          "--format text",
        ],
      },
    },
    example_commands: [
      "echidna src/Vault.sol --contract Vault --test-mode assertion --test-limit 50000 --corpus-dir corpus",
      "echidna src/Token.sol --contract Token --test-mode property --seed 42 --shrink-limit 5000",
      "echidna src/ --config echidna-config.yaml --test-limit 100000 --corpus-dir corpus_vault",
      "echidna src/LendingPool.sol --test-mode overflow --format text --test-limit 25000",
    ],
    typical_output: `Analyzing contract: src/Vault.sol:Vault
Starting fuzzing with mode: assertion
Seed: 42981
Test limit: 50000 transactions

echidna_invariant_totalSupplyConstant: FAILED!
  Call sequence:
    deposit() Value: 1000000000000000000
    withdraw(500000000000000000)
    flashLoan(9990000000000000000999000000000000000)
    donate{value: 1}()
    exploitReentrancy{value: 10000000000000000}(1000)

  Breaker invariant violated:
    totalSupply before: 1000000000000000000
    totalSupply after:  1000900000000000000
    Delta: +9000000000000000 (supply increased without deposit)

  Shrunk 4723 -> 5 calls in 31.2s

echidna_invariant_userBalanceNonNegative: FAILED!
  Call sequence:
    deposit() Value: 1000000000000000000
    transfer(0x5B38Da6a701c568545dCfcB03FcB875f56beddC4, 1000000000000000000)
    emergencyWithdraw()
    claimRewards()

  Assertion failed at src/Vault.sol:287:
    require(userBalances[msg.sender] >= amount, "Insufficient balance");
    userBalance became negative: -999000000000000000

  Shrunk 1247 -> 4 calls in 18.7s

echidna_invariant_protocolSolvent: PASSED
echidna_invariant_accessControl: PASSED

Statistics:
  Unique commands:       1847
  Total commands:        47832
  Unique sequences:      29134
  Coverage:              89.2% (312/350 basic blocks)
  Elapsed time:          4m 12s
  Corpus size:           47 entries

Results:
  2 invariants failed, 2 invariants passed
  Vulnerability classes detected:
    - Reentrancy (totalSupply inflation)
    - Integer underflow (balance manipulation)

Saving corpus to: corpus/
Saved corpus with 47 test cases (47 new)`,
  },
  {
    name: "hardhat",
    description:
      "JavaScript/TypeScript development environment for Ethereum smart contracts. Provides testing framework, debugging tools, network forking, and plugin ecosystem for comprehensive smart contract testing.",
    category: "exploitation",
    parameters: {
      task: {
        type: "string",
        description:
          "Hardhat task to execute: 'test' runs test suites, 'compile' builds contracts, 'run' executes scripts, 'node' starts local network, 'console' opens interactive console.",
        required: true,
        examples: ["test", "compile", "run", "node", "console"],
      },
      network: {
        type: "string",
        description:
          "Target network: 'localhost' for local node, 'hardhat' for built-in network, 'mainnet-fork' for forked mainnet state, or any custom network defined in hardhat.config.",
        required: false,
        default: "hardhat",
        examples: ["localhost", "hardhat", "mainnet-fork", "goerli"],
      },
      flags: {
        type: "array",
        description:
          "Additional CLI flags. Common flags: --grep PATTERN (filter tests), --no-compile (skip compilation), --parallel (run tests in parallel), --gas-reporter (gas analysis), --bail (stop on first failure).",
        required: false,
        examples: ["--grep exploit", "--no-compile", "--parallel", "--gas-reporter", "--bail"],
      },
    },
    example_commands: [
      "npx hardhat test test/VaultExploit.test.ts --no-compile --gas-reporter",
      "npx hardhat test test/FlashLoan.test.ts --network mainnet-fork --grep 'manipulation'",
      "npx hardhat run scripts/exploit-vault.ts --network localhost",
      "npx hardhat test --parallel --bail",
    ],
    typical_output: `npx hardhat test test/VaultExploit.test.ts --no-compile --gas-reporter


  VaultExploit
    Reentrancy Attack
      ✔ should exploit vulnerable withdraw function (142ms)
      ✔ should drain all vault funds via recursive calls
      ✔ should revert when vault is already drained

    Flash Loan Manipulation
      ✔ should manipulate price oracle via flash loan (89ms)
      ✔ should profit from liquidation after oracle manipulation
      ⚠ Warning: Oracle price deviated >90% from TWAP

    Access Control Bypass
      1) should bypass owner-only restriction on withdraw


  5 passing (1s)
  1 failing

  1) VaultExploit
       Access Control Bypass
         should bypass owner-only restriction on withdraw:
     AssertionError: Expected transaction to be reverted
      at Context.<anonymous> (test/VaultExploit.test.ts:142:31)

  ·------------------------------------------------------|---------------------------|-------------|-----------------------------·
  |                    Solc version: 0.8.19               |···························|·············|·····························|
  |  Enabled via EVM version: london                      |···························|·············|·····························|
  |  Compiler: optimized (runs: 200)                      |···························|·············|·····························|
  |  Method Name                                          |  Min                      |  Max        |  Avg                        |
  |  -----------------------------------------------------|---------------------------|-------------|-----------------------------|
  |  Vault.deposit()                                      |                   45231   |      45231  |                      45231  |
  |  Vault.withdraw()                                     |                  123847   |     187432  |                     155640  |
  |  Vault.flashLoan(address,uint256)                     |                  298123   |     342891  |                     320507  |
  |  Vault.emergencyWithdraw()                            |                   67234   |      67234  |                      67234  |
  |  ExploitContract.executeReentrancy()                  |                  412891   |     587234  |                     500063  |
  |  -----------------------------------------------------|---------------------------|-------------|-----------------------------|`,
  },
];
