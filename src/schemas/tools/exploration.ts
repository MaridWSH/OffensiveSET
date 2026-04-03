import type { ToolDefinition } from "./types.js";

export const EXPLORATION_TOOLS: ToolDefinition[] = [
  {
    name: "cast",
    description:
      "Ethereum CLI tool from the Foundry toolkit. Performs RPC calls, contract interactions, transaction encoding/decoding, state queries, and ABI encoding. Essential for smart contract auditors to interact with live contracts.",
    category: "exploitation",
    parameters: {
      action: {
        type: "string",
        description:
          "The cast action to perform: 'call' for read-only function calls, 'send' for broadcasting transactions, 'decode' for ABI decoding, 'code' for retrieving bytecode, 'storage' for reading storage slots, 'create2' for deterministic address computation",
        required: true,
        examples: ["call", "send", "decode", "code", "storage"],
      },
      target: {
        type: "string",
        description:
          "Target contract address or RPC URL depending on action. For contract actions use 0x address; for RPC-level actions use the RPC endpoint",
        required: true,
        examples: ["0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984", "https://eth.llamarpc.com"],
      },
      function_sig: {
        type: "string",
        description:
          "Function signature or selector for contract calls. Can be a full signature like 'balanceOf(address)' or a 4-byte selector like '0x70a08231'",
        required: false,
        examples: ["balanceOf(address)", "0x70a08231", "transfer(address,uint256)"],
      },
      flags: {
        type: "string",
        description:
          "Additional cast flags such as --rpc-url, --block, --private-key, --from, --value, --gas-limit, --etherscan-api-key, --json, --raw",
        required: false,
        examples: ["--rpc-url https://eth.llamarpc.com --block latest --json"],
      },
    },
    example_commands: [
      "cast call 0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984 'balanceOf(address)' 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045 --rpc-url https://eth.llamarpc.com",
      "cast storage 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2 3 --rpc-url https://eth.llamarpc.com --block 19000000",
      "cast code 0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D --rpc-url https://eth.llamarpc.com --block latest",
      "cast decode-calldata 0xa9059cbb000000000000000000000000d8da6bf26964af9d7eed9e03e53415d37aa960450000000000000000000000000000000000000000000000056bc75e2d63100000 'transfer(address,uint256)'",
      "cast storage 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc --rpc-url https://eth.llamarpc.com",
    ],
    typical_output: `$ cast call 0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984 'balanceOf(address)' 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045 --rpc-url https://eth.llamarpc.com
0x00000000000000000000000000000000000000000000001b1ae4d6e2ef500000

# Decoded: 500000000000000000000 (500.0 UNI tokens)

$ cast storage 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2 3 --rpc-url https://eth.llamarpc.com --block 19000000
0x0000000000000000000000000000000000000000000000000000000000000001

$ cast code 0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D --rpc-url https://eth.llamarpc.com | head -c 200
0x6080604052600436106101355760003560e01c80638803dbee116100b0578063c45a01551161006f578063c45a01551461043c578063d06ca61f14610451578063ded9382a1461047e578063e8e33700146104a0578063f305d719146104bd578063fb3bdb41146104d557610135565b80638803dbee14610346578063ad5c45...

$ cast decode-calldata 0xa9059cbb... 'transfer(address,uint256)'
Function: transfer(address to, uint256 amount)
Method ID: 0xa9059cbb
Inputs:
  - to: 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045
  - amount: 100000000000000000000`,
  },
  {
    name: "anvil",
    description:
      "Local Ethereum node from Foundry. Spins up a fork of any EVM chain at a specific block number, enabling deterministic testing with real protocol state. Supports account impersonation, state manipulation, and transaction simulation.",
    category: "exploitation",
    parameters: {
      fork_url: {
        type: "string",
        description:
          "RPC URL of the chain to fork. Can be any EVM-compatible chain endpoint (Ethereum, Arbitrum, Optimism, Polygon, Base, etc.)",
        required: true,
        examples: ["https://eth.llamarpc.com", "https://arb1.arbitrum.io/rpc", "https://mainnet.base.org"],
      },
      fork_block_number: {
        type: "number",
        description:
          "Specific block number to fork the chain at. Using a fixed block ensures reproducible state across runs. Omit for latest block",
        required: false,
        examples: [19000000, 18500000],
      },
      flags: {
        type: "string",
        description:
          "Additional Anvil flags such as --port, --accounts, --balance, --gas-limit, --gas-price, --block-time, --no-mining, --prune-history, --host",
        required: false,
        examples: ["--port 8545 --accounts 10 --balance 10000 --gas-limit 30000000"],
      },
    },
    example_commands: [
      "anvil --fork-url https://eth.llamarpc.com --fork-block-number 19000000 --port 8545",
      "anvil --fork-url https://arb1.arbitrum.io/rpc --fork-block-number 180000000 --gas-limit 30000000",
      "anvil --fork-url https://eth.llamarpc.com --fork-block-number 19000000 --accounts 5 --balance 100000 --port 8546",
      "anvil --fork-url https://mainnet.base.org --fork-block-number 14000000 --prune-history --no-mining",
    ],
    typical_output: `$ anvil --fork-url https://eth.llamarpc.com --fork-block-number 19000000 --port 8545

                             _   _
                            (_) | |
      __ _   _ __   __   __  _  | |
     / _\` | | '_ \\  \\ \\ / / | | | |
    | (_| | | | | |  \\ V /  | | | |
     \\__,_| |_| |_|   \\_/   |_| |_|

    19000000
    https://eth.llamarpc.com

    Available Accounts
    ==================
    (0) 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 (100000 ETH)
    (1) 0x70997970C51812dc3A010C7d01b50e0d17dc79C8 (100000 ETH)
    (2) 0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC (100000 ETH)
    (3) 0x90F79bf6EB2c4f870365E785982E1f101E93b906 (100000 ETH)
    (4) 0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65 (100000 ETH)

    Private Keys
    ==================
    (0) 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
    (1) 0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d
    (2) 0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a

    Wallet
    ==================
    Mnemonic:          test test test test test test test test test test test junk
    Derivation path:   m/44'/60'/0'/0/

    Base Fee: 15.234 gwei
    Gas Price: 16.000 gwei
    Gas Limit: 30000000

    Listening on 127.0.0.1:8545`,
  },
  {
    name: "etherscan",
    description:
      "Ethereum block explorer API integration. Retrieves verified contract source code, ABI, transaction history, event logs, token holders, and internal transactions. Primary tool for understanding deployed contract state.",
    category: "recon",
    parameters: {
      action: {
        type: "string",
        description:
          "The Etherscan action to perform: 'source' for verified Solidity source code, 'abi' for contract ABI, 'tx' for transaction details, 'logs' for event logs, 'balance' for ETH/token balance, 'holders' for token holder list",
        required: true,
        examples: ["source", "abi", "tx", "logs", "balance", "holders"],
      },
      address: {
        type: "string",
        description:
          "Ethereum contract address or transaction hash depending on action. For contract-level actions use 0x address; for tx lookup use transaction hash",
        required: true,
        examples: ["0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984", "0xabc123..."],
      },
      flags: {
        type: "string",
        description:
          "Additional flags such as --api-key, --start-block, --end-block, --topic0 (event signature), --chain (eth/goerly/polygon/arbitrum), --output (json/csv)",
        required: false,
        examples: ["--api-key $ETHERSCAN_API_KEY --chain eth --output json"],
      },
    },
    example_commands: [
      "etherscan source 0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984 --api-key $ETHERSCAN_API_KEY",
      "etherscan abi 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2 --api-key $ETHERSCAN_API_KEY --output json",
      "etherscan tx 0x5c504ed432cb51138bcf09aa5e8a410dd4a1e204ef84bfed1be16dfba1b22060 --api-key $ETHERSCAN_API_KEY",
      "etherscan logs 0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984 --topic0 '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef' --start-block 18000000 --end-block 18001000 --api-key $ETHERSCAN_API_KEY",
      "etherscan balance 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045 --api-key $ETHERSCAN_API_KEY",
    ],
    typical_output: `$ etherscan source 0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D --api-key $ETHERSCAN_API_KEY
// SPDX-License-Identifier: GPL-3.0-or-later
// File: contracts/UniswapV2Router02.sol

pragma solidity =0.6.6;

import './interfaces/IUniswapV2Router02.sol';
import './interfaces/IUniswapV2Factory.sol';
import './interfaces/IERC20.sol';
import './libraries/SafeMath.sol';
import './libraries/UniswapV2Library.sol';
import './libraries/TransferHelper.sol';

contract UniswapV2Router02 is IUniswapV2Router02 {
    using SafeMath for uint256;

    address public immutable override factory;
    address public immutable override WETH;

    modifier ensure(uint deadline) {
        require(deadline >= block.timestamp, 'UniswapV2Router: EXPIRED');
        _;
    }

    constructor(address _factory, address _WETH) public {
        factory = _factory;
        WETH = _WETH;
    }

    receive() external payable {
        assert(msg.sender == WETH);
    }

    // ... 12 source files retrieved (verified on Etherscan 2021-03-15)
    // Compiler: v0.6.6+commit.6c089d02
    // Optimization: Yes (999999 runs)

$ etherscan abi 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2 --api-key $ETHERSCAN_API_KEY --output json
[
  {"constant":true,"inputs":[],"name":"name","outputs":[{"name":"","type":"string"}],"payable":false,"stateMutability":"view","type":"function"},
  {"constant":false,"inputs":[{"name":"guy","type":"address"},{"name":"wad","type":"uint256"}],"name":"approve","outputs":[{"name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},
  {"constant":true,"inputs":[],"name":"totalSupply","outputs":[{"name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},
  {"constant":false,"inputs":[{"name":"src","type":"address"},{"name":"dst","type":"address"},{"name":"wad","type":"uint256"}],"name":"transferFrom","outputs":[{"name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},
  {"constant":false,"inputs":[],"name":"deposit","outputs":[],"payable":true,"stateMutability":"payable","type":"function"},
  {"constant":true,"inputs":[{"name":"owner","type":"address"}],"name":"balanceOf","outputs":[{"name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},
  ...
]`,
  },
  {
    name: "tenderly",
    description:
      "Transaction simulation and debugging platform. Simulates transactions against real or forked chain state without executing them, providing step-by-step execution traces, state diffs, gas profiling, and error diagnostics.",
    category: "post_exploitation",
    parameters: {
      action: {
        type: "string",
        description:
          "The Tenderly action to perform: 'simulate' to run a transaction simulation, 'trace' to get a detailed step-by-step execution trace, 'estimate' to estimate gas consumption for a transaction",
        required: true,
        examples: ["simulate", "trace", "estimate"],
      },
      network: {
        type: "string",
        description:
          "Target blockchain network for simulation. Supports mainnet and L2 networks. Determines which state the simulation runs against",
        required: true,
        examples: ["mainnet", "arbitrum", "optimism", "polygon", "base"],
      },
      flags: {
        type: "string",
        description:
          "Additional flags such as --from (sender address), --to (target contract), --value (ETH amount in wei), --data (calldata hex), --block (block number), --gas-limit, --state-overrides (JSON), --save (persist simulation)",
        required: false,
        examples: ["--from 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045 --to 0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984 --data 0xa9059cbb..."],
      },
    },
    example_commands: [
      "tenderly simulate --network mainnet --from 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045 --to 0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984 --data 0xa9059cbb000000000000000000000000d8da6bf26964af9d7eed9e03e53415d37aa960450000000000000000000000000000000000000000000000056bc75e2d63100000 --block 19000000",
      "tenderly trace --network mainnet --from 0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D --to 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2 --data 0xd0e30db0 --value 1000000000000000000 --save",
      "tenderly estimate --network arbitrum --from 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 --to 0x912CE59144191C1204E64559FE8253a0e49E6548 --data 0xa9059cbb000000000000000000000000d8da6bf26964af9d7eed9e03e53415d37aa960450000000000000000000000000000000000000000000000056bc75e2d63100000",
      "tenderly simulate --network mainnet --from 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045 --to 0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D --data 0x38ed1739... --state-overrides '{\"0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045\":{\"balance\":\"0x56BC75E2D63100000\"}}'",
    ],
    typical_output: `$ tenderly simulate --network mainnet --from 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045 --to 0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984 --data 0xa9059cbb... --block 19000000

Simulation ID: sim-abc123def456
Network: Ethereum Mainnet
Block: 19000000 (2024-02-15 08:32:11 UTC)
Status: SUCCESS
Gas Used: 46,523 / 30,000,000

Execution Trace:
┌─ Step ─┬─ Operation ──────────────────────────┬─ Gas ───────┬─ Refund ────┬─ Depth ─┐
│   0    │ CALL                                │ 30,000,000  │            │   0    │
│   1    │ ├─ SLOAD                            │ 29,952,000  │            │   1    │
│   2    │ ├─ transfer(address,uint256)        │ 29,949,900  │            │   1    │
│   3    │ │  ├─ require(balances[msg.sender] │            │            │   2    │
│   4    │ │  ├─ BALANCE_SUB: 50000000000...  │ 29,940,000  │            │   2    │
│   5    │ │  ├─ BALANCE_ADD: 50000000000...  │ 29,938,000  │            │   2    │
│   6    │ │  └─ emit Transfer(...)           │ 29,936,000  │            │   2    │
│   7    │ └─ RETURN: 0x0000...0001          │ 29,934,477  │            │   1    │
└────────┴─────────────────────────────────────┴─────────────┴────────────┴────────┘

State Changes:
  Storage[0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984][0x429...f23]
    Before: 0x00000000000000000000000000000000000000000000001b1ae4d6e2ef500000
    After:  0x000000000000000000000000000000000000000000000015b8c39d3b2c400000
    Delta:  -500,000,000,000,000,000,000 (500 UNI)

Events Emitted:
  Transfer(
    from: 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045,
    to:   0x70997970C51812dc3A010C7d01b50e0d17dc79C8,
    value: 500000000000000000000
  )

Simulation URL: https://dashboard.tenderly.co/sim/sim-abc123def456`,
  },
  {
    name: "dune",
    description:
      "On-chain analytics platform. Queries indexed blockchain data using SQL to analyze protocol usage, token flows, event patterns, and historical state. Used by auditors to quantify real-world impact of vulnerabilities.",
    category: "recon",
    parameters: {
      query: {
        type: "string",
        description:
          "SQL query to execute against Dune's indexed blockchain data. Supports standard SQL with Dune-specific tables like ethereum.transactions, erc20_ethereum.evt_Transfer, dex.trades, etc.",
        required: true,
        examples: [
          "SELECT date_trunc('day', evt_block_time) as day, sum(value/1e18) as volume FROM uniswap_v3_ethereum.Swap_evt GROUP BY 1 ORDER BY 1 DESC LIMIT 30",
          "SELECT COUNT(*) FROM ethereum.transactions WHERE block_number > 19000000",
        ],
      },
      output: {
        type: "string",
        description:
          "Output format for query results. 'table' for formatted terminal output, 'csv' for CSV export, 'json' for raw JSON",
        required: false,
        default: "table",
        examples: ["table", "csv", "json"],
      },
      flags: {
        type: "string",
        description:
          "Additional flags such as --api-key (Dune API key), --query-id (run saved query by ID), --limit (max rows), --since (date filter), --output-file (write to file)",
        required: false,
        examples: ["--api-key $DUNE_API_KEY --limit 100 --output-file results.csv"],
      },
    },
    example_commands: [
      "dune query \"SELECT date_trunc('day', evt_block_time) as day, COUNT(*) as swap_count, SUM(amount_usd) as volume_usd FROM uniswap_v3_ethereum.Swap_evt WHERE evt_block_time > NOW() - INTERVAL '30 days' GROUP BY 1 ORDER BY 1 DESC\" --api-key $DUNE_API_KEY --limit 30",
      "dune query \"SELECT holder_address, SUM(value/1e18) as balance, COUNT(DISTINCT contract_address) as token_count FROM erc20_ethereum.evt_Transfer WHERE to_address = 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045 GROUP BY 1 ORDER BY 2 DESC LIMIT 20\" --api-key $DUNE_API_KEY",
      "dune query --query-id 3547891 --api-key $DUNE_API_KEY --output-file aave_v3_liquidation_analysis.csv",
    ],
    typical_output: `$ dune query "SELECT date_trunc('day', evt_block_time) as day, COUNT(*) as swap_count, SUM(amount_usd) as volume_usd FROM uniswap_v3_ethereum.Swap_evt WHERE evt_block_time > NOW() - INTERVAL '30 days' GROUP BY 1 ORDER BY 1 DESC" --api-key $DUNE_API_KEY --limit 30

Query executed successfully (execution time: 12.4s)
Rows: 30  |  Query ID: 3891234  |  Cached: false

| day                  | swap_count | volume_usd        |
|----------------------|------------|-------------------|
| 2026-04-02 00:00:00  | 48,291     | $287,432,109.45   |
| 2026-04-01 00:00:00  | 52,103     | $312,891,224.18   |
| 2026-03-31 00:00:00  | 44,817     | $265,118,437.92   |
| 2026-03-30 00:00:00  | 41,209     | $243,507,881.33   |
| 2026-03-29 00:00:00  | 38,445     | $221,394,552.07   |
| ...                  | ...        | ...               |
| 2026-03-04 00:00:00  | 35,112     | $198,227,643.91   |

30 rows returned. 30-day avg daily swaps: 42,847 | 30-day avg daily volume: $254.2M`,
  },
];
