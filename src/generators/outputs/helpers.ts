// Shared types, data constants, and helper functions for smart contract output generators

export class SeededRNG {
  private seed: number;

  constructor(seed: number) {
    this.seed = seed;
  }

  next(): number {
    this.seed = (this.seed * 1664525 + 1013904223) & 0xffffffff;
    return (this.seed >>> 0) / 0xffffffff;
  }

  pick<T>(arr: T[]): T {
    return arr[Math.floor(this.next() * arr.length)];
  }

  pickN<T>(arr: T[], n: number): T[] {
    const shuffled = [...arr].sort(() => this.next() - 0.5);
    return shuffled.slice(0, Math.min(n, arr.length));
  }

  int(min: number, max: number): number {
    return Math.floor(this.next() * (max - min + 1)) + min;
  }

  float(min: number, max: number): number {
    return min + this.next() * (max - min);
  }

  bool(probability: number = 0.5): boolean {
    return this.next() < probability;
  }
}

export interface ContractProfile {
  protocolName: string;
  chainId: number;
  contractAddress: string;
  contractName: string;
  solidityVersion: string;
  inheritanceChain: string[];
  stateVariables: StateVar[];
  externalFunctions: FuncDef[];
  events: string[];
  dependencies: string[];
  vulnType: string;
  affectedFunction: string;
  missingCheck: string;
  impactType: string;
  severity: string;
  exploitComplexity: "trivial" | "moderate" | "complex";
  requiresFork: boolean;
  requiresCapital: number;
  pocType: "unit" | "fork" | "fuzz" | "invariant";
  tvl: string;
  tokenPrice: string;
  affectedToken: string;
}

export interface StateVar {
  name: string;
  type: string;
  visibility: string;
}

export interface FuncDef {
  name: string;
  visibility: string;
  modifiers: string[];
  params: string[];
}

export interface OutputContext {
  rng: SeededRNG;
  generateDate(): string;
  generateUUID(): string;
  generateHex(length: number): string;
  generateAddress(): string;
  generateTxHash(): string;
  generateBlockNumber(): number;
  generateAmount(): string;
  generateGasUsed(): number;
  generateRandomAuditor(): { handle: string; firm: string };
  generateTimestamp(): number;
}

// ============================================================
// Protocol Data
// ============================================================

const PROTOCOL_NAMES = [
  "Alchemix", "ZeroLend", "Folks Finance", "Puffer Finance", "Lombard Finance",
  "DeGate", "Fuel Network", "Celo", "BadgerDAO", "Aave", "Compound",
  "Uniswap", "Curve", "SushiSwap", "Balancer", "Yearn",
  "Convex", "Frax", "Lido", "Rocket Pool", "Eigenlayer",
  "Saffron", "Ostium", "Shardeum", "Anvil", "IDEX",
  "Jito", "Butter Protocol", "Acre", "ThunderNFT", "Swaylend",
];

const CONTRACT_NAMES = [
  "Voter", "RevenueHandler", "PoolVoter", "OmnichainStaking", "RewardDistributor",
  "Vault", "LendingPool", "Bridge", "Adapter", "Treasury",
  "StakingManager", "Governor", "Timelock", "Token", "NFTMarketplace",
  "LiquidationEngine", "PriceOracle", "FeeCollector", "Escrow", "MintManager",
  "LiquidityPool", "SwapRouter", "PerpetualsManager", "InsuranceFund", "YieldOptimizer",
];

const TOKEN_NAMES = [
  "FLUX", "ALCX", "zFLX", "veALCX", "ZERO", "zZERO", "vZERO",
  "LBTC", "stBTC", "pBTC", "FUEL", "stFUEL", "celoCELO",
  "LPX", "vLPX", "SOLID", "veSOLID", "BRG", "stkBRG",
  "THUNDER", "veTHUNDER", "SWAY", "veSWAY", "ACRE", "vACRE",
];

const CHAIN_DATA = [
  { id: 1, name: "Ethereum", rpc: "https://eth.llamarpc.com", blockTime: 12 },
  { id: 42161, name: "Arbitrum", rpc: "https://arb1.arbitrum.io/rpc", blockTime: 0.25 },
  { id: 10, name: "Optimism", rpc: "https://mainnet.optimism.io", blockTime: 2 },
  { id: 8453, name: "Base", rpc: "https://mainnet.base.org", blockTime: 2 },
  { id: 137, name: "Polygon", rpc: "https://polygon-rpc.com", blockTime: 2 },
  { id: 56, name: "BNB Chain", rpc: "https://bsc-dataseed.binance.org", blockTime: 3 },
];

const SOLIDITY_VERSIONS = ["0.7.6", "0.8.0", "0.8.4", "0.8.10", "0.8.13", "0.8.17", "0.8.19", "0.8.20", "0.8.23", "0.8.24"];

const INHERITANCE_CHAINS = [
  ["Ownable", "ReentrancyGuard"],
  ["OwnableUpgradeable", "ReentrancyGuardUpgradeable", "Initializable"],
  ["Pausable", "AccessControl", "ERC20"],
  ["UUPSUpgradeable", "AccessControlUpgradeable"],
  ["Multicall", "ERC20Permit", "ERC20"],
  ["Governor", "GovernorVotes", "GovernorVotesQuorumFraction", "GovernorTimelockControl"],
  ["BaseBridge", "MessageRelay", "AccessControl"],
  ["OracleAggregator", "PriceFeed", "Ownable"],
];

const STATE_VAR_TEMPLATES = [
  { name: "totalSupply", type: "uint256", visibility: "public" },
  { name: "balances", type: "mapping(address => uint256)", visibility: "public" },
  { name: "owner", type: "address", visibility: "public" },
  { name: "paused", type: "bool", visibility: "public" },
  { name: "rewardIndex", type: "uint256", visibility: "public" },
  { name: "accRewardPerShare", type: "uint256", visibility: "public" },
  { name: "userInfo", type: "mapping(address => UserInfo)", visibility: "public" },
  { name: "stakingToken", type: "IERC20", visibility: "public" },
  { name: "rewardToken", type: "IERC20", visibility: "public" },
  { name: "epoch", type: "uint256", visibility: "public" },
  { name: "lockEndTime", type: "uint256", visibility: "public" },
  { name: "votingPower", type: "mapping(address => uint256)", visibility: "public" },
  { name: "delegatedAmount", type: "mapping(address => uint256)", visibility: "public" },
  { name: "bridgeNonce", type: "mapping(uint256 => uint256)", visibility: "public" },
  { name: "priceFeed", type: "IPriceOracle", visibility: "public" },
  { name: "feeRate", type: "uint256", visibility: "public" },
  { name: "treasury", type: "address", visibility: "public" },
  { name: "implementation", type: "address", visibility: "private" },
];

const FUNC_TEMPLATES = [
  { name: "stake", visibility: "external", modifiers: ["nonReentrant"], params: ["uint256 amount"] },
  { name: "withdraw", visibility: "external", modifiers: ["nonReentrant"], params: ["uint256 amount"] },
  { name: "claim", visibility: "external", modifiers: [], params: [] },
  { name: "poke", visibility: "external", modifiers: [], params: ["uint256 tokenId"] },
  { name: "vote", visibility: "external", modifiers: [], params: ["address[] calldata pools", "uint256[] calldata weights"] },
  { name: "delegate", visibility: "external", modifiers: [], params: ["address delegatee", "uint256 amount"] },
  { name: "execute", visibility: "external", modifiers: ["onlyGovernor"], params: ["address target", "uint256 value", "bytes calldata data"] },
  { name: "bridge", visibility: "external", modifiers: [], params: ["uint256 destChainId", "address recipient", "uint256 amount"] },
  { name: "receiveMessage", visibility: "external", modifiers: [], params: ["bytes calldata payload", "bytes calldata proof"] },
  { name: "mint", visibility: "external", modifiers: ["onlyMinter"], params: ["address to", "uint256 amount"] },
  { name: "setPrice", visibility: "external", modifiers: ["onlyOracle"], params: ["address token", "uint256 price"] },
  { name: "liquidate", visibility: "external", modifiers: [], params: ["address borrower", "uint256 debtToCover"] },
];

const DEPENDENCIES = [
  "@openzeppelin/contracts/token/ERC20/IERC20.sol",
  "@openzeppelin/contracts/access/Ownable.sol",
  "@openzeppelin/contracts/security/ReentrancyGuard.sol",
  "@openzeppelin/contracts/utils/math/SafeMath.sol",
  "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol",
  "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol",
  "@openzeppelin/contracts/governance/Governor.sol",
  "forge-std/Test.sol",
  "forge-std/console.sol",
  "solmate/auth/Owned.sol",
];

const AUDITOR_HANDLES = [
  "Pashov Audit Group", "Trail of Bits", "OpenZeppelin", "Cyfrin", "Code4rena",
  "Sherlock", "Consensys Diligence", "Quantstamp", "Hexens", "Sigma Prime",
  "OtterSec", "Cantina", "Halborn", "Spearbit", "ZachObront",
  "Codehawks", "0x52", "Trust Security", "MixBytes", "Recon Audits",
];

const TVL_VALUES = ["$5M", "$12M", "$23M", "$45M", "$67M", "$89M", "$120M", "$250M", "$500M", "$1.2B", "$2.5B"];
const TOKEN_PRICES = ["$0.0034", "$0.12", "$0.45", "$1.23", "$2.87", "$5.67", "$12.34", "$45.00", "$123.45", "$1,234.56"];
const SEVERITY_LEVELS = ["Critical", "High", "Medium", "Low", "Informational"];
const EXPLOIT_COMPLEXITIES: Array<"trivial" | "moderate" | "complex"> = ["trivial", "moderate", "complex"];
const POC_TYPES: Array<"unit" | "fork" | "fuzz" | "invariant"> = ["unit", "fork", "fuzz", "invariant"];
const IMPACT_TYPES = [
  "unlimited minting", "fund drainage", "governance takeover", "privilege escalation",
  "denial of service", "permanent fund lock", "price manipulation", "fee bypass",
  "reward inflation", "collateral liquidation", "oracle manipulation", "reentrancy drain",
];
const VULN_TYPES = [
  "unauthorized-mint", "oracle-manipulation", "reentrancy", "access-control-bypass",
  "integer-overflow", "rounding-precision", "signature-replay", "storage-collision",
  "logic-error", "fee-bypass", "initialization-missing", "timelock-bypass",
  "cross-chain-replay", "dos-griefing", "mev-front-running", "decimal-mismatch",
];

// ============================================================
// Generator Functions
// ============================================================

export function generateContractProfile(rng: SeededRNG, vulnType?: string): ContractProfile {
  const protocolName = rng.pick(PROTOCOL_NAMES);
  const contractName = rng.pick(CONTRACT_NAMES);
  const chainData = rng.pick(CHAIN_DATA);
  const tokenName = rng.pick(TOKEN_NAMES);

  const nStateVars = rng.int(6, 12);
  const nFuncs = rng.int(4, 8);

  return {
    protocolName,
    chainId: chainData.id,
    contractAddress: `0x${generateHex(rng, 40)}`,
    contractName,
    solidityVersion: rng.pick(SOLIDITY_VERSIONS),
    inheritanceChain: rng.pick(INHERITANCE_CHAINS),
    stateVariables: rng.pickN(STATE_VAR_TEMPLATES, nStateVars).map(v => ({ ...v })),
    externalFunctions: rng.pickN(FUNC_TEMPLATES, nFuncs).map(f => ({ ...f })),
    events: rng.pickN(["Staked", "Withdrawn", "RewardClaimed", "Voted", "Bridged", "Minted", "Burned", "Liquidated", "PriceUpdated", "OwnershipTransferred"], rng.int(3, 6)),
    dependencies: rng.pickN(DEPENDENCIES, rng.int(3, 6)),
    vulnType: vulnType || rng.pick(VULN_TYPES),
    affectedFunction: rng.pick(FUNC_TEMPLATES).name + "()",
    missingCheck: rng.pick(["onlyNewEpoch modifier", "access control modifier", "zero address check", "rate limit validation", "signature uniqueness check", "chainId binding", "overflow protection", "reentrancy guard"]),
    impactType: rng.pick(IMPACT_TYPES),
    severity: rng.pick(SEVERITY_LEVELS),
    exploitComplexity: rng.pick(EXPLOIT_COMPLEXITIES),
    requiresFork: rng.bool(0.6),
    requiresCapital: rng.pick([0, 0, 0, 100, 1000, 10000, 100000]),
    pocType: rng.pick(POC_TYPES),
    tvl: rng.pick(TVL_VALUES),
    tokenPrice: rng.pick(TOKEN_PRICES),
    affectedToken: tokenName,
  };
}

function generateHex(rng: SeededRNG, length: number): string {
  const chars = "0123456789abcdef";
  return Array.from({ length }, () => chars[Math.floor(rng.next() * 16)]).join("");
}

export function generateAddress(rng: SeededRNG): string {
  return `0x${generateHex(rng, 40)}`;
}

export function generateTxHash(rng: SeededRNG): string {
  return `0x${generateHex(rng, 64)}`;
}

export function generateBlockNumber(rng: SeededRNG): number {
  return rng.int(18000000, 20000000);
}

export function generateAmount(rng: SeededRNG): string {
  const amounts = ["0.001 ether", "0.01 ether", "0.1 ether", "1 ether", "10 ether", "100 ether", "1000 ether", "1000000000000000000", "10000000000000000000", "100000000000000000000"];
  return rng.pick(amounts);
}

export function generateGasUsed(rng: SeededRNG): number {
  return rng.int(21000, 2000000);
}

export function generateRandomAuditor(rng: SeededRNG): { handle: string; firm: string } {
  const firm = rng.pick(AUDITOR_HANDLES);
  const handles = ["0x" + generateHex(rng, 4).toLowerCase(), "auditor_" + generateHex(rng, 3), "sec_" + generateHex(rng, 4), rng.pick(["whitehat", "researcher", "warden"]) + rng.int(1, 9999)];
  return { handle: rng.pick(handles), firm };
}

export function generateTimestamp(rng: SeededRNG): number {
  return rng.int(1700000000, 1720000000);
}
