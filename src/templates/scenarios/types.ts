// Scenario and attack phase type definitions for Smart Contract Security

export interface ScenarioTemplate {
  id: string;
  category: string;
  subcategory: string;
  title: string;
  difficulty: "beginner" | "intermediate" | "advanced" | "expert";
  description: string;
  target_description: string;
  attack_phases: AttackPhase[];
  cve_references?: string[];
  tools_involved: string[];
  tags: string[];
}

export interface AttackPhase {
  phase: string;
  description: string;
  tools: string[];
  commands: string[];
  expected_output: string;
  thinking?: string;  // Chain-of-thought reasoning
  analysis: string;
  next_action: string;
}

// Smart Contract-specific types

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
  slot?: number;
}

export interface FuncDef {
  name: string;
  visibility: string;
  modifiers: string[];
  params: string[];
}

export interface AuditFinding {
  severity: "Critical" | "High" | "Medium" | "Low" | "Informational";
  contract: string;
  functionName: string;
  title: string;
  description: string;
  attackPath: string[];
  impact: string;
  recommendation: string;
  secureCodeSnippet: string;
  cvssScore: number;
  swcIds: string[];
  cweIds: string[];
}
