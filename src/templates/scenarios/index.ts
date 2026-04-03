// Combine all smart contract scenario categories

export type { ScenarioTemplate, AttackPhase, ContractProfile, StateVar, FuncDef, AuditFinding } from "./types.js";

import type { ScenarioTemplate } from "./types.js";
import { DEFI_SCENARIOS } from "./defi.js";
import { GOVERNANCE_SCENARIOS } from "./governance.js";
import { CROSSCHAIN_SCENARIOS } from "./crosschain.js";
import { NFT_SCENARIOS } from "./nft.js";
import { CORE_SCENARIOS } from "./core.js";

export const ALL_SCENARIOS: ScenarioTemplate[] = [
  ...DEFI_SCENARIOS,
  ...GOVERNANCE_SCENARIOS,
  ...CROSSCHAIN_SCENARIOS,
  ...NFT_SCENARIOS,
  ...CORE_SCENARIOS,
];

export { DEFI_SCENARIOS, GOVERNANCE_SCENARIOS, CROSSCHAIN_SCENARIOS, NFT_SCENARIOS, CORE_SCENARIOS };

export function getScenariosByCategory(category: string): ScenarioTemplate[] {
  return ALL_SCENARIOS.filter(s => s.category === category || s.subcategory.includes(category));
}

export function getScenariosByTag(tag: string): ScenarioTemplate[] {
  return ALL_SCENARIOS.filter(s => s.tags.includes(tag));
}

export function getScenariosByDifficulty(difficulty: ScenarioTemplate["difficulty"]): ScenarioTemplate[] {
  return ALL_SCENARIOS.filter(s => s.difficulty === difficulty);
}

export function getScenarioById(id: string): ScenarioTemplate | undefined {
  return ALL_SCENARIOS.find(s => s.id === id);
}

export const SCENARIO_CATEGORIES = [...new Set(ALL_SCENARIOS.map(s => s.category))];
export const SCENARIO_TAGS = [...new Set(ALL_SCENARIOS.flatMap(s => s.tags))];
