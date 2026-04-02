// Combine all scenario categories

export type { ScenarioTemplate, AttackPhase } from "./types.js";

import type { ScenarioTemplate } from "./types.js";
import { OWASP_SCENARIOS } from "./owasp.js";
import { MODERN_ATTACK_SCENARIOS } from "./modern.js";
import { API_SECURITY_SCENARIOS } from "./api.js";
import { ADVANCED_SCENARIOS } from "./advanced.js";

export const ALL_SCENARIOS: ScenarioTemplate[] = [
  ...OWASP_SCENARIOS,
  ...MODERN_ATTACK_SCENARIOS,
  ...API_SECURITY_SCENARIOS,
  ...ADVANCED_SCENARIOS,
];

export { OWASP_SCENARIOS, MODERN_ATTACK_SCENARIOS, API_SECURITY_SCENARIOS, ADVANCED_SCENARIOS };

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
