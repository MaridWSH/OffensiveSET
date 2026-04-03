export type { ToolDefinition, ToolParam } from "./types.js";
import type { ToolDefinition } from "./types.js";
import { ANALYSIS_TOOLS } from "./analysis.js";
import { TESTING_TOOLS } from "./testing.js";
import { EXPLORATION_TOOLS } from "./exploration.js";
import { UTILITY_TOOLS } from "./utility.js";

export const SMARTCONTRACT_TOOLS: ToolDefinition[] = [
  ...ANALYSIS_TOOLS,
  ...TESTING_TOOLS,
  ...EXPLORATION_TOOLS,
  ...UTILITY_TOOLS,
];

export { ANALYSIS_TOOLS, TESTING_TOOLS, EXPLORATION_TOOLS, UTILITY_TOOLS };

export const TOOL_NAMES = SMARTCONTRACT_TOOLS.map(t => t.name);

export function getToolByName(name: string): ToolDefinition | undefined {
  return SMARTCONTRACT_TOOLS.find(t => t.name === name);
}

export function getToolsByCategory(category: ToolDefinition["category"]): ToolDefinition[] {
  return SMARTCONTRACT_TOOLS.filter(t => t.category === category);
}
