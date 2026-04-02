export type { ToolDefinition, ToolParam } from "./types.js";
import type { ToolDefinition } from "./types.js";
import { RECON_TOOLS } from "./recon.js";
import { ENUM_TOOLS } from "./enum.js";
import { SCAN_TOOLS } from "./scan.js";
import { EXPLOIT_TOOLS } from "./exploit.js";
import { UTILITY_TOOLS } from "./utility.js";

export const PENTESTING_TOOLS: ToolDefinition[] = [
  ...RECON_TOOLS,
  ...ENUM_TOOLS,
  ...SCAN_TOOLS,
  ...EXPLOIT_TOOLS,
  ...UTILITY_TOOLS,
];

export { RECON_TOOLS, ENUM_TOOLS, SCAN_TOOLS, EXPLOIT_TOOLS, UTILITY_TOOLS };

export const TOOL_NAMES = PENTESTING_TOOLS.map(t => t.name);

export function getToolByName(name: string): ToolDefinition | undefined {
  return PENTESTING_TOOLS.find(t => t.name === name);
}

export function getToolsByCategory(category: ToolDefinition["category"]): ToolDefinition[] {
  return PENTESTING_TOOLS.filter(t => t.category === category);
}
