// Quality scoring engine for Dataset Generator V2

import { ShareGPTConversation } from "./types.js";

export function scoreEntryQuality(entry: ShareGPTConversation): { overall: number; breakdown: Record<string, number> } {
  const scores: Record<string, number> = {};

  // Turn count score (8-15 is ideal)
  const turns = entry.metadata.turn_count;
  scores.turns = turns >= 8 && turns <= 15 ? 1.0 : turns >= 6 ? 0.7 : 0.4;

  // Tool diversity (more tools = higher score)
  scores.toolDiversity = Math.min(entry.metadata.tools_used.length / 5, 1.0);

  // Has thinking blocks (preferred)
  scores.thinking = entry.metadata.has_thinking ? 1.0 : 0.5;

  // Message length variance (check that responses aren't all the same length)
  const gptMsgs = entry.conversations.filter(m => m.from === "gpt");
  const lengths = gptMsgs.map(m => m.value.length);
  const avgLen = lengths.reduce((a, b) => a + b, 0) / lengths.length;
  const variance = lengths.reduce((a, b) => a + Math.pow(b - avgLen, 2), 0) / lengths.length;
  scores.responseVariety = Math.min(Math.sqrt(variance) / avgLen, 1.0);

  // Has tool calls (not just text)
  scores.toolCalls = gptMsgs.some(m => m.tool_calls && m.tool_calls.length > 0) ? 1.0 : 0.3;

  // Has report section
  scores.hasReport = gptMsgs.some(m => m.value.includes("Severity") || m.value.includes("CVSS") || m.value.includes("Remediation")) ? 1.0 : 0.5;

  // Overall weighted score
  const weights = { turns: 0.15, toolDiversity: 0.2, thinking: 0.15, responseVariety: 0.15, toolCalls: 0.2, hasReport: 0.15 };
  const overall = Object.entries(weights).reduce((sum, [key, weight]) => sum + (scores[key] || 0) * weight, 0);

  return { overall, breakdown: scores };
}

export function calculateDiversityScore(
  categories: Record<string, number>,
  difficulties: Record<string, number>,
  tools: Record<string, number>
): number {
  // Shannon entropy-based diversity score
  const entropy = (counts: Record<string, number>) => {
    const total = Object.values(counts).reduce((a, b) => a + b, 0);
    if (total === 0) return 0;
    return -Object.values(counts).reduce((sum, count) => {
      const p = count / total;
      return p > 0 ? sum + p * Math.log2(p) : sum;
    }, 0);
  };

  const maxCatEntropy = Math.log2(Math.max(Object.keys(categories).length, 1));
  const maxDiffEntropy = Math.log2(Math.max(Object.keys(difficulties).length, 1));
  const maxToolEntropy = Math.log2(Math.max(Object.keys(tools).length, 1));

  const catScore = maxCatEntropy > 0 ? entropy(categories) / maxCatEntropy : 0;
  const diffScore = maxDiffEntropy > 0 ? entropy(difficulties) / maxDiffEntropy : 0;
  const toolScore = maxToolEntropy > 0 ? entropy(tools) / maxToolEntropy : 0;

  return Math.round(((catScore + diffScore + toolScore) / 3) * 100) / 100;
}
