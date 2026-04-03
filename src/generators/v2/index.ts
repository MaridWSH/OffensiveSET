// Dataset Generator V2 — Main entry point

import { ALL_SCENARIOS, ScenarioTemplate } from "../../templates/scenarios/index.js";
import { SeededRNG, ContractProfile, SmartContractOutputEngine } from "../outputs/index.js";

import { GenerationConfig, DatasetQualityReport, DEFAULT_CONFIG } from "./types.js";
import { buildConversationV2 } from "./conversation.js";
import { scoreEntryQuality, calculateDiversityScore } from "./quality.js";

import * as fs from "fs";
import * as fsp from "fs/promises";
import * as path from "path";

export type { ShareGPTConversation, ShareGPTMessage, ToolCall, ToolResult, ConversationMetadata, GenerationConfig, DatasetQualityReport } from "./types.js";

export async function generateDatasetV2(config: Partial<GenerationConfig> = {}): Promise<{
  outputPath: string;
  count: number;
  stats: Record<string, number>;
  qualityReport: DatasetQualityReport;
}> {
  const finalConfig = { ...DEFAULT_CONFIG, ...config };
  const rng = new SeededRNG(finalConfig.seed || Date.now());

  // Filter scenarios
  let scenarios = [...ALL_SCENARIOS];
  if (finalConfig.categories?.length) {
    scenarios = scenarios.filter(s =>
      finalConfig.categories!.some(c => s.category.includes(c) || s.subcategory.includes(c))
    );
  }
  if (finalConfig.difficulties?.length) {
    scenarios = scenarios.filter(s => finalConfig.difficulties!.includes(s.difficulty));
  }
  if (finalConfig.tags?.length) {
    scenarios = scenarios.filter(s => s.tags.some(t => finalConfig.tags!.includes(t)));
  }

  if (scenarios.length === 0) throw new Error("No scenarios match the given filters");

  const outputDir = path.resolve(finalConfig.outputDir);
  await fsp.mkdir(outputDir, { recursive: true });

  const timestamp = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
  const outputPath = path.join(outputDir, `pentesterflow_v2_dataset_${timestamp}.jsonl`);
  const metadataPath = path.join(outputDir, `pentesterflow_v2_metadata_${timestamp}.json`);

  const stats: Record<string, number> = {
    total: 0,
    with_thinking: 0,
    without_thinking: 0,
    with_failures: 0,
    without_failures: 0,
  };
  const categoryStats: Record<string, number> = {};
  const difficultyStats: Record<string, number> = {};
  const toolUsageStats: Record<string, number> = {};
  const qualityScores: number[] = [];

  const writeStream = fs.createWriteStream(outputPath);

  // Balanced scenario selection — round-robin with shuffle instead of pure random
  const balancedScenarios: ScenarioTemplate[] = [];
  while (balancedScenarios.length < finalConfig.count) {
    const shuffled = [...scenarios].sort(() => rng.next() - 0.5);
    balancedScenarios.push(...shuffled);
  }

  for (let i = 0; i < finalConfig.count; i++) {
    const scenario = balancedScenarios[i];
    const conversation = buildConversationV2(scenario, rng, finalConfig, i);

    // Quality scoring per entry
    const quality = scoreEntryQuality(conversation);
    qualityScores.push(quality.overall);

    // Track tool usage
    for (const tool of conversation.metadata.tools_used) {
      toolUsageStats[tool] = (toolUsageStats[tool] || 0) + 1;
    }

    const canContinue = writeStream.write(JSON.stringify(conversation) + "\n");
    if (!canContinue) {
      await new Promise<void>(resolve => writeStream.once("drain", resolve));
    }

    stats.total++;
    if (conversation.metadata.has_thinking) stats.with_thinking++;
    else stats.without_thinking++;
    if (conversation.metadata.has_failures) stats.with_failures++;
    else stats.without_failures++;
    categoryStats[scenario.category] = (categoryStats[scenario.category] || 0) + 1;
    difficultyStats[scenario.difficulty] = (difficultyStats[scenario.difficulty] || 0) + 1;
  }

  await new Promise<void>((resolve, reject) => {
    writeStream.end(() => resolve());
    writeStream.on("error", reject);
  });

  // Quality report
  const avgQuality = qualityScores.reduce((a, b) => a + b, 0) / qualityScores.length;
  const qualityReport: DatasetQualityReport = {
    averageScore: Math.round(avgQuality * 100) / 100,
    highQuality: qualityScores.filter(q => q >= 0.8).length,
    mediumQuality: qualityScores.filter(q => q >= 0.5 && q < 0.8).length,
    lowQuality: qualityScores.filter(q => q < 0.5).length,
    toolCoverage: Object.keys(toolUsageStats).length,
    scenarioCoverage: Object.keys(categoryStats).length,
    diversityScore: calculateDiversityScore(categoryStats, difficultyStats, toolUsageStats),
  };

  const metadata = {
    dataset_name: "PentesterFlow V2 Epic Offensive Security Dataset",
    version: "2.0.0",
    format: "ShareGPT/ChatML (JSONL)",
    target_model: "Qwen3.5",
    generated_at: new Date().toISOString(),
    improvements: [
      "Dynamic unique outputs per entry (no two entries share tool outputs)",
      "Failure cases and negative examples with realistic evasion techniques",
      "Deep thinking blocks (500-2000 words with hypothesis/elimination/pivoting)",
      "100+ unique user prompt templates across 6 categories",
      "Varied system prompts per entry with expertise rotation",
      "Balanced tool usage across 55+ tool arsenal",
      "Unique target profiles (IP, tech stack, databases) per entry",
      "Contextual remediation with secure code examples",
      "Multiple report styles (executive, technical, bug bounty)",
      "45+ attack scenarios covering OWASP, API, Cloud, CI/CD, AD, Mobile",
      "Advanced failure patterns: WAF bypass, honeypot, IDS evasion, rate limiting",
      "Per-entry quality scoring and dataset quality report",
      "Async streaming I/O with backpressure handling",
    ],
    config: finalConfig,
    statistics: {
      ...stats,
      categories: categoryStats,
      difficulties: difficultyStats,
      tool_usage: toolUsageStats,
      scenario_count: scenarios.length,
    },
    quality: qualityReport,
  };

  await fsp.writeFile(metadataPath, JSON.stringify(metadata, null, 2));

  return { outputPath, count: stats.total, stats: { ...stats, ...categoryStats, ...difficultyStats }, qualityReport };
}

// Re-export original for comparison
export { generateDataset, listAvailableScenarios } from "../v1-generator.js";
