// MCP Tool Handlers: Dataset Generation (V1 + V2)

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { generateDataset } from "../generators/v1-generator.js";
import { generateDatasetV2 } from "../generators/v2/index.js";

export function registerGenerateTools(server: McpServer) {
  server.tool(
    "generate_dataset",
    "Generate an offensive security dataset for fine-tuning PentesterFlow model. Produces JSONL in ShareGPT/ChatML format with multi-turn pentesting conversations including tool calls, reasoning, and thinking blocks.",
    {
      count: z.number().min(1).max(50000).default(2000).describe("Number of dataset entries to generate (1-50000)"),
      output_dir: z.string().default("./datasets").describe("Output directory for generated files"),
      thinking_ratio: z.number().min(0).max(1).default(0.6).describe("Ratio of entries with thinking/reasoning blocks (0.0-1.0)"),
      min_turns: z.number().min(4).max(30).default(8).describe("Minimum conversation turns per entry"),
      max_turns: z.number().min(4).max(30).default(15).describe("Maximum conversation turns per entry"),
      categories: z.array(z.string()).optional().describe("Filter by vulnerability categories (e.g., ['OWASP Top 10', 'API Security'])"),
      difficulties: z.array(z.string()).optional().describe("Filter by difficulty levels (beginner, intermediate, advanced, expert)"),
      tags: z.array(z.string()).optional().describe("Filter by specific tags (e.g., ['sqli', 'xss', 'ssrf'])"),
      seed: z.number().optional().describe("Random seed for reproducibility"),
    },
    async (args) => {
      try {
        const result = await generateDataset({
          count: args.count,
          outputDir: args.output_dir,
          thinkingRatio: args.thinking_ratio,
          minTurns: args.min_turns,
          maxTurns: args.max_turns,
          categories: args.categories,
          difficulties: args.difficulties,
          tags: args.tags,
          seed: args.seed,
        });

        return {
          content: [{
            type: "text",
            text: `Dataset generated successfully!\n\nOutput: ${result.outputPath}\nTotal entries: ${result.count}\n\nStatistics:\n${Object.entries(result.stats).map(([k, v]) => `  ${k}: ${v}`).join("\n")}\n\nThe dataset is in ShareGPT/ChatML JSONL format, ready for Qwen3.5 fine-tuning.`,
          }],
        };
      } catch (error) {
        return { content: [{ type: "text", text: `Error generating dataset: ${error}` }], isError: true };
      }
    }
  );

  server.tool(
    "generate_dataset_v2",
    "Generate an improved V2 offensive security dataset with unique outputs per entry, failure cases, deep thinking, and massive prompt diversity. Recommended over V1.",
    {
      count: z.number().min(1).max(50000).default(2000).describe("Number of dataset entries to generate (1-50000)"),
      output_dir: z.string().default("./datasets").describe("Output directory for generated files"),
      thinking_ratio: z.number().min(0).max(1).default(0.6).describe("Ratio of entries with thinking/reasoning blocks (0.0-1.0)"),
      failure_ratio: z.number().min(0).max(1).default(0.35).describe("Ratio of entries containing failure/dead-end scenarios (0.0-1.0)"),
      min_turns: z.number().min(4).max(30).default(8).describe("Minimum conversation turns per entry"),
      max_turns: z.number().min(4).max(30).default(15).describe("Maximum conversation turns per entry"),
      categories: z.array(z.string()).optional().describe("Filter by vulnerability categories"),
      difficulties: z.array(z.string()).optional().describe("Filter by difficulty levels"),
      tags: z.array(z.string()).optional().describe("Filter by specific tags"),
      seed: z.number().optional().describe("Random seed for reproducibility"),
      max_tokens_per_entry: z.number().min(0).default(0).describe("Max estimated tokens per entry (0 = no limit). Recommended: 8192 for 8K context, 16384 for 16K."),
      thinking_style: z.enum(["inline", "field"]).default("inline").describe("'inline' = Qwen-native <think> tags in message value (recommended). 'field' = separate thinking field."),
    },
    async (args) => {
      try {
        const result = await generateDatasetV2({
          count: args.count,
          outputDir: args.output_dir,
          thinkingRatio: args.thinking_ratio,
          failureRatio: args.failure_ratio,
          minTurns: args.min_turns,
          maxTurns: args.max_turns,
          maxTokensPerEntry: args.max_tokens_per_entry,
          thinkingStyle: args.thinking_style,
          categories: args.categories,
          difficulties: args.difficulties,
          tags: args.tags,
          seed: args.seed,
        });

        return {
          content: [{
            type: "text",
            text: `V2 Dataset generated successfully!\n\nOutput: ${result.outputPath}\nTotal entries: ${result.count}\n\nStatistics:\n${Object.entries(result.stats).map(([k, v]) => `  ${k}: ${v}`).join("\n")}\n\nQuality Report:\n- Average quality score: ${result.qualityReport.averageScore}/1.0\n- High quality entries: ${result.qualityReport.highQuality}\n- Tool coverage: ${result.qualityReport.toolCoverage} unique tools\n- Diversity score: ${result.qualityReport.diversityScore}/1.0`,
          }],
        };
      } catch (error) {
        return { content: [{ type: "text", text: `Error generating V2 dataset: ${error}` }], isError: true };
      }
    }
  );
}
