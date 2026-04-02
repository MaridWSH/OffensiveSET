// MCP Tool Handlers: Dataset Analysis (stats, validate, quality)

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import * as fsp from "fs/promises";

export function registerAnalysisTools(server: McpServer) {
  server.tool(
    "get_dataset_stats",
    "Get statistics about a previously generated dataset file.",
    {
      file_path: z.string().describe("Path to the JSONL dataset file"),
    },
    async (args) => {
      try {
        const content = await fsp.readFile(args.file_path, "utf-8");
        const lines = content.trim().split("\n");

        const stats = {
          total_entries: lines.length,
          with_thinking: 0,
          without_thinking: 0,
          categories: {} as Record<string, number>,
          difficulties: {} as Record<string, number>,
          avg_turns: 0,
          tools_used: {} as Record<string, number>,
          tags: {} as Record<string, number>,
        };

        let totalTurns = 0;
        for (const line of lines) {
          try {
            const entry = JSON.parse(line);
            const meta = entry.metadata;
            if (meta.has_thinking) stats.with_thinking++;
            else stats.without_thinking++;
            stats.categories[meta.category] = (stats.categories[meta.category] || 0) + 1;
            stats.difficulties[meta.difficulty] = (stats.difficulties[meta.difficulty] || 0) + 1;
            totalTurns += meta.turn_count;
            for (const tool of meta.tools_used) stats.tools_used[tool] = (stats.tools_used[tool] || 0) + 1;
            for (const tag of meta.tags) stats.tags[tag] = (stats.tags[tag] || 0) + 1;
          } catch { /* skip malformed */ }
        }
        stats.avg_turns = Math.round(totalTurns / lines.length);

        return {
          content: [{
            type: "text",
            text: `Dataset Statistics: ${args.file_path}\n\nTotal entries: ${stats.total_entries}\nWith thinking blocks: ${stats.with_thinking} (${Math.round(stats.with_thinking / stats.total_entries * 100)}%)\nWithout thinking: ${stats.without_thinking} (${Math.round(stats.without_thinking / stats.total_entries * 100)}%)\nAverage turns per conversation: ${stats.avg_turns}\n\nCategory Distribution:\n${Object.entries(stats.categories).sort(([, a], [, b]) => b - a).map(([k, v]) => `  ${k}: ${v} (${Math.round(v / stats.total_entries * 100)}%)`).join("\n")}\n\nDifficulty Distribution:\n${Object.entries(stats.difficulties).sort(([, a], [, b]) => b - a).map(([k, v]) => `  ${k}: ${v}`).join("\n")}\n\nTop Tools Used:\n${Object.entries(stats.tools_used).sort(([, a], [, b]) => b - a).slice(0, 15).map(([k, v]) => `  ${k}: ${v}`).join("\n")}\n\nTop Tags:\n${Object.entries(stats.tags).sort(([, a], [, b]) => b - a).slice(0, 20).map(([k, v]) => `  ${k}: ${v}`).join("\n")}`,
          }],
        };
      } catch (error) {
        return { content: [{ type: "text", text: `Error reading dataset: ${error}` }], isError: true };
      }
    }
  );

  server.tool(
    "validate_dataset",
    "Validate a PentesterFlow dataset for schema compliance, data quality, and training readiness.",
    {
      file_path: z.string().describe("Path to the JSONL dataset file"),
      strict: z.boolean().default(false).describe("Enable strict mode (fail on warnings)"),
    },
    async (args) => {
      try {
        const content = await fsp.readFile(args.file_path, "utf-8");
        const lines = content.trim().split("\n");
        const issues: string[] = [];
        const warnings: string[] = [];
        let valid = 0, invalid = 0;
        const seenIds = new Set<string>();

        for (let lineNum = 0; lineNum < lines.length; lineNum++) {
          try {
            const entry = JSON.parse(lines[lineNum]);
            if (!entry.id) issues.push(`Line ${lineNum + 1}: Missing 'id' field`);
            if (!entry.conversations || !Array.isArray(entry.conversations)) { issues.push(`Line ${lineNum + 1}: Missing or invalid 'conversations' array`); invalid++; continue; }
            if (!entry.metadata) issues.push(`Line ${lineNum + 1}: Missing 'metadata' field`);
            if (seenIds.has(entry.id)) warnings.push(`Line ${lineNum + 1}: Duplicate ID '${entry.id}'`);
            seenIds.add(entry.id);

            const msgs = entry.conversations;
            if (msgs.length < 3) warnings.push(`Line ${lineNum + 1}: Very short conversation (${msgs.length} messages)`);
            if (msgs[0]?.from !== "system") warnings.push(`Line ${lineNum + 1}: First message is not 'system' role`);

            let hasHuman = false, hasGpt = false;
            for (const msg of msgs) {
              if (!["system", "human", "gpt", "tool", "observation"].includes(msg.from)) issues.push(`Line ${lineNum + 1}: Invalid role '${msg.from}'`);
              if (!msg.value || typeof msg.value !== "string") issues.push(`Line ${lineNum + 1}: Empty or invalid message value`);
              if (msg.from === "human") hasHuman = true;
              if (msg.from === "gpt") hasGpt = true;
            }
            if (!hasHuman) issues.push(`Line ${lineNum + 1}: No human messages`);
            if (!hasGpt) issues.push(`Line ${lineNum + 1}: No assistant messages`);

            const fullText = JSON.stringify(entry);
            if (fullText.includes("target.com")) warnings.push(`Line ${lineNum + 1}: Contains unreplaced 'target.com'`);
            if (fullText.includes("{domain}")) issues.push(`Line ${lineNum + 1}: Contains unreplaced '{domain}'`);
            if (fullText.includes("{param}")) issues.push(`Line ${lineNum + 1}: Contains unreplaced '{param}'`);

            valid++;
          } catch (parseErr) { issues.push(`Line ${lineNum + 1}: Invalid JSON — ${parseErr}`); invalid++; }
        }

        const passed = issues.length === 0 && (!args.strict || warnings.length === 0);
        return {
          content: [{
            type: "text",
            text: `Dataset Validation Report\n═══════════════════════\n\nFile: ${args.file_path}\nMode: ${args.strict ? "STRICT" : "STANDARD"}\nResult: ${passed ? "PASSED" : "FAILED"}\n\nSummary:\n  Total: ${lines.length} | Valid: ${valid} | Invalid: ${invalid}\n  Errors: ${issues.length} | Warnings: ${warnings.length}\n\n${issues.length > 0 ? `Errors:\n${issues.slice(0, 20).map(i => `  ${i}`).join("\n")}${issues.length > 20 ? `\n  ... and ${issues.length - 20} more` : ""}` : "No errors."}\n\n${warnings.length > 0 ? `Warnings:\n${warnings.slice(0, 20).map(w => `  ${w}`).join("\n")}${warnings.length > 20 ? `\n  ... and ${warnings.length - 20} more` : ""}` : "No warnings."}\n\n${passed ? "Dataset is ready for training." : "Dataset needs fixes."}`,
          }],
        };
      } catch (error) {
        return { content: [{ type: "text", text: `Error validating dataset: ${error}` }], isError: true };
      }
    }
  );

  server.tool(
    "quality_score",
    "Deep quality analysis of a dataset. Scores entries on diversity, realism, complexity, and training readiness.",
    {
      file_path: z.string().describe("Path to the JSONL dataset file"),
      sample_size: z.number().default(500).describe("Number of entries to sample (0 = all)"),
    },
    async (args) => {
      try {
        const content = await fsp.readFile(args.file_path, "utf-8");
        const lines = content.trim().split("\n");
        const sampleSize = args.sample_size === 0 ? lines.length : Math.min(args.sample_size, lines.length);
        const indices = Array.from({ length: lines.length }, (_, i) => i).sort(() => Math.random() - 0.5).slice(0, sampleSize);

        let totalTokenEstimate = 0, totalTurns = 0, withThinking = 0, withToolCalls = 0, withFailures = 0, withCode = 0, withReport = 0;
        const responseLengths: number[] = [], thinkingLengths: number[] = [];
        const uniqueDomains = new Set<string>(), uniqueTools = new Set<string>(), promptDiversity = new Set<string>();
        let unreplacedPlaceholders = 0, shortConversations = 0;

        for (const idx of indices) {
          try {
            const entry = JSON.parse(lines[idx]);
            const msgs = entry.conversations || [];
            totalTurns += msgs.length;
            const fullText = JSON.stringify(entry);
            totalTokenEstimate += Math.ceil(fullText.length / 4);
            if (fullText.includes("target.com") || fullText.includes("{domain}")) unreplacedPlaceholders++;
            if (msgs.length < 6) shortConversations++;

            for (const msg of msgs) {
              if (msg.from === "gpt") {
                responseLengths.push(msg.value?.length || 0);
                if (msg.thinking) { withThinking++; thinkingLengths.push(msg.thinking.length); }
                if (msg.tool_calls?.length > 0) withToolCalls++;
                if (msg.value?.includes("```")) withCode++;
                if (msg.value?.includes("CVSS") || msg.value?.includes("Remediation")) withReport++;
              }
              if (msg.from === "human") promptDiversity.add(msg.value?.slice(0, 50) || "");
            }
            if (entry.metadata?.has_failures) withFailures++;
            if (entry.metadata?.tools_used) for (const t of entry.metadata.tools_used) uniqueTools.add(t);
            const domainMatch = fullText.match(/https?:\/\/([\w.-]+)/);
            if (domainMatch) uniqueDomains.add(domainMatch[1]);
          } catch { /* skip */ }
        }

        const avgResponseLen = responseLengths.reduce((a, b) => a + b, 0) / responseLengths.length;
        const avgThinkingLen = thinkingLengths.length > 0 ? thinkingLengths.reduce((a, b) => a + b, 0) / thinkingLengths.length : 0;
        const metrics = {
          turnDepth: Math.min(totalTurns / (sampleSize * 10), 1.0),
          thinkingRatio: withThinking / (sampleSize * 3),
          toolCallRatio: withToolCalls / sampleSize,
          codeRatio: withCode / sampleSize,
          reportRatio: withReport / sampleSize,
          domainDiversity: Math.min(uniqueDomains.size / 20, 1.0),
          toolDiversity: Math.min(uniqueTools.size / 30, 1.0),
          promptDiversity: Math.min(promptDiversity.size / (sampleSize * 0.5), 1.0),
          noPlaceholders: 1.0 - (unreplacedPlaceholders / sampleSize),
          noShortConvos: 1.0 - (shortConversations / sampleSize),
        };
        const overallScore = Object.values(metrics).reduce((a, b) => a + b, 0) / Object.keys(metrics).length;
        const grade = overallScore >= 0.85 ? "A" : overallScore >= 0.7 ? "B" : overallScore >= 0.55 ? "C" : overallScore >= 0.4 ? "D" : "F";

        return {
          content: [{
            type: "text",
            text: `Dataset Quality Analysis\n════════════════════════\n\nFile: ${args.file_path}\nSampled: ${sampleSize} of ${lines.length}\nGrade: ${grade} (${(overallScore * 100).toFixed(1)}%)\n\nTokens: ~${totalTokenEstimate.toLocaleString()} total, ~${Math.round(totalTokenEstimate / sampleSize).toLocaleString()}/entry\nAvg response: ${Math.round(avgResponseLen).toLocaleString()} chars | Avg thinking: ${Math.round(avgThinkingLen).toLocaleString()} chars\nAvg turns: ${(totalTurns / sampleSize).toFixed(1)}\n\nContent: thinking=${((withThinking / (sampleSize * 3)) * 100).toFixed(1)}% | tools=${((withToolCalls / sampleSize) * 100).toFixed(1)}% | code=${((withCode / sampleSize) * 100).toFixed(1)}% | reports=${((withReport / sampleSize) * 100).toFixed(1)}%\n\nDiversity: ${uniqueDomains.size} domains, ${uniqueTools.size} tools, ${promptDiversity.size} unique prompts\n\nMetrics:\n${Object.entries(metrics).map(([k, v]) => `  ${k.padEnd(20)} ${(v * 100).toFixed(0).padStart(3)}%${"█".repeat(Math.round(v * 20))}${"░".repeat(20 - Math.round(v * 20))}`).join("\n")}\n\n${overallScore >= 0.7 ? "Training-ready." : "Consider regenerating low-quality entries."}`,
          }],
        };
      } catch (error) {
        return { content: [{ type: "text", text: `Error analyzing dataset: ${error}` }], isError: true };
      }
    }
  );
}
