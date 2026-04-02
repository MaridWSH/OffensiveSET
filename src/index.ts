#!/usr/bin/env node

// OffensiveSET — Offensive Security Dataset Generator
// MCP server for generating high-quality pentesting datasets for LLM fine-tuning

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

import { registerGenerateTools } from "./server/generate-tools.js";
import { registerBrowseTools } from "./server/browse-tools.js";
import { registerAnalysisTools } from "./server/analysis-tools.js";
import { registerExportTools } from "./server/export-tools.js";
import { registerResources } from "./server/resources.js";

const server = new McpServer({
  name: "offensiveset",
  version: "2.0.0",
});

// Register all tool handlers
registerGenerateTools(server);
registerBrowseTools(server);
registerAnalysisTools(server);
registerExportTools(server);
registerResources(server);

// Start server
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("OffensiveSET v2.0.0 — Offensive Security Dataset Generator running on stdio");
}

main().catch(console.error);
