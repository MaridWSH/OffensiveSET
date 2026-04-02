// MCP Resources: Scenario library and tool arsenal

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { listAvailableScenarios } from "../generators/v1-generator.js";
import { PENTESTING_TOOLS } from "../schemas/tools/index.js";

export function registerResources(server: McpServer) {
  server.resource(
    "scenario-library",
    "pentesterflow://scenarios",
    async (uri) => {
      const info = listAvailableScenarios();
      return {
        contents: [{
          uri: uri.href,
          mimeType: "application/json",
          text: JSON.stringify(info, null, 2),
        }],
      };
    }
  );

  server.resource(
    "tool-arsenal",
    "pentesterflow://tools",
    async (uri) => {
      return {
        contents: [{
          uri: uri.href,
          mimeType: "application/json",
          text: JSON.stringify(PENTESTING_TOOLS.map(t => ({
            name: t.name,
            category: t.category,
            description: t.description,
            parameters: Object.keys(t.parameters),
            example: t.example_commands[0],
          })), null, 2),
        }],
      };
    }
  );
}
