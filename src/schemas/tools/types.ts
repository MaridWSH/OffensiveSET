// Tool definition type interfaces

export interface ToolDefinition {
  name: string;
  description: string;
  category: "recon" | "enumeration" | "scanning" | "exploitation" | "post_exploitation" | "reporting" | "utility";
  parameters: Record<string, ToolParam>;
  example_commands: string[];
  typical_output: string;
}

export interface ToolParam {
  type: "string" | "number" | "boolean" | "array";
  description: string;
  required: boolean;
  default?: string | number | boolean;
  examples?: (string | number)[];
}
