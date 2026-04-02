// Qwen compatibility post-processing for Dataset Generator V2

import { ShareGPTMessage, GenerationConfig } from "./types.js";

export function postProcessForQwen(messages: ShareGPTMessage[], config: GenerationConfig): ShareGPTMessage[] {
  let processed = messages.map(msg => {
    // FIX 1: Inline thinking — merge thinking into value with <think> tags
    // This is Qwen3.5's native format for reasoning
    if (config.thinkingStyle === "inline" && msg.thinking && msg.from === "gpt") {
      return {
        ...msg,
        value: `<think>\n${msg.thinking}\n</think>\n\n${msg.value}`,
        thinking: undefined,  // clear separate field — it's now inline
      };
    }
    return { ...msg };
  });

  // FIX 2: Map 'tool' role to Qwen-compatible format
  // Qwen uses 'observation' role for tool outputs in its ChatML template:
  //   <|im_start|>assistant ... tool_call ... <|im_end|>
  //   <|im_start|>observation ... tool_output ... <|im_end|>
  // In ShareGPT format, we map tool → 'observation' as a virtual role
  // and restructure tool_calls into Qwen's function_call format
  processed = processed.map(msg => {
    if (msg.from === "tool") {
      return {
        ...msg,
        from: "observation" as any,  // Qwen's tool output role
      };
    }

    // For gpt messages with tool_calls, format as Qwen function_call
    if (msg.from === "gpt" && msg.tool_calls && msg.tool_calls.length > 0) {
      const functionCallBlock = msg.tool_calls.map(tc =>
        `<tool_call>\n{"name": "${tc.name}", "arguments": ${JSON.stringify(tc.arguments)}}\n</tool_call>`
      ).join("\n");

      return {
        ...msg,
        value: `${msg.value}\n\n${functionCallBlock}`,
        // Keep tool_calls in metadata for non-Qwen consumers
      };
    }

    return msg;
  });

  // FIX 3: Token length control — truncate conversations that exceed max
  if (config.maxTokensPerEntry && config.maxTokensPerEntry > 0) {
    const maxTokens = config.maxTokensPerEntry;
    let totalTokens = 0;
    const truncated: ShareGPTMessage[] = [];

    // Always keep system messages
    for (const msg of processed) {
      if (msg.from === "system") {
        truncated.push(msg);
        totalTokens += estimateMessageTokens(msg);
        continue;
      }

      const msgTokens = estimateMessageTokens(msg);
      if (totalTokens + msgTokens > maxTokens) {
        // If we're over limit and this is a gpt message, try truncating its value
        if (msg.from === "gpt" && msgTokens > 500) {
          const remainingTokens = maxTokens - totalTokens;
          if (remainingTokens > 200) {
            const truncatedValue = msg.value.slice(0, remainingTokens * 4); // ~4 chars/token
            truncated.push({ ...msg, value: truncatedValue + "\n\n[Response truncated for context length]" });
          }
        }
        break; // stop adding messages
      }

      truncated.push(msg);
      totalTokens += msgTokens;
    }

    // Ensure we have at least one human + gpt turn
    const hasHuman = truncated.some(m => m.from === "human");
    const hasGpt = truncated.some(m => m.from === "gpt");
    if (hasHuman && hasGpt) {
      processed = truncated;
    }
    // else: don't truncate if it would remove all content
  }

  return processed;
}

export function estimateMessageTokens(msg: ShareGPTMessage): number {
  let text = msg.value || "";
  if (msg.thinking) text += msg.thinking;
  if (msg.tool_calls) text += JSON.stringify(msg.tool_calls);
  if (msg.tool_results) text += JSON.stringify(msg.tool_results);
  return Math.ceil(text.length / 3.5); // ~3.5 chars per token for mixed code/text
}

export function estimateTokens(messages: ShareGPTMessage[]): number {
  return messages.reduce((sum, msg) => sum + estimateMessageTokens(msg), 0);
}
