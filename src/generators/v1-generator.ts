// Core dataset generation engine
// Hybrid: templates for structure + variation logic for diversity
// Outputs ShareGPT/ChatML format in JSONL

import { ScenarioTemplate, AttackPhase, ALL_SCENARIOS } from "../templates/scenarios/index.js";
import { PENTESTING_TOOLS, ToolDefinition } from "../schemas/tools/index.js";
import * as fs from "fs";
import * as fsp from "fs/promises";
import * as path from "path";

// ============================================================
// ShareGPT Format Types
// ============================================================

export interface ShareGPTConversation {
  id: string;
  conversations: ShareGPTMessage[];
  metadata: ConversationMetadata;
}

export interface ShareGPTMessage {
  from: "system" | "human" | "gpt" | "tool";
  value: string;
  thinking?: string;  // Chain-of-thought reasoning block
  tool_calls?: ToolCall[];
  tool_results?: ToolResult[];
}

export interface ToolCall {
  id: string;
  name: string;
  arguments: Record<string, string>;
}

export interface ToolResult {
  tool_call_id: string;
  name: string;
  output: string;
}

export interface ConversationMetadata {
  scenario_id: string;
  category: string;
  subcategory: string;
  difficulty: string;
  tags: string[];
  tools_used: string[];
  has_thinking: boolean;
  turn_count: number;
  cve_references: string[];
  generated_at: string;
}

// ============================================================
// Generation Configuration
// ============================================================

export interface GenerationConfig {
  count: number;
  outputDir: string;
  thinkingRatio: number;     // 0.0 - 1.0, percentage with thinking blocks
  minTurns: number;
  maxTurns: number;
  categories?: string[];     // filter by categories
  difficulties?: string[];   // filter by difficulty
  tags?: string[];            // filter by tags
  seed?: number;              // for reproducibility
}

const DEFAULT_CONFIG: GenerationConfig = {
  count: 2000,
  outputDir: "./datasets",
  thinkingRatio: 0.6,        // 60% with thinking, 40% without
  minTurns: 8,
  maxTurns: 15,
  categories: undefined,
  difficulties: undefined,
  tags: undefined,
};

// ============================================================
// Variation Engine - makes each entry unique
// ============================================================

const TARGET_DOMAINS = [
  "acme-corp.com", "globex.io", "initech.net", "umbrella-corp.com", "wayne-ent.com",
  "stark-ind.com", "oscorp.io", "lexcorp.net", "cyberdyne.com", "massive-dynamic.io",
  "pied-piper.com", "hooli.net", "soylent.io", "aperture.com", "blackmesa.net",
  "weyland-yutani.com", "tyrell-corp.io", "omni-consumer.com", "veridian.net", "dunder-mifflin.io",
  "target-app.com", "secure-bank.io", "health-portal.net", "gov-services.com", "edu-platform.io",
  "fintech-pay.com", "cloud-saas.io", "retail-hub.net", "media-stream.com", "iot-manage.io",
];

const INTERNAL_IPS = [
  "10.0.1.50", "10.0.2.100", "172.16.0.25", "172.16.1.100", "192.168.1.50",
  "192.168.10.100", "10.10.10.1", "10.10.14.2", "172.20.0.5", "192.168.100.10",
];

const USERNAMES = [
  "john.doe", "jane.smith", "admin", "sysadmin", "devops", "testuser",
  "m.johnson", "s.williams", "k.brown", "a.garcia", "r.martinez", "l.wilson",
  "d.anderson", "c.taylor", "b.thomas", "n.jackson", "e.white", "p.harris",
];

const WEB_TECHNOLOGIES = [
  { backend: "Node.js/Express", db: "MongoDB", frontend: "React" },
  { backend: "Python/Django", db: "PostgreSQL", frontend: "Vue.js" },
  { backend: "Python/Flask", db: "MySQL", frontend: "Angular" },
  { backend: "Java/Spring Boot", db: "PostgreSQL", frontend: "React" },
  { backend: "PHP/Laravel", db: "MySQL", frontend: "Blade/Alpine.js" },
  { backend: "Ruby/Rails", db: "PostgreSQL", frontend: "Hotwire" },
  { backend: "Go/Gin", db: "PostgreSQL", frontend: "HTMX" },
  { backend: "ASP.NET Core", db: "SQL Server", frontend: "Blazor" },
  { backend: "Node.js/Fastify", db: "Redis + PostgreSQL", frontend: "Svelte" },
  { backend: "Python/FastAPI", db: "PostgreSQL", frontend: "Next.js" },
];

const USER_PROMPTS_RECON = [
  "I need you to perform a full reconnaissance on {domain}. Start with subdomain enumeration and identify the tech stack.",
  "Begin an external assessment of {domain}. Map the attack surface — subdomains, open ports, exposed services.",
  "Run passive recon on {domain} and identify all subdomains, then probe which ones are alive and what they're running.",
  "I want you to enumerate {domain}. Find subdomains, check for exposed services, and identify the technology stack.",
  "Start a pentest engagement against {domain}. Phase 1: reconnaissance and attack surface mapping.",
  "Conduct initial recon on {domain}. I need subdomains, live hosts, and technology fingerprinting.",
  "Perform OSINT and passive reconnaissance on {domain}. Then actively probe the attack surface.",
  "Map the external attack surface of {domain}. Find all entry points — subdomains, APIs, exposed panels.",
];

const USER_PROMPTS_VULN = [
  "I found an interesting endpoint at {url}. Test it for common web vulnerabilities.",
  "The {endpoint} endpoint looks suspicious. Fuzz the parameters and check for injection vulnerabilities.",
  "Test {url} for SQL injection, XSS, and SSRF. Use aggressive scanning.",
  "I noticed the {parameter} parameter might be injectable. Investigate and exploit if vulnerable.",
  "Check {url} for authentication and authorization flaws. Try to escalate privileges.",
  "The API at {url} might have IDOR issues. Test all endpoints for broken access control.",
  "Test the GraphQL endpoint at {url} for introspection, injection, and authorization bypass.",
  "Run a comprehensive vulnerability scan against {url}. Focus on OWASP Top 10.",
];

const USER_PROMPTS_EXPLOIT = [
  "I confirmed {vuln_type} at {url}. Exploit it and demonstrate the impact.",
  "The {parameter} parameter is vulnerable to {vuln_type}. Extract all the data you can.",
  "Exploit the {vuln_type} vulnerability and try to escalate to RCE or admin access.",
  "The target is vulnerable. Chain the {vuln_type} with other findings for maximum impact.",
  "Demonstrate full exploitation of {vuln_type}. I need a complete PoC with evidence.",
  "Take the {vuln_type} finding further. What's the worst-case scenario we can demonstrate?",
];

const USER_PROMPTS_REPORT = [
  "Write up the findings as a professional pentest report. Include CVSS scores and remediation.",
  "Generate a detailed finding report for the {vuln_type} vulnerability with evidence and remediation steps.",
  "Create a report for this vulnerability. Include severity, impact, reproduction steps, and fix recommendations.",
  "Document this finding professionally. I need it for the client report.",
];

// System prompt for the pentester model
const SYSTEM_PROMPT = `You are PentesterFlow, an expert offensive security AI assistant specialized in web application penetration testing, API security assessment, and bug bounty hunting. You operate as an enterprise-grade penetration tester with deep knowledge of:

- OWASP Top 10 (2021) and API Security Top 10 (2023)
- Modern web attack techniques (prototype pollution, HTTP smuggling, cache poisoning, GraphQL attacks, WebSocket hijacking, race conditions)
- Cloud security (AWS, GCP, Azure misconfigurations and exploitation)
- CI/CD pipeline security and supply chain attacks
- Container security and escape techniques
- Authentication/authorization bypass (OAuth, JWT, SSO, 2FA)
- Full penetration testing lifecycle from reconnaissance to reporting

You have access to a comprehensive toolkit of security tools and can write custom exploits in Python and Bash when existing tools are insufficient. You think methodically, chain vulnerabilities for maximum impact, and provide professional-grade reporting.

When analyzing targets:
1. Always start with thorough reconnaissance
2. Enumerate the attack surface systematically
3. Test for vulnerabilities methodically
4. Chain findings for maximum demonstrated impact
5. Document everything with evidence
6. Provide actionable remediation guidance

You operate within an authorized penetration testing engagement scope.`;

// ============================================================
// Random Utilities
// ============================================================

class SeededRandom {
  private seed: number;

  constructor(seed: number) {
    this.seed = seed;
  }

  next(): number {
    this.seed = (this.seed * 1664525 + 1013904223) & 0xffffffff;
    return (this.seed >>> 0) / 0xffffffff;
  }

  pick<T>(arr: T[]): T {
    return arr[Math.floor(this.next() * arr.length)];
  }

  pickN<T>(arr: T[], n: number): T[] {
    const shuffled = [...arr].sort(() => this.next() - 0.5);
    return shuffled.slice(0, Math.min(n, arr.length));
  }

  int(min: number, max: number): number {
    return Math.floor(this.next() * (max - min + 1)) + min;
  }

  bool(probability: number = 0.5): boolean {
    return this.next() < probability;
  }
}

// ============================================================
// Variation Functions
// ============================================================

function variateDomain(rng: SeededRandom): string {
  return rng.pick(TARGET_DOMAINS);
}

function variateIP(rng: SeededRandom): string {
  return rng.pick(INTERNAL_IPS);
}

function variateTechStack(rng: SeededRandom) {
  return rng.pick(WEB_TECHNOLOGIES);
}

function variateUsername(rng: SeededRandom): string {
  return rng.pick(USERNAMES);
}

function variatePort(rng: SeededRandom): number {
  const ports = [80, 443, 3000, 3306, 5432, 6379, 8080, 8443, 9200, 27017, 8888, 9090];
  return rng.pick(ports);
}

function variateCommand(cmd: string, domain: string, ip: string, username: string, rng: SeededRandom): string {
  return cmd
    .replace(/target\.com/g, domain)
    .replace(/shop\.target\.com/g, `shop.${domain}`)
    .replace(/api\.target\.com/g, `api.${domain}`)
    .replace(/admin\.target\.com/g, `admin.${domain}`)
    .replace(/corp\.target\.com/g, `corp.${domain}`)
    .replace(/cloud-app\.target\.com/g, `cloud.${domain}`)
    .replace(/webapp\.target\.com/g, `app.${domain}`)
    .replace(/app\.target\.com/g, `app.${domain}`)
    .replace(/forum\.target\.com/g, `forum.${domain}`)
    .replace(/enterprise\.target\.com/g, `enterprise.${domain}`)
    .replace(/bank\.target\.com/g, `bank.${domain}`)
    .replace(/jobs\.target\.com/g, `jobs.${domain}`)
    .replace(/store\.target\.com/g, `store.${domain}`)
    .replace(/trade\.target\.com/g, `trade.${domain}`)
    .replace(/www\.target\.com/g, `www.${domain}`)
    .replace(/ws\.target\.com/g, `ws.${domain}`)
    .replace(/10\.10\.10\.1/g, ip)
    .replace(/10\.0\.1\.50/g, ip)
    .replace(/192\.168\.1\.100/g, ip)
    .replace(/testuser/g, username);
}

function variateOutput(output: string, domain: string, ip: string, username: string): string {
  return output
    .replace(/target\.com/g, domain)
    .replace(/10\.10\.10\.1/g, ip)
    .replace(/10\.0\.1\.50/g, ip)
    .replace(/192\.168\.1\.100/g, ip)
    .replace(/testuser/g, username);
}

function variateThinking(thinking: string, domain: string, rng: SeededRandom): string {
  return thinking.replace(/target\.com/g, domain);
}

// ============================================================
// Conversation Builder
// ============================================================

function buildConversation(
  scenario: ScenarioTemplate,
  rng: SeededRandom,
  config: GenerationConfig
): ShareGPTConversation {
  const domain = variateDomain(rng);
  const ip = variateIP(rng);
  const tech = variateTechStack(rng);
  const username = variateUsername(rng);
  const includeThinking = rng.bool(config.thinkingRatio);

  const messages: ShareGPTMessage[] = [];
  const toolsUsed: string[] = [];

  // 1. System message
  messages.push({
    from: "system",
    value: SYSTEM_PROMPT,
  });

  // 2. Available tools definition
  const scenarioTools = scenario.tools_involved
    .map(name => PENTESTING_TOOLS.find(t => t.name === name))
    .filter((t): t is ToolDefinition => t !== undefined);

  const toolsDescription = scenarioTools
    .map(t => `### ${t.name}\n${t.description}\nParameters: ${Object.entries(t.parameters).map(([k, v]) => `${k} (${v.type}${v.required ? ', required' : ''}): ${v.description}`).join(', ')}`)
    .join('\n\n');

  messages.push({
    from: "system",
    value: `Available tools:\n\n${toolsDescription}\n\nUse these tools to accomplish the penetration testing objectives. You may also write custom Python or Bash scripts when needed.`,
  });

  // 3. Initial user prompt
  const targetDesc = scenario.target_description
    .replace(/target\.com/g, domain)
    .replace(/testuser/g, username);

  const initialPrompt = rng.pick(USER_PROMPTS_RECON)
    .replace("{domain}", domain)
    .replace("{url}", `https://${domain}`)
    + `\n\nTarget context: ${targetDesc}\nTechnology stack: ${tech.backend} with ${tech.db} database and ${tech.frontend} frontend.`;

  messages.push({
    from: "human",
    value: initialPrompt,
  });

  // 4. Generate conversation turns from attack phases
  for (let phaseIdx = 0; phaseIdx < scenario.attack_phases.length; phaseIdx++) {
    const phase = scenario.attack_phases[phaseIdx];

    // Assistant response with analysis and tool calls
    let assistantResponse = `## ${phase.phase}\n\n${phase.description}\n\n`;

    // Add thinking block if enabled
    const thinkingBlock = includeThinking && phase.thinking
      ? variateThinking(phase.thinking, domain, rng)
      : undefined;

    // Build tool calls
    const toolCalls: ToolCall[] = [];
    const toolResults: ToolResult[] = [];

    for (let cmdIdx = 0; cmdIdx < phase.commands.length; cmdIdx++) {
      const cmd = variateCommand(phase.commands[cmdIdx], domain, ip, username, rng);
      if (cmd.startsWith("#") || cmd.trim() === "") continue;

      const toolCallId = `call_${phaseIdx}_${cmdIdx}_${rng.int(1000, 9999)}`;

      // Determine which tool is being used
      const toolName = identifyToolFromCommand(cmd);
      if (toolName) toolsUsed.push(toolName);

      toolCalls.push({
        id: toolCallId,
        name: toolName || "bash",
        arguments: { command: cmd },
      });

      toolResults.push({
        tool_call_id: toolCallId,
        name: toolName || "bash",
        output: variateOutput(phase.expected_output, domain, ip, username),
      });
    }

    // Assistant message with reasoning and tool calls
    assistantResponse += variateOutput(phase.analysis, domain, ip, username);
    assistantResponse += `\n\n**Next step:** ${phase.next_action}`;

    messages.push({
      from: "gpt",
      value: assistantResponse,
      thinking: thinkingBlock,
      tool_calls: toolCalls.length > 0 ? toolCalls : undefined,
    });

    // Tool results message
    if (toolResults.length > 0) {
      messages.push({
        from: "tool",
        value: toolResults.map(r => `[${r.name}] ${r.output}`).join("\n\n---\n\n"),
        tool_results: toolResults,
      });
    }

    // User follow-up between phases (except last)
    if (phaseIdx < scenario.attack_phases.length - 1) {
      const nextPhase = scenario.attack_phases[phaseIdx + 1];
      let followUp: string;

      if (nextPhase.phase.toLowerCase().includes("exploit")) {
        followUp = rng.pick(USER_PROMPTS_EXPLOIT)
          .replace("{url}", `https://${domain}`)
          .replace("{vuln_type}", scenario.subcategory)
          .replace("{parameter}", "the identified parameter")
          .replace("{endpoint}", `/${rng.pick(["api", "search", "admin", "users", "profile"])}`);
      } else if (nextPhase.phase.toLowerCase().includes("report")) {
        followUp = rng.pick(USER_PROMPTS_REPORT)
          .replace("{vuln_type}", scenario.subcategory);
      } else {
        followUp = rng.pick(USER_PROMPTS_VULN)
          .replace("{url}", `https://${domain}`)
          .replace("{endpoint}", `/${rng.pick(["api", "v1", "v2", "admin"])}/${rng.pick(["users", "search", "login", "profile"])}`)
          .replace("{parameter}", rng.pick(["id", "q", "search", "url", "redirect", "file", "sort"]));
      }

      messages.push({
        from: "human",
        value: followUp,
      });
    }
  }

  // 5. Final reporting turn
  if (!messages.some(m => m.value.includes("## Reporting") || m.value.includes("## Finding"))) {
    messages.push({
      from: "human",
      value: rng.pick(USER_PROMPTS_REPORT).replace("{vuln_type}", scenario.title),
    });

    const reportThinking = includeThinking
      ? `I need to compile all findings into a professional penetration test report. The engagement covered ${scenario.attack_phases.length} phases: ${scenario.attack_phases.map(p => p.phase).join(" → ")}. The primary finding is ${scenario.title} with severity based on impact and exploitability. I should include CVSS score, CWE references, detailed reproduction steps, evidence from tool outputs, and actionable remediation recommendations.`
      : undefined;

    messages.push({
      from: "gpt",
      value: generateReport(scenario, domain, tech),
      thinking: reportThinking,
    });
  }

  // Pad to minimum turn count with additional analysis turns
  while (countTurns(messages) < config.minTurns) {
    messages.push({
      from: "human",
      value: rng.pick([
        "Can you also check for any related vulnerabilities in the same area?",
        "What's the overall risk to the organization from this finding?",
        "Are there any other attack paths we should explore from here?",
        "Can you verify the finding one more time with a different technique?",
        "What would the full attack chain look like in a real-world scenario?",
        "How would an attacker maintain persistence after this exploitation?",
        "What compensating controls could mitigate this until a fix is deployed?",
        "Can you test if WAF/IDS would detect this attack pattern?",
      ]),
    });

    const addlThinking = includeThinking
      ? `The user is asking for deeper analysis. Let me think about additional attack vectors and verification approaches related to ${scenario.title}. I should consider chaining this with other common vulnerabilities and assess the broader impact on the application's security posture.`
      : undefined;

    messages.push({
      from: "gpt",
      value: generateAdditionalAnalysis(scenario, domain, tech, rng),
      thinking: addlThinking,
    });
  }

  const uniqueTools = [...new Set(toolsUsed)];

  return {
    id: `pentesterflow-${scenario.id}-${rng.int(100000, 999999)}`,
    conversations: messages,
    metadata: {
      scenario_id: scenario.id,
      category: scenario.category,
      subcategory: scenario.subcategory,
      difficulty: scenario.difficulty,
      tags: scenario.tags,
      tools_used: uniqueTools,
      has_thinking: includeThinking,
      turn_count: countTurns(messages),
      cve_references: scenario.cve_references || [],
      generated_at: new Date().toISOString(),
    },
  };
}

function countTurns(messages: ShareGPTMessage[]): number {
  return messages.filter(m => m.from === "human" || m.from === "gpt").length;
}

function identifyToolFromCommand(cmd: string): string | undefined {
  const toolKeywords: Record<string, string[]> = {
    nmap: ["nmap "],
    sqlmap: ["sqlmap "],
    ffuf: ["ffuf "],
    gobuster: ["gobuster "],
    nuclei: ["nuclei "],
    nikto: ["nikto "],
    wfuzz: ["wfuzz "],
    curl: ["curl "],
    httpx: ["httpx ", "| httpx"],
    subfinder: ["subfinder "],
    amass: ["amass "],
    dirsearch: ["dirsearch "],
    dalfox: ["dalfox "],
    commix: ["commix "],
    ssrfmap: ["ssrfmap "],
    jwt_tool: ["jwt_tool "],
    hydra: ["hydra "],
    metasploit: ["msfconsole", "metasploit"],
    arjun: ["arjun "],
    paramspider: ["paramspider "],
    gau: ["gau "],
    linpeas: ["linpeas"],
    feroxbuster: ["feroxbuster "],
    rustscan: ["rustscan "],
    trufflehog: ["trufflehog "],
    semgrep: ["semgrep "],
    katana: ["katana "],
    puredns: ["puredns "],
    dnsx: ["dnsx "],
    crlfuzz: ["crlfuzz "],
    corsy: ["corsy "],
    kiterunner: ["kr ", "kiterunner "],
    secretfinder: ["secretfinder "],
    linkfinder: ["linkfinder "],
    testssl: ["testssl "],
    nosqlmap: ["nosqlmap "],
  };

  for (const [tool, keywords] of Object.entries(toolKeywords)) {
    if (keywords.some(kw => cmd.includes(kw))) {
      return tool;
    }
  }

  // Custom scripts
  if (cmd.startsWith("python3") || cmd.startsWith("python ")) return "python_script";
  if (cmd.includes("for ") && cmd.includes("do ")) return "bash_script";
  if (cmd.startsWith("export ") || cmd.startsWith("aws ")) return "aws_cli";
  if (cmd.startsWith("kubectl ") || cmd.startsWith("k ")) return "kubectl";
  if (cmd.startsWith("docker ")) return "docker";

  return undefined;
}

function generateReport(scenario: ScenarioTemplate, domain: string, tech: { backend: string; db: string; frontend: string }): string {
  const severityMap: Record<string, string> = {
    beginner: "Medium (5.3)",
    intermediate: "High (7.5)",
    advanced: "Critical (9.1)",
    expert: "Critical (9.8)",
  };

  return `## Penetration Test Finding Report

### ${scenario.title}

**Severity:** ${severityMap[scenario.difficulty]}
**CVSS Vector:** AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L
**CWE:** ${(scenario.cve_references || []).join(", ")}
**Affected Component:** ${domain} (${tech.backend})

---

### Executive Summary

During the authorized penetration test of ${domain}, a ${scenario.subcategory} vulnerability was identified. ${scenario.description}

### Technical Details

**Attack Surface:** ${scenario.target_description.replace(/target\.com/g, domain)}

**Tools Used:** ${scenario.tools_involved.join(", ")}

### Exploitation Steps

${scenario.attack_phases.map((phase, i) => `${i + 1}. **${phase.phase}**: ${phase.description}\n   - Commands: \`${phase.commands[0]?.replace(/target\.com/g, domain) || "N/A"}\`\n   - Result: ${phase.analysis.replace(/target\.com/g, domain)}`).join("\n\n")}

### Impact

This vulnerability allows an attacker to:
- Gain unauthorized access to sensitive data
- Potentially escalate privileges within the application
- Compromise the confidentiality, integrity, and availability of the system
${scenario.tags.includes("rce") ? "- Execute arbitrary commands on the server (Remote Code Execution)" : ""}
${scenario.tags.includes("account-takeover") ? "- Take over any user account including administrators" : ""}
${scenario.tags.includes("data-exfiltration") || scenario.tags.includes("data-leak") ? "- Exfiltrate sensitive user data and PII at scale" : ""}

### Remediation

**Immediate Actions:**
${getRemediationForTags(scenario.tags)}

**Long-term Recommendations:**
- Implement defense-in-depth security architecture
- Regular penetration testing and code review
- Security awareness training for development teams
- Deploy WAF rules as an additional layer of protection
- Implement comprehensive logging and monitoring`;
}

function getRemediationForTags(tags: string[]): string {
  const remediations: string[] = [];

  if (tags.includes("sqli")) remediations.push("- Use parameterized queries / prepared statements for all database interactions\n- Implement input validation and output encoding\n- Apply principle of least privilege to database accounts");
  if (tags.includes("xss")) remediations.push("- Implement Content Security Policy (CSP) headers\n- Use context-aware output encoding\n- Sanitize all user-generated content, especially in markdown rendering");
  if (tags.includes("idor") || tags.includes("bola")) remediations.push("- Implement object-level authorization checks on every API endpoint\n- Use indirect references (UUIDs) instead of sequential IDs\n- Validate that the authenticated user owns the requested resource");
  if (tags.includes("ssrf")) remediations.push("- Implement URL allowlisting for server-side requests\n- Block requests to private IP ranges and metadata endpoints\n- Use a dedicated SSRF-safe HTTP client library");
  if (tags.includes("jwt") || tags.includes("authentication-bypass")) remediations.push("- Explicitly specify allowed algorithms in JWT verification\n- Use strong, unique secrets for JWT signing\n- Implement token rotation and short expiration times");
  if (tags.includes("ssti") || tags.includes("template-injection")) remediations.push("- Never pass user input directly to template engines\n- Use sandboxed template rendering\n- Implement strict input validation for template contexts");
  if (tags.includes("race-condition")) remediations.push("- Use atomic database operations (transactions with row-level locking)\n- Implement idempotency keys for critical operations\n- Use Redis INCR for atomic rate limiting counters");
  if (tags.includes("mass-assignment")) remediations.push("- Define explicit allowlists of writable fields for each endpoint\n- Use DTOs/serializers to control which fields are accepted\n- Never pass raw request body to ORM update methods");
  if (tags.includes("cors")) remediations.push("- Never reflect arbitrary origins in Access-Control-Allow-Origin\n- Maintain an explicit allowlist of trusted origins\n- Remove Access-Control-Allow-Credentials unless absolutely necessary");
  if (tags.includes("deserialization")) remediations.push("- Never deserialize untrusted data\n- Use safe data formats (JSON) instead of native serialization\n- Implement integrity checks (signatures) on serialized data");
  if (tags.includes("cloud-misconfig") || tags.includes("s3") || tags.includes("aws")) remediations.push("- Enable S3 Block Public Access on all buckets\n- Rotate all exposed credentials immediately\n- Use IAM roles with least-privilege policies\n- Never store secrets in environment files on storage");
  if (tags.includes("prototype-pollution")) remediations.push("- Use Object.create(null) for dictionary-like objects\n- Sanitize __proto__ and constructor from JSON input\n- Freeze Object.prototype in Node.js applications");
  if (tags.includes("container-escape")) remediations.push("- Never run containers in privileged mode\n- Do not mount the Docker socket inside containers\n- Use seccomp and AppArmor profiles\n- Drop all unnecessary capabilities");
  if (tags.includes("cicd") || tags.includes("pipeline")) remediations.push("- Never use pull_request_target with head checkout\n- Use read-only tokens for PR CI builds\n- Implement code review requirements before CI runs with secrets");

  if (remediations.length === 0) {
    remediations.push("- Implement input validation on all user-controlled data\n- Apply principle of least privilege\n- Enable comprehensive security logging and monitoring");
  }

  return remediations.join("\n");
}

function generateAdditionalAnalysis(
  scenario: ScenarioTemplate,
  domain: string,
  tech: { backend: string; db: string; frontend: string },
  rng: SeededRandom
): string {
  const analyses = [
    `### Additional Analysis\n\nBased on the ${scenario.subcategory} vulnerability identified in ${domain}, I've also checked for related issues:\n\n1. **Attack Chaining Potential**: This vulnerability can be chained with other common issues in ${tech.backend} applications. For example, combining this with a secondary SSRF or open redirect could amplify the impact significantly.\n\n2. **Lateral Movement**: If an attacker gains initial access through this vulnerability, they could potentially:\n   - Access internal services through the compromised application\n   - Pivot to other microservices in the ${tech.backend} ecosystem\n   - Extract credentials stored in environment variables or config files\n\n3. **WAF Evasion**: Standard WAF rules may not catch this attack pattern because:\n   - The payload uses encoding techniques to bypass signature-based detection\n   - The attack leverages business logic flaws rather than known attack signatures\n   - Request patterns appear legitimate without deep inspection\n\n4. **Detection Difficulty**: This attack would likely go unnoticed because:\n   - No anomalous error rates in server logs\n   - Requests appear as normal API usage\n   - No filesystem changes that would trigger FIM alerts`,

    `### Risk Assessment\n\nFor ${domain} running ${tech.backend}:\n\n**Business Impact:**\n- Potential data breach affecting user PII and financial data\n- Regulatory compliance violations (GDPR, PCI-DSS, HIPAA depending on data types)\n- Reputational damage and customer trust erosion\n- Potential for supply chain compromise if the application serves other businesses\n\n**Technical Scope:**\n- The vulnerability affects all users of the application\n- Exploitation requires only low-privilege authenticated access\n- No specialized tools required — standard HTTP requests suffice\n- The attack is reliable and reproducible\n\n**Compensating Controls:**\nUntil a fix is deployed, consider:\n- Implementing additional WAF rules targeting the specific attack pattern\n- Enabling enhanced logging on the affected endpoints\n- Rate limiting API requests per user/IP\n- Implementing anomaly detection on the ${tech.db} query patterns`,

    `### Persistence and Post-Exploitation Considerations\n\nIf an attacker had exploited this ${scenario.subcategory} vulnerability in a real attack:\n\n**Persistence Mechanisms:**\n- Creating backdoor admin accounts via the compromised endpoint\n- Injecting persistent XSS payloads that survive application updates\n- Modifying cron jobs or scheduled tasks through database manipulation\n- Planting web shells in upload directories\n\n**Data Exfiltration:**\n- Bulk extraction of user records via the vulnerable API\n- Accessing database backups stored on accessible storage\n- Intercepting real-time data through WebSocket or event stream hijacking\n\n**Covering Tracks:**\n- The attack generates minimal log artifacts\n- No file system modifications in the initial exploitation phase\n- API logs would show normal-looking request patterns\n- Difficult to distinguish from legitimate usage without behavioral analytics`,
  ];

  return rng.pick(analyses).replace(/target\.com/g, domain);
}

// ============================================================
// Main Generation Engine
// ============================================================

export async function generateDataset(config: Partial<GenerationConfig> = {}): Promise<{
  outputPath: string;
  count: number;
  stats: Record<string, number>;
}> {
  const finalConfig = { ...DEFAULT_CONFIG, ...config };
  const rng = new SeededRandom(finalConfig.seed || Date.now());

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

  if (scenarios.length === 0) {
    throw new Error("No scenarios match the given filters");
  }

  // Ensure output directory exists
  const outputDir = path.resolve(finalConfig.outputDir);
  await fsp.mkdir(outputDir, { recursive: true });

  const timestamp = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
  const outputPath = path.join(outputDir, `pentesterflow_dataset_${timestamp}.jsonl`);
  const metadataPath = path.join(outputDir, `pentesterflow_metadata_${timestamp}.json`);

  const stats: Record<string, number> = {
    total: 0,
    with_thinking: 0,
    without_thinking: 0,
  };
  const categoryStats: Record<string, number> = {};
  const difficultyStats: Record<string, number> = {};

  // Generate entries with backpressure-aware streaming
  const writeStream = fs.createWriteStream(outputPath);

  for (let i = 0; i < finalConfig.count; i++) {
    const scenario = rng.pick(scenarios);
    const conversation = buildConversation(scenario, rng, finalConfig);

    const canContinue = writeStream.write(JSON.stringify(conversation) + "\n");
    if (!canContinue) {
      await new Promise<void>(resolve => writeStream.once("drain", resolve));
    }

    // Track stats
    stats.total++;
    if (conversation.metadata.has_thinking) {
      stats.with_thinking++;
    } else {
      stats.without_thinking++;
    }
    categoryStats[scenario.category] = (categoryStats[scenario.category] || 0) + 1;
    difficultyStats[scenario.difficulty] = (difficultyStats[scenario.difficulty] || 0) + 1;
  }

  await new Promise<void>((resolve, reject) => {
    writeStream.end(() => resolve());
    writeStream.on("error", reject);
  });

  // Write metadata file
  const metadata = {
    dataset_name: "PentesterFlow Offensive Security Dataset",
    version: "2.0.0",
    format: "ShareGPT/ChatML (JSONL)",
    target_model: "Qwen3.5",
    generated_at: new Date().toISOString(),
    config: finalConfig,
    statistics: {
      ...stats,
      categories: categoryStats,
      difficulties: difficultyStats,
      scenario_count: scenarios.length,
      unique_tags: [...new Set(scenarios.flatMap(s => s.tags))].length,
    },
  };

  await fsp.writeFile(metadataPath, JSON.stringify(metadata, null, 2));

  return {
    outputPath,
    count: stats.total,
    stats: { ...stats, ...categoryStats, ...difficultyStats },
  };
}

export function listAvailableScenarios(): {
  total: number;
  categories: Record<string, number>;
  difficulties: Record<string, number>;
  tags: string[];
  scenarios: Array<{ id: string; title: string; category: string; difficulty: string; tags: string[] }>;
} {
  const categories: Record<string, number> = {};
  const difficulties: Record<string, number> = {};

  for (const s of ALL_SCENARIOS) {
    categories[s.category] = (categories[s.category] || 0) + 1;
    difficulties[s.difficulty] = (difficulties[s.difficulty] || 0) + 1;
  }

  return {
    total: ALL_SCENARIOS.length,
    categories,
    difficulties,
    tags: [...new Set(ALL_SCENARIOS.flatMap(s => s.tags))],
    scenarios: ALL_SCENARIOS.map(s => ({
      id: s.id,
      title: s.title,
      category: s.category,
      difficulty: s.difficulty,
      tags: s.tags,
    })),
  };
}
