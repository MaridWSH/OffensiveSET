// Conversation builder for Dataset Generator V2

import { ScenarioTemplate, AttackPhase } from "../../templates/scenarios/index.js";
import { PENTESTING_TOOLS, ToolDefinition } from "../../schemas/tools/index.js";
import { DynamicOutputEngine, SeededRNG, TargetProfile, generateTargetProfile } from "../outputs/index.js";
import { ThinkingEngine } from "../thinking-engine.js";

import { ShareGPTConversation, ShareGPTMessage, ToolCall, ToolResult, GenerationConfig } from "./types.js";
import {
  USER_PROMPTS_INITIAL,
  USER_PROMPTS_VULN_TESTING,
  USER_PROMPTS_EXPLOIT,
  USER_PROMPTS_FAILURE_FOLLOWUP,
  USER_PROMPTS_REPORT,
  USER_PROMPTS_DEEP_ANALYSIS,
  USER_PROMPTS_EVASION,
  DOMAINS,
} from "./prompts.js";
import { generateSystemPrompt } from "./system-prompts.js";
import { variateText, generateGroundedResponse } from "./responses.js";
import { generateUniqueReport, generateDeepAnalysis } from "./reports.js";
import { postProcessForQwen } from "./post-processor.js";
import { estimateTokens } from "./post-processor.js";

export function countTurns(messages: ShareGPTMessage[]): number {
  return messages.filter(m => m.from === "human" || m.from === "gpt").length;
}

export function identifyToolFromCommand(cmd: string): string | undefined {
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
    caido: ["caido "],
    puredns: ["puredns "],
    dnsx: ["dnsx "],
    interactsh: ["interactsh"],
    crlfuzz: ["crlfuzz "],
    corsy: ["corsy "],
    kiterunner: ["kr ", "kiterunner "],
    secretfinder: ["secretfinder "],
    linkfinder: ["linkfinder "],
    gf: ["gf "],
    testssl: ["testssl "],
    nosqlmap: ["nosqlmap "],
  };

  for (const [tool, keywords] of Object.entries(toolKeywords)) {
    if (keywords.some(kw => cmd.includes(kw))) return tool;
  }

  if (cmd.startsWith("python3") || cmd.startsWith("python ")) return "python_script";
  if (cmd.includes("for ") && cmd.includes("do ")) return "bash_script";
  if (cmd.startsWith("export ") || cmd.startsWith("aws ")) return "aws_cli";
  if (cmd.startsWith("kubectl ") || cmd.startsWith("k ")) return "kubectl";
  if (cmd.startsWith("docker ")) return "docker";
  if (cmd.startsWith("terraform ")) return "terraform";
  if (cmd.startsWith("gcloud ")) return "gcloud";
  if (cmd.startsWith("az ")) return "az_cli";

  return undefined;
}

export function generateDynamicOutput(
  engine: DynamicOutputEngine,
  toolName: string,
  domain: string,
  profile: TargetProfile,
  phase: AttackPhase,
  rng: SeededRNG
): string {
  switch (toolName) {
    case "nmap": return engine.generateNmapOutput(domain, profile);
    case "ffuf": return engine.generateFfufOutput(domain, profile);
    case "gobuster": return engine.generateGobusterOutput(domain, profile);
    case "sqlmap":
      if (phase.phase.toLowerCase().includes("detect") || phase.phase.toLowerCase().includes("discover")) return engine.generateSqlmapOutput(domain, profile, "detect");
      if (phase.phase.toLowerCase().includes("enum")) return engine.generateSqlmapOutput(domain, profile, "enumerate");
      if (phase.phase.toLowerCase().includes("dump") || phase.phase.toLowerCase().includes("extract")) return engine.generateSqlmapOutput(domain, profile, "dump");
      return engine.generateSqlmapOutput(domain, profile, rng.pick(["detect", "enumerate", "dump", "os"]));
    case "nuclei": return engine.generateNucleiOutput(domain, profile);
    case "curl": return engine.generateHttpResponse(profile, domain, rng.pick(["api_json", "error", "auth", "admin", "ssrf"]));
    case "httpx": return engine.generateHttpxOutput(domain, profile);
    case "subfinder": return engine.generateSubfinderOutput(domain, profile);
    case "amass": return engine.generateAmassOutput(domain, profile);
    case "jwt_tool": return engine.generateJwtOutput(rng.pick(["decode", "crack", "attack"]));
    case "dalfox": return engine.generateDalfoxOutput(domain, profile);
    case "nikto": return engine.generateNiktoOutput(domain, profile);
    case "wfuzz": return engine.generateWfuzzOutput(domain, profile);
    case "ssrfmap": return engine.generateHttpResponse(profile, domain, "ssrf");
    case "feroxbuster": return engine.generateFeroxbusterOutput(domain, profile);
    case "rustscan": return engine.generateRustscanOutput(domain, profile);
    case "trufflehog": return engine.generateTrufflehogOutput(domain, profile);
    case "semgrep": return engine.generateSemgrepOutput(domain, profile);
    case "katana": return engine.generateKatanaOutput(domain, profile);
    case "testssl": return engine.generateTestsslOutput(domain, profile);
    case "nosqlmap": return engine.generateNosqlmapOutput(domain, profile);
    case "metasploit": return engine.generateMetasploitOutput(domain, profile);
    case "crlfuzz": return `[VULN] Found CRLF injection at https://${rng.pick(profile.subdomains)}.${domain}/${rng.pick(profile.directories)} via ${rng.pick(["Header injection", "Response splitting", "Log injection"])}`;
    case "corsy": return `[VULN] ${domain} reflects arbitrary Origin header\n  Access-Control-Allow-Origin: https://evil.com\n  Access-Control-Allow-Credentials: true`;
    case "kiterunner": return `[${rng.int(200, 403)}] ${rng.pick(["GET", "POST", "PUT"])} https://${domain}/${rng.pick(["api/v1", "api/v2", "api/internal"])}/${rng.pick(["users", "admin", "config", "health", "debug", "metrics"])} [${rng.int(100, 9000)} bytes]`;
    case "secretfinder": return `[!] Found ${rng.int(1, 8)} secrets in JS files:\n  [API_KEY] https://${domain}/assets/app.js:${rng.int(100, 5000)} → ${engine.generateHex(32)}\n  [JWT] https://${domain}/assets/main.js:${rng.int(100, 3000)} → eyJhbGci...`;
    case "linkfinder": return Array.from({ length: rng.int(5, 15) }, () => `https://${domain}/${rng.pick(["api/v1", "api/v2", "internal"])}/${rng.pick(["users", "settings", "config", "auth", "data", "export", "graphql", "webhook"])}`).join("\n");
    case "dnsx": return Array.from({ length: rng.int(3, 10) }, () => `${rng.pick(profile.subdomains)}.${domain} [A] ${rng.pick([10, 172, 52, 34, 104])}.${rng.int(0, 255)}.${rng.int(0, 255)}.${rng.int(1, 254)}`).join("\n");
    case "puredns": return `Resolved ${rng.int(50, 500)} subdomains from ${rng.int(5000, 50000)} total\n${rng.pickN(profile.subdomains, rng.int(5, 15)).map(s => `${s}.${domain}`).join("\n")}`;
    case "arjun": {
      const stability = rng.pick(["stable", "unstable (high jitter)", "stable with minor variance"]);
      const anomalies = rng.int(0, 3);
      const paramCount = rng.int(2, 8);
      const foundParams = rng.pickN([...profile.injectableParams, "debug", "verbose", "admin", "token", "api_key", "format", "callback", "limit", "offset", "fields", "include", "expand", "v", "version", "lang"], paramCount);
      return `[*] Probing the target for stability\n[*] Target is ${stability}\n[*] Analysing HTTP response for anomalies\n[*] Found ${anomalies} anomalies in response\n[*] Performing parameter discovery (${rng.pick(["GET", "POST", "JSON"])} method)\n[*] Tried ${rng.int(2000, 10000)} payloads\n[+] Parameters found (${foundParams.length}): ${foundParams.join(", ")}\n[*] Completed in ${rng.float(2, 45).toFixed(1)}s`;
    }
    case "paramspider": {
      const paths = rng.pickN(["search", "users", "data", "page", "api/v1/query", "api/v2/filter", "download", "export", "redirect", "callback", "profile", "settings", "upload", "preview", "render"], rng.int(5, 12));
      return paths.map(p => `https://${rng.pick(profile.subdomains)}.${domain}/${p}?${rng.pick(profile.injectableParams)}=FUZZ`).join("\n");
    }
    case "gau": {
      const gauPaths = rng.pickN(["api/v1", "api/v2", "api/v3", "search", "page", "data", "admin", "login", "dashboard", "export", "download", "user", "settings", "graphql", "webhook", "callback", "reset-password", "verify"], rng.int(6, 15));
      return gauPaths.map(p => `https://${rng.pick(profile.subdomains)}.${domain}/${p}?${rng.pick(profile.injectableParams)}=${rng.pick(["test", "1", "admin", "true", "SELECT", "../etc/passwd", "http://localhost", "{{7*7}}", "<script>"])}`).join("\n");
    }
    case "hydra":
      return `Hydra v${rng.pick(["9.4", "9.5", "9.6"])} (c) 2024 by van Hauser/THC\n[DATA] max ${rng.int(4, 32)} tasks per 1 server, overall ${rng.int(4, 64)} tasks\n[DATA] attacking ${rng.pick(["http-post-form", "ssh", "ftp", "mysql", "http-get"])}://${domain}\n[${rng.pick(["80", "443", "22", "3306"])}][${rng.pick(["http-post-form", "ssh", "ftp", "mysql"])}] host: ${domain}   login: ${rng.pick(["admin", "root", "test", "user"])}   password: ${rng.pick(["admin123", "password", "P@ssw0rd!", "changeme", "letmein", "123456"])}\n1 of 1 target successfully completed, 1 valid password found`;
    case "commix":
      return `[info] Testing connection to the target URL.\n[info] Performing ${rng.pick(["classic", "eval-based", "time-based"])} injection technique.\n[info] The ${rng.pick(["GET", "POST"])} parameter '${rng.pick(profile.injectableParams)}' seems injectable via ${rng.pick(["classic", "eval-based", "time-based"])} injection technique.\n    Payload: ${rng.pick([";id", "| id", "$(id)", "`id`"])}\n[info] The target is vulnerable.\n    uid=${rng.int(33, 1000)}(${rng.pick(["www-data", "apache", "nginx", "node", "app"])}) gid=${rng.int(33, 1000)}(${rng.pick(["www-data", "apache", "nginx", "nogroup"])})`;
    case "linpeas":
      return `${rng.pick(["╔══════════╣", "════════════"])} ${rng.pick(["SUID binaries", "Writable files", "Interesting GROUPs", "Cron jobs", "Docker membership", "Kernel version"])}\n${rng.pick(["/usr/bin/pkexec\n/usr/bin/sudo\n/usr/local/bin/" + rng.pick(["backup", "deploy", "monitor"]) + " (Unknown SUID!)", "/etc/crontab writable\n/opt/scripts/" + rng.pick(["backup.sh", "deploy.sh", "cleanup.sh"]) + " writable", "uid=" + rng.int(33, 1000) + "(" + rng.pick(["www-data", "app"]) + ") groups=" + rng.pick(["docker", "sudo", "lxd", "adm"])])}\n\n${rng.pick(["╔══════════╣", "════════════"])} ${rng.pick(["Kernel", "OS Info"])}\nLinux ${rng.pick(["5.4.0", "5.15.0", "6.1.0", "5.10.0"])}-${rng.int(50, 200)}-${rng.pick(["generic", "amd64", "cloud"])} #${rng.int(50, 250)}\n${rng.pick(["Ubuntu 22.04", "Ubuntu 20.04", "Debian 12", "CentOS 8", "Amazon Linux 2"])}`;
    default: {
      // Dynamic fallback for scripts/custom tools — NEVER use static template text
      const sub = rng.pick(profile.subdomains);
      const user = engine.generateRandomUser();
      const customOutputs = [
        `[+] Script completed successfully\n[+] Target: ${sub}.${domain}\n[+] Found ${rng.int(1, 50)} results\n[+] Data saved to /tmp/output_${engine.generateHex(6)}.json\n\nSample output:\n${JSON.stringify({ id: rng.int(1, 9999), email: user.email, role: user.role }, null, 2)}`,
        `$ python3 exploit.py --target https://${sub}.${domain} --param ${rng.pick(profile.injectableParams)}\n[*] Connecting to target...\n[*] Sending ${rng.int(1, 100)} requests...\n[+] ${rng.pick(["Vulnerability confirmed", "Data extracted", "Access granted", "Bypass successful", "Shell obtained"])}\n[+] Response: ${rng.int(200, 500)} (${rng.int(100, 9000)} bytes)\n[+] Extracted ${rng.int(1, 500)} records`,
        `#!/bin/bash\n# Results from automated scan of ${domain}\nTARGETS_SCANNED=${rng.int(5, 50)}\nVULNERABLE=${rng.int(1, 10)}\nCRITICAL=${rng.int(0, 3)}\n\n[+] ${sub}.${domain} - ${rng.pick(["VULNERABLE", "INTERESTING", "NEEDS_REVIEW"])}\n[+] Port ${rng.pick(profile.openPorts)} - ${rng.pick(["open", "filtered"])}\n[+] Parameter ${rng.pick(profile.injectableParams)} - ${rng.pick(["injectable", "reflected", "stored"])}\n[+] Duration: ${rng.int(1, 300)}s`,
      ];
      return rng.pick(customOutputs);
    }
  }
}

export function buildConversationV2(
  scenario: ScenarioTemplate,
  rng: SeededRNG,
  config: GenerationConfig,
  entryIndex: number
): ShareGPTConversation {
  const domain = rng.pick(DOMAINS);
  const profile = generateTargetProfile(rng);
  profile.domain = domain;

  const outputEngine = new DynamicOutputEngine(rng.int(0, 999999999));
  const thinkingEngine = new ThinkingEngine(rng.int(0, 999999999));

  const includeThinking = rng.bool(config.thinkingRatio);
  const includeFailures = rng.bool(config.failureRatio);

  const messages: ShareGPTMessage[] = [];
  const toolsUsed: string[] = [];
  let hasFailures = false;

  // FIX #5: Single shorter system message (combine role + tools, save tokens)
  const scenarioTools = scenario.tools_involved
    .map(name => PENTESTING_TOOLS.find(t => t.name === name))
    .filter((t): t is ToolDefinition => t !== undefined);
  const extraTools = rng.pickN(
    PENTESTING_TOOLS.filter(t => !scenario.tools_involved.includes(t.name)),
    rng.int(1, 3)
  );
  const allTools = [...scenarioTools, ...extraTools];
  const toolsList = allTools.map(t => `- ${t.name}: ${t.description.slice(0, 80)}`).join('\n');

  messages.push({
    from: "system",
    value: `${generateSystemPrompt(rng, profile)}\n\nAvailable tools:\n${toolsList}`,
  });

  // 3. Initial user prompt (highly varied)
  const targetDesc = variateText(scenario.target_description, domain, profile);
  const techStr = `${profile.technologies.join("/")} with ${profile.databases.name} database`;

  const initialPrompt = rng.pick(USER_PROMPTS_INITIAL)
    .replace(/\{domain\}/g, domain)
    + `\n\nTarget context: ${targetDesc}\nTechnology: ${techStr}`;

  messages.push({ from: "human", value: initialPrompt });

  // FIX #1: Randomize phase order — sometimes skip phases, sometimes reorder
  let phases = [...scenario.attack_phases];
  const structureVariant = rng.int(0, 4);
  if (structureVariant === 1 && phases.length > 3) {
    // Skip one middle phase
    const skipIdx = rng.int(1, phases.length - 2);
    phases = phases.filter((_, i) => i !== skipIdx);
  } else if (structureVariant === 2 && phases.length > 2) {
    // Merge first two phases into one
    phases = [phases[0], ...phases.slice(2)];
  }
  // structureVariant 0, 3, 4 = normal order (60% of entries)

  // FIX #3: Decide WHERE failures happen (not always middle)
  const failurePhaseIdx = includeFailures ? rng.int(0, phases.length - 1) : -1;
  // Also: 15% chance of "nothing found" even in non-failure entries
  const softFailChance = 0.15;

  // Track tool outputs for grounding
  let lastToolOutputSummary = "";
  let lastFindingSummary = "";

  // 4. Phase-by-phase conversation generation
  for (let phaseIdx = 0; phaseIdx < phases.length; phaseIdx++) {
    const phase = phases[phaseIdx];
    const isFailurePhase = phaseIdx === failurePhaseIdx;
    const isSoftFail = !isFailurePhase && rng.bool(softFailChance);

    // FIX #1: Sometimes do multiple tool calls then one analysis, sometimes interleave
    const toolCalls: ToolCall[] = [];
    const toolResults: ToolResult[] = [];
    const toolOutputTexts: string[] = []; // FIX #7: collect for grounding

    // FIX #9: Vary command construction — don't always use template commands
    const cmdCount = rng.int(1, Math.min(phase.commands.length, rng.int(2, 5)));
    const selectedCmds = rng.pickN(phase.commands.filter(c => !c.startsWith("#") && c.trim() !== ""), cmdCount);

    for (let cmdIdx = 0; cmdIdx < selectedCmds.length; cmdIdx++) {
      let cmd = variateText(selectedCmds[cmdIdx], domain, profile);
      // FIX #9: Add random flags/variations to commands
      if (rng.bool(0.3) && cmd.includes("curl")) {
        cmd += rng.pick([" --connect-timeout 10", " -w '\\n%{http_code}'", " --max-time 30", ` -H 'X-Request-Id: ${outputEngine.generateUUID()}'`]);
      }
      if (rng.bool(0.2) && cmd.includes("ffuf")) {
        cmd += rng.pick([" -rate 100", " -timeout 15", " -ac", ` -H 'User-Agent: Mozilla/5.0'`]);
      }

      const toolCallId = `call_${entryIndex}_${phaseIdx}_${cmdIdx}_${rng.int(10000, 99999)}`;
      const toolName = identifyToolFromCommand(cmd);
      if (toolName) toolsUsed.push(toolName);

      toolCalls.push({
        id: toolCallId,
        name: toolName || "bash",
        arguments: { command: cmd },
      });

      let output: string;
      if (isFailurePhase) {
        output = outputEngine.generateFailureOutput(toolName || "generic", cmd);
        hasFailures = true;
      } else if (isSoftFail && cmdIdx === 0) {
        // FIX #3: Soft failure — tool runs but finds nothing interesting
        output = outputEngine.generateFailureOutput(toolName || "generic", cmd);
      } else {
        output = generateDynamicOutput(outputEngine, toolName || "bash", domain, profile, phase, rng);
      }

      toolOutputTexts.push(output.slice(0, 200)); // FIX #7: save summary for grounding
      toolResults.push({ tool_call_id: toolCallId, name: toolName || "bash", output });
    }

    // FIX #7: Build grounding context from tool outputs
    lastToolOutputSummary = toolOutputTexts.join(" | ").slice(0, 300);

    // Generate thinking block — FIX #4: make it LONGER when present
    let thinkingBlock: string | undefined;
    if (includeThinking) {
      if (isFailurePhase) {
        thinkingBlock = thinkingEngine.generateFailureThinking(domain, profile, phase.phase,
          rng.pick(["WAF blocked the payload", "parameter validation prevented injection", "rate limiting kicked in", "the endpoint returned consistent responses", "no injectable parameters found"]));
      } else if (phaseIdx === 0) {
        thinkingBlock = thinkingEngine.generateReconThinking(domain, profile, [phase.analysis]);
      } else if (phase.phase.toLowerCase().includes("enum") || phase.phase.toLowerCase().includes("discover")) {
        thinkingBlock = thinkingEngine.generateEnumThinking(domain, profile, phase.phase);
      } else if (phase.phase.toLowerCase().includes("exploit") || phase.phase.toLowerCase().includes("attack")) {
        thinkingBlock = thinkingEngine.generateExploitThinking(domain, profile, scenario.subcategory, phase.analysis);
      } else {
        thinkingBlock = thinkingEngine.generateVulnAnalysisThinking(domain, profile, scenario.subcategory, phase.analysis);
      }
    }

    // FIX #2 + #4 + #7: Generate response — varied format, grounded in tool output, longer with thinking
    const assistantResponse = generateGroundedResponse(rng, phase, profile, domain, isFailurePhase || isSoftFail, lastToolOutputSummary, includeThinking);
    lastFindingSummary = assistantResponse.slice(0, 150);

    messages.push({
      from: "gpt",
      value: assistantResponse,
      thinking: thinkingBlock,
      tool_calls: toolCalls.length > 0 ? toolCalls : undefined,
    });

    // Tool results — FIX #1: sometimes put tool results BEFORE gpt analysis
    if (toolResults.length > 0) {
      // 30% of the time: swap order so tool output comes first, then GPT analyzes
      if (rng.bool(0.3) && messages.length >= 2) {
        const gptMsg = messages.pop()!;
        messages.push({
          from: "tool",
          value: toolResults.map(r => `[${r.name}] Output:\n${r.output}`).join("\n\n---\n\n"),
          tool_results: toolResults,
        });
        messages.push(gptMsg);
      } else {
        messages.push({
          from: "tool",
          value: toolResults.map(r => `[${r.name}] Output:\n${r.output}`).join("\n\n---\n\n"),
          tool_results: toolResults,
        });
      }
    }

    // FIX #8: Contextual user follow-ups referencing prior findings
    if (phaseIdx < phases.length - 1) {
      const nextPhase = phases[phaseIdx + 1];
      let followUp: string;

      if (isFailurePhase || isSoftFail) {
        // 40% evasion-specific prompts, 60% general failure follow-ups
        followUp = rng.bool(0.4) ? rng.pick(USER_PROMPTS_EVASION) : rng.pick(USER_PROMPTS_FAILURE_FOLLOWUP);
      } else {
        // FIX #8: 60% contextual (reference prior findings), 40% generic
        if (rng.bool(0.6)) {
          const contextParts = [
            `Based on what you just found on ${rng.pick(profile.subdomains)}.${domain}`,
            `You mentioned the \`${rng.pick(profile.injectableParams)}\` parameter is ${rng.pick(["injectable", "reflected", "vulnerable", "interesting"])}`,
            `The ${rng.pick(profile.technologies)} backend seems to have ${rng.pick(["weak validation", "no authorization checks", "exposed debug info", "verbose errors"])}`,
            `Since we confirmed the ${scenario.subcategory} issue`,
            `The tool output showed ${rng.pick(["several open ports", "interesting directories", "database errors", "reflected input", "missing security headers"])}`,
            `Looking at the ${profile.databases.name} error from the last scan`,
          ];
          followUp = `${rng.pick(contextParts)} — ${rng.pick([
            `can you test if ${rng.pick(["other endpoints", "the admin panel", "the API v1", "the mobile API"])} has the same issue?`,
            `try to escalate this further. What's the worst-case impact?`,
            `chain this with the ${rng.pick(["authentication", "authorization", "session handling", "CORS config"])} to increase severity.`,
            `exploit it fully and extract evidence for the report.`,
            `check if the ${rng.pick(["WAF", "rate limiter", "input filter", "CSP"])} catches this attack pattern.`,
            `test the same parameter with ${rng.pick(["time-based payloads", "out-of-band techniques", "different encoding", "a custom script"])}.`,
          ])}`;
        } else if (nextPhase.phase.toLowerCase().includes("exploit")) {
          followUp = rng.pick(USER_PROMPTS_EXPLOIT)
            .replace(/\{endpoint\}/g, `https://${rng.pick(profile.subdomains)}.${domain}/${rng.pick(["api", "v1", "v2"])}/${rng.pick(["users", "search", "login", "profile"])}`)
            .replace(/\{vulnType\}/g, scenario.subcategory)
            .replace(/\{param\}/g, rng.pick(profile.injectableParams));
        } else if (nextPhase.phase.toLowerCase().includes("report")) {
          followUp = rng.pick(USER_PROMPTS_REPORT).replace(/\{vulnType\}/g, scenario.title);
        } else {
          followUp = rng.pick(USER_PROMPTS_VULN_TESTING)
            .replace(/\{endpoint\}/g, `https://${rng.pick(profile.subdomains)}.${domain}/${rng.pick(["api/v1", "api/v2", "api"])}/${rng.pick(["users", "search", "login", "profile"])}`)
            .replace(/\{param\}/g, rng.pick(profile.injectableParams));
        }
      }

      messages.push({ from: "human", value: followUp });
    }
  }

  // 5. Final reporting turn — FIX #5 (reports): always include CVSS + evidence + remediation
  messages.push({
    from: "human",
    value: rng.pick(USER_PROMPTS_REPORT).replace(/\{vulnType\}/g, scenario.title),
  });

  const reportThinking = includeThinking
    ? thinkingEngine.generateReportThinking(domain, scenario.subcategory, scenario.difficulty, scenario.attack_phases.map(p => p.phase))
    : undefined;

  messages.push({
    from: "gpt",
    value: generateUniqueReport(scenario, domain, profile, rng),
    thinking: reportThinking,
  });

  // 6. Pad to minimum turns with deep analysis
  while (countTurns(messages) < config.minTurns) {
    // FIX #8: Contextual deep analysis prompts
    messages.push({
      from: "human",
      value: rng.pick(USER_PROMPTS_DEEP_ANALYSIS),
    });

    const addlThinking = includeThinking
      ? thinkingEngine.generatePostExploitThinking(domain, profile, rng.pick(["application-level", "database-level", "OS-level", "network-level"]))
      : undefined;

    messages.push({
      from: "gpt",
      value: generateDeepAnalysis(scenario, domain, profile, rng),
      thinking: addlThinking,
    });
  }

  // Post-process: apply Qwen-compatible transformations
  const finalMessages = postProcessForQwen(messages, config);

  return {
    id: `pentesterflow-${scenario.id}-${rng.int(100000, 999999)}-${entryIndex}`,
    conversations: finalMessages,
    metadata: {
      scenario_id: scenario.id,
      category: scenario.category,
      subcategory: scenario.subcategory,
      difficulty: scenario.difficulty,
      tags: scenario.tags,
      tools_used: [...new Set(toolsUsed)],
      has_thinking: includeThinking,
      has_failures: hasFailures,
      turn_count: countTurns(finalMessages),
      cve_references: scenario.cve_references || [],
      estimated_tokens: estimateTokens(finalMessages),
      generated_at: new Date().toISOString(),
    },
  };
}
