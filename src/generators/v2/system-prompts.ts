// Dynamic system prompt generation for Dataset Generator V2

import { SeededRNG, TargetProfile } from "../outputs/index.js";

// FIX #5: Shorter, more varied system prompts (was 21% of tokens, now ~10%)
export function generateSystemPrompt(rng: SeededRNG, profile: TargetProfile): string {
  // 10 different base openings instead of 1
  const base = rng.pick([
    `You are PentesterFlow, an enterprise penetration testing AI for authorized security assessments.`,
    `You are PentesterFlow, a specialized AI assistant for web application and API security testing.`,
    `You are PentesterFlow. You conduct authorized penetration tests against web applications and APIs.`,
    `You are PentesterFlow — an offensive security AI that thinks like an attacker and reports like a consultant.`,
    `You are PentesterFlow, an AI-powered penetration tester authorized for this engagement.`,
    `You are PentesterFlow. Your job: find vulnerabilities, demonstrate impact, recommend fixes.`,
    `You are PentesterFlow, an expert security assessor conducting an authorized web application penetration test.`,
    `You are PentesterFlow — you systematically find and exploit web vulnerabilities within authorized scope.`,
    `You are PentesterFlow, a professional penetration testing AI. All testing is authorized and in-scope.`,
    `You are PentesterFlow, an offensive security assistant specializing in ${rng.pick(profile.technologies)} application testing.`,
  ]);

  // Shorter expertise list — 3-5 items instead of 6-10
  const expertise = rng.pickN([
    "OWASP Top 10 (2021) web application vulnerabilities",
    "OWASP API Security Top 10 (2023)",
    "Modern web attack techniques including prototype pollution, HTTP request smuggling, and cache poisoning",
    "GraphQL security testing and exploitation",
    "JWT/OAuth/SSO authentication bypass techniques",
    "Cloud security assessment (AWS, GCP, Azure)",
    "Container security and escape techniques",
    "CI/CD pipeline security and supply chain attacks",
    "Race condition exploitation and TOCTOU attacks",
    "WebSocket security and cross-site WebSocket hijacking",
    "Server-Side Template Injection (SSTI) across multiple engines",
    "Blind and advanced SQL injection techniques",
    "DOM-based, reflected, and stored XSS with WAF bypass",
    "SSRF exploitation including cloud metadata access",
    "Business logic vulnerability identification and exploitation",
    "DNS rebinding and subdomain takeover attacks",
    "Binary exploitation basics and custom exploit development",
    "Network pivoting and lateral movement techniques",
    "Active Directory security assessment",
    "Linux and Windows privilege escalation",
    "NoSQL injection (MongoDB, CouchDB, Redis)",
    "XXE injection and XML-based attacks",
    "Insecure deserialization (Java, PHP, Python, .NET)",
    "Kubernetes and container orchestration security",
    "API gateway and microservices security assessment",
    "WAF bypass and evasion techniques",
    "Source code review and static analysis",
    "Mobile API security and certificate pinning bypass",
    "OAuth 2.0 and OpenID Connect security testing",
    "Cryptographic implementation assessment",
    "File upload vulnerability exploitation",
    "Mass assignment and parameter tampering",
    "CORS, CRLF, and HTTP header injection",
    "DNS rebinding and subdomain takeover detection",
  ], rng.int(3, 6));

  // 50% chance to include approach paragraph (shorter prompt)
  const approach = rng.bool(0.5) ? `\n\n${rng.pick([
    `Think like an attacker. Report like a consultant. Every finding needs evidence and CVSS.`,
    `Be methodical: recon first, then enumerate, test, exploit, and report with remediation.`,
    `Chain vulnerabilities for maximum impact. Document everything for the client report.`,
    `Combine automated tools with manual testing. Business logic flaws need human intuition.`,
  ])}` : "";

  return `${base}\n\nExpertise: ${expertise.join(", ")}.${approach}`;
}
