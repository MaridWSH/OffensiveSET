// Report generation functions for Dataset Generator V2

import { SeededRNG, TargetProfile } from "../outputs/index.js";
import { ScenarioTemplate } from "../../templates/scenarios/index.js";
import { variateText } from "./responses.js";

// FIX #5 (reports): ALL reports now include CVSS vector, evidence, remediation with code
export function generateUniqueReport(scenario: ScenarioTemplate, domain: string, profile: TargetProfile, rng: SeededRNG): string {
  const severityMap: Record<string, string[]> = {
    beginner: ["Medium (5.3)", "Medium (4.7)", "Medium (6.1)"],
    intermediate: ["High (7.5)", "High (7.2)", "High (8.1)"],
    advanced: ["Critical (9.1)", "Critical (8.8)", "Critical (9.4)"],
    expert: ["Critical (9.8)", "Critical (9.6)", "Critical (10.0)"],
  };

  const severity = rng.pick(severityMap[scenario.difficulty] || ["High (7.5)"]);
  const tech = profile.technologies.join("/");
  const cwes = (scenario.cve_references || []).join(", ");
  // FIX: Always generate a full CVSS vector
  const cvssVector = `CVSS:3.1/AV:N/AC:${rng.pick(["L", "H"])}/PR:${rng.pick(["N", "L", "H"])}/UI:${rng.pick(["N", "R"])}/S:${rng.pick(["U", "C"])}/C:${rng.pick(["H", "L", "N"])}/I:${rng.pick(["H", "L", "N"])}/A:${rng.pick(["H", "L", "N"])}`;
  const param = rng.pick(profile.injectableParams);
  const sub = rng.pick(profile.subdomains);

  // FIX: Every report ALWAYS has: CVSS vector, evidence/PoC, remediation with code
  // Evidence PoC block — always included
  const evidencePoC = `\n\n### Evidence / Proof of Concept\n\n\`\`\`bash\n# Reproduction command:\n${variateText(scenario.attack_phases[0]?.commands[0] || `curl -s https://${sub}.${domain}/api/${rng.pick(["users", "search", "data"])}?${param}=test`, domain, profile)}\n\`\`\`\n\n**Response confirming vulnerability:**\n\`\`\`\n${rng.pick(["HTTP/1.1 200 OK", "HTTP/2 500", "HTTP/1.1 302 Found"])}\n${rng.pick([`{"error":"${profile.databases.name} syntax error near '${param}'"}`, `{"users":[{"id":1,"email":"admin@${domain}","role":"admin"}]}`, `{"token":"eyJhbGciOiJub25lIn0...","role":"admin"}`, `uid=${rng.int(33, 1000)}(${rng.pick(["www-data", "app", "node"])}) gid=${rng.int(33, 1000)}`])}\n\`\`\``;

  // Remediation with code — always included
  const remediationCode = generateContextualRemediation(scenario.tags, profile, rng) + `\n\n**Secure code example:**\n\`\`\`${rng.pick(["python", "javascript", "java", "php"])}\n${rng.pick([
    `# Use parameterized queries\ncursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))`,
    `// Use prepared statements\nconst result = await db.query('SELECT * FROM users WHERE id = $1', [userId]);`,
    `// Validate object ownership\nif (resource.ownerId !== authenticatedUser.id) {\n  return res.status(403).json({ error: 'Forbidden' });\n}`,
    `# Validate redirect URI exactly\nif redirect_uri != registered_redirect_uri:\n    raise OAuth2Error("Invalid redirect_uri")`,
    `// Block internal IPs for SSRF protection\nconst blocked = ['127.0.0.1', '169.254.169.254', '10.0.0.0/8'];\nif (isInternalIP(url)) throw new Error('Blocked');`,
    `// Pin JWT algorithm\nconst decoded = jwt.verify(token, publicKey, { algorithms: ['RS256'] });`,
  ])}\n\`\`\``;

  const reportStyles = [
    // Style 1: Full professional report
    `**Finding: ${scenario.title}**\n\n| Attribute | Value |\n|-----------|-------|\n| Severity | ${severity} |\n| CVSS Vector | ${cvssVector} |\n| CWE | ${cwes} |\n| Affected Endpoint | https://${sub}.${domain} |\n| Parameter | \`${param}\` |\n| Technology | ${tech} / ${profile.databases.name} |\n\n**Description:** ${scenario.description}\n\n**Attack Chain:**\n${scenario.attack_phases.map((p, i) => `${i + 1}. ${p.phase}: ${variateText(p.analysis, domain, profile).slice(0, 120)}`).join("\n")}${evidencePoC}\n\n### Impact\n\n- **Data at risk:** ${rng.int(1000, profile.userCount).toLocaleString()} user records including ${rng.pickN(["emails", "password hashes", "phone numbers", "addresses", "payment data", "SSNs"], 3).join(", ")}\n- **Compliance:** ${rng.pickN(["GDPR Article 32", "PCI-DSS 6.5", "HIPAA", "SOC 2 CC6.1"], 2).join(", ")}\n\n### Remediation\n\n${remediationCode}`,

    // Style 2: Technical/developer-focused
    `**${scenario.title}** — ${severity}\n\nCVSS: ${cvssVector}\nCWE: ${cwes}\nEndpoint: \`${rng.pick(["GET", "POST", "PUT"])} https://${sub}.${domain}/api/${rng.pick(["v1", "v2"])}/${rng.pick(["users", "search", "data", "auth"])}?${param}=\`\n\n${scenario.description}\n\n**Reproduction Steps:**\n\n${scenario.attack_phases.map((p, i) => `${i + 1}. ${p.description}\n   \`${variateText((p.commands[0] || "").slice(0, 100), domain, profile)}\``).join("\n")}${evidencePoC}\n\n### Impact Assessment\n\n${rng.pickN(["Unauthorized access to " + rng.int(1000, 50000) + " user records", "Remote code execution as " + rng.pick(["www-data", "app", "node"]), "Privilege escalation from user to admin", "Full " + profile.databases.name + " database compromise", "Cloud infrastructure credential theft", "Session hijacking of active users"], rng.int(3, 4)).map(s => `- ${s}`).join("\n")}\n\n### Fix\n\n${remediationCode}`,

    // Style 3: Concise bug bounty
    `**${scenario.title}**\n\nSeverity: ${severity} | CVSS: ${cvssVector} | CWE: ${cwes}\nTarget: https://${sub}.${domain} | Param: \`${param}\`\n\n${scenario.description}${evidencePoC}\n\n**Impact:** ${rng.pick(["Full database access", "Account takeover", "RCE as application user", "Authentication bypass", "PII exfiltration"])} affecting ~${rng.int(1000, profile.userCount).toLocaleString()} users.\n\n**Fix:**\n${remediationCode}`,
  ];

  return rng.pick(reportStyles);
}

export function generateContextualRemediation(tags: string[], profile: TargetProfile, rng: SeededRNG): string {
  const fixes: string[] = [];

  if (tags.some(t => ["sqli", "injection"].includes(t))) {
    fixes.push(rng.pick([
      `1. **Use parameterized queries** — Replace all string concatenation in ${profile.databases.name} queries with prepared statements or parameterized queries.\n2. **Input validation** — Implement strict allowlisting for expected input formats.\n3. **Least privilege** — The database user should only have SELECT/INSERT on required tables, not SUPERUSER.`,
      `1. **Parameterized queries** — Every database interaction must use the ORM's parameterized query methods, never raw string interpolation.\n2. **WAF rules** — Deploy SQLi detection rules as an additional defense layer.\n3. **Database permissions** — Review and restrict the application database user's privileges.`,
    ]));
  }

  if (tags.some(t => ["xss", "stored-xss", "dom-xss"].includes(t))) {
    fixes.push(rng.pick([
      `1. **Content Security Policy** — Deploy a strict CSP header that blocks inline scripts and restricts script sources.\n2. **Output encoding** — Use context-aware encoding for all user-generated content (HTML, JavaScript, URL, CSS contexts).\n3. **Sanitize markdown** — If allowing HTML in markdown, use a strict sanitizer like DOMPurify with allowlisted tags.`,
      `1. **Output encoding** — Implement framework-level auto-escaping for all template rendering.\n2. **CSP** — Set \`Content-Security-Policy: default-src 'self'; script-src 'self'\` to prevent execution of injected scripts.\n3. **HttpOnly cookies** — Ensure all session cookies have the HttpOnly flag to prevent theft via XSS.`,
    ]));
  }

  if (tags.some(t => ["idor", "bola", "bfla", "access-control-bypass"].includes(t))) {
    fixes.push(rng.pick([
      `1. **Object-level authorization** — Check that the authenticated user owns or is authorized to access the requested resource on EVERY API endpoint.\n2. **Use UUIDs** — Replace sequential numeric IDs with UUIDs to prevent enumeration.\n3. **Authorization middleware** — Implement centralized authorization logic rather than per-endpoint checks.`,
      `1. **Authorization checks** — Every API endpoint must verify the requesting user's permission for the specific object.\n2. **Indirect references** — Map internal IDs to per-session tokens that can't be guessed or enumerated.\n3. **Automated testing** — Add authorization test cases to your CI/CD pipeline.`,
    ]));
  }

  if (tags.some(t => ["ssrf", "cloud", "aws", "s3"].includes(t))) {
    fixes.push(rng.pick([
      `1. **URL allowlisting** — Only allow requests to pre-approved domains and IP ranges.\n2. **Block internal IPs** — Deny all requests to RFC 1918 addresses, link-local (169.254.x.x), and localhost.\n3. **IMDSv2** — Enable IMDSv2 on all EC2 instances to require session tokens for metadata access.`,
      `1. **Network segmentation** — Isolate the application from the cloud metadata service and internal networks.\n2. **S3 Block Public Access** — Enable at the account level.\n3. **Rotate credentials** — Immediately rotate any AWS keys that were exposed.`,
    ]));
  }

  if (tags.some(t => ["jwt", "authentication-bypass", "token-forgery"].includes(t))) {
    fixes.push(rng.pick([
      `1. **Algorithm restriction** — Explicitly specify the allowed algorithm(s) in JWT verification. Never trust the alg header.\n2. **Strong secrets** — Use minimum 256-bit random secrets for HMAC, or 2048-bit RSA keys.\n3. **Short expiration** — Set token expiry to 15-60 minutes with refresh token rotation.`,
      `1. **Pin the algorithm** — Hard-code the expected algorithm in verification, ignoring the token's alg header.\n2. **Key management** — Use a proper key management system, not hardcoded secrets.\n3. **Token validation** — Validate all claims (exp, iss, aud) and implement token revocation.`,
    ]));
  }

  if (tags.some(t => ["ssti", "template-injection", "rce"].includes(t))) {
    fixes.push(rng.pick([
      `1. **Sandbox templates** — Never pass user input directly to template engines (Jinja2, Twig, Freemarker, etc.).\n2. **Input validation** — Restrict template context variables to a strict allowlist of safe types.\n3. **Disable dangerous features** — Disable autoescaping bypass, raw blocks, and native Python/Java object access in templates.`,
      `1. **Use logic-less templates** — Prefer Mustache/Handlebars over Jinja2/Twig for user-controlled content.\n2. **Sandboxed rendering** — If template rendering is required, use a sandboxed environment with restricted builtins.\n3. **CSP** — Deploy strict Content-Security-Policy to limit the impact even if SSTI leads to XSS.`,
    ]));
  }

  if (tags.some(t => ["nosql", "nosql-injection", "mongodb"].includes(t))) {
    fixes.push(rng.pick([
      `1. **Input sanitization** — Strip MongoDB operators ($gt, $ne, $regex, etc.) from all user input.\n2. **Schema validation** — Use Mongoose/Joi schemas to enforce expected types (string, number) before querying.\n3. **Parameterized queries** — Use the MongoDB driver's built-in parameterization instead of building query objects from raw input.`,
      `1. **Type checking** — Ensure all query parameters are the expected type (e.g., string not object).\n2. **Disable $where** — Never use $where or mapReduce with user-controlled input.\n3. **Least privilege** — The database user should only have access to required collections with minimal permissions.`,
    ]));
  }

  if (tags.some(t => ["xxe", "xml"].includes(t))) {
    fixes.push(rng.pick([
      `1. **Disable DTD processing** — Set the XML parser to disallow Document Type Definitions entirely.\n2. **Disable external entities** — Configure XMLParser to reject external entity references (FEATURE_EXTERNAL_ENTITIES = false).\n3. **Use JSON** — Where possible, switch from XML to JSON for API communication to eliminate the XXE attack surface entirely.`,
      `1. **Secure parser configuration** — For Java: set XMLConstants.FEATURE_SECURE_PROCESSING. For Python: use defusedxml. For PHP: libxml_disable_entity_loader(true).\n2. **Input validation** — Reject XML documents containing DOCTYPE declarations.\n3. **WAF rules** — Deploy WAF rules to block XML payloads containing entity declarations as a defense-in-depth measure.`,
    ]));
  }

  if (tags.some(t => ["file-upload", "unrestricted-upload", "webshell"].includes(t))) {
    fixes.push(rng.pick([
      `1. **Content validation** — Validate file content (magic bytes), not just extension or MIME type.\n2. **Rename files** — Generate random filenames on upload, never use the client-provided name.\n3. **Separate storage** — Store uploads outside the webroot or on a separate domain/CDN with no script execution.\n4. **File type allowlist** — Only allow specific file types (e.g., .jpg, .png, .pdf) based on business requirements.`,
      `1. **Magic byte validation** — Check actual file content signatures, not just the Content-Type header.\n2. **No execution** — Configure the web server to never execute scripts in the upload directory (disable PHP, CGI, etc.).\n3. **Size limits** — Enforce maximum file size and rate limits on upload endpoints.\n4. **Antivirus scanning** — Scan uploaded files with ClamAV or similar before making them accessible.`,
    ]));
  }

  if (tags.some(t => ["kubernetes", "k8s", "container-escape", "docker"].includes(t))) {
    fixes.push(rng.pick([
      `1. **Pod Security Standards** — Enforce restricted or baseline pod security standards at the namespace level.\n2. **RBAC least privilege** — Review and restrict ServiceAccount permissions. Never use cluster-admin for application pods.\n3. **Network policies** — Implement NetworkPolicies to restrict pod-to-pod communication.\n4. **No privileged containers** — Never run containers with privileged: true or hostPID/hostNetwork.`,
      `1. **Read-only filesystem** — Set readOnlyRootFilesystem: true for all containers.\n2. **Drop capabilities** — Drop all capabilities and only add those explicitly needed.\n3. **Seccomp/AppArmor** — Apply seccomp profiles to restrict system calls.\n4. **Image scanning** — Scan all container images for vulnerabilities before deployment (Trivy, Grype).`,
    ]));
  }

  if (tags.some(t => ["deserialization", "insecure-deserialization"].includes(t))) {
    fixes.push(rng.pick([
      `1. **Never deserialize untrusted data** — Use safe data formats (JSON) instead of native serialization (pickle, Java serialization, PHP unserialize).\n2. **Integrity checks** — If deserialization is required, sign serialized data with HMAC to prevent tampering.\n3. **Allowlist classes** — Configure the deserializer to only allow specific, safe classes to be instantiated.`,
      `1. **Replace with JSON** — Migrate from native serialization to JSON or Protocol Buffers.\n2. **Look-ahead deserialization** — Use ObjectInputStream filters (Java 9+) to restrict which classes can be deserialized.\n3. **Monitor** — Log all deserialization events and alert on unexpected class instantiation.`,
    ]));
  }

  // Default if no specific tags matched
  if (fixes.length === 0) {
    fixes.push(`1. **Input validation** — Validate all user-controlled input on the server side using strict allowlists.\n2. **Defense in depth** — Implement multiple layers of security controls rather than relying on a single mechanism.\n3. **Security testing** — Integrate automated security testing (SAST/DAST) into the CI/CD pipeline.\n4. **Monitoring** — Deploy comprehensive logging and alerting for security-relevant events.`);
  }

  return fixes.join("\n\n");
}

// Deep Analysis Generator (for padding turns)
export function generateDeepAnalysis(scenario: ScenarioTemplate, domain: string, profile: TargetProfile, rng: SeededRNG): string {
  const analyses = [
    `### Extended Analysis\n\nLooking deeper at the ${scenario.subcategory} finding on ${domain}:\n\n**Attack Surface Expansion:**\nThe ${profile.technologies.join("/")} application has ${rng.int(10, 50)} API endpoints, of which I've tested ${rng.int(5, 20)}. The vulnerability pattern I found likely extends to:\n- ${rng.pickN(profile.injectableParams, 3).map(p => `The '${p}' parameter on adjacent endpoints`).join("\n- ")}\n\nThis is because the vulnerable code is likely shared across multiple endpoints through ${rng.pick(["a common middleware function", "a shared data access layer", "a base controller class", "a utility function called from multiple routes"])}.\n\n**Detection Difficulty:**\nFrom a defender's perspective, this attack would be ${rng.pick(["difficult to detect because the requests appear as normal API usage", "moderately detectable through anomaly detection on request patterns", "visible in application logs but easily missed without specific monitoring rules", "nearly invisible without database query logging enabled"])}.\n\n**Recommended monitoring:**\n- ${rng.pick(["Monitor for unusual data access patterns (e.g., user A accessing user B's resources)", "Alert on high-volume API requests from a single session", "Log and monitor all failed authentication attempts with source IP correlation", "Implement database query logging and alert on unexpected SELECT/UPDATE patterns"])}`,

    `### Risk Assessment Deep Dive\n\nFor ${domain} (${profile.technologies.join("/")} / ${profile.databases.name}):\n\n**Quantified Risk:**\n- Affected users: approximately ${rng.int(1000, profile.userCount).toLocaleString()} based on database sampling\n- Data sensitivity: ${rng.pick(["PII (names, emails, addresses)", "Financial data (payment methods, transactions)", "Healthcare data (patient records)", "Authentication credentials (password hashes)"])}\n- Estimated remediation effort: ${rng.int(2, 40)} developer hours for the primary fix, ${rng.int(5, 80)} hours for comprehensive hardening\n\n**Compensating Controls (while fix is developed):**\n1. Deploy a WAF rule targeting the specific attack pattern: \`${rng.pick(["Block requests containing SQL metacharacters in the identified parameter", "Rate limit API requests to max 100/minute per authenticated user", "Add additional logging on the vulnerable endpoint", "Implement IP-based anomaly detection for the affected service"])}\`\n2. ${rng.pick(["Enable enhanced logging on the affected endpoints for incident response readiness", "Temporarily restrict the affected endpoint to internal IPs only if feasible", "Add an additional authorization check at the load balancer level", "Deploy a canary token in the database to detect unauthorized access"])}\n3. ${rng.pick(["Brief the SOC team on indicators of compromise for this specific vulnerability", "Review access logs for the past 90 days for signs of prior exploitation", "Implement real-time alerting on the affected database tables", "Add the vulnerability signature to the SIEM correlation rules"])}`,

    `### Alternative Attack Paths\n\nBeyond the primary ${scenario.subcategory} finding, I identified several related attack vectors on ${domain}:\n\n**Path 1: ${rng.pick(["API Version Downgrade", "Mobile API Bypass", "Internal API Exposure", "Debug Endpoint Abuse"])}**\n${rng.pick(["The v1 API endpoint appears to lack the security controls present in v2. An attacker could target the older version.", "The mobile API at /api/mobile/ may have reduced input validation compared to the web API.", "Internal API endpoints are accessible from the public network due to misconfigured routing.", "Debug endpoints are still active in the production deployment and expose sensitive configuration."])}\n\n**Path 2: ${rng.pick(["Session Handling Weakness", "CORS Exploitation", "Cache Poisoning", "Rate Limit Bypass"])}**\n${rng.pick(["Session tokens don't rotate after privilege changes, allowing session fixation attacks.", "The CORS configuration reflects arbitrary origins which could enable cross-origin data theft.", "Unkeyed headers in the CDN cache could be poisoned to serve malicious content to all users.", "Rate limiting can be bypassed by rotating source IPs or using concurrent requests."])}\n\n**Chaining potential:** Combining the primary finding with ${rng.pick(["the session handling weakness", "the CORS misconfiguration", "the exposed debug endpoint", "the API version downgrade"])} would escalate the impact from ${rng.pick(["data disclosure to account takeover", "single-user impact to application-wide compromise", "authenticated access to unauthenticated exploitation", "information disclosure to remote code execution"])}.`,

    `### Post-Exploitation Impact Assessment\n\nAssuming an attacker successfully exploits the ${scenario.subcategory} vulnerability on ${domain}:\n\n**Immediate capabilities:**\n${rng.pickN(["- Read all user records in the ${profile.databases.name} database (${rng.int(1000, profile.userCount).toLocaleString()} records)", "- Access administrative functions and modify application configuration", "- Exfiltrate API keys and internal service credentials from environment variables", "- Execute commands on the application server as the service user", "- Access internal network services reachable from the application server", "- Read application source code and identify additional vulnerabilities", "- Intercept other users' sessions and sensitive data in transit", "- Modify database records including user permissions and financial data"], rng.int(3, 5)).join("\n")}\n\n**Persistence mechanisms an attacker could establish:**\n${rng.pickN(["- Create a backdoor admin account in the application database", "- Plant a web shell in a static assets directory", "- Add an SSH key for remote access to the server", "- Modify a cron job to maintain callback access", "- Inject a persistent XSS payload that survives application updates", "- Create an API key with elevated privileges", "- Modify the application code to include a subtle backdoor"], rng.int(2, 4)).join("\n")}\n\n**Recommended incident response actions:**\n1. ${rng.pick(["Review access logs for the past 90 days for indicators of prior exploitation", "Scan the application files for unauthorized modifications or web shells", "Rotate all credentials that could have been exposed through this vulnerability", "Notify affected users if evidence of data access is found"])}`,
  ];

  return rng.pick(analyses);
}
