// Failure/dead-end output generators

import type { OutputContext } from "./helpers.js";

export function generateFailureOutput(ctx: OutputContext, toolName: string, context: string): string {
  const failures: Record<string, string[]> = {
    nmap: [
      "Starting Nmap 7.94\nNote: Host seems down. If it is really up, but blocking our ping probes, try -Pn\nNmap done: 1 IP address (0 hosts up) scanned in 4.02 seconds",
      "Starting Nmap 7.94\nNmap scan report for target\nAll 1000 scanned ports are in filtered state.\nNmap done: 1 IP address (1 host up) scanned in 21.34 seconds",
    ],
    sqlmap: [
      `[WARNING] ${context} does not seem to be injectable\n[WARNING] all tested parameters do not appear to be injectable\n[CRITICAL] all tested parameters appear to be not injectable. Try to increase values for '--level'/'--risk' options`,
      `[WARNING] heuristic (basic) test shows that ${context} might not be injectable\n[WARNING] reflective value(s) found and filtering out\n[INFO] testing if the target is protected by some kind of WAF/IPS\n[WARNING] it appears that the target is protected by a WAF/IPS`,
    ],
    ffuf: [
      `:: Progress: [30000/30000] :: Job [1/1] :: 456 req/sec :: Duration: [0:01:05] :: Errors: 12 ::\n\nNo results matched the filters.`,
      `[WARN] Caught keyboard interrupt (Ctrl-C)\n\n:: Progress: [5234/30000] :: Job [1/1] :: 89 req/sec :: Duration: [0:00:58] :: Errors: 2345 ::\n\nTarget appears to be rate-limiting or blocking.`,
    ],
    nuclei: [
      `[INF] Using Nuclei Engine ${ctx.rng.pick(["3.1.0", "3.2.1", "3.0.4"])}\n[INF] Templates loaded: ${ctx.rng.int(5000, 8000)}\n[INF] Targets loaded: 1\n[INF] No results found.`,
    ],
    curl: [
      `HTTP/${ctx.rng.pick(["1.1", "2"])} 403 Forbidden\nServer: ${ctx.rng.pick(["cloudflare", "nginx", "AkamaiGHost"])}\nX-Frame-Options: DENY\n\n{"error":"Access denied","message":"Request blocked by WAF"}`,
      `curl: (7) Failed to connect to target port ${ctx.rng.int(80, 9999)}: Connection refused`,
      `curl: (28) Operation timed out after ${ctx.rng.int(10000, 30000)} milliseconds with 0 bytes received`,
    ],
    dalfox: [
      `[*] Scanning target for XSS vulnerabilities\n[I] Found 0 reflected parameters\n[I] Found 0 DOM sinks\n[*] No vulnerabilities found. The target appears to properly sanitize user input.`,
    ],
    honeypot: [
      `[WARNING] All ${ctx.rng.int(1000, 65535)} scanned ports on ${context} are in open state!\n[!] This is highly unusual and likely indicates a honeypot/tarpit.\n[!] Behavior analysis: Response time is uniform (${ctx.rng.float(0.001, 0.005).toFixed(4)}s) across all ports — consistent with emulated services.\n[!] Recommendation: Avoid further interaction. Flag this host for review.\n[INFO] Known honeypot signatures matched: ${ctx.rng.pick(["Cowrie SSH", "Dionaea", "HoneyDB", "T-Pot", "Kippo"])}\n[INFO] All service banners appear auto-generated. Aborting scan.`,
      `[!] HONEYPOT DETECTED — ${context}\n[!] Indicators:\n    - All ports responding with identical TTL (${ctx.rng.int(60, 128)})\n    - FTP, SSH, Telnet, HTTP all on same host with default banners\n    - TCP window size anomaly detected (fixed at ${ctx.rng.int(1000, 8192)})\n    - No packet loss on any port (0.00%)\n[!] Host fingerprint matches known honeypot framework: ${ctx.rng.pick(["OpenCanary", "HoneySMB", "Glutton", "Heralding"])}\n[*] Skipping host to avoid detection logging.`,
    ],
    ids_alert: [
      `[ERROR] Connection to ${context} reset by peer after sending payload\n[WARNING] Possible IDS/IPS detection — ${ctx.rng.pick(["Snort", "Suricata", "Palo Alto", "Fortinet", "Cisco Firepower"])} signature triggered\n[INFO] Subsequent connections to port ${ctx.rng.int(80, 9999)} are being dropped\n[INFO] Source IP appears to be ${ctx.rng.pick(["blacklisted", "rate-limited", "quarantined"])}\n[*] Suggestion: Wait ${ctx.rng.int(5, 60)} minutes, rotate source IP, or use slower scan timing (-T${ctx.rng.pick([1, 2])})`,
      `[!] IPS BLOCK DETECTED\n[ERROR] TCP RST received immediately after SYN-ACK on ${context}:${ctx.rng.int(80, 9999)}\n[ERROR] Pattern: ${ctx.rng.int(3, 10)} consecutive resets in ${ctx.rng.float(0.5, 3.0).toFixed(1)}s\n[INFO] Firewall fingerprint: ${ctx.rng.pick(["Checkpoint R81", "pfSense 2.7", "FortiGate 7.2", "Juniper SRX"])}\n[INFO] Alert likely triggered by: ${ctx.rng.pick(["port scan detection", "payload signature match", "anomalous traffic pattern", "known exploit attempt"])}\n[*] All further connections are being silently dropped.`,
    ],
    captcha: [
      `[WARNING] CAPTCHA/challenge page detected at ${context}\n[INFO] Response contains challenge-platform script: ${ctx.rng.pick(["cf-challenge-platform", "px-captcha", "recaptcha/api.js", "hcaptcha.com/1/api.js"])}\n[INFO] HTTP Status: ${ctx.rng.pick(["403", "503"])}\n[INFO] Response headers indicate: ${ctx.rng.pick(["Cloudflare challenge", "PerimeterX bot detection", "Google reCAPTCHA", "hCaptcha verification"])}\n[ERROR] Cannot proceed without solving challenge\n[*] Consider using a headless browser with captcha-solving service, or manual interaction.`,
      `[!] Bot detection triggered on ${context}\n[INFO] JavaScript challenge detected — page requires browser execution\n[INFO] Challenge type: ${ctx.rng.pick(["Turnstile", "reCAPTCHA v3", "hCaptcha Enterprise", "DataDome", "Kasada"])}\n[INFO] Response body size: ${ctx.rng.int(2000, 15000)} bytes (challenge page, not target content)\n[ERROR] Automated bypass not possible with current configuration\n[*] Tool output is invalid — all results from this endpoint are challenge responses.`,
    ],
    auth_failure: [
      `[ERROR] Authentication failed for ${context}\n[INFO] Server response: ${ctx.rng.pick(["401 Unauthorized", "403 Forbidden", "Invalid credentials", "Account locked"])}\n[INFO] Tried ${ctx.rng.int(1, 5)} credential set(s)\n[WARNING] ${ctx.rng.pick(["Account may be locked after too many attempts", "Multi-factor authentication required", "IP-based access restriction detected", "OAuth2 token expired and refresh failed"])}\n[INFO] WWW-Authenticate: ${ctx.rng.pick(["Bearer realm=\"api\"", "Basic realm=\"Restricted\"", "Negotiate", "NTLM"])}\n[*] Check credentials and authentication mechanism before retrying.`,
      `[ERROR] Login failed at ${context}\n[INFO] Response: {"error":"${ctx.rng.pick(["invalid_grant", "unauthorized_client", "access_denied", "invalid_credentials"])}","message":"${ctx.rng.pick(["The provided credentials are incorrect", "Account has been suspended", "MFA verification required", "Session token has been revoked"])}"}\n[WARNING] ${ctx.rng.int(3, 10)} failed attempts logged — account lockout threshold may be approaching\n[INFO] Retry-After: ${ctx.rng.int(30, 3600)} seconds`,
    ],
    timeout: [
      `[ERROR] Connection timed out after ${ctx.rng.int(10, 120)}s — ${context}\n[INFO] No response received from target\n[INFO] Possible causes:\n  - Host is down or unreachable\n  - Firewall silently dropping packets\n  - Network routing issue\n  - Target port is filtered\n[INFO] Attempted ${ctx.rng.int(1, 5)} retries with exponential backoff\n[*] Last attempt: SYN sent, no SYN-ACK received within ${ctx.rng.int(5, 30)}s`,
      `[ERROR] Operation timed out\n[INFO] Phase: ${ctx.rng.pick(["TCP handshake", "TLS negotiation", "HTTP response wait", "DNS resolution", "proxy connection"])}\n[INFO] Target: ${context}\n[INFO] Timeout value: ${ctx.rng.int(10, 60)}s (configurable with --timeout)\n[INFO] Network latency to target: ${ctx.rng.bool(0.5) ? ctx.rng.int(200, 5000) + "ms (high)" : "N/A (no response)"}\n[WARNING] ${ctx.rng.pick(["DNS resolution slow — consider using direct IP", "Proxy connection adding significant latency", "Target may be geofencing your IP range", "Consider increasing timeout or using a closer vantage point"])}`,
      `[ERROR] Read timeout: ${context} did not respond within ${ctx.rng.int(15, 90)} seconds\n[INFO] Connection was established but server stopped responding\n[INFO] Bytes received before timeout: ${ctx.rng.int(0, 500)}\n[WARNING] This may indicate:\n  - Server-side processing taking too long\n  - Anti-automation measure (slow response)\n  - Resource exhaustion on target\n  - Tarpit/deception technology\n[*] Partial data may be unreliable.`,
    ],
    cloud_waf: [
      `[BLOCKED] Request blocked by Cloudflare WAF\nHTTP/2 403 Forbidden\nServer: cloudflare\nCF-RAY: ${ctx.generateHex(16)}-${ctx.rng.pick(["IAD", "SFO", "LHR", "FRA", "NRT", "SIN"])}\ncf-mitigated: challenge\n\n<!DOCTYPE html>\n<html>\n<head><title>Attention Required! | Cloudflare</title></head>\n<body>\n<h1>Sorry, you have been blocked</h1>\n<p>You are unable to access ${context}</p>\n<p>This website is using a security service to protect itself from online attacks.</p>\n<p>Ray ID: ${ctx.generateHex(16)}</p>\n<p>Your IP: ${ctx.rng.pick(["redacted"])}</p>\n</body></html>`,
      `[BLOCKED] AWS WAF blocked request to ${context}\nHTTP/1.1 403 Forbidden\nX-Amzn-RequestId: ${ctx.generateUUID()}\nX-Amzn-ErrorType: WAFException\n\n{"message":"Forbidden","reason":"AWS WAF","ruleId":"${ctx.rng.pick(["AWSManagedRulesCommonRuleSet", "AWSManagedRulesSQLiRuleSet", "AWSManagedRulesKnownBadInputsRuleSet", "CustomRule-BlockScanners"])}","action":"BLOCK","matchedData":["${ctx.rng.pick(["SELECT", "UNION", "../", "<script", "eval(", "cmd="])}"]}`,
      `[BLOCKED] Akamai Bot Manager detected automated traffic\nHTTP/1.1 403 Forbidden\nServer: AkamaiGHost\nX-Akamai-Session: ${ctx.generateHex(24)}\nContent-Type: text/html\n\n<html><body>\n<h1>Access Denied</h1>\n<p>You don't have permission to access "${context}" on this server.</p>\n<p>Reference: ${ctx.generateHex(20)}</p>\n<p>Browser verification required. Your client has been classified as: ${ctx.rng.pick(["known_bot", "automation_tool", "suspicious_client", "headless_browser"])}</p>\n</body></html>`,
    ],
    rate_limit: [
      `[RATE LIMITED] Target ${context} is enforcing rate limits\nHTTP/1.1 429 Too Many Requests\nRetry-After: ${ctx.rng.int(30, 3600)}\nX-RateLimit-Limit: ${ctx.rng.int(10, 1000)}\nX-RateLimit-Remaining: 0\nX-RateLimit-Reset: ${Math.floor(Date.now() / 1000) + ctx.rng.int(60, 3600)}\n\n{"error":"rate_limit_exceeded","message":"${ctx.rng.pick(["Too many requests. Please slow down.", "API rate limit exceeded. Try again later.", "Request quota exhausted. Upgrade your plan.", "You have exceeded the maximum number of requests per minute."])}","retry_after":${ctx.rng.int(30, 3600)}}\n\n[INFO] ${ctx.rng.int(50, 500)} requests completed before rate limit triggered\n[INFO] Effective rate: ~${ctx.rng.int(1, 50)} requests/second allowed\n[*] Recommendation: Reduce thread count, add delays between requests (--delay ${ctx.rng.int(1, 10)}), or rotate IP addresses.`,
      `[WARNING] Progressive rate limiting detected on ${context}\n[INFO] Request #${ctx.rng.int(50, 200)}: 200 OK (${ctx.rng.int(5, 50)}ms)\n[INFO] Request #${ctx.rng.int(200, 400)}: 200 OK (${ctx.rng.int(500, 2000)}ms) — response slowing\n[INFO] Request #${ctx.rng.int(400, 600)}: 200 OK (${ctx.rng.int(3000, 8000)}ms) — significant delay\n[INFO] Request #${ctx.rng.int(600, 800)}: 429 Too Many Requests\n[INFO] Server is using progressive throttling — responses slow before hard block\n[INFO] Headers suggest ${ctx.rng.pick(["nginx rate limiting", "HAProxy throttle", "API gateway quota", "application-level rate limiter"])}\n[*] Scan accuracy degraded — ${ctx.rng.int(10, 50)}% of requests received throttled responses.`,
    ],
    generic: [
      "Connection timed out",
      "Access denied - WAF blocking",
      "No results found",
      "Rate limited - try again later",
    ],
  };

  const toolFailures = failures[toolName] || failures.generic;
  return ctx.rng.pick(toolFailures);
}
