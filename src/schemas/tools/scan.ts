import type { ToolDefinition } from "./types.js";

export const SCAN_TOOLS: ToolDefinition[] = [
{
    name: "nuclei",
    description: "Fast vulnerability scanner powered by community-maintained templates covering CVEs, misconfigs, exposures, and more.",
    category: "scanning",
    parameters: {
      target: { type: "string", description: "Target URL or list (-u / -l)", required: true, examples: ["-u https://target.com", "-l alive_hosts.txt"] },
      templates: { type: "string", description: "Template selection", required: false, examples: ["-t cves/", "-t vulnerabilities/", "-tags sqli,xss,ssrf", "-severity critical,high"] },
      flags: { type: "string", description: "Additional flags", required: false, examples: ["-c 50", "-rl 150", "-headless", "-system-resolvers", "--proxy http://127.0.0.1:8080"] },
      output: { type: "string", description: "Output options", required: false, examples: ["-o nuclei_results.txt", "-j -o nuclei.json", "-me nuclei_output/"] },
    },
    example_commands: [
      "nuclei -l alive_hosts.txt -severity critical,high -o critical_vulns.txt",
      "nuclei -u https://target.com -t cves/ -t vulnerabilities/ -c 50",
      "nuclei -u https://target.com -tags sqli,xss,ssrf,rce -severity critical,high,medium",
      "nuclei -l targets.txt -t exposures/ -t misconfigurations/ -o exposed.txt",
      "nuclei -u https://target.com -headless -t headless/ -c 10",
    ],
    typical_output: `[CVE-2021-44228] [critical] [http] https://target.com/api/log4j
[git-config] [medium] [http] https://target.com/.git/config
[apache-status] [info] [http] https://target.com/server-status
[open-redirect] [medium] [http] https://target.com/redirect?url=
[cors-misconfig] [high] [http] https://api.target.com/v1/users
[jwt-none-algorithm] [high] [http] https://api.target.com/auth`,
  },
{
    name: "nikto",
    description: "Comprehensive web server scanner that tests for dangerous files, outdated software, and server misconfigurations.",
    category: "scanning",
    parameters: {
      host: { type: "string", description: "Target host (-h)", required: true, examples: ["-h https://target.com", "-h 10.10.10.1"] },
      flags: { type: "string", description: "Additional flags", required: false, examples: ["-p 80,443,8080", "-Tuning 123", "-ssl", "-Plugins @@ALL", "-evasion 1"] },
      output: { type: "string", description: "Output options", required: false, examples: ["-o nikto_scan.html -Format html", "-o nikto.csv -Format csv"] },
    },
    example_commands: [
      "nikto -h https://target.com -o nikto_results.html -Format html",
      "nikto -h 10.10.10.1 -p 80,443,8080 -ssl -Plugins @@ALL",
    ],
    typical_output: `+ Server: Apache/2.4.52
+ /: The X-Content-Type-Options header is not set.
+ /admin/: Directory indexing found.
+ /backup/: Backup directory found.
+ /phpinfo.php: PHP info file found.
+ /server-status: Apache server-status accessible.
+ OSVDB-3233: /icons/README: Apache default file found.`,
  },
{
    name: "wfuzz",
    description: "Web application fuzzer for brute-forcing parameters, directories, headers, cookies, POST data, and more.",
    category: "scanning",
    parameters: {
      url: { type: "string", description: "Target URL with FUZZ keyword", required: true, examples: ["https://target.com/FUZZ", "https://target.com/api?id=FUZZ"] },
      wordlist: { type: "string", description: "Wordlist (-z)", required: true, examples: ["-z file,/usr/share/seclists/Discovery/Web-Content/common.txt", "-z range,1-1000"] },
      flags: { type: "string", description: "Additional flags", required: false, examples: ["--hc 404", "--hl 0", "--hw 12", "-H 'Cookie: session=abc'", "-d 'user=FUZZ'", "-t 50"] },
    },
    example_commands: [
      "wfuzz -z file,/usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt --hc 404 https://target.com/page?file=FUZZ",
      "wfuzz -z range,1-10000 --hc 404 https://target.com/api/users/FUZZ",
      "wfuzz -z file,/usr/share/seclists/Fuzzing/SQLi/Generic-SQLi.txt --hc 404 'https://target.com/search?q=FUZZ'",
    ],
    typical_output: `ID    Response   Lines    Word     Chars    Payload
00001:  C=200     97 L     325 W    4532 Ch   "admin"
00045:  C=200     12 L      43 W     893 Ch   "../../etc/passwd"
00123:  C=500     0  L       0 W       0 Ch   "' OR 1=1--"`,
  },
  {
    name: "trufflehog",
    description: "Secret detection tool that scans git repositories, filesystems, and S3 buckets for leaked API keys, passwords, and other credentials.",
    category: "scanning",
    parameters: {
      source: { type: "string", description: "Source to scan", required: true, examples: ["git https://github.com/org/repo.git", "filesystem /path/to/code", "s3 --bucket=mybucket", "github --org=targetorg"] },
      flags: { type: "string", description: "Additional flags", required: false, examples: ["--only-verified", "--json", "--concurrency 10", "--include-detectors all", "--entropy", "--regex"] },
      output: { type: "string", description: "Output options", required: false, examples: ["--json > secrets.json", "2>&1 | tee trufflehog_output.txt"] },
    },
    example_commands: [
      "trufflehog git https://github.com/org/repo.git --only-verified --json > secrets.json",
      "trufflehog filesystem /path/to/code --only-verified --concurrency 10",
      "trufflehog github --org=targetorg --only-verified --json",
      "trufflehog s3 --bucket=target-bucket --only-verified",
    ],
    typical_output: `Found verified result
Detector Type: AWS
Decoder Type: PLAIN
Raw result: AKIAIOSFODNN7EXAMPLE
Commit: a]f3c21d
Email: dev@target.com
File: config/settings.py
Line: 42
Repository: https://github.com/org/repo.git

Found verified result
Detector Type: Slack
Decoder Type: PLAIN
Raw result: xoxb-REDACTED-EXAMPLE-TOKEN
File: src/notifications.js
Line: 18

Found verified result
Detector Type: GitHub
Decoder Type: PLAIN
Raw result: ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
File: .env.example
Line: 5`,
  },
  {
    name: "semgrep",
    description: "Lightweight static analysis tool for finding security vulnerabilities, bugs, and enforcing code patterns across 30+ programming languages.",
    category: "scanning",
    parameters: {
      target: { type: "string", description: "Target directory or file", required: true, examples: [".", "/path/to/code", "src/"] },
      config: { type: "string", description: "Rule configuration (--config)", required: false, examples: ["--config auto", "--config p/owasp-top-ten", "--config p/sql-injection", "--config p/xss", "--config r/python.lang.security"] },
      flags: { type: "string", description: "Additional flags", required: false, examples: ["--severity ERROR", "--json", "--verbose", "--exclude tests/", "--include '*.py'", "--autofix", "--metrics off"] },
      output: { type: "string", description: "Output options", required: false, examples: ["-o semgrep_results.json --json", "-o results.sarif --sarif"] },
    },
    example_commands: [
      "semgrep --config auto --severity ERROR /path/to/code -o semgrep_results.json --json",
      "semgrep --config p/owasp-top-ten src/ --exclude tests/",
      "semgrep --config p/sql-injection --config p/xss . --json -o vulns.json",
      "semgrep --config auto . --severity WARNING --include '*.py' --metrics off",
    ],
    typical_output: `Scanning 142 files with 423 rules...

  src/controllers/user.py
    security.sql-injection
      SQL injection vulnerability: user input concatenated in query
      15: query = "SELECT * FROM users WHERE id = " + request.args.get("id")

  src/views/profile.py
    security.xss.reflected-xss
      Reflected XSS: user input rendered without escaping
      42: return "<h1>Welcome " + username + "</h1>"

  src/auth/login.py
    security.hardcoded-credentials
      Hardcoded password found in source code
      8: DB_PASSWORD = "supersecret123"

  Findings: 12 (3 critical, 5 high, 4 medium)`,
  },
  {
    name: "crlfuzz",
    description: "Fast CRLF injection vulnerability scanner that tests for HTTP response splitting via header injection.",
    category: "scanning",
    parameters: {
      target: { type: "string", description: "Target URL or list (-u / -l)", required: true, examples: ["-u https://target.com", "-l urls.txt"] },
      flags: { type: "string", description: "Additional flags", required: false, examples: ["-s", "-c 50", "-H 'Cookie: session=abc'", "-x http://127.0.0.1:8080", "-V"] },
      output: { type: "string", description: "Output file (-o)", required: false, examples: ["-o crlf_results.txt"] },
    },
    example_commands: [
      "crlfuzz -u https://target.com -o crlf_results.txt",
      "crlfuzz -l urls.txt -c 50 -s -o vulnerable.txt",
      "cat alive_hosts.txt | crlfuzz -c 25 -s -o crlf_vulns.txt",
    ],
    typical_output: `
   _____ ____  _     _____
  / ____|  _ \\| |   |  ___|   _ _________
 | |    | |_) | |   | |_ | | | |_  /_  /
 | |    |  _ <| |   |  _|| |_| |/ / / /
 | |____|_| \\_\\_|___|_|   \\__,_/___/___|

[VLN] [CRLFi] https://target.com/%0d%0aSet-Cookie:crlfuzz=true
[VLN] [CRLFi] https://target.com/redirect?url=%0d%0aInjected-Header:true
[VLN] [CRLFi] https://target.com/api/callback%0d%0aX-Injected:yes`,
  },
  {
    name: "corsy",
    description: "CORS (Cross-Origin Resource Sharing) misconfiguration scanner that tests for various CORS bypass techniques.",
    category: "scanning",
    parameters: {
      target: { type: "string", description: "Target URL or file (-u / -i)", required: true, examples: ["-u https://target.com", "-i urls.txt"] },
      flags: { type: "string", description: "Additional flags", required: false, examples: ["-t 20", "-d 2", "--headers 'Cookie: session=abc'"] },
      output: { type: "string", description: "Output file (-o)", required: false, examples: ["-o cors_results.json"] },
    },
    example_commands: [
      "python3 corsy.py -u https://target.com",
      "python3 corsy.py -i urls.txt -t 20 -o cors_results.json",
      "python3 corsy.py -u https://api.target.com --headers 'Authorization: Bearer token123'",
    ],
    typical_output: `[target.com] URL: https://target.com/api/v1/users
  [CRITICAL] Arbitrary origin reflected
    Origin: https://evil.com => Access-Control-Allow-Origin: https://evil.com
    Access-Control-Allow-Credentials: true

[target.com] URL: https://target.com/api/v1/data
  [HIGH] Null origin allowed
    Origin: null => Access-Control-Allow-Origin: null
    Access-Control-Allow-Credentials: true

[target.com] URL: https://target.com/api/v1/config
  [MEDIUM] Prefix match
    Origin: https://target.com.evil.com => Access-Control-Allow-Origin: https://target.com.evil.com`,
  },
  {
    name: "secretfinder",
    description: "Python tool to discover sensitive data like API keys, tokens, and credentials in JavaScript files using regex patterns.",
    category: "scanning",
    parameters: {
      input: { type: "string", description: "Input URL or file (-i)", required: true, examples: ["-i https://target.com/assets/js/app.js", "-i /path/to/file.js"] },
      output: { type: "string", description: "Output format (-o)", required: false, examples: ["-o cli", "-o results.html"] },
      flags: { type: "string", description: "Additional flags", required: false, examples: ["-e", "--cookies 'session=abc'", "--headers 'Authorization: Bearer token'", "-r"] },
      regex: { type: "string", description: "Custom regex pattern (-g)", required: false, examples: ["-g 'AIza[0-9A-Za-z-_]{35}'", "-g 'api[_-]?key'"] },
    },
    example_commands: [
      "secretfinder -i https://target.com/assets/js/app.js -o cli",
      "secretfinder -i https://target.com -e -o results.html",
      "cat jsfiles.txt | while read url; do secretfinder -i $url -o cli; done",
    ],
    typical_output: `Results for: https://target.com/assets/js/app.js

[Google API Key] AIzaSyD-xxxxxxxxxxxxxxxxxxxxxxxxxxxx
[AWS Access Key] AKIAIOSFODNN7EXAMPLE
[Authorization Bearer] Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
[Slack Webhook] https://hooks.example.com/services/TXXXXX/BXXXXX/REDACTED
[Private Key] -----BEGIN RSA PRIVATE KEY-----
[API Endpoint] /api/v1/internal/admin/users
[Firebase URL] https://project-name.firebaseio.com`,
  },
  {
    name: "testssl",
    description: "Command-line tool for testing SSL/TLS services for supported ciphers, protocols, vulnerabilities (Heartbleed, POODLE, etc.), and certificate issues.",
    category: "scanning",
    parameters: {
      target: { type: "string", description: "Target host:port", required: true, examples: ["target.com", "target.com:443", "10.10.10.1:8443"] },
      flags: { type: "string", description: "Additional flags", required: false, examples: ["-U", "-S", "-P", "-E", "--fast", "--sneaky", "--ip one", "--vulnerable", "--headers"] },
      output: { type: "string", description: "Output options", required: false, examples: ["--jsonfile results.json", "--htmlfile results.html", "--csvfile results.csv", "--logfile results.log"] },
      checks: { type: "string", description: "Specific checks to run", required: false, examples: ["--heartbleed", "--poodle", "--robot", "--breach", "--crime", "--lucky13"] },
    },
    example_commands: [
      "testssl --vulnerable --headers target.com",
      "testssl -U --fast target.com:443 --jsonfile ssl_results.json",
      "testssl -S -P -E target.com --htmlfile ssl_report.html",
      "testssl --heartbleed --poodle --robot --breach target.com",
    ],
    typical_output: `Testing protocols via sockets

 SSLv2      not offered (OK)
 SSLv3      not offered (OK)
 TLS 1      offered (deprecated)
 TLS 1.1    offered (deprecated)
 TLS 1.2    offered (OK)
 TLS 1.3    offered (OK)

Testing vulnerabilities

 Heartbleed (CVE-2014-0160)        not vulnerable (OK)
 CCS (CVE-2014-0224)               not vulnerable (OK)
 Ticketbleed (CVE-2016-9244)       not vulnerable (OK)
 ROBOT                             not vulnerable (OK)
 POODLE, SSL (CVE-2014-3566)       not vulnerable (OK)
 BEAST (CVE-2011-3389)             TLS1: ECDHE-RSA-AES128-SHA -- vulnerable
 BREACH (CVE-2013-3587)            potentially NOT ok (uses gzip)

 Certificate Validity (UTC)        expires in 45 days
 Certificate Fingerprint SHA256    abc123def456...`,
  },
];
