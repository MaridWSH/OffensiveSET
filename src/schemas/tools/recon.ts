import type { ToolDefinition } from "./types.js";

export const RECON_TOOLS: ToolDefinition[] = [
{
    name: "nmap",
    description: "Network exploration and security auditing tool. Discovers hosts, services, OS, and vulnerabilities on target networks.",
    category: "recon",
    parameters: {
      target: { type: "string", description: "Target IP, hostname, or CIDR range", required: true, examples: ["192.168.1.0/24", "target.com", "10.10.10.1"] },
      ports: { type: "string", description: "Port specification (-p)", required: false, examples: ["-p 80,443", "-p-", "-p 1-65535", "--top-ports 1000"] },
      scan_type: { type: "string", description: "Scan technique", required: false, examples: ["-sS", "-sT", "-sV", "-sC", "-A", "-sU"] },
      scripts: { type: "string", description: "NSE scripts to run", required: false, examples: ["--script=vuln", "--script=http-enum", "--script=ssl-heartbleed"] },
      output: { type: "string", description: "Output format", required: false, examples: ["-oN scan.txt", "-oX scan.xml", "-oG scan.gnmap", "-oA full_scan"] },
      flags: { type: "string", description: "Additional flags", required: false, examples: ["-Pn", "-T4", "--min-rate 1000", "-v", "--reason"] },
    },
    example_commands: [
      "nmap -sS -sV -sC -T4 -p- target.com -oA full_scan",
      "nmap -sV --script=vuln -p 80,443,8080 10.10.10.1",
      "nmap -sU -sV --top-ports 100 192.168.1.0/24",
      "nmap -A -T4 --min-rate 5000 -p- target.com",
      "nmap --script=http-enum,http-headers -p 80,443 target.com",
    ],
    typical_output: `Starting Nmap 7.94 ( https://nmap.org )
Nmap scan report for target.com (10.10.10.1)
Host is up (0.034s latency).

PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.9p1
80/tcp   open  http     Apache httpd 2.4.52
443/tcp  open  ssl/http nginx 1.18.0
3306/tcp open  mysql    MySQL 8.0.28
8080/tcp open  http     Apache Tomcat 9.0.65`,
  },
{
    name: "subfinder",
    description: "Fast passive subdomain discovery tool using multiple sources (APIs, search engines, certificates).",
    category: "recon",
    parameters: {
      domain: { type: "string", description: "Target domain", required: true, examples: ["target.com", "example.org"] },
      output: { type: "string", description: "Output file", required: false, examples: ["-o subdomains.txt"] },
      sources: { type: "string", description: "Specific sources to use", required: false, examples: ["-s crtsh,virustotal,shodan"] },
      recursive: { type: "boolean", description: "Enable recursive subdomain discovery", required: false, default: false },
      flags: { type: "string", description: "Additional flags", required: false, examples: ["-silent", "-all", "-nW"] },
    },
    example_commands: [
      "subfinder -d target.com -all -o subdomains.txt",
      "subfinder -d target.com -silent | httpx -silent -status-code",
      "subfinder -d target.com -recursive -o deep_subs.txt",
    ],
    typical_output: `api.target.com
admin.target.com
dev.target.com
staging.target.com
mail.target.com
vpn.target.com
cdn.target.com
internal.target.com`,
  },
{
    name: "amass",
    description: "In-depth attack surface mapping and asset discovery using OSINT techniques.",
    category: "recon",
    parameters: {
      mode: { type: "string", description: "Amass subcommand", required: true, examples: ["enum", "intel", "viz", "track", "db"] },
      domain: { type: "string", description: "Target domain (-d)", required: true, examples: ["target.com"] },
      flags: { type: "string", description: "Additional flags", required: false, examples: ["-passive", "-active", "-brute", "-ip", "-src"] },
      output: { type: "string", description: "Output options", required: false, examples: ["-o amass_results.txt", "-json amass.json", "-dir amass_output/"] },
    },
    example_commands: [
      "amass enum -passive -d target.com -o passive_subs.txt",
      "amass enum -active -brute -d target.com -ip -src -o full_enum.txt",
      "amass intel -whois -d target.com",
    ],
    typical_output: `target.com (FQDN) --> a_record --> 93.184.216.34
api.target.com (FQDN) --> a_record --> 93.184.216.35
admin.target.com (FQDN) --> cname_record --> admin-lb.target.com
dev.target.com (FQDN) --> a_record --> 10.0.1.50`,
  },
{
    name: "httpx",
    description: "Fast HTTP toolkit for probing, technology detection, and response analysis across multiple hosts.",
    category: "recon",
    parameters: {
      input: { type: "string", description: "Input target or list", required: true, examples: ["-l subdomains.txt", "-u https://target.com"] },
      probes: { type: "string", description: "Information to extract", required: false, examples: ["-status-code", "-title", "-tech-detect", "-content-length", "-web-server", "-follow-redirects"] },
      output: { type: "string", description: "Output file", required: false, examples: ["-o alive.txt", "-json -o results.json"] },
      flags: { type: "string", description: "Additional flags", required: false, examples: ["-silent", "-threads 50", "-mc 200,301,302,403"] },
    },
    example_commands: [
      "cat subdomains.txt | httpx -silent -status-code -title -tech-detect -o alive.txt",
      "httpx -l targets.txt -status-code -content-length -web-server -follow-redirects",
      "echo target.com | httpx -ports 80,443,8080,8443 -status-code",
    ],
    typical_output: `https://target.com [200] [Target Corp - Home] [nginx/1.18.0] [PHP,WordPress]
https://api.target.com [200] [API Documentation] [nginx/1.18.0] [Node.js,Express]
https://admin.target.com [302] [] [Apache/2.4.52] [PHP,Laravel]
https://dev.target.com [403] [403 Forbidden] [nginx/1.18.0] []`,
  },
{
    name: "rustscan",
    description: "Ultra-fast port scanner written in Rust that scans all 65535 ports in seconds and automatically pipes results to nmap for service detection.",
    category: "recon",
    parameters: {
      target: { type: "string", description: "Target IP or hostname (-a)", required: true, examples: ["-a 10.10.10.1", "-a target.com", "-a 192.168.1.0/24"] },
      ports: { type: "string", description: "Port specification (-p)", required: false, examples: ["-p 80,443,8080", "-p 1-65535", "--range 1-10000"] },
      flags: { type: "string", description: "Additional flags", required: false, examples: ["-b 4500", "-t 3000", "--ulimit 5000", "--tries 2", "--accessible"] },
      nmap_args: { type: "string", description: "Arguments to pass to nmap (after --)", required: false, examples: ["-- -sV -sC", "-- -A -T4", "-- --script=vuln"] },
    },
    example_commands: [
      "rustscan -a 10.10.10.1 -b 4500 --ulimit 5000 -- -sV -sC",
      "rustscan -a target.com -p 80,443,8080 -- -A -T4",
      "rustscan -a 10.10.10.1 --range 1-65535 -b 4500 -- --script=vuln",
    ],
    typical_output: `.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__  {_   _}{ {__  /  ___} / {} \\ |  \`| |
| .-. \\| {_} |.-._} } | |  .-._} }\\     }/  /\\  \\| |\\  |
\`-' \`-'\`-----'\`----'  \`-'  \`----'  \`---' \`-'  \`-'\`-' \`-'

Open 10.10.10.1:22
Open 10.10.10.1:80
Open 10.10.10.1:443
Open 10.10.10.1:3306
Open 10.10.10.1:8080
[~] Starting Script(s)
[~] Starting Nmap 7.94 ( https://nmap.org )

PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.9p1
80/tcp   open  http     Apache httpd 2.4.52
443/tcp  open  ssl/http nginx 1.18.0
3306/tcp open  mysql    MySQL 8.0.28
8080/tcp open  http     Apache Tomcat 9.0.65`,
  },
  {
    name: "puredns",
    description: "Fast mass DNS resolution and subdomain bruteforcing tool with wildcard detection and accurate results.",
    category: "recon",
    parameters: {
      mode: { type: "string", description: "Operation mode", required: true, examples: ["bruteforce", "resolve"] },
      input: { type: "string", description: "Domain or input file", required: true, examples: ["target.com", "subdomains.txt"] },
      wordlist: { type: "string", description: "Wordlist for bruteforce", required: false, examples: ["/usr/share/seclists/Discovery/DNS/dns-Jhaddix.txt", "/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt"] },
      resolvers: { type: "string", description: "Resolvers file (-r)", required: false, examples: ["-r resolvers.txt", "-r /opt/resolvers/trusted.txt"] },
      flags: { type: "string", description: "Additional flags", required: false, examples: ["-q", "--wildcard-tests 10", "--bin massdns", "-l 1000", "--write-wildcards wildcards.txt"] },
    },
    example_commands: [
      "puredns bruteforce /usr/share/seclists/Discovery/DNS/dns-Jhaddix.txt target.com -r resolvers.txt -q",
      "puredns resolve subdomains.txt -r resolvers.txt --write resolved.txt",
      "puredns bruteforce /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt target.com -r resolvers.txt --wildcard-tests 10",
    ],
    typical_output: `api.target.com
admin.target.com
dev.target.com
staging.target.com
internal.target.com
vpn.target.com
mail.target.com
cdn.target.com
test.target.com
beta.target.com`,
  },
  {
    name: "dnsx",
    description: "Fast and multi-purpose DNS toolkit for running multiple DNS queries, mass resolution, and DNS-based recon.",
    category: "recon",
    parameters: {
      input: { type: "string", description: "Input list or domain (-l / -d)", required: true, examples: ["-l subdomains.txt", "-d target.com"] },
      query_type: { type: "string", description: "DNS record types to query", required: false, examples: ["-a", "-aaaa", "-cname", "-mx", "-ns", "-txt", "-soa", "-any", "-resp"] },
      flags: { type: "string", description: "Additional flags", required: false, examples: ["-silent", "-resp", "-cdn", "-asn", "-json", "-retry 3", "-t 100", "-rc noerror"] },
      output: { type: "string", description: "Output file (-o)", required: false, examples: ["-o dns_results.txt", "-json -o dns.json"] },
    },
    example_commands: [
      "cat subdomains.txt | dnsx -silent -a -resp -cdn -o dns_resolved.txt",
      "dnsx -l subdomains.txt -a -aaaa -cname -resp -json -o dns.json",
      "subfinder -d target.com -silent | dnsx -silent -a -resp -asn",
      "echo target.com | dnsx -silent -txt -mx -ns -resp",
    ],
    typical_output: `api.target.com [A] [93.184.216.35] [Cloudflare]
admin.target.com [A] [93.184.216.36]
dev.target.com [CNAME] [dev-lb.target.com]
mail.target.com [A] [93.184.216.40]
target.com [MX] [mail.target.com]
target.com [NS] [ns1.target.com]
target.com [TXT] [v=spf1 include:_spf.google.com ~all]`,
  },
  // --- SCANNING ---
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
  // --- EXPLOITATION ---
  {
    name: "caido",
    description: "Modern lightweight web security testing tool and proxy, serving as a Burp Suite alternative with built-in replay, automate, and HTTPQL features.",
    category: "exploitation",
    parameters: {
      listen: { type: "string", description: "Proxy listen address and port", required: false, default: "127.0.0.1:8080", examples: ["--listen 127.0.0.1:8080", "--listen 0.0.0.0:9090"] },
      flags: { type: "string", description: "Additional flags", required: false, examples: ["--no-open", "--data-path /path/to/data", "--upstream-proxy http://127.0.0.1:9090"] },
      project: { type: "string", description: "Project file to load", required: false, examples: ["--project target_assessment"] },
    },
    example_commands: [
      "caido --listen 127.0.0.1:8080 --no-open",
      "caido --listen 127.0.0.1:8080 --project target_pentest",
      "caido --listen 0.0.0.0:9090 --upstream-proxy http://127.0.0.1:8081",
    ],
    typical_output: `Caido v0.35.0 is running
Dashboard: http://localhost:8080
Proxy listening on: 127.0.0.1:8080

[INFO] Intercepted: GET https://target.com/ -> 200 OK (4532 bytes)
[INFO] Intercepted: POST https://target.com/api/login -> 200 OK (342 bytes)
[INFO] Intercepted: GET https://target.com/api/v1/users -> 200 OK (8923 bytes)
[INFO] Intercepted: GET https://target.com/admin -> 302 Found -> /admin/login`,
  },
  {
    name: "interactsh",
    description: "Out-of-band (OOB) interaction gathering tool for detecting blind vulnerabilities like SSRF, XXE, RCE, and blind SQL injection. Companion tool to nuclei.",
    category: "exploitation",
    parameters: {
      flags: { type: "string", description: "Client flags", required: false, examples: ["-n 1", "-t 60", "-json", "-v", "-poll-interval 5", "-sf interactions.txt"] },
      server: { type: "string", description: "Self-hosted server URL (-s)", required: false, examples: ["-s https://interact.sh", "-s https://oast.live"] },
      token: { type: "string", description: "Authentication token (-token)", required: false, examples: ["-token abc123"] },
      output: { type: "string", description: "Output options (-o)", required: false, examples: ["-o interactions.txt", "-json -o interactions.json"] },
    },
    example_commands: [
      "interactsh-client -n 1 -json -o interactions.json",
      "interactsh-client -v -poll-interval 5 -sf interactions.txt",
      "interactsh-client -s https://interact.sh -json",
    ],
    typical_output: `[INF] Listing 1 payload for OOB Testing
[INF] abc123def456.interact.sh

---

[DNS] Received DNS interaction (A) from 93.184.216.34 at 2024-01-15 14:32:21
  Query: abc123def456.interact.sh

[HTTP] Received HTTP interaction from 93.184.216.34 at 2024-01-15 14:32:22
  GET / HTTP/1.1
  Host: abc123def456.interact.sh
  User-Agent: Java/11.0.14

[DNS] Received DNS interaction (A) from 10.10.10.1 at 2024-01-15 14:33:05
  Query: sqli-test.abc123def456.interact.sh`,
  },
  {
    name: "nosqlmap",
    description: "Automated NoSQL injection detection and exploitation tool supporting MongoDB, CouchDB, and other NoSQL databases.",
    category: "exploitation",
    parameters: {
      target: { type: "string", description: "Target URL (-u)", required: true, examples: ["-u https://target.com/api/login", "-u https://target.com/search"] },
      attack: { type: "string", description: "Attack type (-a)", required: false, examples: ["-a 1", "-a 2", "-a 3"] },
      flags: { type: "string", description: "Additional flags", required: false, examples: ["--method POST", "--data '{\"username\":\"admin\",\"password\":\"test\"}'", "--headers '{\"Content-Type\":\"application/json\"}'", "--depth 5", "-dbPort 27017"] },
      db: { type: "string", description: "Database platform", required: false, examples: ["--platform MongoDB", "--platform CouchDB"] },
    },
    example_commands: [
      "nosqlmap -u https://target.com/api/login --method POST --data '{\"username\":\"admin\",\"password\":\"test\"}' --headers '{\"Content-Type\":\"application/json\"}'",
      "nosqlmap -u https://target.com/search?q=test --platform MongoDB",
      "nosqlmap -u http://10.10.10.1:27017 -a 2 --platform MongoDB --depth 5",
    ],
    typical_output: `[+] Checking for GET parameter injection...
[+] Testing parameter: username
[+] NoSQL injection detected!
    Type: Authentication bypass
    Payload: {"username": {"$gt": ""}, "password": {"$gt": ""}}
    Response: 200 OK - Login successful

[+] Enumerating databases...
    [*] admin
    [*] config
    [*] local
    [*] webapp

[+] Enumerating collections in 'webapp':
    [*] users (2847 documents)
    [*] sessions (142 documents)
    [*] orders (9521 documents)`,
  },
  // --- UTILITY ---
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
