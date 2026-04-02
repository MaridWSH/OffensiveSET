import type { ToolDefinition } from "./types.js";

export const ENUM_TOOLS: ToolDefinition[] = [
{
    name: "ffuf",
    description: "Fast web fuzzer for directory/file discovery, parameter fuzzing, virtual host discovery, and more.",
    category: "enumeration",
    parameters: {
      url: { type: "string", description: "Target URL with FUZZ keyword", required: true, examples: ["https://target.com/FUZZ", "https://target.com/api/FUZZ", "https://target.com/page?id=FUZZ"] },
      wordlist: { type: "string", description: "Wordlist file (-w)", required: true, examples: ["/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt", "/usr/share/seclists/Discovery/Web-Content/api-endpoints.txt"] },
      filters: { type: "string", description: "Match/filter options", required: false, examples: ["-mc 200,301,302", "-fc 404", "-fs 0", "-fw 1", "-fl 10"] },
      flags: { type: "string", description: "Additional flags", required: false, examples: ["-t 100", "-r", "-recursion", "-e .php,.asp,.html", "-H 'Cookie: session=abc'", "-X POST", "-d 'user=FUZZ'"] },
      output: { type: "string", description: "Output options", required: false, examples: ["-o results.json -of json", "-o results.csv -of csv"] },
    },
    example_commands: [
      "ffuf -u https://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -mc 200,301,302,403 -t 100",
      "ffuf -u https://target.com/api/v1/FUZZ -w /usr/share/seclists/Discovery/Web-Content/api-endpoints.txt -mc all -fc 404",
      "ffuf -u https://target.com/ -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -H 'Host: FUZZ.target.com' -fs 0",
      "ffuf -u https://target.com/login -X POST -d 'username=admin&password=FUZZ' -w /usr/share/seclists/Passwords/Common-Credentials/top-1000.txt -fc 401",
      "ffuf -u 'https://target.com/api/users/FUZZ' -w <(seq 1 1000) -mc 200 -t 50",
    ],
    typical_output: `        /'___\\  /'___\\           /'___\\
       /\\ \\__/ /\\ \\__/  __  __  /\\ \\__/
       \\ \\ ,__\\\\ \\ ,__\\/\\ \\/\\ \\ \\ \\ ,__\\
        \\ \\ \\_/ \\ \\ \\_/\\ \\ \\_\\ \\ \\ \\ \\_/
         \\ \\_\\   \\ \\_\\  \\ \\____/  \\ \\_\\
          \\/_/    \\/_/   \\/___/    \\/_/

[Status: 200, Size: 4532, Words: 213, Lines: 87, Duration: 34ms]
    * FUZZ: admin
[Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 28ms]
    * FUZZ: api
[Status: 200, Size: 1893, Words: 102, Lines: 42, Duration: 41ms]
    * FUZZ: backup
[Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 22ms]
    * FUZZ: .git`,
  },
{
    name: "gobuster",
    description: "Directory/file, DNS, S3, and virtual host brute-forcing tool.",
    category: "enumeration",
    parameters: {
      mode: { type: "string", description: "Brute-force mode", required: true, examples: ["dir", "dns", "vhost", "s3", "fuzz"] },
      url: { type: "string", description: "Target URL (-u)", required: true, examples: ["https://target.com"] },
      wordlist: { type: "string", description: "Wordlist (-w)", required: true, examples: ["/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt"] },
      flags: { type: "string", description: "Additional flags", required: false, examples: ["-t 50", "-x php,html,txt", "-s 200,204,301,302,307", "--no-error", "-k"] },
      output: { type: "string", description: "Output file (-o)", required: false, examples: ["-o gobuster_results.txt"] },
    },
    example_commands: [
      "gobuster dir -u https://target.com -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -x php,html -t 50",
      "gobuster dns -d target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t 50",
      "gobuster vhost -u https://target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
    ],
    typical_output: `===============================================================
Gobuster v3.6
===============================================================
/admin                (Status: 302) [Size: 0] [--> /admin/login]
/api                  (Status: 200) [Size: 2341]
/backup               (Status: 200) [Size: 1893]
/config               (Status: 403) [Size: 278]
/.git                 (Status: 403) [Size: 278]
/uploads              (Status: 301) [Size: 0] [--> /uploads/]`,
  },
{
    name: "dirsearch",
    description: "Web path discovery tool with recursive scanning and extension brute-forcing.",
    category: "enumeration",
    parameters: {
      url: { type: "string", description: "Target URL (-u)", required: true, examples: ["https://target.com"] },
      extensions: { type: "string", description: "Extensions to append (-e)", required: false, examples: ["-e php,asp,aspx,jsp,html,js,json"] },
      wordlist: { type: "string", description: "Custom wordlist (-w)", required: false, examples: ["-w /path/to/wordlist.txt"] },
      flags: { type: "string", description: "Additional flags", required: false, examples: ["-r", "-t 50", "--exclude-status=404,500", "--deep-recursive"] },
    },
    example_commands: [
      "dirsearch -u https://target.com -e php,html,js,json -t 50 -r",
      "dirsearch -u https://target.com/api/ -e json --exclude-status=404",
    ],
    typical_output: `Target: https://target.com/
[12:00:01] 200 -   4KB - /admin/
[12:00:02] 301 -    0B  - /api  ->  /api/
[12:00:03] 200 -  823B  - /robots.txt
[12:00:04] 200 -   1KB - /.well-known/security.txt
[12:00:05] 403 -  278B  - /.git/config`,
  },
{
    name: "paramspider",
    description: "Mining parameters from web archives for a given domain.",
    category: "enumeration",
    parameters: {
      domain: { type: "string", description: "Target domain (-d)", required: true, examples: ["target.com"] },
      output: { type: "string", description: "Output file", required: false, examples: ["-o params.txt"] },
      flags: { type: "string", description: "Additional flags", required: false, examples: ["--exclude woff,css,js,png,svg,jpg", "--level high"] },
    },
    example_commands: [
      "paramspider -d target.com --exclude woff,css,js,png -o params.txt",
      "paramspider -d target.com | grep '=' | qsreplace FUZZ",
    ],
    typical_output: `https://target.com/search?q=FUZZ
https://target.com/api/users?id=FUZZ
https://target.com/redirect?url=FUZZ
https://target.com/page?file=FUZZ
https://target.com/download?path=FUZZ`,
  },
{
    name: "gau",
    description: "Fetch known URLs from AlienVault OTX, Wayback Machine, and Common Crawl for a domain.",
    category: "enumeration",
    parameters: {
      domain: { type: "string", description: "Target domain", required: true, examples: ["target.com"] },
      flags: { type: "string", description: "Additional flags", required: false, examples: ["--threads 10", "--subs", "--blacklist png,jpg,gif,css,woff"] },
      output: { type: "string", description: "Output redirection", required: false, examples: ["-o urls.txt", "| tee urls.txt"] },
    },
    example_commands: [
      "gau target.com --threads 10 --subs --blacklist png,jpg,gif,css,woff -o urls.txt",
      "gau target.com | grep '=' | uro | tee paramurls.txt",
    ],
    typical_output: `https://target.com/api/v1/users?id=123
https://target.com/search?q=test&page=1
https://target.com/admin/login
https://target.com/download?file=report.pdf
https://target.com/redirect?url=https://example.com`,
  },
{
    name: "arjun",
    description: "HTTP parameter discovery tool that finds hidden/undocumented parameters in web applications.",
    category: "enumeration",
    parameters: {
      url: { type: "string", description: "Target URL (-u)", required: true, examples: ["https://target.com/api/endpoint"] },
      method: { type: "string", description: "HTTP method (-m)", required: false, examples: ["-m GET", "-m POST", "-m JSON"] },
      flags: { type: "string", description: "Additional flags", required: false, examples: ["-t 10", "--stable", "-w /path/to/params.txt", "--headers 'Cookie: sess=abc'"] },
    },
    example_commands: [
      "arjun -u https://target.com/api/search -m GET -t 10",
      "arjun -u https://target.com/api/users -m JSON --stable",
    ],
    typical_output: `[*] Probing the target for stability
[*] Analysing HTTP response for anomalies
[*] Performing parameter discovery
[+] Parameters found: id, username, role, debug, admin, verbose, format`,
  },
{
    name: "feroxbuster",
    description: "Rust-based fast directory and content discovery tool with recursion support, auto-filtering, and smart wordlist handling.",
    category: "enumeration",
    parameters: {
      url: { type: "string", description: "Target URL (-u)", required: true, examples: ["https://target.com", "http://10.10.10.1:8080"] },
      wordlist: { type: "string", description: "Wordlist file (-w)", required: false, examples: ["/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt", "/usr/share/seclists/Discovery/Web-Content/common.txt"] },
      extensions: { type: "string", description: "File extensions to search (-x)", required: false, examples: ["-x php,html,txt,bak,js", "-x asp,aspx,jsp"] },
      flags: { type: "string", description: "Additional flags", required: false, examples: ["-t 100", "--depth 3", "--filter-status 404", "--auto-tune", "--collect-words", "--dont-filter", "-C 404,403", "-n"] },
      output: { type: "string", description: "Output file (-o)", required: false, examples: ["-o ferox_results.txt", "-o ferox.json --json"] },
    },
    example_commands: [
      "feroxbuster -u https://target.com -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x php,html,txt -t 100 --depth 3",
      "feroxbuster -u https://target.com/api -w /usr/share/seclists/Discovery/Web-Content/api-endpoints.txt --auto-tune -o api_results.txt",
      "feroxbuster -u http://10.10.10.1:8080 -x php,bak,conf --depth 4 --collect-words -C 404,403",
      "feroxbuster -u https://target.com -w /usr/share/seclists/Discovery/Web-Content/common.txt --json -o ferox.json",
    ],
    typical_output: `
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  \` /  \\ \\_/ |__) |  ) |__
|    |___ |  \\ |  \\ | \\__, \\__/ / \\ |__) |__) |___

301      GET        0l        0w        0c https://target.com/admin => https://target.com/admin/
200      GET       87l      213w     4532c https://target.com/admin/login
200      GET       42l      102w     1893c https://target.com/backup/
403      GET       10l       20w      278c https://target.com/.git/
200      GET       15l       38w      823c https://target.com/robots.txt
200      GET      120l      340w     6721c https://target.com/api/docs
301      GET        0l        0w        0c https://target.com/uploads => https://target.com/uploads/`,
  },
{
    name: "katana",
    description: "Next-generation web crawling and spidering framework by ProjectDiscovery with headless browser support and automatic form filling.",
    category: "enumeration",
    parameters: {
      target: { type: "string", description: "Target URL or list (-u / -list)", required: true, examples: ["-u https://target.com", "-list targets.txt"] },
      depth: { type: "number", description: "Maximum crawl depth (-d)", required: false, default: 3, examples: [2, 3, 5] },
      flags: { type: "string", description: "Additional flags", required: false, examples: ["-headless", "-jc", "-kf", "-ef png,jpg,gif,css", "-f qurl", "-aff", "-hl", "-silent"] },
      output: { type: "string", description: "Output options", required: false, examples: ["-o crawl.txt", "-jsonl -o crawl.jsonl"] },
    },
    example_commands: [
      "katana -u https://target.com -d 5 -jc -kf -ef png,jpg,gif,css -o crawl_results.txt",
      "katana -u https://target.com -headless -d 3 -aff -o headless_crawl.txt",
      "katana -list targets.txt -d 3 -jc -silent -f qurl | tee all_urls.txt",
      "katana -u https://target.com -jc -kf -d 4 -silent | grep -i api",
    ],
    typical_output: `https://target.com/
https://target.com/about
https://target.com/api/v1/docs
https://target.com/api/v1/users
https://target.com/login
https://target.com/assets/js/app.js
https://target.com/dashboard
https://target.com/api/v1/search?q=test
https://target.com/profile?id=1
https://target.com/contact
https://target.com/admin/panel`,
  },
{
    name: "kiterunner",
    description: "Context-aware content discovery tool designed for finding API endpoints and routes using pre-compiled wordlists of known API paths.",
    category: "enumeration",
    parameters: {
      target: { type: "string", description: "Target URL or file", required: true, examples: ["https://target.com", "--targets targets.txt"] },
      wordlist: { type: "string", description: "Kite wordlist or routes file (-w)", required: false, examples: ["-w routes-large.kite", "-w routes-small.kite", "-w apiroutes-210328:20000"] },
      flags: { type: "string", description: "Additional flags", required: false, examples: ["--fail-status-codes 404,400", "-x 10", "--max-redirects 3", "--delay 100ms", "--ignore-length 34"] },
      output: { type: "string", description: "Output file (-o)", required: false, examples: ["-o kiterunner_results.txt"] },
    },
    example_commands: [
      "kr scan https://target.com -w routes-large.kite -x 10 --fail-status-codes 404,400",
      "kr scan https://target.com/api -w routes-small.kite --ignore-length 34 -o api_discovery.txt",
      "kr brute https://target.com -w /usr/share/seclists/Discovery/Web-Content/api-endpoints.txt -x 20",
    ],
    typical_output: `GET     200 [   4532,   87,  213] https://target.com/api/v1/users
GET     200 [   1204,   32,   84] https://target.com/api/v1/config
POST    201 [    342,   12,   28] https://target.com/api/v1/auth/login
GET     200 [   8923,  204,  512] https://target.com/api/v2/docs
GET     200 [    521,   18,   42] https://target.com/api/v1/health
PUT     200 [    128,    4,   12] https://target.com/api/v1/users/1
DELETE  204 [      0,    0,    0] https://target.com/api/v1/sessions`,
  },
{
    name: "linkfinder",
    description: "Python-based tool to extract endpoints and their parameters from JavaScript files for further testing.",
    category: "enumeration",
    parameters: {
      input: { type: "string", description: "Input URL or file (-i)", required: true, examples: ["-i https://target.com/assets/js/app.js", "-i /path/to/localfile.js"] },
      output: { type: "string", description: "Output file or format (-o)", required: false, examples: ["-o results.html", "-o cli"] },
      domain: { type: "string", description: "Limit results to specific domain (-d)", required: false, examples: ["-d target.com"] },
      flags: { type: "string", description: "Additional flags", required: false, examples: ["-r", "--cookies 'session=abc'", "--headers 'Authorization: Bearer token'"] },
    },
    example_commands: [
      "linkfinder -i https://target.com/assets/js/app.js -o cli",
      "linkfinder -i https://target.com -d target.com -r -o results.html",
      "linkfinder -i https://target.com/static/bundle.min.js -o cli | grep api",
    ],
    typical_output: `/api/v1/users
/api/v1/auth/login
/api/v1/auth/reset-password
/api/v2/admin/settings
/api/v1/upload
/graphql
/api/v1/search?query=
/api/internal/debug
/api/v1/export?format=csv`,
  },
];
