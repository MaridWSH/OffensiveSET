// Vulnerability scanning tool output generators

import type { OutputContext, TargetProfile } from "./helpers.js";
import { NUCLEI_FINDINGS, XSS_PAYLOADS } from "./helpers.js";

export function generateNucleiOutput(ctx: OutputContext, domain: string, targetProfile: TargetProfile): string {
  const nucleiVersion = ctx.rng.pick(["3.0.4", "3.1.0", "3.1.4", "3.2.0", "3.2.1", "3.2.4"]);
  const templateCount = ctx.rng.int(4500, 8200);
  const findingCount = ctx.rng.int(2, 10);
  const findings = ctx.rng.pickN(NUCLEI_FINDINGS, findingCount);

  let output = `[INF] Using Nuclei Engine ${nucleiVersion}\n`;
  output += `[INF] Templates loaded: ${templateCount}\n`;
  output += `[INF] Targets loaded: ${ctx.rng.int(1, 5)}\n`;
  if (ctx.rng.bool(0.3)) {
    output += `[INF] Using ${ctx.rng.int(10, 50)} interactsh server(s)\n`;
  }
  output += `\n`;

  for (const finding of findings) {
    const severity = ctx.rng.pick(finding.severities);
    const fpath = ctx.rng.pick(finding.paths);
    const sub = ctx.rng.pick(targetProfile.subdomains);
    const targetHost = ctx.rng.bool(0.4) ? `${sub}.${domain}` : domain;
    const matcherName = ctx.rng.pick(["status-code", "word", "regex", "binary", "dsl"]);
    output += `[${finding.id}] [${finding.protocol}] [${severity}] ${ctx.rng.bool(0.5) ? `[matcher:${matcherName}] ` : ""}https://${targetHost}${fpath}`;

    // Add extracted data for some findings
    if (ctx.rng.bool(0.3)) {
      output += ` [${ctx.rng.pick(["extracted", "matched"])}:${ctx.rng.pick(["version=", "token=", "key=", "path="])}${ctx.generateHex(ctx.rng.int(4, 12))}]`;
    }
    output += `\n`;
  }

  const elapsed = `${ctx.rng.int(0, 3)}m${ctx.rng.int(1, 59)}s`;
  output += `\n[INF] Scan completed in ${elapsed}`;
  if (ctx.rng.bool(0.25)) {
    output += `\n[INF] ${ctx.rng.int(100, 600)} templates with no results`;
  }

  return output.trim();
}

export function generateNiktoOutput(ctx: OutputContext, domain: string, targetProfile: TargetProfile): string {
  const niktoVersion = ctx.rng.pick(["2.5.0", "2.1.6", "2.5.0-git"]);
  const serverHeader = ctx.rng.pick(targetProfile.techHeaders);
  const findingCount = ctx.rng.int(3, 12);

  let output = `- Nikto v${niktoVersion}\n`;
  output += `---------------------------------------------------------------------------\n`;
  output += `+ Target IP:          ${targetProfile.ip}\n`;
  output += `+ Target Hostname:    ${domain}\n`;
  output += `+ Target Port:        ${ctx.rng.pick([80, 443, 8080, 8443])}\n`;
  output += `+ Start Time:         ${ctx.generateDate().slice(0, 19).replace("T", " ")}\n`;
  output += `---------------------------------------------------------------------------\n`;
  output += `+ Server: ${serverHeader}\n`;

  const niktoFindings = [
    `The anti-clickjacking X-Frame-Options header is not present.`,
    `The X-Content-Type-Options header is not set.`,
    `No CGI Directories found (use '-C all' to force check).`,
    `${ctx.rng.pick(["OSVDB-3092", "OSVDB-3233", "OSVDB-637", "OSVDB-877"])}: /${ctx.rng.pick(targetProfile.directories)}: This may be interesting.`,
    `/${ctx.rng.pick(["admin", "phpmyadmin", ".git", "backup", "config"])}/: Directory indexing found.`,
    `Server may leak inodes via ETags, header found with file /${ctx.rng.pick(["", "index.html", "robots.txt"])}.`,
    `Allowed HTTP Methods: ${ctx.rng.pickN(["GET", "POST", "OPTIONS", "HEAD", "PUT", "DELETE", "TRACE"], ctx.rng.int(3, 6)).join(", ")}`,
    `/${ctx.rng.pick(targetProfile.directories)}: ${ctx.rng.pick(["Admin login page/section found", "Backup file found", "Configuration file found", "Default page found"])}.`,
    `Cookie ${ctx.rng.pick(["session", "JSESSIONID", "PHPSESSID", "connect.sid", "token"])} created without the ${ctx.rng.pick(["httponly", "secure", "SameSite"])} flag.`,
    `The site uses TLS and the Strict-Transport-Security HTTP header is not defined.`,
    `/${ctx.rng.pick([".env", "web.config", "config.php", ".htaccess"])}: Configuration file found.`,
    `OSVDB-${ctx.rng.int(1000, 9999)}: /${ctx.rng.pick(targetProfile.directories)}: ${ctx.rng.pick(["Default credentials may be present", "Debug endpoint exposed", "Version information disclosed", "Stack trace in error response"])}.`,
  ];

  const selectedFindings = ctx.rng.pickN(niktoFindings, findingCount);
  for (const finding of selectedFindings) {
    output += `+ ${finding}\n`;
  }

  output += `---------------------------------------------------------------------------\n`;
  output += `+ ${findingCount} item(s) reported on remote host\n`;
  output += `+ End Time:           ${ctx.generateDate().slice(0, 19).replace("T", " ")} (${ctx.rng.int(15, 300)} seconds)\n`;
  output += `---------------------------------------------------------------------------`;
  return output;
}

export function generateDalfoxOutput(ctx: OutputContext, domain: string, targetProfile: TargetProfile): string {
  const paramCount = ctx.rng.int(1, 5);
  const params = ctx.rng.pickN(targetProfile.reflectedParams, paramCount);
  let output = "";

  for (const param of params) {
    if (ctx.rng.bool(0.6)) {
      const payload = ctx.rng.pick(XSS_PAYLOADS);
      const xssType = ctx.rng.pick(["V", "R", "D"]); // Verified, Reflected, DOM
      output += `[POC][${xssType}][GET] https://${domain}/${ctx.rng.pick(["search", "page", "profile", "comment"])}?${param}=${encodeURIComponent(payload)}\n`;
    }
    output += `[I] Found ${ctx.rng.pick(["reflected", "injected", "DOM sink"])} parameter: ${param}\n`;
  }

  if (ctx.rng.bool(0.3)) {
    output += `[I] Found DOM sink: ${ctx.rng.pick(["document.write()", "innerHTML", "eval()", "setTimeout()", "location.href"])} in /assets/${ctx.rng.pick(["app", "main", "bundle", "index"])}.js:${ctx.rng.int(10, 2000)}\n`;
  }

  if (ctx.rng.bool(0.2)) {
    output += `[W] No reflected/stored XSS found for ${ctx.rng.int(1, 5)} parameter(s)\n`;
  }

  return output.trim();
}

export function generateSemgrepOutput(ctx: OutputContext, domain: string, targetProfile: TargetProfile): string {
  const semgrepVersion = ctx.rng.pick(["1.56.0", "1.55.2", "1.50.0", "1.48.0", "1.60.1"]);
  const findingCount = ctx.rng.int(3, 10);
  const repoName = domain.split(".")[0];

  const rules = [
    {
      id: "javascript.lang.security.detect-eval-with-expression",
      severity: "WARNING",
      message: "Detected `eval` with a non-literal argument. This could lead to code injection.",
      lang: "javascript",
      file: () => `src/${ctx.rng.pick(["utils", "helpers", "lib", "controllers"])}/${ctx.rng.pick(["parser", "template", "eval", "handler"])}.js`,
      code: () => {
        const varName = ctx.rng.pick(["userInput", "data", "payload", "expression"]);
        return `    eval(${varName})`;
      },
      line: () => ctx.rng.int(15, 300),
    },
    {
      id: "python.lang.security.audit.dangerous-subprocess-use",
      severity: "ERROR",
      message: "Detected subprocess call with shell=True and user-controlled input.",
      lang: "python",
      file: () => `app/${ctx.rng.pick(["views", "tasks", "services", "utils"])}/${ctx.rng.pick(["deploy", "backup", "export", "processor"])}.py`,
      code: () => {
        const cmd = ctx.rng.pick(["user_cmd", "command", "shell_input", "cmd_str"]);
        return `    subprocess.call(${cmd}, shell=True)`;
      },
      line: () => ctx.rng.int(20, 250),
    },
    {
      id: "javascript.express.security.audit.xss.mustache-escape",
      severity: "WARNING",
      message: "Unescaped variable in template. This could lead to XSS.",
      lang: "javascript",
      file: () => `views/${ctx.rng.pick(["profile", "dashboard", "settings", "search"])}.${ctx.rng.pick(["ejs", "hbs", "pug"])}`,
      code: () => `    {{{ ${ctx.rng.pick(["userBio", "comment", "displayName", "message"])} }}}`,
      line: () => ctx.rng.int(5, 100),
    },
    {
      id: "python.django.security.injection.sql.sql-injection-using-raw-query",
      severity: "ERROR",
      message: "Detected raw SQL query with string formatting. Use parameterized queries.",
      lang: "python",
      file: () => `app/${ctx.rng.pick(["models", "views", "api"])}/${ctx.rng.pick(["search", "reports", "users", "analytics"])}.py`,
      code: () => {
        const param = ctx.rng.pick(["user_id", "search_term", "filter_val", "order_by"]);
        return `    cursor.execute(f"SELECT * FROM users WHERE id = {${param}}")`;
      },
      line: () => ctx.rng.int(30, 400),
    },
    {
      id: "generic.secrets.security.detected-aws-access-key-id",
      severity: "ERROR",
      message: "AWS Access Key ID detected. Remove and rotate immediately.",
      lang: "generic",
      file: () => `${ctx.rng.pick(["config", "src", "lib"])}/${ctx.rng.pick(["settings", "config", "aws", "deploy"])}.${ctx.rng.pick(["py", "js", "ts", "yml"])}`,
      code: () => `    aws_access_key_id = "AKIA${ctx.generateAlphanumeric(16).toUpperCase()}"`,
      line: () => ctx.rng.int(5, 100),
    },
    {
      id: "javascript.lang.security.detect-non-literal-require",
      severity: "WARNING",
      message: "Detected non-literal argument to require(). This could allow arbitrary code loading.",
      lang: "javascript",
      file: () => `src/${ctx.rng.pick(["plugins", "modules", "loaders"])}/${ctx.rng.pick(["loader", "dynamic", "plugin-manager"])}.js`,
      code: () => {
        const varName = ctx.rng.pick(["moduleName", "pluginPath", "dynamicModule"]);
        return `    const mod = require(${varName})`;
      },
      line: () => ctx.rng.int(10, 200),
    },
    {
      id: "python.lang.security.deserialization.avoid-pickle",
      severity: "ERROR",
      message: "Detected use of pickle to deserialize untrusted data. This can lead to RCE.",
      lang: "python",
      file: () => `app/${ctx.rng.pick(["services", "utils", "workers"])}/${ctx.rng.pick(["cache", "session", "data", "serializer"])}.py`,
      code: () => `    data = pickle.loads(request.body)`,
      line: () => ctx.rng.int(15, 180),
    },
    {
      id: "java.lang.security.audit.crypto.weak-hash",
      severity: "WARNING",
      message: "Use of weak hash algorithm (MD5/SHA1). Use SHA-256 or stronger.",
      lang: "java",
      file: () => `src/main/java/com/${repoName}/${ctx.rng.pick(["util", "security", "auth", "crypto"])}/${ctx.rng.pick(["HashUtil", "PasswordManager", "TokenGenerator"])}.java`,
      code: () => `    MessageDigest md = MessageDigest.getInstance("${ctx.rng.pick(["MD5", "SHA1"])}")`,
      line: () => ctx.rng.int(25, 300),
    },
    {
      id: "typescript.react.security.audit.react-dangerouslysetinnerhtml",
      severity: "WARNING",
      message: "Usage of dangerouslySetInnerHTML with user-controlled content detected.",
      lang: "typescript",
      file: () => `src/components/${ctx.rng.pick(["Comment", "Article", "Preview", "RichText"])}.tsx`,
      code: () => `    <div dangerouslySetInnerHTML={{ __html: ${ctx.rng.pick(["content", "htmlBody", "userMarkup"])} }} />`,
      line: () => ctx.rng.int(10, 150),
    },
    {
      id: "generic.ci.security.hardcoded-credentials-in-ci",
      severity: "ERROR",
      message: "Hardcoded credentials detected in CI/CD configuration file.",
      lang: "generic",
      file: () => `.${ctx.rng.pick(["github/workflows/deploy", "gitlab-ci", "circleci/config"])}.yml`,
      code: () => `    password: "${ctx.rng.pick(["admin123", "deploy_pass!", "Pr0d_S3cr3t", ctx.generateHex(12)])}"`,
      line: () => ctx.rng.int(10, 80),
    },
  ];

  const selectedRules = ctx.rng.pickN(rules, findingCount);

  let output = `Semgrep ${semgrepVersion}\n`;
  output += `Scanning ${ctx.rng.int(20, 500)} files with ${ctx.rng.int(50, 2000)} rules...\n\n`;

  let errorCount = 0;
  let warningCount = 0;

  for (const rule of selectedRules) {
    const file = rule.file();
    const line = rule.line();
    const code = rule.code();

    if (rule.severity === "ERROR") errorCount++;
    else warningCount++;

    output += `  ${file}\n`;
    output += `    ${rule.id}\n`;
    output += `      ${rule.message}\n`;
    output += `      Severity: ${rule.severity}\n`;
    output += `      Details: https://semgrep.dev/r/${rule.id}\n`;
    output += `\n`;
    output += `        ${line} | ${code}\n`;
    output += `\n`;
  }

  output += `Ran ${ctx.rng.int(50, 2000)} rules on ${ctx.rng.int(20, 500)} files.\n`;
  output += `Findings: ${findingCount} (${errorCount} errors, ${warningCount} warnings)\n`;
  output += `Scan completed in ${ctx.rng.float(2.0, 45.0).toFixed(1)}s`;
  return output;
}

export function generateTestsslOutput(ctx: OutputContext, domain: string, targetProfile: TargetProfile): string {
  const testsslVersion = ctx.rng.pick(["3.0.8", "3.2", "3.0.9", "3.2rc3"]);
  const port = ctx.rng.pick([443, 8443]);
  const serialNumber = ctx.generateHex(32).toUpperCase();
  const certExpiry = `${ctx.rng.int(2025, 2027)}-${String(ctx.rng.int(1, 12)).padStart(2, "0")}-${String(ctx.rng.int(1, 28)).padStart(2, "0")}`;
  const certIssuer = ctx.rng.pick(["Let's Encrypt Authority X3", "DigiCert SHA2 Extended Validation Server CA", "Sectigo RSA Domain Validation Secure Server CA", "Amazon RSA 2048 M01", "Cloudflare Inc ECC CA-3", "GlobalSign Atlas R3 DV TLS CA 2024 Q1"]);
  const keySize = ctx.rng.pick(["2048", "4096", "256 (EC)"]);
  const sigAlg = ctx.rng.pick(["SHA256withRSA", "SHA384withRSA", "SHA256withECDSA"]);

  let output = `\n###########################################################\n    testssl.sh       ${testsslVersion}     https://testssl.sh\n\n    Testing: ${domain}:${port}\n    Start ${ctx.generateDate().slice(0, 19).replace("T", " ")}\n###########################################################\n\n`;

  output += ` Testing protocols via sockets\n\n`;
  output += ` SSLv2      not offered (OK)\n`;
  output += ` SSLv3      not offered (OK)\n`;
  output += ` TLS 1      ${ctx.rng.bool(0.3) ? "offered (deprecated)" : "not offered"}\n`;
  output += ` TLS 1.1    ${ctx.rng.bool(0.2) ? "offered (deprecated)" : "not offered"}\n`;
  output += ` TLS 1.2    offered (OK)\n`;
  output += ` TLS 1.3    ${ctx.rng.bool(0.85) ? "offered (OK)" : "not offered"}\n`;

  output += `\n Testing cipher categories\n\n`;
  output += ` NULL ciphers (no encryption)                  not offered (OK)\n`;
  output += ` Anonymous NULL Ciphers (no authentication)    not offered (OK)\n`;
  output += ` Export ciphers (w/o ADH+NULL)                 not offered (OK)\n`;
  output += ` LOW: 64 Bit + DES, RC[2,4] (w/o export)      not offered (OK)\n`;
  output += ` Triple DES Ciphers / IDEA                     ${ctx.rng.bool(0.2) ? "offered (NOT ok)" : "not offered (OK)"}\n`;
  output += ` Obsolete CBC ciphers (AES, ARIA etc.)         ${ctx.rng.bool(0.4) ? "offered" : "not offered"}\n`;
  output += ` Strong encryption (AEAD ciphers)              offered (OK)\n`;

  output += `\n Testing server's cipher order\n\n`;
  const ciphers = ctx.rng.pickN([
    "TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256", "TLS_CHACHA20_POLY1305_SHA256",
    "ECDHE-RSA-AES256-GCM-SHA384", "ECDHE-RSA-AES128-GCM-SHA256",
    "ECDHE-RSA-CHACHA20-POLY1305", "ECDHE-ECDSA-AES256-GCM-SHA384",
    "ECDHE-ECDSA-AES128-GCM-SHA256", "ECDHE-ECDSA-CHACHA20-POLY1305",
  ], ctx.rng.int(3, 7));

  for (const cipher of ciphers) {
    const bits = cipher.includes("256") ? "256" : "128";
    output += `  ${cipher}   ${bits} bit\n`;
  }

  output += `\n Testing server defaults (Server Hello)\n\n`;
  output += ` TLS extensions (standard)    "${ctx.rng.pickN(["server name/#0", "renegotiation info/#65281", "EC point formats/#11", "session ticket/#35", "status request/#5", "ALPN/#16", "extended master secret/#23"], ctx.rng.int(3, 6)).join(" ")}"\n`;
  output += ` Session Ticket RFC 5077 hint ${ctx.rng.pick(["7200 s", "3600 s", "no -- noass. lifetime", "300 s"])}\n`;
  output += ` SSL Session ID support       yes\n`;
  output += ` TLS clock skew               ${ctx.rng.int(-5, 5)}s from localtime\n`;

  output += `\n Testing HTTP header response\n\n`;
  output += ` HTTP Status Code             ${ctx.rng.pick(["200 OK", "301 Moved Permanently", "302 Found"])}\n`;
  output += ` HTTP clock skew              ${ctx.rng.int(-3, 3)}s from localtime\n`;
  output += ` Strict Transport Security    ${ctx.rng.bool(0.7) ? `max-age=${ctx.rng.pick(["31536000", "63072000", "15768000"])}${ctx.rng.bool(0.5) ? "; includeSubDomains" : ""}${ctx.rng.bool(0.3) ? "; preload" : ""}` : "not offered (NOT ok)"}\n`;
  output += ` Public Key Pinning           --\n`;
  output += ` Server banner                ${ctx.rng.pick(targetProfile.techHeaders)}\n`;
  output += ` Application banner           ${ctx.rng.pick(["X-Powered-By: " + ctx.rng.pick(targetProfile.technologies), "--"])}\n`;
  output += ` Cookie(s)                    ${ctx.rng.int(0, 5)} issued: ${ctx.rng.bool(0.6) ? "HttpOnly" : "NOT HttpOnly (NOT ok)"}, ${ctx.rng.bool(0.7) ? "Secure" : "NOT Secure (NOT ok)"}\n`;
  output += ` Security headers             ${ctx.rng.bool(0.5) ? "X-Frame-Options, X-Content-Type-Options, X-XSS-Protection" : "X-Content-Type-Options only (could be better)"}\n`;

  output += `\n Testing certificate information\n\n`;
  output += ` Serial Number                ${serialNumber}\n`;
  output += ` Subject                      CN=${domain}\n`;
  output += ` Subj. Alt. Name (SAN)        ${domain} *.${domain}${ctx.rng.bool(0.3) ? ` ${ctx.rng.pick(targetProfile.subdomains)}.${domain}` : ""}\n`;
  output += ` Issuer                       ${certIssuer}\n`;
  output += ` Trust (hostname)             Ok via SAN\n`;
  output += ` Chain of trust               Ok\n`;
  output += ` EV cert (stricter)           ${ctx.rng.bool(0.15) ? "yes" : "no"}\n`;
  output += ` Certificate Validity (UTC)   expires ${certExpiry}\n`;
  output += ` ETS/"eTLS"                   --\n`;
  output += ` Certificate Transparency     yes (${ctx.rng.int(2, 5)} SCTs)\n`;
  output += ` Certificates provided        ${ctx.rng.int(2, 4)}\n`;
  output += ` Signature Algorithm          ${sigAlg}\n`;
  output += ` Server key size              RSA ${keySize} bits\n`;
  output += ` Server key usage             Digital Signature, Key Encipherment\n`;

  output += `\n Testing vulnerabilities\n\n`;
  output += ` Heartbleed (CVE-2014-0160)            not vulnerable (OK)${ctx.rng.bool(0.05) ? ", but VULNERABLE -- serverass. a]llocating 65535 bytes" : ""}\n`;
  output += ` CCS (CVE-2014-0224)                   not vulnerable (OK)\n`;
  output += ` Ticketbleed (CVE-2016-9244)           not vulnerable (OK)\n`;
  output += ` ROBOT                                 not vulnerable (OK)\n`;
  output += ` Secure Renegotiation (RFC 5746)       ${ctx.rng.bool(0.85) ? "supported (OK)" : "VULNERABLE (NOT ok)"}\n`;
  output += ` Secure Client-Initiated Renegotiation ${ctx.rng.bool(0.9) ? "not vulnerable (OK)" : "VULNERABLE (NOT ok), DoS threat"}\n`;
  output += ` CRIME, TLS (CVE-2012-4929)            not vulnerable (OK)\n`;
  output += ` BREACH (CVE-2013-3587)                ${ctx.rng.bool(0.6) ? "potentially NOT ok, \"gzip\" HTTP compression detected" : "no HTTP compression (OK)"}\n`;
  output += ` POODLE, SSL (CVE-2014-3566)           not vulnerable (OK)\n`;
  output += ` TLS_FALLBACK_SCSV (RFC 7507)          ${ctx.rng.bool(0.85) ? "Downgrade attack prevention supported (OK)" : "No fallback possible (OK)"}\n`;
  output += ` SWEET32 (CVE-2016-2183, CVE-2016-6329) ${ctx.rng.bool(0.15) ? "VULNERABLE, uses 64 bit block ciphers" : "not vulnerable (OK)"}\n`;
  output += ` FREAK (CVE-2015-0204)                 not vulnerable (OK)\n`;
  output += ` DROWN (CVE-2016-0800, CVE-2016-0703)  not vulnerable (OK)\n`;
  output += ` LOGJAM (CVE-2015-4000)                not vulnerable (OK)\n`;
  output += ` BEAST (CVE-2011-3389)                 ${ctx.rng.bool(0.2) ? "TLS1: ECDHE-RSA-AES128-SHA -- VULNERABLE but also supports higher protocols" : "not vulnerable (OK)"}\n`;
  output += ` LUCKY13 (CVE-2013-0169)               ${ctx.rng.bool(0.3) ? "potentially VULNERABLE, uses cipher block chaining (CBC) ciphers with TLS" : "not vulnerable (OK)"}\n`;
  output += ` Winshock (CVE-2014-6321)              not vulnerable (OK)\n`;
  output += ` RC4 (CVE-2013-2566, CVE-2015-2808)    no RC4 ciphers detected (OK)\n`;

  output += `\n Done ${ctx.generateDate().slice(0, 19).replace("T", " ")} [ -->> ${ctx.rng.int(30, 180)}s]`;
  return output;
}

export function generateTrufflehogOutput(ctx: OutputContext, domain: string, targetProfile: TargetProfile): string {
  const trufflehogVersion = ctx.rng.pick(["3.63.0", "3.62.1", "3.60.0", "3.55.0"]);
  const findingCount = ctx.rng.int(2, 8);
  const repoName = domain.split(".")[0];

  let output = `\x1b[0mtrufflehog ${trufflehogVersion}\n`;
  output += `Scanning source: git\n`;
  output += `Target: https://github.com/${ctx.rng.pick(["org", repoName, "company"])}/${repoName}\n`;
  output += `\n`;

  const secretTypes = [
    {
      detectorType: "AWS",
      decoderType: "PLAIN",
      generator: () => {
        const keyId = `AKIA${ctx.generateAlphanumeric(16).toUpperCase()}`;
        const secretKey = ctx.generateBase64(40);
        return {
          raw: keyId,
          extraData: `Secret Access Key: ${secretKey}`,
          file: ctx.rng.pick(["config/deploy.yml", ".env", "terraform/main.tf", "docker-compose.yml", "scripts/setup.sh", "src/config.py"]),
          email: `${ctx.rng.pick(["dev", "ops", "admin", "deploy"])}@${domain}`,
        };
      },
    },
    {
      detectorType: "PrivateKey",
      decoderType: "PLAIN",
      generator: () => {
        return {
          raw: "-----BEGIN RSA PRIVATE KEY-----",
          extraData: `Key Type: RSA, Key Size: ${ctx.rng.pick(["2048", "4096"])}`,
          file: ctx.rng.pick(["keys/server.key", "ssl/private.pem", ".ssh/id_rsa", "certs/tls.key", "deploy/server.key"]),
          email: `${ctx.rng.pick(["devops", "sre", "admin"])}@${domain}`,
        };
      },
    },
    {
      detectorType: "Slack",
      decoderType: "PLAIN",
      generator: () => {
        return {
          raw: `slack-token-${ctx.rng.int(100000000, 999999999)}-${ctx.rng.int(100000000, 999999999)}-${ctx.generateAlphanumeric(24)}`,
          extraData: "Token Type: Bot",
          file: ctx.rng.pick(["src/integrations/slack.ts", "lib/notify.py", "config/slack.yml", ".env.production"]),
          email: `${ctx.rng.pick(["backend", "integrations", "dev"])}@${domain}`,
        };
      },
    },
    {
      detectorType: "GitHub",
      decoderType: "PLAIN",
      generator: () => {
        return {
          raw: `ghp_${ctx.generateAlphanumeric(36)}`,
          extraData: "Token Type: Personal Access Token (classic)",
          file: ctx.rng.pick([".github/workflows/deploy.yml", "scripts/release.sh", "Makefile", "ci/build.sh"]),
          email: `${ctx.rng.pick(["ci", "deploy", "dev"])}@${domain}`,
        };
      },
    },
    {
      detectorType: "Stripe",
      decoderType: "PLAIN",
      generator: () => {
        return {
          raw: `sk_live_${ctx.generateAlphanumeric(24)}`,
          extraData: "Account Type: Live",
          file: ctx.rng.pick(["src/payments/stripe.js", "lib/billing.py", "config/payment.env", "app/services/stripe_service.rb"]),
          email: `${ctx.rng.pick(["billing", "payments", "dev"])}@${domain}`,
        };
      },
    },
    {
      detectorType: "SendGrid",
      decoderType: "PLAIN",
      generator: () => {
        return {
          raw: `SG.${ctx.generateAlphanumeric(22)}.${ctx.generateAlphanumeric(43)}`,
          extraData: "Token Type: API Key",
          file: ctx.rng.pick(["src/mailer.ts", "config/email.yml", "lib/notifications.py", ".env"]),
          email: `${ctx.rng.pick(["marketing", "dev", "notifications"])}@${domain}`,
        };
      },
    },
    {
      detectorType: "GoogleAPI",
      decoderType: "PLAIN",
      generator: () => {
        return {
          raw: `AIza${ctx.generateAlphanumeric(35)}`,
          extraData: "Service: Google Maps API",
          file: ctx.rng.pick(["src/maps.js", "public/index.html", "config/google.yml", "lib/geocoder.py"]),
          email: `${ctx.rng.pick(["frontend", "dev", "maps"])}@${domain}`,
        };
      },
    },
  ];

  const selectedTypes = ctx.rng.pickN(secretTypes, findingCount);

  for (const secretType of selectedTypes) {
    const data = secretType.generator();
    const commitHash = ctx.generateHex(40);
    const commitDate = ctx.generateDate().slice(0, 10);
    const verified = ctx.rng.bool(0.6);

    output += `Found ${verified ? "verified" : "unverified"} result\n`;
    output += `Detector Type: ${secretType.detectorType}\n`;
    output += `Decoder Type:  ${secretType.decoderType}\n`;
    output += `Raw:           ${data.raw}\n`;
    if (data.extraData) {
      output += `Extra Data:    ${data.extraData}\n`;
    }
    output += `File:          ${data.file}\n`;
    output += `Commit:        ${commitHash}\n`;
    output += `Date:          ${commitDate}\n`;
    output += `Email:         ${data.email}\n`;
    if (verified) {
      output += `Verified:      true\n`;
    }
    output += `\n`;
  }

  output += `Scan completed.\n`;
  output += `${findingCount} result(s) found (${selectedTypes.filter((_, i) => ctx.rng.bool(0.6)).length} verified)\n`;
  output += `${ctx.rng.int(200, 5000)} commits scanned in ${ctx.rng.float(2.0, 60.0).toFixed(1)}s`;
  return output;
}
