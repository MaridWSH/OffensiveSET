// Enumeration tool output generators

import type { OutputContext, TargetProfile } from "./helpers.js";

export function generateFfufOutput(ctx: OutputContext, domain: string, targetProfile: TargetProfile): string {
  const resultCount = ctx.rng.int(3, 15);
  const dirs = ctx.rng.pickN(targetProfile.directories, resultCount);
  const ffufVersion = ctx.rng.pick(["2.0.0", "2.1.0", "1.5.0", "2.0.0-dev"]);
  const method = ctx.rng.pick(["GET", "GET", "POST", "HEAD"]);
  const sub = ctx.rng.pick(targetProfile.subdomains);
  const targetUrl = ctx.rng.bool(0.3) ? `${sub}.${domain}` : domain;
  const wordlist = ctx.rng.pick([
    "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
    "/usr/share/seclists/Discovery/Web-Content/big.txt",
    "/usr/share/seclists/Discovery/Web-Content/raft-large-files.txt",
  ]);
  const threads = ctx.rng.pick([40, 50, 75, 100, 150, 200]);
  const matchers = ctx.rng.pick(["200,204,301,302,307,401,403", "200,301,302,403", "200,301,302,403,500", "all"]);

  let output = `        /'___\\  /'___\\           /'___\\\n       /\\ \\__/ /\\ \\__/  __  __  /\\ \\__/\n       \\ \\ ,__\\\\ \\ ,__\\/\\ \\/\\ \\ \\ \\ ,__\\\n        \\ \\ \\_/ \\ \\ \\_/\\ \\ \\_\\ \\ \\ \\ \\_/\n         \\ \\_\\   \\ \\_\\  \\ \\____/  \\ \\_\\\n          \\/_/    \\/_/   \\/___/    \\/_/\n\n       v${ffufVersion}\n________________________________________________\n\n :: Method           : ${method}\n :: URL              : https://${targetUrl}/FUZZ\n :: Wordlist         : FUZZ: ${wordlist}\n :: Follow redirects : ${ctx.rng.bool(0.3)}\n :: Calibration      : ${ctx.rng.bool(0.2)}\n :: Timeout          : ${ctx.rng.pick([10, 15, 20, 30])}\n :: Threads          : ${threads}\n :: Matcher          : Response status: ${matchers}\n`;

  if (ctx.rng.bool(0.3)) {
    output += ` :: Filter           : Response size: ${ctx.rng.int(0, 500)}\n`;
  }
  output += `________________________________________________\n\n`;

  for (const dir of dirs) {
    const status = ctx.rng.pick([200, 200, 200, 301, 302, 403, 403, 401]);
    const size = ctx.rng.int(0, 45000);
    const words = ctx.rng.int(0, 3500);
    const lines = ctx.rng.int(0, 500);
    const duration = ctx.rng.int(15, 800);
    output += `[Status: ${status}, Size: ${size}, Words: ${words}, Lines: ${lines}, Duration: ${duration}ms]\n    * FUZZ: ${dir}\n`;
  }

  const totalReqs = ctx.rng.int(20000, 35000);
  const durationSec = ctx.rng.int(20, 180);
  const reqSec = ctx.rng.int(150, 900);
  const errors = ctx.rng.int(0, 15);
  output += `\n:: Progress: [${totalReqs}/${totalReqs}] :: Job [1/1] :: ${reqSec} req/sec :: Duration: [0:${String(Math.floor(durationSec / 60)).padStart(2, "0")}:${String(durationSec % 60).padStart(2, "0")}] :: Errors: ${errors} ::`;
  return output;
}

export function generateFeroxbusterOutput(ctx: OutputContext, domain: string, targetProfile: TargetProfile): string {
  const feroxVersion = ctx.rng.pick(["2.10.0", "2.10.1", "2.9.5", "2.10.2"]);
  const threads = ctx.rng.pick([50, 100, 150, 200]);
  const wordlist = ctx.rng.pick([
    "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
    "/usr/share/seclists/Discovery/Web-Content/big.txt",
  ]);
  const sub = ctx.rng.pick(targetProfile.subdomains);
  const targetUrl = ctx.rng.bool(0.3) ? `https://${sub}.${domain}` : `https://${domain}`;
  const resultCount = ctx.rng.int(5, 18);
  const dirs = ctx.rng.pickN(targetProfile.directories, resultCount);
  const recursionDepth = ctx.rng.int(1, 4);
  const statusCodes = ctx.rng.pick(["200,204,301,302,307,308,401,403,405", "200,301,302,403", "200,204,301,302,307,401,403,405,500"]);

  let output = `\n ___  ___  __   __     __      __         __   ___\n|__  |__  |__) |__) | /  \`   /  \\ \\_/ | |  \\ |__\n|    |___ |  \\ |  \\ | \\__,   \\__/ / \\ | |__/ |___\nby Ben "epi" Risher                    ver: ${feroxVersion}\n───────────────────────────┬──────────────────────\n Target Url            │ ${targetUrl}\n Threads               │ ${threads}\n Wordlist              │ ${wordlist}\n Status Codes          │ [${statusCodes}]\n Timeout (secs)        │ ${ctx.rng.pick([7, 10, 15, 20])}\n User-Agent            │ feroxbuster/${feroxVersion}\n Recursion Depth       │ ${recursionDepth}\n`;

  if (ctx.rng.bool(0.4)) {
    output += ` Extract Links         │ true\n`;
  }
  if (ctx.rng.bool(0.3)) {
    output += ` Collect Extensions    │ [${ctx.rng.pick(["php, html, js, txt", "asp, aspx, jsp", "py, rb, pl"])}]\n`;
  }
  output += `───────────────────────────┴──────────────────────\n`;

  for (const dir of dirs) {
    const status = ctx.rng.pick([200, 200, 200, 301, 302, 403, 403, 401, 405, 500]);
    const method = ctx.rng.pick(["GET", "GET", "GET", "POST"]);
    const size = ctx.rng.int(0, 85000);
    const lines = ctx.rng.int(1, 600);
    const words = ctx.rng.int(1, 5000);
    const responseTime = ctx.rng.int(5, 2500);
    const depth = ctx.rng.int(0, recursionDepth);
    const cleanDir = dir.replace(/^\//, "");
    output += `${status}      ${method}     ${String(lines).padStart(5)}l  ${String(words).padStart(6)}w  ${String(size).padStart(7)}c  ${targetUrl}/${cleanDir}`;
    if (ctx.rng.bool(0.2)) {
      output += ` => ${targetUrl}/${cleanDir}/`;
    }
    output += `\n`;
  }

  if (ctx.rng.bool(0.3)) {
    output += `WLD      GET         ${ctx.rng.int(1, 50)}l    ${ctx.rng.int(1, 200)}w     ${ctx.rng.int(100, 5000)}c  ${targetUrl}/wildcard${ctx.generateHex(4)} (url length: ${ctx.rng.int(20, 60)})\n`;
  }

  const totalReqs = ctx.rng.int(20000, 120000);
  const elapsed = ctx.rng.int(30, 600);
  const reqSec = Math.floor(totalReqs / elapsed);
  output += `\n Scanning: ${targetUrl}\n`;
  output += ` ${totalReqs} requests in ${Math.floor(elapsed / 60)}m ${elapsed % 60}s (${reqSec} req/sec)\n`;
  output += ` ${resultCount} unique responses received\n`;
  if (ctx.rng.bool(0.3)) {
    output += ` ${ctx.rng.int(1, 5)} error(s) during scan\n`;
  }
  return output;
}

export function generateGobusterOutput(ctx: OutputContext, domain: string, targetProfile: TargetProfile): string {
  const resultCount = ctx.rng.int(3, 15);
  const dirs = ctx.rng.pickN(targetProfile.directories, resultCount);
  const mode = ctx.rng.pick(["dir", "dns", "vhost"]);
  const gobusterVersion = ctx.rng.pick(["3.5.0", "3.6.0", "3.6.1"]);
  const wordlist = ctx.rng.pick([
    "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
    "/usr/share/seclists/Discovery/Web-Content/big.txt",
  ]);
  const threads = ctx.rng.pick([10, 20, 30, 50]);

  let output = `===============================================================\nGobuster v${gobusterVersion}\nby OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)\n===============================================================\n`;
  output += `[+] Url:                     https://${domain}\n`;
  output += `[+] Method:                  GET\n`;
  output += `[+] Threads:                 ${threads}\n`;
  output += `[+] Wordlist:                ${wordlist}\n`;
  output += `[+] Status codes:            ${ctx.rng.pick(["200,204,301,302,307,401,403", "200,301,302,403"])}\n`;
  output += `[+] Timeout:                 ${ctx.rng.pick(["10s", "15s", "20s"])}\n`;
  output += `===============================================================\n`;
  output += `Starting gobuster in ${mode} enumeration mode\n`;
  output += `===============================================================\n`;

  for (const dir of dirs) {
    const status = ctx.rng.pick([200, 200, 301, 302, 403, 403]);
    const size = ctx.rng.int(0, 45000);
    output += `/${dir.replace(/^\//, "")}${" ".repeat(Math.max(1, 30 - dir.length))}(Status: ${status}) [Size: ${size}]\n`;
  }

  output += `\n===============================================================\nFinished\n===============================================================`;
  return output;
}

export function generateWfuzzOutput(ctx: OutputContext, domain: string, targetProfile: TargetProfile): string {
  const resultCount = ctx.rng.int(3, 12);
  const dirs = ctx.rng.pickN(targetProfile.directories, resultCount);
  const wfuzzVersion = ctx.rng.pick(["3.1.0", "3.1.1", "3.0.3"]);

  let output = `********************************************************\n* Wfuzz ${wfuzzVersion} - The Web Fuzzer                      *\n********************************************************\n\n`;
  output += `Target: https://${domain}/FUZZ\n`;
  output += `Total requests: ${ctx.rng.int(20000, 35000)}\n\n`;
  output += `=====================================================================\nID           Response   Lines    Word       Chars       Payload\n=====================================================================\n\n`;

  for (let i = 0; i < dirs.length; i++) {
    const status = ctx.rng.pick([200, 200, 200, 301, 302, 403]);
    const lines = ctx.rng.int(1, 500);
    const words = ctx.rng.int(1, 3500);
    const chars = ctx.rng.int(50, 45000);
    const id = String(ctx.rng.int(1, 30000)).padStart(6, "0");
    output += `${id}:  ${status}      ${String(lines).padEnd(5)}L   ${String(words).padEnd(7)}W    ${String(chars).padEnd(8)}Ch   "${dirs[i]}"\n`;
  }

  output += `\nTotal time: ${ctx.rng.float(5, 120).toFixed(1)}s\nProcessed Requests: ${ctx.rng.int(20000, 35000)}\nFiltered Requests: ${ctx.rng.int(19000, 34000)}\nRequests/sec.: ${ctx.rng.float(100, 900).toFixed(1)}`;
  return output;
}

export function generateKatanaOutput(ctx: OutputContext, domain: string, targetProfile: TargetProfile): string {
  const katanaVersion = ctx.rng.pick(["1.0.4", "1.0.3", "1.0.2", "1.1.0"]);
  const sub = ctx.rng.pick(targetProfile.subdomains);
  const targetUrl = ctx.rng.bool(0.3) ? `https://${sub}.${domain}` : `https://${domain}`;
  const depth = ctx.rng.int(2, 5);
  const concurrency = ctx.rng.pick([10, 20, 30, 50]);

  let output = `\n   __        __                \n  / /_____ _/ /_____ ____  ___ _\n / '_/ _  / __/ _  / _ \\/ _  /\n/_/\\_\\_,_/\\__/\\_,_/_//_/\\_,_/ v${katanaVersion}\n\n`;
  output += `[INF] Current katana version v${katanaVersion}\n`;
  output += `[INF] Started crawling ${targetUrl}\n`;
  output += `[INF] Configuration: depth=${depth}, concurrency=${concurrency}, headless=${ctx.rng.bool(0.3)}\n`;
  output += `\n`;

  const endpointPatterns = [
    () => `${targetUrl}/api/v${ctx.rng.int(1, 3)}/${ctx.rng.pick(["users", "products", "orders", "search", "auth", "settings", "config", "status", "health"])}`,
    () => `${targetUrl}/${ctx.rng.pick(["login", "register", "forgot-password", "reset-password", "signup", "signin", "logout", "callback"])}`,
    () => `${targetUrl}/assets/${ctx.rng.pick(["js", "css", "images"])}/${ctx.rng.pick(["app", "main", "vendor", "bundle", "chunk"])}.${ctx.rng.pick(["js", "css", "min.js", "min.css"])}`,
    () => `${targetUrl}/${ctx.rng.pick(targetProfile.directories)}`,
    () => `${targetUrl}/api/${ctx.rng.pick(["graphql", "webhook", "callback", "oauth", "token"])}`,
    () => `${targetUrl}/static/${ctx.rng.pick(["app", "runtime", "polyfills", "vendor"])}-${ctx.generateHex(8)}.js`,
    () => `${targetUrl}/${ctx.rng.pick(["robots.txt", "sitemap.xml", ".well-known/security.txt", "humans.txt", "manifest.json"])}`,
    () => `${targetUrl}/api/v${ctx.rng.int(1, 2)}/${ctx.rng.pick(["users", "items", "data"])}/${ctx.rng.int(1, 999)}`,
  ];

  const formPatterns = [
    () => `[form] ${targetUrl}/login method=POST fields=[username, password, csrf_token]`,
    () => `[form] ${targetUrl}/register method=POST fields=[email, password, confirm_password, name]`,
    () => `[form] ${targetUrl}/search method=GET fields=[q, category, sort]`,
    () => `[form] ${targetUrl}/contact method=POST fields=[name, email, message, captcha]`,
    () => `[form] ${targetUrl}/forgot-password method=POST fields=[email]`,
    () => `[form] ${targetUrl}/settings/profile method=POST fields=[name, bio, avatar] enctype=multipart/form-data`,
    () => `[form] ${targetUrl}/api/feedback method=POST fields=[rating, comment, user_id]`,
  ];

  const jsPatterns = [
    () => `[js] ${targetUrl}/assets/js/app-${ctx.generateHex(8)}.js`,
    () => `[js] ${targetUrl}/static/bundle.min.js`,
    () => `[js] ${targetUrl}/js/${ctx.rng.pick(["analytics", "tracking", "gtm", "hotjar", "sentry"])}.js`,
    () => `[js] ${targetUrl}/api/config.js`,
    () => `[js] ${targetUrl}/node_modules/${ctx.rng.pick(["jquery", "lodash", "axios", "moment", "react-dom"])}/dist/${ctx.rng.pick(["jquery.min", "lodash.min", "axios.min", "moment.min", "react-dom.production.min"])}.js`,
  ];

  const endpointCount = ctx.rng.int(8, 20);
  const formCount = ctx.rng.int(1, 4);
  const jsCount = ctx.rng.int(2, 6);

  for (let i = 0; i < endpointCount; i++) {
    const generator = ctx.rng.pick(endpointPatterns);
    output += `${generator()}\n`;
  }

  for (let i = 0; i < formCount; i++) {
    const generator = ctx.rng.pick(formPatterns);
    output += `${generator()}\n`;
  }

  for (let i = 0; i < jsCount; i++) {
    const generator = ctx.rng.pick(jsPatterns);
    output += `${generator()}\n`;
  }

  if (ctx.rng.bool(0.4)) {
    const emailsFound = ctx.rng.int(1, 3);
    for (let i = 0; i < emailsFound; i++) {
      output += `[email] ${ctx.rng.pick(["info", "support", "admin", "contact", "security"])}@${domain}\n`;
    }
  }

  if (ctx.rng.bool(0.3)) {
    output += `[s3-bucket] https://${domain.replace(/\./g, "-")}-${ctx.rng.pick(["assets", "uploads", "static"])}.s3.amazonaws.com\n`;
  }

  const totalUrls = endpointCount + formCount + jsCount;
  output += `\n[INF] Crawling completed\n`;
  output += `[INF] Total unique endpoints: ${totalUrls}\n`;
  output += `[INF] Total forms found: ${formCount}\n`;
  output += `[INF] Total JS files: ${jsCount}\n`;
  output += `[INF] Duration: ${ctx.rng.float(3.0, 120.0).toFixed(1)}s`;
  return output;
}
