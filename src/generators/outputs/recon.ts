// Reconnaissance tool output generators

import type { OutputContext, TargetProfile } from "./helpers.js";
import { PORT_SERVICES } from "./helpers.js";

export function generateNmapOutput(ctx: OutputContext, domain: string, targetProfile: TargetProfile): string {
  const portCount = ctx.rng.int(3, 12);
  const ports = ctx.rng.pickN(targetProfile.openPorts, portCount);
  const hostUp = ctx.rng.bool(0.95);
  const nmapVersion = ctx.rng.pick(["7.93", "7.94", "7.94SVN", "7.92", "7.95"]);
  const latency = ctx.rng.float(0.001, 0.250).toFixed(3);

  if (!hostUp) {
    return `Starting Nmap ${nmapVersion} ( https://nmap.org )\nNote: Host seems down. If it is really up, but blocking our ping probes, try -Pn\nNmap done: 1 IP address (0 hosts up) scanned in ${ctx.rng.float(2.0, 8.5).toFixed(2)} seconds`;
  }

  const scanType = ctx.rng.pick(["SYN Stealth Scan", "Connect Scan", "Service Scan", "Version Detection"]);
  let output = `Starting Nmap ${nmapVersion} ( https://nmap.org ) at ${ctx.generateDate().slice(0, 19).replace("T", " ")}\n`;
  if (ctx.rng.bool(0.3)) {
    output += `Initiating ${scanType}\n`;
  }
  output += `Nmap scan report for ${domain} (${targetProfile.ip})\nHost is up (${latency}s latency).\n`;
  if (ctx.rng.bool(0.4)) {
    output += `rDNS record for ${targetProfile.ip}: ${ctx.rng.pick(["ec2-", "host-", "server-", "web-"])}${targetProfile.ip.replace(/\./g, "-")}.${ctx.rng.pick(["compute.amazonaws.com", "cloudprovider.net", "hosting.com"])}\n`;
  }
  if (ctx.rng.bool(0.35)) {
    output += `Not shown: ${ctx.rng.int(980, 998)} closed tcp ports (${ctx.rng.pick(["reset", "conn-refused", "no-response"])})\n`;
  }
  output += `\nPORT     STATE    SERVICE       VERSION\n`;

  for (const port of ports) {
    const state = ctx.rng.pick(["open", "open", "open", "open", "filtered", "open|filtered"]);
    const svc = PORT_SERVICES[port] || { service: "unknown", versions: ["unknown"] };
    const version = ctx.rng.pick(svc.versions);
    output += `${String(port).padEnd(5)}/${ctx.rng.pick(["tcp", "tcp", "tcp", "udp"])}  ${state.padEnd(8)} ${svc.service.padEnd(13)} ${version}\n`;
  }

  if (ctx.rng.bool(0.4)) {
    const os = ctx.rng.pick(["Linux 5.4 - 5.15", "Linux 4.15 - 5.8", "Linux 3.10 - 4.11", "FreeBSD 12.0-RELEASE", "Linux; CPE: cpe:/o:linux:linux_kernel"]);
    output += `\nService Info: OS: ${os}\n`;
  }

  // NSE script results — vary which scripts and findings
  if (ctx.rng.bool(0.35)) {
    output += `\n| http-title: ${ctx.rng.pick(targetProfile.pageTitles)}\n|_Requested resource was ${ctx.rng.pick(["/login", "/dashboard", "/", "/home", "/index.html", "/app"])}\n`;
  }
  if (ctx.rng.bool(0.25)) {
    output += `| http-server-header: ${ctx.rng.pick(targetProfile.techHeaders)}\n`;
  }
  if (ctx.rng.bool(0.2)) {
    output += `| ssl-cert: Subject: commonName=${domain}/organizationName=${domain.split(".")[0]}\n|   Not valid after: ${ctx.rng.int(2025, 2027)}-${String(ctx.rng.int(1, 12)).padStart(2, "0")}-${String(ctx.rng.int(1, 28)).padStart(2, "0")}\n`;
  }
  if (ctx.rng.bool(0.15)) {
    output += `| http-methods:\n|_  Potentially risky methods: ${ctx.rng.pickN(["PUT", "DELETE", "TRACE", "OPTIONS", "CONNECT"], ctx.rng.int(1, 3)).join(" ")}\n`;
  }
  if (ctx.rng.bool(0.15)) {
    output += `| http-robots.txt: ${ctx.rng.int(2, 15)} disallowed entries\n|_  ${ctx.rng.pickN(["/admin", "/backup", "/config", "/.git", "/api/internal", "/debug", "/tmp"], ctx.rng.int(1, 4)).join(", ")}\n`;
  }

  const totalScanTime = ctx.rng.float(2, 120).toFixed(2);
  output += `\nNmap done: 1 IP address (1 host up) scanned in ${totalScanTime} seconds`;
  return output;
}

export function generateSubfinderOutput(ctx: OutputContext, domain: string, targetProfile: TargetProfile): string {
  const subCount = ctx.rng.int(5, 25);
  const subs = ctx.rng.pickN(targetProfile.subdomains, subCount);
  return subs.map(s => `${s}.${domain}`).join("\n");
}

export function generateAmassOutput(ctx: OutputContext, domain: string, targetProfile: TargetProfile): string {
  const subCount = ctx.rng.int(5, 25);
  const subs = ctx.rng.pickN(targetProfile.subdomains, subCount);
  const amassVersion = ctx.rng.pick(["4.2.0", "4.1.0", "4.0.7"]);

  let output = `OWASP Amass v${amassVersion}\n\n`;
  if (ctx.rng.bool(0.4)) {
    output += `[INFO] Starting enumeration of ${domain}\n`;
  }

  const sources = ["DNS", "Brute", "cert", "AlienVault", "Shodan", "VirusTotal", "SecurityTrails", "Wayback", "CommonCrawl", "Crtsh", "HackerTarget", "ThreatCrowd", "BufferOver"];

  for (const sub of subs) {
    const source = ctx.rng.pick(sources);
    const ip = `${ctx.rng.pick([10, 172, 52, 34, 104])}.${ctx.rng.int(0, 255)}.${ctx.rng.int(0, 255)}.${ctx.rng.int(1, 254)}`;

    if (ctx.rng.bool(0.6)) {
      output += `${sub}.${domain} (${source}) --> ${ip}\n`;
    } else {
      output += `${sub}.${domain} [${source}]\n`;
    }
  }

  output += `\n${subCount} subdomain(s) discovered for ${domain}`;
  if (ctx.rng.bool(0.3)) {
    output += `\n${ctx.rng.int(5, 15)} data source(s) used`;
  }
  return output;
}

export function generateHttpxOutput(ctx: OutputContext, domain: string, targetProfile: TargetProfile): string {
  const subCount = ctx.rng.int(4, 15);
  const subs = ctx.rng.pickN(targetProfile.subdomains, subCount);
  let output = "";

  for (const sub of subs) {
    const status = ctx.rng.pick([200, 200, 200, 301, 302, 403, 404, 500]);
    const title = ctx.rng.pick(targetProfile.pageTitles.concat(["", "403 Forbidden", "404 Not Found", "301 Moved"]));
    const server = ctx.rng.pick(targetProfile.techHeaders);
    const techs = ctx.rng.pickN(targetProfile.technologies, ctx.rng.int(0, 3)).join(",");
    output += `https://${sub}.${domain} [${status}] [${title}] [${server}] [${techs}]\n`;
  }

  return output.trim();
}

export function generateRustscanOutput(ctx: OutputContext, domain: string, targetProfile: TargetProfile): string {
  const rustscanVersion = ctx.rng.pick(["2.1.1", "2.2.0", "2.2.1", "2.0.1"]);
  const batchSize = ctx.rng.pick([3000, 4500, 5000, 8000, 10000]);
  const timeout = ctx.rng.pick([1500, 2000, 3000, 5000]);
  const portCount = ctx.rng.int(3, 10);
  const ports = ctx.rng.pickN(targetProfile.openPorts, portCount);
  const nmapVersion = ctx.rng.pick(["7.93", "7.94", "7.94SVN"]);

  let output = `.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.\n| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \\ |  \`| |\n| .-. \\| {_} |.-._} } | |  .-._} }\\     }/  /\\  \\| |\\  |\n\`-' \`-'\`-----'\`----'  \`-'  \`----'  \`---' \`-'  \`-'\`-' \`-'\nThe Modern Day Port Scanner.\n________________________________________\n: https://discord.gg/GFrQsGy           :\n: https://github.com/RustScan/RustScan  :\n --------------------------------------\nRustscan ${rustscanVersion}\n\n`;
  output += `[~] The config file is expected to be at "/home/${ctx.rng.pick(["kali", "user", "pentest"])}/.rustscan.toml"\n`;
  output += `[!] File limit is lower than default batch size. Consider upping with --ulimit. (current: ${ctx.rng.int(1024, 8192)})\n`;
  output += `[~] Starting Scan\n`;
  output += `[~] Scanning ${domain} (${targetProfile.ip})\n`;
  output += `[~] Batch Size: ${batchSize}\n`;
  output += `[~] Timeout: ${timeout}ms\n`;
  output += `[~] Ports: ${ports.sort((a, b) => a - b).join(", ")}\n`;

  const scanTimeMs = ctx.rng.float(0.05, 2.5).toFixed(3);
  output += `[~] Scan completed in ${scanTimeMs}s\n`;
  output += `Open ${targetProfile.ip}:${ports.sort((a, b) => a - b).join(`\nOpen ${targetProfile.ip}:`)}\n`;

  output += `[~] Running nmap with arguments: -vvv -p ${ports.sort((a, b) => a - b).join(",")} -sCV -A ${targetProfile.ip}\n`;
  output += `\nStarting Nmap ${nmapVersion} ( https://nmap.org )\n`;
  output += `Nmap scan report for ${domain} (${targetProfile.ip})\n`;
  output += `Host is up (${ctx.rng.float(0.001, 0.200).toFixed(3)}s latency).\n\n`;
  output += `PORT      STATE SERVICE       VERSION\n`;

  for (const port of ports.sort((a, b) => a - b)) {
    const svc = PORT_SERVICES[port] || { service: "unknown", versions: ["unknown"] };
    const version = ctx.rng.pick(svc.versions);
    output += `${String(port).padEnd(5)}/tcp open  ${svc.service.padEnd(13)} ${version}\n`;
  }

  if (ctx.rng.bool(0.4)) {
    const os = ctx.rng.pick(["Linux 5.4 - 5.15", "Linux 4.15 - 5.8", "FreeBSD 12.0-RELEASE"]);
    output += `\nService Info: OS: ${os}\n`;
  }

  output += `\nNmap done: 1 IP address (1 host up) scanned in ${ctx.rng.float(5, 60).toFixed(2)} seconds`;
  return output;
}
