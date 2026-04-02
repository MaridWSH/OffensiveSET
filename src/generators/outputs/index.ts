// DynamicOutputEngine — composed from modular output generators
// This file re-exports all public types so consumers can import from this path.

import { SeededRNG } from "./helpers.js";
import type { TargetProfile, OutputContext } from "./helpers.js";
export { SeededRNG, generateTargetProfile } from "./helpers.js";
export type { TargetProfile, DatabaseProfile, OutputContext } from "./helpers.js";

import * as recon from "./recon.js";
import * as enumOutputs from "./enum.js";
import * as vuln from "./vuln.js";
import * as exploit from "./exploit.js";
import * as cloud from "./cloud.js";
import * as failures from "./failures.js";

export class DynamicOutputEngine implements OutputContext {
  rng: SeededRNG;

  constructor(seed: number) {
    this.rng = new SeededRNG(seed);
  }

  // ============================================================
  // Recon
  // ============================================================
  generateNmapOutput(domain: string, targetProfile: TargetProfile): string {
    return recon.generateNmapOutput(this, domain, targetProfile);
  }

  generateSubfinderOutput(domain: string, targetProfile: TargetProfile): string {
    return recon.generateSubfinderOutput(this, domain, targetProfile);
  }

  generateAmassOutput(domain: string, targetProfile: TargetProfile): string {
    return recon.generateAmassOutput(this, domain, targetProfile);
  }

  generateHttpxOutput(domain: string, targetProfile: TargetProfile): string {
    return recon.generateHttpxOutput(this, domain, targetProfile);
  }

  generateRustscanOutput(domain: string, targetProfile: TargetProfile): string {
    return recon.generateRustscanOutput(this, domain, targetProfile);
  }

  // ============================================================
  // Enumeration
  // ============================================================
  generateFfufOutput(domain: string, targetProfile: TargetProfile): string {
    return enumOutputs.generateFfufOutput(this, domain, targetProfile);
  }

  generateFeroxbusterOutput(domain: string, targetProfile: TargetProfile): string {
    return enumOutputs.generateFeroxbusterOutput(this, domain, targetProfile);
  }

  generateGobusterOutput(domain: string, targetProfile: TargetProfile): string {
    return enumOutputs.generateGobusterOutput(this, domain, targetProfile);
  }

  generateWfuzzOutput(domain: string, targetProfile: TargetProfile): string {
    return enumOutputs.generateWfuzzOutput(this, domain, targetProfile);
  }

  generateKatanaOutput(domain: string, targetProfile: TargetProfile): string {
    return enumOutputs.generateKatanaOutput(this, domain, targetProfile);
  }

  // ============================================================
  // Vulnerability Scanning
  // ============================================================
  generateNucleiOutput(domain: string, targetProfile: TargetProfile): string {
    return vuln.generateNucleiOutput(this, domain, targetProfile);
  }

  generateNiktoOutput(domain: string, targetProfile: TargetProfile): string {
    return vuln.generateNiktoOutput(this, domain, targetProfile);
  }

  generateDalfoxOutput(domain: string, targetProfile: TargetProfile): string {
    return vuln.generateDalfoxOutput(this, domain, targetProfile);
  }

  generateSemgrepOutput(domain: string, targetProfile: TargetProfile): string {
    return vuln.generateSemgrepOutput(this, domain, targetProfile);
  }

  generateTestsslOutput(domain: string, targetProfile: TargetProfile): string {
    return vuln.generateTestsslOutput(this, domain, targetProfile);
  }

  generateTrufflehogOutput(domain: string, targetProfile: TargetProfile): string {
    return vuln.generateTrufflehogOutput(this, domain, targetProfile);
  }

  // ============================================================
  // Exploitation
  // ============================================================
  generateSqlmapOutput(domain: string, targetProfile: TargetProfile, phase: "detect" | "enumerate" | "dump" | "os"): string {
    return exploit.generateSqlmapOutput(this, domain, targetProfile, phase);
  }

  generateNosqlmapOutput(domain: string, targetProfile: TargetProfile): string {
    return exploit.generateNosqlmapOutput(this, domain, targetProfile);
  }

  generateJwtOutput(phase: "decode" | "crack" | "attack"): string {
    return exploit.generateJwtOutput(this, phase);
  }

  generateHydraOutput(domain: string, targetProfile: TargetProfile): string {
    return exploit.generateHydraOutput(this, domain, targetProfile);
  }

  generateMetasploitOutput(domain: string, targetProfile: TargetProfile): string {
    return exploit.generateMetasploitOutput(this, domain, targetProfile);
  }

  generateHttpResponse(targetProfile: TargetProfile, endpoint: string, context: "api_json" | "error" | "auth" | "admin" | "ssrf"): string {
    return exploit.generateHttpResponse(this, targetProfile, endpoint, context);
  }

  generateLinpeasOutput(targetProfile: TargetProfile): string {
    return exploit.generateLinpeasOutput(this, targetProfile);
  }

  // ============================================================
  // Cloud
  // ============================================================
  generateS3Output(domain: string, targetProfile: TargetProfile): string {
    return cloud.generateS3Output(this, domain, targetProfile);
  }

  generateEnvFileOutput(targetProfile: TargetProfile): string {
    return cloud.generateEnvFileOutput(this, targetProfile);
  }

  // ============================================================
  // Failures
  // ============================================================
  generateFailureOutput(toolName: string, context: string): string {
    return failures.generateFailureOutput(this, toolName, context);
  }

  // ============================================================
  // Helper methods (used by delegate functions via OutputContext)
  // ============================================================
  timestamp(): string {
    return `${String(this.rng.int(0, 23)).padStart(2, "0")}:${String(this.rng.int(0, 59)).padStart(2, "0")}:${String(this.rng.int(0, 59)).padStart(2, "0")}`;
  }

  generateSqlPayload(param: string, technique: string, dbms: string): string {
    const payloads: Record<string, string[]> = {
      "boolean-based blind": [
        `${param}=test' AND ${this.rng.int(1000, 9999)}=${this.rng.int(1000, 9999)} AND '${this.rng.pick(["a", "x", "t"])}' = '${this.rng.pick(["a", "x", "t"])}`,
        `${param}=1 AND (SELECT ${this.rng.int(1000, 9999)} FROM (SELECT COUNT(*),CONCAT(0x7e,version(),0x7e,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)`,
      ],
      "time-based blind": [
        `${param}=test' AND (SELECT ${this.rng.int(1000, 9999)} FROM (SELECT(SLEEP(${this.rng.int(3, 7)})))a) AND 'a'='a`,
        `${param}=1; WAITFOR DELAY '0:0:${this.rng.int(3, 7)}'--`,
      ],
      "error-based": [
        `${param}=test' AND EXTRACTVALUE(${this.rng.int(1000, 9999)},CONCAT(0x7e,version()))-- -`,
        `${param}=1' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a)-- -`,
      ],
      "UNION query": [
        `${param}=test' UNION SELECT NULL,NULL,CONCAT(user(),0x7e,version()),NULL-- -`,
        `${param}=-1 UNION SELECT 1,2,3,group_concat(schema_name) FROM information_schema.schemata-- -`,
      ],
      "stacked queries": [
        `${param}=test'; SELECT SLEEP(${this.rng.int(3, 7)});-- -`,
      ],
    };
    return this.rng.pick(payloads[technique] || payloads["boolean-based blind"]);
  }

  generateRandomUser(): { username: string; email: string; role: string; password_hash: string } {
    const first = this.rng.pick(["james", "emma", "oliver", "sophia", "liam", "ava", "noah", "isabella", "william", "mia", "benjamin", "charlotte", "lucas", "amelia", "henry", "harper", "alexander", "evelyn", "daniel", "abigail", "carlos", "maria", "ahmed", "fatima", "yuki", "chen", "raj", "priya"]);
    const last = this.rng.pick(["smith", "johnson", "williams", "brown", "jones", "garcia", "miller", "davis", "rodriguez", "martinez", "wilson", "anderson", "taylor", "thomas", "moore", "jackson", "martin", "lee", "chen", "kumar", "patel", "kim"]);
    const domain = this.rng.pick(["gmail.com", "yahoo.com", "corp.com", "company.com", "protonmail.com", "outlook.com", "work.com"]);
    return {
      username: `${first}.${last}${this.rng.bool(0.3) ? this.rng.int(1, 99) : ""}`,
      email: `${first}.${last}@${domain}`,
      role: this.rng.pick(["admin", "user", "editor", "moderator", "superadmin", "viewer", "analyst", "manager", "support"]),
      password_hash: `$2b$12$${this.generateBase64(22)}`,
    };
  }

  generatePhone(): string {
    return `+${this.rng.pick(["1", "44", "49", "33", "61", "81", "86", "91"])}-${this.rng.int(200, 999)}-${this.rng.int(100, 999)}-${this.rng.int(1000, 9999)}`;
  }

  generateAddress(): string {
    return `${this.rng.int(1, 9999)} ${this.rng.pick(["Main", "Oak", "Elm", "Park", "Cedar", "Pine", "Maple", "Birch", "Lake", "River"])} ${this.rng.pick(["St", "Ave", "Blvd", "Dr", "Ln", "Way", "Rd"])}, ${this.rng.pick(["New York", "San Francisco", "London", "Berlin", "Tokyo", "Sydney", "Toronto", "Austin", "Seattle", "Boston"])} ${this.rng.int(10000, 99999)}`;
  }

  generateDate(): string {
    const y = this.rng.int(2023, 2025);
    const m = String(this.rng.int(1, 12)).padStart(2, "0");
    const d = String(this.rng.int(1, 28)).padStart(2, "0");
    return `${y}-${m}-${d}T${String(this.rng.int(0, 23)).padStart(2, "0")}:${String(this.rng.int(0, 59)).padStart(2, "0")}:${String(this.rng.int(0, 59)).padStart(2, "0")}Z`;
  }

  generateUUID(): string {
    return `${this.generateHex(8)}-${this.generateHex(4)}-${this.generateHex(4)}-${this.generateHex(4)}-${this.generateHex(12)}`;
  }

  generateHex(length: number): string {
    const chars = "0123456789abcdef";
    return Array.from({ length }, () => chars[Math.floor(this.rng.next() * 16)]).join("");
  }

  generateBase64(length: number): string {
    const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    return Array.from({ length }, () => chars[Math.floor(this.rng.next() * 64)]).join("");
  }

  generateAlphanumeric(length: number): string {
    const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    return Array.from({ length }, () => chars[Math.floor(this.rng.next() * 62)]).join("");
  }
}
