// SmartContractOutputEngine — composed from modular output generators for smart contract security

import { SeededRNG, generateContractProfile, generateAddress, generateTxHash, generateBlockNumber, generateAmount, generateGasUsed, generateRandomAuditor, generateTimestamp } from "./helpers.js";
import type { ContractProfile, StateVar, FuncDef, OutputContext } from "./helpers.js";

export { SeededRNG, generateContractProfile } from "./helpers.js";
export type { ContractProfile, StateVar, FuncDef, OutputContext } from "./helpers.js";

import * as analysis from "./analysis.js";
import * as testing from "./testing.js";
import * as exploitation from "./exploitation.js";
import * as code from "./code.js";
import * as failures from "./failures.js";

export class SmartContractOutputEngine implements OutputContext {
  rng: SeededRNG;

  constructor(seed: number) {
    this.rng = new SeededRNG(seed);
  }

  // ============================================================
  // Analysis
  // ============================================================
  generateSlitherOutput(profile: ContractProfile): string {
    return analysis.generateSlitherOutput(this, profile);
  }

  generateMythrilOutput(profile: ContractProfile): string {
    return analysis.generateMythrilOutput(this, profile);
  }

  // ============================================================
  // Testing
  // ============================================================
  generateForgeTestOutput(profile: ContractProfile): string {
    return testing.generateForgeTestOutput(this, profile);
  }

  generateEchidnaOutput(profile: ContractProfile): string {
    return testing.generateEchidnaOutput(this, profile);
  }

  // ============================================================
  // Exploitation / Interaction
  // ============================================================
  generateCastCallOutput(profile: ContractProfile, functionName: string, args?: string): string {
    return exploitation.generateCastCallOutput(this, profile, functionName, args);
  }

  generateAnvilOutput(profile: ContractProfile): string {
    return exploitation.generateAnvilOutput(this, profile);
  }

  // ============================================================
  // Code Generation
  // ============================================================
  generateVulnerableCodeSnippet(profile: ContractProfile): string {
    return code.generateVulnerableCodeSnippet(this, profile);
  }

  generatePoCTestCode(profile: ContractProfile): string {
    return code.generatePoCTestCode(this, profile);
  }

  // ============================================================
  // Failures
  // ============================================================
  generateCompileError(profile: ContractProfile): string {
    return failures.generateCompileError(this, profile);
  }

  generateTestFailure(profile: ContractProfile): string {
    return failures.generateTestFailure(this, profile);
  }

  generateSlitherFalsePositive(profile: ContractProfile): string {
    return failures.generateSlitherFalsePositive(this, profile);
  }

  // ============================================================
  // Helper methods
  // ============================================================
  generateDate(): string {
    const y = this.rng.int(2024, 2026);
    const m = String(this.rng.int(1, 12)).padStart(2, "0");
    const d = String(this.rng.int(1, 28)).padStart(2, "0");
    return `${y}-${m}-${d}`;
  }

  generateUUID(): string {
    return `${this.generateHex(8)}-${this.generateHex(4)}-${this.generateHex(4)}-${this.generateHex(4)}-${this.generateHex(12)}`;
  }

  generateHex(length: number): string {
    const chars = "0123456789abcdef";
    return Array.from({ length }, () => chars[Math.floor(this.rng.next() * 16)]).join("");
  }

  generateAddress(): string {
    return generateAddress(this.rng);
  }

  generateTxHash(): string {
    return generateTxHash(this.rng);
  }

  generateBlockNumber(): number {
    return generateBlockNumber(this.rng);
  }

  generateAmount(): string {
    return generateAmount(this.rng);
  }

  generateGasUsed(): number {
    return generateGasUsed(this.rng);
  }

  generateRandomAuditor(): { handle: string; firm: string } {
    return generateRandomAuditor(this.rng);
  }

  generateTimestamp(): number {
    return generateTimestamp(this.rng);
  }
}
