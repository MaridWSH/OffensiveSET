// Scenario and attack phase type definitions

export interface ScenarioTemplate {
  id: string;
  category: string;
  subcategory: string;
  title: string;
  difficulty: "beginner" | "intermediate" | "advanced" | "expert";
  description: string;
  target_description: string;
  attack_phases: AttackPhase[];
  cve_references?: string[];
  tools_involved: string[];
  tags: string[];
}

export interface AttackPhase {
  phase: string;
  description: string;
  tools: string[];
  commands: string[];
  expected_output: string;
  thinking?: string;  // Chain-of-thought reasoning
  analysis: string;
  next_action: string;
}
