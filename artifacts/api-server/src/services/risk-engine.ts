export interface RiskInput {
  baseScore: number;
  confidence: number;
  indicatorsCount: number;
  criticalityMultiplier?: number;
  hasCredentialThreat?: boolean;
}

export class RiskEngine {
  static evaluateRisk(input: RiskInput): { score: number; severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" } {
    let score = input.baseScore;

    // Apply confidence weighting
    if (input.confidence > 90) {
      score = score * 1.05;
    } else if (input.confidence < 60) {
      score = score * 0.85;
    }

    if (input.hasCredentialThreat) {
      score += 12;
    }

    if (input.indicatorsCount > 3) {
      score += 8;
    }

    const finalScore = Math.min(100, Math.max(0, Math.round(score)));

    let severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" = "LOW";
    if (finalScore >= 81) {
      severity = "CRITICAL";
    } else if (finalScore >= 61) {
      severity = "HIGH";
    } else if (finalScore >= 31) {
      severity = "MEDIUM";
    } else {
      severity = "LOW";
    }

    return { score: finalScore, severity };
  }
}
