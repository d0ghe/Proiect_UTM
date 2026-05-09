/**
 * Heuristic Scoring Engine
 *
 * Agregă semnalele din toate modulele de analiză (hex signatures, entropie,
 * detecție evaziune, injecție sub-byte) într-un scor de risc unificat 0–100.
 *
 * Scoruri:
 *  0–14   → MINIMAL_RISK  — niciun indicator semnificativ
 *  15–39  → LOW_RISK      — câteva pattern-uri suspecte, probabil benign
 *  40–69  → MEDIUM_RISK   — multiple tehnici suspecte, necesită analiză
 *  70–100 → HIGH_RISK     — indicatori critici, probabil malițios
 */

/**
 * @typedef {Object} ScoringInput
 * @property {Array}  hexMatches      - Rezultate din hexSignatures.js
 * @property {Object} entropyResult   - Rezultat din analyzeEntropy()
 * @property {Object} evasionResult   - Rezultat din detectEvasion()
 * @property {Object} injectionResult - Rezultat din detectSubbyteInjection()
 */

/**
 * Calculează scorul euristic complet pe baza tuturor semnalelor disponibile.
 *
 * @param {ScoringInput} input
 * @returns {{ score: number, verdict: string, reasons: string[], breakdown: Object }}
 */
function computeHeuristicScore({ hexMatches, entropyResult, evasionResult, injectionResult }) {
  let score = 0;
  const reasons = [];
  const breakdown = {
    hexSignatures: 0,
    entropy: 0,
    evasion: 0,
    injection: 0,
  };

  // ─── Contribuție semnături hex ─────────────────────────────────────────────
  if (Array.isArray(hexMatches) && hexMatches.length > 0) {
    const criticalHex = hexMatches.filter((m) => m.severity === 'critical').length;
    const warningHex = hexMatches.filter((m) => m.severity === 'warning').length;
    const hexScore = Math.min(criticalHex * 30 + warningHex * 8, 40);
    score += hexScore;
    breakdown.hexSignatures = hexScore;

    if (criticalHex > 0) {
      reasons.push(`${criticalHex} semnătură(i) hex critică(e) (shellcode/EICAR)`);
    }
    if (warningHex > 0) {
      reasons.push(`${warningHex} header(e) binar(e) suspecte (PE/ELF/OLE2)`);
    }
  }

  // ─── Contribuție entropie ──────────────────────────────────────────────────
  if (entropyResult) {
    let entropyScore = 0;

    if (entropyResult.verdict === 'likely_encrypted_or_packed') {
      entropyScore = 25;
      reasons.push(`Entropie Shannon foarte ridicată (${entropyResult.overall}/8.0) — probabil criptat/packed`);
    } else if (entropyResult.verdict === 'suspicious_high_entropy') {
      entropyScore = 10;
      reasons.push(`Entropie Shannon ridicată (${entropyResult.overall}/8.0)`);
    }

    if (entropyResult.highEntropyRatio > 0.6) {
      entropyScore += 10;
      reasons.push(`${Math.round(entropyResult.highEntropyRatio * 100)}% din blocuri au entropie > 7.0`);
    }

    score += Math.min(entropyScore, 30);
    breakdown.entropy = Math.min(entropyScore, 30);
  }

  // ─── Contribuție detecție evaziune ────────────────────────────────────────
  if (evasionResult) {
    score += evasionResult.riskContribution;
    breakdown.evasion = evasionResult.riskContribution;

    for (const ind of evasionResult.indicators) {
      if (ind.category === 'dangerous_imports') {
        reasons.push(`${ind.matches.length} import(uri) API periculoase (injecție/rețea/keylog)`);
      }
      if (ind.category === 'anti_debug') {
        reasons.push(`Tehnici anti-debug detectate (${ind.matches.length} API-uri)`);
      }
      if (ind.category === 'anti_vm') {
        reasons.push(`Indicatori anti-VM/sandbox (${ind.matches.length} string-uri)`);
      }
      if (ind.category === 'packer') {
        reasons.push(`Packer detectat: ${ind.matches.join(', ')}`);
      }
    }
  }

  // ─── Contribuție injecție sub-byte ────────────────────────────────────────
  if (injectionResult) {
    score += injectionResult.riskContribution;
    breakdown.injection = injectionResult.riskContribution;

    const largeCaves = injectionResult.codeCaves.filter((c) => c.size > 1024).length;
    if (largeCaves > 0) {
      reasons.push(`${largeCaves} code cave(uri) mari (> 1KB) — posibil shellcode ascuns`);
    }
    if (injectionResult.appendedPayloads.length > 0) {
      reasons.push(`Conținut detectat după EOF (${injectionResult.appendedPayloads.map((p) => p.type).join(', ')})`);
    }
    if (injectionResult.polyglot.length > 0) {
      const formats = injectionResult.polyglot[0]?.formats || [];
      reasons.push(`Fișier polyglot: ${formats.join(' + ')}`);
    }
  }

  const finalScore = Math.min(score, 100);

  let verdict;
  if (finalScore >= 70) {
    verdict = 'HIGH_RISK';
  } else if (finalScore >= 40) {
    verdict = 'MEDIUM_RISK';
  } else if (finalScore >= 15) {
    verdict = 'LOW_RISK';
  } else {
    verdict = 'MINIMAL_RISK';
  }

  return {
    score: finalScore,
    verdict,
    reasons,
    breakdown,
  };
}

module.exports = { computeHeuristicScore };
