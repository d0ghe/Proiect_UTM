/**
 * Heuristic Scoring Engine
 *
 * Agregă semnalele explicabile din modulele de analiză într-un scor de risc
 * unificat 0-100. Entropia este intenționat exclusă din scor deoarece fișierele
 * comprimate, media și binarele legitime pot avea entropie mare fără să fie
 * malițioase.
 *
 * Scoruri:
 *  0–14   → MINIMAL_RISK  — niciun indicator semnificativ
 *  15–54  → LOW_RISK      — câteva pattern-uri suspecte, probabil benign
 *  55–84  → MEDIUM_RISK   — multiple tehnici suspecte, necesită analiză
 *  85–100 → HIGH_RISK     — indicatori critici, probabil malițios
 */

/**
 * @typedef {Object} ScoringInput
 * @property {Array}  hexMatches      - Rezultate din hexSignatures.js
 * @property {Object} evasionResult   - Rezultat din detectEvasion()
 * @property {Object} injectionResult - Rezultat din detectSubbyteInjection()
 * @property {Object} peResult        - Rezultat din parsePE(), daca fisierul este PE
 */

function isPeHeaderAtFileStart(match) {
  return match?.name === 'PE_Executable_Header' && Number(match.offset || 0) === 0;
}

function isCommonPeLayoutWarning(match) {
  return isPeHeaderAtFileStart(match) || match?.name === 'Debugger_Trap_Sequence';
}

function scoreEvasionIndicator(indicator, isPortableExecutable) {
  const matchCount = Array.isArray(indicator?.matches) ? indicator.matches.length : 0;

  if (indicator?.category === 'dangerous_imports') {
    // For PE files these are usually normal Windows imports. Treat them as
    // context, not proof, unless they appear in a larger suspicious cluster.
    if (isPortableExecutable) {
      if (matchCount >= 8) return 8;
      if (matchCount >= 4) return 4;
      return 1;
    }

    return indicator.severity === 'critical' ? 16 : 6;
  }

  if (indicator?.category === 'anti_debug') {
    return isPortableExecutable ? Math.min(8, matchCount * 2) : 8;
  }

  if (indicator?.category === 'anti_vm') {
    return isPortableExecutable ? Math.min(6, matchCount * 2) : 8;
  }

  if (indicator?.category === 'packer') {
    return isPortableExecutable ? 8 : 6;
  }

  return indicator?.severity === 'critical' ? 12 : 4;
}

function scoreEvasionResult(evasionResult, isPortableExecutable) {
  if (!evasionResult || !Array.isArray(evasionResult.indicators)) {
    return 0;
  }

  const score = evasionResult.indicators.reduce(
    (total, indicator) => total + scoreEvasionIndicator(indicator, isPortableExecutable),
    0,
  );

  return Math.min(score, isPortableExecutable ? 22 : 36);
}

function scoreInjectionResult(injectionResult, isPortableExecutable) {
  if (!injectionResult) {
    return 0;
  }

  const largeCaves = (injectionResult.codeCaves || []).filter((c) => c.size > (isPortableExecutable ? 16384 : 4096)).length;
  const veryLargeCaves = (injectionResult.codeCaves || []).filter((c) => c.size > 65536).length;
  const appendedPayloads = isPortableExecutable ? 0 : (injectionResult.appendedPayloads || []).length;
  const polyglot = (injectionResult.polyglot || []).length;

  // PE files often contain null padding and alignment gaps. Score only very
  // large cave clusters lightly; non-PE payloads need stronger structure before
  // they become review-worthy.
  return Math.min(
    veryLargeCaves * (isPortableExecutable ? 5 : 8)
    + largeCaves * (isPortableExecutable ? 2 : 5)
    + appendedPayloads * 18
    + polyglot * 12,
    isPortableExecutable ? 18 : 30,
  );
}

function scorePeAnomalies(peResult) {
  if (!peResult?.isValidPE || !Array.isArray(peResult.anomalies)) {
    return 0;
  }

  const critical = peResult.anomalies.filter((item) => item.severity === 'critical').length;
  const warning = peResult.anomalies.filter((item) => item.severity === 'warning').length;
  return Math.min(critical * 18 + warning * 4, 30);
}

/**
 * Calculează scorul euristic complet pe baza tuturor semnalelor disponibile.
 *
 * @param {ScoringInput} input
 * @returns {{ score: number, verdict: string, reasons: string[], breakdown: Object }}
 */
function computeHeuristicScore({ hexMatches, evasionResult, injectionResult, peResult } = {}) {
  let score = 0;
  const reasons = [];
  const evasionIndicators = Array.isArray(evasionResult?.indicators) ? evasionResult.indicators : [];
  const codeCaves = Array.isArray(injectionResult?.codeCaves) ? injectionResult.codeCaves : [];
  const appendedPayloads = Array.isArray(injectionResult?.appendedPayloads) ? injectionResult.appendedPayloads : [];
  const polyglot = Array.isArray(injectionResult?.polyglot) ? injectionResult.polyglot : [];
  const breakdown = {
    hexSignatures: 0,
    evasion: 0,
    injection: 0,
    pe: 0,
  };
  const isPortableExecutable = Boolean(peResult?.isValidPE);
  const scoredAppendedPayloads = isPortableExecutable ? [] : appendedPayloads;

  // ─── Contribuție semnături hex ─────────────────────────────────────────────
  if (Array.isArray(hexMatches) && hexMatches.length > 0) {
    const criticalHex = hexMatches.filter((m) => m.severity === 'critical').length;
    const warningHexMatches = hexMatches.filter((m) => (
      m.severity === 'warning'
      && !(isPortableExecutable && isCommonPeLayoutWarning(m))
    ));
    const warningHex = warningHexMatches.length;
    const hexScore = Math.min(criticalHex * 30 + warningHex * 8, 40);
    score += hexScore;
    breakdown.hexSignatures = hexScore;

    if (criticalHex > 0) {
      reasons.push(`${criticalHex} critical hex signature(s) (shellcode/EICAR)`);
    }
    if (warningHex > 0) {
      reasons.push(`${warningHex} suspicious or embedded binary header(s) (ELF/OLE2/PE in body)`);
    }
  }

  // ─── Contribuție entropie ──────────────────────────────────────────────────
  // ─── Contribuție detecție evaziune ────────────────────────────────────────
  if (evasionResult) {
    const evasionScore = scoreEvasionResult(evasionResult, isPortableExecutable);
    score += evasionScore;
    breakdown.evasion = evasionScore;

    for (const ind of evasionIndicators) {
      if (ind.category === 'dangerous_imports' && (!isPortableExecutable || ind.matches.length >= 4)) {
        reasons.push(`${ind.matches.length} dual-use API import(s) (injection/network/keylogging)`);
      }
      if (ind.category === 'anti_debug') {
        reasons.push(`Anti-debug techniques detected (${ind.matches.length} APIs)`);
      }
      if (ind.category === 'anti_vm') {
        reasons.push(`Anti-VM/sandbox indicators (${ind.matches.length} strings)`);
      }
      if (ind.category === 'packer') {
        reasons.push(`Packer detected: ${ind.matches.join(', ')}`);
      }
    }
  }

  // ─── Contribuție injecție sub-byte ────────────────────────────────────────
  if (injectionResult) {
    const injectionScore = scoreInjectionResult(injectionResult, isPortableExecutable);
    score += injectionScore;
    breakdown.injection = injectionScore;

    const codeCaveReasonThreshold = isPortableExecutable ? 65536 : 1024;
    const largeCaves = codeCaves.filter((c) => c.size > codeCaveReasonThreshold).length;
    if (largeCaves > 0) {
      reasons.push(`${largeCaves} large code cave(s) (>${Math.round(codeCaveReasonThreshold / 1024)}KB) - possible hidden shellcode`);
    }
    if (scoredAppendedPayloads.length > 0) {
      reasons.push(`Content detected after EOF (${scoredAppendedPayloads.map((p) => p.type).join(', ')})`);
    }
    if (polyglot.length > 0) {
      const formats = polyglot[0]?.formats || [];
      reasons.push(`Polyglot file: ${formats.join(' + ')}`);
    }
  }

  const peScore = scorePeAnomalies(peResult);
  if (peScore > 0) {
    score += peScore;
    breakdown.pe = peScore;

    const criticalAnomalies = (peResult.anomalies || []).filter((item) => item.severity === 'critical').length;
    const warningAnomalies = (peResult.anomalies || []).filter((item) => item.severity === 'warning').length;
    if (criticalAnomalies > 0) {
      reasons.push(`${criticalAnomalies} critical PE anomal${criticalAnomalies === 1 ? 'y' : 'ies'}`);
    }
    if (warningAnomalies > 0) {
      reasons.push(`${warningAnomalies} PE anomal${warningAnomalies === 1 ? 'y' : 'ies'} to review`);
    }
  }

  const finalScore = Math.min(score, 100);

  let verdict;
  if (finalScore >= 85) {
    verdict = 'HIGH_RISK';
  } else if (finalScore >= 55) {
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
