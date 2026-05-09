/**
 * YARA-style Custom Rule Engine
 *
 * Implementare simplificată a unui motor inspirat din YARA. Permite
 * userului să definească reguli prin DSL minimal:
 *
 *   rule MyMalware {
 *     meta:
 *       author = "analyst"
 *       severity = "critical"
 *     strings:
 *       $a = "malicious_string"
 *       $b = { 4D 5A 90 00 }
 *       $c = /[a-z]{5}\.exe/
 *     condition:
 *       $a and ($b or $c)
 *   }
 *
 * Suportă: string ASCII, hex pattern, regex, condiții logice (and/or/not),
 * și operatorul "any of" / "all of" / "N of".
 */

/**
 * Parsează un text cu reguli YARA-style și returnează structura.
 */
function parseRules(rulesText) {
  const rules = [];
  const ruleRegex = /rule\s+([A-Za-z_][\w]*)\s*\{([\s\S]*?)\n\}/g;
  let match;

  while ((match = ruleRegex.exec(rulesText)) !== null) {
    const name = match[1];
    const body = match[2];

    const meta = {};
    const metaSection = body.match(/meta\s*:\s*([\s\S]*?)(?:strings\s*:|condition\s*:)/);
    if (metaSection) {
      const lines = metaSection[1].split('\n');
      for (const line of lines) {
        const m = line.match(/(\w+)\s*=\s*"([^"]*)"/);
        if (m) meta[m[1]] = m[2];
      }
    }

    const strings = {};
    const stringsSection = body.match(/strings\s*:\s*([\s\S]*?)condition\s*:/);
    if (stringsSection) {
      const lines = stringsSection[1].split('\n');
      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed.startsWith('$')) continue;

        // Hex: $a = { 4D 5A ... }
        const hexMatch = trimmed.match(/\$(\w+)\s*=\s*\{\s*([0-9A-Fa-f\s?]+)\s*\}/);
        if (hexMatch) {
          strings[`$${hexMatch[1]}`] = { type: 'hex', value: hexMatch[2].replace(/\s+/g, '').toLowerCase() };
          continue;
        }

        // Regex: $a = /pattern/
        const regexMatch = trimmed.match(/\$(\w+)\s*=\s*\/(.+)\/([gimsu]*)/);
        if (regexMatch) {
          try {
            strings[`$${regexMatch[1]}`] = { type: 'regex', value: new RegExp(regexMatch[2], regexMatch[3] || '') };
          } catch {
            // skip invalid regex
          }
          continue;
        }

        // String ASCII: $a = "text"
        const strMatch = trimmed.match(/\$(\w+)\s*=\s*"([^"]*)"/);
        if (strMatch) {
          strings[`$${strMatch[1]}`] = { type: 'ascii', value: strMatch[2] };
        }
      }
    }

    const conditionSection = body.match(/condition\s*:\s*([\s\S]*?)$/);
    const condition = conditionSection ? conditionSection[1].trim() : 'false';

    rules.push({ name, meta, strings, condition });
  }

  return rules;
}

/**
 * Verifică dacă un string match-uiește în buffer.
 */
function matchString(buffer, def) {
  if (def.type === 'ascii') {
    return buffer.indexOf(def.value) !== -1;
  }
  if (def.type === 'hex') {
    const cleanHex = def.value.replace(/\?/g, ''); // ignorăm wildcards (simplificat)
    if (cleanHex.length % 2 !== 0) return false;
    const pat = Buffer.from(cleanHex, 'hex');
    return buffer.indexOf(pat) !== -1;
  }
  if (def.type === 'regex') {
    return def.value.test(buffer.toString('latin1'));
  }
  return false;
}

/**
 * Evaluează condiția unei reguli folosind hash-ul de match-uri.
 * Suportă: $a, $a and $b, $a or $b, not $a, "any of them", "N of them".
 */
function evaluateCondition(condition, matches, allStringIds) {
  let expr = condition;

  // "any of them"
  if (/\bany\s+of\s+them\b/i.test(expr)) {
    return Object.values(matches).some(Boolean);
  }
  // "all of them"
  if (/\ball\s+of\s+them\b/i.test(expr)) {
    return allStringIds.every((id) => matches[id]);
  }
  // "N of them"
  const nOfMatch = expr.match(/(\d+)\s+of\s+them/i);
  if (nOfMatch) {
    const n = parseInt(nOfMatch[1], 10);
    const count = Object.values(matches).filter(Boolean).length;
    return count >= n;
  }

  // Înlocuiește $a → true/false
  expr = expr.replace(/\$\w+/g, (token) => (matches[token] ? 'true' : 'false'));
  expr = expr.replace(/\band\b/gi, '&&');
  expr = expr.replace(/\bor\b/gi, '||');
  expr = expr.replace(/\bnot\b/gi, '!');

  // Doar caractere sigure permise
  if (!/^[\s!&|()truefals]+$/.test(expr)) return false;

  try {
    return Function(`"use strict"; return (${expr});`)();
  } catch {
    return false;
  }
}

/**
 * Rulează toate regulile pe un Buffer și returnează lista de match-uri.
 */
function runRules(buffer, rulesText) {
  if (!Buffer.isBuffer(buffer) || !rulesText) return { rules: [], matched: [] };

  const rules = parseRules(rulesText);
  const matched = [];

  for (const rule of rules) {
    const stringMatches = {};
    for (const [id, def] of Object.entries(rule.strings)) {
      stringMatches[id] = matchString(buffer, def);
    }

    const stringIds = Object.keys(rule.strings);
    const matchedCondition = evaluateCondition(rule.condition, stringMatches, stringIds);

    if (matchedCondition) {
      matched.push({
        name: rule.name,
        meta: rule.meta,
        matchedStrings: Object.entries(stringMatches).filter(([, v]) => v).map(([k]) => k),
        severity: rule.meta.severity || 'warning',
      });
    }
  }

  return { rules: rules.map((r) => ({ name: r.name, meta: r.meta })), matched };
}

module.exports = { parseRules, runRules };
