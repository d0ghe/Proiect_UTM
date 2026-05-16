/**
 * Script Deobfuscator
 *
 * Detectează tehnici de obfuscare în scripturi malițioase:
 *  - PowerShell: -EncodedCommand, IEX (FromBase64String), Invoke-Expression
 *  - JavaScript/VBScript: eval(), Function(), char concatenation, escape()
 *  - Common: string reverse, char-code arrays, document.write tricks
 */

const POWERSHELL_INDICATORS = [
  { regex: /-encodedcommand|-enc\b/i, name: 'PowerShell -EncodedCommand', severity: 'critical', description: 'PowerShell encoded command (Base64) - standard AV bypass technique.' },
  { regex: /\biex\s*\(|invoke-expression/i, name: 'IEX/Invoke-Expression', severity: 'critical', description: 'Dynamic code execution through IEX/Invoke-Expression.' },
  { regex: /frombase64string/i, name: 'FromBase64String', severity: 'warning', description: 'Runtime Base64 decoding.' },
  { regex: /downloadstring|webclient|net\.webclient/i, name: 'WebClient.DownloadString', severity: 'critical', description: 'Download remote code (download cradle).' },
  { regex: /bypass|hidden|noprofile/i, name: 'Execution Policy Bypass', severity: 'warning', description: 'PowerShell execution policy bypass.' },
  { regex: /\$\{[a-z]\}|`[a-z]/i, name: 'Variable Obfuscation', severity: 'warning', description: 'Variable/backtick obfuscation.' },
  { regex: /\.gettype\(\)\.assembly|reflection/i, name: 'Reflection Abuse', severity: 'warning', description: '.NET reflection abuse.' },
];

const JS_INDICATORS = [
  { regex: /\beval\s*\(/i, name: 'eval()', severity: 'critical', description: 'eval() - dynamic code execution.' },
  { regex: /new\s+function\s*\(/i, name: 'new Function()', severity: 'critical', description: 'Function constructor - indirect eval.' },
  { regex: /unescape\s*\(|decodeuricomponent/i, name: 'unescape/decodeURIComponent', severity: 'warning', description: 'URL-encoded decoding - obfuscated payload.' },
  { regex: /string\.fromcharcode/i, name: 'String.fromCharCode', severity: 'warning', description: 'String construction from ASCII codes - classic obfuscation.' },
  { regex: /atob\s*\(|btoa\s*\(/i, name: 'atob/btoa', severity: 'warning', description: 'Base64 encoding in JavaScript.' },
  { regex: /document\.write\s*\(.*unescape/i, name: 'document.write(unescape(', severity: 'critical', description: 'Classic drive-by injection.' },
];

const VBS_INDICATORS = [
  { regex: /\bexecute\s*\(|\bexecuteglobal/i, name: 'Execute/ExecuteGlobal', severity: 'critical', description: 'VBScript Execute - eval equivalent.' },
  { regex: /createobject\s*\(\s*["']wscript\.shell/i, name: 'WScript.Shell.Run', severity: 'critical', description: 'VBScript spawns shell processes.' },
  { regex: /msxml2\.xmlhttp|microsoft\.xmlhttp/i, name: 'XMLHTTP download', severity: 'warning', description: 'VBScript download cradle.' },
  { regex: /chr\s*\(\s*\d+\s*\)/i, name: 'Chr() obfuscation', severity: 'warning', description: 'String construction from character codes (Chr).' },
];

function detectLanguage(text, filename = '') {
  const lower = text.toLowerCase();
  const fname = (filename || '').toLowerCase();

  if (fname.endsWith('.ps1') || fname.endsWith('.psm1')) return 'powershell';
  if (fname.endsWith('.vbs') || fname.endsWith('.vbe')) return 'vbscript';
  if (fname.endsWith('.js') || fname.endsWith('.jse')) return 'javascript';
  if (fname.endsWith('.bat') || fname.endsWith('.cmd')) return 'batch';

  // Heuristici pe conținut
  if (/\$[a-z]+\s*=|invoke-|cmdlet|param\s*\(/i.test(lower)) return 'powershell';
  if (/dim\s+\w+|sub\s+\w+|wscript\.|createobject/i.test(lower)) return 'vbscript';
  if (/var\s+\w+\s*=|function\s+\w+|=\>\s*{|let\s+\w+\s*=/i.test(lower)) return 'javascript';

  return 'unknown';
}

/**
 * Calculează un "obfuscation score" bazat pe densitatea caracterelor non-alfanumerice
 * și pe lungimea liniilor. Scripturile obfuscate au scoruri mari.
 */
function obfuscationDensity(text) {
  const lines = text.split('\n');
  const longLines = lines.filter((l) => l.length > 200).length;
  const totalLen = text.length;
  if (totalLen === 0) return 0;

  let nonAlpha = 0;
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (!((c >= 65 && c <= 90) || (c >= 97 && c <= 122) || (c >= 48 && c <= 57) || c === 32)) {
      nonAlpha++;
    }
  }

  return {
    nonAlphaRatio: parseFloat((nonAlpha / totalLen).toFixed(3)),
    longLines,
    totalLines: lines.length,
    suspicious: nonAlpha / totalLen > 0.45 || longLines > 3,
  };
}

/**
 * Analizează un buffer ca posibil script malițios.
 */
function analyzeScript(buffer, filename = '') {
  if (!Buffer.isBuffer(buffer) || buffer.length === 0) {
    return { language: 'unknown', findings: [], density: null, riskContribution: 0 };
  }

  const text = buffer.toString('utf8');
  const language = detectLanguage(text, filename);

  let indicators = [];
  if (language === 'powershell') indicators = POWERSHELL_INDICATORS;
  else if (language === 'javascript') indicators = JS_INDICATORS;
  else if (language === 'vbscript') indicators = VBS_INDICATORS;
  else {
    // Pentru text necunoscut, încearcă toate
    indicators = [...POWERSHELL_INDICATORS, ...JS_INDICATORS, ...VBS_INDICATORS];
  }

  const findings = [];
  for (const ind of indicators) {
    if (ind.regex.test(text)) {
      findings.push({
        name: ind.name,
        severity: ind.severity,
        description: ind.description,
        language,
      });
    }
  }

  const density = obfuscationDensity(text);
  if (density.suspicious) {
    findings.push({
      name: 'High Obfuscation Density',
      severity: 'warning',
      description: `${Math.round(density.nonAlphaRatio * 100)}% non-alpha + ${density.longLines} lines > 200 char.`,
      language,
    });
  }

  const criticalCount = findings.filter((f) => f.severity === 'critical').length;
  const warningCount = findings.filter((f) => f.severity === 'warning').length;
  const riskContribution = Math.min(criticalCount * 20 + warningCount * 8, 40);

  return { language, findings, density, riskContribution };
}

module.exports = { analyzeScript };
