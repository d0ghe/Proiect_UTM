const assert = require('assert/strict');
const { test } = require('node:test');

const { computeHeuristicScore } = require('../utils/heuristicScorer');
const { runRules } = require('../utils/yaraEngine');
const { getRulesText } = require('../store/yaraStore');

test('valid PE header at file start is not scored as an embedded suspicious header', () => {
  const result = computeHeuristicScore({
    hexMatches: [
      { name: 'PE_Executable_Header', severity: 'warning', offset: 0 },
      { name: 'Debugger_Trap_Sequence', severity: 'warning', offset: 4096 },
    ],
    entropyResult: { verdict: 'normal', highEntropyRatio: 0, overall: 5.1 },
    evasionResult: { indicators: [], riskContribution: 0 },
    injectionResult: { codeCaves: [], appendedPayloads: [], polyglot: [], riskContribution: 0 },
    peResult: { isValidPE: true, anomalies: [] },
  });

  assert.equal(result.breakdown.hexSignatures, 0);
  assert.equal(result.score, 0);
  assert.equal(result.verdict, 'MINIMAL_RISK');
});

test('generic PE imports and alignment padding stay below local review threshold', () => {
  const result = computeHeuristicScore({
    hexMatches: [{ name: 'PE_Executable_Header', severity: 'warning', offset: 0 }],
    entropyResult: { verdict: 'normal', highEntropyRatio: 0, overall: 6.2 },
    evasionResult: {
      indicators: [
        {
          category: 'dangerous_imports',
          severity: 'critical',
          matches: ['OpenProcess', 'CreateProcess', 'WSAStartup'],
        },
      ],
      riskContribution: 25,
    },
    injectionResult: {
      codeCaves: [{ size: 8192 }, { size: 12000 }],
      appendedPayloads: [
        { type: 'JPEG_EOI', bytesAfter: 26000 },
        { type: 'PNG_IEND', bytesAfter: 43000 },
      ],
      polyglot: [],
      riskContribution: 40,
    },
    peResult: { isValidPE: true, anomalies: [] },
  });

  assert.ok(result.score < 15);
  assert.equal(result.verdict, 'MINIMAL_RISK');
});

test('Cobalt Strike builtin rule does not match a generic PE MZ header', () => {
  const mzHeader = Buffer.from('4d5a90000300000004000000ffff0000b800000000000000', 'hex');
  const result = runRules(mzHeader, getRulesText());

  assert.equal(result.matched.some((match) => match.name === 'Cobalt_Strike'), false);
});

test('Cobalt Strike builtin rule still matches specific beacon indicators', () => {
  const sample = Buffer.from('loader config contains cobaltstrike beacon.x64.dll', 'utf8');
  const result = runRules(sample, getRulesText());

  assert.equal(result.matched.some((match) => match.name === 'Cobalt_Strike'), true);
});
