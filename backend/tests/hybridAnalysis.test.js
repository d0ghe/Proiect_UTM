const test = require('node:test');
const assert = require('node:assert/strict');

const {
  extractCrowdStrikeVerdict,
  normalizeHashLookupPayload,
  normalizeQuickScanPayload,
  normalizeReportOverviewPayload,
} = require('../utils/hybridAnalysis');

test('normalizeQuickScanPayload maps malicious quick scans into infected provider verdicts', () => {
  const payload = {
    id: 'sample-123',
    status: 'finished',
    verdict: 'malicious',
    threat_score: 92,
    classification: 'trojan',
    scanners_v2: {
      crowdstrike_ml: {
        name: 'CrowdStrike ML',
        label: 'malicious',
        score: 0.99,
      },
    },
  };

  const quickScan = normalizeQuickScanPayload(payload);

  assert.equal(quickScan.id, 'sample-123');
  assert.equal(quickScan.finished, true);
  assert.equal(quickScan.verdict, 'INFECTED');
  assert.equal(quickScan.classification, 'trojan');
  assert.equal(quickScan.crowdStrike?.verdict, 'INFECTED');
});

test('normalizeHashLookupPayload keeps known clean samples clean', () => {
  const payload = [
    {
      id: 'known-clean',
      sha256: 'abc123',
      verdict: 'clean',
      classification: 'archive',
      threat_score: 0,
      state: 'finished',
    },
  ];

  const result = normalizeHashLookupPayload(payload);

  assert.equal(result.found, true);
  assert.equal(result.id, 'known-clean');
  assert.equal(result.verdict, 'CLEAN');
  assert.equal(result.classification, 'archive');
});

test('normalizeReportOverviewPayload exposes sandbox artifacts for the UI', () => {
  const payload = {
    id: 'report-1',
    state: 'finished',
    verdict: 'malicious',
    threat_score: 88,
    mitre_attcks: [{ attck_id: 'T1059' }],
    contacted_hosts: [{ host: 'example.org' }],
    dropped_files: [{ filename: 'dropper.exe' }],
    signatures: [{ name: 'Creates autorun key' }],
  };

  const report = normalizeReportOverviewPayload(payload);

  assert.equal(report.id, 'report-1');
  assert.equal(report.status, 'completed');
  assert.equal(report.verdict, 'INFECTED');
  assert.deepEqual(report.mitreTechniques, ['T1059']);
  assert.deepEqual(report.contactedHosts, ['example.org']);
  assert.deepEqual(report.droppedFiles, ['dropper.exe']);
  assert.deepEqual(report.signatures, ['Creates autorun key']);
});

test('extractCrowdStrikeVerdict finds Falcon scanner data in scanner collections', () => {
  const payload = {
    scanners: {
      falcon: {
        name: 'CrowdStrike Falcon',
        verdict: 'suspicious',
        confidence: 76,
      },
    },
  };

  const result = extractCrowdStrikeVerdict(payload);

  assert.equal(result?.id, 'crowdstrike-ml');
  assert.equal(result?.verdict, 'INFECTED');
  assert.equal(result?.metadata?.score, 76);
});
