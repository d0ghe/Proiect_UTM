const test = require('node:test');
const assert = require('node:assert/strict');

const {
  createHybridAnalysisClient,
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

test('normalizeHashLookupPayload accepts official search/hash report collections', () => {
  const sha256 = 'a'.repeat(64);
  const payload = {
    sha256s: [sha256],
    reports: [
      {
        id: 'report-123',
        environment_id: 160,
        state: 'SUCCESS',
        verdict: 'malicious',
      },
    ],
  };

  const result = normalizeHashLookupPayload(payload);

  assert.equal(result.found, true);
  assert.equal(result.id, 'report-123');
  assert.equal(result.sha256, sha256);
  assert.equal(result.verdict, 'INFECTED');
});

test('normalizeQuickScanPayload preserves sha256 and pending quick scan ids', () => {
  const sha256 = 'b'.repeat(64);
  const payload = {
    id: 'quick-123',
    sha256,
    finished: false,
    scanners_v2: {
      crowdstrike_ml: {
        name: 'CrowdStrike ML',
        status: 'no-result',
      },
    },
  };

  const quickScan = normalizeQuickScanPayload(payload);

  assert.equal(quickScan.id, 'quick-123');
  assert.equal(quickScan.quickScanId, 'quick-123');
  assert.equal(quickScan.sha256, sha256);
  assert.equal(quickScan.status, 'queued');
  assert.equal(quickScan.finished, false);
  assert.equal(quickScan.crowdStrike?.verdict, null);
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

test('quickScanFile hydrates completed quick scans from the overview endpoint', async () => {
  const sha256 = 'c'.repeat(64);
  const calls = [];
  const originalFetch = global.fetch;

  global.fetch = async (url, options) => {
    calls.push({ method: options.method, url: url.toString() });
    if (url.pathname === '/api/v2/quick-scan/file') {
      return new Response(JSON.stringify({
        id: 'quick-finished',
        sha256,
        finished: true,
      }), {
        status: 201,
        headers: { 'content-type': 'application/json' },
      });
    }

    if (url.pathname === `/api/v2/overview/${sha256}`) {
      return new Response(JSON.stringify({
        sha256,
        verdict: 'malicious',
        threat_score: 92,
        vx_family: 'trojan',
      }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    }

    return new Response(JSON.stringify({ message: 'not found' }), {
      status: 404,
      headers: { 'content-type': 'application/json' },
    });
  };

  try {
    const client = createHybridAnalysisClient({
      config: {
        apiKey: 'test-key',
        baseUrl: 'https://hybrid-analysis.com/api/v2',
        enabled: true,
        requestTimeoutMs: 1000,
        pollIntervalMs: 1,
        pollTimeoutMs: 5,
      },
    });
    const result = await client.quickScanFile({
      buffer: Buffer.from('hello'),
      mimetype: 'text/plain',
      originalname: 'sample.txt',
    });

    assert.equal(result.verdict, 'INFECTED');
    assert.equal(result.threatScore, 92);
    assert.equal(result.classification, 'trojan');
    assert.equal(calls.some((call) => call.url.endsWith(`/overview/${sha256}`)), true);
  } finally {
    global.fetch = originalFetch;
  }
});

test('getReportOverview returns running state before summary is available', async () => {
  const calls = [];
  const originalFetch = global.fetch;

  global.fetch = async (url, options) => {
    calls.push({ method: options.method, url: url.toString() });
    if (url.pathname === '/api/v2/report/job-123/state') {
      return new Response(JSON.stringify({ state: 'IN_PROGRESS' }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    }

    return new Response(JSON.stringify({ message: 'not found' }), {
      status: 404,
      headers: { 'content-type': 'application/json' },
    });
  };

  try {
    const client = createHybridAnalysisClient({
      config: {
        apiKey: 'test-key',
        baseUrl: 'https://hybrid-analysis.com/api/v2',
        enabled: true,
        requestTimeoutMs: 1000,
      },
    });
    const result = await client.getReportOverview('job-123');

    assert.equal(result.status, 'running');
    assert.equal(calls.some((call) => call.url.endsWith('/summary')), false);
  } finally {
    global.fetch = originalFetch;
  }
});

test('getReportOverview reads completed sandbox summaries from report summary endpoint', async () => {
  const sha256 = 'd'.repeat(64);
  const originalFetch = global.fetch;

  global.fetch = async (url) => {
    if (url.pathname === '/api/v2/report/job-456/state') {
      return new Response(JSON.stringify({ state: 'SUCCESS' }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    }

    if (url.pathname === '/api/v2/report/job-456/summary') {
      return new Response(JSON.stringify({
        job_id: 'job-456',
        sha256,
        state: 'SUCCESS',
        verdict: 'malicious',
        threat_score: 88,
        mitre_attcks: [{ attck_id: 'T1059' }],
      }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    }

    return new Response(JSON.stringify({ message: 'not found' }), {
      status: 404,
      headers: { 'content-type': 'application/json' },
    });
  };

  try {
    const client = createHybridAnalysisClient({
      config: {
        apiKey: 'test-key',
        baseUrl: 'https://hybrid-analysis.com/api/v2',
        enabled: true,
        requestTimeoutMs: 1000,
      },
    });
    const result = await client.getReportOverview('job-456', {
      environmentId: 160,
      sha256,
    });

    assert.equal(result.status, 'completed');
    assert.equal(result.verdict, 'INFECTED');
    assert.deepEqual(result.mitreTechniques, ['T1059']);
    assert.equal(result.reportUrl, `https://hybrid-analysis.com/sample/${sha256}/job-456`);
  } finally {
    global.fetch = originalFetch;
  }
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
