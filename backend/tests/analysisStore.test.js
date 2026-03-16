const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { createAnalysisStore } = require('../store/analysisStore');

test('analysis store persists jobs and summaries', () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'analysis-store-'));
  const storePath = path.join(tempDir, 'jobs.json');
  const store = createAnalysisStore(storePath);

  const job = store.createAnalysisJob({
    provider: 'falcon-sandbox',
    filename: 'sample.exe',
    sha256: 'hash-1',
    status: 'queued',
    history: [{ title: 'Queued', detail: 'Sample queued.' }],
  });

  const updated = store.updateAnalysisJob(job.id, {
    status: 'completed',
    verdict: 'INFECTED',
    reportUrl: 'https://example.test/report',
  }, {
    title: 'Completed',
    detail: 'Sample completed.',
    severity: 'critical',
  });

  const reloadedStore = createAnalysisStore(storePath);
  const persisted = reloadedStore.getAnalysisJob(job.id);
  const summary = reloadedStore.summarizeAnalysisJobs();

  assert.equal(updated.status, 'completed');
  assert.equal(persisted.verdict, 'INFECTED');
  assert.equal(persisted.history.length, 2);
  assert.equal(summary.total, 1);
  assert.equal(summary.completed, 1);
  assert.equal(summary.malicious, 1);
});
