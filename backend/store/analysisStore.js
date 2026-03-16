const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const DEFAULT_FILE = path.join(__dirname, 'analysis-jobs.json');

function clone(value) {
  return value === undefined ? undefined : JSON.parse(JSON.stringify(value));
}

function sortJobsNewestFirst(left, right) {
  const rightTime = new Date(right?.updatedAt || right?.createdAt || 0).getTime();
  const leftTime = new Date(left?.updatedAt || left?.createdAt || 0).getTime();
  return rightTime - leftTime;
}

function createAnalysisStore(storeFile = process.env.HYBRID_ANALYSIS_STORE_FILE || DEFAULT_FILE) {
  function ensureStoreFile() {
    const directory = path.dirname(storeFile);
    if (!fs.existsSync(directory)) {
      fs.mkdirSync(directory, { recursive: true });
    }

    if (!fs.existsSync(storeFile)) {
      fs.writeFileSync(storeFile, JSON.stringify({ jobs: [] }, null, 2));
    }
  }

  function readStore() {
    ensureStoreFile();

    try {
      const raw = fs.readFileSync(storeFile, 'utf8').trim();
      if (!raw) {
        return { jobs: [] };
      }

      const parsed = JSON.parse(raw);
      if (!Array.isArray(parsed.jobs)) {
        return { jobs: [] };
      }

      return {
        jobs: parsed.jobs.map((job) => ({
          ...job,
          history: Array.isArray(job.history) ? job.history : [],
        })),
      };
    } catch {
      return { jobs: [] };
    }
  }

  function writeStore(store) {
    ensureStoreFile();
    const serialized = JSON.stringify(store, null, 2);
    fs.writeFileSync(storeFile, serialized);
  }

  function normalizeHistoryEntry(entry) {
    return {
      id: entry?.id || crypto.randomUUID(),
      source: entry?.source || 'Hybrid Analysis',
      severity: entry?.severity || 'info',
      title: entry?.title || 'Analysis update',
      detail: entry?.detail || 'Analysis activity recorded.',
      time: entry?.time || new Date().toISOString(),
    };
  }

  function createAnalysisJob(payload = {}) {
    const now = new Date().toISOString();
    const store = readStore();
    const job = {
      id: payload.id || crypto.randomUUID(),
      provider: payload.provider || 'falcon-sandbox',
      type: payload.type || 'file',
      status: payload.status || 'queued',
      verdict: payload.verdict || null,
      filename: payload.filename || null,
      sha256: payload.sha256 || null,
      url: payload.url || null,
      environmentId: payload.environmentId || null,
      publicSubmission: Boolean(payload.publicSubmission),
      externalId: payload.externalId || null,
      reportUrl: payload.reportUrl || null,
      message: payload.message || '',
      metadata: clone(payload.metadata) || {},
      report: clone(payload.report) || null,
      createdAt: payload.createdAt || now,
      updatedAt: payload.updatedAt || now,
      history: (payload.history || []).map(normalizeHistoryEntry),
    };

    store.jobs.unshift(job);
    store.jobs.sort(sortJobsNewestFirst);
    writeStore(store);
    return clone(job);
  }

  function getAnalysisJobs() {
    const store = readStore();
    return clone(store.jobs.sort(sortJobsNewestFirst));
  }

  function getAnalysisJob(jobId) {
    const store = readStore();
    const job = store.jobs.find((entry) => entry.id === jobId);
    return clone(job || null);
  }

  function updateAnalysisJob(jobId, patch = {}, historyEntry = null) {
    const store = readStore();
    const index = store.jobs.findIndex((entry) => entry.id === jobId);

    if (index === -1) {
      return null;
    }

    const current = store.jobs[index];
    const next = {
      ...current,
      ...patch,
      metadata: patch.metadata === undefined ? current.metadata : { ...(current.metadata || {}), ...(patch.metadata || {}) },
      report: patch.report === undefined ? current.report : clone(patch.report),
      updatedAt: patch.updatedAt || new Date().toISOString(),
      history: Array.isArray(current.history) ? [...current.history] : [],
    };

    if (historyEntry) {
      next.history.unshift(normalizeHistoryEntry(historyEntry));
      next.history = next.history.slice(0, 50);
    }

    store.jobs[index] = next;
    store.jobs.sort(sortJobsNewestFirst);
    writeStore(store);
    return clone(next);
  }

  function appendAnalysisHistory(jobId, historyEntry) {
    return updateAnalysisJob(jobId, {}, historyEntry);
  }

  function summarizeAnalysisJobs() {
    return getAnalysisJobs().reduce((summary, job) => {
      summary.total += 1;
      summary.byProvider[job.provider] = (summary.byProvider[job.provider] || 0) + 1;

      if (['queued', 'pending'].includes(String(job.status).toLowerCase())) {
        summary.pending += 1;
      } else if (['running', 'processing'].includes(String(job.status).toLowerCase())) {
        summary.running += 1;
      } else if (String(job.status).toLowerCase() === 'completed') {
        summary.completed += 1;
      } else if (String(job.status).toLowerCase() === 'failed') {
        summary.failed += 1;
      }

      if (job.verdict === 'INFECTED') {
        summary.malicious += 1;
      } else if (job.verdict === 'REVIEW') {
        summary.review += 1;
      } else if (job.verdict === 'CLEAN') {
        summary.clean += 1;
      }

      return summary;
    }, {
      total: 0,
      pending: 0,
      running: 0,
      completed: 0,
      failed: 0,
      malicious: 0,
      review: 0,
      clean: 0,
      byProvider: {},
    });
  }

  function clearAnalysisJobs() {
    writeStore({ jobs: [] });
  }

  return {
    appendAnalysisHistory,
    clearAnalysisJobs,
    createAnalysisJob,
    getAnalysisJob,
    getAnalysisJobs,
    storeFile,
    summarizeAnalysisJobs,
    updateAnalysisJob,
  };
}

const defaultStore = createAnalysisStore();

module.exports = {
  ANALYSIS_STORE_FILE: defaultStore.storeFile,
  createAnalysisStore,
  ...defaultStore,
};
