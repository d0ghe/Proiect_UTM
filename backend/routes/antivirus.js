const crypto = require('crypto');
const express = require('express');
const fs = require('fs');
const multer = require('multer');
const path = require('path');
const axios = require('axios');

const verifyToken = require('../middleware/verifyToken');
const { getAnalysisJob, getAnalysisJobs, createAnalysisJob, summarizeAnalysisJobs, updateAnalysisJob } = require('../store/analysisStore');
const { readScanLogs, summarizeScanLogs } = require('../utils/scanLog');
const {
  createHybridAnalysisClient,
  createProviderResult,
  getHybridAnalysisConfig,
  mapRawVerdict,
  parseBoolean,
} = require('../utils/hybridAnalysis');

const router = express.Router();
const hybridAnalysisConfig = getHybridAnalysisConfig();
const hybridAnalysisClient = createHybridAnalysisClient({ config: hybridAnalysisConfig });

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 50 * 1024 * 1024 },
});

const MALWARE_BAZAAR_KEY = process.env.MALWARE_BAZAAR_KEY;
const LOG_FILE = path.join(__dirname, '../scans.log');
const QUARANTINE_DIR = path.join(__dirname, '../quarantine');
const EICAR_MARKER = ['EICAR', 'STANDARD', 'ANTIVIRUS', 'TEST', 'FILE'].join('-');

router.use(verifyToken);

function ensureQuarantineDir() {
  if (!fs.existsSync(QUARANTINE_DIR)) {
    fs.mkdirSync(QUARANTINE_DIR, { recursive: true });
  }
}

function updateGlobalStats(results) {
  if (!global.stats) {
    return;
  }

  global.stats.files_scanned += results.length;
  global.stats.threats_found += results.filter((result) => result.status === 'INFECTED').length;
  global.stats.quarantined += results.filter((result) => result.status === 'INFECTED').length;
}

function logScanResult(data) {
  const timestamp = new Date().toISOString();
  const detail = data.signature || data.message || 'No extra detail';
  const logEntry = `[${timestamp}] STATUS: ${data.status} | Fisier: ${data.filename} | Hash: ${data.sha256 || '-'} | Rezultat: ${detail}\n`;
  fs.appendFileSync(LOG_FILE, logEntry);
}

function getQuarantineFiles() {
  ensureQuarantineDir();

  return fs
    .readdirSync(QUARANTINE_DIR)
    .map((file) => {
      const stats = fs.statSync(path.join(QUARANTINE_DIR, file));
      return {
        name: file,
        date: stats.birthtime,
        size: `${(stats.size / 1024).toFixed(2)} KB`,
      };
    })
    .reverse();
}

function buildProviderCatalog() {
  return [
    {
      id: 'local-heuristic',
      name: 'Local Heuristic',
      enabled: true,
      available: true,
      configurable: false,
      defaultSelected: true,
      consentRequired: false,
      capabilities: {
        fileScan: true,
        hashLookup: false,
        quickScan: false,
        sandbox: false,
        urlSubmission: false,
      },
    },
    {
      id: 'malwarebazaar',
      name: 'MalwareBazaar',
      enabled: Boolean(MALWARE_BAZAAR_KEY),
      available: Boolean(MALWARE_BAZAAR_KEY),
      configurable: true,
      defaultSelected: Boolean(MALWARE_BAZAAR_KEY),
      consentRequired: false,
      capabilities: {
        fileScan: false,
        hashLookup: true,
        quickScan: false,
        sandbox: false,
        urlSubmission: false,
      },
    },
    {
      id: 'hybrid-analysis',
      name: 'Hybrid Analysis Quick Scan',
      enabled: hybridAnalysisConfig.enabled && hybridAnalysisConfig.isConfigured,
      available: hybridAnalysisConfig.isConfigured,
      configurable: true,
      defaultSelected: hybridAnalysisConfig.enabled && hybridAnalysisConfig.isConfigured,
      consentRequired: true,
      requiresApiKey: true,
      capabilities: {
        fileScan: false,
        hashLookup: true,
        quickScan: true,
        sandbox: false,
        urlSubmission: false,
        crowdStrikeMl: true,
      },
      defaults: {
        publicSubmission: hybridAnalysisConfig.publicOptInDefault,
        pollIntervalMs: hybridAnalysisConfig.pollIntervalMs,
        pollTimeoutMs: hybridAnalysisConfig.pollTimeoutMs,
        maxUploadMb: hybridAnalysisConfig.maxUploadMb,
      },
    },
    {
      id: 'falcon-sandbox',
      name: 'Falcon Sandbox',
      enabled: hybridAnalysisConfig.enabled && hybridAnalysisConfig.isConfigured && Boolean(hybridAnalysisConfig.environmentId),
      available: hybridAnalysisConfig.isConfigured,
      configurable: true,
      defaultSelected: false,
      consentRequired: true,
      requiresApiKey: true,
      capabilities: {
        fileScan: false,
        hashLookup: true,
        quickScan: false,
        sandbox: true,
        urlSubmission: true,
      },
      defaults: {
        publicSubmission: hybridAnalysisConfig.publicOptInDefault,
        environmentId: hybridAnalysisConfig.environmentId || null,
        pollIntervalMs: hybridAnalysisConfig.pollIntervalMs,
        pollTimeoutMs: hybridAnalysisConfig.pollTimeoutMs,
      },
    },
  ];
}

function parseRequestedProviders(body = {}) {
  const values = [];
  const explicitlyProvided = parseBoolean(body.providersSpecified, false);
  const rawProviders = [
    body.providers,
    body['providers[]'],
  ];

  rawProviders.forEach((entry) => {
    if (Array.isArray(entry)) {
      entry.forEach((item) => values.push(item));
      return;
    }

    if (typeof entry === 'string' && entry.trim()) {
      if (entry.trim().startsWith('[')) {
        try {
          const parsed = JSON.parse(entry);
          if (Array.isArray(parsed)) {
            parsed.forEach((item) => values.push(item));
            return;
          }
        } catch {
          // Ignore invalid JSON and fall back to comma parsing.
        }
      }

      entry
        .split(',')
        .map((item) => item.trim())
        .filter(Boolean)
        .forEach((item) => values.push(item));
    }
  });

  const providers = new Set(values.map((value) => String(value).trim().toLowerCase()));
  if (providers.size === 0 && !explicitlyProvided) {
    providers.add('malwarebazaar');
    if (hybridAnalysisConfig.enabled && hybridAnalysisConfig.isConfigured) {
      providers.add('hybrid-analysis');
    }
  }

  return providers;
}

function isTruthyVerdict(value) {
  return ['INFECTED', 'REVIEW'].includes(String(value || '').toUpperCase());
}

function createLocalHeuristicResult(file, fileHash) {
  const fileContent = file.buffer.toString('utf8');

  if (fileContent.includes(EICAR_MARKER)) {
    return {
      detected: true,
      signature: 'EICAR_Test_File (Local Detection)',
      provider: createProviderResult({
        id: 'local-heuristic',
        name: 'Local Heuristic',
        verdict: 'INFECTED',
        message: 'Local heuristic matched the EICAR self-test signature.',
        metadata: {
          sha256: fileHash,
          signature: 'EICAR_Test_File (Local Detection)',
        },
      }),
    };
  }

  return {
    detected: false,
    signature: null,
    provider: createProviderResult({
      id: 'local-heuristic',
      name: 'Local Heuristic',
      verdict: 'CLEAN',
      message: 'No local heuristic detection found.',
      metadata: {
        sha256: fileHash,
      },
    }),
  };
}

async function lookupMalwareBazaar(fileHash) {
  if (!MALWARE_BAZAAR_KEY) {
    return createProviderResult({
      id: 'malwarebazaar',
      name: 'MalwareBazaar',
      status: 'disabled',
      verdict: null,
      message: 'MalwareBazaar is not configured on this backend.',
    });
  }

  try {
    const response = await axios.post(
      'https://mb-api.abuse.ch/api/v1/',
      new URLSearchParams({ query: 'get_info', hash: fileHash }),
      {
        headers: {
          'Auth-Key': MALWARE_BAZAAR_KEY,
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        timeout: 10000,
      },
    );

    if (response.data.query_status === 'ok') {
      const signature = response.data.data?.[0]?.signature || 'Malware Generic';
      return createProviderResult({
        id: 'malwarebazaar',
        name: 'MalwareBazaar',
        verdict: 'INFECTED',
        message: `Hash matched MalwareBazaar: ${signature}.`,
        metadata: {
          signature,
          queryStatus: response.data.query_status,
        },
      });
    }

    return createProviderResult({
      id: 'malwarebazaar',
      name: 'MalwareBazaar',
      verdict: 'CLEAN',
      message: 'Hash not found in MalwareBazaar.',
      metadata: {
        queryStatus: response.data.query_status || 'not_found',
      },
    });
  } catch (error) {
    return createProviderResult({
      id: 'malwarebazaar',
      name: 'MalwareBazaar',
      status: 'error',
      verdict: 'REVIEW',
      message: `MalwareBazaar lookup failed: ${error.message}`,
      metadata: {
        transient: true,
      },
    });
  }
}

function buildHybridDisabledResult(providerId, name, message) {
  return createProviderResult({
    id: providerId,
    name,
    status: 'disabled',
    verdict: null,
    message,
  });
}

function buildHybridQuickProvider(quickScan, reusedHashLookup = false) {
  if (!quickScan) {
    return null;
  }

  const providerVerdict = quickScan.verdict || (quickScan.finished ? 'CLEAN' : null);
  const verdictText = quickScan.rawVerdict || providerVerdict || quickScan.status;
  const status = quickScan.finished ? 'completed' : 'running';

  return createProviderResult({
    id: 'hybrid-analysis',
    name: 'Hybrid Analysis Quick Scan',
    status,
    verdict: providerVerdict,
    message: reusedHashLookup
      ? `Known sample reused from Hybrid Analysis hash lookup (${verdictText || 'report found'}).`
      : quickScan.finished
        ? `Hybrid Analysis quick scan verdict: ${verdictText || providerVerdict || 'completed'}.`
        : quickScan.message || 'Hybrid Analysis quick scan is still processing.',
    reportId: quickScan.id,
    reportUrl: quickScan.reportUrl,
    metadata: {
      classification: quickScan.classification,
      reusedHashLookup,
      threatScore: quickScan.threatScore,
    },
  });
}

function buildKnownSandboxReport(file, fileHash, knownSample, publicSubmission) {
  return createAnalysisJob({
    provider: 'falcon-sandbox',
    type: 'file',
    status: 'completed',
    verdict: knownSample.verdict || null,
    filename: file.originalname,
    sha256: fileHash,
    publicSubmission,
    externalId: knownSample.id || null,
    reportUrl: knownSample.reportUrl || null,
    message: 'Known Hybrid Analysis report reused instead of resubmitting the sample.',
    report: {
      classification: knownSample.classification,
      contactedHosts: knownSample.contactedHosts,
      droppedFiles: knownSample.droppedFiles,
      mitreTechniques: knownSample.mitreTechniques,
      signatures: knownSample.signatures,
      threatScore: knownSample.threatScore,
    },
    history: [
      {
        source: 'Hybrid Analysis',
        severity: knownSample.verdict === 'INFECTED' ? 'critical' : 'info',
        title: 'Existing Falcon Sandbox report reused',
        detail: `${file.originalname} matched a known Hybrid Analysis sample by hash.`,
      },
    ],
  });
}

async function submitSandboxJob(file, fileHash, publicSubmission) {
  const queuedJob = createAnalysisJob({
    provider: 'falcon-sandbox',
    type: 'file',
    status: 'queued',
    verdict: null,
    filename: file.originalname,
    sha256: fileHash,
    publicSubmission,
    environmentId: hybridAnalysisConfig.environmentId || null,
    message: 'Waiting for Falcon Sandbox submission.',
    history: [
      {
        source: 'Hybrid Analysis',
        severity: 'info',
        title: 'Sandbox submission queued',
        detail: `${file.originalname} is queued for Falcon Sandbox submission.`,
      },
    ],
  });

  try {
    const submission = await hybridAnalysisClient.submitFile(file, {
      environmentId: hybridAnalysisConfig.environmentId,
      noShareThirdParty: !publicSubmission,
    });

    return updateAnalysisJob(queuedJob.id, {
      status: 'running',
      externalId: submission.id,
      reportUrl: submission.reportUrl,
      message: 'Sample submitted to Falcon Sandbox. Poll the report endpoint for updates.',
      metadata: {
        submission: submission.raw,
      },
    }, {
      source: 'Hybrid Analysis',
      severity: 'info',
      title: 'Sandbox sample submitted',
      detail: `${file.originalname} was submitted to Falcon Sandbox.`,
    });
  } catch (error) {
    return updateAnalysisJob(queuedJob.id, {
      status: 'failed',
      message: error.message,
      metadata: {
        error: error.message,
      },
    }, {
      source: 'Hybrid Analysis',
      severity: 'warning',
      title: 'Sandbox submission failed',
      detail: `${file.originalname} could not be submitted to Falcon Sandbox: ${error.message}`,
    });
  }
}

function buildSandboxProvider(job, reusedHashLookup = false) {
  if (!job) {
    return null;
  }

  return createProviderResult({
    id: 'falcon-sandbox',
    name: 'Falcon Sandbox',
    status: job.status,
    verdict: job.verdict,
    message: reusedHashLookup
      ? 'Known Falcon Sandbox report reused from Hybrid Analysis.'
      : job.status === 'completed'
        ? 'Falcon Sandbox report is available.'
        : job.status === 'failed'
          ? `Falcon Sandbox submission failed: ${job.message}`
          : 'Full sandbox analysis is running.',
    reportId: job.externalId || job.id,
    reportUrl: job.reportUrl || null,
    metadata: {
      environmentId: job.environmentId || null,
      publicSubmission: Boolean(job.publicSubmission),
      jobId: job.id,
    },
  });
}

async function collectHybridAnalysisSignals(file, fileHash, providerSelection, publicSubmission) {
  const selectedQuickScan = providerSelection.has('hybrid-analysis');
  const selectedSandbox = providerSelection.has('falcon-sandbox');
  const selectedAnything = selectedQuickScan || selectedSandbox;
  const shouldAttemptHashLookup = selectedSandbox;

  const response = {
    errors: [],
    hashLookup: null,
    providerResults: [],
    quickScan: null,
    sandboxJob: null,
  };

  if (!selectedAnything) {
    return response;
  }

  if (!hybridAnalysisConfig.enabled) {
    if (selectedQuickScan) {
      response.providerResults.push(buildHybridDisabledResult('hybrid-analysis', 'Hybrid Analysis Quick Scan', 'Hybrid Analysis is disabled on this backend.'));
    }
    if (selectedSandbox) {
      response.providerResults.push(buildHybridDisabledResult('falcon-sandbox', 'Falcon Sandbox', 'Falcon Sandbox is disabled on this backend.'));
    }
    return response;
  }

  if (!hybridAnalysisConfig.isConfigured) {
    if (selectedQuickScan) {
      response.providerResults.push(buildHybridDisabledResult('hybrid-analysis', 'Hybrid Analysis Quick Scan', 'Hybrid Analysis API key is not configured.'));
    }
    if (selectedSandbox) {
      response.providerResults.push(buildHybridDisabledResult('falcon-sandbox', 'Falcon Sandbox', 'Hybrid Analysis API key is not configured.'));
    }
    return response;
  }

  if (file.size > hybridAnalysisConfig.maxUploadBytes) {
    const message = `File exceeds the Hybrid Analysis upload limit of ${hybridAnalysisConfig.maxUploadMb} MB.`;
    if (selectedQuickScan) {
      response.providerResults.push(createProviderResult({
        id: 'hybrid-analysis',
        name: 'Hybrid Analysis Quick Scan',
        status: 'error',
        verdict: 'REVIEW',
        message,
      }));
    }
    if (selectedSandbox) {
      response.providerResults.push(createProviderResult({
        id: 'falcon-sandbox',
        name: 'Falcon Sandbox',
        status: 'error',
        verdict: 'REVIEW',
        message,
      }));
    }
    response.errors.push(message);
    return response;
  }

  if (shouldAttemptHashLookup) {
    try {
      response.hashLookup = await hybridAnalysisClient.lookupHash(fileHash, { timeoutMs: 6000 });
    } catch (error) {
      if (!error.isTimeout && ![400, 404].includes(Number(error.status))) {
        response.errors.push(`Hybrid Analysis hash lookup failed: ${error.message}`);
      }
    }
  }

  if (selectedQuickScan) {
    try {
      if (response.hashLookup?.found) {
        response.quickScan = {
          id: response.hashLookup.id,
          status: 'completed',
          finished: true,
          verdict: response.hashLookup.verdict || mapRawVerdict(response.hashLookup.rawVerdict, 'REVIEW'),
          rawVerdict: response.hashLookup.rawVerdict,
          threatScore: response.hashLookup.threatScore,
          classification: response.hashLookup.classification,
          reportUrl: response.hashLookup.reportUrl,
          scannerSummary: [],
          crowdStrike: null,
          message: 'Known sample report reused from Hybrid Analysis hash lookup.',
        };
      } else {
        response.quickScan = await hybridAnalysisClient.quickScanFile(file, {
          environmentId: hybridAnalysisConfig.environmentId,
          waitForCompletion: false,
        });
      }

      const quickProvider = buildHybridQuickProvider(response.quickScan, Boolean(response.hashLookup?.found));
      if (quickProvider) {
        response.providerResults.push(quickProvider);
      }

      if (response.quickScan?.crowdStrike) {
        response.providerResults.push({
          ...response.quickScan.crowdStrike,
          reportId: response.quickScan.id,
          reportUrl: response.quickScan.reportUrl,
        });
      }
    } catch (error) {
      response.errors.push(`Hybrid Analysis quick scan failed: ${error.message}`);
      response.providerResults.push(createProviderResult({
        id: 'hybrid-analysis',
        name: 'Hybrid Analysis Quick Scan',
        status: 'error',
        verdict: 'REVIEW',
        message: `Hybrid Analysis quick scan failed: ${error.message}`,
      }));
    }
  }

  if (selectedSandbox) {
    if (!hybridAnalysisConfig.environmentId) {
      response.errors.push('Falcon Sandbox requires HYBRID_ANALYSIS_ENVIRONMENT_ID.');
      response.providerResults.push(createProviderResult({
        id: 'falcon-sandbox',
        name: 'Falcon Sandbox',
        status: 'disabled',
        verdict: null,
        message: 'Falcon Sandbox requires HYBRID_ANALYSIS_ENVIRONMENT_ID before submissions can start.',
      }));
    } else if (response.hashLookup?.found) {
      response.sandboxJob = buildKnownSandboxReport(file, fileHash, response.hashLookup, publicSubmission);
      response.providerResults.push(buildSandboxProvider(response.sandboxJob, true));
    } else {
      response.sandboxJob = await submitSandboxJob(file, fileHash, publicSubmission);
      response.providerResults.push(buildSandboxProvider(response.sandboxJob, false));
    }
  }

  return response;
}

function buildResultSummary(localHeuristic, malwareBazaar, hybridSignals) {
  const providerResults = [
    localHeuristic.provider,
    malwareBazaar,
    ...hybridSignals.providerResults,
  ].filter(Boolean);

  const malwareHit = malwareBazaar?.verdict === 'INFECTED';
  const sandboxHit = hybridSignals.sandboxJob?.status === 'completed' && hybridSignals.sandboxJob?.verdict === 'INFECTED';
  const reviewSignals = providerResults.filter((result) => isTruthyVerdict(result?.verdict)).length;
  const hasErrors = providerResults.some((result) => result?.status === 'error');
  const hasPendingProviders = providerResults.some((result) => ['queued', 'running'].includes(String(result?.status || '').toLowerCase()));

  let status = 'CLEAN';
  let signature = null;
  let message = 'No provider raised a threat indicator.';

  if (localHeuristic.detected) {
    status = 'INFECTED';
    signature = localHeuristic.signature;
    message = 'Local heuristic matched a known test signature.';
  } else if (malwareHit) {
    status = 'INFECTED';
    signature = malwareBazaar?.metadata?.signature || 'MalwareBazaar detection';
    message = malwareBazaar.message;
  } else if (sandboxHit) {
    status = 'INFECTED';
    signature = 'Falcon Sandbox malicious verdict';
    message = hybridSignals.sandboxJob?.message || 'Falcon Sandbox classified the sample as malicious.';
  } else if (hasPendingProviders) {
    status = 'REVIEW';
    message = providerResults.find((result) => ['queued', 'running'].includes(String(result?.status || '').toLowerCase()))?.message
      || 'One or more external providers are still processing this sample.';
  } else if (reviewSignals > 0 || hasErrors || hybridSignals.errors.length > 0) {
    status = 'REVIEW';
    message = providerResults.find((result) => result?.verdict === 'INFECTED')?.message
      || providerResults.find((result) => result?.verdict === 'REVIEW')?.message
      || hybridSignals.errors[0]
      || 'One or more providers recommend manual review.';
  }

  const method = providerResults.map((result) => result.name).join(' + ');

  return {
    message,
    method,
    providers: providerResults,
    signature,
    status,
  };
}

async function scanFile(file, options = {}) {
  const fileHash = crypto.createHash('sha256').update(file.buffer).digest('hex');
  const providerSelection = options.providers || new Set();
  const publicSubmission = Boolean(options.publicSubmission);

  const localHeuristic = createLocalHeuristicResult(file, fileHash);
  const malwareBazaar = providerSelection.has('malwarebazaar')
    ? await lookupMalwareBazaar(fileHash)
    : null;

  const hybridSignals = await collectHybridAnalysisSignals(file, fileHash, providerSelection, publicSubmission);
  const combined = buildResultSummary(localHeuristic, malwareBazaar, hybridSignals);

  const result = {
    filename: file.originalname,
    sha256: fileHash,
    sizeBytes: file.size,
    status: combined.status,
    signature: combined.signature,
    message: combined.message,
    method: combined.method,
    providers: combined.providers,
    hybridAnalysis: {
      enabled: hybridAnalysisConfig.enabled,
      configured: hybridAnalysisConfig.isConfigured,
      publicSubmission,
      hashLookup: hybridSignals.hashLookup,
      quickScan: hybridSignals.quickScan,
      sandbox: hybridSignals.sandboxJob ? {
        jobId: hybridSignals.sandboxJob.id,
        status: hybridSignals.sandboxJob.status,
        verdict: hybridSignals.sandboxJob.verdict,
        reportUrl: hybridSignals.sandboxJob.reportUrl,
      } : null,
      warnings: hybridSignals.errors,
    },
    sandboxJob: hybridSignals.sandboxJob ? {
      id: hybridSignals.sandboxJob.id,
      status: hybridSignals.sandboxJob.status,
      verdict: hybridSignals.sandboxJob.verdict,
      reportUrl: hybridSignals.sandboxJob.reportUrl,
      createdAt: hybridSignals.sandboxJob.createdAt,
      updatedAt: hybridSignals.sandboxJob.updatedAt,
      externalId: hybridSignals.sandboxJob.externalId,
      publicSubmission: hybridSignals.sandboxJob.publicSubmission,
      environmentId: hybridSignals.sandboxJob.environmentId,
    } : null,
  };

  logScanResult(result);
  return result;
}

function buildScanSummary(results) {
  return {
    total: results.length,
    infected: results.filter((result) => result.status === 'INFECTED').length,
    clean: results.filter((result) => result.status === 'CLEAN').length,
    review: results.filter((result) => result.status === 'REVIEW').length,
    failed: results.filter((result) => result.status === 'ERROR').length,
    pendingSandboxJobs: results.filter((result) => ['queued', 'running'].includes(String(result?.sandboxJob?.status || '').toLowerCase())).length,
  };
}

router.get('/providers', (_req, res) => {
  res.json({
    success: true,
    providers: buildProviderCatalog(),
  });
});

router.post('/scan', upload.any(), async (req, res) => {
  const uploadedFiles = Array.isArray(req.files)
    ? req.files.filter((file) => ['files', 'file'].includes(file.fieldname))
    : [];

  if (uploadedFiles.length === 0) {
    return res.status(400).json({
      success: false,
      message: 'Select at least one file to scan.',
    });
  }

  const providers = parseRequestedProviders(req.body);
  const publicSubmission = parseBoolean(
    req.body.hybridAnalysisOptInPublic,
    hybridAnalysisConfig.publicOptInDefault,
  );

  try {
    const results = await Promise.all(uploadedFiles.map((file) => scanFile(file, { providers, publicSubmission })));
    const summary = buildScanSummary(results);

    updateGlobalStats(results);

    res.json({
      success: true,
      summary,
      results,
      selectedProviders: Array.from(providers),
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Internal scanning error.',
      error: error.message,
    });
  }
});

router.get('/analysis/:jobId', (req, res) => {
  const job = getAnalysisJob(req.params.jobId);

  if (!job) {
    return res.status(404).json({
      success: false,
      message: 'Analysis job not found.',
    });
  }

  return res.json({
    success: true,
    job,
  });
});

router.post('/analysis/:jobId/poll', async (req, res) => {
  const existingJob = getAnalysisJob(req.params.jobId);
  if (!existingJob) {
    return res.status(404).json({
      success: false,
      message: 'Analysis job not found.',
    });
  }

  if (!existingJob.externalId) {
    return res.status(400).json({
      success: false,
      message: 'This job does not have a provider report ID yet.',
      job: existingJob,
    });
  }

  try {
    const report = await hybridAnalysisClient.getReportOverview(existingJob.externalId);
    const nextStatus = report?.status || existingJob.status;
    const nextVerdict = report?.verdict || existingJob.verdict || null;
    const severity = nextVerdict === 'INFECTED' ? 'critical' : nextStatus === 'failed' ? 'warning' : 'info';
    const title = nextStatus === 'completed'
      ? 'Sandbox report completed'
      : nextStatus === 'failed'
        ? 'Sandbox report failed'
        : 'Sandbox report updated';

    const updatedJob = updateAnalysisJob(existingJob.id, {
      status: nextStatus,
      verdict: nextVerdict,
      reportUrl: report?.reportUrl || existingJob.reportUrl,
      message: report?.message || existingJob.message,
      report,
    }, {
      source: 'Hybrid Analysis',
      severity,
      title,
      detail: `${existingJob.filename || existingJob.url || existingJob.sha256 || 'Submission'} status is now ${nextStatus}.`,
    });

    return res.json({
      success: true,
      job: updatedJob,
    });
  } catch (error) {
    const updatedJob = updateAnalysisJob(existingJob.id, {
      status: 'failed',
      message: error.message,
      metadata: {
        ...(existingJob.metadata || {}),
        pollError: error.message,
      },
    }, {
      source: 'Hybrid Analysis',
      severity: 'warning',
      title: 'Sandbox polling failed',
      detail: `Could not refresh ${existingJob.filename || existingJob.url || existingJob.sha256 || 'submission'}: ${error.message}`,
    });

    return res.status(502).json({
      success: false,
      message: error.message,
      job: updatedJob,
    });
  }
});

router.post('/submit-url', async (req, res) => {
  const url = String(req.body?.url || '').trim();
  if (!url) {
    return res.status(400).json({
      success: false,
      message: 'A URL is required.',
    });
  }

  if (!hybridAnalysisConfig.isConfigured || !hybridAnalysisConfig.enabled) {
    return res.status(400).json({
      success: false,
      message: 'Hybrid Analysis is not available on this backend.',
    });
  }

  if (!hybridAnalysisConfig.environmentId) {
    return res.status(400).json({
      success: false,
      message: 'HYBRID_ANALYSIS_ENVIRONMENT_ID is required for Falcon Sandbox URL submissions.',
    });
  }

  const publicSubmission = parseBoolean(
    req.body.hybridAnalysisOptInPublic,
    hybridAnalysisConfig.publicOptInDefault,
  );

  const queuedJob = createAnalysisJob({
    provider: 'falcon-sandbox',
    type: 'url',
    status: 'queued',
    url,
    publicSubmission,
    environmentId: hybridAnalysisConfig.environmentId,
    message: 'Waiting for Falcon Sandbox URL submission.',
    history: [
      {
        source: 'Hybrid Analysis',
        severity: 'info',
        title: 'URL submission queued',
        detail: `${url} is queued for Falcon Sandbox URL analysis.`,
      },
    ],
  });

  try {
    const submission = await hybridAnalysisClient.submitUrl(url, {
      environmentId: hybridAnalysisConfig.environmentId,
      noShareThirdParty: !publicSubmission,
    });

    const updatedJob = updateAnalysisJob(queuedJob.id, {
      status: 'running',
      externalId: submission.id,
      reportUrl: submission.reportUrl,
      message: 'URL submitted to Falcon Sandbox. Poll for the completed report.',
      metadata: {
        submission: submission.raw,
      },
    }, {
      source: 'Hybrid Analysis',
      severity: 'info',
      title: 'URL submitted to Falcon Sandbox',
      detail: `${url} was submitted to Falcon Sandbox.`,
    });

    return res.json({
      success: true,
      job: updatedJob,
    });
  } catch (error) {
    const failedJob = updateAnalysisJob(queuedJob.id, {
      status: 'failed',
      message: error.message,
      metadata: {
        error: error.message,
      },
    }, {
      source: 'Hybrid Analysis',
      severity: 'warning',
      title: 'URL submission failed',
      detail: `${url} could not be submitted to Falcon Sandbox: ${error.message}`,
    });

    return res.status(502).json({
      success: false,
      message: error.message,
      job: failedJob,
    });
  }
});

router.get('/logs', (_req, res) => {
  try {
    res.json({
      success: true,
      logs: readScanLogs(LOG_FILE),
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Could not read scan logs.',
      error: error.message,
    });
  }
});

router.get('/summary', (_req, res) => {
  try {
    const logs = readScanLogs(LOG_FILE);
    const summary = summarizeScanLogs(logs);
    const analysisSummary = summarizeAnalysisJobs();
    const recentJobs = getAnalysisJobs().slice(0, 8);

    res.json({
      success: true,
      summary: {
        ...summary,
        quarantined: getQuarantineFiles().length,
        recentJobs,
        providerSummary: {
          ...analysisSummary,
          hybridAnalysisEnabled: hybridAnalysisConfig.enabled,
          hybridAnalysisConfigured: hybridAnalysisConfig.isConfigured,
        },
      },
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Could not build scan summary.',
      error: error.message,
    });
  }
});

router.get('/quarantine', (_req, res) => {
  try {
    res.json({
      success: true,
      files: getQuarantineFiles(),
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Could not read quarantine list.',
      error: error.message,
    });
  }
});

module.exports = router;
