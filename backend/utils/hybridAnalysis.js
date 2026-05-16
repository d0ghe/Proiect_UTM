const axios = require('axios');

const DEFAULT_BASE_URL = 'https://hybrid-analysis.com/api/v2';
const DEFAULT_ENVIRONMENTS = [
  { id: 140, label: 'Windows 11 64-bit' },
  { id: 160, label: 'Windows 10 64-bit' },
  { id: 120, label: 'Windows 7 64-bit' },
  { id: 110, label: 'Windows 7 32-bit (HWP support)' },
  { id: 100, label: 'Windows 7 32-bit' },
  { id: 330, label: 'Ubuntu 24.04 64-bit' },
  { id: 310, label: 'Ubuntu 20.04 64-bit' },
  { id: 400, label: 'macOS Catalina 64-bit' },
  { id: 200, label: 'Android static analysis' },
];

function parseBoolean(value, fallback = false) {
  if (value === undefined || value === null || value === '') {
    return fallback;
  }

  if (typeof value === 'boolean') {
    return value;
  }

  const normalized = String(value).trim().toLowerCase();
  if (['true', '1', 'yes', 'on'].includes(normalized)) {
    return true;
  }

  if (['false', '0', 'no', 'off'].includes(normalized)) {
    return false;
  }

  return fallback;
}

function toNumber(value, fallback = undefined) {
  if (value === undefined || value === null || value === '') {
    return fallback;
  }

  const numeric = Number(value);
  return Number.isFinite(numeric) ? numeric : fallback;
}

function pickFirst(...values) {
  return values.find((value) => value !== undefined && value !== null && value !== '');
}

function summarizeValidationErrors(value) {
  if (!value) {
    return '';
  }

  if (Array.isArray(value)) {
    return value
      .map((entry) => {
        if (typeof entry === 'string') {
          return entry;
        }

        if (entry && typeof entry === 'object') {
          const field = pickFirst(entry.field, entry.name, entry.param);
          const nestedErrors = Array.isArray(entry.errors)
            ? entry.errors.join(', ')
            : pickFirst(entry.errors, entry.error_message);
          const message = pickFirst(entry.message, entry.detail, entry.error, nestedErrors);
          return [field, message].filter(Boolean).join(': ');
        }

        return null;
      })
      .filter(Boolean)
      .join('; ');
  }

  if (typeof value === 'object') {
    return Object.entries(value)
      .map(([field, detail]) => {
        if (Array.isArray(detail)) {
          return `${field}: ${detail.join(', ')}`;
        }

        if (detail && typeof detail === 'object') {
          return `${field}: ${pickFirst(detail.message, detail.detail, JSON.stringify(detail))}`;
        }

        return `${field}: ${detail}`;
      })
      .join('; ');
  }

  return String(value);
}

function stringifyValidationErrors(value) {
  if (!value) {
    return '';
  }

  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

function isRetryableValidationError(error) {
  return Boolean(error) && [400, 404].includes(Number(error.status));
}

function createMultipartFormData(file, options = {}) {
  const formData = new FormData();
  const blob = new Blob([file.buffer], { type: file.mimetype || 'application/octet-stream' });
  formData.append('file', blob, file.originalname);

  if (options.scanType) {
    formData.append('scan_type', String(options.scanType));
  }

  if (options.submitName) {
    formData.append('submit_name', String(options.submitName));
  }

  if (options.environmentId) {
    formData.append('environment_id', String(options.environmentId));
  }

  if (options.comment) {
    formData.append('comment', String(options.comment));
  }

  if (options.noShareThirdParty !== undefined) {
    formData.append('no_share_third_party', String(Boolean(options.noShareThirdParty)));
  }

  return formData;
}

function createUrlEncodedBody(fields = {}) {
  const params = new URLSearchParams();
  Object.entries(fields).forEach(([key, value]) => {
    if (value !== undefined && value !== null && value !== '') {
      params.append(key, String(value));
    }
  });

  return params;
}

function isBinaryBody(value) {
  return typeof Buffer !== 'undefined' && Buffer.isBuffer(value);
}

function isFormDataBody(value) {
  return typeof FormData !== 'undefined' && value instanceof FormData;
}

function isUrlEncodedBody(value) {
  return value instanceof URLSearchParams;
}

function getHybridAnalysisConfig(env = process.env) {
  const apiKey = env.HYBRID_ANALYSIS_API_KEY;
  const enabled = parseBoolean(env.HYBRID_ANALYSIS_ENABLED, Boolean(apiKey));
  const maxUploadMb = toNumber(env.HYBRID_ANALYSIS_MAX_UPLOAD_MB, 50);
  let baseUrl = String(env.HYBRID_ANALYSIS_BASE_URL || DEFAULT_BASE_URL).replace(/\/+$/, '');
  try {
    const parsedBaseUrl = new URL(baseUrl);
    if (parsedBaseUrl.hostname === 'www.hybrid-analysis.com') {
      parsedBaseUrl.hostname = 'hybrid-analysis.com';
      baseUrl = parsedBaseUrl.toString().replace(/\/+$/, '');
    }
  } catch {
    // Keep the user-provided value if it is not a valid URL.
  }
  const environmentId = toNumber(env.HYBRID_ANALYSIS_ENVIRONMENT_ID, undefined);

  return {
    apiKey,
    baseUrl,
    enabled,
    environmentId,
    environments: DEFAULT_ENVIRONMENTS,
    isConfigured: Boolean(apiKey),
    maxUploadBytes: maxUploadMb * 1024 * 1024,
    maxUploadMb,
    requestTimeoutMs: toNumber(env.HYBRID_ANALYSIS_REQUEST_TIMEOUT_MS, 60000),
    pollIntervalMs: toNumber(env.HYBRID_ANALYSIS_POLL_INTERVAL_MS, 5000),
    pollTimeoutMs: toNumber(env.HYBRID_ANALYSIS_POLL_TIMEOUT_MS, 120000),
    publicOptInDefault: parseBoolean(env.HYBRID_ANALYSIS_PUBLIC_OPT_IN_DEFAULT, false),
  };
}

function createProviderResult({
  checkedAt = new Date().toISOString(),
  id,
  message = '',
  metadata = {},
  name,
  reportId = null,
  reportUrl = null,
  status = 'completed',
  verdict = null,
} = {}) {
  return {
    id,
    name,
    status,
    verdict,
    message,
    reportId,
    reportUrl,
    checkedAt,
    metadata,
  };
}

function mapRawVerdict(value, fallback = null) {
  const normalized = String(value || '').trim().toLowerCase();

  if (!normalized) {
    return fallback;
  }

  if ([
    'queued',
    'in-queue',
    'pending',
    'processing',
    'in progress',
    'in-progress',
    'running',
    'no-result',
    'no result',
    'unknown yet',
  ].includes(normalized)) {
    return null;
  }

  if ([
    'malicious',
    'infected',
    'dangerous',
    'suspicious',
    'trojan',
    'ransomware',
    'phishing',
    'riskware',
    'high-risk',
    'high risk',
  ].includes(normalized) || normalized.includes('malicious') || normalized.includes('trojan')) {
    return 'INFECTED';
  }

  if ([
    'review',
    'unknown',
    'grayware',
    'graylist',
    'suspicious-low',
    'medium-risk',
    'medium risk',
  ].includes(normalized)) {
    return 'REVIEW';
  }

  if ([
    'clean',
    'benign',
    'safe',
    'no threat',
    'no specific threat',
    'no threat detected',
    'not malicious',
    'harmless',
    'whitelisted',
  ].includes(normalized)) {
    return 'CLEAN';
  }

  return fallback;
}

function normalizeScannerCollection(collection) {
  if (!collection) {
    return [];
  }

  if (Array.isArray(collection)) {
    return collection.map((entry, index) => ({
      key: String(entry?.name || entry?.scanner || entry?.id || `scanner-${index}`),
      value: entry,
    }));
  }

  if (typeof collection === 'object') {
    return Object.entries(collection).map(([key, value]) => ({ key, value }));
  }

  return [];
}

function isSha256(value) {
  return /^[a-f0-9]{64}$/i.test(String(value || '').trim());
}

function normalizeAnalysisStatus(value, fallback = 'completed') {
  const normalized = String(value || '').trim().toLowerCase().replace(/[\s-]+/g, '_');

  if (!normalized) {
    return fallback;
  }

  if (['in_queue', 'queued', 'queue', 'pending'].includes(normalized)) {
    return 'queued';
  }

  if (['in_progress', 'running', 'processing', 'analyzing'].includes(normalized)) {
    return 'running';
  }

  if (['success', 'finished', 'completed', 'complete', 'done', 'partial_success'].includes(normalized)) {
    return 'completed';
  }

  if (['error', 'failed', 'failure', 'aborted', 'timeout'].includes(normalized)) {
    return 'failed';
  }

  return normalized;
}

function buildReportUrl(config, reportRef) {
  if (!reportRef) {
    return null;
  }

  const base = config?.baseUrl || DEFAULT_BASE_URL;
  const webBase = base.replace(/\/api\/v2$/i, '').replace(/\/+$/, '') || 'https://www.hybrid-analysis.com';
  const reference = typeof reportRef === 'object' ? reportRef : { id: reportRef };
  const sha256 = pickFirst(reference.sha256, isSha256(reference.id) ? reference.id : null);
  const jobId = pickFirst(reference.jobId, reference.job_id, reference.id && !isSha256(reference.id) ? reference.id : null);
  const fallbackId = pickFirst(reference.id, reference.submissionId, reference.submission_id);

  if (sha256 && jobId) {
    return `${webBase}/sample/${sha256}/${jobId}`;
  }

  const publicId = pickFirst(sha256, jobId, fallbackId);
  return publicId ? `${webBase}/sample/${publicId}` : null;
}

function normalizeScannerSummary(collection) {
  return normalizeScannerCollection(collection).map(({ key, value }) => ({
    name: value?.name || key,
    verdict: pickFirst(
      value?.verdict,
      value?.classification,
      value?.label,
      value?.result,
      value?.statusRaw,
      value?.status_raw,
      value?.status,
    ) || null,
    score: pickFirst(
      value?.score,
      value?.confidence,
      value?.threat_score,
      value?.percent,
      value?.positives,
    ) || null,
  }));
}

function extractCrowdStrikeVerdict(payload) {
  const scanners = [
    ...normalizeScannerCollection(payload?.scanners_v2),
    ...normalizeScannerCollection(payload?.scanners),
  ];

  const crowdStrike = scanners.find(({ key, value }) => {
    const joined = `${key} ${value?.name || ''} ${value?.scanner || ''}`.toLowerCase();
    return joined.includes('crowdstrike') || joined.includes('falcon');
  });

  if (!crowdStrike) {
    return null;
  }

  const rawVerdict = pickFirst(
    crowdStrike.value?.verdict,
    crowdStrike.value?.classification,
    crowdStrike.value?.label,
    crowdStrike.value?.statusRaw,
    crowdStrike.value?.status_raw,
    crowdStrike.value?.status,
    crowdStrike.value?.result,
  );

  const score = pickFirst(
    crowdStrike.value?.score,
    crowdStrike.value?.confidence,
    crowdStrike.value?.threat_score,
  );
  const normalizedVerdict = mapRawVerdict(rawVerdict, null);
  const isPending = normalizedVerdict === null && ['no-result', 'no result', 'in-queue', 'in_queue', 'queued', 'pending', 'processing'].includes(String(rawVerdict || '').trim().toLowerCase());

  return createProviderResult({
    id: 'crowdstrike-ml',
    name: 'CrowdStrike ML',
    verdict: normalizedVerdict ?? (rawVerdict && !isPending ? 'REVIEW' : null),
    message: rawVerdict
      ? isPending
        ? 'CrowdStrike ML is still processing.'
        : `CrowdStrike ML verdict: ${rawVerdict}.`
      : 'CrowdStrike ML data available.',
    metadata: {
      label: crowdStrike.value?.label || null,
      rawVerdict: rawVerdict || null,
      score,
    },
  });
}

function summarizeMitre(payload) {
  const raw = payload?.mitre_attcks || payload?.mitre_attck || payload?.mitre;
  if (!Array.isArray(raw)) {
    return [];
  }

  return raw
    .map((item) => pickFirst(item?.attck_id, item?.id, item?.technique, item?.name))
    .filter(Boolean)
    .slice(0, 8);
}

function summarizeHosts(payload) {
  const collections = [
    payload?.hosts,
    payload?.domains,
    payload?.domains_info,
    payload?.contacted_hosts,
    payload?.network?.hosts,
  ];

  const hosts = [];
  collections.forEach((collection) => {
    if (Array.isArray(collection)) {
      collection.forEach((item) => {
        const host = pickFirst(item?.host, item?.domain, item?.ip, item?.name, item);
        if (host && !hosts.includes(host)) {
          hosts.push(String(host));
        }
      });
    }
  });

  return hosts.slice(0, 10);
}

function summarizeDroppedFiles(payload) {
  const raw = payload?.extracted_files || payload?.dropped_files || payload?.files;
  if (!Array.isArray(raw)) {
    return [];
  }

  return raw
    .map((item) => pickFirst(item?.name, item?.filename, item?.sha256))
    .filter(Boolean)
    .slice(0, 10);
}

function summarizeSignatures(payload) {
  const raw = payload?.signatures || payload?.tags;
  if (!Array.isArray(raw)) {
    return [];
  }

  return raw
    .map((item) => pickFirst(item?.name, item?.description, item))
    .filter(Boolean)
    .map((item) => String(item))
    .slice(0, 10);
}

function normalizeQuickScanPayload(payload, config = getHybridAnalysisConfig()) {
  if (!payload) {
    return null;
  }

  const sha256 = pickFirst(payload.sha256, payload.sha256_hex) || null;
  const quickScanId = pickFirst(payload.id, payload.quick_scan_id, payload.scan_id);
  const reportId = pickFirst(quickScanId, payload.job_id, sha256);
  const crowdStrike = extractCrowdStrikeVerdict(payload);
  const rawVerdict = pickFirst(
    payload.verdict,
    payload.verdict_human,
    payload.threat_level_human,
    payload.threat_level,
    payload.classification,
    payload.result,
    crowdStrike?.metadata?.rawVerdict,
  );
  const threatScore = pickFirst(payload.threat_score, payload.score, payload.vx_family_score);
  const scannerSummary = normalizeScannerSummary(payload?.scanners_v2);
  const verdict = mapRawVerdict(rawVerdict, toNumber(threatScore, 0) > 0 ? 'REVIEW' : null);
  const status = normalizeAnalysisStatus(
    pickFirst(payload.status, payload.state, payload.scan_status),
    payload.finished ? 'completed' : 'queued',
  );
  const finished = Boolean(
    payload.finished
    || payload.done
    || ['completed', 'failed'].includes(status)
  );

  return {
    id: reportId ? String(reportId) : null,
    quickScanId: quickScanId ? String(quickScanId) : null,
    sha256: sha256 ? String(sha256) : null,
    status: finished && status === 'queued' ? 'completed' : status,
    finished,
    verdict,
    rawVerdict: rawVerdict || null,
    threatScore: toNumber(threatScore, null),
    classification: pickFirst(payload.classification, payload.vx_family, payload.type_short, payload.type) || null,
    reportUrl: buildReportUrl(config, { id: reportId, sha256 }),
    crowdStrike,
    scannerSummary,
    message: payload.message || null,
    raw: payload,
  };
}

function normalizeHashLookupPayload(payload, config = getHybridAnalysisConfig()) {
  const items = Array.isArray(payload)
    ? payload
    : Array.isArray(payload?.data)
      ? payload.data
      : Array.isArray(payload?.result)
        ? payload.result
        : Array.isArray(payload?.reports)
          ? payload.reports
          : [];

  if (items.length === 0) {
    return null;
  }

  const [match] = items;
  const sha256 = pickFirst(match?.sha256, match?.sha256_hex, payload?.sha256, payload?.sha256s?.[0]) || null;
  const reportId = pickFirst(match?.id, match?.job_id, sha256, match?.sha1);
  const rawVerdict = pickFirst(match?.verdict, match?.threat_level_human, match?.threat_level, match?.classification);

  return {
    found: true,
    id: reportId ? String(reportId) : null,
    sha256,
    verdict: mapRawVerdict(rawVerdict, toNumber(match?.threat_score, 0) > 0 ? 'REVIEW' : null),
    rawVerdict: rawVerdict || null,
    classification: pickFirst(match?.classification, match?.vx_family, match?.type_short, match?.type) || null,
    threatScore: toNumber(pickFirst(match?.threat_score, match?.score), null),
    reportUrl: buildReportUrl(config, {
      id: reportId,
      sha256,
      jobId: match?.job_id || match?.id,
    }),
    state: pickFirst(match?.state, match?.analysis_state, match?.status) || null,
    mitreTechniques: summarizeMitre(match),
    contactedHosts: summarizeHosts(match),
    droppedFiles: summarizeDroppedFiles(match),
    signatures: summarizeSignatures(match),
    raw: match,
  };
}

function normalizeReportOverviewPayload(payload, config = getHybridAnalysisConfig()) {
  if (!payload) {
    return null;
  }

  const sha256 = pickFirst(payload.sha256, payload.sha256_hex) || null;
  const jobId = pickFirst(payload.job_id, payload.id && !isSha256(payload.id) ? payload.id : null);
  const reportId = pickFirst(jobId, sha256, payload.id, payload.sha1);
  const rawVerdict = pickFirst(
    payload.verdict,
    payload.verdict_human,
    payload.threat_level_human,
    payload.threat_level,
    payload.classification,
    payload.result,
  );
  const status = normalizeAnalysisStatus(pickFirst(payload.state, payload.status, payload.analysis_state), 'completed');

  return {
    id: reportId ? String(reportId) : null,
    sha256: sha256 ? String(sha256) : null,
    jobId: jobId ? String(jobId) : null,
    status,
    verdict: mapRawVerdict(rawVerdict, toNumber(pickFirst(payload.threat_score, payload.score), 0) > 0 ? 'REVIEW' : null),
    rawVerdict: rawVerdict || null,
    reportUrl: buildReportUrl(config, { id: reportId, sha256, jobId }),
    classification: pickFirst(payload.classification, payload.vx_family, payload.type_short, payload.type) || null,
    threatScore: toNumber(pickFirst(payload.threat_score, payload.score), null),
    mitreTechniques: summarizeMitre(payload),
    contactedHosts: summarizeHosts(payload),
    droppedFiles: summarizeDroppedFiles(payload),
    signatures: summarizeSignatures(payload),
    scannerSummary: normalizeScannerSummary(payload?.scanners_v2),
    crowdStrike: extractCrowdStrikeVerdict(payload),
    message: payload.message || null,
    raw: payload,
  };
}

function normalizeReportStatePayload(payload, config = getHybridAnalysisConfig(), reportRef = {}) {
  if (!payload) {
    return null;
  }

  const relatedReport = Array.isArray(payload.related_reports) ? payload.related_reports[0] : null;
  const sha256 = pickFirst(payload.sha256, relatedReport?.sha256, reportRef.sha256) || null;
  const jobId = pickFirst(payload.job_id, relatedReport?.job_id, reportRef.jobId, reportRef.id && !isSha256(reportRef.id) ? reportRef.id : null);
  const reportId = pickFirst(jobId, sha256, reportRef.id);
  const rawVerdict = pickFirst(payload.verdict, relatedReport?.verdict);
  const status = normalizeAnalysisStatus(payload.state || payload.status, 'running');

  return {
    id: reportId ? String(reportId) : null,
    sha256: sha256 ? String(sha256) : null,
    jobId: jobId ? String(jobId) : null,
    status,
    verdict: mapRawVerdict(rawVerdict, null),
    rawVerdict: rawVerdict || null,
    reportUrl: buildReportUrl(config, { id: reportId, sha256, jobId }),
    classification: null,
    threatScore: null,
    mitreTechniques: [],
    contactedHosts: [],
    droppedFiles: [],
    signatures: [],
    scannerSummary: [],
    crowdStrike: null,
    message: pickFirst(payload.message, payload.error, payload.error_type, payload.error_origin) || null,
    raw: payload,
  };
}

function mergeQuickScanWithOverview(quickScan, overview) {
  if (!overview) {
    return quickScan;
  }

  const status = overview.status || quickScan.status;

  return {
    ...quickScan,
    status,
    finished: quickScan.finished || ['completed', 'failed'].includes(status),
    verdict: overview.verdict || quickScan.verdict,
    rawVerdict: overview.rawVerdict || quickScan.rawVerdict,
    threatScore: overview.threatScore ?? quickScan.threatScore,
    classification: overview.classification || quickScan.classification,
    reportUrl: overview.reportUrl || quickScan.reportUrl,
    scannerSummary: overview.scannerSummary?.length ? overview.scannerSummary : quickScan.scannerSummary,
    crowdStrike: overview.crowdStrike || quickScan.crowdStrike,
    message: overview.message || quickScan.message,
    overview,
  };
}

function normalizeSubmissionPayload(payload, config = getHybridAnalysisConfig(), environmentId = null) {
  const jobId = pickFirst(payload?.job_id, payload?.id) || null;
  const submissionId = pickFirst(payload?.submission_id, payload?.submissionId) || null;
  const sha256 = pickFirst(payload?.sha256, payload?.sha256_hex) || null;
  const id = pickFirst(jobId, submissionId, sha256);
  const reportRef = pickFirst(jobId, sha256 && environmentId ? `${sha256}:${environmentId}` : null, sha256);

  return {
    id: id ? String(id) : null,
    jobId: jobId ? String(jobId) : null,
    submissionId: submissionId ? String(submissionId) : null,
    sha256: sha256 ? String(sha256) : null,
    reportRef: reportRef ? String(reportRef) : null,
    reportUrl: buildReportUrl(config, { id, sha256, jobId }),
    raw: payload,
    environmentId,
  };
}

function createHybridAnalysisClient({
  config = getHybridAnalysisConfig(),
  httpClient = axios,
} = {}) {
  function assertReady() {
    if (!config.enabled) {
      throw new Error('Hybrid Analysis integration is disabled.');
    }

    if (!config.apiKey) {
      throw new Error('Hybrid Analysis API key is not configured.');
    }
  }

  async function request(method, endpoint, options = {}) {
    assertReady();

    const timeout = options.timeout || config.requestTimeoutMs || 60000;
    const url = new URL(`${config.baseUrl}${endpoint}`);
    Object.entries(options.params || {}).forEach(([key, value]) => {
      if (value !== undefined && value !== null && value !== '') {
        url.searchParams.set(key, String(value));
      }
    });

    const headers = {
      Accept: 'application/json',
      'User-Agent': 'Argus-Core/1.0',
      'api-key': config.apiKey,
      ...(options.headers || {}),
    };

    let body = options.data;
    if (
      body !== undefined
      && body !== null
      && !isFormDataBody(body)
      && !isUrlEncodedBody(body)
      && !isBinaryBody(body)
      && typeof body === 'object'
    ) {
      body = JSON.stringify(body);
      if (!headers['Content-Type']) {
        headers['Content-Type'] = 'application/json';
      }
    }

    let status = 0;
    let data = null;

    if (typeof fetch === 'function') {
      let response;
      try {
        response = await fetch(url, {
          method,
          headers,
          body,
          signal: AbortSignal.timeout(timeout),
        });
      } catch (error) {
        if (error?.name === 'TimeoutError' || error?.name === 'AbortError') {
          const timeoutError = new Error(`[${method.toUpperCase()} ${endpoint}] Hybrid Analysis timed out after ${timeout} ms.`);
          timeoutError.code = 'ECONNABORTED';
          timeoutError.status = 504;
          timeoutError.endpoint = endpoint;
          timeoutError.isTimeout = true;
          throw timeoutError;
        }

        throw error;
      }

      status = response.status;
      const contentType = response.headers.get('content-type') || '';
      if (status !== 204) {
        if (contentType.includes('application/json')) {
          data = await response.json();
        } else {
          const text = await response.text();
          data = text ? { message: text } : null;
        }
      }
    } else {
      let response;
      try {
        response = await httpClient.request({
          method,
          url: url.toString(),
          headers,
          data: body,
          timeout,
          validateStatus: () => true,
          maxBodyLength: Infinity,
          maxContentLength: Infinity,
        });
      } catch (error) {
        if (String(error?.code || '').toUpperCase() === 'ECONNABORTED') {
          const timeoutError = new Error(`[${method.toUpperCase()} ${endpoint}] Hybrid Analysis timed out after ${timeout} ms.`);
          timeoutError.code = error.code;
          timeoutError.status = 504;
          timeoutError.endpoint = endpoint;
          timeoutError.isTimeout = true;
          throw timeoutError;
        }

        throw error;
      }

      status = response.status;
      data = response.data;
    }

    if (status >= 400) {
      const validationSummary = summarizeValidationErrors(data?.validation_errors);
      const validationRaw = stringifyValidationErrors(data?.validation_errors);
      const primaryMessage = pickFirst(
        data?.message,
        data?.error,
        data?.detail,
        `Hybrid Analysis request failed with status ${status}.`,
      );
      const validationMessage = validationSummary && validationSummary.length > 12
        ? validationSummary
        : validationRaw;
      const message = pickFirst(
        validationMessage ? `${primaryMessage} ${validationMessage}` : '',
        primaryMessage,
      );
      const error = new Error(`[${method.toUpperCase()} ${endpoint}] ${message}`);
      error.status = status;
      error.payload = data;
      error.endpoint = endpoint;
      throw error;
    }

    return data;
  }

  async function lookupHash(hash, options = {}) {
    const attempts = [
      () => request('GET', '/search/hash', {
        params: { hash },
        timeout: pickFirst(options.timeoutMs, 8000),
      }),
      () => request('GET', `/search/hash/${hash}`, {
        timeout: pickFirst(options.timeoutMs, 8000),
      }),
      () => request('POST', '/search/hash', {
        data: { hash },
        timeout: pickFirst(options.timeoutMs, 8000),
      }),
    ];

    let lastError = null;
    for (const attempt of attempts) {
      try {
        const payload = await attempt();
        return normalizeHashLookupPayload(payload, config);
      } catch (error) {
        lastError = error;
        if (!isRetryableValidationError(error)) {
          throw error;
        }
      }
    }

    if (isRetryableValidationError(lastError)) {
      return null;
    }

    throw lastError;
  }

  function buildReportCandidates(reportId, options = {}) {
    const candidates = [];
    const pushCandidate = (value) => {
      if (value !== undefined && value !== null && value !== '') {
        const candidate = String(value);
        if (!candidates.includes(candidate)) {
          candidates.push(candidate);
        }
      }
    };

    const sha256 = pickFirst(options.sha256, isSha256(reportId) ? reportId : null);
    const environmentId = pickFirst(options.environmentId, options.environment_id, config.environmentId);
    const jobId = pickFirst(options.jobId, options.job_id, reportId && !isSha256(reportId) ? reportId : null);

    pushCandidate(reportId);
    pushCandidate(jobId);
    if (sha256 && environmentId) {
      pushCandidate(`${sha256}:${environmentId}`);
    }
    pushCandidate(sha256);

    return candidates;
  }

  async function getOverview(sha256) {
    if (!isSha256(sha256)) {
      throw new Error('Hybrid Analysis overview lookup requires a SHA256 hash.');
    }

    try {
      const payload = await request('GET', `/overview/${sha256}`);
      return normalizeReportOverviewPayload(payload, config);
    } catch (error) {
      if (error.status !== 404) {
        throw error;
      }

      const fallback = await request('GET', `/overview/${sha256}/summary`);
      return normalizeReportOverviewPayload(fallback, config);
    }
  }

  async function hydrateQuickScanWithOverview(quickScan, options = {}) {
    if (!quickScan?.sha256 || (!quickScan.finished && options.fetchOverviewWhenPending !== true)) {
      return quickScan;
    }

    try {
      const overview = await getOverview(quickScan.sha256);
      return mergeQuickScanWithOverview(quickScan, overview);
    } catch (error) {
      if (isRetryableValidationError(error)) {
        return quickScan;
      }

      throw error;
    }
  }

  async function requestFirstReportCandidate(candidates, endpointBuilder, normalize) {
    let lastError = null;

    for (const candidate of candidates) {
      try {
        const payload = await request('GET', endpointBuilder(encodeURIComponent(candidate)));
        return normalize(payload, candidate);
      } catch (error) {
        lastError = error;
        if (!isRetryableValidationError(error)) {
          throw error;
        }
      }
    }

    throw lastError;
  }

  async function getReportState(reportId, options = {}) {
    const candidates = buildReportCandidates(reportId, options);
    return requestFirstReportCandidate(
      candidates,
      (candidate) => `/report/${candidate}/state`,
      (payload, candidate) => normalizeReportStatePayload(payload, config, {
        id: candidate,
        jobId: options.jobId || (!isSha256(candidate) && !candidate.includes(':') ? candidate : null),
        sha256: options.sha256 || (isSha256(candidate) ? candidate : null),
      }),
    );
  }

  async function getReportSummary(reportId, options = {}) {
    const candidates = buildReportCandidates(reportId, options);
    return requestFirstReportCandidate(
      candidates,
      (candidate) => `/report/${candidate}/summary`,
      (payload) => normalizeReportOverviewPayload(payload, config),
    );
  }

  async function quickScanFile(file, options = {}) {
    const environmentId = pickFirst(options.environmentId, config.environmentId);
    const scanType = pickFirst(options.scanType, 'all');
    const attempts = [
      () => request('POST', '/quick-scan/file', {
        data: createMultipartFormData(file, { scanType }),
      }),
      () => request('POST', '/quick-scan/file', {
        data: createMultipartFormData(file, {
          scanType,
          submitName: file.originalname,
        }),
      }),
      () => request('POST', '/quick-scan/file', {
        data: createMultipartFormData(file, {
          scanType,
          submitName: file.originalname,
          comment: options.comment,
        }),
      }),
      () => request('POST', '/quick-scan/file', {
        data: createMultipartFormData(file, {
          scanType,
          submitName: file.originalname,
          comment: options.comment,
          environmentId,
        }),
      }),
    ];

    let payload = null;
    let lastError = null;
    for (const attempt of attempts) {
      try {
        payload = await attempt();
        lastError = null;
        break;
      } catch (error) {
        lastError = error;
        if (!isRetryableValidationError(error)) {
          throw error;
        }
      }
    }

    if (!payload) {
      throw lastError;
    }

    let quickScan = normalizeQuickScanPayload(payload, config);

    if (quickScan?.quickScanId && !quickScan.finished && options.waitForCompletion !== false) {
      try {
        quickScan = await waitForQuickScan(quickScan.quickScanId, options);
      } catch (error) {
        if (!isRetryableValidationError(error)) {
          throw error;
        }

        quickScan = {
          ...quickScan,
          status: 'running',
          finished: false,
          message: 'Hybrid Analysis quick scan was submitted, but status polling is not available for this account yet.',
        };
      }
    }

    return hydrateQuickScanWithOverview(quickScan, options);
  }

  async function getQuickScan(scanId) {
    const attempts = [
      () => request('GET', `/quick-scan/${scanId}`),
      () => request('GET', '/quick-scan', { params: { id: scanId } }),
    ];

    let lastError = null;
    for (const attempt of attempts) {
      try {
        const payload = await attempt();
        return normalizeQuickScanPayload(payload, config);
      } catch (error) {
        lastError = error;
        if (!isRetryableValidationError(error)) {
          throw error;
        }
      }
    }

    throw lastError;
  }

  async function waitForQuickScan(scanId, options = {}) {
    const intervalMs = pickFirst(options.intervalMs, config.pollIntervalMs, 5000);
    const timeoutMs = pickFirst(options.timeoutMs, config.pollTimeoutMs, 120000);
    const deadline = Date.now() + timeoutMs;
    let latest = null;

    while (Date.now() <= deadline) {
      latest = await getQuickScan(scanId);
      if (!latest || latest.finished || ['completed', 'failed'].includes(latest.status)) {
        return latest;
      }

      await new Promise((resolve) => setTimeout(resolve, intervalMs));
    }

    return latest;
  }

  async function submitFile(file, options = {}) {
    const environmentId = pickFirst(options.environmentId, config.environmentId);
    if (!environmentId) {
      throw new Error('Hybrid Analysis sandbox submission requires HYBRID_ANALYSIS_ENVIRONMENT_ID.');
    }

    const formData = createMultipartFormData(file, {
      environmentId,
      submitName: file.originalname,
      comment: options.comment,
      noShareThirdParty: options.noShareThirdParty,
    });

    const payload = await request('POST', '/submit/file', { data: formData });
    return normalizeSubmissionPayload(payload, config, environmentId);
  }

  async function submitUrl(url, options = {}) {
    const environmentId = pickFirst(options.environmentId, config.environmentId);
    if (!environmentId) {
      throw new Error('Hybrid Analysis URL submission requires HYBRID_ANALYSIS_ENVIRONMENT_ID.');
    }

    const formData = new FormData();
    formData.append('url', String(url));
    formData.append('environment_id', String(environmentId));

    if (options.comment) {
      formData.append('comment', String(options.comment));
    }

    if (options.noShareThirdParty !== undefined) {
      formData.append('no_share_third_party', String(Boolean(options.noShareThirdParty)));
    }

    let payload;
    try {
      payload = await request('POST', '/submit/url', { data: formData });
    } catch (error) {
      if (error.status !== 404) {
        throw error;
      }

      payload = await request('POST', '/submit/url-to-file', { data: formData });
    }
    return normalizeSubmissionPayload(payload, config, environmentId);
  }

  async function getReportOverview(reportId, options = {}) {
    let state = null;
    try {
      state = await getReportState(reportId, options);
      if (state && ['queued', 'running', 'failed'].includes(state.status)) {
        return state;
      }
    } catch (error) {
      if (!isRetryableValidationError(error)) {
        throw error;
      }
    }

    try {
      return await getReportSummary(reportId, options);
    } catch (error) {
      if (!isRetryableValidationError(error)) {
        throw error;
      }

      const sha256 = pickFirst(options.sha256, isSha256(reportId) ? reportId : null);
      if (sha256) {
        try {
          return await getOverview(sha256);
        } catch (overviewError) {
          if (!isRetryableValidationError(overviewError)) {
            throw overviewError;
          }
        }
      }

      if (state) {
        return state;
      }

      throw error;
    }
  }

  async function pollSandboxReport(reportId, options = {}) {
    const intervalMs = pickFirst(options.intervalMs, config.pollIntervalMs, 5000);
    const timeoutMs = pickFirst(options.timeoutMs, config.pollTimeoutMs, 120000);
    const deadline = Date.now() + timeoutMs;
    let latest = null;

    while (Date.now() <= deadline) {
      latest = await getReportOverview(reportId, options);
      if (!latest || ['completed', 'failed'].includes(latest.status)) {
        return latest;
      }

      await new Promise((resolve) => setTimeout(resolve, intervalMs));
    }

    return latest;
  }

  return {
    config,
    getOverview,
    getQuickScan,
    getReportOverview,
    getReportState,
    getReportSummary,
    lookupHash,
    pollSandboxReport,
    quickScanFile,
    request,
    submitFile,
    submitUrl,
    waitForQuickScan,
  };
}

module.exports = {
  DEFAULT_BASE_URL,
  DEFAULT_ENVIRONMENTS,
  createHybridAnalysisClient,
  createProviderResult,
  extractCrowdStrikeVerdict,
  getHybridAnalysisConfig,
  mapRawVerdict,
  normalizeHashLookupPayload,
  normalizeQuickScanPayload,
  normalizeReportOverviewPayload,
  parseBoolean,
  toNumber,
};
