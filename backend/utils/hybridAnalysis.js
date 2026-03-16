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
    'not malicious',
    'harmless',
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

function buildReportUrl(config, reportId) {
  if (!reportId) {
    return null;
  }

  const base = config?.baseUrl || DEFAULT_BASE_URL;
  return `${base.replace('/api/v2', '') || 'https://www.hybrid-analysis.com'}/sample/${reportId}`;
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
    crowdStrike.value?.status,
    crowdStrike.value?.result,
  );

  const score = pickFirst(
    crowdStrike.value?.score,
    crowdStrike.value?.confidence,
    crowdStrike.value?.threat_score,
  );
  const normalizedVerdict = mapRawVerdict(rawVerdict, null);
  const isPending = normalizedVerdict === null && ['no-result', 'no result', 'in-queue', 'queued', 'pending', 'processing'].includes(String(rawVerdict || '').trim().toLowerCase());

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

  const reportId = pickFirst(payload.id, payload.quick_scan_id, payload.scan_id, payload.job_id, payload.sha256);
  const rawVerdict = pickFirst(
    payload.verdict,
    payload.threat_level,
    payload.classification,
    payload.result,
    payload.state,
  );
  const threatScore = pickFirst(payload.threat_score, payload.score, payload.vx_family_score);
  const scannerSummary = normalizeScannerCollection(payload?.scanners_v2).map(({ key, value }) => ({
    name: value?.name || key,
    verdict: pickFirst(value?.verdict, value?.classification, value?.label, value?.result, value?.status) || null,
    score: pickFirst(value?.score, value?.confidence, value?.threat_score) || null,
  }));
  const verdict = mapRawVerdict(rawVerdict, toNumber(threatScore, 0) > 0 ? 'REVIEW' : null);
  const crowdStrike = extractCrowdStrikeVerdict(payload);

  return {
    id: reportId ? String(reportId) : null,
    status: String(pickFirst(payload.status, payload.state, payload.scan_status, payload.finished ? 'finished' : 'queued')).toLowerCase(),
    finished: Boolean(payload.finished || payload.done || ['finished', 'completed', 'success'].includes(String(payload.status || payload.state || '').toLowerCase())),
    verdict,
    rawVerdict: rawVerdict || null,
    threatScore: toNumber(threatScore, null),
    classification: pickFirst(payload.classification, payload.vx_family, payload.type_short, payload.type) || null,
    reportUrl: buildReportUrl(config, reportId),
    crowdStrike,
    scannerSummary,
    message: payload.message || null,
  };
}

function normalizeHashLookupPayload(payload, config = getHybridAnalysisConfig()) {
  const items = Array.isArray(payload)
    ? payload
    : Array.isArray(payload?.data)
      ? payload.data
      : Array.isArray(payload?.result)
        ? payload.result
        : [];

  if (items.length === 0) {
    return null;
  }

  const [match] = items;
  const reportId = pickFirst(match?.id, match?.job_id, match?.sha256, match?.sha1);
  const rawVerdict = pickFirst(match?.verdict, match?.threat_level, match?.state, match?.classification);

  return {
    found: true,
    id: reportId ? String(reportId) : null,
    sha256: pickFirst(match?.sha256, match?.sha256_hex) || null,
    verdict: mapRawVerdict(rawVerdict, toNumber(match?.threat_score, 0) > 0 ? 'REVIEW' : null),
    rawVerdict: rawVerdict || null,
    classification: pickFirst(match?.classification, match?.vx_family, match?.type_short, match?.type) || null,
    threatScore: toNumber(pickFirst(match?.threat_score, match?.score), null),
    reportUrl: buildReportUrl(config, reportId),
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

  const reportId = pickFirst(payload.id, payload.job_id, payload.sha256, payload.sha1);
  const rawVerdict = pickFirst(payload.verdict, payload.threat_level, payload.classification, payload.state, payload.result);
  const state = String(pickFirst(payload.state, payload.status, payload.analysis_state, 'completed')).toLowerCase();

  return {
    id: reportId ? String(reportId) : null,
    status: ['queued', 'running', 'processing'].includes(state) ? state : state === 'error' ? 'failed' : 'completed',
    verdict: mapRawVerdict(rawVerdict, toNumber(pickFirst(payload.threat_score, payload.score), 0) > 0 ? 'REVIEW' : null),
    rawVerdict: rawVerdict || null,
    reportUrl: buildReportUrl(config, reportId),
    classification: pickFirst(payload.classification, payload.vx_family, payload.type_short, payload.type) || null,
    threatScore: toNumber(pickFirst(payload.threat_score, payload.score), null),
    mitreTechniques: summarizeMitre(payload),
    contactedHosts: summarizeHosts(payload),
    droppedFiles: summarizeDroppedFiles(payload),
    signatures: summarizeSignatures(payload),
    scannerSummary: normalizeScannerCollection(payload?.scanners_v2).map(({ key, value }) => ({
      name: value?.name || key,
      verdict: pickFirst(value?.verdict, value?.classification, value?.label, value?.result, value?.status) || null,
      score: pickFirst(value?.score, value?.confidence, value?.threat_score) || null,
    })),
    crowdStrike: extractCrowdStrikeVerdict(payload),
    message: payload.message || null,
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
      'User-Agent': 'Sentinel-Core/1.0',
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

    if (quickScan?.id && !quickScan.finished && options.waitForCompletion !== false) {
      try {
        quickScan = await waitForQuickScan(quickScan.id, options);
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

    return quickScan;
  }

  async function getQuickScan(scanId) {
    const attempts = [
      () => request('GET', `/quick-scan/${scanId}`),
      () => request('GET', '/quick-scan', { params: { id: scanId } }),
      () => request('GET', `/quick-scan/state/${scanId}`),
      () => request('GET', '/quick-scan/state', { params: { id: scanId } }),
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
      if (!latest || latest.finished || ['completed', 'finished', 'failed'].includes(latest.status)) {
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
    return {
      id: pickFirst(payload?.id, payload?.job_id, payload?.submission_id, payload?.sha256) ? String(pickFirst(payload?.id, payload?.job_id, payload?.submission_id, payload?.sha256)) : null,
      reportUrl: buildReportUrl(config, pickFirst(payload?.id, payload?.job_id, payload?.submission_id, payload?.sha256)),
      raw: payload,
      environmentId,
    };
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
    return {
      id: pickFirst(payload?.id, payload?.job_id, payload?.submission_id, payload?.sha256) ? String(pickFirst(payload?.id, payload?.job_id, payload?.submission_id, payload?.sha256)) : null,
      reportUrl: buildReportUrl(config, pickFirst(payload?.id, payload?.job_id, payload?.submission_id, payload?.sha256)),
      raw: payload,
      environmentId,
    };
  }

  async function getReportOverview(reportId) {
    try {
      const payload = await request('GET', `/report/${reportId}/overview`);
      return normalizeReportOverviewPayload(payload, config);
    } catch (error) {
      if (error.status === 404) {
        const fallback = await request('GET', `/overview/${reportId}`);
        return normalizeReportOverviewPayload(fallback, config);
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
      latest = await getReportOverview(reportId);
      if (!latest || ['completed', 'failed'].includes(latest.status)) {
        return latest;
      }

      await new Promise((resolve) => setTimeout(resolve, intervalMs));
    }

    return latest;
  }

  return {
    config,
    getQuickScan,
    getReportOverview,
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
