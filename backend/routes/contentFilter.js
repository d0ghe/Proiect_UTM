const express = require('express');

const verifyToken = require('../middleware/verifyToken');
const {
  getContentFilterState,
  updateContentFilterPolicy,
  updateContentFilterRuntime,
} = require('../store/contentFilterStore');
const {
  applyPolicy,
  buildOverview,
  checkDomainAgainstPolicy,
  removePolicyEnforcement,
  splitTextList,
  syncPolicy,
} = require('../utils/contentFilter');

const router = express.Router();

router.use(verifyToken);

function sendError(res, error, fallbackMessage) {
  return res.status(Number(error.status) || 500).json({
    success: false,
    message: error.message || fallbackMessage,
    code: error.code || 'CONTENT_FILTER_ERROR',
  });
}

function buildPolicyPatch(body = {}) {
  const patch = {};

  if (body.enabled !== undefined) {
    patch.enabled = body.enabled;
  }

  if (body.categories && typeof body.categories === 'object') {
    patch.categories = body.categories;
  }

  if (body.customBlocklist !== undefined) {
    patch.customBlocklist = splitTextList(body.customBlocklist);
  }

  if (body.allowlist !== undefined) {
    patch.allowlist = splitTextList(body.allowlist);
  }

  return patch;
}

function buildApplyRuntimeMessage(result) {
  if (result.applied) {
    return `${result.appliedDomainCount} domains blocked through the local proxy.`;
  }

  if ((result.domains?.length || 0) > 0) {
    return 'The policy is compiled, but the browser proxy is disabled.';
  }

  return 'No category selected - blocking has been disabled.';
}

function buildApplyResponseMessage(result) {
  if (result.applied) {
    return `Active blocking: ${result.appliedDomainCount} domains.`;
  }

  if ((result.domains?.length || 0) > 0) {
    return 'Blocking was not applied because the browser proxy is disabled.';
  }

  return 'No category selected.';
}

function countSyncedFeeds(result) {
  return Object.values(result?.categoryDomainCounts || {}).filter((count) => Number(count) > 0).length;
}

router.get('/', (_req, res) => {
  res.json({
    success: true,
    ...buildOverview(getContentFilterState()),
  });
});

router.patch('/', (req, res) => {
  updateContentFilterPolicy(buildPolicyPatch(req.body));

  res.json({
    success: true,
    message: 'Content-filter policy updated.',
    ...buildOverview(getContentFilterState()),
  });
});

router.post('/sync', async (_req, res) => {
  try {
    const state = getContentFilterState();
    const result = await syncPolicy(state.policy, { sync: true, loadAllCategories: true });

    updateContentFilterRuntime({
      lastSyncedAt: result.lastSyncedAt,
      categoryDomainCounts: result.categoryDomainCounts,
      sourceStatus: result.sourceStatus,
      lastError: '',
      lastMessage: `Synchronized ${countSyncedFeeds(result)} category feeds from remote sources.`,
    });

    res.json({
      success: true,
      message: `Synchronized ${countSyncedFeeds(result)} category feeds.`,
      ...buildOverview(getContentFilterState()),
    });
  } catch (error) {
    sendError(res, error, 'Could not sync content-filter sources.');
  }
});

router.post('/apply', async (req, res) => {
  try {
    const patch = buildPolicyPatch(req.body);

    // Auto-activează policy dacă sunt categorii selectate
    const hasCategories = patch.categories && Object.values(patch.categories).some(Boolean);
    const hasCustom = patch.customBlocklist && patch.customBlocklist.length > 0;
    if (patch.enabled === undefined && (hasCategories || hasCustom)) {
      patch.enabled = true;
    }

    if (Object.keys(patch).length > 0) {
      updateContentFilterPolicy(patch);
    }

    const state = getContentFilterState();
    const result = await applyPolicy(state.policy, { sync: true, loadAllCategories: true });

    updateContentFilterRuntime({
      applied: Boolean(result.applied),
      appliedDomainCount: result.appliedDomainCount,
      categoryDomainCounts: result.categoryDomainCounts,
      enforcementMode: result.enforcementMode,
      proxyEnabled: result.proxyEnabled,
      proxyAddress: result.proxyAddress,
      proxyPort: result.proxyPort,
      proxyRunning: result.proxyRunning,
      browserProxyConfigured: result.browserProxyConfigured,
      proxyMessage: result.proxyMessage,
      quicBlocked: result.quicBlocked,
      sourceStatus: result.sourceStatus,
      lastSyncedAt: result.lastSyncedAt,
      lastApplyAt: result.lastApplyAt,
      lastError: '',
      lastMessage: buildApplyRuntimeMessage(result),
    });

    res.json({
      success: true,
      message: buildApplyResponseMessage(result),
      ...buildOverview(getContentFilterState()),
    });
  } catch (error) {
    updateContentFilterRuntime({
      lastError: error.message,
      lastMessage: '',
    });
    sendError(res, error, 'Could not apply content-filter policy.');
  }
});

router.post('/remove', (_req, res) => {
  try {
    const result = removePolicyEnforcement();

    updateContentFilterPolicy({ enabled: false });
    updateContentFilterRuntime({
      applied: false,
      appliedDomainCount: 0,
      enforcementMode: 'none',
      proxyEnabled: result.proxyEnabled,
      proxyAddress: result.proxyAddress,
      proxyPort: result.proxyPort,
      proxyRunning: result.proxyRunning,
      proxyMessage: result.proxyMessage,
      quicBlocked: false,
      lastRemoveAt: result.lastRemoveAt,
      lastError: '',
      lastMessage: 'Content-filter proxy cache cleared.',
    });

    res.json({
      success: true,
      message: 'Content-filter proxy cache cleared.',
      ...buildOverview(getContentFilterState()),
    });
  } catch (error) {
    sendError(res, error, 'Could not remove content-filter entries.');
  }
});

router.post('/check', async (req, res) => {
  try {
    const result = await checkDomainAgainstPolicy(req.body?.domain, getContentFilterState().policy);
    res.json({
      success: true,
      result,
    });
  } catch (error) {
    sendError(res, error, 'Could not check the requested domain.');
  }
});

module.exports = router;
