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
  removeManagedBlock,
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
    if (result.enforcementMode === 'proxy') {
      return `${result.appliedDomainCount} domenii blocate prin proxy optional (Chrome/Edge).`;
    }

    return `${result.appliedDomainCount} domenii blocate prin hosts file.`;
  }

  if ((result.domains?.length || 0) > 0) {
    return 'Blocarea nu a fost aplicata: ruleaza backend-ul ca Administrator pentru hosts file. Proxy-ul browser este dezactivat.';
  }

  return 'Nicio categorie selectata - blocarea a fost dezactivata.';
}

function buildApplyResponseMessage(result) {
  if (result.applied) {
    return `Blocare activa: ${result.appliedDomainCount} domenii.`;
  }

  if ((result.domains?.length || 0) > 0) {
    return 'Blocarea nu a fost aplicata. Ruleaza backend-ul ca Administrator pentru hosts file sau activeaza explicit proxy-ul optional.';
  }

  return 'Nicio categorie selectata.';
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
    const result = await syncPolicy(state.policy, { sync: true });

    updateContentFilterRuntime({
      lastSyncedAt: result.lastSyncedAt,
      categoryDomainCounts: result.categoryDomainCounts,
      sourceStatus: result.sourceStatus,
      lastError: '',
      lastMessage: `Synchronized ${result.domains.length} blocked domains from remote sources.`,
    });

    res.json({
      success: true,
      message: `Synchronized ${result.domains.length} blocked domains.`,
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
    if (hasCategories || hasCustom) {
      patch.enabled = true;
    }

    if (Object.keys(patch).length > 0) {
      updateContentFilterPolicy(patch);
    }

    const state = getContentFilterState();
    const result = await applyPolicy(state.policy, { sync: true });

    updateContentFilterRuntime({
      applied: Boolean(result.applied),
      appliedDomainCount: result.appliedDomainCount,
      categoryDomainCounts: result.categoryDomainCounts,
      sourceStatus: result.sourceStatus,
      lastSyncedAt: result.lastSyncedAt,
      lastApplyAt: result.lastApplyAt,
      dnsFlushMessage: result.dnsFlushMessage,
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
    const result = removeManagedBlock();

    updateContentFilterPolicy({ enabled: false });
    updateContentFilterRuntime({
      applied: false,
      appliedDomainCount: 0,
      lastRemoveAt: result.lastRemoveAt,
      dnsFlushMessage: result.dnsFlushMessage,
      lastError: '',
      lastMessage: 'Removed managed content-filter entries from the hosts file.',
    });

    res.json({
      success: true,
      message: 'Content-filter entries removed from the system hosts file.',
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
