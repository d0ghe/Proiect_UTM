const test = require('node:test');
const assert = require('node:assert/strict');

const { CATEGORY_IDS, isDomainBlocked } = require('../store/contentFilterStore');
const {
  applyPolicy,
  checkDomainAgainstPolicy,
  parseDomainList,
  parseValidatedCategoryDomains,
  removePolicyEnforcement,
} = require('../utils/contentFilter');

function buildDisabledCategories() {
  return CATEGORY_IDS.reduce((categories, id) => {
    categories[id] = false;
    return categories;
  }, {});
}

test('content filter applies and clears proxy cache for custom domains', async () => {
  const previousProxyEnv = process.env.CONTENT_FILTER_BROWSER_PROXY_ENABLED;
  process.env.CONTENT_FILTER_BROWSER_PROXY_ENABLED = 'true';

  try {
    const applied = await applyPolicy({
      enabled: true,
      categories: buildDisabledCategories(),
      customBlocklist: ['ads.example.test', 'allow.example.test'],
      allowlist: ['allow.example.test'],
    }, { sync: false, configureBrowserProxy: false });

    assert.equal(applied.applied, true);
    assert.equal(applied.enforcementMode, 'proxy');
    assert.equal(applied.appliedDomainCount, 1);
    assert.equal(applied.proxyAddress, '127.0.0.1:8877');
    assert.equal(isDomainBlocked('ads.example.test'), true);
    assert.equal(isDomainBlocked('media.ads.example.test'), true);
    assert.equal(isDomainBlocked('allow.example.test'), false);

    const removed = removePolicyEnforcement();
    assert.equal(removed.removed, true);
    assert.equal(isDomainBlocked('ads.example.test'), false);
  } finally {
    if (previousProxyEnv) {
      process.env.CONTENT_FILTER_BROWSER_PROXY_ENABLED = previousProxyEnv;
    } else {
      delete process.env.CONTENT_FILTER_BROWSER_PROXY_ENABLED;
    }

    removePolicyEnforcement();
  }
});

test('domain checks use cached custom policy data without syncing remote sources', async () => {
  const result = await checkDomainAgainstPolicy('media.ads.example.test', {
    enabled: true,
    categories: buildDisabledCategories(),
    customBlocklist: ['ads.example.test'],
    allowlist: [],
  });

  assert.equal(result.blocked, true);
  assert.equal(result.matchedDomain, 'ads.example.test');
  assert.deepEqual(result.reasons, ['custom']);
});

test('disabled policies do not block domains that remain selected in the draft policy', async () => {
  const result = await checkDomainAgainstPolicy('media.ads.example.test', {
    enabled: false,
    categories: buildDisabledCategories(),
    customBlocklist: ['ads.example.test'],
    allowlist: [],
  });

  assert.equal(result.blocked, false);
  assert.equal(result.matchedDomain, '');
  assert.deepEqual(result.reasons, []);
});

test('blocklist parsing accepts wildcard entries and rejects CDN error bodies', () => {
  assert.deepEqual(parseDomainList('*.ads.example.test\n||tracker.example.test^\n0.0.0.0 pixel.example.test'), [
    'ads.example.test',
    'tracker.example.test',
    'pixel.example.test',
  ]);

  assert.throws(
    () => parseValidatedCategoryDomains('429: Too Many Requests\nFor more on scraping GitHub and how it may affect your rights'),
    /valid domain list/,
  );
});

test('disabled browser proxy compiles policy without enabling runtime blocking', async () => {
  const previousProxyEnv = process.env.CONTENT_FILTER_BROWSER_PROXY_ENABLED;
  process.env.CONTENT_FILTER_BROWSER_PROXY_ENABLED = 'false';

  try {
    const applied = await applyPolicy({
      enabled: true,
      categories: buildDisabledCategories(),
      customBlocklist: ['one.example.test', 'two.example.test'],
      allowlist: [],
    }, { sync: false, configureBrowserProxy: false });

    assert.equal(applied.applied, false);
    assert.equal(applied.enforcementMode, 'none');
    assert.equal(applied.appliedDomainCount, 0);
    assert.match(applied.proxyMessage, /proxy enforcement is disabled/);
    assert.equal(isDomainBlocked('one.example.test'), false);
  } finally {
    if (previousProxyEnv) {
      process.env.CONTENT_FILTER_BROWSER_PROXY_ENABLED = previousProxyEnv;
    } else {
      delete process.env.CONTENT_FILTER_BROWSER_PROXY_ENABLED;
    }

    removePolicyEnforcement();
  }
});
