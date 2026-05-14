const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { CATEGORY_IDS } = require('../store/contentFilterStore');
const {
  applyPolicy,
  checkDomainAgainstPolicy,
  parseDomainList,
  parseValidatedCategoryDomains,
  removeManagedBlock,
} = require('../utils/contentFilter');

function buildDisabledCategories() {
  return CATEGORY_IDS.reduce((categories, id) => {
    categories[id] = false;
    return categories;
  }, {});
}

test('content filter writes and removes a managed hosts section for custom domains', async () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'content-filter-'));
  const hostsPath = path.join(tempDir, 'hosts');
  const originalHosts = '127.0.0.1 localhost\n';
  fs.writeFileSync(hostsPath, originalHosts);

  const previousHostsEnv = process.env.CONTENT_FILTER_HOSTS_FILE;
  process.env.CONTENT_FILTER_HOSTS_FILE = hostsPath;

  try {
    const applied = await applyPolicy({
      enabled: true,
      categories: buildDisabledCategories(),
      customBlocklist: ['ads.example.test', 'allow.example.test'],
      allowlist: ['allow.example.test'],
    }, { sync: false });

    const afterApply = fs.readFileSync(hostsPath, 'utf8');
    assert.equal(applied.applied, true);
    assert.match(afterApply, /ads\.example\.test/);
    assert.doesNotMatch(afterApply, /allow\.example\.test/);

    const removed = removeManagedBlock();
    const afterRemove = fs.readFileSync(hostsPath, 'utf8');
    assert.equal(removed.removed, true);
    assert.equal(afterRemove.trim(), originalHosts.trim());
  } finally {
    if (previousHostsEnv) {
      process.env.CONTENT_FILTER_HOSTS_FILE = previousHostsEnv;
    } else {
      delete process.env.CONTENT_FILTER_HOSTS_FILE;
    }
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

test('large hosts policies are not written to hosts and remove stale managed entries', async () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'content-filter-large-'));
  const hostsPath = path.join(tempDir, 'hosts');
  fs.writeFileSync(hostsPath, [
    '127.0.0.1 localhost',
    '# === U-Trust Content Filter Start ===',
    '# stale',
    '0.0.0.0 stale.example.test',
    '# === U-Trust Content Filter End ===',
    '',
  ].join('\n'));

  const previousHostsEnv = process.env.CONTENT_FILTER_HOSTS_FILE;
  const previousMaxEnv = process.env.CONTENT_FILTER_HOSTS_MAX_DOMAINS;
  process.env.CONTENT_FILTER_HOSTS_FILE = hostsPath;
  process.env.CONTENT_FILTER_HOSTS_MAX_DOMAINS = '1';

  try {
    const applied = await applyPolicy({
      enabled: true,
      categories: buildDisabledCategories(),
      customBlocklist: ['one.example.test', 'two.example.test'],
      allowlist: [],
    }, { sync: false });

    const afterApply = fs.readFileSync(hostsPath, 'utf8');
    assert.equal(applied.applied, false);
    assert.equal(applied.enforcementMode, 'none');
    assert.match(applied.hostsSkippedReason, /above the safe Windows hosts limit/);
    assert.doesNotMatch(afterApply, /stale\.example\.test/);
    assert.doesNotMatch(afterApply, /one\.example\.test/);
  } finally {
    if (previousHostsEnv) {
      process.env.CONTENT_FILTER_HOSTS_FILE = previousHostsEnv;
    } else {
      delete process.env.CONTENT_FILTER_HOSTS_FILE;
    }

    if (previousMaxEnv) {
      process.env.CONTENT_FILTER_HOSTS_MAX_DOMAINS = previousMaxEnv;
    } else {
      delete process.env.CONTENT_FILTER_HOSTS_MAX_DOMAINS;
    }
  }
});
