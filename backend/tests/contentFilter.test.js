const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { CATEGORY_IDS } = require('../store/contentFilterStore');
const {
  applyPolicy,
  checkDomainAgainstPolicy,
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
