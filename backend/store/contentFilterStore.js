const fs = require('fs');
const path = require('path');

const DEFAULT_FILE = path.join(__dirname, 'content-filter-policy.json');
const CATEGORY_IDS = ['adult', 'ads', 'malware', 'gambling', 'social', 'piracy', 'bypass'];

function clone(value) {
  return value === undefined ? undefined : JSON.parse(JSON.stringify(value));
}

function buildDefaultCategories() {
  return CATEGORY_IDS.reduce((categories, id) => {
    categories[id] = false;
    return categories;
  }, {});
}

function createDefaultStore() {
  return {
    policy: {
      enabled: false,
      categories: buildDefaultCategories(),
      customBlocklist: [],
      allowlist: [],
      lastUpdated: new Date().toISOString(),
    },
    runtime: {
      applied: false,
      appliedDomainCount: 0,
      categoryDomainCounts: buildDefaultCategories(),
      lastSyncedAt: null,
      lastApplyAt: null,
      lastRemoveAt: null,
      lastMessage: '',
      lastError: '',
      sourceStatus: {},
      dnsFlushMessage: '',
    },
  };
}

function createContentFilterStore(storeFile = process.env.CONTENT_FILTER_STORE_FILE || DEFAULT_FILE) {
  function ensureStoreFile() {
    const directory = path.dirname(storeFile);
    if (!fs.existsSync(directory)) {
      fs.mkdirSync(directory, { recursive: true });
    }

    if (!fs.existsSync(storeFile)) {
      fs.writeFileSync(storeFile, JSON.stringify(createDefaultStore(), null, 2));
    }
  }

  function readStore() {
    ensureStoreFile();

    try {
      const raw = fs.readFileSync(storeFile, 'utf8').trim();
      if (!raw) {
        return createDefaultStore();
      }

      const parsed = JSON.parse(raw);
      return {
        ...createDefaultStore(),
        ...parsed,
        policy: {
          ...createDefaultStore().policy,
          ...(parsed.policy || {}),
          categories: {
            ...buildDefaultCategories(),
            ...((parsed.policy || {}).categories || {}),
          },
          customBlocklist: Array.isArray(parsed?.policy?.customBlocklist) ? parsed.policy.customBlocklist : [],
          allowlist: Array.isArray(parsed?.policy?.allowlist) ? parsed.policy.allowlist : [],
        },
        runtime: {
          ...createDefaultStore().runtime,
          ...(parsed.runtime || {}),
          categoryDomainCounts: {
            ...buildDefaultCategories(),
            ...((parsed.runtime || {}).categoryDomainCounts || {}),
          },
          sourceStatus: parsed?.runtime?.sourceStatus && typeof parsed.runtime.sourceStatus === 'object'
            ? parsed.runtime.sourceStatus
            : {},
        },
      };
    } catch {
      return createDefaultStore();
    }
  }

  function writeStore(store) {
    ensureStoreFile();
    fs.writeFileSync(storeFile, JSON.stringify(store, null, 2));
  }

  function normalizeDomainList(values) {
    return Array.from(new Set(
      (Array.isArray(values) ? values : [])
        .map((value) => String(value || '').trim().toLowerCase())
        .filter(Boolean),
    ));
  }

  function getContentFilterState() {
    return clone(readStore());
  }

  function updateContentFilterPolicy(patch = {}) {
    const store = readStore();
    const nextPolicy = {
      ...store.policy,
      lastUpdated: new Date().toISOString(),
    };

    if (patch.enabled !== undefined) {
      nextPolicy.enabled = Boolean(patch.enabled);
    }

    if (patch.categories && typeof patch.categories === 'object') {
      nextPolicy.categories = {
        ...nextPolicy.categories,
        ...Object.fromEntries(
          Object.entries(patch.categories)
            .filter(([key]) => CATEGORY_IDS.includes(key))
            .map(([key, value]) => [key, Boolean(value)]),
        ),
      };
    }

    if (patch.customBlocklist !== undefined) {
      nextPolicy.customBlocklist = normalizeDomainList(patch.customBlocklist);
    }

    if (patch.allowlist !== undefined) {
      nextPolicy.allowlist = normalizeDomainList(patch.allowlist);
    }

    store.policy = nextPolicy;
    writeStore(store);
    return clone(nextPolicy);
  }

  function updateContentFilterRuntime(patch = {}) {
    const store = readStore();
    store.runtime = {
      ...store.runtime,
      ...patch,
      categoryDomainCounts: {
        ...store.runtime.categoryDomainCounts,
        ...((patch.categoryDomainCounts && typeof patch.categoryDomainCounts === 'object') ? patch.categoryDomainCounts : {}),
      },
      sourceStatus: patch.sourceStatus && typeof patch.sourceStatus === 'object'
        ? patch.sourceStatus
        : store.runtime.sourceStatus,
    };

    writeStore(store);
    return clone(store.runtime);
  }

  return {
    getContentFilterState,
    storeFile,
    updateContentFilterPolicy,
    updateContentFilterRuntime,
  };
}

const defaultStore = createContentFilterStore();

module.exports = {
  CATEGORY_IDS,
  CONTENT_FILTER_STORE_FILE: defaultStore.storeFile,
  createContentFilterStore,
  ...defaultStore,
};
