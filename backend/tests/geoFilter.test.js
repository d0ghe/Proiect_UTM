const fs = require('fs');
const path = require('path');
const test = require('node:test');
const assert = require('node:assert/strict');

const { updateGeoFilter } = require('../store/geoFilterStore');
const {
  countryFromTld,
  getCountryDomainSuffixes,
  isGeoBlocked,
  normalizeHostname,
  parseCountryDomains,
} = require('../utils/geoFilter');
const { getBlockDecision } = require('../utils/httpProxy');

const STORE_FILE = path.join(__dirname, '../store/geo-filter-policy.json');

async function withGeoPolicy(policy, fn) {
  const hadStoreFile = fs.existsSync(STORE_FILE);
  const original = hadStoreFile ? fs.readFileSync(STORE_FILE, 'utf8') : '';

  try {
    updateGeoFilter(policy);
    return await fn();
  } finally {
    if (hadStoreFile) {
      fs.writeFileSync(STORE_FILE, original, 'utf8');
    } else if (fs.existsSync(STORE_FILE)) {
      fs.unlinkSync(STORE_FILE);
    }
  }
}

test('geo hostname normalization accepts URLs, hostnames, and ports', () => {
  assert.equal(normalizeHostname('https://Example.RU:443/news?q=1'), 'example.ru');
  assert.equal(normalizeHostname('bund.de:443'), 'bund.de');
  assert.equal(normalizeHostname('[2001:db8::1]:443'), '2001:db8::1');
});

test('geo filter maps country-code TLDs for selected countries', async () => {
  await withGeoPolicy({ enabled: true, blockedCountries: ['DE', 'GB', 'RU'] }, async () => {
    assert.equal(countryFromTld('bund.de'), 'DE');
    assert.equal(countryFromTld('news.gov.uk'), 'GB');
    assert.equal(countryFromTld('example.su'), 'RU');
    assert.equal(countryFromTld('https://xn--d1acpjx3f.xn--p1ai'), 'RU');

    assert.deepEqual(await isGeoBlocked('https://bund.de/path'), {
      blocked: true,
      country: 'DE',
      reason: 'country-tld',
    });
  });
});

test('geo filter parses common country website list formats', () => {
  const domains = parseCountryDomains(`
    DOMAIN-SUFFIX,vk.com
    - DOMAIN,baidu.com
    nftset=/gosuslugi.ru/4#inet#fw4#vpn_domains
    0.0.0.0 mail.ru
    DOMAIN-SUFFIX,.ru
    IP-CIDR,1.2.3.0/24
  `);

  assert.deepEqual(domains, ['vk.com', 'baidu.com', 'gosuslugi.ru', 'mail.ru']);
});

test('geo filter applies built-in website rules before DNS lookup', async () => {
  await withGeoPolicy({ enabled: true, blockedCountries: ['RU', 'CN'] }, async () => {
    assert.ok(getCountryDomainSuffixes('RU').includes('xn--p1ai'));
    assert.deepEqual(await isGeoBlocked('vk.com'), {
      blocked: true,
      country: 'RU',
      reason: 'domain-list',
    });
    assert.deepEqual(await isGeoBlocked('baidu.com'), {
      blocked: true,
      country: 'CN',
      reason: 'domain-list',
    });
  });
});

test('proxy block decision applies geo policy to plain HTTP destinations', async () => {
  await withGeoPolicy({ enabled: true, blockedCountries: ['RU'] }, async () => {
    const block = await getBlockDecision('example.ru', 80);

    assert.equal(block.blocked, true);
    assert.match(block.label, /Geo Tracking/);
    assert.equal(block.geo.country, 'RU');
  });
});
