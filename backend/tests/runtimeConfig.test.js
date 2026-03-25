const test = require('node:test');
const assert = require('node:assert/strict');

const {
  decryptSecretPayload,
  encryptSecretPayload,
} = require('../utils/runtimeConfig');

test('encrypted secret payloads round-trip with the same passphrase', () => {
  const values = {
    HYBRID_ANALYSIS_API_KEY: 'secret-value',
    PLATFORM_ADMIN_PASSWORD: 'another-secret',
  };
  const passphrase = 'test-passphrase';
  const encrypted = encryptSecretPayload(values, passphrase);
  const decrypted = decryptSecretPayload(encrypted, passphrase);

  assert.equal(encrypted.version, 1);
  assert.equal(decrypted.HYBRID_ANALYSIS_API_KEY, 'secret-value');
  assert.equal(decrypted.PLATFORM_ADMIN_PASSWORD, 'another-secret');
});
