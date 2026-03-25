const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const dotenv = require('dotenv');

const DEFAULT_ENV_FILE = path.join(__dirname, '../.env');
const DEFAULT_SECRET_FILE = path.join(__dirname, '../config/secrets.enc.json');
const SECRET_KEYS = [
  'HYBRID_ANALYSIS_API_KEY',
  'MALWARE_BAZAAR_KEY',
  'PLATFORM_ADMIN_PASSWORD',
  'PLATFORM_TOKEN_SECRET',
];

let configStatus = {
  initialized: false,
  secretFile: DEFAULT_SECRET_FILE,
  decryptedKeys: [],
  warnings: [],
};

function createWarning(message) {
  return {
    message,
    time: new Date().toISOString(),
  };
}

function toBase64Url(value) {
  return Buffer.from(value).toString('base64url');
}

function fromBase64Url(value) {
  return Buffer.from(String(value || ''), 'base64url');
}

function deriveSecretKey(passphrase, salt) {
  return crypto.scryptSync(passphrase, salt, 32);
}

function encryptSecretPayload(values, passphrase) {
  if (!passphrase) {
    throw new Error('A project secret passphrase is required to encrypt secrets.');
  }

  const payload = JSON.stringify({
    values,
    encryptedAt: new Date().toISOString(),
  });
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);
  const key = deriveSecretKey(passphrase, salt);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(payload, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();

  return {
    version: 1,
    algorithm: 'aes-256-gcm',
    kdf: 'scrypt',
    salt: toBase64Url(salt),
    iv: toBase64Url(iv),
    tag: toBase64Url(tag),
    ciphertext: toBase64Url(ciphertext),
  };
}

function decryptSecretPayload(envelope, passphrase) {
  if (!passphrase) {
    throw new Error('A project secret passphrase is required to decrypt secrets.');
  }

  if (!envelope || Number(envelope.version) !== 1) {
    throw new Error('Unsupported encrypted secret file version.');
  }

  const salt = fromBase64Url(envelope.salt);
  const iv = fromBase64Url(envelope.iv);
  const tag = fromBase64Url(envelope.tag);
  const ciphertext = fromBase64Url(envelope.ciphertext);
  const key = deriveSecretKey(passphrase, salt);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
  const parsed = JSON.parse(plaintext);
  return parsed?.values && typeof parsed.values === 'object' ? parsed.values : parsed;
}

function applySecretValues(values) {
  return Object.entries(values || {}).reduce((keys, [key, value]) => {
    if (value === undefined || value === null || value === '') {
      return keys;
    }

    process.env[key] = String(value);
    keys.push(key);
    return keys;
  }, []);
}

function ensurePlatformTokenSecret() {
  if (!process.env.PLATFORM_TOKEN_SECRET) {
    process.env.PLATFORM_TOKEN_SECRET = crypto.randomBytes(32).toString('hex');
  }
}

function getRuntimeConfigStatus() {
  return {
    ...configStatus,
    decryptedKeys: [...configStatus.decryptedKeys],
    warnings: [...configStatus.warnings],
  };
}

function loadRuntimeConfig(options = {}) {
  if (configStatus.initialized) {
    return getRuntimeConfigStatus();
  }

  const envFile = options.envFile || DEFAULT_ENV_FILE;
  dotenv.config({ path: envFile, quiet: true });

  const resolvedSecretFile = process.env.PROJECT_SECRET_FILE || options.secretFile || DEFAULT_SECRET_FILE;
  const nextWarnings = [];
  let decryptedKeys = [];

  if (fs.existsSync(resolvedSecretFile)) {
    const passphrase = process.env.PROJECT_SECRET_PASSPHRASE || process.env.SECRETS_PASSPHRASE;

    if (!passphrase) {
      nextWarnings.push(createWarning(`Encrypted secrets found at ${resolvedSecretFile}, but PROJECT_SECRET_PASSPHRASE is missing.`));
    } else {
      try {
        const raw = fs.readFileSync(resolvedSecretFile, 'utf8');
        const encrypted = JSON.parse(raw);
        decryptedKeys = applySecretValues(decryptSecretPayload(encrypted, passphrase));
      } catch (error) {
        nextWarnings.push(createWarning(`Could not decrypt encrypted secrets: ${error.message}`));
      }
    }
  }

  ensurePlatformTokenSecret();

  configStatus = {
    initialized: true,
    secretFile: resolvedSecretFile,
    decryptedKeys,
    warnings: nextWarnings,
  };

  return getRuntimeConfigStatus();
}

module.exports = {
  DEFAULT_ENV_FILE,
  DEFAULT_SECRET_FILE,
  SECRET_KEYS,
  decryptSecretPayload,
  encryptSecretPayload,
  getRuntimeConfigStatus,
  loadRuntimeConfig,
};
