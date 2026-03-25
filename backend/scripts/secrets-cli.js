#!/usr/bin/env node
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const dotenv = require('dotenv');

const {
  DEFAULT_SECRET_FILE,
  SECRET_KEYS,
  encryptSecretPayload,
} = require('../utils/runtimeConfig');

const ENV_PATH = path.join(__dirname, '../.env');

function ensureEnvFile() {
  if (!fs.existsSync(ENV_PATH)) {
    throw new Error('backend/.env was not found. Create it before migrating secrets.');
  }
}

function loadEnvFile() {
  ensureEnvFile();
  const raw = fs.readFileSync(ENV_PATH, 'utf8');
  return {
    raw,
    parsed: dotenv.parse(raw),
  };
}

function extractKey(line) {
  const match = String(line || '').match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=/);
  return match ? match[1] : '';
}

function upsertEnvValue(lines, key, value) {
  const nextLine = `${key}=${value}`;
  const index = lines.findIndex((line) => extractKey(line) === key);

  if (index === -1) {
    lines.push(nextLine);
    return lines;
  }

  lines[index] = nextLine;
  return lines;
}

function migrateSecrets() {
  const { raw, parsed } = loadEnvFile();
  const secretValues = Object.fromEntries(
    SECRET_KEYS
      .filter((key) => parsed[key])
      .map((key) => [key, parsed[key]]),
  );

  if (Object.keys(secretValues).length === 0) {
    console.log('No secret keys were found in backend/.env. Nothing to migrate.');
    return;
  }

  const passphrase = parsed.PROJECT_SECRET_PASSPHRASE
    || process.env.PROJECT_SECRET_PASSPHRASE
    || crypto.randomBytes(24).toString('base64url');
  const secretFile = process.env.PROJECT_SECRET_FILE || DEFAULT_SECRET_FILE;
  const secretDir = path.dirname(secretFile);
  const keepPlaintextBackup = String(process.env.KEEP_PLAINTEXT_SECRET_BACKUP || '').trim().toLowerCase() === 'true';
  const envelope = encryptSecretPayload(secretValues, passphrase);

  if (!fs.existsSync(secretDir)) {
    fs.mkdirSync(secretDir, { recursive: true });
  }

  if (keepPlaintextBackup) {
    fs.copyFileSync(ENV_PATH, `${ENV_PATH}.pre-secrets.bak`);
  }

  fs.writeFileSync(secretFile, JSON.stringify(envelope, null, 2));

  const keptLines = raw
    .split(/\r?\n/)
    .filter((line) => {
      const key = extractKey(line);
      return !SECRET_KEYS.includes(key);
    });

  upsertEnvValue(keptLines, 'PROJECT_SECRET_PASSPHRASE', passphrase);
  fs.writeFileSync(ENV_PATH, `${keptLines.join('\n').trimEnd()}\n`);

  console.log(`Encrypted ${Object.keys(secretValues).length} secret(s) into ${path.relative(path.join(__dirname, '..'), secretFile)}.`);
  console.log(keepPlaintextBackup
    ? 'Plain secret keys were removed from backend/.env and a plaintext backup was kept by request.'
    : 'Plain secret keys were removed from backend/.env.');
}

const command = process.argv[2] || 'migrate';

if (command !== 'migrate') {
  console.error(`Unsupported command: ${command}`);
  process.exit(1);
}

try {
  migrateSecrets();
} catch (error) {
  console.error(error.message);
  process.exit(1);
}
