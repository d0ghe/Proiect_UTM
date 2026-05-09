/**
 * Honeypot Canary File System
 *
 * Generează fișiere "canary" cu nume atrăgătoare pentru atacatori
 * (passwords.txt, bitcoin_wallet.dat, customer_db_backup.sql).
 * Watcher-ul detectează când sunt accesate / modificate / șterse.
 *
 * Folosit ca tripwire pentru ransomware, exfiltrare, și malicious insider.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const STORE_FILE = path.join(__dirname, '../store/honeypots.json');

const CANARY_TEMPLATES = [
  { name: 'passwords.txt', content: 'admin:password123\nroot:toor\nbackup_user:Backup2024!\nmysql:RootSql#2024\nftp_admin:FTPpass!\n' },
  { name: 'bitcoin_wallet.dat', content: 'BTC_PRIVATE_KEY=L1aW4aubDFB7yfras2S1mFhFkxFcrUzVa6SeeC8gSXDVNYM5JFgL\nWALLET_ADDRESS=1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa\n' },
  { name: 'customer_db_backup.sql', content: '-- MySQL dump\nCREATE TABLE customers (id INT, email VARCHAR(255), credit_card VARCHAR(20));\n-- TRUNCATED\n' },
  { name: 'aws_credentials.csv', content: 'User Name,Access key ID,Secret access key\nadmin,AKIAIOSFODNN7EXAMPLE,wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n' },
  { name: 'salaries_2024.xlsx', content: 'PK\x03\x04Mock_xlsx_content_for_canary\n' },
  { name: 'private_keys.pem', content: '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...CANARY_PLACEHOLDER...\n-----END RSA PRIVATE KEY-----\n' },
  { name: 'company_secrets.docx', content: 'PK\x03\x04Mock_docx_canary_document\n' },
  { name: 'database_backup.bak', content: 'TAPE_HEADER_CANARY_DATABASE_BACKUP\n' },
];

function loadStore() {
  try {
    if (!fs.existsSync(STORE_FILE)) return { canaries: [], events: [] };
    return JSON.parse(fs.readFileSync(STORE_FILE, 'utf8'));
  } catch {
    return { canaries: [], events: [] };
  }
}

function saveStore(data) {
  try {
    fs.writeFileSync(STORE_FILE, JSON.stringify(data, null, 2));
  } catch (err) {
    console.warn('[Honeypot] Could not persist store:', err.message);
  }
}

/**
 * Plantează un set de canaries într-un director țintă.
 *
 * @param {string} targetDir
 * @returns {Array} - lista canaries create
 */
function plantCanaries(targetDir) {
  if (!fs.existsSync(targetDir)) {
    fs.mkdirSync(targetDir, { recursive: true });
  }

  const store = loadStore();
  const created = [];

  for (const tpl of CANARY_TEMPLATES) {
    const fullPath = path.join(targetDir, tpl.name);
    try {
      fs.writeFileSync(fullPath, tpl.content);
      const stat = fs.statSync(fullPath);
      const fingerprint = crypto.createHash('sha256').update(tpl.content).digest('hex');

      const canary = {
        id: crypto.randomUUID(),
        path: fullPath,
        name: tpl.name,
        fingerprint,
        plantedAt: new Date().toISOString(),
        size: stat.size,
        mtime: stat.mtimeMs,
        triggered: false,
        triggerCount: 0,
      };
      created.push(canary);
      store.canaries.push(canary);
    } catch (err) {
      console.warn(`[Honeypot] Failed to plant ${tpl.name}:`, err.message);
    }
  }

  saveStore(store);
  return created;
}

/**
 * Verifică toate canary-urile active. Returnează cele atinse (modificate/șterse).
 */
function checkCanaries() {
  const store = loadStore();
  const triggered = [];

  for (const canary of store.canaries) {
    if (!fs.existsSync(canary.path)) {
      // Șters
      if (!canary.triggered || canary.lastTrigger?.type !== 'deleted') {
        canary.triggered = true;
        canary.triggerCount++;
        canary.lastTrigger = { type: 'deleted', at: new Date().toISOString() };
        const event = {
          id: crypto.randomUUID(),
          canaryId: canary.id,
          path: canary.path,
          name: canary.name,
          type: 'deleted',
          severity: 'critical',
          at: new Date().toISOString(),
          message: `Canary file "${canary.name}" deleted — possible ransomware or destructive action.`,
        };
        store.events.unshift(event);
        triggered.push(event);
      }
      continue;
    }

    try {
      const stat = fs.statSync(canary.path);
      const buf = fs.readFileSync(canary.path);
      const fingerprint = crypto.createHash('sha256').update(buf).digest('hex');

      if (fingerprint !== canary.fingerprint) {
        canary.triggered = true;
        canary.triggerCount++;
        canary.lastTrigger = { type: 'modified', at: new Date().toISOString() };
        const event = {
          id: crypto.randomUUID(),
          canaryId: canary.id,
          path: canary.path,
          name: canary.name,
          type: 'modified',
          severity: 'critical',
          at: new Date().toISOString(),
          message: `Canary file "${canary.name}" modified — content fingerprint changed.`,
        };
        store.events.unshift(event);
        triggered.push(event);
        canary.fingerprint = fingerprint;
        canary.size = stat.size;
      }
    } catch (err) {
      // ignore read errors (file might be locked momentarily)
    }
  }

  if (store.events.length > 200) store.events = store.events.slice(0, 200);
  saveStore(store);

  return triggered;
}

function listCanaries() {
  return loadStore().canaries;
}

function listEvents() {
  return loadStore().events;
}

function removeAllCanaries() {
  const store = loadStore();
  const removed = [];
  for (const c of store.canaries) {
    try {
      if (fs.existsSync(c.path)) {
        fs.unlinkSync(c.path);
        removed.push(c.path);
      }
    } catch {
      // ignore
    }
  }
  store.canaries = [];
  saveStore(store);
  return removed;
}

module.exports = { plantCanaries, checkCanaries, listCanaries, listEvents, removeAllCanaries };
