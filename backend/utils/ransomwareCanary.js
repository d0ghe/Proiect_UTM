/**
 * Ransomware Canary — Mass Write Detector
 *
 * Monitorizează evenimentele de scriere/redenumire în directoare critice.
 * Dacă se observă > N modificări într-o fereastră de T secunde,
 * declanșează alertă de ransomware.
 *
 * Suplimentar: detectează extensii suspecte adăugate (.encrypted, .locked,
 * .crypto, .xtbl, .zepto, .cerber, .locky, etc.) — semnături clasice ransomware.
 */

const fs = require('fs');
const path = require('path');

const STORE_FILE = path.join(__dirname, '../store/ransomware-events.json');
const WINDOW_MS = 30000; // 30 secunde
const THRESHOLD = 50; // 50+ modificări în 30s = alertă

const RANSOMWARE_EXTENSIONS = [
  '.encrypted', '.locked', '.crypto', '.crypt', '.cryp1', '.aes', '.aaa',
  '.zepto', '.cerber', '.locky', '.xtbl', '.tesla', '.zzz', '.zzzzz',
  '.wallet', '.lock', '.WCRY', '.WNCRY', '.wnry', '.onion', '.thor',
  '.lockbit', '.conti', '.ryuk', '.maze', '.darkside', '.babuk', '.djvu',
];

const RANSOM_NOTE_NAMES = [
  'README.txt', 'HOW_TO_DECRYPT.txt', 'DECRYPT_INSTRUCTIONS.txt',
  'YOUR_FILES.txt', '!!!READ_ME!!!.txt', 'RECOVERY.txt',
  'HOW_TO_RECOVER.html', 'restore_files.txt',
];

let recentEvents = [];
let alertCallback = null;

function loadStore() {
  try {
    if (!fs.existsSync(STORE_FILE)) return { alerts: [] };
    return JSON.parse(fs.readFileSync(STORE_FILE, 'utf8'));
  } catch {
    return { alerts: [] };
  }
}

function saveStore(data) {
  try {
    fs.writeFileSync(STORE_FILE, JSON.stringify(data, null, 2));
  } catch {
    // ignore
  }
}

function pushAlert(alert) {
  const store = loadStore();
  store.alerts.unshift(alert);
  if (store.alerts.length > 100) store.alerts = store.alerts.slice(0, 100);
  saveStore(store);
  if (typeof alertCallback === 'function') {
    try { alertCallback(alert); } catch { /* ignore */ }
  }
}

function setAlertCallback(cb) {
  alertCallback = cb;
}

/**
 * Înregistrează un eveniment de scriere/modificare/redenumire.
 *
 * @param {string} eventType - 'change' | 'add' | 'rename' | 'unlink'
 * @param {string} filePath
 */
function recordFileEvent(eventType, filePath) {
  const now = Date.now();
  recentEvents.push({ at: now, type: eventType, path: filePath });
  recentEvents = recentEvents.filter((e) => now - e.at < WINDOW_MS);

  const ext = path.extname(filePath).toLowerCase();
  const basename = path.basename(filePath);

  // Detecție 1: extensie suspectă
  if (RANSOMWARE_EXTENSIONS.includes(ext)) {
    const alert = {
      id: `ransom-ext-${now}`,
      type: 'ransomware_extension',
      severity: 'critical',
      path: filePath,
      detail: `Fișier cu extensie ransomware cunoscută detectat: ${basename} (${ext})`,
      at: new Date(now).toISOString(),
    };
    pushAlert(alert);
    return alert;
  }

  // Detecție 2: ransom note clasic
  if (RANSOM_NOTE_NAMES.some((n) => basename.toLowerCase().includes(n.toLowerCase()))) {
    const alert = {
      id: `ransom-note-${now}`,
      type: 'ransom_note',
      severity: 'critical',
      path: filePath,
      detail: `Posibil ransom note creat: ${basename}`,
      at: new Date(now).toISOString(),
    };
    pushAlert(alert);
    return alert;
  }

  // Detecție 3: mass-write (volum mare în fereastră)
  if (recentEvents.length >= THRESHOLD) {
    const uniquePaths = new Set(recentEvents.map((e) => e.path));
    if (uniquePaths.size >= THRESHOLD) {
      const alert = {
        id: `ransom-mass-${now}`,
        type: 'mass_write',
        severity: 'critical',
        fileCount: uniquePaths.size,
        windowSec: WINDOW_MS / 1000,
        sampleFiles: Array.from(uniquePaths).slice(0, 10),
        detail: `${uniquePaths.size} fișiere modificate în ${WINDOW_MS / 1000}s — pattern tipic ransomware/wiper.`,
        at: new Date(now).toISOString(),
      };
      pushAlert(alert);
      // Resetăm fereastra după alertă pentru a nu spama
      recentEvents = [];
      return alert;
    }
  }

  return null;
}

function getAlerts() {
  return loadStore().alerts;
}

function getCurrentWindow() {
  const now = Date.now();
  recentEvents = recentEvents.filter((e) => now - e.at < WINDOW_MS);
  return {
    windowSec: WINDOW_MS / 1000,
    threshold: THRESHOLD,
    currentCount: recentEvents.length,
    uniquePaths: new Set(recentEvents.map((e) => e.path)).size,
  };
}

module.exports = { recordFileEvent, getAlerts, getCurrentWindow, setAlertCallback };
