/**
 * Activity Log — Persistent In-Memory Event Store
 *
 * Reține un istoric detaliat al acțiunilor critice ale sistemului:
 * scanări, amenințări izolate, cleanup, modificări de reguli firewall etc.
 * Maximum MAX_ENTRIES intrări; cele mai vechi sunt eliminate automat (FIFO).
 *
 * Structura unei intrări:
 * {
 *   id:        string  (uuid-lite bazat pe timestamp + contor)
 *   timestamp: string  (ISO 8601)
 *   level:     'ALERT' | 'WARNING' | 'INFO'
 *   source:    string  (ex: 'Protection', 'Cleanup', 'Firewall')
 *   action:    string  (titlu scurt — ex: 'Trojan Quarantined')
 *   detail:    string  (descriere completă)
 * }
 */

const MAX_ENTRIES = 200;

let entries = [];
let counter = 0;

function generateId() {
  counter += 1;
  return `log-${Date.now()}-${counter}`;
}

/**
 * Adaugă o intrare nouă în jurnalul de activitate.
 *
 * @param {'ALERT'|'WARNING'|'INFO'} level
 * @param {string} source  — modulul sursă (ex: 'Protection')
 * @param {string} action  — titlu scurt pentru eveniment
 * @param {string} detail  — descriere detaliată
 * @returns {object} intrarea creată
 */
function addActivityEntry(level, source, action, detail) {
  const entry = {
    id: generateId(),
    timestamp: new Date().toISOString(),
    level: String(level || 'INFO').toUpperCase(),
    source: String(source || 'System'),
    action: String(action || ''),
    detail: String(detail || ''),
  };

  entries.unshift(entry);

  if (entries.length > MAX_ENTRIES) {
    entries = entries.slice(0, MAX_ENTRIES);
  }

  return entry;
}

/**
 * Returnează toate intrările (cele mai recente primele).
 *
 * @param {number} [limit]  — limitează numărul de rezultate
 * @returns {Array}
 */
function getActivityLog(limit) {
  if (limit && limit > 0) {
    return entries.slice(0, limit);
  }

  return [...entries];
}

/**
 * Șterge toate intrările (util pentru teste sau reset manual).
 */
function clearActivityLog() {
  entries = [];
  counter = 0;
}

/**
 * Returnează un sumar rapid: total per nivel.
 */
function summarizeActivityLog() {
  return entries.reduce(
    (acc, entry) => {
      if (entry.level === 'ALERT') acc.alerts += 1;
      else if (entry.level === 'WARNING') acc.warnings += 1;
      else acc.info += 1;
      acc.total += 1;
      return acc;
    },
    { total: 0, alerts: 0, warnings: 0, info: 0 },
  );
}

module.exports = {
  addActivityEntry,
  clearActivityLog,
  getActivityLog,
  summarizeActivityLog,
};
