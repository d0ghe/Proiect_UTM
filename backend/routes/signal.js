/**
 * Signal & Communications Route — SNR Simulation + Fallback Mechanism
 *
 * Implementează conceptele din "Semnale și Sisteme":
 *
 *  1. SNR (Signal-to-Noise Ratio): Backend-ul calculează continuu "calitatea"
 *     canalului de comunicație ca un semnal variabil (random walk + zgomot gaussian).
 *
 *  2. Fallback Automat:
 *     - SNR > SNR_THRESHOLD_PRIMARY  → Canal PRIMAR (WiFi/Ethernet)
 *     - SNR > SNR_THRESHOLD_FALLBACK → Canal DEGRADAT (avertisment)
 *     - SNR ≤ SNR_THRESHOLD_FALLBACK → FALLBACK LoRa CSS (Chirp Spread Spectrum)
 *       dacă LoRa tot eșuează → GSM/GPRS (Out-of-Band)
 *
 *  3. Fault Tolerance: alertele critice sunt rutate pe canalul disponibil
 *     indiferent de starea canalului primar — demonstrând toleranță la erori.
 *
 * Valorile SNR sunt în dB (decibeli), interval realist: 0–35 dB.
 */

const express = require('express');
const verifyToken = require('../middleware/verifyToken');
const { getActivityLog, summarizeActivityLog } = require('../store/activityLog');

const router = express.Router();

router.use(verifyToken);

// Praguri SNR în dB
const SNR_THRESHOLD_PRIMARY  = 20;  // > 20 dB → WiFi/Ethernet stabil
const SNR_THRESHOLD_FALLBACK = 10;  // 10–20 dB → degradat; < 10 dB → LoRa fallback

// Stare internă a simulatorului (persistă între request-uri)
const signalState = {
  snr: 25,          // pornit la 25 dB (semnal bun)
  velocity: 0,      // viteza de schimbare (random walk cu inerție)
  ticks: 0,         // număr total de poll-uri
  loraActivatedAt:  null,
  loraDeactivatedAt: null,
  lastUpdateAt: new Date().toISOString(),
};

/**
 * Generează zgomot gaussian simplu (Box-Muller transform).
 */
function gaussianNoise(mean = 0, stdDev = 1) {
  const u1 = Math.random();
  const u2 = Math.random();
  const z = Math.sqrt(-2 * Math.log(u1)) * Math.cos(2 * Math.PI * u2);
  return mean + z * stdDev;
}

/**
 * Avansează starea SNR cu un pas de simulare.
 * Folosim un random walk cu inerție (ca un canal radio real).
 */
function stepSignal() {
  // Inerție: velocity se schimbă lent
  signalState.velocity += gaussianNoise(0, 0.4);
  signalState.velocity = Math.max(-2.5, Math.min(2.5, signalState.velocity));

  // Forță de revenire spre centru (mean-reversion la 22 dB)
  const meanTarget = 22;
  const reversionForce = (meanTarget - signalState.snr) * 0.04;
  signalState.snr += signalState.velocity + reversionForce + gaussianNoise(0, 0.2);

  // Clamp între 0 și 35 dB
  signalState.snr = Math.max(0, Math.min(35, signalState.snr));
  signalState.ticks += 1;
  signalState.lastUpdateAt = new Date().toISOString();
}

/**
 * Determină modul de comunicație curent pe baza SNR.
 */
function resolveChannelMode(snr) {
  if (snr > SNR_THRESHOLD_PRIMARY) {
    return {
      id: 'primary',
      label: 'Primary Channel',
      technology: 'WiFi / Ethernet',
      band: '2.4 GHz / 5 GHz',
      fallbackActive: false,
      color: 'green',
      description: 'Canal primar stabil. Toate alertele sunt transmise prin rețeaua principală.',
    };
  }

  if (snr > SNR_THRESHOLD_FALLBACK) {
    return {
      id: 'degraded',
      label: 'Degraded Channel',
      technology: 'WiFi (Weak Signal)',
      band: '2.4 GHz',
      fallbackActive: false,
      color: 'amber',
      description: 'Semnal degradat detectat. Sistemul monitorizează activ pentru tranziție la LoRa.',
    };
  }

  return {
    id: 'lora',
    label: 'LoRa Fallback Active',
    technology: 'LoRa CSS (Chirp Spread Spectrum)',
    band: '868 MHz ISM',
    fallbackActive: true,
    color: 'red',
    description: 'Canalul primar sub prag. Alertele critice sunt rutate prin LoRa 868 MHz (CSS modulation) — Out-of-Band.',
  };
}

/**
 * GET /api/signal
 * Returnează starea curentă a semnalului + logul de activitate.
 */
router.get('/', (_req, res) => {
  stepSignal();

  const snrRounded = Math.round(signalState.snr * 10) / 10;
  const mode = resolveChannelMode(snrRounded);

  // Urmărim când s-a activat / dezactivat LoRa
  if (mode.id === 'lora' && !signalState.loraActivatedAt) {
    signalState.loraActivatedAt = new Date().toISOString();
    signalState.loraDeactivatedAt = null;
  } else if (mode.id !== 'lora' && signalState.loraActivatedAt && !signalState.loraDeactivatedAt) {
    signalState.loraDeactivatedAt = new Date().toISOString();
    signalState.loraActivatedAt = null;
  }

  const activitySummary = summarizeActivityLog();
  const recentActivity = getActivityLog(8);

  res.json({
    success: true,
    signal: {
      snr: snrRounded,
      snrUnit: 'dB',
      thresholds: {
        primary:  SNR_THRESHOLD_PRIMARY,
        fallback: SNR_THRESHOLD_FALLBACK,
      },
      mode,
      quality: buildQualityLabel(snrRounded),
      ticks: signalState.ticks,
      lastUpdateAt: signalState.lastUpdateAt,
      loraActivatedAt:   signalState.loraActivatedAt,
      loraDeactivatedAt: signalState.loraDeactivatedAt,
    },
    activityLog: {
      summary: activitySummary,
      recent: recentActivity,
    },
  });
});

/**
 * POST /api/signal/reset
 * Resetează simulatorul la valori inițiale (util pentru demo).
 */
router.post('/reset', (_req, res) => {
  signalState.snr = 25;
  signalState.velocity = 0;
  signalState.ticks = 0;
  signalState.loraActivatedAt = null;
  signalState.loraDeactivatedAt = null;
  signalState.lastUpdateAt = new Date().toISOString();

  res.json({ success: true, message: 'Signal simulator reset to initial state (25 dB).' });
});

/**
 * POST /api/signal/inject-noise
 * Injectează zgomot puternic pentru a forța tranziția la LoRa (demonstrație).
 */
router.post('/inject-noise', (_req, res) => {
  signalState.snr = Math.max(0, signalState.snr - 18);
  signalState.velocity = -3;
  signalState.lastUpdateAt = new Date().toISOString();

  res.json({
    success: true,
    message: 'Noise injection applied — SNR dropped significantly.',
    snr: Math.round(signalState.snr * 10) / 10,
  });
});

function buildQualityLabel(snr) {
  if (snr >= 25) return 'Excellent';
  if (snr >= 18) return 'Good';
  if (snr >= 12) return 'Fair';
  if (snr >= SNR_THRESHOLD_FALLBACK) return 'Poor';
  return 'Critical — LoRa Active';
}

module.exports = router;
