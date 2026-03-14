require('dotenv').config();

const crypto = require('crypto');
const express = require('express');
const fs = require('fs');
const multer = require('multer');
const path = require('path');
const axios = require('axios');

const verifyToken = require('../middleware/verifyToken');
const { readScanLogs, summarizeScanLogs } = require('../utils/scanLog');

const router = express.Router();
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 50 * 1024 * 1024 },
});

const MALWARE_BAZAAR_KEY = process.env.MALWARE_BAZAAR_KEY;
const LOG_FILE = path.join(__dirname, '../scans.log');
const QUARANTINE_DIR = path.join(__dirname, '../quarantine');

router.use(verifyToken);

function ensureQuarantineDir() {
  if (!fs.existsSync(QUARANTINE_DIR)) {
    fs.mkdirSync(QUARANTINE_DIR, { recursive: true });
  }
}

function updateGlobalStats(results) {
  if (!global.stats) {
    return;
  }

  global.stats.files_scanned += results.length;
  global.stats.threats_found += results.filter((result) => result.status === 'INFECTED').length;
  global.stats.quarantined += results.filter((result) => result.status === 'INFECTED').length;
}

function logScanResult(data) {
  const timestamp = new Date().toISOString();
  const detail = data.signature || data.message || 'No extra detail';
  const logEntry = `[${timestamp}] STATUS: ${data.status} | Fisier: ${data.filename} | Hash: ${data.sha256 || '-'} | Rezultat: ${detail}\n`;
  fs.appendFileSync(LOG_FILE, logEntry);
}

function getQuarantineFiles() {
  ensureQuarantineDir();

  return fs
    .readdirSync(QUARANTINE_DIR)
    .map((file) => {
      const stats = fs.statSync(path.join(QUARANTINE_DIR, file));
      return {
        name: file,
        date: stats.birthtime,
        size: `${(stats.size / 1024).toFixed(2)} KB`,
      };
    })
    .reverse();
}

async function scanFile(file) {
  const fileHash = crypto.createHash('sha256').update(file.buffer).digest('hex');
  const fileContent = file.buffer.toString();

  if (fileContent.includes('EICAR-STANDARD-ANTIVIRUS-TEST-FILE')) {
    const result = {
      filename: file.originalname,
      sha256: fileHash,
      status: 'INFECTED',
      signature: 'EICAR_Test_File (Local Detection)',
      method: 'Heuristic',
    };
    logScanResult(result);
    return result;
  }

  if (!MALWARE_BAZAAR_KEY) {
    const result = {
      filename: file.originalname,
      sha256: fileHash,
      status: 'CLEAN',
      message: 'No local heuristic detection found. Cloud lookup is not configured.',
      method: 'Local Heuristic',
    };
    logScanResult(result);
    return result;
  }

  try {
    const response = await axios.post(
      'https://mb-api.abuse.ch/api/v1/',
      new URLSearchParams({ query: 'get_info', hash: fileHash }),
      {
        headers: {
          'Auth-Key': MALWARE_BAZAAR_KEY,
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        timeout: 10000,
      },
    );

    if (response.data.query_status === 'ok') {
      const result = {
        filename: file.originalname,
        sha256: fileHash,
        status: 'INFECTED',
        signature: response.data.data?.[0]?.signature || 'Malware Generic',
        method: 'Cloud API',
      };
      logScanResult(result);
      return result;
    }

    const cleanResult = {
      filename: file.originalname,
      sha256: fileHash,
      status: 'CLEAN',
      message: 'File looks safe.',
      method: 'Cloud API',
    };
    logScanResult(cleanResult);
    return cleanResult;
  } catch (_error) {
    const reviewResult = {
      filename: file.originalname,
      sha256: fileHash,
      status: 'REVIEW',
      message: 'Cloud scan is unavailable right now. Manual review recommended.',
      method: 'Fallback',
    };
    logScanResult(reviewResult);
    return reviewResult;
  }
}

router.post('/scan', upload.any(), async (req, res) => {
  const uploadedFiles = Array.isArray(req.files)
    ? req.files.filter((file) => ['files', 'file'].includes(file.fieldname))
    : [];

  if (uploadedFiles.length === 0) {
    return res.status(400).json({
      success: false,
      message: 'Select at least one file to scan.',
    });
  }

  try {
    const results = await Promise.all(uploadedFiles.map(scanFile));
    const summary = {
      total: results.length,
      infected: results.filter((result) => result.status === 'INFECTED').length,
      clean: results.filter((result) => result.status === 'CLEAN').length,
      review: results.filter((result) => result.status === 'REVIEW').length,
      failed: results.filter((result) => result.status === 'ERROR').length,
    };

    updateGlobalStats(results);

    res.json({
      success: true,
      summary,
      results,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Internal scanning error.',
      error: error.message,
    });
  }
});

router.get('/logs', (_req, res) => {
  try {
    res.json({
      success: true,
      logs: readScanLogs(LOG_FILE),
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Could not read scan logs.',
      error: error.message,
    });
  }
});

router.get('/summary', (_req, res) => {
  try {
    const logs = readScanLogs(LOG_FILE);
    const summary = summarizeScanLogs(logs);

    res.json({
      success: true,
      summary: {
        ...summary,
        quarantined: getQuarantineFiles().length,
      },
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Could not build scan summary.',
      error: error.message,
    });
  }
});

router.get('/quarantine', (_req, res) => {
  try {
    res.json({
      success: true,
      files: getQuarantineFiles(),
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Could not read quarantine list.',
      error: error.message,
    });
  }
});

module.exports = router;
