require('dotenv').config(); // Încarcă variabilele din .env
const express = require('express');
const router = express.Router();
const multer = require('multer');
const crypto = require('crypto');
const axios = require('axios');
const fs = require('fs');
const path = require('path');
const verifyToken = require('../middleware/verifyToken');

// Protejăm accesul - doar utilizatorii logați pot scana
router.use(verifyToken);

// --- CONFIGURARE MULTER ---
const upload = multer({ 
    storage: multer.memoryStorage(),
    limits: { fileSize: 50 * 1024 * 1024 } // 50MB per fișier
});

// Folosim cheia din variabila de mediu pentru securitate
const MALWARE_BAZAAR_KEY = process.env.MALWARE_BAZAAR_KEY;
const LOG_FILE = path.join(__dirname, '../scans.log');

// --- HELPER: LOGGING ---
const logScanResult = (data) => {
    const timestamp = new Date().toLocaleString();
    const threatDetail = data.status === 'CLEAN' ? 'Nicio amenintare' : (data.signature || 'Malware Generic');
    const logEntry = `[${timestamp}] STATUS: ${data.status} | Fisier: ${data.filename} | Hash: ${data.sha256} | Rezultat: ${threatDetail}\n`;
    
    fs.appendFileSync(LOG_FILE, logEntry);
};

// --- RUTĂ UNICĂ: SCANARE (SINGLE SAU MULTIPLE) ---
/**
 * @route   POST /api/antivirus/scan
 * @desc    Scanează unul sau mai multe fișiere (Heuristic + Cloud API)
 */
router.post('/scan', upload.array('files', 20), async (req, res) => {
    if (!req.files || req.files.length === 0) {
        return res.status(400).json({ success: false, message: 'Selectează cel puțin un fișier!' });
    }

    const scanPromises = req.files.map(async (file) => {
        try {
            const fileContent = file.buffer.toString();
            const fileHash = crypto.createHash('sha256').update(file.buffer).digest('hex');

            // 1. ANALIZĂ EURISTICĂ LOCALĂ (EICAR Check)
            if (fileContent.includes('EICAR-STANDARD-ANTIVIRUS-TEST-FILE')) {
                const result = {
                    filename: file.originalname,
                    sha256: fileHash,
                    status: 'INFECTED',
                    signature: 'EICAR_Test_File (Local Detection)',
                    method: 'Heuristic'
                };
                logScanResult(result);
                return result;
            }

            // 2. INTEROGARE CLOUD (MalwareBazaar API)
            const response = await axios.post(
                'https://mb-api.abuse.ch/api/v1/',
                new URLSearchParams({ query: 'get_info', hash: fileHash }),
                {
                    headers: {
                        'Auth-Key': MALWARE_BAZAAR_KEY,
                        'Content-Type': 'application/x-www-form-urlencoded'
                    },
                    timeout: 10000 
                }
            );

            const apiData = response.data;
            let result = {
                filename: file.originalname,
                sha256: fileHash,
                method: 'Cloud API'
            };

            if (apiData.query_status === 'ok') {
                result.status = 'INFECTED';
                result.signature = apiData.data[0].signature || 'Malware Generic';
            } else {
                result.status = 'CLEAN';
                result.message = 'Fisierul pare sigur.';
            }

            logScanResult(result);
            return result;

        } catch (error) {
            return {
                filename: file.originalname,
                status: 'ERROR',
                message: 'Eroare la procesare sau conexiune API.'
            };
        }
    });

    try {
        const scanResults = await Promise.all(scanPromises);
        
        const summary = {
            total: scanResults.length,
            infected: scanResults.filter(r => r.status === 'INFECTED').length,
            clean: scanResults.filter(r => r.status === 'CLEAN').length,
            failed: scanResults.filter(r => r.status === 'ERROR').length
        };

        res.json({ success: true, summary, results: scanResults });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Eroare interna la scanare.' });
    }
});

/**
 * @route   GET /api/antivirus/logs
 */
router.get('/logs', (req, res) => {
    if (!fs.existsSync(LOG_FILE)) return res.json({ success: true, logs: [] });
    try {
        const fileContent = fs.readFileSync(LOG_FILE, 'utf8');
        const lines = fileContent.trim().split('\n').filter(l => l !== "");
        res.json({ success: true, logs: lines.reverse() });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Eroare la citirea log-urilor.' });
    }
});

module.exports = router;