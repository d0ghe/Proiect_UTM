const chokidar = require('chokidar');
const path = require('path');
const fs = require('fs');
const notifier = require('node-notifier'); // Modulul de notificări

// --- CONFIGURARE DOSARE ---
const homeDir = process.env.USERPROFILE;
const watchTargets = [
    path.join(homeDir, 'Desktop'),
    path.join(homeDir, 'Downloads'),
    path.join(homeDir, 'OneDrive', 'Desktop'),
    path.join(homeDir, 'OneDrive', 'Downloads')
].filter(dir => fs.existsSync(dir));

const QUARANTINE_DIR = path.join(__dirname, 'quarantine');
if (!fs.existsSync(QUARANTINE_DIR)) fs.mkdirSync(QUARANTINE_DIR);
const REPO_ROOT = path.resolve(__dirname, '..');
const EICAR_MARKER = ['EICAR', 'STANDARD', 'ANTIVIRUS', 'TEST', 'FILE'].join('-');
const ignoredRoots = [
    QUARANTINE_DIR,
    REPO_ROOT
].map((entry) => path.resolve(entry));

const shouldIgnorePath = (targetPath) => {
    const resolvedPath = path.resolve(targetPath);
    return ignoredRoots.some((entry) => resolvedPath === entry || resolvedPath.startsWith(`${entry}${path.sep}`));
};

// --- FUNCȚIA DE NOTIFICARE ---
const notifyThreat = (fileName, threatName) => {
    notifier.notify({
        title: '🛡️ Sentinel Security Alert',
        message: `Amenințare detectată: ${threatName}. Fișierul ${fileName} a fost mutat în carantină!`,
        icon: path.join(__dirname, 'icon-security.png'), // Opțional, dacă ai o iconiță
        sound: true, // Redă sunetul de sistem "Ping"
        wait: true,
        appID: "UTM Containment Atlas"
    });
};

// --- FUNCȚIA PRINCIPALĂ DE SCANARE ---
const scanFile = async (filePath) => {
    const fileName = path.basename(filePath);
    if (fileName.startsWith('~') || fileName.endsWith('.tmp') || shouldIgnorePath(filePath)) return;

    console.log(`[🔍] Scanare activă: ${fileName}`);
    if (global.stats) global.stats.files_scanned++;

    try {
        const fileBuffer = fs.readFileSync(filePath);
        const fileContent = fileBuffer.toString();

        let isInfected = false;
        let threatName = "";

        // Verificăm semnătura EICAR
        if (fileContent.includes(EICAR_MARKER)) {
            isInfected = true;
            threatName = "EICAR_Test_File";
        }

        if (isInfected) {
            console.log(`[⚠️] AMENINȚARE DETECTATĂ: ${threatName}`);
            
            // Trimitem notificarea în Windows
            notifyThreat(fileName, threatName);

            if (global.stats) {
                global.stats.threats_found++;
                global.stats.quarantined++;
            }

            const destPath = path.join(QUARANTINE_DIR, `${Date.now()}_${fileName}.quarantine`);
            
            try {
                fs.renameSync(filePath, destPath);
            } catch (moveErr) {
                fs.copyFileSync(filePath, destPath);
                fs.unlinkSync(filePath);
            }
            console.log(`[🔒] Fișierul a fost izolat.`);
        } else {
            console.log(`[✅] ${fileName} este curat.`);
        }
    } catch (err) {
        if (err.code !== 'EBUSY') console.error(`[❌] Eroare:`, err.message);
    }
};

// --- INIȚIALIZARE WATCHER ---
const watcher = chokidar.watch(watchTargets, {
    persistent: true,
    ignoreInitial: true,
    ignored: (targetPath) => shouldIgnorePath(targetPath),
    awaitWriteFinish: { stabilityThreshold: 1000, pollInterval: 100 }
});

watcher.on('add', (p) => scanFile(p)).on('change', (p) => scanFile(p));

module.exports = watcher;
