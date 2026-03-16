const express = require('express');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');

const verifyToken = require('../middleware/verifyToken');

const router = express.Router();

router.use(verifyToken);

function getCleanupTargets() {
  const platformKey = process.platform;
  const candidates = new Set([os.tmpdir()]);

  if (platformKey === 'win32') {
    candidates.add(path.join(process.env.SystemRoot || 'C:\\Windows', 'Temp'));
  } else if (platformKey === 'linux') {
    candidates.add('/var/tmp');
  } else if (platformKey === 'darwin') {
    candidates.add('/private/var/tmp');
  }

  return Array.from(candidates).filter((target) => {
    if (!target || !path.isAbsolute(target)) {
      return false;
    }

    const root = path.parse(target).root;
    return target !== root && fs.existsSync(target);
  });
}

function getNativeCleanupAction() {
  const platformKey = process.platform;

  if (platformKey === 'win32') {
    return {
      supported: true,
      label: 'Open Disk Cleanup',
      command: 'cleanmgr.exe',
      args: [],
      description: 'Launch the built-in Windows Disk Cleanup utility.',
    };
  }

  if (platformKey === 'linux') {
    return {
      supported: true,
      label: 'Open Temp Folder',
      command: 'xdg-open',
      args: [os.tmpdir()],
      description: 'Open the active temp directory in the desktop file manager.',
    };
  }

  if (platformKey === 'darwin') {
    return {
      supported: true,
      label: 'Open Temp Folder',
      command: 'open',
      args: [os.tmpdir()],
      description: 'Open the active temp directory in Finder.',
    };
  }

  return {
    supported: false,
    label: 'Native Cleanup Unavailable',
    command: '',
    args: [],
    description: 'This platform does not expose a native cleanup action in the app.',
  };
}

function launchDetached(command, args = []) {
  try {
    const child = spawn(command, args, {
      detached: true,
      stdio: 'ignore',
      windowsHide: true,
    });

    child.unref();
    return true;
  } catch {
    return false;
  }
}

function calculatePathSize(targetPath) {
  let stats;

  try {
    stats = fs.lstatSync(targetPath);
  } catch {
    return 0;
  }

  if (stats.isSymbolicLink()) {
    return 0;
  }

  if (stats.isDirectory()) {
    return fs.readdirSync(targetPath).reduce(
      (total, childName) => total + calculatePathSize(path.join(targetPath, childName)),
      0,
    );
  }

  return stats.size;
}

function clearDirectoryContents(directoryPath) {
  const entries = fs.readdirSync(directoryPath);
  const result = {
    removedEntries: 0,
    reclaimedBytes: 0,
  };

  entries.forEach((entryName) => {
    const entryPath = path.join(directoryPath, entryName);

    try {
      result.reclaimedBytes += calculatePathSize(entryPath);
      fs.rmSync(entryPath, { recursive: true, force: true });
      result.removedEntries += 1;
    } catch {}
  });

  return result;
}

router.get('/', (_req, res) => {
  const nativeAction = getNativeCleanupAction();
  const tempTargets = getCleanupTargets();

  res.json({
    success: true,
    platformKey: process.platform,
    nativeAction: {
      supported: nativeAction.supported,
      label: nativeAction.label,
      description: nativeAction.description,
    },
    tempTargets,
  });
});

router.post('/open-native', (_req, res) => {
  const nativeAction = getNativeCleanupAction();

  if (!nativeAction.supported) {
    return res.status(501).json({
      success: false,
      message: 'Native cleanup is not supported on this platform.',
    });
  }

  const launched = launchDetached(nativeAction.command, nativeAction.args);

  if (!launched) {
    return res.status(500).json({
      success: false,
      message: 'Could not open the native cleanup utility.',
    });
  }

  res.json({
    success: true,
    message: `${nativeAction.label} launched.`,
  });
});

router.post('/temp-files', (_req, res) => {
  try {
    const tempTargets = getCleanupTargets();
    const summary = tempTargets.reduce((result, targetPath) => {
      const targetResult = clearDirectoryContents(targetPath);

      return {
        removedEntries: result.removedEntries + targetResult.removedEntries,
        reclaimedBytes: result.reclaimedBytes + targetResult.reclaimedBytes,
      };
    }, {
      removedEntries: 0,
      reclaimedBytes: 0,
    });

    res.json({
      success: true,
      message: `Removed ${summary.removedEntries} temp entries.`,
      result: {
        ...summary,
        tempTargets,
        completedAt: new Date().toISOString(),
      },
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Could not clear temp files.',
      error: error.message,
    });
  }
});

module.exports = router;
