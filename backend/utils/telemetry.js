const os = require('os');
const { spawn } = require('child_process');
const si = require('systeminformation');

function round(value, digits = 1) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) {
    return null;
  }

  return Number(numeric.toFixed(digits));
}

function formatUptime(seconds) {
  const totalMinutes = Math.max(0, Math.floor(seconds / 60));
  const hours = Math.floor(totalMinutes / 60);
  const minutes = totalMinutes % 60;
  return `${hours}h ${minutes}m`;
}

function formatRate(bytesPerSecond) {
  const value = Number(bytesPerSecond);
  if (!Number.isFinite(value) || value <= 0) {
    return '0 B/s';
  }

  if (value >= 1024 * 1024) {
    return `${round(value / (1024 * 1024), 1)} MB/s`;
  }

  if (value >= 1024) {
    return `${round(value / 1024, 1)} KB/s`;
  }

  return `${Math.round(value)} B/s`;
}

function pickNetworkSample(networkStats) {
  if (!Array.isArray(networkStats) || networkStats.length === 0) {
    return null;
  }

  return (
    networkStats.find((entry) => Number(entry.rx_sec) > 0 || Number(entry.tx_sec) > 0) ||
    networkStats.find((entry) => String(entry.operstate).toLowerCase() === 'up') ||
    networkStats[0]
  );
}

function runCommand(command, args, timeoutMs = 2500) {
  return new Promise((resolve) => {
    let child;

    try {
      child = spawn(command, args, {
        windowsHide: true,
      });
    } catch (_error) {
      resolve('');
      return;
    }

    let stdout = '';
    let settled = false;

    const finalize = (value) => {
      if (!settled) {
        settled = true;
        resolve(value);
      }
    };

    const timer = setTimeout(() => {
      try {
        child.kill();
      } catch {}
      finalize('');
    }, timeoutMs);

    child.stdout.on('data', (chunk) => {
      stdout += chunk.toString();
    });

    child.on('error', () => {
      clearTimeout(timer);
      finalize('');
    });

    child.on('close', () => {
      clearTimeout(timer);
      finalize(stdout.trim());
    });
  });
}

function extractTemperatureNumber(value) {
  const numeric = round(value);
  return numeric && numeric > 0 ? numeric : null;
}

async function readGraphicsTemperature() {
  const graphics = await si.graphics().catch(() => ({ controllers: [] }));
  const controllers = Array.isArray(graphics.controllers) ? graphics.controllers : [];

  for (const controller of controllers) {
    const temperature = extractTemperatureNumber(controller.temperatureGpu ?? controller.temperature);
    if (temperature !== null) {
      return {
        value: temperature,
        source: controller.model ? `gpu:${controller.model}` : 'gpu-systeminformation',
      };
    }
  }

  return null;
}

async function readNvidiaTemperature() {
  const stdout = await runCommand('nvidia-smi', [
    '--query-gpu=temperature.gpu',
    '--format=csv,noheader,nounits',
  ]);

  const firstLine = stdout.split(/\r?\n/).find(Boolean);
  const temperature = extractTemperatureNumber(firstLine);

  return temperature === null
    ? null
    : {
        value: temperature,
        source: 'gpu:nvidia-smi',
      };
}

async function readAmdTemperature() {
  const stdout = await runCommand('amd-smi', ['metric', '--gpu', 'all', '--json']);
  if (!stdout) {
    return null;
  }

  try {
    const payload = JSON.parse(stdout);
    const devices = Object.values(payload || {});

    for (const device of devices) {
      const metrics = device?.metrics || device;
      const temperature = extractTemperatureNumber(
        metrics?.temperature_edge ?? metrics?.temperature_hotspot ?? metrics?.temperature_mem,
      );

      if (temperature !== null) {
        return {
          value: temperature,
          source: 'gpu:amd-smi',
        };
      }
    }
  } catch {}

  return null;
}

async function readRocmTemperature() {
  const stdout = await runCommand('rocm-smi', ['--showtemp', '--json']);
  if (!stdout) {
    return null;
  }

  try {
    const payload = JSON.parse(stdout);
    const devices = Object.values(payload || {});

    for (const device of devices) {
      const numericValues = Object.values(device || {})
        .map((value) => extractTemperatureNumber(value))
        .filter((value) => value !== null);

      if (numericValues.length > 0) {
        return {
          value: numericValues[0],
          source: 'gpu:rocm-smi',
        };
      }
    }
  } catch {}

  return null;
}

function readThermalZoneFallback() {
  return new Promise((resolve) => {
    const command = [
      '$ErrorActionPreference = "Stop";',
      '$zone = Get-CimInstance -Namespace root/wmi -ClassName MSAcpi_ThermalZoneTemperature | Select-Object -First 1 CurrentTemperature;',
      'if ($null -eq $zone -or $null -eq $zone.CurrentTemperature) { Write-Output ""; exit 0 }',
      '[math]::Round(($zone.CurrentTemperature / 10) - 273.15, 1)',
    ].join(' ');

    let child;

    try {
      child = spawn('powershell.exe', ['-NoProfile', '-Command', command], {
        windowsHide: true,
      });
    } catch (_error) {
      resolve(null);
      return;
    }

    let stdout = '';

    child.stdout.on('data', (chunk) => {
      stdout += chunk.toString();
    });

    child.on('error', () => resolve(null));
    child.on('close', () => {
      const value = Number.parseFloat(stdout.trim());
      resolve(Number.isFinite(value) ? value : null);
    });
  });
}

async function readTemperature() {
  const sensorData = await si.cpuTemperature().catch(() => ({ main: null }));
  const primary = round(sensorData.main);
  if (primary && primary > 0) {
    return {
      value: primary,
      source: 'systeminformation',
    };
  }

  const graphicsTemperature = await readGraphicsTemperature();
  if (graphicsTemperature) {
    return graphicsTemperature;
  }

  const nvidiaTemperature = await readNvidiaTemperature();
  if (nvidiaTemperature) {
    return nvidiaTemperature;
  }

  const amdTemperature = await readAmdTemperature();
  if (amdTemperature) {
    return amdTemperature;
  }

  const rocmTemperature = await readRocmTemperature();
  if (rocmTemperature) {
    return rocmTemperature;
  }

  const fallback = await readThermalZoneFallback();
  if (fallback && fallback > 0) {
    return {
      value: fallback,
      source: 'windows-thermal-zone',
    };
  }

  return {
    value: null,
    source: 'unavailable',
  };
}

function rankInterface(candidate) {
  let score = 0;

  if (candidate.default) {
    score += 10;
  }

  if (String(candidate.operstate).toLowerCase() === 'up') {
    score += 8;
  }

  if (candidate.ip4 && candidate.ip4 !== '127.0.0.1') {
    score += 6;
  }

  if (!candidate.internal) {
    score += 4;
  }

  if (!candidate.virtual) {
    score += 3;
  }

  if (candidate.ifaceName && !String(candidate.ifaceName).toLowerCase().includes('loopback')) {
    score += 1;
  }

  return score;
}

async function readPreferredNetworkSample() {
  const interfaces = await si.networkInterfaces().catch(() => []);
  const rankedInterfaces = (Array.isArray(interfaces) ? interfaces : [])
    .filter((candidate) => Boolean(candidate.iface))
    .sort((left, right) => rankInterface(right) - rankInterface(left));

  for (const candidate of rankedInterfaces.slice(0, 6)) {
    const statsResult = await si.networkStats(candidate.iface).catch(() => []);
    const sample = Array.isArray(statsResult) ? statsResult[0] : statsResult;

    if (sample) {
      return {
        ...sample,
        iface: candidate.iface,
      };
    }
  }

  const fallbackStats = await si.networkStats().catch(() => []);
  return pickNetworkSample(fallbackStats);
}

async function collectTelemetry() {
  const [load, memory, osInfo, cpuInfo, network, users, temperature] = await Promise.all([
    si.currentLoad().catch(() => ({ currentLoad: null })),
    si.mem().catch(() => ({ total: 0, active: 0, used: 0 })),
    si.osInfo().catch(() => ({ hostname: os.hostname(), platform: os.platform(), distro: '' })),
    si.cpu().catch(() => ({ brand: '', manufacturer: '', cores: os.cpus().length, physicalCores: os.cpus().length })),
    readPreferredNetworkSample(),
    si.users().catch(() => []),
    readTemperature(),
  ]);

  const totalMemory = memory.total || 0;
  const usedMemory = memory.active || memory.used || 0;
  const ramPercent = totalMemory > 0 ? round((usedMemory / totalMemory) * 100) : null;
  const platformParts = [osInfo.hostname, osInfo.platform || os.platform()]
    .filter(Boolean)
    .join(' ');
  const cpuModel = cpuInfo.brand || cpuInfo.manufacturer || os.cpus()?.[0]?.model || 'Unknown CPU';

  return {
    platform: platformParts || `${os.hostname()} ${os.platform()}`,
    cpu: {
      model: cpuModel,
      cores: cpuInfo.cores || os.cpus().length,
      physicalCores: cpuInfo.physicalCores || cpuInfo.cores || os.cpus().length,
      load: round(load.currentLoad) ?? 0,
    },
    ram: {
      total: round(totalMemory / (1024 ** 3), 1) ?? 0,
      used: round(usedMemory / (1024 ** 3), 1) ?? 0,
      percent: ramPercent ?? 0,
    },
    uptime: formatUptime(os.uptime()),
    uptimeSeconds: os.uptime(),
    temperature: {
      celsius: temperature.value,
      source: temperature.source,
      available: temperature.value !== null,
    },
    network: {
      iface: network?.iface || 'default',
      rxRate: formatRate(network?.rx_sec),
      txRate: formatRate(network?.tx_sec),
      rxBytes: network?.rx_bytes || 0,
      txBytes: network?.tx_bytes || 0,
    },
    connectedClients: Array.isArray(users) ? users.length : 0,
  };
}

module.exports = {
  collectTelemetry,
};
