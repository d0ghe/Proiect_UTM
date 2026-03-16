const fs = require('fs');
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

function toNumber(value) {
  if (value === null || value === undefined || value === '') {
    return null;
  }

  if (typeof value === 'number') {
    return Number.isFinite(value) ? value : null;
  }

  const numeric = Number(String(value).replace(/[^\d.-]/g, ''));
  return Number.isFinite(numeric) ? numeric : null;
}

function formatUptime(seconds) {
  const totalMinutes = Math.max(0, Math.floor(seconds / 60));
  const hours = Math.floor(totalMinutes / 60);
  const minutes = totalMinutes % 60;
  return `${hours} h ${minutes} m`;
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

function runCommand(command, args, timeoutMs = 3000) {
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

function average(values) {
  if (!Array.isArray(values) || values.length === 0) {
    return null;
  }

  const total = values.reduce((sum, value) => sum + value, 0);
  return round(total / values.length, 1);
}

function parseEndpoint(endpoint) {
  const value = String(endpoint || '').trim();
  if (!value || value === '*' || value === '*:*') {
    return {
      address: value || '*',
      port: null,
    };
  }

  if (value.startsWith('[') && value.includes(']:')) {
    const splitIndex = value.lastIndexOf(']:');
    return {
      address: value.slice(1, splitIndex),
      port: toNumber(value.slice(splitIndex + 2)),
    };
  }

  const splitIndex = value.lastIndexOf(':');
  if (splitIndex === -1) {
    return {
      address: value,
      port: null,
    };
  }

  return {
    address: value.slice(0, splitIndex),
    port: toNumber(value.slice(splitIndex + 1)),
  };
}

function parseCsvLine(line) {
  const values = [];
  let current = '';
  let insideQuotes = false;

  for (let index = 0; index < line.length; index += 1) {
    const character = line[index];

    if (character === '"') {
      if (insideQuotes && line[index + 1] === '"') {
        current += '"';
        index += 1;
      } else {
        insideQuotes = !insideQuotes;
      }
      continue;
    }

    if (character === ',' && !insideQuotes) {
      values.push(current);
      current = '';
      continue;
    }

    current += character;
  }

  values.push(current);
  return values;
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

function normalizeGpuControllers(rawControllers) {
  return (Array.isArray(rawControllers) ? rawControllers : []).map((controller, index) => ({
    name: controller?.model || controller?.vendor || `GPU ${index + 1}`,
    vendor: controller?.vendor || '',
    usagePercent: toNumber(controller?.utilizationGpu ?? controller?.utilization),
    memoryUsedMb: toNumber(controller?.memoryUsed ?? controller?.vramUsed),
    memoryTotalMb: toNumber(controller?.memoryTotal ?? controller?.vram),
    temperatureC: extractTemperatureNumber(controller?.temperatureGpu ?? controller?.temperature),
  }));
}

function buildGpuPayload(controllers, source) {
  const normalizedControllers = normalizeGpuControllers(controllers);
  const usageValues = normalizedControllers
    .map((controller) => controller.usagePercent)
    .filter((value) => value !== null);

  let usagePercent = average(usageValues);

  if (usagePercent === null) {
    const memoryControllers = normalizedControllers.filter(
      (controller) => controller.memoryUsedMb !== null && controller.memoryTotalMb && controller.memoryTotalMb > 0,
    );

    if (memoryControllers.length > 0) {
      const usedMemory = memoryControllers.reduce((sum, controller) => sum + controller.memoryUsedMb, 0);
      const totalMemory = memoryControllers.reduce((sum, controller) => sum + controller.memoryTotalMb, 0);
      usagePercent = totalMemory > 0 ? round((usedMemory / totalMemory) * 100, 1) : null;
    }
  }

  const names = normalizedControllers.map((controller) => controller.name).filter(Boolean);

  return {
    available: usagePercent !== null || normalizedControllers.length > 0,
    source,
    usagePercent,
    model: names.join(', ') || 'Unavailable',
    controllers: normalizedControllers,
  };
}

async function readNvidiaGpuUsage() {
  const stdout = await runCommand('nvidia-smi', [
    '--query-gpu=name,utilization.gpu,memory.used,memory.total',
    '--format=csv,noheader,nounits',
  ]);

  if (!stdout) {
    return null;
  }

  const controllers = stdout
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      const [name, usage, memoryUsed, memoryTotal] = line.split(',').map((value) => value.trim());
      return {
        model: name,
        vendor: 'NVIDIA',
        utilizationGpu: usage,
        memoryUsed,
        memoryTotal,
      };
    });

  return controllers.length > 0 ? buildGpuPayload(controllers, 'nvidia-smi') : null;
}

async function readGpu() {
  const graphics = await si.graphics().catch(() => ({ controllers: [] }));
  const graphicsPayload = buildGpuPayload(graphics?.controllers, 'systeminformation');

  if (graphicsPayload.available) {
    return graphicsPayload;
  }

  const nvidiaPayload = await readNvidiaGpuUsage();
  if (nvidiaPayload) {
    return nvidiaPayload;
  }

  return {
    available: false,
    source: 'unavailable',
    usagePercent: null,
    model: 'Unavailable',
    controllers: [],
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

function buildProcessMapFromTasklist(stdout) {
  const processMap = new Map();
  stdout
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .forEach((line) => {
      const [imageName, pid] = parseCsvLine(line);
      const numericPid = toNumber(pid);

      if (numericPid !== null && imageName) {
        processMap.set(numericPid, imageName);
      }
    });

  return processMap;
}

function buildProcessMapFromPs(stdout) {
  const processMap = new Map();
  stdout
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .forEach((line) => {
      const match = line.match(/^(\d+)\s+(.+)$/);
      if (!match) {
        return;
      }

      const [, pid, processName] = match;
      const numericPid = toNumber(pid);

      if (numericPid !== null) {
        processMap.set(numericPid, processName.trim());
      }
    });

  return processMap;
}

async function readProcessMap() {
  if (process.platform === 'win32') {
    const stdout = await runCommand('cmd', ['/c', 'tasklist', '/fo', 'csv', '/nh']);
    return buildProcessMapFromTasklist(stdout);
  }

  if (process.platform === 'linux' || process.platform === 'darwin') {
    const stdout = await runCommand('ps', ['-eo', 'pid=,comm=']);
    return buildProcessMapFromPs(stdout);
  }

  return new Map();
}

function normalizeConnection(entry) {
  return {
    protocol: String(entry.protocol || '').toUpperCase(),
    localAddress: entry.localAddress || '*',
    localPort: entry.localPort ?? null,
    remoteAddress: entry.remoteAddress || '*',
    remotePort: entry.remotePort ?? null,
    state: String(entry.state || 'UNKNOWN').toUpperCase(),
    pid: entry.pid ?? null,
    processName: entry.processName || '',
  };
}

function normalizeSystemInformationConnections(connections) {
  return (Array.isArray(connections) ? connections : []).map((entry) => normalizeConnection({
    protocol: entry.protocol,
    localAddress: entry.localaddress,
    localPort: toNumber(entry.localport),
    remoteAddress: entry.peeraddress,
    remotePort: toNumber(entry.peerport),
    state: entry.state || (String(entry.protocol).toLowerCase() === 'udp' ? 'LISTENING' : 'UNKNOWN'),
    pid: toNumber(entry.pid),
    processName: entry.process || '',
  }));
}

function parseWindowsNetstat(stdout, processMap) {
  return stdout
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => /^(TCP|UDP)\s+/i.test(line))
    .map((line) => {
      const tcpMatch = line.match(/^(TCP)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\d+)$/i);
      if (tcpMatch) {
        const [, protocol, local, remote, state, pidValue] = tcpMatch;
        const pid = toNumber(pidValue);
        const localEndpoint = parseEndpoint(local);
        const remoteEndpoint = parseEndpoint(remote);

        return normalizeConnection({
          protocol,
          localAddress: localEndpoint.address,
          localPort: localEndpoint.port,
          remoteAddress: remoteEndpoint.address,
          remotePort: remoteEndpoint.port,
          state,
          pid,
          processName: pid === null ? '' : processMap.get(pid) || '',
        });
      }

      const udpMatch = line.match(/^(UDP)\s+(\S+)\s+(\S+)\s+(\d+)$/i);
      if (udpMatch) {
        const [, protocol, local, remote, pidValue] = udpMatch;
        const pid = toNumber(pidValue);
        const localEndpoint = parseEndpoint(local);
        const remoteEndpoint = parseEndpoint(remote);

        return normalizeConnection({
          protocol,
          localAddress: localEndpoint.address,
          localPort: localEndpoint.port,
          remoteAddress: remoteEndpoint.address,
          remotePort: remoteEndpoint.port,
          state: 'LISTENING',
          pid,
          processName: pid === null ? '' : processMap.get(pid) || '',
        });
      }

      return null;
    })
    .filter(Boolean);
}

function parseSsConnections(stdout) {
  return stdout
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      const parts = line.split(/\s+/);
      if (parts.length < 6) {
        return null;
      }

      const protocol = parts[0];
      const state = protocol.startsWith('udp') && parts[1] === 'UNCONN' ? 'LISTENING' : parts[1];
      const localEndpoint = parseEndpoint(parts[4]);
      const remoteEndpoint = parseEndpoint(parts[5]);
      const processBlock = parts.slice(6).join(' ');
      const pidMatch = processBlock.match(/pid=(\d+)/);
      const processMatch = processBlock.match(/users:\(\("([^"]+)"/);

      return normalizeConnection({
        protocol,
        localAddress: localEndpoint.address,
        localPort: localEndpoint.port,
        remoteAddress: remoteEndpoint.address,
        remotePort: remoteEndpoint.port,
        state,
        pid: toNumber(pidMatch?.[1]),
        processName: processMatch?.[1] || '',
      });
    })
    .filter(Boolean);
}

async function readFallbackConnections() {
  if (process.platform === 'win32') {
    const [stdout, processMap] = await Promise.all([
      runCommand('cmd', ['/c', 'netstat', '-ano'], 5000),
      readProcessMap(),
    ]);

    return parseWindowsNetstat(stdout, processMap);
  }

  if (process.platform === 'linux') {
    const stdout = await runCommand('ss', ['-tunapH'], 5000);
    return parseSsConnections(stdout);
  }

  return [];
}

function rankConnection(connection) {
  const state = String(connection.state || '').toUpperCase();

  if (state === 'ESTABLISHED') {
    return 0;
  }

  if (state === 'LISTENING') {
    return 1;
  }

  if (String(connection.protocol || '').toUpperCase() === 'UDP') {
    return 2;
  }

  return 3;
}

function summarizeConnections(connections) {
  const listeningPorts = Array.from(new Set(
    connections
      .filter((connection) => ['LISTENING', 'UNCONN'].includes(String(connection.state || '').toUpperCase()))
      .map((connection) => connection.localPort)
      .filter((port) => port !== null),
  )).sort((left, right) => left - right);

  return {
    total: connections.length,
    established: connections.filter((connection) => String(connection.state || '').toUpperCase() === 'ESTABLISHED').length,
    listening: listeningPorts.length,
    ports: listeningPorts.slice(0, 20),
  };
}

async function readConnections() {
  const connections = await si.networkConnections().catch(() => []);
  const normalizedConnections = normalizeSystemInformationConnections(connections);
  const hasStructuredPorts = normalizedConnections.some(
    (connection) => connection.localPort !== null || connection.remotePort !== null,
  );

  const candidateConnections = hasStructuredPorts
    ? normalizedConnections
    : await readFallbackConnections();

  const sortedConnections = candidateConnections
    .sort((left, right) => {
      const stateRank = rankConnection(left) - rankConnection(right);
      if (stateRank !== 0) {
        return stateRank;
      }

      return (left.localPort || 0) - (right.localPort || 0);
    })
    .slice(0, 30);

  return {
    items: sortedConnections,
    summary: summarizeConnections(candidateConnections),
  };
}

function parseWindowsPacketCounters(stdout) {
  const metrics = {};

  stdout
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .forEach((line) => {
      const match = line.match(/^([A-Za-z- ]+?)\s+([\d,]+)\s+([\d,]+)$/);
      if (!match) {
        return;
      }

      const [, label, receivedValue, sentValue] = match;
      metrics[label.toLowerCase()] = {
        received: Number(String(receivedValue).replace(/,/g, '')),
        sent: Number(String(sentValue).replace(/,/g, '')),
      };
    });

  const unicast = metrics['unicast packets'] || { received: 0, sent: 0 };
  const nonUnicast = metrics['non-unicast packets'] || { received: 0, sent: 0 };
  const bytes = metrics.bytes || { received: 0, sent: 0 };
  const discards = metrics.discards || { received: 0, sent: 0 };
  const errors = metrics.errors || { received: 0, sent: 0 };

  return {
    rxBytes: bytes.received,
    txBytes: bytes.sent,
    rxPackets: unicast.received + nonUnicast.received,
    txPackets: unicast.sent + nonUnicast.sent,
    rxDiscards: discards.received,
    txDiscards: discards.sent,
    rxErrors: errors.received,
    txErrors: errors.sent,
    source: 'netstat-e',
  };
}

function parseLinuxPacketCounters() {
  if (!fs.existsSync('/proc/net/dev')) {
    return null;
  }

  const lines = fs.readFileSync('/proc/net/dev', 'utf8')
    .split('\n')
    .slice(2)
    .map((line) => line.trim())
    .filter(Boolean);

  const parsedInterfaces = lines
    .map((line) => {
      const [iface, counters] = line.split(':');
      if (!counters) {
        return null;
      }

      const values = counters.trim().split(/\s+/).map((value) => Number(value));
      if (values.length < 16) {
        return null;
      }

      return {
        iface: iface.trim(),
        rxBytes: values[0],
        rxPackets: values[1],
        rxErrors: values[2],
        rxDiscards: values[3],
        txBytes: values[8],
        txPackets: values[9],
        txErrors: values[10],
        txDiscards: values[11],
      };
    })
    .filter(Boolean);

  const candidates = parsedInterfaces.filter((entry) => entry.iface !== 'lo');
  const selected = candidates.length > 0 ? candidates : parsedInterfaces;

  if (selected.length === 0) {
    return null;
  }

  return selected.reduce((summary, entry) => ({
    rxBytes: summary.rxBytes + entry.rxBytes,
    txBytes: summary.txBytes + entry.txBytes,
    rxPackets: summary.rxPackets + entry.rxPackets,
    txPackets: summary.txPackets + entry.txPackets,
    rxErrors: summary.rxErrors + entry.rxErrors,
    txErrors: summary.txErrors + entry.txErrors,
    rxDiscards: summary.rxDiscards + entry.rxDiscards,
    txDiscards: summary.txDiscards + entry.txDiscards,
    source: '/proc/net/dev',
  }), {
    rxBytes: 0,
    txBytes: 0,
    rxPackets: 0,
    txPackets: 0,
    rxErrors: 0,
    txErrors: 0,
    rxDiscards: 0,
    txDiscards: 0,
    source: '/proc/net/dev',
  });
}

async function readPacketCounters(networkSample) {
  if (process.platform === 'win32') {
    const stdout = await runCommand('cmd', ['/c', 'netstat', '-e']);
    if (stdout) {
      return parseWindowsPacketCounters(stdout);
    }
  }

  if (process.platform === 'linux') {
    const linuxCounters = parseLinuxPacketCounters();
    if (linuxCounters) {
      return linuxCounters;
    }
  }

  return {
    rxBytes: Number(networkSample?.rx_bytes || 0),
    txBytes: Number(networkSample?.tx_bytes || 0),
    rxPackets: Number(networkSample?.rx_packets || 0),
    txPackets: Number(networkSample?.tx_packets || 0),
    rxErrors: Number(networkSample?.rx_errors || 0),
    txErrors: Number(networkSample?.tx_errors || 0),
    rxDiscards: Number(networkSample?.rx_dropped || 0),
    txDiscards: Number(networkSample?.tx_dropped || 0),
    source: 'network-sample',
  };
}

function parseWindowsVersion(stdout) {
  const match = stdout.match(/Version\s+([\d.]+)/i);
  return match ? match[1] : '';
}

async function readOperatingSystemDetails(osInfo) {
  const platformKey = process.platform;
  let version = osInfo?.release || os.release();
  let build = osInfo?.build || '';

  if (platformKey === 'win32') {
    const windowsVersion = parseWindowsVersion(await runCommand('cmd', ['/c', 'ver']));
    if (windowsVersion) {
      version = windowsVersion;
    }

    if (!build) {
      const versionParts = String(version).split('.');
      build = versionParts.length >= 3 ? versionParts[2] : '';
    }
  }

  return {
    platformKey,
    family: osInfo?.platform || platformKey,
    hostname: osInfo?.hostname || os.hostname(),
    distro: osInfo?.distro || osInfo?.platform || platformKey,
    version,
    release: osInfo?.release || os.release(),
    build,
    kernel: osInfo?.kernel || os.release(),
    arch: osInfo?.arch || os.arch(),
    codename: osInfo?.codename || '',
    servicePack: osInfo?.servicepack || '',
  };
}

async function collectTelemetry() {
  const [load, memory, osInfo, cpuInfo, network, users, temperature, gpu, connectionData] = await Promise.all([
    si.currentLoad().catch(() => ({ currentLoad: null })),
    si.mem().catch(() => ({ total: 0, active: 0, used: 0 })),
    si.osInfo().catch(() => ({ hostname: os.hostname(), platform: os.platform(), distro: '' })),
    si.cpu().catch(() => ({ brand: '', manufacturer: '', cores: os.cpus().length, physicalCores: os.cpus().length })),
    readPreferredNetworkSample(),
    si.users().catch(() => []),
    readTemperature(),
    readGpu(),
    readConnections(),
  ]);

  const packetCounters = await readPacketCounters(network);
  const operatingSystem = await readOperatingSystemDetails(osInfo);
  const totalMemory = memory.total || 0;
  const usedMemory = memory.active || memory.used || 0;
  const ramPercent = totalMemory > 0 ? round((usedMemory / totalMemory) * 100) : null;
  const platformParts = [operatingSystem.hostname, operatingSystem.family]
    .filter(Boolean)
    .join(' ');
  const cpuModel = cpuInfo.brand || cpuInfo.manufacturer || os.cpus()?.[0]?.model || 'Unknown CPU';

  return {
    platform: platformParts || `${os.hostname()} ${os.platform()}`,
    os: operatingSystem,
    cpu: {
      model: cpuModel,
      cores: cpuInfo.cores || os.cpus().length,
      physicalCores: cpuInfo.physicalCores || cpuInfo.cores || os.cpus().length,
      load: round(load.currentLoad) ?? 0,
    },
    gpu: {
      available: gpu.available,
      model: gpu.model,
      usagePercent: gpu.usagePercent,
      source: gpu.source,
      controllers: gpu.controllers,
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
      rxBytes: Number(network?.rx_bytes || 0),
      txBytes: Number(network?.tx_bytes || 0),
      rxErrors: Number(network?.rx_errors || 0),
      txErrors: Number(network?.tx_errors || 0),
      rxDiscards: Number(network?.rx_dropped || 0),
      txDiscards: Number(network?.tx_dropped || 0),
    },
    packets: packetCounters,
    connections: connectionData.items,
    connectionSummary: connectionData.summary,
    connectedClients: Array.isArray(users) ? users.length : 0,
  };
}

module.exports = {
  collectTelemetry,
};
