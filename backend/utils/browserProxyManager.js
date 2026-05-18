'use strict';

const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');

const { PROXY_PORT } = require('./httpProxy');

const REGISTRY_KEY = 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings';
const PAC_DIR = path.join(process.env.TEMP || process.env.TMP || __dirname, 'argus');
const PAC_PATH = path.join(PAC_DIR, 'browser-proxy.pac');

function parseBoolean(value, fallback = false) {
  if (value === undefined || value === null || value === '') {
    return fallback;
  }

  if (typeof value === 'boolean') {
    return value;
  }

  const normalized = String(value).trim().toLowerCase();
  if (['true', '1', 'yes', 'on'].includes(normalized)) {
    return true;
  }

  if (['false', '0', 'no', 'off'].includes(normalized)) {
    return false;
  }

  return fallback;
}

function isDirectFallbackEnabled() {
  return parseBoolean(process.env.CONTENT_FILTER_PROXY_DIRECT_FALLBACK, false);
}

function run(command) {
  return new Promise((resolve) => {
    exec(command, { windowsHide: true }, (error, stdout, stderr) => resolve({ error, stdout, stderr }));
  });
}

function buildPacFileUrl(filePath) {
  return `file:///${path.resolve(filePath).replace(/\\/g, '/')}`;
}

function getBrowserProxyPacUrl() {
  return process.env.CONTENT_FILTER_PROXY_PAC_URL || `http://127.0.0.1:${process.env.PORT || 5000}/browser-proxy.pac`;
}

function getBrowserProxyPacContent(options = {}) {
  const directFallback = options.directFallback ?? isDirectFallbackEnabled();
  const externalProxyRule = directFallback
    ? `PROXY 127.0.0.1:${PROXY_PORT}; DIRECT`
    : `PROXY 127.0.0.1:${PROXY_PORT}`;

  return `function FindProxyForURL(url, host) {
  if (
    isPlainHostName(host) ||
    shExpMatch(host, "localhost") ||
    shExpMatch(host, "127.*") ||
    shExpMatch(host, "10.*") ||
    shExpMatch(host, "192.168.*") ||
    shExpMatch(host, "172.16.*") ||
    shExpMatch(host, "172.17.*") ||
    shExpMatch(host, "172.18.*") ||
    shExpMatch(host, "172.19.*") ||
    shExpMatch(host, "172.2*.*") ||
    shExpMatch(host, "172.30.*") ||
    shExpMatch(host, "172.31.*")
  ) {
    return "DIRECT";
  }

  return "${externalProxyRule}";
}
`;
}

function writeBrowserProxyPac(options = {}) {
  fs.mkdirSync(PAC_DIR, { recursive: true });
  const pac = getBrowserProxyPacContent(options);

  fs.writeFileSync(PAC_PATH, pac, 'utf8');
  return buildPacFileUrl(PAC_PATH);
}

function parseRegistryValue(stdout, valueName) {
  const line = String(stdout || '')
    .split(/\r?\n/)
    .find((entry) => new RegExp(`\\b${valueName}\\b`, 'i').test(entry));

  if (!line) {
    return '';
  }

  const parts = line.trim().split(/\s{2,}/);
  return parts.length >= 3 ? parts.slice(2).join(' ').trim() : '';
}

async function queryRegistryValue(valueName) {
  if (process.platform !== 'win32') {
    return '';
  }

  const result = await run(`reg query "${REGISTRY_KEY}" /v ${valueName}`);
  if (result.error) {
    return '';
  }

  return parseRegistryValue(result.stdout, valueName);
}

function isDwordEnabled(value) {
  const normalized = String(value || '').trim().toLowerCase();
  return normalized === '1' || normalized === '0x1';
}

async function getWindowsProxyState() {
  if (process.platform !== 'win32') {
    return {
      supported: false,
      configured: true,
      autoConfigUrl: '',
      autoDetect: false,
      proxyEnable: false,
      proxyServer: '',
      proxyOverride: '',
    };
  }

  const [autoConfigUrl, proxyEnableValue, proxyServer, proxyOverride, autoDetectValue] = await Promise.all([
    queryRegistryValue('AutoConfigURL'),
    queryRegistryValue('ProxyEnable'),
    queryRegistryValue('ProxyServer'),
    queryRegistryValue('ProxyOverride'),
    queryRegistryValue('AutoDetect'),
  ]);
  const autoDetect = autoDetectValue === '' ? true : isDwordEnabled(autoDetectValue);
  const proxyEnable = isDwordEnabled(proxyEnableValue);
  const argusPacActive = /browser-proxy\.pac/i.test(autoConfigUrl) || /\/argus\//i.test(autoConfigUrl.replace(/\\/g, '/'));
  const manualProxyActive = proxyEnable && Boolean(proxyServer);

  return {
    supported: true,
    configured: argusPacActive && !manualProxyActive && !autoDetect,
    autoConfigUrl,
    autoDetect,
    proxyEnable,
    proxyServer,
    proxyOverride,
    argusPacActive,
    manualProxyActive,
  };
}

async function notifyWinInet() {
  if (process.platform !== 'win32') {
    return;
  }

  const ps = [
    `Add-Type -TypeDefinition 'using System;using System.Runtime.InteropServices;`,
    `public class WI{[DllImport("wininet.dll")]`,
    `public static extern bool InternetSetOption(IntPtr h,int o,IntPtr b,int l);}';`,
    `[WI]::InternetSetOption([IntPtr]::Zero,39,[IntPtr]::Zero,0)|Out-Null;`,
    `[WI]::InternetSetOption([IntPtr]::Zero,37,[IntPtr]::Zero,0)|Out-Null`,
  ].join('');

  await run(`powershell -NonInteractive -ExecutionPolicy Bypass -Command "${ps}"`);
}

async function enableBrowserProxyAutoConfig(options = {}) {
  if (process.platform !== 'win32') {
    console.log('[i] Browser proxy auto-config is only supported on Windows; skipping WinINET setup.');
    return { configured: true, supported: false, pacUrl: '', state: await getWindowsProxyState() };
  }

  const directFallback = options.directFallback ?? isDirectFallbackEnabled();
  writeBrowserProxyPac({ directFallback });
  const pacUrl = options.pacUrl || getBrowserProxyPacUrl();
  const [autoDetectResult, proxyEnableResult, pacResult] = await Promise.all([
    run(`reg add "${REGISTRY_KEY}" /v AutoDetect /t REG_DWORD /d 0 /f`),
    run(`reg add "${REGISTRY_KEY}" /v ProxyEnable /t REG_DWORD /d 0 /f`),
    run(`reg add "${REGISTRY_KEY}" /v AutoConfigURL /t REG_SZ /d "${pacUrl}" /f`),
    run(`reg delete "${REGISTRY_KEY}" /v ProxyServer /f`),
    run(`reg delete "${REGISTRY_KEY}" /v ProxyOverride /f`),
  ]);

  await notifyWinInet();
  const state = await getWindowsProxyState();

  if (autoDetectResult.error || proxyEnableResult.error || pacResult.error || !state.configured) {
    console.warn('[!] Browser PAC was written, but Windows proxy settings do not look fully configured.');
  } else {
    console.log(`[+] Browser PAC set to ${pacUrl}${directFallback ? ' with DIRECT fallback' : ''}.`);
  }

  return {
    configured: state.configured,
    supported: true,
    pacUrl,
    state,
  };
}

async function disableBrowserProxyAutoConfig() {
  if (process.platform !== 'win32') {
    return { configured: true, supported: false, state: await getWindowsProxyState() };
  }

  await Promise.all([
    run(`reg add "${REGISTRY_KEY}" /v ProxyEnable /t REG_DWORD /d 0 /f`),
    run(`reg delete "${REGISTRY_KEY}" /v AutoConfigURL /f`),
    run(`reg delete "${REGISTRY_KEY}" /v ProxyServer /f`),
    run(`reg delete "${REGISTRY_KEY}" /v ProxyOverride /f`),
  ]);
  await notifyWinInet();
  const state = await getWindowsProxyState();
  console.log('[+] Browser proxy disabled; direct connection restored.');

  return {
    configured: !state.argusPacActive && !state.manualProxyActive,
    supported: true,
    state,
  };
}

async function disableBrowserProxyIfOwned() {
  if (process.platform !== 'win32') {
    return { disabled: false, state: await getWindowsProxyState() };
  }

  const state = await getWindowsProxyState();
  const proxyServer = String(state.proxyServer || '');
  const ownedProxy = state.argusPacActive
    || proxyServer.includes(`127.0.0.1:${PROXY_PORT}`)
    || proxyServer.includes(`localhost:${PROXY_PORT}`)
    || proxyServer.includes('localhost:5000')
    || proxyServer.includes('127.0.0.1:5000');

  if (!ownedProxy) {
    return { disabled: false, state };
  }

  const result = await disableBrowserProxyAutoConfig();
  return { disabled: true, state: result.state };
}

module.exports = {
  PAC_PATH,
  buildPacFileUrl,
  disableBrowserProxyAutoConfig,
  disableBrowserProxyIfOwned,
  enableBrowserProxyAutoConfig,
  getBrowserProxyPacContent,
  getBrowserProxyPacUrl,
  getWindowsProxyState,
  parseBoolean,
  writeBrowserProxyPac,
};
