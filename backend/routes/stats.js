const express = require('express');

const verifyToken = require('../middleware/verifyToken');
const { collectTelemetry } = require('../utils/telemetry');

const router = express.Router();

router.use(verifyToken);

router.get('/system', async (_req, res) => {
  try {
    const telemetry = await collectTelemetry();

    res.json({
      success: true,
      platform: telemetry.platform,
      os: telemetry.os,
      uptime: telemetry.uptime,
      cpu_percent: telemetry.cpu.load,
      ram_percent: telemetry.ram.percent,
      gpu_percent: telemetry.gpu.usagePercent,
      ram_used_gb: telemetry.ram.used,
      temperature_c: telemetry.temperature.celsius,
      temperature_source: telemetry.temperature.source,
      temperature_available: telemetry.temperature.available,
      rx_rate: telemetry.network.rxRate,
      tx_rate: telemetry.network.txRate,
      connected_clients: telemetry.connectedClients,
      cpu: telemetry.cpu,
      gpu: telemetry.gpu,
      ram: telemetry.ram,
      network: telemetry.network,
      packets: telemetry.packets,
      connections: telemetry.connections,
      connectionSummary: telemetry.connectionSummary,
      temperature: telemetry.temperature,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Could not collect telemetry.',
      error: error.message,
    });
  }
});

module.exports = router;
