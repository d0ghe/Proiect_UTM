const fs = require('fs');

function readScanLogs(logFile) {
  if (!fs.existsSync(logFile)) {
    return [];
  }

  const fileContent = fs.readFileSync(logFile, 'utf8').trim();
  if (!fileContent) {
    return [];
  }

  return fileContent
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean)
    .reverse();
}

function summarizeScanLogs(lines) {
  return lines.reduce(
    (summary, line) => {
      if (line.includes('STATUS: INFECTED')) {
        summary.infected += 1;
      } else if (line.includes('STATUS: CLEAN')) {
        summary.clean += 1;
      } else if (line.includes('STATUS: REVIEW')) {
        summary.review += 1;
      } else if (line.includes('STATUS: ERROR')) {
        summary.failed += 1;
      }

      summary.total += 1;
      return summary;
    },
    {
      total: 0,
      infected: 0,
      clean: 0,
      review: 0,
      failed: 0,
    },
  );
}

module.exports = {
  readScanLogs,
  summarizeScanLogs,
};
