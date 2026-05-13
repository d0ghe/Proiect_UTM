const assert = require('assert/strict');
const { test } = require('node:test');

const { CHUNK_SIZE, scanBufferForHexSignatures } = require('../utils/hexSignatures');

test('hex signature scanning returns for small files without matches', () => {
  const result = scanBufferForHexSignatures(Buffer.from('hello local scan'));

  assert.deepEqual(result, {
    detected: false,
    matches: [],
  });
});

test('hex signature scanning detects signatures across chunk boundaries', () => {
  const prefix = Buffer.alloc(CHUNK_SIZE - 2, 0x41);
  const payload = Buffer.concat([
    prefix,
    Buffer.from([0x90, 0x90, 0x90, 0x90, 0x90]),
  ]);

  const result = scanBufferForHexSignatures(payload);

  assert.equal(result.detected, true);
  assert.equal(result.matches.some((match) => match.name === 'Shellcode_NOP_Sled'), true);
});
