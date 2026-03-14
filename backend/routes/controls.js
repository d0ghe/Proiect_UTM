const express = require('express');

const verifyToken = require('../middleware/verifyToken');
const { getControls, updateControls } = require('../store/runtimeState');

const router = express.Router();

router.use(verifyToken);

router.get('/', (_req, res) => {
  res.json({ success: true, controls: getControls() });
});

router.patch('/', (req, res) => {
  const nextControls = updateControls(req.body);
  res.json({ success: true, controls: nextControls });
});

module.exports = router;
