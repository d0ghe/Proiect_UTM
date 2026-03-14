const express = require('express');
const router = express.Router();

// 1. Importăm bodyguard-ul
const verifyToken = require('../middleware/verifyToken');

// 2. Îl punem la ușă pentru TOATE rutele din acest fișier
router.use(verifyToken);

let firewallRules = [
    { id: 1, action: "BLOCK", protocol: "TCP", port: 22, ip: "Any", status: "Active", desc: "Blocheaza SSH" },
    { id: 2, action: "ALLOW", protocol: "TCP", port: 80, ip: "Any", status: "Active", desc: "Permite HTTP" }
];

// Nu mai folosim app.get, ci router.get
// Atenție: nu mai scriem '/api/firewall/rules', ci doar '/rules', pentru că prefixul îl punem în server.js
router.get('/rules', (req, res) => {
    res.json(firewallRules);
});

router.post('/rules', (req, res) => {
    const newRule = { id: Date.now(), ...req.body };
    firewallRules.push(newRule);
    res.status(201).json({ message: "Regula adăugată!", rule: newRule });
});

router.delete('/rules/:id', (req, res) => {
    const ruleId = parseInt(req.params.id);
    firewallRules = firewallRules.filter(rule => rule.id !== ruleId);
    res.json({ message: `Regula ${ruleId} ștearsă.` });
});

// Exportăm router-ul ca să poată fi folosit de server.js
module.exports = router;