const express = require('express');
const router = express.Router();

const adminUser = { username: "admin", password: "password123" };

router.post('/login', (req, res) => {
    const { username, password } = req.body;

    if (username === adminUser.username && password === adminUser.password) {
        const fakeToken = "utm-auth-token-" + Date.now();
        res.status(200).json({ success: true, token: fakeToken });
    } else {
        res.status(401).json({ success: false, message: "Parolă incorectă!" });
    }
});

module.exports = router;