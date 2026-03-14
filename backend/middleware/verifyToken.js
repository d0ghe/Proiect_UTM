// middleware/verifyToken.js

const verifyToken = (req, res, next) => {
    // 1. Căutăm "biletul" în header-ul cererii
    const authHeader = req.headers['authorization'];

    // Dacă nu există deloc biletul
    if (!authHeader) {
        return res.status(403).json({ 
            success: false, 
            message: "Acces interzis! Nu ai furnizat un Token de securitate." 
        });
    }

    // Token-ul vine de obicei în formatul: "Bearer utm-auth-token-12345"
    // Îl tăiem ca să luăm doar partea a doua (token-ul propriu-zis)
    const token = authHeader.split(' ')[1];

    // 2. Verificăm dacă token-ul este valid
    // (Aici am pus regula simplă setată de noi la login)
    if (token && token.startsWith("utm-auth-token-")) {
        next(); // Bodyguard-ul zice: "Ești ok, poți trece mai departe!"
    } else {
        res.status(401).json({ 
            success: false, 
            message: "Token invalid sau expirat!" 
        });
    }
};

module.exports = verifyToken;