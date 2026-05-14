const jwt = require('jsonwebtoken');
const config = require('../config');

/**
 * PASS: Verifica JWT en el header Authorization.
 * FAIL: Usa el secreto hardcodeado de config.js — debería venir de un Secret Manager.
 */
const verifyToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }

  try {
    const decoded = jwt.verify(token, config.jwt.secret);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(403).json({ error: 'Invalid or expired token' });
  }
};

/**
 * PASS: Verifica rol de administrador después de verifyToken.
 */
const requireAdmin = (req, res, next) => {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Se requiere rol de administrador' });
  }
  next();
};

module.exports = { verifyToken, requireAdmin };
