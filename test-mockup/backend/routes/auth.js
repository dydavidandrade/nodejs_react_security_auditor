const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const config = require('../config');
const router = express.Router();

// PASS: Contraseñas hasheadas con bcrypt (salt rounds 10)
const users = [
  {
    id: 1,
    username: 'admin',
    email: 'admin@example.com',
    password: bcrypt.hashSync('Admin@1234', 10),
    role: 'admin',
  },
  {
    id: 2,
    username: 'user1',
    email: 'user1@example.com',
    password: bcrypt.hashSync('User@1234', 10),
    role: 'user',
  },
];

module.exports.users = users;

/**
 * POST /api/auth/login
 * PASS: Validación básica de input, bcrypt compare
 * FAIL: Sin rate limit específico en este endpoint
 * FAIL: JWT expira en 7 días (debería ser ≤15min + refresh token)
 * FAIL: Sin blacklist de tokens revocados
 * FAIL: Token devuelto en body — debería ser cookie HttpOnly
 */
router.post('/login', async (req, res) => {
  const { username, password } = req.body;

  // PASS: Validación básica
  if (!username || typeof username !== 'string' || username.length < 2) {
    return res.status(400).json({ error: 'Username inválido' });
  }
  if (!password || typeof password !== 'string') {
    return res.status(400).json({ error: 'Password requerido' });
  }

  const user = users.find(u => u.username === username);
  if (!user) {
    return res.status(401).json({ error: 'Credenciales inválidas' });
  }

  // PASS: Comparación con bcrypt (timing-safe)
  const valid = await bcrypt.compare(password, user.password);
  if (!valid) {
    return res.status(401).json({ error: 'Credenciales inválidas' });
  }

  // FAIL: Expiry de 7 días — ASVS 2.8.1 exige ≤15min para access tokens
  const token = jwt.sign(
    { id: user.id, role: user.role, username: user.username },
    config.jwt.secret,
    { expiresIn: config.jwt.expiresIn }
  );

  // FAIL: Token en body, no en cookie HttpOnly + Secure + SameSite=Strict
  res.json({
    token,
    user: { id: user.id, username: user.username, role: user.role },
  });
});

/**
 * POST /api/auth/logout
 * PASS: Endpoint de logout existe
 * FAIL: No hay revocación server-side (sin blacklist Redis)
 */
router.post('/logout', (req, res) => {
  // FAIL: El token JWT sigue siendo válido hasta que expire (7 días)
  res.json({ message: 'Logout exitoso — borra el token del cliente' });
});

/**
 * GET /api/auth/redirect
 * FAIL: Open redirect — parámetro `url` no es validado contra allowlist
 * Detectado por OpenRedirectScanner: devuelve HTTP 302 a dominio externo
 */
router.get('/redirect', (req, res) => {
  const target = req.query.url || req.query.redirect || req.query.next || '/';
  // FAIL: Sin validación — cualquier URL externa es aceptada
  res.redirect(target);
});

/**
 * POST /api/auth/register
 * PASS: Validación de longitud de password
 * PASS: Hash bcrypt antes de almacenar
 */
router.post('/register', async (req, res) => {
  const { username, email, password } = req.body;

  // PASS: Validación server-side de campos
  if (!username || username.length < 3 || username.length > 30) {
    return res.status(400).json({ error: 'Username debe tener 3-30 caracteres' });
  }
  if (!password || password.length < 8) {
    return res.status(400).json({ error: 'Password debe tener al menos 8 caracteres' });
  }

  if (users.find(u => u.username === username)) {
    return res.status(409).json({ error: 'Usuario ya existe' });
  }

  // PASS: Bcrypt hash
  const hashed = await bcrypt.hash(password, 10);
  const newUser = { id: users.length + 1, username, email, password: hashed, role: 'user' };
  users.push(newUser);

  res.status(201).json({ id: newUser.id, username: newUser.username });
});

module.exports = router;
