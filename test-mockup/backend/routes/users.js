const express = require('express');
const router = express.Router();
const { verifyToken } = require('../middleware/authMiddleware');

// Base de datos en memoria (simulada)
let dbUsers = [
  { id: 1, username: 'admin',  email: 'admin@example.com',  role: 'admin', bio: 'Administrador del sistema' },
  { id: 2, username: 'user1',  email: 'user1@example.com',  role: 'user',  bio: 'Usuario regular' },
  { id: 3, username: 'alice',  email: 'alice@example.com',  role: 'user',  bio: '' },
];

/**
 * GET /api/users/profile
 * PASS: Ruta protegida con auth middleware
 */
router.get('/profile', verifyToken, (req, res) => {
  const user = dbUsers.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: 'Usuario no encontrado' });
  const { password, ...safeUser } = user;
  res.json(safeUser);
});

/**
 * PUT /api/users/profile
 * PASS: Protegido, validación de longitud
 * FAIL: Sin CSRF token — CsrfScanner detectará que Origin externo devuelve 200
 */
router.put('/profile', verifyToken, (req, res) => {
  const { bio, email } = req.body;

  // PASS: Validación server-side de longitud
  if (bio !== undefined && bio.length > 500) {
    return res.status(400).json({ error: 'Bio demasiado larga (máx 500 caracteres)' });
  }

  const idx = dbUsers.findIndex(u => u.id === req.user.id);
  if (idx === -1) return res.status(404).json({ error: 'Usuario no encontrado' });

  // FAIL: Sin CSRF token — cualquier sitio puede hacer esta petición con credenciales del usuario
  if (bio !== undefined) dbUsers[idx].bio = bio;
  if (email !== undefined) dbUsers[idx].email = email;

  const { password, ...safeUser } = dbUsers[idx];
  res.json(safeUser);
});

/**
 * GET /api/users/search
 * FAIL: SQL Injection — entrada del usuario concatenada directamente en la query
 * FAIL: XSS reflejado — el parámetro `q` se devuelve en la respuesta sin sanitizar
 * SqliScanner detecta error de sintaxis SQL en la respuesta
 * XssScanner detecta que XSS_PROBE aparece en la respuesta JSON
 */
router.get('/search', (req, res) => {
  const { q } = req.query;

  // FAIL: SQL Injection — string concatenation en lugar de prepared statements
  const rawQuery = `SELECT * FROM users WHERE username LIKE '%${q}%' OR email LIKE '%${q}%'`;

  // Simula error de SQL cuando la entrada contiene comilla simple
  if (q && (q.includes("'") || q.includes('"') || q.toLowerCase().includes(' or ') || q.toLowerCase().includes(' and '))) {
    return res.status(500).json({
      error: `You have an error in your SQL syntax; check the manual near '${q}' at line 1`,
      query: rawQuery,
    });
  }

  // FAIL: XSS reflejado — `q` se incluye en la respuesta sin escapar
  const results = dbUsers.filter(u =>
    u.username.toLowerCase().includes((q || '').toLowerCase()) ||
    u.email.toLowerCase().includes((q || '').toLowerCase())
  ).map(({ password, ...u }) => u);

  // `query` devuelve el input sin sanitizar → XSS reflejado en JSON
  res.json({ query: q, results });
});

/**
 * DELETE /api/users/:id
 * PASS: Requiere autenticación
 * FAIL: IDOR — cualquier usuario autenticado puede borrar a cualquier otro
 */
router.delete('/:id', verifyToken, (req, res) => {
  const targetId = parseInt(req.params.id);
  // FAIL: Sin verificar que req.user.id === targetId o que req.user.role === 'admin'
  dbUsers = dbUsers.filter(u => u.id !== targetId);
  res.json({ message: `Usuario ${targetId} eliminado` });
});

module.exports = router;
