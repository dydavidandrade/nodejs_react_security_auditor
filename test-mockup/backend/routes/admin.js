const express = require('express');
const router = express.Router();
const { verifyToken, requireAdmin } = require('../middleware/authMiddleware');

/**
 * GET /api/admin/dashboard
 * PASS: Protegido con verifyToken + requireAdmin
 */
router.get('/dashboard', verifyToken, requireAdmin, (req, res) => {
  res.json({
    stats: { users: 3, activeSessions: 7, requestsToday: 1200 },
    announcements: [
      { id: 1, content: '<b>Bienvenido</b> al panel de administración.' },
      { id: 2, content: 'Recuerda actualizar las dependencias.' },
    ],
  });
});

/**
 * POST /api/admin/execute
 * FAIL: RCE — eval() y Function() con input de usuario
 * RceScanner (SAST) detecta el patrón eval()
 * SSTI: payload ${7*7} devuelto como 49 → detectado por RceScanner DAST
 * Params testados: code, input, query (todos en CMD_PARAMS del scanner)
 */
router.post('/execute', verifyToken, requireAdmin, (req, res) => {
  const code = req.body.code || req.body.input || req.body.query || req.query.code || '';
  try {
    // FAIL: eval() con input de usuario — RCE crítico
    const result = eval(code); // eslint-disable-line no-eval
    res.json({ result: String(result) });
  } catch (err) {
    // FAIL: Expone stack trace
    res.status(500).json({ error: err.message, stack: err.stack });
  }
});

/**
 * GET /api/admin/render
 * FAIL: SSTI — sustituye ${expr} evaluando con eval()
 * RceScanner envía ?q=${7*7} → respuesta contiene "49" → SSTI detectado
 */
router.get('/render', verifyToken, requireAdmin, (req, res) => {
  const template = req.query.template || req.query.q || req.query.input || '';
  try {
    // FAIL: SSTI — sustituye expresiones ${...} evaluándolas con eval
    const output = template.replace(/\$\{([^}]+)\}/g, (_, expr) => {
      try { return eval(expr); } catch { return ''; } // eslint-disable-line no-eval
    });
    res.json({ output });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * GET /api/admin/fetch
 * FAIL: SSRF — hace fetch a cualquier URL sin validación de allowlist
 * SsrfScanner envía ?url=http://127.0.0.1 → respuesta contiene "127.0.0.1" → detectado
 */
router.get('/fetch', verifyToken, requireAdmin, async (req, res) => {
  const url = req.query.url || req.query.target || req.query.src;
  if (!url) return res.status(400).json({ error: 'url param required' });

  try {
    // FAIL: SSRF — sin validación de outbound allowlist
    const response = await fetch(url, { signal: AbortSignal.timeout(5000) });
    const text = await response.text();
    res.json({ url, status: response.status, data: text.substring(0, 500) });
  } catch (err) {
    // Incluso el error puede revelar info (timeouts indican host activo)
    res.status(500).json({ error: err.message, url });
  }
});

/**
 * GET /api/admin/proxy
 * FAIL: Open redirect + SSRF
 * OpenRedirectScanner envía ?url=https://evil-attacker.com → 302 a evil
 */
router.get('/proxy', verifyToken, requireAdmin, (req, res) => {
  const target = req.query.target || req.query.url || req.query.redirect;
  if (!target) return res.status(400).json({ error: 'target param required' });
  // FAIL: Sin validación — redirige a cualquier destino externo
  res.redirect(target);
});

/**
 * GET /api/admin/users
 * PASS: Protegido con verifyToken + requireAdmin
 * PASS: Devuelve datos sin contraseñas
 */
router.get('/users', verifyToken, requireAdmin, (req, res) => {
  const { users } = require('./auth');
  const safe = (users || []).map(({ password, ...u }) => u);
  res.json(safe);
});

module.exports = router;
