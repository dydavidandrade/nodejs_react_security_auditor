const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const config = require('./config');

const authRoutes  = require('./routes/auth');
const usersRoutes = require('./routes/users');
const adminRoutes = require('./routes/admin');
const filesRoutes = require('./routes/files');

const app = express();

// PASS: CORS restringido a origen conocido
app.use(cors({ origin: 'http://localhost:3000', credentials: true }));

// PASS: Parsing de body con límite de tamaño
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: false, limit: '1mb' }));

// PASS: Rate limiting general en /api (100 req/15min)
// FAIL: No hay rate limit específico en /api/auth/login
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
});
app.use('/api', generalLimiter);

// PASS: Algunos headers de seguridad configurados manualmente
// FAIL: Falta CSP, HSTS, Referrer-Policy, Permissions-Policy
app.use((req, res, next) => {
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  // FAIL: Server header expone tecnología
  res.setHeader('X-Powered-By', 'Express/Node.js');
  next();
});

app.use('/api/auth',  authRoutes);
app.use('/api/users', usersRoutes);
app.use('/api/admin', adminRoutes);
app.use('/api/files', filesRoutes);

// Ruta raíz — health check
app.get('/', (req, res) => {
  res.json({ status: 'ok', app: 'Mockup API', version: '1.0.0' });
});

// FAIL: Manejador de errores expone stack traces en producción
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(err.status || 500).json({
    error: err.message,
    stack: err.stack,          // FAIL: stack trace público
    details: err.details,
  });
});

const PORT = config.server.port;
app.listen(PORT, () => {
  console.log(`[mockup-backend] Servidor en http://localhost:${PORT}`);
  console.log(`[mockup-backend] Credenciales de prueba: admin/Admin@1234 | user1/User@1234`);
});

module.exports = app;
