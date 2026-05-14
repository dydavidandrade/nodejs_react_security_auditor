# test-mockup — Aplicación de prueba para SEC-Auditor

Proyecto mínimo con backend Express + frontend React diseñado específicamente para evaluar SEC-Auditor.
Contiene **vulnerabilidades intencionales** para que el auditor detecte aproximadamente el **50%** de los controles como fallidos.

> ⚠️ **USO EXCLUSIVAMENTE EN ENTORNO LOCAL DE PRUEBAS**. Nunca exponer a internet.

---

## Credenciales de prueba

| Usuario  | Contraseña  | Rol   |
|----------|-------------|-------|
| admin    | Admin@1234  | admin |
| user1    | User@1234   | user  |

---

## Levantar el backend

```bash
cd test-mockup/backend
npm install
npm start
# Servidor en http://localhost:3001
```

## Ejecutar el auditor contra el mockup

```bash
# Desde la raíz del proyecto sec-auditor, con el mockup corriendo:
node /ruta/a/sec_auditor/index.js http://localhost:3001

# Cuando pregunte credenciales de auth:
#   Token: obtener haciendo POST /api/auth/login con admin / Admin@1234
```

---

## Mapa de vulnerabilidades intencionales

### ❌ FAIL — Vulnerabilidades presentes (~50%)

| # | Control | Archivo | Scanner que lo detecta |
|---|---------|---------|----------------------|
| 1 | HTTP sin TLS/HTTPS | `backend/index.js` | TlsScanner |
| 2 | Sin CSP header | `backend/index.js` | HeadersScanner |
| 3 | Sin HSTS header | `backend/index.js` | HeadersScanner / TlsScanner |
| 4 | Sin Referrer-Policy | `backend/index.js` | HeadersScanner |
| 5 | Server header expone tecnología | `backend/index.js` | HeadersScanner |
| 6 | Stack traces en errores 500 | `backend/index.js` | BackendAnalyzer / DAST |
| 7 | JWT secret hardcodeado | `backend/config.js` | SecretsAnalyzer / AuthScanner |
| 8 | JWT expiry 7 días (debe ser ≤15min) | `backend/config.js` | AuthScanner |
| 9 | Sin blacklist de tokens revocados | `backend/routes/auth.js` | AuthScanner |
| 10 | Token JWT en localStorage | `frontend/src/App.jsx` | FrontendAnalyzer |
| 11 | Sin rate limit en /api/auth/login | `backend/index.js` | RateLimitScanner |
| 12 | SQL Injection en /users/search | `backend/routes/users.js` | SqliScanner |
| 13 | XSS reflejado en /users/search | `backend/routes/users.js` | XssScanner |
| 14 | RCE via eval() en /admin/execute | `backend/routes/admin.js` | RceScanner / SAST |
| 15 | SSTI en /admin/render | `backend/routes/admin.js` | RceScanner |
| 16 | SSRF en /admin/fetch | `backend/routes/admin.js` | SsrfScanner |
| 17 | Open Redirect en /auth/redirect | `backend/routes/auth.js` | OpenRedirectScanner |
| 18 | Open Redirect en /admin/proxy | `backend/routes/admin.js` | OpenRedirectScanner |
| 19 | Path Traversal en /files/download | `backend/routes/files.js` | PathTraversalScanner |
| 20 | Sin CSRF protection | `backend/routes/users.js` | CsrfScanner |
| 21 | IDOR en DELETE /users/:id | `backend/routes/users.js` | BackendAnalyzer |
| 22 | dangerouslySetInnerHTML | `frontend/src/components/Dashboard.jsx` | FrontendAnalyzer / XssScanner |
| 23 | Claves Stripe/API hardcodeadas en frontend | `frontend/src/components/Dashboard.jsx` | SecretsAnalyzer |
| 24 | API key en App.jsx | `frontend/src/App.jsx` | SecretsAnalyzer |
| 25 | Stripe key en config.js | `backend/config.js` | SecretsAnalyzer |
| 26 | Inline scripts en HTML | `frontend/public/index.html` | FrontendAnalyzer |
| 27 | Script externo sin SRI | `frontend/public/index.html` | FrontendAnalyzer |

### ✅ PASS — Controles correctamente implementados (~50%)

| # | Control | Archivo |
|---|---------|---------|
| 1 | Contraseñas hasheadas con bcrypt (10 rounds) | `backend/routes/auth.js` |
| 2 | Rate limiting general en /api (100 req/15min) | `backend/index.js` |
| 3 | Auth middleware (verifyToken) en rutas protegidas | `backend/middleware/authMiddleware.js` |
| 4 | RBAC — requireAdmin para rutas de administración | `backend/middleware/authMiddleware.js` |
| 5 | CORS restringido a origen específico | `backend/index.js` |
| 6 | X-Frame-Options: DENY | `backend/index.js` |
| 7 | X-Content-Type-Options: nosniff | `backend/index.js` |
| 8 | X-XSS-Protection: 1; mode=block | `backend/index.js` |
| 9 | Validación server-side en /register (longitud) | `backend/routes/auth.js` |
| 10 | Validación server-side en PUT /profile (bio ≤500) | `backend/routes/users.js` |
| 11 | Listado de archivos requiere autenticación | `backend/routes/files.js` |
| 12 | Respuesta de login no devuelve contraseña | `backend/routes/auth.js` |
| 13 | React auto-escaping en la mayoría de componentes | `frontend/src/components/UserProfile.jsx` |
| 14 | Validación client-side en Login y UserProfile | `frontend/src/components/Login.jsx` |
| 15 | Rutas frontend protegidas (requieren token) | `frontend/src/App.jsx` |

---

## Endpoints del backend

| Método | Ruta | Auth | Vulnerabilidad |
|--------|------|------|----------------|
| POST | /api/auth/login | No | Sin rate limit, JWT 7d |
| POST | /api/auth/logout | No | Sin revocación |
| GET | /api/auth/redirect | No | **Open Redirect** |
| POST | /api/auth/register | No | — |
| GET | /api/users/profile | ✓ | — |
| PUT | /api/users/profile | ✓ | **Sin CSRF** |
| GET | /api/users/search | No | **SQLi + XSS reflejado** |
| DELETE | /api/users/:id | ✓ | **IDOR** |
| GET | /api/admin/dashboard | ✓ Admin | — |
| POST | /api/admin/execute | ✓ Admin | **RCE (eval)** |
| GET | /api/admin/render | ✓ Admin | **SSTI** |
| GET | /api/admin/fetch | ✓ Admin | **SSRF** |
| GET | /api/admin/proxy | ✓ Admin | **Open Redirect + SSRF** |
| GET | /api/files/ | ✓ | — |
| GET | /api/files/download | ✓ | **Path Traversal** |
| POST | /api/files/upload | ✓ | Unrestricted upload |
