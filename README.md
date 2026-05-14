# Node.js + React Security Auditor

Herramienta CLI de ethical hacking que evalúa la seguridad de una aplicación Node.js + React. Analiza el código fuente, detecta vulnerabilidades mediante análisis estático (SAST) y dinámico (DAST), y genera un reporte detallado con pasos de remediación.

Cubre los 11 dominios definidos en `SEC.spec.md`: autenticación, frontend, backend/API, WebSocket/WebRTC, criptografía, infraestructura, DevSecOps, observabilidad, privacidad, controles de IA y gobierno.

---

## Como ejecutar

### Requisitos previos

- **Node.js** >= 18 LTS
- **pnpm** >= 8

```bash
npm install -g pnpm
```

### 1. Clonar el repositorio

```bash
git clone https://github.com/dydavidandrade/nodejs_react_security_auditor.git
cd nodejs_react_security_auditor
```

### 2. Instalar dependencias

```bash
pnpm install
```

### 3. Ejecutar la auditoría

```bash
node /ruta/al/sec_auditor/index.js <URL> [path-al-codigo]
```

| Parámetro | Obligatorio | Descripción |
|-----------|-------------|-------------|
| `<URL>` | ✅ | URL completa de la aplicación objetivo (`http://` o `https://`) |
| `[path-al-codigo]` | ❌ | Ruta al código fuente a analizar. Si se omite, usa el directorio actual (`cwd`) |

**Ejemplos:**

```bash
# Desde la raíz del proyecto a auditar (usa cwd como path)
cd /mi/proyecto/nodejs-react
node /ruta/al/sec_auditor/index.js https://myapp.example.com

# Pasando el path explícitamente desde cualquier directorio
node /ruta/al/sec_auditor/index.js http://localhost:3001 ./test-mockup

# Con path absoluto
node /ruta/al/sec_auditor/index.js https://myapp.example.com /ruta/absoluta/al/proyecto
```

O bien, si se instaló de forma global con `pnpm link`:

```bash
sec-auditor https://myapp.example.com /ruta/al/proyecto
```

### 4. Resultados

Al finalizar el auditor genera en el directorio de trabajo:

| Artefacto | Descripción |
|---|---|
| `SEC_REPORT_<timestamp>.md` | Reporte legible en texto plano con hallazgos y remediaciones |
| `SEC_REPORT_<timestamp>.json` | Reporte estructurado con todos los findings en formato `findings.json` |

Al terminar, el auditor limpia automáticamente los artefactos temporales del escaneo.

### Parámetros

```
Uso: node index.js <URL>

  URL   URL completa de la aplicación objetivo (http:// o https://)
```

---

## Versiones

| Versión | Fecha | Característica |
|---|---|---|
| 1.0.0 | 2026-05-14 | Versión inicial. Analizadores SAST/DAST, escáneres de vectores de ataque (XSS, SQLi, SSRF, RCE, CSRF, Path Traversal, Open Redirect, Rate Limit, TLS, Headers, Auth, WebSocket), análisis de backend (Express/NestJS), análisis de frontend (React), escáner de secretos, análisis de dependencias, reporte JSON + texto plano con remediaciones según SEC.spec.md |
| 1.1.0 | 2026-05-14 | Refactor a ESM (chalk v5, inquirer v13, ora v9). Soporte de segundo parámetro `[path-al-codigo]` para apuntar al código fuente desde cualquier directorio. Proyecto de prueba `test-mockup` con backend Express + frontend React con ~50% de vulnerabilidades intencionales |
| 1.2.0 | 2026-05-14 | Sección **OWASP Top 10 — 2021** en el reporte con matriz de cumplimiento y puntuación. Nuevo `OwaspAnalyzer` con 12 verificaciones SAST+DAST propias (A01–A10): CORS wildcard, NestJS sin guards, hash débil MD5/SHA1, sin CSRF middleware, sin validación de schema, sin helmet, jwt.sign sin expiresIn, deserialización insegura, SSRF endpoints sensibles expuestos, sin logging estructurado, console.log con datos sensibles, sin logging de eventos de auth. Campo `owasp` agregado a cada Finding |
| 1.3.0 | 2026-05-14 | **Matriz de cumplimiento gerencial SEC.spec.md** en el reporte: los 60 controles de los 11 dominios (Gobierno, Auth, Frontend, Backend, WebSocket, Criptografía, Infra, DevSecOps, Observabilidad, Privacidad, IA/Voz) con estado ✅ OK / ⚠️ PARCIAL / ❌ FALLO / ⚪ NO EVALUADO. Lógica severity threshold (critical/high → FALLO, medium → PARCIAL). Score de cumplimiento automático con barra visual. Resumen por dominio + tabla detallada. Sección posicionada al inicio del reporte para lectura gerencial |
