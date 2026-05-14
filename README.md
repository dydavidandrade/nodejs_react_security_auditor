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

Posicionarse en la **raíz del proyecto a auditar** y ejecutar el script pasando la URL de la aplicación como único parámetro:

```bash
node /ruta/al/sec_auditor/index.js <URL>
```

**Ejemplo:**

```bash
cd /mi/proyecto/nodejs-react
node /ruta/al/sec_auditor/index.js https://myapp.example.com
```

O bien, si se instaló de forma global con `pnpm link`:

```bash
cd /mi/proyecto/nodejs-react
sec-auditor https://myapp.example.com
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
