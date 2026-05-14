import path from 'path';
import BaseAnalyzer from './BaseAnalyzer.js';
import { Finding } from '../utils/Finding.js';

/** Rutas sensibles expuestas que nunca deberían ser accesibles en producción. */
const SENSITIVE_PATHS = [
  '/.env', '/.env.local', '/.env.production',
  '/.git/HEAD', '/.git/config',
  '/debug', '/api/debug', '/_debug', '/_status',
  '/swagger', '/swagger-ui', '/swagger-ui.html', '/api-docs', '/openapi.json',
  '/graphql',
  '/actuator', '/actuator/env', '/actuator/health',
  '/server-status', '/server-info',
  '/phpinfo.php', '/info.php',
  '/config', '/config.json', '/app-config.json',
];

/** Librerías de logging reconocidas. */
const LOGGING_LIBS = ['morgan', 'winston', 'pino', 'bunyan', 'log4js', 'npmlog', 'loglevel'];

/** Librerías de validación de input reconocidas. */
const VALIDATION_LIBS = ['joi', 'zod', 'yup', 'class-validator', 'express-validator', 'ajv', 'superstruct'];

/** Librerías de CSRF reconocidas. */
const CSRF_LIBS = ['csurf', 'csrf-csrf', 'lusca', 'tiny-csrf', 'csrf'];

/**
 * Analizador OWASP Top 10 — 2021.
 * Ejecuta verificaciones estáticas (SAST) y dinámicas (DAST) específicas de cada categoría.
 * Complementa los escáneres existentes con controles propios del marco OWASP.
 */
class OwaspAnalyzer extends BaseAnalyzer {
  /**
   * @param {string} rootDir
   * @param {import('../utils/FileSystem.js').default} fileSystem
   * @param {import('../utils/Logger.js').default} logger
   * @param {string} url - URL objetivo para verificaciones dinámicas
   */
  constructor(rootDir, fileSystem, logger, url) {
    super(rootDir, fileSystem, logger);
    this.url = url;
  }

  async analyze() {
    const allFiles = this.fs.getAllFiles(['.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs']);
    const allContent = allFiles.map(f => this.fs.readFile(f) || '').join('\n');
    const pkgJson    = this._readPackageJson();

    await this._checkA01_BrokenAccessControl(allFiles, allContent);
    await this._checkA02_CryptographicFailures(allContent);
    await this._checkA04_InsecureDesign(allContent, pkgJson);
    await this._checkA05_SecurityMisconfiguration(allContent, pkgJson);
    await this._checkA07_AuthFailures(allFiles);
    await this._checkA08_DataIntegrity(allContent);
    await this._checkA09_LoggingMonitoring(allContent, pkgJson);
    await this._checkA05_ExposedEndpoints();
  }

  // ── A01: Broken Access Control ────────────────────────────────────────────

  async _checkA01_BrokenAccessControl(allFiles, allContent) {
    // CORS wildcard — cualquier origen puede hacer peticiones con credenciales
    if (/cors\s*\(\s*\{\s*[^}]*origin\s*:\s*['"\*]/m.test(allContent)) {
      this.addFinding(new Finding({
        title: 'CORS con origin wildcard (*)',
        control_id: 'A01-CORS', asvs_id: 'ASVS 14.5.3', severity: 'high', category: 'access_control',
        owasp: 'A01:2021',
        description: 'La configuración CORS acepta peticiones de cualquier origen (`*`). Con `credentials: true` permite ataques CSRF cross-origin.',
        remediation_steps: 'Define una allowlist explícita de orígenes: `cors({ origin: ["https://app.tudominio.com"] })`.',
        file: this._findFileWith(allFiles, /cors\s*\(\s*\{[^}]*origin\s*:\s*['"\*]/m),
      }));
    }

    // NestJS @Controller sin @UseGuards en el mismo archivo
    for (const file of allFiles) {
      const content = this.fs.readFile(file) || '';
      if (!content.includes('@Controller')) continue;
      const controllers = (content.match(/@Controller\s*\(/g) || []).length;
      const guards      = (content.match(/@UseGuards\s*\(/g) || []).length;
      if (controllers > 0 && guards === 0) {
        this.addFinding(new Finding({
          title: `NestJS Controller sin @UseGuards: ${path.basename(file)}`,
          control_id: 'A01-NESTJS', asvs_id: 'ASVS 4.1.1', severity: 'high', category: 'access_control',
          owasp: 'A01:2021',
          description: `El controlador NestJS en ${path.basename(file)} no tiene ningún guard de autenticación/autorización definido.`,
          remediation_steps: 'Aplica `@UseGuards(JwtAuthGuard)` a nivel de controlador o en cada endpoint sensible. Usa `@Public()` solo para rutas explícitamente públicas.',
          file: path.relative(this.rootDir, file),
        }));
      }
    }
  }

  // ── A02: Cryptographic Failures ───────────────────────────────────────────

  async _checkA02_CryptographicFailures(allContent) {
    // MD5 o SHA1 aplicado a contraseñas
    if (/(?:md5|sha1|createHash\s*\(\s*['"](?:md5|sha1)['"])\s*[.(][^)]*(?:password|passwd|pwd|contraseña)/i.test(allContent)) {
      this.addFinding(new Finding({
        title: 'Hash débil (MD5/SHA1) para contraseñas',
        control_id: 'A02-HASH', asvs_id: 'ASVS 2.4.1', severity: 'critical', category: 'authentication',
        owasp: 'A02:2021',
        description: 'Se detectó uso de MD5 o SHA1 para hashear contraseñas. Estos algoritmos son criptográficamente rotos para este propósito.',
        remediation_steps: 'Usa `bcrypt` (≥10 rounds), `argon2id` o `scrypt`. Ejemplo: `await bcrypt.hash(password, 12)`.',
      }));
    }

    // URLs HTTP hardcodeadas (no HTTPS) en configuración
    const httpMatches = [...(allContent.matchAll(/(?:apiBase|baseUrl|API_URL|endpoint)\s*[=:]\s*['"]http:\/\//gm))];
    if (httpMatches.length > 0) {
      this.addFinding(new Finding({
        title: 'URLs de API configuradas con HTTP en lugar de HTTPS',
        control_id: 'A02-HTTP', asvs_id: 'ASVS 9.1.1', severity: 'medium', category: 'transport_security',
        owasp: 'A02:2021',
        description: 'Se encontraron URLs de API hardcodeadas con esquema `http://`. El tráfico va sin cifrar, exponiendo tokens y datos sensibles.',
        remediation_steps: 'Usa siempre `https://` en producción. Extrae las URLs a variables de entorno y valida que usen HTTPS.',
      }));
    }
  }

  // ── A04: Insecure Design ──────────────────────────────────────────────────

  async _checkA04_InsecureDesign(allContent, pkgJson) {
    // Sin middleware CSRF en el backend
    const hasCsrf = CSRF_LIBS.some(lib =>
      allContent.includes(`'${lib}'`) || allContent.includes(`"${lib}"`) ||
      (pkgJson?.dependencies?.[lib] || pkgJson?.devDependencies?.[lib])
    );
    if (!hasCsrf && /express|fastify/i.test(allContent)) {
      this.addFinding(new Finding({
        title: 'Sin middleware CSRF a nivel de aplicación',
        control_id: 'A04-CSRF', asvs_id: 'ASVS 4.2.2', severity: 'high', category: 'csrf',
        owasp: 'A04:2021',
        description: 'No se detectó ninguna librería de protección CSRF (csurf, csrf-csrf, lusca). Las rutas mutantes son vulnerables a ataques cross-site.',
        remediation_steps: 'Instala `csrf-csrf` y aplica el middleware en rutas POST/PUT/DELETE. Complementa con `SameSite=Strict` en cookies.',
      }));
    }

    // Sin librería de validación de input
    const hasValidation = VALIDATION_LIBS.some(lib =>
      allContent.includes(`'${lib}'`) || allContent.includes(`"${lib}"`) ||
      (pkgJson?.dependencies?.[lib] || pkgJson?.devDependencies?.[lib])
    );
    if (!hasValidation) {
      this.addFinding(new Finding({
        title: 'Sin librería de validación de input (schema validation)',
        control_id: 'A04-VALIDATION', asvs_id: 'ASVS 5.1.3', severity: 'medium', category: 'validation',
        owasp: 'A04:2021',
        description: 'No se detectó ninguna librería de validación de schema (Zod, Joi, class-validator, express-validator). El input de usuario no se valida contra contratos definidos.',
        remediation_steps: 'Integra Zod o Joi para validar todos los inputs. En NestJS usa `class-validator` con `ValidationPipe`. Ejemplo: `app.useGlobalPipes(new ValidationPipe({ whitelist: true }))`.',
      }));
    }
  }

  // ── A05: Security Misconfiguration ───────────────────────────────────────

  async _checkA05_SecurityMisconfiguration(allContent, pkgJson) {
    // Helmet no instalado ni importado
    const hasHelmet = /require\s*\(\s*['"]helmet['"]|import\s+\w+\s+from\s+['"]helmet['"]/m.test(allContent) ||
      pkgJson?.dependencies?.helmet || pkgJson?.devDependencies?.helmet;
    if (!hasHelmet && /express/i.test(allContent)) {
      this.addFinding(new Finding({
        title: 'Helmet no configurado — cabeceras de seguridad HTTP ausentes',
        control_id: 'A05-HELMET', asvs_id: 'ASVS 14.4.1', severity: 'high', category: 'headers',
        owasp: 'A05:2021',
        description: 'No se detectó `helmet` en la aplicación Express. Sin él faltan cabeceras críticas: CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Permissions-Policy.',
        remediation_steps: 'Instala y configura helmet: `app.use(helmet())`. Configura CSP con nonces: `helmet.contentSecurityPolicy({ directives: { ... } })`.',
      }));
    }

    // CORS wildcard (también A01, pero en A05 es misconfiguration)
    if (/cors\s*\(\s*['"]?\*['"]?\s*\)|cors\s*\(\s*\)\s*(?![\w{])/m.test(allContent)) {
      this.addFinding(new Finding({
        title: 'CORS sin restricción de origen (misconfiguration)',
        control_id: 'A05-CORS', asvs_id: 'ASVS 14.5.3', severity: 'medium', category: 'headers',
        owasp: 'A05:2021',
        description: 'CORS configurado sin especificar origen. Puede derivar en configuración de `*` por defecto.',
        remediation_steps: 'Siempre especifica `origin` explícitamente: `cors({ origin: process.env.ALLOWED_ORIGIN })`.',
      }));
    }

    // Modo debug / development activo
    if (/app\.set\s*\(\s*['"]env['"][^,)]+development|DEBUG\s*=\s*['"]?\*/m.test(allContent)) {
      this.addFinding(new Finding({
        title: 'Modo debug/development activo en configuración',
        control_id: 'A05-DEBUG', asvs_id: 'ASVS 14.3.2', severity: 'medium', category: 'information_disclosure',
        owasp: 'A05:2021',
        description: 'Se detectó configuración de modo desarrollo activo (`app.set("env", "development")` o `DEBUG=*`). Esto habilita stack traces detallados y puede exponer rutas internas.',
        remediation_steps: 'Usa `NODE_ENV=production` en producción. Lee el entorno desde variables de entorno, nunca lo hardcodees.',
      }));
    }
  }

  // ── A07: Identification and Authentication Failures ───────────────────────

  async _checkA07_AuthFailures(allFiles) {
    for (const file of allFiles) {
      const content = this.fs.readFile(file) || '';
      if (!content.includes('jwt') && !content.includes('jsonwebtoken')) continue;

      // jwt.sign() sin expiresIn
      const signCalls = [...content.matchAll(/jwt\.sign\s*\(([^;]{0,300})/gm)];
      for (const [, args] of signCalls) {
        if (!args.includes('expiresIn') && !args.includes('exp:')) {
          this.addFinding(new Finding({
            title: 'jwt.sign() sin expiresIn — tokens sin expiración',
            control_id: 'A07-JWT-EXP', asvs_id: 'ASVS 2.8.1', severity: 'high', category: 'authentication',
            owasp: 'A07:2021',
            description: 'Se detectó una llamada a `jwt.sign()` sin la opción `expiresIn`. Los tokens generados nunca expiran, lo que permite acceso indefinido si son robados.',
            remediation_steps: 'Siempre define `expiresIn` ≤15min para access tokens: `jwt.sign(payload, secret, { expiresIn: "15m" })`. Implementa refresh tokens con rotación.',
            file: path.relative(this.rootDir, file),
            line: this._lineOf(content, content.indexOf('jwt.sign')),
          }));
          break;
        }
      }
    }
  }

  // ── A08: Software and Data Integrity Failures ─────────────────────────────

  async _checkA08_DataIntegrity(allContent) {
    // Deserialización insegura con node-serialize
    if (/require\s*\(\s*['"]node-serialize['"]|unserialize\s*\([^)]*req\./m.test(allContent)) {
      this.addFinding(new Finding({
        title: 'Deserialización insegura — node-serialize con input de usuario',
        control_id: 'A08-DESERIAL', asvs_id: 'ASVS 1.5.2', severity: 'critical', category: 'deserialization',
        owasp: 'A08:2021',
        description: '`node-serialize` con input de usuario permite RCE mediante IIFE en el payload serializado. CVE-2017-5941.',
        remediation_steps: 'Nunca uses `node-serialize` con datos externos. Para transferir datos estructurados usa JSON con validación de schema (Zod/Joi).',
      }));
    }

    // new Function() con input del usuario
    if (/new\s+Function\s*\([^)]*(?:req\.|body\.|params\.|query\.)/m.test(allContent)) {
      this.addFinding(new Finding({
        title: 'new Function() con input de usuario — RCE / Data Integrity',
        control_id: 'A08-FUNC', asvs_id: 'ASVS 1.5.2', severity: 'critical', category: 'rce',
        owasp: 'A08:2021',
        description: '`new Function(userInput)` es equivalente a `eval()`. Ejecuta código arbitrario con el contexto del proceso Node.js.',
        remediation_steps: 'Elimina cualquier uso de `new Function()` con input externo. Para expresiones matemáticas usa `mathjs`. Para templates usa motores con sandboxing.',
      }));
    }

    // JSON.parse sobre input de usuario sin try/catch visible cerca
    if (/JSON\.parse\s*\(\s*req\./m.test(allContent)) {
      this.addFinding(new Finding({
        title: 'JSON.parse() aplicado directamente sobre req.body/params/query',
        control_id: 'A08-JSONPARSE', asvs_id: 'ASVS 5.1.1', severity: 'low', category: 'validation',
        owasp: 'A08:2021',
        description: '`JSON.parse()` sobre input de usuario sin validación de schema posterior puede aceptar estructuras maliciosas (prototype pollution, unexpected types).',
        remediation_steps: 'Valida el resultado de `JSON.parse()` contra un schema: `const data = Schema.parse(JSON.parse(raw))`.',
      }));
    }
  }

  // ── A09: Security Logging and Monitoring Failures ─────────────────────────

  async _checkA09_LoggingMonitoring(allContent, pkgJson) {
    // Sin librería de logging
    const hasLogging = LOGGING_LIBS.some(lib =>
      allContent.includes(`'${lib}'`) || allContent.includes(`"${lib}"`) ||
      pkgJson?.dependencies?.[lib] || pkgJson?.devDependencies?.[lib]
    );
    if (!hasLogging) {
      this.addFinding(new Finding({
        title: 'Sin librería de logging estructurado',
        control_id: 'A09-NOLOG', asvs_id: 'ASVS 7.1.1', severity: 'medium', category: 'logging',
        owasp: 'A09:2021',
        description: 'No se detectó ninguna librería de logging (morgan, winston, pino, bunyan). Sin logging persistente no es posible detectar ni investigar incidentes.',
        remediation_steps: 'Agrega `morgan` para HTTP request logging y `winston` o `pino` para logs estructurados. Configura niveles (error/warn/info) y envío a sistema centralizado.',
      }));
    }

    // console.log con datos sensibles
    if (/console\.(?:log|info|debug)\s*\([^)]*(?:password|passwd|token|secret|apiKey|api_key|Authorization)/im.test(allContent)) {
      this.addFinding(new Finding({
        title: 'console.log() con datos potencialmente sensibles',
        control_id: 'A09-SENSLOG', asvs_id: 'ASVS 7.1.2', severity: 'medium', category: 'logging',
        owasp: 'A09:2021',
        description: 'Se detectaron llamadas a `console.log/info/debug` que incluyen variables de nombres sensibles (password, token, secret, apiKey). Expone credenciales en logs.',
        remediation_steps: 'Nunca loguees credenciales o tokens. Usa una función de sanitización de logs que elimine campos sensibles antes de registrar.',
      }));
    }

    // Sin manejador global de errores que logee eventos de seguridad
    const hasAuthLog = /(?:login|auth|signin).*(?:failed|success|error).*(?:log|warn|error)|(?:log|warn|error).*(?:login|auth|signin)/im.test(allContent);
    if (!hasAuthLog) {
      this.addFinding(new Finding({
        title: 'Sin logging de eventos de autenticación (éxito/fallo)',
        control_id: 'A09-AUTHLOG', asvs_id: 'ASVS 7.2.1', severity: 'medium', category: 'logging',
        owasp: 'A09:2021',
        description: 'No se detectó logging de eventos de autenticación. Los intentos de login fallidos y exitosos deben registrarse para detectar ataques de fuerza bruta y account takeover.',
        remediation_steps: 'Registra cada intento de login con: timestamp, IP, username (nunca password), resultado (éxito/fallo). Alerta tras N fallos consecutivos.',
      }));
    }
  }

  // ── A05: Endpoints sensibles expuestos (DAST) ─────────────────────────────

  async _checkA05_ExposedEndpoints() {
    if (!this.url) return;
    for (const p of SENSITIVE_PATHS) {
      try {
        const res = await fetch(`${this.url}${p}`, {
          signal: AbortSignal.timeout(5000),
          headers: { 'User-Agent': 'SEC-Auditor/1.0' },
          redirect: 'manual',
        });
        if (res.status !== 200) continue;
        const body = await res.text();
        // Solo reportar si el cuerpo contiene indicios de datos sensibles o config
        const isSensitive = /DB_|SECRET|PASSWORD|API_KEY|TOKEN|private_key|BEGIN PRIVATE|ref:\s*refs/i.test(body);
        const isLargeDoc  = body.length > 500 && (/swagger|openapi|paths:/i.test(body));
        if (isSensitive || isLargeDoc) {
          this.addFinding(new Finding({
            title: `Endpoint sensible expuesto: ${p}`,
            control_id: 'A05-EXPOSED', asvs_id: 'ASVS 14.3.3', severity: isSensitive ? 'critical' : 'high',
            category: 'information_disclosure',
            owasp: 'A05:2021',
            description: `El recurso ${p} está accesible públicamente y contiene información sensible (${isSensitive ? 'credenciales/secretos' : 'documentación de API'}).`,
            remediation_steps: `Protege ${p} con autenticación, o elimínalo en producción. Revisa el .gitignore para no publicar archivos de configuración.`,
            evidence_uri: `${this.url}${p}`,
            response: body.substring(0, 300),
          }));
        }
      } catch { /* timeout o network error — ignorar */ }
    }
  }

  // ── Helpers ───────────────────────────────────────────────────────────────

  _readPackageJson() {
    try {
      const raw = this.fs.readFile(path.join(this.rootDir, 'package.json'));
      return raw ? JSON.parse(raw) : null;
    } catch { return null; }
  }

  _findFileWith(files, pattern) {
    const found = files.find(f => pattern.test(this.fs.readFile(f) || ''));
    return found ? path.relative(this.rootDir, found) : null;
  }
}

export default OwaspAnalyzer;
