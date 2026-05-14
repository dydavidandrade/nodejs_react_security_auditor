import BaseDastModule from './BaseDastModule.js';
import { Finding } from '../utils/Finding.js';

const REQUIRED_HEADERS = [
  { name: 'strict-transport-security', title: 'HSTS no configurado', control_id: 'CRYPTO-01', asvs_id: 'ASVS 9.1.2', severity: 'critical', description: 'HTTP Strict-Transport-Security ausente. Los usuarios pueden ser víctimas de ataques MITM y downgrade a HTTP.', remediation: 'Agrega: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' },
  { name: 'content-security-policy', title: 'Content-Security-Policy no configurada', control_id: 'FRONTEND-01', asvs_id: 'ASVS 14.4.6', severity: 'critical', description: 'Sin CSP la aplicación es vulnerable a XSS y data injection attacks.', remediation: 'Configura CSP estricta con Helmet: default-src \'self\'; script-src \'self\' \'nonce-{random}\'; object-src \'none\'.' },
  { name: 'x-frame-options', title: 'X-Frame-Options ausente — Clickjacking', control_id: 'FRONTEND-05', asvs_id: 'ASVS 14.4.3', severity: 'high', description: 'Sin X-Frame-Options la página puede ser embebida en iframes para ataques de clickjacking.', remediation: 'Agrega: X-Frame-Options: DENY. Configurable en Helmet.' },
  { name: 'x-content-type-options', title: 'X-Content-Type-Options ausente', control_id: 'BACKEND-03', asvs_id: 'ASVS 14.4.5', severity: 'medium', description: 'Sin este header el browser puede hacer MIME sniffing, permitiendo XSS con archivos de tipos inesperados.', remediation: 'Agrega: X-Content-Type-Options: nosniff' },
  { name: 'x-xss-protection', title: 'X-XSS-Protection ausente', control_id: 'FRONTEND-02', asvs_id: 'ASVS 14.4.4', severity: 'low', description: 'Header legacy para XSS filter del browser ausente.', remediation: 'Agrega: X-XSS-Protection: 1; mode=block' },
  { name: 'referrer-policy', title: 'Referrer-Policy no configurada', control_id: 'BACKEND-03', asvs_id: 'ASVS 14.4.7', severity: 'low', description: 'Sin Referrer-Policy se puede filtrar información sensible de URLs a sitios terceros.', remediation: 'Agrega: Referrer-Policy: strict-origin-when-cross-origin' },
  { name: 'permissions-policy', title: 'Permissions-Policy no configurada', control_id: 'BACKEND-03', asvs_id: 'ASVS 14.4.9', severity: 'low', description: 'Sin Permissions-Policy las APIs del browser no están restringidas.', remediation: 'Agrega: Permissions-Policy: geolocation=(), microphone=(), camera=()' },
];

const INSECURE_VALUES = [
  { header: 'content-security-policy', badPattern: /unsafe-inline|unsafe-eval/, title: 'CSP permite unsafe-inline o unsafe-eval', control_id: 'FRONTEND-01', asvs_id: 'ASVS 14.4.6', severity: 'high', description: 'CSP con \'unsafe-inline\' o \'unsafe-eval\' neutraliza la protección XSS.', remediation: 'Elimina unsafe-inline y unsafe-eval. Usa nonces para scripts inline.' },
  { header: 'strict-transport-security', minAge: 31536000, title: 'HSTS max-age insuficiente (< 1 año)', control_id: 'CRYPTO-01', asvs_id: 'ASVS 9.1.2', severity: 'medium', description: 'HSTS configurado con duración menor a 1 año.', remediation: 'Establece max-age=31536000 con includeSubDomains y preload.' },
];

class HeadersScanner extends BaseDastModule {
  async scan() {
    const res = await this._get('/');
    if (!res) { this.logger.warn('No se pudo conectar al objetivo para análisis de headers'); return; }

    const headers = res.headers;
    const host = new URL(this.baseUrl).host;

    for (const spec of REQUIRED_HEADERS) {
      if (!headers[spec.name]) {
        this.addFinding(new Finding({
          title: spec.title, control_id: spec.control_id, asvs_id: spec.asvs_id, severity: spec.severity, category: 'headers',
          description: spec.description, remediation_steps: spec.remediation, evidence_uri: `${this.baseUrl}/`,
          request: `GET / HTTP/1.1\nHost: ${host}`, response: `Response missing header: ${spec.name}`,
        }));
      }
    }

    for (const spec of INSECURE_VALUES) {
      const val = headers[spec.header];
      if (!val) continue;
      if (spec.badPattern?.test(val)) {
        this.addFinding(new Finding({ title: spec.title, control_id: spec.control_id, asvs_id: spec.asvs_id, severity: spec.severity, category: 'headers', description: spec.description, remediation_steps: spec.remediation, evidence_uri: `${this.baseUrl}/`, response: `${spec.header}: ${val}` }));
      }
      if (spec.minAge) {
        const m = val.match(/max-age=(\d+)/);
        if (m && parseInt(m[1]) < spec.minAge) {
          this.addFinding(new Finding({ title: spec.title, control_id: spec.control_id, asvs_id: spec.asvs_id, severity: spec.severity, category: 'headers', description: spec.description, remediation_steps: spec.remediation, evidence_uri: `${this.baseUrl}/`, response: `${spec.header}: ${val}` }));
        }
      }
    }

    for (const cookie of (res.headers['set-cookie'] || [])) {
      this._checkCookieSecurity(cookie);
    }

    if (headers['server'] && /apache|nginx|iis|express|node/i.test(headers['server'])) {
      this.addFinding(new Finding({
        title: 'Server header revela tecnología backend', control_id: 'BACKEND-06', asvs_id: 'ASVS 14.3.3', severity: 'low', category: 'information_disclosure',
        description: `Header Server expone: "${headers['server']}", facilitando ataques dirigidos.`,
        remediation_steps: 'Elimina o enmascara el header Server. Con Express: `app.disable(\'x-powered-by\')` y Helmet lo hace automáticamente.',
        evidence_uri: `${this.baseUrl}/`, response: `server: ${headers['server']}`,
      }));
    }
  }

  _checkCookieSecurity(cookie) {
    const lower = cookie.toLowerCase();
    const name = cookie.split('=')[0];
    const issues = [
      { flag: 'HttpOnly', check: 'httponly', sev: 'critical', asvs: 'ASVS 3.4.2', remedy: 'Agrega HttpOnly a todas las cookies de sesión para prevenir acceso JS.' },
      { flag: 'Secure',   check: 'secure',   sev: 'critical', asvs: 'ASVS 3.4.1', remedy: 'Agrega Secure para transmitir cookies solo por HTTPS.' },
      { flag: 'SameSite', check: 'samesite', sev: 'high',     asvs: 'ASVS 3.4.3', remedy: 'Agrega SameSite=Strict o SameSite=Lax para proteger contra CSRF.' },
    ];
    for (const issue of issues) {
      if (!lower.includes(issue.check)) {
        this.addFinding(new Finding({
          title: `Cookie sin flag ${issue.flag}: ${name}`, control_id: 'AUTH-07', asvs_id: issue.asvs, severity: issue.sev, category: 'cookies',
          description: `La cookie "${name}" no tiene el flag ${issue.flag}.`,
          remediation_steps: issue.remedy, evidence_uri: `${this.baseUrl}/`, response: `set-cookie: ${cookie.substring(0, 100)}`,
        }));
      }
    }
  }
}

export default HeadersScanner;
