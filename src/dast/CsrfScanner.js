import BaseDastModule from './BaseDastModule.js';
import { Finding } from '../utils/Finding.js';

class CsrfScanner extends BaseDastModule {
  async scan() {
    const mutating = ['/api', ...this.endpoints.filter(e => ['POST', 'PUT', 'DELETE', 'PATCH'].includes(e.method)).map(e => e.path)];
    for (const p of [...new Set(mutating)].slice(0, 20)) {
      await this._testCsrf(p);
    }
    await this._checkSameSite();
  }

  async _testCsrf(path) {
    const res = await this._post(path, { test: 'csrf_probe' }, {
      'Origin': 'https://evil-attacker.com',
      'Referer': 'https://evil-attacker.com/attack.html',
    });
    if (!res) return;
    if (res.status >= 200 && res.status < 400) {
      const body = String(res.data || '');
      if (!/csrf|forbidden|invalid origin|cross.?site/i.test(body)) {
        this.addFinding(new Finding({
          title: `CSRF potencial — origen externo aceptado: ${path}`, control_id: 'FRONTEND-06', asvs_id: 'ASVS 4.2.2', severity: 'high', category: 'csrf', attack_vector: 'csrf',
          description: `POST a ${path} con Origin: evil-attacker.com fue aceptado (HTTP ${res.status}).`,
          remediation_steps: 'Implementa tokens CSRF (csurf para Express). Configura SameSite=Strict en cookies de sesión. Valida el header Origin/Referer en el servidor.',
          evidence_uri: `${this.baseUrl}${path}`,
          request: `POST ${path}\nOrigin: https://evil-attacker.com`, response: `HTTP ${res.status}: ${body.substring(0, 200)}`,
        }));
      }
    }
  }

  async _checkSameSite() {
    const res = await this._get('/');
    if (!res) return;
    for (const cookie of (res.headers['set-cookie'] || [])) {
      const lower = cookie.toLowerCase();
      const name = cookie.split('=')[0];
      if (/session|auth|jwt|token/i.test(name) && !lower.includes('samesite=strict')) {
        this.addFinding(new Finding({
          title: `Cookie de sesión sin SameSite=Strict: ${name}`, control_id: 'AUTH-07', asvs_id: 'ASVS 3.4.3', severity: 'high', category: 'csrf',
          description: `La cookie "${name}" no tiene SameSite=Strict, permitiendo envío en peticiones cross-site.`,
          remediation_steps: 'Agrega SameSite=Strict a todas las cookies de sesión.',
          evidence_uri: `${this.baseUrl}/`, response: `set-cookie: ${cookie.substring(0, 150)}`,
        }));
      }
    }
  }
}

export default CsrfScanner;
