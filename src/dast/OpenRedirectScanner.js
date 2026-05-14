import BaseDastModule from './BaseDastModule.js';
import { Finding } from '../utils/Finding.js';

const PAYLOADS = [
  'https://evil-attacker.com',
  '//evil-attacker.com',
  '/\\evil-attacker.com',
  '%2F%2Fevil-attacker.com',
];

const REDIRECT_PARAMS = ['redirect', 'redirect_uri', 'next', 'url', 'return', 'returnUrl', 'goto', 'continue', 'dest', 'redir', 'back'];

class OpenRedirectScanner extends BaseDastModule {
  async scan() {
    for (const param of REDIRECT_PARAMS) {
      for (const payload of PAYLOADS.slice(0, 2)) {
        await this._testRedirect('/', param, payload);
      }
    }
    for (const ep of this.endpoints.slice(0, 15)) {
      await this._testRedirect(ep.path, 'redirect', PAYLOADS[0]);
    }
  }

  async _testRedirect(path, param, payload) {
    const res = await this._get(path, { [param]: payload });
    if (!res) return;
    const location = res.headers['location'] || '';
    if ([301, 302, 303, 307, 308].includes(res.status) && (location.includes('evil-attacker.com') || location === payload)) {
      this.addFinding(new Finding({
        title: `Open Redirect: ${path}?${param}`, control_id: 'BACKEND-06', asvs_id: 'ASVS 5.1.5', severity: 'medium', category: 'open_redirect', attack_vector: 'open_redirect',
        description: `El parámetro "${param}" en ${path} redirige a dominios externos sin validación. Location: ${location}`,
        remediation_steps: 'Valida que las URLs de redirección sean relativas o pertenezcan a tu allowlist. Implementa: `if (!isAllowedRedirect(url)) url = "/";`.',
        evidence_uri: `${this.baseUrl}${path}?${param}=${encodeURIComponent(payload)}`,
        request: `GET ${path}?${param}=${encodeURIComponent(payload)}`, response: `HTTP ${res.status} Location: ${location}`,
      }));
    }
  }
}

export default OpenRedirectScanner;
