import BaseDastModule from './BaseDastModule.js';
import { Finding } from '../utils/Finding.js';

const XSS_PAYLOADS = [
  '<script>alert("XSS_PROBE")</script>',
  '"><script>alert("XSS_PROBE")</script>',
  "'><img src=x onerror=alert('XSS_PROBE')>",
  '<svg/onload=alert("XSS_PROBE")>',
  'javascript:alert("XSS_PROBE")',
  '"><details open ontoggle=alert("XSS_PROBE")>',
  '{{7*7}}',
  '${7*7}',
];

const PROBE_MARKER = 'XSS_PROBE';
const SSTI_MARKERS = ['49'];

class XssScanner extends BaseDastModule {
  async scan() {
    const baseParams = ['q', 'search', 'query', 'name', 'input', 'redirect', 'url', 'next', 'page'];
    for (const param of baseParams) {
      await this._testEndpoint('/', param);
    }
    for (const ep of this.endpoints.slice(0, 30)) {
      await this._testEndpoint(ep.path, ep.param || 'q');
      await this._testPostEndpoint(ep.path);
    }
  }

  async _testEndpoint(path, param) {
    for (const payload of XSS_PAYLOADS) {
      const res = await this._get(path, { [param]: payload });
      if (!res) continue;
      const body = String(res.data || '');

      if (SSTI_MARKERS.some(m => body.includes(m)) && !body.includes(payload)) {
        this.addFinding(new Finding({
          title: `SSTI detectado: ${path}?${param}`, control_id: 'BACKEND-04', asvs_id: 'ASVS 5.2.5', severity: 'critical', category: 'injection', attack_vector: 'ssti',
          description: `Server-Side Template Injection: el payload "${payload}" fue evaluado en el servidor.`,
          remediation_steps: 'Nunca renderices templates con input de usuario sin sandboxing. Valida y escapa todos los inputs.',
          evidence_uri: `${this.baseUrl}${path}?${param}=${encodeURIComponent(payload)}`,
          request: `GET ${path}?${param}=${encodeURIComponent(payload)}`, response: body.substring(0, 300),
        }));
        return;
      }

      if (body.includes(PROBE_MARKER) || body.includes(payload)) {
        this.addFinding(new Finding({
          title: `XSS Reflejado detectado: ${path}?${param}`, control_id: 'FRONTEND-02', asvs_id: 'ASVS 5.3.3', severity: 'critical', category: 'xss', attack_vector: 'reflected_xss',
          description: `El parámetro "${param}" en ${path} refleja el payload XSS sin sanitización.`,
          remediation_steps: 'Implementa sanitización con DOMPurify. Configura CSP estricta. En el backend, usa helmet y nunca reflejes input sin escapar.',
          evidence_uri: `${this.baseUrl}${path}?${param}=${encodeURIComponent(payload)}`,
          request: `GET ${path}?${param}=${encodeURIComponent(payload)}`, response: body.substring(0, 300),
        }));
        break;
      }
    }
  }

  async _testPostEndpoint(path) {
    for (const field of ['content', 'message', 'name']) {
      for (const payload of XSS_PAYLOADS.slice(0, 3)) {
        const res = await this._post(path, { [field]: payload });
        if (!res) continue;
        const body = String(res.data || '');
        if (body.includes(PROBE_MARKER) || body.includes(payload)) {
          this.addFinding(new Finding({
            title: `XSS Almacenado potencial: POST ${path}`, control_id: 'FRONTEND-02', asvs_id: 'ASVS 5.3.3', severity: 'critical', category: 'xss', attack_vector: 'stored_xss',
            description: `El campo "${field}" en POST ${path} refleja el payload XSS en la respuesta.`,
            remediation_steps: 'Sanitiza todos los campos con DOMPurify antes de renderizar. Implementa Content-Security-Policy.',
            evidence_uri: `${this.baseUrl}${path}`,
            request: `POST ${path}\nBody: ${JSON.stringify({ [field]: payload })}`, response: body.substring(0, 300),
          }));
          return;
        }
      }
    }
  }
}

export default XssScanner;
