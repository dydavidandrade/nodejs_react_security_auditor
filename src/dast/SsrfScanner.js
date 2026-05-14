import BaseDastModule from './BaseDastModule.js';
import { Finding } from '../utils/Finding.js';

const SSRF_TARGETS = [
  { url: 'http://localhost/',                             label: 'localhost' },
  { url: 'http://127.0.0.1/',                             label: '127.0.0.1' },
  { url: 'http://169.254.169.254/latest/meta-data/',      label: 'AWS metadata' },
  { url: 'http://metadata.google.internal/',              label: 'GCP metadata' },
  { url: 'file:///etc/passwd',                            label: 'file:// LFI' },
  { url: 'gopher://localhost:6379/_INFO',                 label: 'gopher:// redis' },
];

const URL_PARAMS = ['url', 'redirect', 'next', 'target', 'dest', 'uri', 'link', 'src', 'load', 'fetch', 'callback', 'webhook'];

class SsrfScanner extends BaseDastModule {
  async scan() {
    for (const param of URL_PARAMS) await this._testParam('/', param);
    for (const ep of this.endpoints.slice(0, 15)) await this._testParam(ep.path, ep.param || 'url');
    for (const p of ['/api/fetch', '/api/proxy', '/proxy', '/api/webhook']) await this._testEndpoint(p);
  }

  async _testParam(path, param) {
    for (const target of SSRF_TARGETS.slice(0, 4)) {
      const res = await this._get(path, { [param]: target.url });
      if (!res) continue;
      if (this._isInternalAccess(String(res.data || ''), target)) {
        this.addFinding(new Finding({
          title: `SSRF detectado vía "${param}": acceso a ${target.label}`, control_id: 'BACKEND-03', asvs_id: 'ASVS 12.6.1', severity: 'critical', category: 'ssrf', attack_vector: 'ssrf',
          description: `El parámetro "${param}" en ${path} permite acceso a recursos internos: ${target.label}`,
          remediation_steps: 'Implementa una allowlist de dominios/IPs permitidos. Deshabilita peticiones a IPs privadas y metadata endpoints de cloud.',
          evidence_uri: `${this.baseUrl}${path}?${param}=${encodeURIComponent(target.url)}`,
          request: `GET ${path}?${param}=${target.url}`, response: String(res.data || '').substring(0, 300),
        }));
        return;
      }
    }
  }

  async _testEndpoint(path) {
    for (const target of SSRF_TARGETS.slice(0, 3)) {
      const res = await this._post(path, { url: target.url });
      if (!res || res.status === 404) continue;
      if (this._isInternalAccess(String(res.data || ''), target)) {
        this.addFinding(new Finding({
          title: `SSRF en endpoint ${path}: acceso a ${target.label}`, control_id: 'BACKEND-03', asvs_id: 'ASVS 12.6.1', severity: 'critical', category: 'ssrf', attack_vector: 'ssrf',
          description: `El endpoint ${path} realiza peticiones a ${target.url} (${target.label}).`,
          remediation_steps: 'Valida y sanitiza todas las URLs antes de realizar peticiones. Implementa egress filtering.',
          evidence_uri: `${this.baseUrl}${path}`,
          request: `POST ${path}\n{"url":"${target.url}"}`, response: String(res.data || '').substring(0, 300),
        }));
        return;
      }
    }
  }

  _isInternalAccess(body, target) {
    if (target.label === 'AWS metadata'  && /ami-id|instance-id|iam/i.test(body)) return true;
    if (target.label === 'GCP metadata'  && /project-id|service-accounts/i.test(body)) return true;
    if (/root:x:0:|localhost|127\.0\.0\.1/.test(body) && body.length > 50) return true;
    if (target.label.includes('redis')   && /redis_version/i.test(body)) return true;
    return false;
  }
}

export default SsrfScanner;
