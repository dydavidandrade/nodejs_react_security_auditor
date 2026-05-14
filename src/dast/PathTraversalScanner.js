import BaseDastModule from './BaseDastModule.js';
import { Finding } from '../utils/Finding.js';

const TRAVERSAL_PAYLOADS = [
  '../../../etc/passwd', '..%2F..%2F..%2Fetc%2Fpasswd',
  '....//....//....//etc/passwd', '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
  '..\\..\\..\\windows\\win.ini', '/etc/passwd', '/proc/self/environ',
];

const FILE_PARAMS = ['file', 'path', 'filename', 'page', 'include', 'template', 'view', 'load', 'doc', 'read'];
const PASSWD_MARKERS = ['root:x:0:', '/bin/bash', '/bin/sh'];
const WIN_MARKERS = ['[extensions]', 'for 16-bit'];

class PathTraversalScanner extends BaseDastModule {
  async scan() {
    for (const param of FILE_PARAMS) await this._testParam('/', param);
    for (const ep of this.endpoints.slice(0, 20)) await this._testParam(ep.path, ep.param || 'file');
    await this._testUrlPath();
  }

  async _testParam(path, param) {
    for (const payload of TRAVERSAL_PAYLOADS) {
      const res = await this._get(path, { [param]: payload });
      if (!res) continue;
      if (this._isTraversalSuccess(String(res.data || ''))) {
        this.addFinding(new Finding({
          title: `Path Traversal (LFI): ${path}?${param}`, control_id: 'BACKEND-04', asvs_id: 'ASVS 12.3.1', severity: 'critical', category: 'path_traversal', attack_vector: 'lfi',
          description: `Lectura de archivos del sistema via "${param}=${payload}" en ${path}.`,
          remediation_steps: 'Nunca uses input del usuario directamente en rutas de archivos. Usa path.resolve() y verifica que el resultado esté dentro del directorio permitido.',
          evidence_uri: `${this.baseUrl}${path}?${param}=${encodeURIComponent(payload)}`,
          request: `GET ${path}?${param}=${encodeURIComponent(payload)}`, response: String(res.data || '').substring(0, 300),
        }));
        return;
      }
    }
  }

  async _testUrlPath() {
    for (const p of ['/../../../etc/passwd', '/static/../../../etc/passwd', '/public/../../etc/passwd']) {
      const res = await this._get(p);
      if (!res) continue;
      if (this._isTraversalSuccess(String(res.data || ''))) {
        this.addFinding(new Finding({
          title: `Path Traversal en URL: ${p}`, control_id: 'BACKEND-04', asvs_id: 'ASVS 12.3.1', severity: 'critical', category: 'path_traversal', attack_vector: 'url_traversal',
          description: `Acceso a archivos del sistema via URL traversal: ${p}`,
          remediation_steps: 'Configura el servidor para canonicalizar las rutas antes de servirlas. Nunca sirvas archivos fuera del directorio público.',
          evidence_uri: `${this.baseUrl}${p}`, response: String(res.data || '').substring(0, 300),
        }));
        return;
      }
    }
  }

  _isTraversalSuccess(body) {
    return PASSWD_MARKERS.some(m => body.includes(m)) || WIN_MARKERS.some(m => body.includes(m));
  }
}

export default PathTraversalScanner;
