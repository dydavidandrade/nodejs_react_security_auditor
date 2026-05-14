import BaseDastModule from './BaseDastModule.js';
import { Finding } from '../utils/Finding.js';

const CMD_PAYLOADS = [
  { payload: '; echo SEC_RCE_PROBE',    marker: 'SEC_RCE_PROBE' },
  { payload: '| echo SEC_RCE_PROBE',    marker: 'SEC_RCE_PROBE' },
  { payload: '`echo SEC_RCE_PROBE`',    marker: 'SEC_RCE_PROBE' },
  { payload: '$(echo SEC_RCE_PROBE)',   marker: 'SEC_RCE_PROBE' },
  { payload: '&& echo SEC_RCE_PROBE',  marker: 'SEC_RCE_PROBE' },
  { payload: '%0a echo SEC_RCE_PROBE', marker: 'SEC_RCE_PROBE' },
];

const TEMPLATE_PAYLOADS = [
  { payload: '{{7*7}}',    marker: '49', type: 'Jinja2/Twig SSTI' },
  { payload: '${7*7}',     marker: '49', type: 'EL/Freemarker SSTI' },
  { payload: '<%= 7*7 %>', marker: '49', type: 'ERB/EJS SSTI' },
];

const CMD_PARAMS = ['cmd', 'exec', 'command', 'run', 'ping', 'host', 'ip', 'query', 'input', 'code'];

class RceScanner extends BaseDastModule {
  async scan() {
    for (const param of CMD_PARAMS) {
      await this._testCmdInjection('/', param);
      await this._testTemplateInjection('/', param);
    }
    for (const ep of this.endpoints.slice(0, 15)) {
      await this._testCmdInjection(ep.path, ep.param || 'input');
      await this._testTemplateInjection(ep.path, ep.param || 'q');
    }
  }

  async _testCmdInjection(path, param) {
    for (const { payload, marker } of CMD_PAYLOADS) {
      for (const [method, reqFn] of [['GET', () => this._get(path, { [param]: `127.0.0.1${payload}` })], ['POST', () => this._post(path, { [param]: `127.0.0.1${payload}` })]]) {
        const res = await reqFn();
        if (res && String(res.data || '').includes(marker)) {
          this.addFinding(new Finding({
            title: `Command Injection (RCE) detectado: ${method} ${path}`, control_id: 'BACKEND-04', asvs_id: 'ASVS 5.2.4', severity: 'critical', category: 'rce', attack_vector: 'command_injection',
            description: `Inyección de comandos OS exitosa en "${param}". Output del comando observado en respuesta.`,
            remediation_steps: 'NUNCA pases input de usuario a exec()/spawn(). Usa `spawn(cmd, args, {shell: false})` con allowlist si es absolutamente necesario.',
            evidence_uri: `${this.baseUrl}${path}`,
            request: `${method} ${path} con ${param}=127.0.0.1${payload}`, response: String(res.data || '').substring(0, 300),
          }));
          return;
        }
      }
    }
  }

  async _testTemplateInjection(path, param) {
    for (const { payload, marker, type } of TEMPLATE_PAYLOADS) {
      const res = await this._get(path, { [param]: payload });
      if (!res) continue;
      const body = String(res.data || '');
      if (body.includes(marker) && !body.includes(payload)) {
        this.addFinding(new Finding({
          title: `SSTI (${type}): ${path}?${param}`, control_id: 'BACKEND-04', asvs_id: 'ASVS 5.2.5', severity: 'critical', category: 'ssti', attack_vector: 'ssti',
          description: `Server-Side Template Injection: "${payload}" fue evaluado → "${marker}". Tipo: ${type}.`,
          remediation_steps: 'Nunca renderices templates con input de usuario sin sandboxing. Valida y escapa todos los inputs antes de pasarlos al template engine.',
          evidence_uri: `${this.baseUrl}${path}?${param}=${encodeURIComponent(payload)}`,
          request: `GET ${path}?${param}=${encodeURIComponent(payload)}`, response: body.substring(0, 300),
        }));
        return;
      }
    }
  }
}

export default RceScanner;
