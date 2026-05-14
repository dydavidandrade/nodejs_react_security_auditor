import { execSync } from 'child_process';
import path from 'path';
import BaseAnalyzer from './BaseAnalyzer.js';
import { Finding } from '../utils/Finding.js';

const SEMGREP_RULESETS = ['p/nodejs', 'p/react', 'p/javascript', 'p/owasp-top-ten', 'p/jwt'];
const SEV_MAP = { ERROR: 'critical', WARNING: 'high', INFO: 'medium' };

class SastAnalyzer extends BaseAnalyzer {
  constructor(rootDir, fileSystem, logger, toolInstaller) {
    super(rootDir, fileSystem, logger);
    this.tools = toolInstaller;
    this.tmpDir = fileSystem.getTmpDir();
  }

  async analyze() {
    if (!this.tools.has('semgrep')) {
      this.logger.warn('Semgrep no disponible — omitiendo SAST');
      return;
    }

    const outFile = path.join(this.tmpDir, 'semgrep_results.json');
    const rules = SEMGREP_RULESETS.join(' --config ');

    try {
      this.logger.info('Ejecutando Semgrep...');
      const semgrepCmd = this.tools.getCmd('semgrep');
      execSync(
        `${semgrepCmd} --config ${rules} --json --output "${outFile}" --no-git-ignore "${this.rootDir}" 2>/dev/null`,
        { timeout: 300000, stdio: 'pipe' }
      );
    } catch {
      // semgrep exits 1 when findings exist — normal
    }

    const result = this.fs.readJson(outFile);
    if (!result?.results) return;

    for (const r of result.results) {
      const sev = SEV_MAP[r.extra?.severity] || 'medium';
      this.addFinding(new Finding({
        title: `[SAST] ${r.check_id}: ${r.extra?.message?.substring(0, 80) || r.check_id}`,
        control_id: 'SAST-01', asvs_id: this._mapAsvs(r.check_id), severity: sev, category: 'sast',
        description: r.extra?.message || r.check_id,
        remediation_steps: r.extra?.fix_message || r.extra?.metadata?.references?.[0] || 'Revisa la documentación de seguridad de Node.js/React y aplica las prácticas recomendadas.',
        file: this.fs.relative(r.path), line: r.start?.line, evidence_uri: `${this.fs.relative(r.path)}:${r.start?.line}`,
      }));
    }
    this.logger.info(`Semgrep: ${result.results.length} hallazgo(s) encontrado(s)`);
  }

  _mapAsvs(ruleId) {
    if (!ruleId) return 'ASVS 5.1.1';
    if (/xss/i.test(ruleId))           return 'ASVS 5.3.3';
    if (/sqli|injection/i.test(ruleId)) return 'ASVS 5.3.4';
    if (/jwt|auth/i.test(ruleId))      return 'ASVS 3.5.1';
    if (/eval|exec/i.test(ruleId))     return 'ASVS 5.2.4';
    if (/secret|key|password/i.test(ruleId)) return 'ASVS 6.4.1';
    return 'ASVS 5.1.1';
  }
}

export default SastAnalyzer;
