import { execSync } from 'child_process';
import BaseAnalyzer from './BaseAnalyzer.js';
import { Finding } from '../utils/Finding.js';

const SEV_MAP = { critical: 'critical', high: 'high', moderate: 'medium', low: 'low', info: 'low' };
const LOCKFILES = ['pnpm-lock.yaml', 'package-lock.json', 'yarn.lock'];

class DependencyAnalyzer extends BaseAnalyzer {
  async analyze() {
    if (!this.fs.exists(this.fs.join(this.rootDir, 'package.json'))) {
      this.logger.warn('package.json no encontrado — omitiendo análisis de dependencias');
      return;
    }

    const lockfile = LOCKFILES.find(f => this.fs.exists(this.fs.join(this.rootDir, f)));
    if (!lockfile) {
      this.logger.warn('No se encontró lockfile (pnpm-lock.yaml / package-lock.json / yarn.lock) — omitiendo pnpm audit');
      return;
    }

    this.logger.info(`Ejecutando pnpm audit... (lockfile: ${lockfile})`);
    try {
      const output = execSync('pnpm audit --json 2>/dev/null', {
        cwd: this.rootDir, timeout: 120000, encoding: 'utf8',
      });
      this._parseAudit(JSON.parse(output));
    } catch (e) {
      const output = e.stdout || '';
      if (output) {
        try { this._parseAudit(JSON.parse(output)); } catch {
          this.logger.warn('No se pudo parsear pnpm audit — verifica que las dependencias estén instaladas');
        }
      }
    }
  }

  _parseAudit(audit) {
    const vulns = audit.vulnerabilities || audit.advisories || {};
    let count = 0;
    for (const [name, vuln] of Object.entries(vulns)) {
      const sev = SEV_MAP[vuln.severity] || 'medium';
      const via = vuln.via || [];
      const advisory = via.find(v => typeof v === 'object') || {};
      this.addFinding(new Finding({
        title: `Dependencia vulnerable: ${name}@${vuln.range || 'unknown'}`,
        control_id: 'DEVSECOPS-03', asvs_id: 'ASVS 14.2.1', severity: sev, category: 'dependencies',
        description: advisory.title || vuln.title || `Vulnerabilidad ${sev} en ${name}`,
        remediation_steps: vuln.fixAvailable
          ? `Ejecuta \`pnpm audit --fix\`. Fix disponible: ${name}@${vuln.fixAvailable?.version || 'latest'}`
          : `No hay fix automático. Evalúa reemplazar ${name}. URL: ${advisory.url || ''}`,
        evidence_uri: advisory.url || `npm:${name}`,
      }));
      count++;
    }
    this.logger.info(`pnpm audit: ${count} vulnerabilidad(es) encontrada(s)`);
  }
}

export default DependencyAnalyzer;
