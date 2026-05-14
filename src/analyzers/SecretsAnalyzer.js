import { execSync } from 'child_process';
import path from 'path';
import BaseAnalyzer from './BaseAnalyzer.js';
import { Finding } from '../utils/Finding.js';

const SECRET_PATTERNS = [
  { name: 'AWS Access Key',       re: /AKIA[0-9A-Z]{16}/g },
  { name: 'AWS Secret Key',       re: /(?:aws.secret|AWS_SECRET)[^=]*=\s*['"`]?([A-Za-z0-9+/]{40})['"`]?/gi },
  { name: 'Private Key',          re: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g },
  { name: 'Google API Key',       re: /AIza[0-9A-Za-z\\-_]{35}/g },
  { name: 'Slack Token',          re: /xox[baprs]-[0-9a-zA-Z\-]{10,48}/g },
  { name: 'GitHub Token',         re: /ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82}/g },
  { name: 'Stripe Key',           re: /sk_live_[0-9a-zA-Z]{24}/g },
  { name: 'OpenAI Key',           re: /sk-[a-zA-Z0-9]{20,}/g },
  { name: 'JWT Secret Hardcoded', re: /jwt\.sign\([^,]+,\s*['"`]([^'"`]{8,})['"`]/g },
  { name: 'DB Password',          re: /(?:DB_PASS|DATABASE_URL|mongodb\+srv):\/\/[^:]+:([^@]+)@/gi },
  { name: 'Generic Secret',       re: /(?:secret|password|passwd|api_key|apikey)\s*[=:]\s*['"`]([^'"`]{12,})['"`]/gi },
];

class SecretsAnalyzer extends BaseAnalyzer {
  constructor(rootDir, fileSystem, logger, toolInstaller) {
    super(rootDir, fileSystem, logger);
    this.tools = toolInstaller;
    this.tmpDir = fileSystem.getTmpDir();
  }

  async analyze() {
    await this._runGitleaks();
    await this._runCustomPatterns();
    await this._scanEnvFiles();
  }

  async _runGitleaks() {
    if (!this.tools.has('gitleaks')) {
      this.logger.warn('Gitleaks no disponible — usando escaneo de patrones personalizado');
      return;
    }

    const outFile = path.join(this.tmpDir, 'gitleaks_report.json');
    try {
      this.logger.info('Ejecutando Gitleaks...');
      const gitleaksCmd = this.tools.getCmd('gitleaks');
      execSync(
        `${gitleaksCmd} detect --source "${this.rootDir}" --report-format json --report-path "${outFile}" --no-git 2>/dev/null`,
        { timeout: 120000, stdio: 'pipe' }
      );
    } catch {
      // gitleaks exits 1 when secrets found
    }

    const results = this.fs.readJson(outFile);
    if (!Array.isArray(results)) return;

    for (const r of results) {
      const filePath = r.File ? path.join(this.rootDir, r.File) : null;
      const isEnvIgnored = filePath && /\.env(\.|$)/.test(path.basename(r.File || ''))
        && this.fs.isGitIgnored(filePath);

      this.addFinding(new Finding({
        title: `[Gitleaks] Secreto detectado: ${r.RuleID || r.Description}`,
        control_id: 'CRYPTO-04', asvs_id: 'ASVS 6.4.1', category: 'secrets',
        severity: isEnvIgnored ? 'low' : 'critical',
        description: isEnvIgnored
          ? `Gitleaks detectó ${r.Description || r.RuleID} en ${r.File} — archivo en .gitignore, no se subirá al repositorio. Buena práctica en desarrollo; migrar a Secret Manager en producción.`
          : `Gitleaks detectó: ${r.Description || r.RuleID}. Commit: ${r.Commit || 'N/A'}`,
        remediation_steps: isEnvIgnored
          ? 'El .env está correctamente ignorado. Para producción usar GCP Secret Manager, AWS Secrets Manager o HashiCorp Vault en lugar de archivos .env.'
          : 'Elimina el secreto del código inmediatamente. Revoca y rota la credencial comprometida. Usa git-filter-repo para limpiar el historial.',
        file: r.File || null, line: r.StartLine || null, evidence_uri: r.File ? `${r.File}:${r.StartLine}` : null,
      }));
    }
    this.logger.info(`Gitleaks: ${results.length} secreto(s) encontrado(s)`);
  }

  async _runCustomPatterns() {
    // Los archivos .env se gestionan en _scanEnvFiles() con lógica de gitignore
    const files = this.fs.getAllFiles(['.js', '.ts', '.jsx', '.tsx', '.json', '.yaml', '.yml', '.config.js']);
    const skipEnvExample = /\.env\.example$|\.env\.sample$/;

    for (const file of files) {
      if (skipEnvExample.test(file)) continue;
      const content = this.fs.readFile(file);
      if (!content) continue;

      for (const { name, re } of SECRET_PATTERNS) {
        re.lastIndex = 0;
        const m = re.exec(content);
        if (m) {
          const line = this._lineOf(content, m.index);
          this.addFinding(new Finding({
            title: `Secreto potencial: ${name}`,
            control_id: 'CRYPTO-04', asvs_id: 'ASVS 6.4.1', severity: 'critical', category: 'secrets',
            description: `Patrón de ${name} detectado en ${this.fs.relative(file)}:${line}`,
            remediation_steps: 'Elimina el secreto del código y del historial de git. Rota la credencial inmediatamente. Usa variables de entorno o Secret Manager.',
            file: this.fs.relative(file), line, evidence_uri: `${this.fs.relative(file)}:${line}`,
          }));
        }
      }
    }
  }

  /**
   * Escanea archivos .env aunque estén en .gitignore.
   * Si el archivo está correctamente ignorado → severidad low (buena práctica).
   * Si NO está en .gitignore → severidad critical (riesgo de exposición).
   */
  async _scanEnvFiles() {
    const envFiles = this.fs.findEnvFiles();
    for (const file of envFiles) {
      const content = this.fs.readFile(file);
      if (!content) continue;

      // Verificar si tiene algún valor con apariencia de secreto (no solo comentarios o variables vacías)
      let hasSecrets = false;
      for (const { re } of SECRET_PATTERNS) {
        re.lastIndex = 0;
        if (re.exec(content)) { hasSecrets = true; break; }
      }
      // También detectar asignaciones KEY=valor típicas de .env con valores no triviales
      if (!hasSecrets && /^[A-Z][A-Z0-9_]+=.{6,}/m.test(content)) hasSecrets = true;

      if (!hasSecrets) continue;

      const relFile = this.fs.relative(file);
      const isIgnored = this.fs.isGitIgnored(file);

      if (isIgnored) {
        this.addFinding(new Finding({
          title: `Archivo .env con secretos — correctamente ignorado en .gitignore`,
          control_id: 'CRYPTO-04', asvs_id: 'ASVS 6.4.1', severity: 'low', category: 'secrets',
          description: `El archivo "${relFile}" contiene variables de entorno con secretos. Está en .gitignore y no se subirá al repositorio — buena práctica para desarrollo local. En producción se recomienda usar un gestor de secretos centralizado.`,
          remediation_steps: 'Continuar usando .env solo en entornos locales/desarrollo. En producción migrar a GCP Secret Manager, AWS Secrets Manager o HashiCorp Vault. Asegurarse de que .env nunca se añada a commits accidentalmente (usar pre-commit hooks).',
          file: relFile, line: null, evidence_uri: relFile,
        }));
      } else {
        this.addFinding(new Finding({
          title: `Archivo .env con secretos NO está en .gitignore — riesgo de exposición`,
          control_id: 'CRYPTO-04', asvs_id: 'ASVS 6.4.1', severity: 'critical', category: 'secrets',
          description: `El archivo "${relFile}" contiene secretos y NO aparece en .gitignore. Existe riesgo real de que las credenciales sean incluidas en un commit y expuestas en el repositorio.`,
          remediation_steps: 'Agrega .env (y variantes como .env.local, .env.production) a .gitignore inmediatamente. Verifica con "git status" que no esté staged. Si ya fue commiteado, usa git-filter-repo para purgar el historial y rota todas las credenciales expuestas.',
          file: relFile, line: null, evidence_uri: relFile,
        }));
      }
    }
  }
}

export default SecretsAnalyzer;
