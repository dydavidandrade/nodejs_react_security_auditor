import BaseAnalyzer from './BaseAnalyzer.js';
import { Finding } from '../utils/Finding.js';

class FrontendAnalyzer extends BaseAnalyzer {
  constructor(rootDir, fileSystem, logger) {
    super(rootDir, fileSystem, logger);
    this.isReact = false;
    this.libraries = [];
  }

  async analyze() {
    const pkg = this.fs.readJson(this.fs.join(this.rootDir, 'package.json'));
    if (!pkg) return;

    this._detectReactStack(pkg);
    if (!this.isReact) return;

    const files = this.fs.getAllFiles(['.js', '.jsx', '.ts', '.tsx']);
    for (const file of files) {
      const content = this.fs.readFile(file);
      if (!content) continue;
      this._checkDangerouslySetInnerHTML(content, file);
      this._checkEval(content, file);
      this._checkHardcodedApiKeys(content, file);
      this._checkInsecureHttp(content, file);
      this._checkLocalStorageTokens(content, file);
    }

    this._checkCspConfig(pkg);
    this._checkReactVersion(pkg);
  }

  _detectReactStack(pkg) {
    const deps = { ...pkg.dependencies, ...pkg.devDependencies };
    if (deps['react']) {
      this.isReact = true;
      this.logger.info(`Frontend detectado: React ${deps['react']}`);
    }
    const notable = ['next', 'gatsby', 'remix', 'vite', 'zustand', 'redux', 'react-query', 'tanstack'];
    for (const lib of notable) {
      if (deps[lib]) this.libraries.push(`${lib}@${deps[lib]}`);
    }
    if (this.libraries.length) this.logger.info(`Librerías detectadas: ${this.libraries.join(', ')}`);
  }

  _checkDangerouslySetInnerHTML(content, file) {
    if (this._hasPattern(content, 'dangerouslySetInnerHTML') && !this._hasPattern(content, 'DOMPurify|sanitize|xss')) {
      const idx = content.search(/dangerouslySetInnerHTML/);
      const hasUserInput = this._hasPattern(content, 'dangerouslySetInnerHTML[^}]+(?:props|state|param|req|user|input)');
      this.addFinding(new Finding({
        title: 'dangerouslySetInnerHTML sin sanitización — XSS',
        control_id: 'FRONTEND-02', asvs_id: 'ASVS 5.3.3', severity: hasUserInput ? 'critical' : 'high', category: 'xss',
        description: 'Se usa dangerouslySetInnerHTML sin pasar el HTML por un sanitizador, lo que permite XSS.',
        remediation_steps: 'Instala DOMPurify: `npm install dompurify`. Usa siempre: `dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }}`.',
        file: this.fs.relative(file), line: this._lineOf(content, idx), evidence_uri: this.fs.relative(file),
      }));
    }
  }

  _checkEval(content, file) {
    const re = /\beval\s*\(|new\s+Function\s*\(/;
    if (re.test(content)) {
      this.addFinding(new Finding({
        title: 'eval() en código frontend — XSS / RCE potencial',
        control_id: 'FRONTEND-02', asvs_id: 'ASVS 5.2.4', severity: 'critical', category: 'xss',
        description: 'eval() o new Function() en el frontend puede ejecutar código arbitrario inyectado.',
        remediation_steps: 'Elimina eval() y new Function(). Refactoriza usando un mapa de funciones o importaciones dinámicas seguras.',
        file: this.fs.relative(file), line: this._lineOf(content, content.search(re)), evidence_uri: this.fs.relative(file),
      }));
    }
  }

  _checkHardcodedApiKeys(content, file) {
    const re = /(?:apiKey|api_key|apikey|API_KEY)\s*[=:]\s*['"`]([A-Za-z0-9\-_]{20,})['"`]/;
    if (re.test(content)) {
      this.addFinding(new Finding({
        title: 'API key hardcodeada en el frontend',
        control_id: 'CRYPTO-04', asvs_id: 'ASVS 6.4.1', severity: 'critical', category: 'secrets',
        description: 'Credenciales hardcodeadas en código frontend son visibles para cualquier usuario del navegador.',
        remediation_steps: 'Nunca incluyas secretos en el frontend. Las variables REACT_APP_* son públicas. Mueve las llamadas a APIs sensibles al backend.',
        file: this.fs.relative(file), line: this._lineOf(content, content.search(re)), evidence_uri: this.fs.relative(file),
      }));
    }
  }

  _checkInsecureHttp(content, file) {
    const re = /['"`]http:\/\/(?!localhost|127\.0\.0\.1)/;
    if (re.test(content)) {
      this.addFinding(new Finding({
        title: 'Llamada HTTP insegura (no HTTPS)',
        control_id: 'CRYPTO-01', asvs_id: 'ASVS 9.1.1', severity: 'medium', category: 'transport_security',
        description: 'Se encontraron URLs HTTP (no cifradas) en el código frontend hacia servicios externos.',
        remediation_steps: 'Reemplaza todas las URLs http:// por https://. Configura HSTS en el servidor.',
        file: this.fs.relative(file), line: this._lineOf(content, content.search(re)), evidence_uri: this.fs.relative(file),
      }));
    }
  }

  _checkLocalStorageTokens(content, file) {
    const re = /localStorage\.setItem\s*\(\s*['"`][^'"`]*(token|jwt|auth|session|key)[^'"`]*['"`]/i;
    if (re.test(content)) {
      this.addFinding(new Finding({
        title: 'JWT / token de sesión almacenado en localStorage',
        control_id: 'AUTH-07', asvs_id: 'ASVS 3.4.1', severity: 'high', category: 'authentication',
        description: 'Los tokens almacenados en localStorage son accesibles por JavaScript y pueden ser robados via XSS.',
        remediation_steps: 'Almacena tokens en cookies HttpOnly + Secure + SameSite=Strict.',
        file: this.fs.relative(file), line: this._lineOf(content, content.search(re)), evidence_uri: this.fs.relative(file),
      }));
    }
  }

  _checkCspConfig(pkg) {
    const deps = { ...pkg.dependencies, ...pkg.devDependencies };
    if (!deps['helmet'] && !deps['next-safe'] && !deps['vite-plugin-csp']) {
      this.addFinding(new Finding({
        title: 'Content Security Policy (CSP) no configurada',
        control_id: 'FRONTEND-01', asvs_id: 'ASVS 14.4.6', severity: 'critical', category: 'headers',
        description: 'No se detectó configuración de Content Security Policy, lo que facilita ataques XSS.',
        remediation_steps: 'Configura CSP con Helmet. Para React/Next.js usa nonces generados por servidor.',
        evidence_uri: 'package.json',
      }));
    }
  }

  _checkReactVersion(pkg) {
    const deps = { ...pkg.dependencies, ...pkg.devDependencies };
    const version = deps['react'];
    if (!version) return;
    const major = parseInt(version.replace(/[^0-9]/, ''));
    if (!isNaN(major) && major < 16) {
      this.addFinding(new Finding({
        title: `React versión desactualizada: ${version}`,
        control_id: 'DEVSECOPS-03', asvs_id: 'ASVS 14.2.1', severity: 'medium', category: 'dependencies',
        description: `React ${version} tiene vulnerabilidades conocidas y no recibe parches de seguridad.`,
        remediation_steps: 'Actualiza a la última versión estable de React. Ejecuta `npm update react react-dom`.',
        file: 'package.json', evidence_uri: 'package.json',
      }));
    }
  }
}

export default FrontendAnalyzer;
