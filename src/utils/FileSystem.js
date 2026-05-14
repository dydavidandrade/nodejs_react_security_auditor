import fs from 'fs';
import path from 'path';
import ignore from 'ignore';

const ALWAYS_IGNORE = [
  'node_modules', '.git', 'dist', 'build', '.next', 'out', 'coverage',
  '.nyc_output', '.cache', 'tmp', '.tmp', '*.min.js', '*.map',
  '*.lock', 'yarn.lock', 'package-lock.json', '.sec_auditor_tmp',
];

class FileSystem {
  constructor(rootDir) {
    this.rootDir = rootDir;
    this.igAlways = this._buildAlwaysIgnore();
    this.ig = this._buildIgnore();
    this.igGit = this._buildGitIgnore();
  }

  /** Construye un matcher solo con las entradas de ALWAYS_IGNORE */
  _buildAlwaysIgnore() {
    const ig = ignore();
    ig.add(ALWAYS_IGNORE);
    return ig;
  }

  _buildIgnore() {
    const ig = ignore();
    ig.add(ALWAYS_IGNORE);
    const gitignorePath = path.join(this.rootDir, '.gitignore');
    if (fs.existsSync(gitignorePath)) {
      ig.add(fs.readFileSync(gitignorePath, 'utf8'));
    }
    return ig;
  }

  /** Construye un matcher solo con las entradas del .gitignore del proyecto */
  _buildGitIgnore() {
    const ig = ignore();
    const gitignorePath = path.join(this.rootDir, '.gitignore');
    if (fs.existsSync(gitignorePath)) {
      ig.add(fs.readFileSync(gitignorePath, 'utf8'));
    }
    return ig;
  }

  _isIgnored(fullPath) {
    const rel = path.relative(this.rootDir, fullPath);
    if (!rel || rel.startsWith('..')) return true;
    return this.ig.ignores(rel);
  }

  /**
   * Indica si un archivo está explícitamente ignorado por el .gitignore del proyecto
   * (no considera ALWAYS_IGNORE, solo lo que el desarrollador puso en .gitignore).
   * @param {string} fullPath - Ruta absoluta del archivo
   * @returns {boolean}
   */
  isGitIgnored(fullPath) {
    const rel = path.relative(this.rootDir, fullPath);
    if (!rel || rel.startsWith('..')) return false;
    try { return this.igGit.ignores(rel); } catch { return false; }
  }

  /**
   * Busca archivos .env en el árbol de directorios, incluyendo los gitignoreados.
   * Excluye solo ALWAYS_IGNORE, .env.example y .env.sample.
   * @returns {string[]} Rutas absolutas de los archivos .env encontrados
   */
  findEnvFiles() {
    const results = [];
    const walk = (dir) => {
      if (!fs.existsSync(dir)) return;
      let entries;
      try { entries = fs.readdirSync(dir); } catch { return; }
      for (const entry of entries) {
        const full = path.join(dir, entry);
        const rel = path.relative(this.rootDir, full);
        if (!rel || rel.startsWith('..')) continue;
        let alwaysIgnored;
        try { alwaysIgnored = this.igAlways.ignores(rel); } catch { alwaysIgnored = false; }
        if (alwaysIgnored) continue;
        let stat;
        try { stat = fs.statSync(full); } catch { continue; }
        if (stat.isDirectory()) {
          walk(full);
        } else if (/^\.env(\.[^/]*)?$/.test(entry) && !/\.(example|sample|test)$/.test(entry)) {
          results.push(full);
        }
      }
    };
    walk(this.rootDir);
    return results;
  }

  getAllFiles(extensions = []) {
    const results = [];
    const walk = (dir) => {
      if (!fs.existsSync(dir)) return;
      let entries;
      try { entries = fs.readdirSync(dir); } catch { return; }
      for (const entry of entries) {
        const full = path.join(dir, entry);
        if (this._isIgnored(full)) continue;
        let stat;
        try { stat = fs.statSync(full); } catch { continue; }
        if (stat.isDirectory()) {
          walk(full);
        } else if (stat.isFile()) {
          const match = extensions.length === 0 || extensions.some(e => entry.endsWith(e));
          if (match) results.push(full);
        }
      }
    };
    walk(this.rootDir);
    return results;
  }

  readFile(filePath) {
    try { return fs.readFileSync(filePath, 'utf8'); } catch { return null; }
  }

  readJson(filePath) {
    const c = this.readFile(filePath);
    if (!c) return null;
    try { return JSON.parse(c); } catch { return null; }
  }

  exists(p) { return fs.existsSync(p); }

  join(...args) { return path.join(...args); }

  relative(p) { return path.relative(this.rootDir, p); }

  writeFile(filePath, content) {
    const dir = path.dirname(filePath);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(filePath, content, 'utf8');
  }

  writeJson(filePath, data) {
    this.writeFile(filePath, JSON.stringify(data, null, 2));
  }

  delete(p) {
    if (!fs.existsSync(p)) return;
    const s = fs.statSync(p);
    if (s.isDirectory()) fs.rmSync(p, { recursive: true, force: true });
    else fs.unlinkSync(p);
  }

  getTmpDir() {
    const d = path.join(this.rootDir, '.sec_auditor_tmp');
    if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
    return d;
  }
}

export default FileSystem;
