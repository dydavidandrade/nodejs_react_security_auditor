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
    this.ig = this._buildIgnore();
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

  _isIgnored(fullPath) {
    const rel = path.relative(this.rootDir, fullPath);
    if (!rel || rel.startsWith('..')) return true;
    return this.ig.ignores(rel);
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
