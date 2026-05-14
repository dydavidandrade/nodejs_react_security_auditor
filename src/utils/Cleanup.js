import fs from 'fs';
import path from 'path';
import { t } from './i18n.js';

class Cleanup {
  constructor(rootDir, logger) {
    this.rootDir = rootDir;
    this.logger = logger;
    this.tracked = new Set();
  }

  track(p) { this.tracked.add(p); }

  trackTmpDir() { this.track(path.join(this.rootDir, '.sec_auditor_tmp')); }

  run(keepReportPath) {
    this.trackTmpDir();
    for (const p of this.tracked) {
      if (keepReportPath && path.resolve(p) === path.resolve(keepReportPath)) continue;
      this._delete(p);
    }
    const stray = ['semgrep_results.json', 'gitleaks_report.json', 'npm_audit.json', 'trivy_results.json'];
    for (const f of stray) {
      const full = path.join(this.rootDir, f);
      if (fs.existsSync(full)) fs.unlinkSync(full);
    }
    this.logger.success(t('cleanup_done'));
  }

  _delete(p) {
    if (!fs.existsSync(p)) return;
    try {
      const stat = fs.statSync(p);
      if (stat.isDirectory()) fs.rmSync(p, { recursive: true, force: true });
      else fs.unlinkSync(p);
      this.logger.debug(`Deleted: ${p}`);
    } catch (e) {
      this.logger.debug(`Could not delete ${p}: ${e.message}`);
    }
  }
}

export default Cleanup;
