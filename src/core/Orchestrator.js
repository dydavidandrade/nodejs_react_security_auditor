import axios from 'axios';
import path from 'path';
import { t } from '../utils/i18n.js';
import Logger from '../utils/Logger.js';
import FileSystem from '../utils/FileSystem.js';
import Prompt from '../utils/Prompt.js';
import Cleanup from '../utils/Cleanup.js';
import { resetCounter } from '../utils/Finding.js';

import ToolInstaller from './ToolInstaller.js';
import Reporter from './Reporter.js';

import BackendAnalyzer from '../analyzers/BackendAnalyzer.js';
import FrontendAnalyzer from '../analyzers/FrontendAnalyzer.js';
import SastAnalyzer from '../analyzers/SastAnalyzer.js';
import SecretsAnalyzer from '../analyzers/SecretsAnalyzer.js';
import DependencyAnalyzer from '../analyzers/DependencyAnalyzer.js';

import HeadersScanner from '../dast/HeadersScanner.js';
import XssScanner from '../dast/XssScanner.js';
import SqliScanner from '../dast/SqliScanner.js';
import CsrfScanner from '../dast/CsrfScanner.js';
import AuthScanner from '../dast/AuthScanner.js';
import SsrfScanner from '../dast/SsrfScanner.js';
import PathTraversalScanner from '../dast/PathTraversalScanner.js';
import RceScanner from '../dast/RceScanner.js';
import OpenRedirectScanner from '../dast/OpenRedirectScanner.js';
import WebSocketScanner from '../dast/WebSocketScanner.js';
import RateLimitScanner from '../dast/RateLimitScanner.js';
import TlsScanner from '../dast/TlsScanner.js';

class Orchestrator {
  constructor(url, rootDir) {
    this.url     = url;
    this.rootDir = rootDir;
    this.logger  = new Logger();
    this.fs      = new FileSystem(rootDir);
    this.prompt  = new Prompt();
    this.cleanup = new Cleanup(rootDir, this.logger);
    this.allFindings = [];
    this.meta = { url, rootDir, framework: null, frontend: null };
  }

  async run() {
    this.logger.banner(t('banner_title'), t('banner_subtitle'));
    this.logger.warn(t('unauthorized_warning'));

    // Phase 0: Setup
    const lang = await this.prompt.selectLanguage();
    const authConfig = await this.prompt.getAuthConfig();
    const confirmed  = await this.prompt.confirmStart(this.url);

    if (!confirmed) {
      this.logger.warn(t('aborted'));
      process.exit(0);
    }

    resetCounter();
    const installer = new ToolInstaller(this.logger);
    await installer.installAll();

    try {
      // Phase 1: Static Analysis
      await this._runPhase(t('phase_backend'), async () => {
        const analyzer = new BackendAnalyzer(this.rootDir, this.fs, this.logger);
        await analyzer.analyze();
        this.meta.framework = analyzer.framework;
        this._collect(analyzer.getFindings());
      });

      await this._runPhase(t('phase_frontend'), async () => {
        const analyzer = new FrontendAnalyzer(this.rootDir, this.fs, this.logger);
        await analyzer.analyze();
        this.meta.frontend = analyzer.isReact ? `React (${analyzer.libraries.join(', ')})` : null;
        this._collect(analyzer.getFindings());
      });

      await this._runPhase(t('phase_static'), async () => {
        const analyzer = new SastAnalyzer(this.rootDir, this.fs, this.logger, installer);
        await analyzer.analyze();
        this._collect(analyzer.getFindings());
      });

      await this._runPhase(t('phase_secrets'), async () => {
        const analyzer = new SecretsAnalyzer(this.rootDir, this.fs, this.logger, installer);
        await analyzer.analyze();
        this._collect(analyzer.getFindings());
      });

      await this._runPhase(t('phase_deps'), async () => {
        const analyzer = new DependencyAnalyzer(this.rootDir, this.fs, this.logger);
        await analyzer.analyze();
        this._collect(analyzer.getFindings());
      });

      // Phase 2: Discover endpoints for DAST
      const endpoints = await this._discoverEndpoints();

      // Phase 3: Dynamic Analysis (DAST)
      this.logger.section(t('phase_dast'));
      const dastModules = [
        new TlsScanner(this.url, authConfig, this.logger),
        new HeadersScanner(this.url, authConfig, this.logger),
        new XssScanner(this.url, authConfig, this.logger),
        new SqliScanner(this.url, authConfig, this.logger),
        new CsrfScanner(this.url, authConfig, this.logger),
        new AuthScanner(this.url, authConfig, this.logger),
        new SsrfScanner(this.url, authConfig, this.logger),
        new PathTraversalScanner(this.url, authConfig, this.logger),
        new RceScanner(this.url, authConfig, this.logger),
        new OpenRedirectScanner(this.url, authConfig, this.logger),
        new RateLimitScanner(this.url, authConfig, this.logger),
        new WebSocketScanner(this.url, authConfig, this.logger),
      ];

      const dastLabels = {
        TlsScanner:            t('attack_headers'),
        HeadersScanner:        t('attack_headers'),
        XssScanner:            t('attack_xss'),
        SqliScanner:           t('attack_sqli'),
        CsrfScanner:           t('attack_csrf'),
        AuthScanner:           t('attack_auth'),
        SsrfScanner:           t('attack_ssrf'),
        PathTraversalScanner:  t('attack_traversal'),
        RceScanner:            t('attack_rce'),
        OpenRedirectScanner:   t('attack_redirect'),
        RateLimitScanner:      t('attack_headers'),
        WebSocketScanner:      t('attack_ws'),
      };

      for (const mod of dastModules) {
        const label = dastLabels[mod.constructor.name] || mod.getName();
        this.logger.attack(label);
        mod.setEndpoints(endpoints);
        await mod.init();
        try {
          await mod.scan();
        } catch (e) {
          this.logger.debug(`${mod.getName()} error: ${e.message}`);
        }
        this._collect(mod.getFindings());
      }

      // Phase 4: Report
      this.logger.section(t('phase_report'));
      const reporter = new Reporter(this.rootDir, this.fs, this.logger);
      const reportPath = reporter.generate(this.allFindings, this.meta);

      // Phase 5: Cleanup
      this.logger.section(t('phase_cleanup'));
      this.cleanup.run(reportPath);

    } catch (err) {
      this.logger.error(`Audit failed: ${err.message}`);
      this.logger.debug(err.stack);
      this.cleanup.run(null);
      process.exit(1);
    }
  }

  async _runPhase(name, fn) {
    this.logger.section(name);
    try { await fn(); } catch (e) {
      this.logger.warn(`Phase "${name}" error: ${e.message}`);
    }
  }

  _collect(findings) {
    this.allFindings.push(...findings);
  }

  async _discoverEndpoints() {
    const endpoints = [];

    // Extract from source code
    const jsFiles = this.fs.getAllFiles(['.js', '.ts']);
    for (const file of jsFiles) {
      const content = this.fs.readFile(file);
      if (!content) continue;

      // Express routes
      const expressRe = /\.(get|post|put|delete|patch|all)\s*\(\s*['"`]([^'"`]+)['"`]/g;
      let m;
      while ((m = expressRe.exec(content)) !== null) {
        endpoints.push({ path: m[2], method: m[1].toUpperCase(), param: null });
      }

      // NestJS decorators
      const nestRe = /@(Get|Post|Put|Delete|Patch)\s*\(['"`]([^'"`]*)['"`]\)/g;
      while ((m = nestRe.exec(content)) !== null) {
        endpoints.push({ path: m[2] || '/', method: m[1].toUpperCase(), param: null });
      }

      // WebSocket
      if (/socket\.io|ws\.Server|new WebSocket/i.test(content)) {
        endpoints.push({ path: '/ws', method: 'WS', type: 'websocket', param: null });
      }
    }

    // Crawl the target URL for additional endpoints
    try {
      const res = await axios.get(this.url, {
        timeout: 10000,
        headers: { 'User-Agent': 'SEC-Auditor/1.0' },
        validateStatus: () => true,
      });
      const body = String(res.data || '');

      // Extract from HTML/JS links
      const linkRe = /(?:href|src|action)\s*=\s*['"]\/([^'"?#]+)/g;
      let lm;
      while ((lm = linkRe.exec(body)) !== null) {
        endpoints.push({ path: `/${lm[1]}`, method: 'GET', param: null });
      }
    } catch {
      this.logger.debug('Could not crawl target URL for endpoints');
    }

    // Deduplicate
    const seen = new Set();
    return endpoints.filter(e => {
      const key = `${e.method}:${e.path}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    }).slice(0, 100);
  }
}

export default Orchestrator;
