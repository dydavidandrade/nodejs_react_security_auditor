import { execSync, spawnSync } from 'child_process';
import os from 'os';
import { t } from '../utils/i18n.js';

const TOOLS = {
  semgrep: {
    check:        'semgrep --version',
    installMac:   'brew install semgrep',
    installLinux: 'pip3 install semgrep || pip install semgrep',
    dlxPackage:   'semgrep',
    optional:     false,
  },
  gitleaks: {
    check:        'gitleaks version',
    installMac:   'brew install gitleaks',
    installLinux: 'bash -c "curl -sSL https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks_linux_amd64.tar.gz | tar xz -C /usr/local/bin"',
    dlxPackage:   null,
    optional:     false,
  },
  trivy: {
    check:        'trivy --version',
    installMac:   'brew install trivy',
    installLinux: 'bash -c "curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin"',
    dlxPackage:   null,
    optional:     true,
  },
};

class ToolInstaller {
  constructor(logger) {
    this.logger    = logger;
    this.available = {};
    this.commands  = {};
    this.isMac     = os.platform() === 'darwin';
  }

  _exec(cmd) {
    try { execSync(cmd, { stdio: 'ignore', timeout: 10000 }); return true; } catch { return false; }
  }

  _spawn(cmd) {
    return spawnSync('bash', ['-c', cmd], { stdio: 'inherit', timeout: 300000 }).status === 0;
  }

  /** Returns the effective command prefix for a tool (binary or `pnpm dlx <pkg>`). */
  getCmd(name) { return this.commands[name] ?? name; }

  async installAll() {
    this.logger.section(t('installing_tools'));
    this.available.pnpm_audit = true;
    this.commands.pnpm_audit  = 'pnpm audit';

    for (const [name, tool] of Object.entries(TOOLS)) {
      if (this._exec(tool.check)) {
        this.logger.success(t('tool_found', { tool: name }));
        this.available[name] = true;
        this.commands[name]  = name;
        continue;
      }

      if (tool.dlxPackage && this._exec(`pnpm dlx ${tool.dlxPackage} --version`)) {
        this.logger.success(t('tool_found', { tool: `${name} (pnpm dlx)` }));
        this.available[name] = true;
        this.commands[name]  = `pnpm dlx ${tool.dlxPackage}`;
        continue;
      }

      this.logger.info(t('tool_installing', { tool: name }));
      const ok = this._spawn(this.isMac ? tool.installMac : tool.installLinux);

      if (ok && this._exec(tool.check)) {
        this.logger.success(t('tool_installed', { tool: name }));
        this.available[name] = true;
        this.commands[name]  = name;
      } else if (tool.dlxPackage) {
        this.logger.warn(t('tool_failed', { tool: name }) + ' — usando pnpm dlx como fallback');
        this.available[name] = true;
        this.commands[name]  = `pnpm dlx ${tool.dlxPackage}`;
      } else {
        this.logger.warn(t('tool_failed', { tool: name }));
        this.available[name] = false;
      }
    }
  }

  has(tool) { return this.available[tool] === true; }
}

export default ToolInstaller;
