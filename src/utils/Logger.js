import chalk from 'chalk';
import Table from 'cli-table3';

const LEVELS = {
  info:     { fn: 'cyan',    label: 'INFO    ' },
  success:  { fn: 'green',   label: 'OK      ' },
  warn:     { fn: 'yellow',  label: 'WARN    ' },
  error:    { fn: 'red',     label: 'ERROR   ' },
  critical: { fn: 'bgRed',   label: 'CRITICAL' },
  debug:    { fn: 'gray',    label: 'DEBUG   ' },
  finding:  { fn: 'magenta', label: 'FINDING ' },
  attack:   { fn: 'blue',    label: 'ATTACK  ' },
};

class Logger {
  constructor(verbose = false) {
    this.verbose = verbose;
  }

  _ts() {
    return chalk.gray(new Date().toTimeString().substring(0, 8));
  }

  _log(level, msg) {
    const { fn, label } = LEVELS[level];
    const colored = fn.startsWith('bg') ? chalk[fn](` ${label} `) : chalk[fn](`[${label}]`);
    console.log(`${this._ts()} ${colored} ${msg}`);
  }

  info(msg)     { this._log('info', msg); }
  success(msg)  { this._log('success', msg); }
  warn(msg)     { this._log('warn', chalk.yellow(msg)); }
  error(msg)    { this._log('error', chalk.red(msg)); }
  critical(msg) { this._log('critical', chalk.red.bold(msg)); }
  debug(msg)    { if (this.verbose) this._log('debug', chalk.gray(msg)); }
  finding(sev, msg) {
    const color = { critical: 'red', high: 'red', medium: 'yellow', low: 'cyan' }[sev] || 'white';
    this._log('finding', `[${chalk[color](sev.toUpperCase())}] ${msg}`);
  }
  attack(msg) { this._log('attack', chalk.blue(msg)); }

  banner(title, subtitle) {
    const W = 64;
    const line = '═'.repeat(W);
    const pad = (s) => {
      const sp = Math.max(0, Math.floor((W - s.length) / 2));
      return ' '.repeat(sp) + s + ' '.repeat(Math.max(0, W - s.length - sp));
    };
    console.log(chalk.cyan(`\n╔${line}╗`));
    console.log(chalk.cyan(`║${pad(title)}║`));
    if (subtitle) console.log(chalk.cyan(`║${pad(subtitle)}║`));
    console.log(chalk.cyan(`╚${line}╝\n`));
  }

  section(text) {
    console.log(chalk.yellow(`\n▶  ${text}`));
    console.log(chalk.yellow('─'.repeat(52)));
  }

  table(rows, headers) {
    const t = new Table({ head: headers.map(h => chalk.cyan(h)), style: { border: ['gray'] } });
    rows.forEach(r => t.push(r));
    console.log(t.toString());
  }
}

export default Logger;
