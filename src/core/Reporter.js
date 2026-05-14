import path from 'path';
import { t } from '../utils/i18n.js';

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };
const SEV_EMOJI = { critical: '🔴', high: '🟠', medium: '🟡', low: '🔵' };

class Reporter {
  constructor(rootDir, fileSystem, logger) {
    this.rootDir = rootDir;
    this.fs = fileSystem;
    this.logger = logger;
  }

  generate(allFindings, meta) {
    const now = new Date();
    const stamp = `${now.getFullYear()}-${String(now.getMonth()+1).padStart(2,'0')}-${String(now.getDate()).padStart(2,'0')}_${String(now.getHours()).padStart(2,'0')}`;
    const reportFile = path.join(this.rootDir, `SEC_REPORT_${stamp}.md`);

    const sorted = [...allFindings].sort((a, b) => (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9));
    const stats = this._calcStats(sorted);

    const md = this._buildMarkdown(sorted, stats, meta, stamp);
    this.fs.writeFile(reportFile, md);

    this._printSummary(stats, reportFile);
    return reportFile;
  }

  _calcStats(findings) {
    const stats = { critical: 0, high: 0, medium: 0, low: 0, total: findings.length };
    for (const f of findings) { if (stats[f.severity] !== undefined) stats[f.severity]++; }
    return stats;
  }

  _buildMarkdown(findings, stats, meta, stamp) {
    const lines = [];
    const h = (level, text) => lines.push(`${'#'.repeat(level)} ${text}\n`);
    const p  = (text) => lines.push(`${text}\n`);
    const hr = () => lines.push('---\n');

    // Header
    h(1, `🔒 ${t('report_title')}`);
    p(`| Campo | Valor |`);
    p(`|-------|-------|`);
    p(`| **${t('report_target')}** | \`${meta.url}\` |`);
    p(`| **${t('report_date')}** | ${stamp.replace('_', ' ')} |`);
    p(`| **Framework detectado** | ${meta.framework || 'N/A'} |`);
    p(`| **Frontend** | ${meta.frontend || 'N/A'} |`);
    p(`| **Directorio analizado** | \`${meta.rootDir}\` |`);
    hr();

    // Executive Summary
    h(2, `📊 ${t('report_summary')}`);
    p(`| Severidad | Cantidad | SLA Respuesta |`);
    p(`|-----------|----------|---------------|`);
    p(`| 🔴 CRÍTICO | **${stats.critical}** | ≤ 4 horas |`);
    p(`| 🟠 ALTO    | **${stats.high}** | ≤ 24 horas |`);
    p(`| 🟡 MEDIO   | **${stats.medium}** | ≤ 7 días |`);
    p(`| 🔵 BAJO    | **${stats.low}** | ≤ 30 días |`);
    p(`| **TOTAL**  | **${stats.total}** | |`);

    if (stats.critical > 0) {
      p(`\n> ⚠️ **ACCIÓN INMEDIATA REQUERIDA**: Se encontraron ${stats.critical} hallazgo(s) crítico(s) que requieren remediación urgente.\n`);
    }
    hr();

    // Group by category
    const categories = [...new Set(findings.map(f => f.category))];
    h(2, `🔍 ${t('report_findings')}`);

    for (const cat of categories) {
      const catFindings = findings.filter(f => f.category === cat);
      if (!catFindings.length) continue;

      h(3, `${this._catLabel(cat)} (${catFindings.length})`);

      for (const f of catFindings) {
        const sev = SEV_EMOJI[f.severity] || '⚪';
        h(4, `${sev} [${f.severity.toUpperCase()}] ${f.id}: ${f.title}`);
        p(`| Campo | Valor |`);
        p(`|-------|-------|`);
        p(`| **Control ID** | \`${f.control_id}\` |`);
        p(`| **ASVS ID** | \`${f.asvs_id}\` |`);
        p(`| **Severidad** | ${f.severity.toUpperCase()} |`);
        if (f.file) p(`| **Archivo** | \`${f.file}${f.line ? `:${f.line}` : ''}\` |`);
        if (f.evidence_uri) p(`| **Evidencia** | \`${f.evidence_uri}\` |`);
        if (f.attack_vector) p(`| **Vector de ataque** | \`${f.attack_vector}\` |`);

        p(`\n**Descripción:**\n${f.description}\n`);
        p(`**Remediación:**\n${f.remediation_steps}\n`);

        if (f.request || f.response) {
          p(`<details><summary>Evidencia técnica</summary>\n`);
          if (f.request) { p('```http'); p(f.request); p('```'); }
          if (f.response) { p('```'); p(f.response); p('```'); }
          p(`</details>\n`);
        }
        hr();
      }
    }

    // ASVS Coverage
    h(2, '📋 Cobertura ASVS');
    const asvsIds = [...new Set(findings.map(f => f.asvs_id).filter(Boolean))].sort();
    p(`Controles con hallazgos: ${asvsIds.join(', ')}\n`);
    hr();

    // Appendix: JSON
    h(2, `📎 ${t('report_appendix')}`);
    p('```json');
    p(JSON.stringify(findings.map(f => f.toJson()), null, 2));
    p('```');

    p(`\n---`);
    p(`*Generado por SEC-Auditor v1.0 — ${new Date().toISOString()}*`);
    p(`*Esta herramienta es solo para uso autorizado. Unauthorized use is prohibited.*`);

    return lines.join('\n');
  }

  _catLabel(cat) {
    const labels = {
      headers:         '🛡️ Cabeceras HTTP',
      xss:             '⚡ XSS',
      sqli:            '💉 SQL Injection',
      csrf:            '🔄 CSRF',
      authentication:  '🔑 Autenticación',
      authorization:   '🚧 Autorización',
      access_control:  '🚧 Control de Acceso',
      ssrf:            '🌐 SSRF',
      path_traversal:  '📁 Path Traversal',
      rce:             '💥 RCE / Inyección de Comandos',
      ssti:            '🔧 SSTI',
      deserialization: '📦 Deserialización',
      secrets:         '🔐 Secretos',
      tls:             '🔒 TLS/HTTPS',
      cookies:         '🍪 Cookies',
      backend:         '⚙️ Backend',
      frontend:        '🖥️ Frontend',
      injection:       '💉 Inyección',
      sast:            '🔬 SAST',
      dependencies:    '📦 Dependencias',
      validation:      '✅ Validación',
      information_disclosure: '📢 Fuga de Información',
      rate_limiting:   '🚦 Rate Limiting',
      transport_security: '🔒 Seguridad de Transporte',
      websocket:       '🔌 WebSocket',
      general:         '📌 General',
    };
    return labels[cat] || cat;
  }

  _printSummary(stats, reportFile) {
    this.logger.section(t('report_generated', { file: path.basename(reportFile) }));
    this.logger.table(
      [
        ['\x1b[31mCRÍTICO\x1b[0m', stats.critical, '≤ 4h'],
        ['\x1b[33mALTO\x1b[0m',     stats.high,     '≤ 24h'],
        ['\x1b[33mMEDIO\x1b[0m',    stats.medium,   '≤ 7d'],
        ['\x1b[36mBAJO\x1b[0m',     stats.low,      '≤ 30d'],
        ['TOTAL',                    stats.total,    ''],
      ],
      ['Severidad', 'Hallazgos', 'SLA']
    );
    this.logger.success(t('report_generated', { file: reportFile }));
  }
}

export default Reporter;
