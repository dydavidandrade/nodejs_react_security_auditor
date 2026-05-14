import path from 'path';
import { t } from '../utils/i18n.js';
import { OWASP_TOP10, mapFindingsToOwasp, owaspStatus } from '../utils/OwaspMapping.js';
import { evaluateSecSpec, PRIORITY_META, STATUS_META } from '../utils/SecSpecMatrix.js';

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
    const h  = (level, text) => lines.push(`${'#'.repeat(level)} ${text}\n`);
    const p  = (text) => lines.push(`${text}\n`);
    const hr = () => lines.push('---\n');

    // ── Cabecera ──────────────────────────────────────────────────────────
    h(1, `🔒 ${t('report_title')}`);
    p(`| Campo | Valor |`);
    p(`|-------|-------|`);
    p(`| **${t('report_target')}** | \`${meta.url}\` |`);
    p(`| **${t('report_date')}** | ${stamp.replace('_', ' ')} |`);
    p(`| **Framework detectado** | ${meta.framework || 'N/A'} |`);
    p(`| **Frontend** | ${meta.frontend || 'N/A'} |`);
    p(`| **Directorio analizado** | \`${meta.rootDir}\` |`);
    hr();

    // ── Resumen ejecutivo ─────────────────────────────────────────────────
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

    // ── Matriz de cumplimiento SEC.spec.md ────────────────────────────────
    lines.push(...this._buildSecSpecSection(findings));
    hr();

    // ── OWASP Top 10 — 2021 ───────────────────────────────────────────────
    lines.push(...this._buildOwaspSection(findings));
    hr();

    // ── Hallazgos por categoría ───────────────────────────────────────────
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
        if (f.owasp) p(`| **OWASP** | \`${f.owasp}\` |`);
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

    // ── Cobertura ASVS ────────────────────────────────────────────────────
    h(2, '📋 Cobertura ASVS');
    const asvsIds = [...new Set(findings.map(f => f.asvs_id).filter(Boolean))].sort();
    p(`Controles con hallazgos: ${asvsIds.join(', ')}\n`);
    hr();

    // ── Apéndice JSON ─────────────────────────────────────────────────────
    h(2, `📎 ${t('report_appendix')}`);
    p('```json');
    p(JSON.stringify(findings.map(f => f.toJson()), null, 2));
    p('```');

    p(`\n---`);
    p(`*Generado por SEC-Auditor v1.2 — ${new Date().toISOString()}*`);
    p(`*Esta herramienta es solo para uso autorizado. Unauthorized use is prohibited.*`);

    return lines.join('\n');
  }

  /**
   * Construye la sección de Matriz de Cumplimiento SEC.spec.md.
   * Incluye resumen ejecutivo gerencial + tabla detallada por cada uno de los 11 dominios.
   */
  _buildSecSpecSection(findings) {
    const lines = [];
    const h  = (level, text) => lines.push(`${'#'.repeat(level)} ${text}\n`);
    const p  = (text) => lines.push(`${text}\n`);
    const hr = () => lines.push('---\n');

    const { sections, stats, scorePercent } = evaluateSecSpec(findings);

    h(2, '📋 Matriz de Cumplimiento — SEC.spec.md');
    p('> Evaluación gerencial de los **11 dominios de seguridad** definidos en la especificación SEC.spec.md.');
    p('> Los controles marcados **⚪ NO EVALUADO** requieren revisión manual por el equipo de seguridad.\n');

    // Resumen de cumplimiento
    const scoreBar = this._scoreBar(scorePercent);
    p(`**Score de cumplimiento automático: ${scorePercent}%** ${scoreBar}`);
    p(`> _Calculado sobre ${stats.evaluable} controles evaluables. ${stats.manual} controles requieren revisión manual._\n`);
    p(`| Estado | Cantidad | Descripción |`);
    p(`|--------|----------|-------------|`);
    p(`| ✅ OK          | **${stats.ok}**      | Control implementado correctamente según análisis automático |`);
    p(`| ⚠️ PARCIAL     | **${stats.parcial}** | Solo hallazgos de severidad media — requiere atención |`);
    p(`| ❌ FALLO       | **${stats.fallo}**   | Hallazgos críticos o altos detectados — acción requerida |`);
    p(`| ⚪ NO EVALUADO | **${stats.manual}**  | Requiere revisión manual o herramientas de infra/cloud |`);
    p('');
    hr();

    // Tabla compacta de resumen por sección (vista gerencial rápida)
    h(3, 'Resumen por dominio');
    p(`| # | Dominio | ✅ OK | ⚠️ PARCIAL | ❌ FALLO | ⚪ NO EVAL. | Estado |`);
    p(`|---|---------|-------|------------|---------|------------|--------|`);
    for (const sec of sections) {
      const ok      = sec.controls.filter(c => c.result.status === 'OK').length;
      const parcial = sec.controls.filter(c => c.result.status === 'PARCIAL').length;
      const fallo   = sec.controls.filter(c => c.result.status === 'FALLO').length;
      const noeval  = sec.controls.filter(c => c.result.status === 'NO_EVALUADO').length;
      const sectionStatus = fallo > 0 ? '❌ FALLO' : parcial > 0 ? '⚠️ PARCIAL' : ok > 0 ? '✅ OK' : '⚪ N/A';
      p(`| ${sec.id} | **${sec.name}** | ${ok} | ${parcial} | ${fallo} | ${noeval} | ${sectionStatus} |`);
    }
    p('');
    hr();

    // Detalle completo por dominio
    h(3, 'Detalle por dominio');
    for (const sec of sections) {
      h(4, `${sec.id}. ${sec.name}`);
      p(`| Control | Prioridad | Estado | Método | Hallazgos |`);
      p(`|---------|-----------|--------|--------|-----------|`);
      for (const ctrl of sec.controls) {
        const prio   = `${PRIORITY_META[ctrl.priority] || ''} ${ctrl.priority}`;
        const status = `${ctrl.result.icon} ${ctrl.result.label}`;
        const count  = ctrl.result.relatedCount > 0 ? ctrl.result.relatedCount : '—';
        p(`| ${ctrl.name} | ${prio} | ${status} | \`${ctrl.method}\` | ${count} |`);
      }
      p('');
    }

    return lines;
  }

  /**
   * Genera una barra visual de progreso ASCII para el score de cumplimiento.
   * @param {number} percent - 0 a 100
   * @returns {string}
   */
  _scoreBar(percent) {
    const filled = Math.round(percent / 10);
    const empty  = 10 - filled;
    const bar    = '█'.repeat(filled) + '░'.repeat(empty);
    const color  = percent >= 70 ? '🟢' : percent >= 40 ? '🟡' : '🔴';
    return `${color} \`[${bar}]\` ${percent}%`;
  }

  /**
   * Construye la sección OWASP Top 10 del reporte.
   * Incluye matriz de cumplimiento y detalle de hallazgos por categoría.
   */
  _buildOwaspSection(findings) {
    const lines = [];
    const h  = (level, text) => lines.push(`${'#'.repeat(level)} ${text}\n`);
    const p  = (text) => lines.push(`${text}\n`);
    const hr = () => lines.push('---\n');

    h(2, '🛡️ OWASP Top 10 — 2021');
    p('> Cobertura basada en análisis estático (SAST) y dinámico (DAST). Estado por categoría según hallazgos detectados.\n');

    const owaspMap   = mapFindingsToOwasp(findings);
    const totalFail  = Object.values(owaspMap).filter(fs => owaspStatus(fs).status === 'FAIL').length;
    const totalPass  = Object.values(owaspMap).filter(fs => owaspStatus(fs).status === 'PASS').length;
    const totalPart  = 10 - totalFail - totalPass;
    const score      = Math.round((totalPass + totalPart * 0.5) / 10 * 100);

    p(`**Puntuación de cumplimiento: ${score}%** — ${totalPass} ✅ aprobados · ${totalPart} ⚠️ parciales · ${totalFail} ❌ fallidos\n`);

    // Matriz de cumplimiento
    p(`| # | Categoría OWASP | Estado | Hallazgos | Máx. Severidad |`);
    p(`|---|-----------------|--------|-----------|----------------|`);
    for (const [id, data] of Object.entries(OWASP_TOP10)) {
      const catFindings = owaspMap[id] || [];
      const { status, icon, maxSeverity } = owaspStatus(catFindings);
      p(`| \`${id}\` | **${data.name}** | ${icon} ${status} | ${catFindings.length} | ${maxSeverity || '—'} |`);
    }
    p('');
    hr();

    // Detalle por categoría OWASP
    h(3, 'Detalle por categoría OWASP');

    for (const [id, data] of Object.entries(OWASP_TOP10)) {
      const catFindings = owaspMap[id] || [];
      const { status, icon } = owaspStatus(catFindings);

      h(4, `${icon} ${id} — ${data.name}`);
      p(`> ${data.description}\n`);
      p(`**Referencia ASVS:** ${data.asvs_ref}\n`);

      if (catFindings.length === 0) {
        p(`✅ No se detectaron hallazgos en esta categoría.\n`);
      } else {
        p(`Se encontraron **${catFindings.length}** hallazgo(s):\n`);
        for (const f of catFindings.slice().sort((a, b) => (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9))) {
          const sev = SEV_EMOJI[f.severity] || '⚪';
          p(`- ${sev} **[${f.severity.toUpperCase()}]** \`${f.id}\` — ${f.title}${f.file ? ` *(${f.file})*` : ''}`);
        }
        p('');
      }
    }

    return lines;
  }

  _catLabel(cat) {
    const labels = {
      headers:              '🛡️ Cabeceras HTTP',
      xss:                  '⚡ XSS',
      sqli:                 '💉 SQL Injection',
      csrf:                 '🔄 CSRF',
      authentication:       '🔑 Autenticación',
      authorization:        '🚧 Autorización',
      access_control:       '🚧 Control de Acceso',
      ssrf:                 '🌐 SSRF',
      path_traversal:       '📁 Path Traversal',
      rce:                  '💥 RCE / Inyección de Comandos',
      ssti:                 '🔧 SSTI',
      deserialization:      '📦 Deserialización',
      secrets:              '🔐 Secretos',
      tls:                  '🔒 TLS/HTTPS',
      cookies:              '🍪 Cookies',
      backend:              '⚙️ Backend',
      frontend:             '🖥️ Frontend',
      injection:            '💉 Inyección',
      sast:                 '🔬 SAST',
      dependencies:         '📦 Dependencias',
      validation:           '✅ Validación',
      information_disclosure: '📢 Fuga de Información',
      rate_limiting:        '🚦 Rate Limiting',
      transport_security:   '🔒 Seguridad de Transporte',
      websocket:            '🔌 WebSocket',
      logging:              '📝 Logging y Monitoreo',
      general:              '📌 General',
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
