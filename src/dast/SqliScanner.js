import BaseDastModule from './BaseDastModule.js';
import { Finding } from '../utils/Finding.js';

const ERROR_PATTERNS = [
  /SQL syntax.*?MySQL/i, /Warning.*?mysql_/i, /MySQLSyntaxErrorException/i,
  /ORA-[0-9]{5}/i, /Microsoft SQL Server/i, /Unclosed quotation mark/i,
  /SQLITE_ERROR/i, /SQLite.*?syntax/i, /PostgreSQL.*?ERROR/i, /PG::SyntaxError/i,
  /division by zero/i, /quoted string not properly terminated/i,
];

const BOOLEAN_PAYLOADS = [
  { true: "1' OR '1'='1", false: "1' OR '1'='2" },
  { true: "1 OR 1=1", false: "1 OR 1=2" },
];

const TIME_PAYLOADS = ["1'; WAITFOR DELAY '0:0:5'--", "1'; SELECT SLEEP(5)--", "1 OR SLEEP(5)"];
const ERROR_PAYLOADS = ["'", "''", "1'", "1\"", "' OR '1'='1", "' OR 1=1--", "1; SELECT 1--"];

class SqliScanner extends BaseDastModule {
  async scan() {
    const testParams = ['id', 'user_id', 'userId', 'q', 'search', 'name', 'email', 'username'];
    for (const param of testParams) await this._testErrorBased('/', param);
    for (const ep of this.endpoints.slice(0, 20)) {
      const p = ep.param || 'id';
      await this._testErrorBased(ep.path, p);
      await this._testTimeBased(ep.path, p);
      await this._testBooleanBased(ep.path, p);
    }
  }

  async _testErrorBased(path, param) {
    for (const payload of ERROR_PAYLOADS) {
      const res = await this._get(path, { [param]: payload });
      if (!res) continue;
      const body = String(res.data || '');
      for (const pattern of ERROR_PATTERNS) {
        if (pattern.test(body)) {
          this.addFinding(new Finding({
            title: `SQL Injection (Error-Based): ${path}?${param}`, control_id: 'BACKEND-02', asvs_id: 'ASVS 5.3.4', severity: 'critical', category: 'sqli', attack_vector: 'sqli_error',
            description: `El parámetro "${param}" genera un error SQL visible: ${body.match(pattern)?.[0]}`,
            remediation_steps: 'Usa SIEMPRE prepared statements o un ORM. Con Knex: `knex("users").where("id", id)`. Con TypeORM: QueryBuilder parametrizado.',
            evidence_uri: `${this.baseUrl}${path}?${param}=${encodeURIComponent(payload)}`,
            request: `GET ${path}?${param}=${encodeURIComponent(payload)}`, response: body.substring(0, 300),
          }));
          return;
        }
      }
    }
  }

  async _testTimeBased(path, param) {
    for (const payload of TIME_PAYLOADS) {
      const start = Date.now();
      const res = await this._get(path, { [param]: payload });
      const elapsed = Date.now() - start;
      if (res && elapsed >= 4500) {
        this.addFinding(new Finding({
          title: `SQL Injection (Time-Based Blind): ${path}?${param}`, control_id: 'BACKEND-02', asvs_id: 'ASVS 5.3.4', severity: 'critical', category: 'sqli', attack_vector: 'sqli_time_blind',
          description: `Retraso de ${elapsed}ms con payload sleep indica SQLi blind en "${param}".`,
          remediation_steps: 'Usa prepared statements. El time-based blind SQLi indica que la query se ejecuta con input sin sanitizar.',
          evidence_uri: `${this.baseUrl}${path}?${param}=${encodeURIComponent(payload)}`, response: `Response time: ${elapsed}ms`,
        }));
        return;
      }
    }
  }

  async _testBooleanBased(path, param) {
    for (const { true: trueP, false: falseP } of BOOLEAN_PAYLOADS) {
      const [resT, resF] = await Promise.all([
        this._get(path, { [param]: trueP }),
        this._get(path, { [param]: falseP }),
      ]);
      if (!resT || !resF) continue;
      const lenT = String(resT.data || '').length;
      const lenF = String(resF.data || '').length;
      if (Math.abs(lenT - lenF) > 50 && resT.status === 200 && resF.status !== 200) {
        this.addFinding(new Finding({
          title: `SQL Injection (Boolean-Based Blind): ${path}?${param}`, control_id: 'BACKEND-02', asvs_id: 'ASVS 5.3.4', severity: 'critical', category: 'sqli', attack_vector: 'sqli_boolean_blind',
          description: `Respuestas diferenciadas con condiciones true/false sugieren SQLi boolean blind en "${param}".`,
          remediation_steps: 'Implementa prepared statements inmediatamente. Revisa todas las queries que usan este parámetro.',
          evidence_uri: `${this.baseUrl}${path}?${param}=${encodeURIComponent(trueP)}`,
          response: `Diff length: true=${lenT} false=${lenF}`,
        }));
        return;
      }
    }
  }
}

export default SqliScanner;
