import axios from 'axios';

const DEFAULT_TIMEOUT = 10000;
const DEFAULT_HEADERS = {
  'User-Agent': 'SEC-Auditor/1.0 (Authorized Security Testing)',
  'Accept': '*/*',
};

class BaseDastModule {
  constructor(baseUrl, authConfig, logger) {
    this.baseUrl = baseUrl.replace(/\/$/, '');
    this.auth = authConfig;
    this.logger = logger;
    this.findings = [];
    this.authHeaders = {};
    this.endpoints = [];
  }

  getName() { return this.constructor.name; }

  setEndpoints(endpoints) { this.endpoints = endpoints; }

  async init() {
    if (this.auth?.enabled && this.auth.type === 'token') {
      this.authHeaders[this.auth.header] = this.auth.value;
    } else if (this.auth?.enabled && this.auth.type === 'login') {
      await this._doLogin();
    }
  }

  async _doLogin() {
    try {
      const url = this.auth.loginUrl.startsWith('http') ? this.auth.loginUrl : `${this.baseUrl}${this.auth.loginUrl}`;
      const res = await this._req('POST', url, {
        data: { username: this.auth.username, password: this.auth.password },
      });
      const token = res?.data?.token || res?.data?.access_token || res?.data?.accessToken;
      if (token) this.authHeaders['Authorization'] = `Bearer ${token}`;
      const cookies = res?.headers?.['set-cookie'];
      if (cookies) this.authHeaders['Cookie'] = cookies.map(c => c.split(';')[0]).join('; ');
    } catch (e) {
      this.logger.warn(`Login failed: ${e.message}`);
    }
  }

  async _req(method, url, opts = {}) {
    try {
      return await axios({
        method, url,
        timeout: DEFAULT_TIMEOUT,
        headers: { ...DEFAULT_HEADERS, ...this.authHeaders, ...(opts.headers || {}) },
        data: opts.data,
        params: opts.params,
        validateStatus: () => true,
        maxRedirects: 0,
        ...opts.extra,
      });
    } catch { return null; }
  }

  async _get(path, params = {}, headers = {}) {
    const url = path.startsWith('http') ? path : `${this.baseUrl}${path}`;
    return this._req('GET', url, { params, headers });
  }

  async _post(path, data = {}, headers = {}) {
    const url = path.startsWith('http') ? path : `${this.baseUrl}${path}`;
    return this._req('POST', url, { data, headers });
  }

  addFinding(finding) {
    this.findings.push(finding);
    this.logger.finding(finding.severity, finding.title);
  }

  getFindings() { return [...this.findings]; }

  async scan() { throw new Error(`${this.getName()}.scan() not implemented`); }

  _isVulnResponse(res, payload) {
    if (!res) return false;
    const body = String(res.data || '');
    return body.includes(payload) || body.includes(payload.replace(/[<>'"]/g, ''));
  }

  _responseSnippet(res, maxLen = 300) {
    if (!res) return null;
    return String(res.data || '').substring(0, maxLen);
  }
}

export default BaseDastModule;
