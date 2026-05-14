import BaseDastModule from './BaseDastModule.js';
import { Finding } from '../utils/Finding.js';

class RateLimitScanner extends BaseDastModule {
  async scan() {
    await this._testRateLimit('/api');
    await this._testRateLimit('/api/auth/login');
    for (const ep of this.endpoints.filter(e => e.method === 'POST').slice(0, 5)) {
      await this._testRateLimit(ep.path);
    }
  }

  async _testRateLimit(path) {
    const BURST = 30;
    const start = Date.now();
    const results = await Promise.allSettled(Array.from({ length: BURST }, () => this._get(path)));
    const elapsed = Date.now() - start;
    const statuses = results.filter(r => r.status === 'fulfilled' && r.value).map(r => r.value.status);
    const blocked = statuses.filter(s => s === 429 || s === 503).length;
    const successRate = statuses.filter(s => s >= 200 && s < 400).length / (statuses.length || 1);

    if (blocked === 0 && statuses.length >= 20 && successRate > 0.8) {
      this.addFinding(new Finding({
        title: `Rate limiting ausente: ${path}`, control_id: 'BACKEND-08', asvs_id: 'ASVS 4.2.2', severity: 'high', category: 'rate_limiting', attack_vector: 'rate_limit_bypass',
        description: `${BURST} requests en ${elapsed}ms a ${path} sin bloqueo. Success rate: ${Math.round(successRate * 100)}%.`,
        remediation_steps: 'Implementa rate limiting con express-rate-limit o @nestjs/throttler: 100 req/15min para API general, 5 req/15min para auth.',
        evidence_uri: `${this.baseUrl}${path}`,
        request: `${BURST}x GET ${path} concurrentes`, response: `Statuses: ${[...new Set(statuses)].join(', ')} — ${blocked} bloqueados`,
      }));
    }
  }
}

export default RateLimitScanner;
