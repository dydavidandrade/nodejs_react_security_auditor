import { createHmac } from 'crypto';
import BaseDastModule from './BaseDastModule.js';
import { Finding } from '../utils/Finding.js';

const DEFAULT_CREDS = [
  { u: 'admin', p: 'admin' }, { u: 'admin', p: 'password' }, { u: 'admin', p: '123456' },
  { u: 'root', p: 'root' }, { u: 'test', p: 'test' }, { u: 'demo', p: 'demo' },
  { u: 'admin@admin.com', p: 'admin' },
];

const LOGIN_PATHS = ['/api/auth/login', '/api/login', '/auth/login', '/login', '/api/users/login', '/api/session', '/api/signin'];
const WEAK_JWT_SECRETS = ['secret', 'password', '123456', 'jwt', 'token', 'key', 'change_me', 'your-secret'];

class AuthScanner extends BaseDastModule {
  async scan() {
    const loginPath = await this._findLoginEndpoint();
    if (loginPath) {
      await this._testDefaultCreds(loginPath);
      await this._testBruteForceProtection(loginPath);
      await this._testUserEnumeration(loginPath);
    }
    await this._testJwtManipulation();
    await this._testDirectObjectReference();
    await this._checkAdminPaths();
  }

  async _findLoginEndpoint() {
    for (const path of LOGIN_PATHS) {
      const res = await this._post(path, { username: 'test', password: 'test' });
      if (res && res.status !== 404) return path;
    }
    return this.endpoints.find(e => /login|signin|auth|session/.test(e.path))?.path || null;
  }

  async _testDefaultCreds(loginPath) {
    for (const { u, p } of DEFAULT_CREDS) {
      const res = await this._post(loginPath, { username: u, password: p, email: u });
      if (!res) continue;
      const body = String(res.data || '');
      if ((res.status === 200 || res.status === 201) && (body.includes('token') || body.includes('success'))) {
        this.addFinding(new Finding({
          title: `Credenciales por defecto aceptadas: ${u} / ${p}`, control_id: 'AUTH-03', asvs_id: 'ASVS 2.1.5', severity: 'critical', category: 'authentication', attack_vector: 'default_credentials',
          description: `Login exitoso con credenciales por defecto: ${u} / ${p}.`,
          remediation_steps: 'Cambia inmediatamente las contraseñas por defecto. Implementa política de contraseñas mínimas (12+ chars). Fuerza cambio de contraseña en primer login.',
          evidence_uri: `${this.baseUrl}${loginPath}`,
          request: `POST ${loginPath}\n{"username":"${u}","password":"${p}"}`, response: body.substring(0, 200),
        }));
      }
    }
  }

  async _testBruteForceProtection(loginPath) {
    const attempts = [];
    let blocked = false;
    for (let i = 0; i < 10; i++) {
      const res = await this._post(loginPath, { username: 'admin', password: `wrong_pass_${i}` });
      if (!res) break;
      attempts.push(res.status);
      if (res.status === 429 || res.status === 423 || /locked|blocked|too many/i.test(String(res.data || ''))) { blocked = true; break; }
    }
    if (!blocked && attempts.length >= 10) {
      this.addFinding(new Finding({
        title: 'Sin protección contra fuerza bruta en login', control_id: 'AUTH-06', asvs_id: 'ASVS 2.2.1', severity: 'high', category: 'authentication', attack_vector: 'brute_force',
        description: `${attempts.length} intentos de login sin bloqueo (statuses: ${attempts.join(',')}).`,
        remediation_steps: 'Implementa rate limiting: máximo 5 intentos fallidos por IP en 15 minutos. Usa express-rate-limit o @nestjs/throttler. Implementa captcha después de 3 intentos.',
        evidence_uri: `${this.baseUrl}${loginPath}`, response: `Statuses: ${attempts.join(', ')} — sin bloqueo`,
      }));
    }
  }

  async _testUserEnumeration(loginPath) {
    const [resExist, resNoExist] = await Promise.all([
      this._post(loginPath, { username: 'admin', password: 'definitely_wrong_pass_xyz' }),
      this._post(loginPath, { username: 'nonexistent_user_xyz_99', password: 'definitely_wrong_pass_xyz' }),
    ]);
    if (!resExist || !resNoExist) return;
    const bodyE = String(resExist.data || '').toLowerCase();
    const bodyN = String(resNoExist.data || '').toLowerCase();
    const enumerable = resExist.status !== resNoExist.status ||
      (bodyE.includes('password') && bodyN.includes('user')) ||
      (bodyE.includes('incorrect') && bodyN.includes('not found'));
    if (enumerable) {
      this.addFinding(new Finding({
        title: 'User enumeration posible en endpoint de login', control_id: 'AUTH-01', asvs_id: 'ASVS 2.7.6', severity: 'medium', category: 'authentication', attack_vector: 'user_enumeration',
        description: 'Respuestas diferentes para usuario existente vs no existente permiten enumerar usuarios válidos.',
        remediation_steps: 'Retorna siempre el mismo mensaje: "Credenciales inválidas". Usa el mismo tiempo de respuesta para ambos casos.',
        evidence_uri: `${this.baseUrl}${loginPath}`,
        response: `Existing: "${bodyE.substring(0, 100)}" vs Non-existing: "${bodyN.substring(0, 100)}"`,
      }));
    }
  }

  async _testJwtManipulation() {
    const token = this.authHeaders['Authorization']?.replace('Bearer ', '');
    if (!token) return;
    const parts = token.split('.');
    if (parts.length !== 3) return;

    try {
      const header  = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
      const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
      payload.role = 'admin'; payload.isAdmin = true; delete payload.exp;

      // alg:none attack
      const noneHeader = Buffer.from(JSON.stringify({ ...header, alg: 'none' })).toString('base64url');
      const modPayload = Buffer.from(JSON.stringify(payload)).toString('base64url');
      const noneToken  = `${noneHeader}.${modPayload}.`;
      const noneRes    = await this._get('/api/admin', {}, { 'Authorization': `Bearer ${noneToken}` });
      if (noneRes && noneRes.status !== 401 && noneRes.status !== 403) {
        this.addFinding(new Finding({
          title: 'JWT acepta algoritmo "none" — Privilege Escalation', control_id: 'AUTH-04', asvs_id: 'ASVS 3.5.3', severity: 'critical', category: 'authentication', attack_vector: 'jwt_alg_none',
          description: 'El servidor acepta tokens JWT con alg:none sin firma, permitiendo bypass de autenticación.',
          remediation_steps: 'Configura jwt.verify() con algoritmos explícitos: `{ algorithms: ["HS256"] }`. Nunca permitas alg:none.',
          evidence_uri: `${this.baseUrl}/api/admin`, response: `HTTP ${noneRes.status}`,
        }));
      }

      // Weak secret brute force
      for (const secret of WEAK_JWT_SECRETS) {
        const newH = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
        const newP = Buffer.from(JSON.stringify({ ...payload, role: 'admin' })).toString('base64url');
        const sig  = createHmac('sha256', secret).update(`${newH}.${newP}`).digest('base64url');
        const forged = `${newH}.${newP}.${sig}`;
        const forgedRes = await this._get('/api/me', {}, { 'Authorization': `Bearer ${forged}` });
        if (forgedRes?.status === 200) {
          this.addFinding(new Finding({
            title: `JWT secreto débil adivinado: "${secret}"`, control_id: 'AUTH-04', asvs_id: 'ASVS 3.5.3', severity: 'critical', category: 'authentication', attack_vector: 'jwt_weak_secret',
            description: `El secreto JWT es débil y fue adivinado: "${secret}". Permite forjar tokens arbitrarios.`,
            remediation_steps: 'Usa un secreto de mínimo 256 bits aleatorios: `openssl rand -hex 32`. Almacénalo en variables de entorno.',
            evidence_uri: `${this.baseUrl}/api/me`,
          }));
          break;
        }
      }
    } catch (e) {
      this.logger.debug(`JWT manipulation test error: ${e.message}`);
    }
  }

  async _testDirectObjectReference() {
    for (const p of ['/api/users/1', '/api/user/1', '/api/profile/1', '/api/account/1']) {
      const res = await this._get(p);
      if (!res || res.status !== 200) continue;
      const res2 = await this._get(p.replace('/1', '/2'));
      if (res2?.status === 200) {
        this.addFinding(new Finding({
          title: `IDOR (Insecure Direct Object Reference): ${p}`, control_id: 'AUTH-01', asvs_id: 'ASVS 4.2.1', severity: 'high', category: 'access_control', attack_vector: 'idor',
          description: `Acceso sin autorización a recursos de otros usuarios: ${p.replace('/1', '/2')} retornó HTTP 200.`,
          remediation_steps: 'Implementa autorización a nivel de objeto (ABAC). Verifica que el usuario sea el propietario del recurso. Usa UUIDs no secuenciales.',
          evidence_uri: `${this.baseUrl}${p.replace('/1', '/2')}`,
        }));
        break;
      }
    }
  }

  async _checkAdminPaths() {
    const adminPaths = ['/admin', '/admin/dashboard', '/api/admin', '/admin/users', '/_debug', '/.env'];
    for (const p of adminPaths) {
      const res = await this._get(p, {}, { 'X-Forwarded-For': '127.0.0.1' });
      if (res?.status === 200) {
        this.addFinding(new Finding({
          title: `Ruta de administración accesible: ${p}`, control_id: 'AUTH-01', asvs_id: 'ASVS 4.1.3', severity: 'critical', category: 'access_control', attack_vector: 'unprotected_admin',
          description: `La ruta ${p} es accesible sin autenticación apropiada.`,
          remediation_steps: 'Protege todas las rutas de administración con autenticación y autorización de roles.',
          evidence_uri: `${this.baseUrl}${p}`, response: `HTTP ${res.status}`,
        }));
      }
    }
  }
}

export default AuthScanner;