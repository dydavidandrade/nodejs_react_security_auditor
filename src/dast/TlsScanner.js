import https from 'https';
import BaseDastModule from './BaseDastModule.js';
import { Finding } from '../utils/Finding.js';

class TlsScanner extends BaseDastModule {
  async scan() {
    if (!this.baseUrl.startsWith('https')) {
      this.addFinding(new Finding({
        title: 'Aplicación no usa HTTPS', control_id: 'CRYPTO-01', asvs_id: 'ASVS 9.1.1', severity: 'critical', category: 'tls',
        description: 'La URL objetivo usa HTTP en lugar de HTTPS. Todo el tráfico va sin cifrar.',
        remediation_steps: 'Configura un certificado TLS y redirige todo el tráfico HTTP a HTTPS. Agrega HSTS.',
        evidence_uri: this.baseUrl,
      }));
      return;
    }
    await this._checkCertificate();
    await this._checkHsts();
  }

  _checkCertificate() {
    return new Promise(resolve => {
      const url = new URL(this.baseUrl);
      const req = https.request({ hostname: url.hostname, port: url.port || 443, path: '/', method: 'GET', rejectUnauthorized: false }, res => {
        const cert = res.socket?.getPeerCertificate?.();
        if (cert) {
          const daysLeft = Math.floor((new Date(cert.valid_to) - new Date()) / 86400000);
          if (daysLeft < 0) {
            this.addFinding(new Finding({ title: 'Certificado TLS expirado', control_id: 'CRYPTO-01', asvs_id: 'ASVS 9.2.1', severity: 'critical', category: 'tls', description: `Certificado TLS expiró el ${cert.valid_to}.`, remediation_steps: 'Renueva el certificado inmediatamente. Configura renovación automática con Let\'s Encrypt (certbot).', evidence_uri: this.baseUrl }));
          } else if (daysLeft < 30) {
            this.addFinding(new Finding({ title: `Certificado TLS expira en ${daysLeft} días`, control_id: 'CRYPTO-01', asvs_id: 'ASVS 9.2.1', severity: 'medium', category: 'tls', description: `El certificado expira el ${cert.valid_to} (${daysLeft} días).`, remediation_steps: 'Renueva el certificado antes de la expiración.', evidence_uri: this.baseUrl }));
          }
          const cipher = res.socket?.getCipher?.();
          if (cipher && /rc4|des|md5|export|null|anon/i.test(cipher.name)) {
            this.addFinding(new Finding({ title: `Cipher suite débil: ${cipher.name}`, control_id: 'CRYPTO-01', asvs_id: 'ASVS 9.2.3', severity: 'high', category: 'tls', description: `El servidor usa cipher suite inseguro: ${cipher.name}`, remediation_steps: 'Configura solo ciphers modernos (AES-GCM, ChaCha20). Usa Mozilla SSL Config Generator.', evidence_uri: this.baseUrl }));
          }
        }
        resolve();
      });
      req.on('error', () => resolve());
      req.setTimeout(10000, () => { req.destroy(); resolve(); });
      req.end();
    });
  }

  async _checkHsts() {
    const res = await this._get('/');
    if (!res) return;
    const hsts = res.headers['strict-transport-security'];
    if (hsts && !hsts.includes('includeSubDomains')) {
      this.addFinding(new Finding({
        title: 'HSTS sin includeSubDomains', control_id: 'CRYPTO-01', asvs_id: 'ASVS 9.1.2', severity: 'medium', category: 'tls',
        description: 'HSTS configurado sin includeSubDomains, dejando subdominios vulnerables.',
        remediation_steps: 'Agrega includeSubDomains: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
        evidence_uri: this.baseUrl, response: `strict-transport-security: ${hsts}`,
      }));
    }
  }
}

export default TlsScanner;
