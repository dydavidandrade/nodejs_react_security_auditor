import WebSocket from 'ws';
import BaseDastModule from './BaseDastModule.js';
import { Finding } from '../utils/Finding.js';

class WebSocketScanner extends BaseDastModule {
  async scan() {
    const wsEndpoints = this.endpoints.filter(e => e.type === 'websocket');
    if (wsEndpoints.length === 0 && !this.baseUrl.includes('ws')) return;

    await this._checkWsProtocol();
    await this._checkWsOrigin();
  }

  async _checkWsProtocol() {
    const wssUrl = this.baseUrl.replace(/^https?/, 'wss');
    const isHttps = this.baseUrl.startsWith('https');

    if (!isHttps) {
      this.addFinding(new Finding({
        title: 'WebSocket sobre WS (no cifrado)', control_id: 'WEBSOCKET-01', asvs_id: 'ASVS 13.1.1', severity: 'critical', category: 'websocket',
        description: 'La aplicación usa WS:// (no cifrado). El tráfico WebSocket es interceptable.',
        remediation_steps: 'Configura TLS en el servidor y usa siempre WSS://.',
        evidence_uri: wssUrl,
      }));
    }

    await this._connectWs(wssUrl, {}, (ws) => {
      ws.send(JSON.stringify({ type: 'message', content: '<script>alert("WS_XSS")</script>' }));
      return new Promise(resolve => {
        ws.once('message', data => {
          const msg = data.toString();
          if (msg.includes('WS_XSS') || msg.includes('<script>')) {
            this.addFinding(new Finding({
              title: 'WebSocket sin autenticación — conexión anónima aceptada', control_id: 'WEBSOCKET-03', asvs_id: 'ASVS 13.1.3', severity: 'high', category: 'websocket', attack_vector: 'ws_unauth',
              description: 'Conexión WebSocket aceptada sin autenticación JWT en el handshake.',
              remediation_steps: 'Valida el token JWT durante el handshake WebSocket. Rechaza conexiones sin token válido.',
              evidence_uri: wssUrl,
            }));
          }
          resolve();
        });
        setTimeout(resolve, 3000);
      });
    });
  }

  async _checkWsOrigin() {
    const wssUrl = this.baseUrl.replace(/^https?/, 'wss');
    await this._connectWs(wssUrl, { headers: { Origin: 'https://evil-attacker.com' } }, () => {
      this.addFinding(new Finding({
        title: 'WebSocket no valida el Origin — conexión cross-origin aceptada', control_id: 'WEBSOCKET-02', asvs_id: 'ASVS 13.1.2', severity: 'critical', category: 'websocket', attack_vector: 'ws_origin',
        description: 'El servidor WebSocket acepta conexiones con Origin externo sin validación.',
        remediation_steps: 'Valida el header Origin en el servidor WebSocket. Rechaza conexiones de orígenes no autorizados.',
        evidence_uri: wssUrl, request: 'WebSocket upgrade con Origin: https://evil-attacker.com',
      }));
      return Promise.resolve();
    });
  }

  _connectWs(url, opts, onOpen) {
    return new Promise(resolve => {
      let ws;
      try {
        ws = new WebSocket(url, { rejectUnauthorized: false, handshakeTimeout: 5000, ...opts });
      } catch { return resolve(); }

      const timer = setTimeout(() => { try { ws.terminate(); } catch {} resolve(); }, 6000);
      ws.on('open', async () => {
        clearTimeout(timer);
        try { await onOpen(ws); } catch {}
        try { ws.close(); } catch {}
        resolve();
      });
      ws.on('error', () => { clearTimeout(timer); resolve(); });
    });
  }
}

export default WebSocketScanner;
