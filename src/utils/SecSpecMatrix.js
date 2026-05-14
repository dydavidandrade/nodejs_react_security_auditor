/**
 * Matriz de cumplimiento SEC.spec.md — los 11 dominios de seguridad.
 * Cada control define cómo detectar su estado a partir de los findings
 * generados por los analizadores SAST y escáneres DAST.
 *
 * Métodos de evaluación:
 *   SAST       — análisis estático del código fuente
 *   DAST       — análisis dinámico sobre la URL objetivo
 *   SAST+DAST  — ambos
 *   MANUAL     — requiere revisión humana; siempre NO_EVALUADO
 *
 * Lógica de estado (severity threshold):
 *   FALLO       → hay hallazgos critical o high relacionados
 *   PARCIAL     → solo hallazgos medium relacionados
 *   OK          → no hay hallazgos en las categorías/controlIds mapeados
 *   NO_EVALUADO → método MANUAL o sin escáner que cubra el control
 */

/**
 * @typedef {Object} SecControl
 * @property {string}   name         - Nombre del control según SEC.spec.md
 * @property {string}   priority     - Crítica | Alta | Media | Baja
 * @property {string}   method       - SAST | DAST | SAST+DAST | MANUAL
 * @property {string[]} categories   - Categorías de findings relacionadas
 * @property {string[]} controlIds   - Prefijos de control_id relacionados
 */

/** @type {{ id: number, name: string, controls: SecControl[] }[]} */
export const SEC_SPEC_SECTIONS = [
  // ── 1. Gobierno y Arquitectura ──────────────────────────────────────────
  {
    id: 1,
    name: 'Gobierno y Arquitectura',
    controls: [
      { name: 'Inventario de activos automatizado',     priority: 'Alta',   method: 'MANUAL',    categories: [], controlIds: [] },
      { name: 'Clasificación de datos PII',             priority: 'Alta',   method: 'MANUAL',    categories: [], controlIds: [] },
      { name: 'Modelo de amenazas continuo (STRIDE)',   priority: 'Alta',   method: 'MANUAL',    categories: [], controlIds: [] },
      { name: 'Segregación de ambientes',               priority: 'Alta',   method: 'MANUAL',    categories: [], controlIds: [] },
      { name: 'Trazabilidad cambios arquitectura',      priority: 'Media',  method: 'MANUAL',    categories: [], controlIds: [] },
    ],
  },

  // ── 2. Autenticación y Gestión de Sesiones ──────────────────────────────
  {
    id: 2,
    name: 'Autenticación y Gestión de Sesiones',
    controls: [
      { name: 'MFA para administradores (WebAuthn/TOTP)', priority: 'Crítica', method: 'MANUAL',    categories: [], controlIds: [] },
      { name: 'Hashing de contraseñas (bcrypt/argon2id)', priority: 'Crítica', method: 'SAST',      categories: [], controlIds: ['A02-HASH'] },
      { name: 'Política de contraseñas (min 12 chars)',   priority: 'Alta',    method: 'SAST',      categories: ['authentication', 'validation'], controlIds: ['AUTH-03'] },
      { name: 'JWT seguros — exp corto + blacklist',       priority: 'Crítica', method: 'SAST+DAST', categories: ['authentication'], controlIds: ['A07-JWT-EXP'] },
      { name: 'Invalidación de sesiones (logout efectivo)',priority: 'Alta',   method: 'SAST',      categories: ['authentication', 'cookies'], controlIds: ['AUTH-05'] },
      { name: 'Protección brute force (rate limit login)', priority: 'Alta',   method: 'DAST',      categories: ['rate_limiting'], controlIds: [] },
      { name: 'Cookies seguras (HttpOnly/Secure/SameSite)',priority: 'Crítica', method: 'DAST',      categories: ['cookies'], controlIds: [] },
      { name: 'Session rotation tras autenticación',       priority: 'Alta',   method: 'MANUAL',    categories: [], controlIds: [] },
    ],
  },

  // ── 3. Seguridad Frontend React ──────────────────────────────────────────
  {
    id: 3,
    name: 'Seguridad Frontend React',
    controls: [
      { name: 'CSP estricta con nonces/hashes',          priority: 'Crítica', method: 'DAST',      categories: ['headers'], controlIds: ['A05-HELMET'] },
      { name: 'Protección XSS (React escaping + sanit.)', priority: 'Crítica', method: 'SAST+DAST', categories: ['xss', 'frontend'], controlIds: [] },
      { name: 'SRI para assets externos',                 priority: 'Media',   method: 'SAST',      categories: ['frontend'], controlIds: [] },
      { name: 'Sin inline scripts (CSP nonce/hash)',       priority: 'Alta',    method: 'SAST',      categories: ['frontend'], controlIds: [] },
      { name: 'Clickjacking (X-Frame-Options DENY)',       priority: 'Alta',    method: 'DAST',      categories: ['headers'], controlIds: [] },
      { name: 'CSRF protection (tokens + SameSite)',       priority: 'Alta',    method: 'SAST+DAST', categories: ['csrf'], controlIds: ['A04-CSRF'] },
      { name: 'Validación frontend (Zod/Yup)',             priority: 'Media',   method: 'SAST',      categories: ['validation'], controlIds: ['A04-VALIDATION'] },
    ],
  },

  // ── 4. Seguridad Backend y API ───────────────────────────────────────────
  {
    id: 4,
    name: 'Seguridad Backend y API',
    controls: [
      { name: 'Validación server-side (DTO/schema)',      priority: 'Crítica', method: 'SAST',      categories: ['validation'], controlIds: ['A04-VALIDATION'] },
      { name: 'SQL parametrizado (ORM / prepared stmt)',  priority: 'Crítica', method: 'SAST+DAST', categories: ['sqli', 'injection'], controlIds: [] },
      { name: 'Protección SSRF (outbound allowlist)',     priority: 'Alta',    method: 'DAST',      categories: ['ssrf'], controlIds: [] },
      { name: 'Prevención RCE (no eval / exec)',          priority: 'Crítica', method: 'SAST+DAST', categories: ['rce', 'ssti', 'deserialization'], controlIds: ['A08-FUNC', 'A08-DESERIAL'] },
      { name: 'Sanitización centralizada de inputs',      priority: 'Crítica', method: 'SAST',      categories: ['injection', 'validation'], controlIds: [] },
      { name: 'Manejo seguro de errores (sin stacktrace)',priority: 'Alta',    method: 'SAST+DAST', categories: ['information_disclosure'], controlIds: ['A05-DEBUG'] },
      { name: 'API Gateway y WAF',                        priority: 'Alta',    method: 'MANUAL',    categories: [], controlIds: [] },
      { name: 'Rate limiting API (token bucket)',          priority: 'Alta',    method: 'DAST',      categories: ['rate_limiting'], controlIds: [] },
    ],
  },

  // ── 5. WebSocket y WebRTC ────────────────────────────────────────────────
  {
    id: 5,
    name: 'WebSocket y WebRTC',
    controls: [
      { name: 'WSS obligatorio (TLS en WebSocket)',     priority: 'Crítica', method: 'DAST',  categories: ['websocket', 'tls'], controlIds: [] },
      { name: 'Validación del Origin en WebSocket',     priority: 'Crítica', method: 'DAST',  categories: ['websocket'], controlIds: [] },
      { name: 'JWT en handshake WebSocket',             priority: 'Alta',    method: 'DAST',  categories: ['websocket'], controlIds: [] },
      { name: 'Expiración de conexión (idle timeout)',  priority: 'Media',   method: 'MANUAL', categories: [], controlIds: [] },
      { name: 'Protección flooding (throttling)',       priority: 'Alta',    method: 'MANUAL', categories: [], controlIds: [] },
      { name: 'TURN seguro (tokens temporales <1h)',    priority: 'Alta',    method: 'MANUAL', categories: [], controlIds: [] },
      { name: 'Cifrado SRTP extremo a extremo',         priority: 'Crítica', method: 'MANUAL', categories: [], controlIds: [] },
    ],
  },

  // ── 6. Criptografía y Gestión de Secretos ───────────────────────────────
  {
    id: 6,
    name: 'Criptografía y Gestión de Secretos',
    controls: [
      { name: 'TLS 1.2+ y HSTS (max-age ≥ 1 año)',       priority: 'Crítica', method: 'DAST',  categories: ['tls', 'transport_security'], controlIds: [] },
      { name: 'Secret Manager central (sin hardcode)',     priority: 'Crítica', method: 'SAST',  categories: ['secrets'], controlIds: ['A02-'] },
      { name: 'Rotación automática de secretos (≤90d)',    priority: 'Alta',    method: 'MANUAL', categories: [], controlIds: [] },
      { name: 'No hardcoded secrets en repositorio',       priority: 'Crítica', method: 'SAST',  categories: ['secrets'], controlIds: [] },
      { name: 'Cifrado en reposo (KMS)',                    priority: 'Alta',    method: 'MANUAL', categories: [], controlIds: [] },
      { name: 'AES-256 para datos sensibles',               priority: 'Alta',    method: 'MANUAL', categories: [], controlIds: [] },
    ],
  },

  // ── 7. Infraestructura y Cloud GCP ──────────────────────────────────────
  {
    id: 7,
    name: 'Infraestructura y Cloud GCP',
    controls: [
      { name: 'IAM least privilege (roles mínimos)',      priority: 'Crítica', method: 'MANUAL', categories: [], controlIds: [] },
      { name: 'Cloud Armor WAF (rulesets + custom)',       priority: 'Alta',    method: 'MANUAL', categories: [], controlIds: [] },
      { name: 'Containers non-root (Dockerfile USER)',     priority: 'Alta',    method: 'SAST',  categories: ['backend'], controlIds: ['INFRA-01'] },
      { name: 'Escaneo de imágenes (Trivy)',               priority: 'Alta',    method: 'MANUAL', categories: [], controlIds: [] },
      { name: 'Network segmentation (VPCs privadas)',      priority: 'Alta',    method: 'MANUAL', categories: [], controlIds: [] },
      { name: 'Logging centralizado (Cloud Logging/OTEL)',  priority: 'Alta',    method: 'SAST',  categories: ['logging'], controlIds: ['A09-NOLOG'] },
      { name: 'Backup automatizado (snapshots)',           priority: 'Alta',    method: 'MANUAL', categories: [], controlIds: [] },
      { name: 'DRP y simulacros de recuperación',          priority: 'Media',   method: 'MANUAL', categories: [], controlIds: [] },
    ],
  },

  // ── 8. DevSecOps y SDLC ─────────────────────────────────────────────────
  {
    id: 8,
    name: 'DevSecOps y SDLC',
    controls: [
      { name: 'SAST en CI (Semgrep/SonarQube)',           priority: 'Crítica', method: 'SAST',  categories: ['sast'], controlIds: [] },
      { name: 'DAST orquestado (OWASP ZAP en pipeline)',  priority: 'Alta',    method: 'MANUAL', categories: [], controlIds: [] },
      { name: 'Dependency scanning (Snyk/npm audit)',      priority: 'Crítica', method: 'SAST',  categories: ['dependencies'], controlIds: [] },
      { name: 'Secret scanning (Gitleaks pre-commit)',     priority: 'Crítica', method: 'SAST',  categories: ['secrets'], controlIds: [] },
      { name: 'Branch protection (PR + 2 approvals)',     priority: 'Alta',    method: 'MANUAL', categories: [], controlIds: [] },
      { name: 'Code review obligatorio',                   priority: 'Alta',    method: 'MANUAL', categories: [], controlIds: [] },
      { name: 'SBOM y firma de artefactos (CycloneDX)',    priority: 'Media',   method: 'MANUAL', categories: [], controlIds: [] },
    ],
  },

  // ── 9. Observabilidad y Respuesta a Incidentes ──────────────────────────
  {
    id: 9,
    name: 'Observabilidad y Respuesta a Incidentes',
    controls: [
      { name: 'SIEM y alerting (Chronicle/Splunk)',        priority: 'Alta',   method: 'MANUAL', categories: [], controlIds: [] },
      { name: 'Alertas de seguridad (policies)',           priority: 'Alta',   method: 'MANUAL', categories: [], controlIds: [] },
      { name: 'Detección de anomalías (ML/log analysis)',  priority: 'Media',  method: 'MANUAL', categories: [], controlIds: [] },
      { name: 'Auditoría de accesos privilegiados',        priority: 'Alta',   method: 'SAST',   categories: ['logging'], controlIds: ['A09-AUTHLOG'] },
      { name: 'Retención de logs (90–365 días)',           priority: 'Alta',   method: 'MANUAL', categories: [], controlIds: [] },
      { name: 'Runbooks de respuesta a incidentes',        priority: 'Alta',   method: 'MANUAL', categories: [], controlIds: [] },
      { name: 'Evidencia forense (logs inmutables)',       priority: 'Media',  method: 'MANUAL', categories: [], controlIds: [] },
    ],
  },

  // ── 10. Privacidad y Compliance ──────────────────────────────────────────
  {
    id: 10,
    name: 'Privacidad y Compliance',
    controls: [
      { name: 'Consentimiento cookies (CMP integrado)',   priority: 'Alta',  method: 'SAST',  categories: ['frontend', 'cookies'], controlIds: ['PRIVACY-01'] },
      { name: 'Minimización de datos PII',                priority: 'Alta',  method: 'MANUAL', categories: [], controlIds: [] },
      { name: 'Derecho de eliminación (DELETE endpoint)', priority: 'Media', method: 'SAST',   categories: ['access_control'], controlIds: [] },
      { name: 'Retención controlada de datos',            priority: 'Alta',  method: 'MANUAL', categories: [], controlIds: [] },
      { name: 'Anonimización y masking de PII en logs',   priority: 'Media', method: 'SAST',   categories: ['logging'], controlIds: ['A09-SENSLOG'] },
      { name: 'Banner de privacidad visible en UI',       priority: 'Media', method: 'MANUAL', categories: [], controlIds: [] },
    ],
  },

  // ── 11. Controles Especiales IA y Voz ───────────────────────────────────
  {
    id: 11,
    name: 'Controles Especiales IA y Voz',
    controls: [
      { name: 'Protección audio grabado (bucket cifrado)', priority: 'Crítica', method: 'MANUAL', categories: [], controlIds: [] },
      { name: 'Tokens temporales STT/TTS (<1h)',           priority: 'Alta',    method: 'MANUAL', categories: [], controlIds: [] },
      { name: 'Sanitización de prompts IA',                priority: 'Alta',    method: 'SAST',   categories: ['injection', 'validation'], controlIds: ['AI-01'] },
      { name: 'Protección prompt injection (red team)',     priority: 'Alta',    method: 'MANUAL', categories: [], controlIds: [] },
      { name: 'Rate limit IA (quotas por usuario)',         priority: 'Alta',    method: 'SAST',   categories: ['rate_limiting'], controlIds: ['AI-02'] },
      { name: 'Auditoría IA (log prompts/respuestas)',      priority: 'Media',   method: 'SAST',   categories: ['logging'], controlIds: ['AI-03'] },
      { name: 'Redacción PII en respuestas IA',            priority: 'Alta',    method: 'MANUAL', categories: [], controlIds: [] },
    ],
  },
];

// ── Iconos y etiquetas ────────────────────────────────────────────────────

export const STATUS_META = {
  OK:           { status: 'OK',          icon: '✅', label: 'OK',          color: 'verde'     },
  PARCIAL:      { status: 'PARCIAL',     icon: '⚠️',  label: 'PARCIAL',     color: 'amarillo'  },
  FALLO:        { status: 'FALLO',       icon: '❌', label: 'FALLO',        color: 'rojo'      },
  NO_EVALUADO:  { status: 'NO_EVALUADO', icon: '⚪', label: 'NO EVALUADO',  color: 'gris'      },
};

export const PRIORITY_META = {
  'Crítica': '🔴',
  'Alta':    '🟠',
  'Media':   '🟡',
  'Baja':    '🔵',
};

// ── Lógica de evaluación ──────────────────────────────────────────────────

/**
 * Determina el estado de un control individual comparándolo con los findings.
 * Lógica severity threshold:
 *   - FALLO      → hallazgos critical o high relacionados
 *   - PARCIAL    → solo hallazgos medium relacionados
 *   - OK         → ningún hallazgo relacionado (scanner corrió, nada detectó)
 *   - NO_EVALUADO → control con método MANUAL
 *
 * @param {SecControl} control
 * @param {import('./Finding.js').Finding[]} findings
 * @returns {{ status: string, icon: string, label: string, relatedCount: number }}
 */
export function evaluateControl(control, findings) {
  if (control.method === 'MANUAL') {
    return { ...STATUS_META.NO_EVALUADO, relatedCount: 0 };
  }

  const related = findings.filter(f => {
    const catMatch = control.categories.length > 0 && control.categories.includes(f.category);
    const idMatch  = control.controlIds.length > 0  && control.controlIds.some(id => f.control_id?.startsWith(id));
    return catMatch || idMatch;
  });

  if (related.length === 0) return { ...STATUS_META.OK, relatedCount: 0 };

  const hasCriticalOrHigh = related.some(f => f.severity === 'critical' || f.severity === 'high');
  const hasMedium         = related.some(f => f.severity === 'medium');

  if (hasCriticalOrHigh) return { ...STATUS_META.FALLO,   relatedCount: related.length };
  if (hasMedium)         return { ...STATUS_META.PARCIAL,  relatedCount: related.length };
  return                        { ...STATUS_META.OK,       relatedCount: related.length };
}

/**
 * Evalúa todos los controles de la especificación y calcula estadísticas globales.
 *
 * @param {import('./Finding.js').Finding[]} findings
 * @returns {{ sections: object[], stats: object, scorePercent: number }}
 */
export function evaluateSecSpec(findings) {
  let totalOk = 0, totalParcial = 0, totalFallo = 0, totalManual = 0, totalEvaluable = 0;

  const sections = SEC_SPEC_SECTIONS.map(section => ({
    ...section,
    controls: section.controls.map(control => {
      const result = evaluateControl(control, findings);
      if (control.method === 'MANUAL') {
        totalManual++;
      } else {
        totalEvaluable++;
        if (result.status === 'OK')      totalOk++;
        else if (result.status === 'PARCIAL') totalParcial++;
        else if (result.status === 'FALLO')   totalFallo++;
      }
      return { ...control, result };
    }),
  }));

  // Score = (OK + PARCIAL * 0.5) / evaluable * 100
  const scorePercent = totalEvaluable > 0
    ? Math.round((totalOk + totalParcial * 0.5) / totalEvaluable * 100)
    : 0;

  return {
    sections,
    stats: { ok: totalOk, parcial: totalParcial, fallo: totalFallo, manual: totalManual, evaluable: totalEvaluable },
    scorePercent,
  };
}
