/**
 * Metadatos y funciones de mapeo para OWASP Top 10 — 2021.
 * Referencia: https://owasp.org/Top10/
 */

/** @type {Record<string, {name: string, description: string, categories: string[], controlIds: string[], asvs_ref: string}>} */
export const OWASP_TOP10 = {
  'A01:2021': {
    name: 'Broken Access Control',
    description: 'Los controles de acceso no se aplican correctamente. Usuarios actúan fuera de los permisos previstos: elevan privilegios, acceden a datos de otros usuarios o ejecutan funciones restringidas.',
    categories: ['access_control', 'authorization', 'path_traversal', 'open_redirect'],
    controlIds: ['AUTH-', 'BACKEND-06'],
    asvs_ref: 'ASVS 4.x',
  },
  'A02:2021': {
    name: 'Cryptographic Failures',
    description: 'Fallas relacionadas con criptografía (antes "Sensitive Data Exposure"). Datos sensibles expuestos en tránsito o en reposo por uso de HTTP, algoritmos débiles o secretos hardcodeados.',
    categories: ['tls', 'secrets', 'transport_security', 'cookies'],
    controlIds: ['CRYPTO-'],
    asvs_ref: 'ASVS 6.x / 9.x',
  },
  'A03:2021': {
    name: 'Injection',
    description: 'Datos hostiles enviados al intérprete como parte de un comando o consulta. Incluye SQL, OS, LDAP, XSS, SSTI y cualquier forma de inyección donde el intérprete no diferencia instrucción de dato.',
    categories: ['sqli', 'xss', 'rce', 'ssti', 'injection', 'command_injection'],
    controlIds: ['BACKEND-04', 'BACKEND-05'],
    asvs_ref: 'ASVS 5.x',
  },
  'A04:2021': {
    name: 'Insecure Design',
    description: 'Riesgos de diseño y arquitectura inseguros. Ausencia de modelado de amenazas, patrones de diseño seguros o arquitectura de referencia. No se puede corregir solo con implementación correcta.',
    categories: ['csrf', 'rate_limiting'],
    controlIds: ['BACKEND-08'],
    asvs_ref: 'ASVS 1.x / 4.2.x',
  },
  'A05:2021': {
    name: 'Security Misconfiguration',
    description: 'Configuración incorrecta de permisos, cabeceras de seguridad ausentes, características innecesarias habilitadas, mensajes de error verbosos, valores por defecto inseguros.',
    categories: ['headers', 'backend', 'frontend', 'information_disclosure', 'general'],
    controlIds: ['BACKEND-01', 'BACKEND-02'],
    asvs_ref: 'ASVS 14.x',
  },
  'A06:2021': {
    name: 'Vulnerable and Outdated Components',
    description: 'Uso de componentes (librerías, frameworks, runtimes) con vulnerabilidades conocidas, sin soporte o desactualizados que debilitan las defensas de la aplicación.',
    categories: ['dependencies'],
    controlIds: ['DEPS-'],
    asvs_ref: 'ASVS 14.2',
  },
  'A07:2021': {
    name: 'Identification and Authentication Failures',
    description: 'Fallas en la confirmación de identidad del usuario, autenticación y gestión de sesiones. Permite ataques como credential stuffing, brute force, robo de sesiones y account takeover.',
    categories: ['authentication'],
    controlIds: ['AUTH-'],
    asvs_ref: 'ASVS 2.x',
  },
  'A08:2021': {
    name: 'Software and Data Integrity Failures',
    description: 'Código e infraestructura que no protege contra violaciones de integridad. Actualizaciones sin firma, deserialización insegura, pipelines CI/CD comprometidos.',
    categories: ['deserialization', 'sast'],
    controlIds: ['BACKEND-04'],
    asvs_ref: 'ASVS 10.x',
  },
  'A09:2021': {
    name: 'Security Logging and Monitoring Failures',
    description: 'Sin logging suficiente, las brechas no se detectan. Sin monitoreo y respuesta activa, los atacantes persisten más tiempo causando mayor daño.',
    categories: ['logging'],
    controlIds: ['OBS-'],
    asvs_ref: 'ASVS 7.x',
  },
  'A10:2021': {
    name: 'Server-Side Request Forgery (SSRF)',
    description: 'El servidor realiza peticiones a destinos arbitrarios controlados por el atacante. Puede acceder a servicios internos, metadata de cloud (AWS/GCP/Azure), o escanear la red interna.',
    categories: ['ssrf', 'websocket'],
    controlIds: ['BACKEND-03'],
    asvs_ref: 'ASVS 12.1',
  },
};

/**
 * Retorna el ID OWASP Top 10 correspondiente a una categoría de finding.
 * @param {string} category
 * @param {string} [controlId]
 * @returns {string|null}
 */
export function getOwaspId(category, controlId = '') {
  for (const [id, data] of Object.entries(OWASP_TOP10)) {
    if (data.categories.includes(category)) return id;
    if (controlId && data.controlIds.some(prefix => controlId.startsWith(prefix))) return id;
  }
  return null;
}

/**
 * Agrupa un array de findings por categoría OWASP Top 10.
 * Retorna un mapa { 'A01:2021': [Finding, ...], ... } con todas las claves siempre presentes.
 * @param {import('./Finding.js').Finding[]} findings
 * @returns {Record<string, import('./Finding.js').Finding[]>}
 */
export function mapFindingsToOwasp(findings) {
  const map = Object.fromEntries(Object.keys(OWASP_TOP10).map(id => [id, []]));

  for (const f of findings) {
    const owaspId = f.owasp || getOwaspId(f.category, f.control_id);
    if (owaspId && map[owaspId]) {
      map[owaspId].push(f);
    }
  }
  return map;
}

/**
 * Determina el estado de cumplimiento de una categoría OWASP dado sus findings.
 * @param {import('./Finding.js').Finding[]} findings
 * @returns {{ status: 'PASS'|'PARTIAL'|'FAIL', icon: string, maxSeverity: string|null }}
 */
export function owaspStatus(findings) {
  if (findings.length === 0) return { status: 'PASS', icon: '✅', maxSeverity: null };
  const hasCritical = findings.some(f => f.severity === 'critical');
  const hasHigh     = findings.some(f => f.severity === 'high');
  if (hasCritical || hasHigh) return { status: 'FAIL',    icon: '❌', maxSeverity: hasCritical ? 'CRÍTICO' : 'ALTO' };
  const hasMedium   = findings.some(f => f.severity === 'medium');
  return { status: hasMedium ? 'PARTIAL' : 'PASS', icon: hasMedium ? '⚠️' : '✅', maxSeverity: hasMedium ? 'MEDIO' : 'BAJO' };
}
