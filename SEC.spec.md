# Convenciones de la matriz

- **Prioridad:** **Crítica**, **Alta**, **Media**, **Baja**.
- **Evidencia esperada:** artefactos automatizados (SARIF; ZAP HTML/JSON; Trivy JSON; Gitleaks JSON; infra reports).
- **Métrica mínima:** cobertura o SLA cuantificable por control.
- **Referencia normativa:** incluir **ASVS ID** o ISO/CIS cuando aplique.
- **Formato de salida:** cada hallazgo debe producir `control_id`, `asvs_id`, `evidence_uri`, `severity`, `remediation_steps`.

---

# 1 Gobierno y Arquitectura

| **Control**                        | **Prioridad** | **Implementación Técnica**              | **Evidencia**    | **Métrica SLA**                         |
| ---------------------------------- | ------------- | --------------------------------------- | ---------------- | --------------------------------------- |
| Inventario de activos automatizado | Alta          | CMDB export desde infra + repo scan     | CMDB JSON        | Cobertura 100%; actualización diaria    |
| Clasificación de datos PII         | Alta          | Pipeline de data classification         | Matriz datos CSV | % datos etiquetados ≥ 99%               |
| Modelo de amenazas continuo        | Alta          | STRIDE por módulo; backlog mitigaciones | threats.md       | Revisión trimestral; mitigaciones ≤ 30d |
| Segregación ambientes              | Alta          | Terraform workspaces separados          | Terraform state  | No accesos cross-env; CI gate           |
| Trazabilidad cambios arquitectura  | Media         | GitOps PRs firmados                     | PR logs          | 100% cambios en PR; 2 approvals         |

---

# 2 Autenticación y Gestión de Sesiones

| **Control**              | **Prioridad** | **Implementación Técnica**           | **Evidencia**     | **Métrica SLA**                  |
| ------------------------ | ------------- | ------------------------------------ | ----------------- | -------------------------------- |
| MFA para administradores | Crítica       | WebAuthn + TOTP                      | IAM config export | 100% admins MFA                  |
| Hashing de contraseñas   | Crítica       | Argon2id con parámetros documentados | Código + tests    | Cost documentado; revisión anual |
| Política de contraseñas  | Alta          | Min length 12; checks de blacklist   | Config backend    | Enforce en signup/login          |
| JWT seguros y revocación | Crítica       | Exp corto + refresh + blacklist      | Token logs        | Exp ≤ 15m; revocation ≤ 1s       |
| Invalidación de sesiones | Alta          | Redis session store                  | Session logs      | Logout efectivo ≤ 2s             |
| Protección brute force   | Alta          | Rate limiting + lock temporal        | Gateway logs      | Lockout tras 5 intentos          |
| Cookies seguras          | Crítica       | HttpOnly Secure SameSite=Strict      | Response headers  | 100% cookies seguras             |
| Session rotation         | Alta          | Regenerar session ID en login        | Código            | Rotation en cada auth flow       |

---

# 3 Seguridad Frontend React

| **Control**                 | **Prioridad** | **Implementación Técnica**     | **Evidencia**  | **Métrica SLA**                     |
| --------------------------- | ------------- | ------------------------------ | -------------- | ----------------------------------- |
| CSP estricta con nonces     | Crítica       | Helmet CSP + build-time hashes | Headers report | CSP score ≥ 90 SecurityHeaders      |
| Protección XSS              | Crítica       | React escaping + sanitizer     | SAST/DAST      | 0 XSS críticos en DAST              |
| SRI para assets             | Media         | Build genera integrity hashes  | HTML build     | 100% assets con SRI                 |
| Deshabilitar inline scripts | Alta          | Nonce/hash CSP                 | Headers        | No inline scripts sin nonce         |
| Clickjacking protection     | Alta          | X-Frame-Options DENY           | Headers        | 100% respuestas con X-Frame-Options |
| CSRF protection             | Alta          | CSRF tokens + SameSite         | Tests E2E      | CSRF tests verdes                   |
| Validación frontend         | Media         | Zod/Yup + schema sync          | Schemas repo   | 100% endpoints con schema sync      |

---

# 4 Seguridad Backend y API

| **Control**               | **Prioridad** | **Implementación Técnica**             | **Evidencia**        | **Métrica SLA**             |
| ------------------------- | ------------- | -------------------------------------- | -------------------- | --------------------------- |
| Validación server-side    | Crítica       | DTO validation + contract tests        | SARIF / test reports | 100% endpoints validados    |
| SQL parametrizado         | Crítica       | Prepared statements / ORM safe queries | Code scan            | 0 queries concatenadas      |
| Protección SSRF           | Alta          | Outbound allowlists                    | Egress policy        | 100% egress control         |
| Prevención RCE            | Crítica       | No eval; linter rules                  | SAST reports         | 0 RCE patterns              |
| Sanitización centralizada | Crítica       | Validators centralizados               | SAST                 | 0 input-sanitization misses |
| Manejo seguro de errores  | Alta          | No stacktrace público                  | Logs                 | No stacktrace en prod       |
| API Gateway y WAF         | Alta          | Cloud Armor / API Gateway              | Infra config         | Gateway en front of APIs    |
| Rate limiting API         | Alta          | Token bucket / Redis                   | Load test            | Rate limits enforced        |

---

# 5 WebSocket y WebRTC

| **Control**            | **Prioridad** | **Implementación Técnica** | **Evidencia**        | **Métrica SLA**                 |
| ---------------------- | ------------- | -------------------------- | -------------------- | ------------------------------- |
| WSS obligatorio        | Crítica       | TLS 1.2+ enforced          | SSL config           | SSL Labs A                      |
| Validar origen WS      | Crítica       | Origin checking            | Test logs            | 100% origin validated           |
| JWT en handshake       | Alta          | Auth handshake with JWT    | Handshake logs       | 100% handshakes authenticated   |
| Expiración de conexión | Media         | Idle timeout               | Config               | Idle timeout ≤ configured value |
| Protección flooding    | Alta          | Connection throttling      | Logs                 | Flood attempts blocked          |
| TURN seguro            | Alta          | TURN auth temporal         | Config               | TURN tokens exp < 1h            |
| Cifrado SRTP           | Crítica       | DTLS-SRTP                  | Traffic verification | SRTP enabled end-to-end         |

---

# 6 Criptografía y Gestión de Secretos

| **Control**                  | **Prioridad** | **Implementación Técnica** | **Evidencia**   | **Métrica SLA**                |
| ---------------------------- | ------------- | -------------------------- | --------------- | ------------------------------ |
| TLS 1.2+ y HSTS              | Crítica       | HTTPS only + HSTS          | SSL config      | TLS 1.2+; HSTS max-age ≥ 1y    |
| Secret Manager central       | Crítica       | GCP Secret Manager         | Audit logs      | 100% secrets in Secret Manager |
| Rotación de secretos         | Alta          | Rotación automática        | Rotation logs   | Rotación ≤ 90d                 |
| No hardcoded secrets         | Crítica       | Pre-commit + CI scans      | Gitleaks report | 0 secrets in repo              |
| Cifrado en reposo            | Alta          | KMS + disk encryption      | Infra config    | Encrypted volumes              |
| AES-256 para datos sensibles | Alta          | Encryption layer           | Code + infra    | 100% sensitive data encrypted  |

---

# 7 Infraestructura y Cloud GCP

| **Control**          | **Prioridad** | **Implementación Técnica** | **Evidencia**     | **Métrica SLA**                 |
| -------------------- | ------------- | -------------------------- | ----------------- | ------------------------------- |
| IAM least privilege  | Crítica       | Roles mínimos y reviews    | IAM policy export | Reviews trimestrales            |
| Cloud Armor WAF      | Alta          | Rulesets + custom rules    | WAF logs          | Block rate > threshold          |
| Containers non-root  | Alta          | Dockerfile USER non-root   | Image scan        | 100% images non-root            |
| Escaneo de imágenes  | Alta          | Trivy/CI scans             | Trivy JSON        | 0 critical vulns in prod images |
| Network segmentation | Alta          | Private VPCs               | VPC config        | No public DB subnets            |
| Logging centralizado | Alta          | Cloud Logging + OTEL       | Dashboard         | Logs centralizados              |
| Backup automatizado  | Alta          | Snapshots                  | Backup logs       | RPO/RTO definidos               |
| DRP y simulacros     | Media         | Disaster recovery plan     | DR doc            | Simulacro anual                 |

---

# 8 DevSecOps y SDLC

| **Control**             | **Prioridad** | **Implementación Técnica** | **Evidencia** | **Métrica SLA**          |
| ----------------------- | ------------- | -------------------------- | ------------- | ------------------------ |
| SAST en CI              | Crítica       | Semgrep/SonarQube          | SARIF         | 100% PRs scanned         |
| DAST orquestado         | Alta          | OWASP ZAP auth scans       | ZAP reports   | DAST weekly              |
| Dependency scanning     | Crítica       | Snyk / npm audit           | CI logs       | No critical deps in prod |
| Secret scanning         | Crítica       | Gitleaks pre-commit + CI   | Gitleaks JSON | 0 secrets merged         |
| Branch protection       | Alta          | PR mandatory + 2 approvals | Git config    | 100% PRs protected       |
| Code review obligatorio | Alta          | 2 approvals                | PR logs       | 100% code reviewed       |
| SBOM y firma artefactos | Media         | CycloneDX + Cosign         | SBOM artifact | SBOM per release         |

---

# 9 Observabilidad y Respuesta a Incidentes

| **Control**          | **Prioridad** | **Implementación Técnica** | **Evidencia**   | **Métrica SLA**               |
| -------------------- | ------------- | -------------------------- | --------------- | ----------------------------- |
| SIEM y alerting      | Alta          | Chronicle/Splunk + alerts  | Alert dashboard | MTTR ≤ 4h                     |
| Alertas de seguridad | Alta          | Alerting policies          | Alert logs      | Alert coverage ≥ 95%          |
| Detección anomalías  | Media         | ML/log analysis            | SIEM            | False positive rate control   |
| Auditoría de accesos | Alta          | Audit logs                 | Logs            | 100% privileged access logged |
| Retención de logs    | Alta          | 90–365 días                | Storage config  | Retention policy aplicada     |
| Runbooks incidentes  | Alta          | Playbooks por tipo         | Runbooks repo   | Simulacros semestrales        |
| Evidencia forense    | Media         | Immutable logs             | Storage         | Forensic-ready logs           |

---

# 10 Privacidad y Compliance

| **Control**             | **Prioridad** | **Implementación Técnica** | **Evidencia**  | **Métrica SLA**             |
| ----------------------- | ------------- | -------------------------- | -------------- | --------------------------- |
| Consentimiento cookies  | Alta          | CMP integrado              | UI screenshots | Consent capture 100%        |
| Minimización de datos   | Alta          | Diseño DB minimal          | DB schema      | PII stored only when needed |
| Derecho de eliminación  | Media         | Endpoint delete + audit    | Delete logs    | Delete request ≤ 30d        |
| Retención controlada    | Alta          | Lifecycle policies         | Config         | Retention policies enforced |
| Anonimización y masking | Media         | Tokenization/masking       | Tests          | PII masked in logs          |
| Banner de privacidad    | Media         | Política visible           | UI             | Policy accessible from UI   |

---

# 11 Controles Especiales IA y Voz

| **Control**                 | **Prioridad** | **Implementación Técnica** | **Evidencia**    | **Métrica SLA**              |
| --------------------------- | ------------- | -------------------------- | ---------------- | ---------------------------- |
| Protección audio grabado    | Crítica       | Bucket cifrado + ACLs      | Bucket policy    | Encrypted at rest            |
| Tokens temporales STT TTS   | Alta          | Short-lived tokens         | Logs             | Token exp < 1h               |
| Sanitización de prompts     | Alta          | Prompt filters             | Test reports     | 0 critical prompt injections |
| Protección prompt injection | Alta          | Context isolation          | Red Team reports | Fuzzing coverage ≥ 90%       |
| Rate limit IA               | Alta          | Quotas                     | Config           | Quotas enforced              |
| Auditoría IA                | Media         | Log prompts/responses      | Logs             | Retention and access control |
| Redacción PII               | Alta          | Masking pipeline           | Pipeline logs    | PII masked 100%              |

---

# Herramientas recomendadas y artefactos

| **Área**        | **Herramienta**     | **Artefacto esperado** |
| --------------- | ------------------- | ---------------------- |
| SAST            | Semgrep / SonarQube | SARIF                  |
| DAST            | OWASP ZAP           | ZAP HTML/JSON          |
| Dependency scan | Snyk / npm audit    | JSON report            |
| Secret scan     | Gitleaks            | JSON report            |
| Container scan  | Trivy               | JSON report            |
| WAF             | Cloud Armor         | WAF logs               |
| IAM             | GCP IAM             | IAM policy export      |
| SIEM            | Chronicle / Splunk  | Alert dashboard        |
| Observabilidad  | OpenTelemetry       | Traces/metrics         |
| SBOM            | CycloneDX           | SBOM artifact          |

---

# Mapeo mínimo obligatorio de evidencia por control

- **SAST** → SARIF con `ruleId`, `file`, `line`, `severity`.
- **DAST** → ZAP JSON/HTML con request/response y proof-of-concept no destructivo.
- **Secrets** → Gitleaks JSON con commit ID y file path.
- **Image scan** → Trivy JSON con CVE IDs.
- **Infra** → IAM policy export, terraform state diff, OPA/Rego scan results.
- **Runtime** → Handshake logs, SRTP verification, TURN token logs.
- **IA/voz** → Prompt fuzzing report con inputs, outputs, and masking evidence.

---

# Métricas y SLAs recomendados

- **SAST coverage:** 100% PRs scanned.
- **DAST cadence:** weekly authenticated scans.
- **Secret leakage:** 0 secrets merged; Gitleaks on PRs.
- **Image vulnerabilities:** 0 critical in prod images.
- **MTTR seguridad:** ≤ 4 horas para incidentes críticos.
- **Token expiry:** JWT access tokens ≤ 15 minutos.
- **Secret rotation:** ≤ 90 días.
- **Log retention:** 90–365 días según compliance.

---

# Plantilla de `findings.json` por hallazgo

```json
{
  "id": "F-001",
  "title": "JWT sin revocación efectiva",
  "control_id": "AUTH-04",
  "asvs_id": "ASVS 2.2.3",
  "severity": "critical",
  "evidence_uri": "gs://audit-bucket/sarif_sast.json#... ",
  "description": "Tokens JWT con exp largo y sin blacklist",
  "remediation_steps": "Implementar refresh tokens y blacklist en Redis; reducir exp a 15m",
  "file": "src/services/tokenService.js",
  "line": 123
}
```
