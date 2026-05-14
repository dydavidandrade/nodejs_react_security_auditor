let _counter = 1;

export function resetCounter() { _counter = 1; }

export class Finding {
  constructor({ title, control_id, asvs_id, severity, description, remediation_steps, file = null, line = null, evidence_uri = null, category = 'general', attack_vector = null, request = null, response = null }) {
    this.id = `SEC-${String(_counter++).padStart(3, '0')}`;
    this.title = title;
    this.control_id = control_id;
    this.asvs_id = asvs_id;
    this.severity = severity;
    this.description = description;
    this.remediation_steps = remediation_steps;
    this.file = file;
    this.line = line;
    this.evidence_uri = evidence_uri;
    this.category = category;
    this.attack_vector = attack_vector;
    this.request = request;
    this.response = response;
    this.timestamp = new Date().toISOString();
  }

  toJson() {
    return {
      id: this.id,
      title: this.title,
      control_id: this.control_id,
      asvs_id: this.asvs_id,
      severity: this.severity,
      evidence_uri: this.evidence_uri,
      description: this.description,
      remediation_steps: this.remediation_steps,
      file: this.file,
      line: this.line,
      category: this.category,
      attack_vector: this.attack_vector,
      request: this.request,
      response: this.response ? String(this.response).substring(0, 500) : null,
      timestamp: this.timestamp,
    };
  }
}
