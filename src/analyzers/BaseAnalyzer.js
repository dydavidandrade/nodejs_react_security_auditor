class BaseAnalyzer {
  constructor(rootDir, fileSystem, logger) {
    this.rootDir = rootDir;
    this.fs = fileSystem;
    this.logger = logger;
    this.findings = [];
  }

  getName() { return this.constructor.name; }

  addFinding(finding) {
    this.findings.push(finding);
    this.logger.finding(finding.severity, finding.title);
  }

  async analyze() { throw new Error(`${this.getName()}.analyze() not implemented`); }

  getFindings() { return [...this.findings]; }

  _grep(content, pattern, flags = 'gm') {
    const re = new RegExp(pattern, flags);
    const matches = [];
    let m;
    while ((m = re.exec(content)) !== null) {
      matches.push({ match: m[0], index: m.index, groups: m.groups });
    }
    return matches;
  }

  _lineOf(content, index) { return content.substring(0, index).split('\n').length; }

  _hasPattern(content, pattern) { return new RegExp(pattern).test(content); }
}

export default BaseAnalyzer;
