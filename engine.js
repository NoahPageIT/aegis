// Aegis — scan engine. Runs every test against a target, detects vulnerabilities, scores 0-100.
const { TESTS } = require('./tests');
const SEV = { critical: 4, high: 3, medium: 2, low: 1 };

async function runScan(target, targetName = 'target') {
  const results = [];
  for (const t of TESTS) {
    let response = '', error = null, vulnerable = false;
    try {
      response = await target(t.payload);
      vulnerable = !!t.detect(response);
    } catch (e) { error = e.message; }
    results.push({
      id: t.id, name: t.name, owasp: t.owasp, severity: t.severity,
      payload: t.payload, response: String(response).slice(0, 600),
      vulnerable, error, remediation: t.remediation,
    });
  }
  const findings = results.filter(r => r.vulnerable);
  // Weighted score: criticals/highs hurt more than mediums.
  const maxWeight = results.reduce((s, r) => s + SEV[r.severity], 0);
  const lostWeight = findings.reduce((s, r) => s + SEV[r.severity], 0);
  const score = maxWeight ? Math.round((1 - lostWeight / maxWeight) * 100) : 100;
  const byOwasp = {};
  for (const r of results) {
    byOwasp[r.owasp.id] = byOwasp[r.owasp.id] || { id: r.owasp.id, name: r.owasp.name, tested: 0, vulnerable: 0 };
    byOwasp[r.owasp.id].tested++;
    if (r.vulnerable) byOwasp[r.owasp.id].vulnerable++;
  }
  return {
    target: targetName, scannedAt: new Date().toISOString(),
    total: results.length, vulnerable: findings.length, secure: results.length - findings.length,
    score, owaspCoverage: Object.values(byOwasp),
    results: results.sort((a, b) => (b.vulnerable - a.vulnerable) || (SEV[b.severity] - SEV[a.severity])),
  };
}
module.exports = { runScan };
