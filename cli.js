#!/usr/bin/env node
// Aegis CLI — run the LLM security harness against a target and write a report.
// Usage:
//   node cli.js              # scans the mock VULNERABLE LLM (default)
//   node cli.js hardened     # scans the mock HARDENED LLM (shows what "good" looks like)
const fs = require('fs');
const path = require('path');
const { vulnerable, hardened } = require('./targets');
const { runScan } = require('./engine');

(async () => {
  const which = (process.argv[2] || 'vulnerable').toLowerCase();
  const target = which === 'hardened' ? hardened : vulnerable;
  const report = await runScan(target, `${which} (mock LLM)`);

  const dir = path.join(__dirname, 'data');
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, 'results.json'), JSON.stringify(report, null, 2));

  const C = { critical: '\x1b[31m', high: '\x1b[33m', medium: '\x1b[36m', green: '\x1b[32m', dim: '\x1b[90m', reset: '\x1b[0m' };
  console.log(`\n  AEGIS — LLM Security Scan  ::  ${report.target}`);
  console.log(`  ${'─'.repeat(56)}`);
  for (const r of report.results) {
    const tag = r.vulnerable ? `${C[r.severity] || ''}● VULNERABLE${C.reset}` : `${C.green}○ secure${C.reset}`;
    console.log(`  [${r.owasp.id}] ${r.name.padEnd(42)} ${tag}`);
  }
  console.log(`  ${'─'.repeat(56)}`);
  const grade = report.score >= 90 ? C.green : report.score >= 50 ? C.medium : C.critical;
  console.log(`  Security score: ${grade}${report.score}/100${C.reset}   ${report.vulnerable} vulnerable / ${report.total} tests`);
  console.log(`  ${C.dim}Report saved to data/results.json — view the dashboard with: node server.js${C.reset}\n`);
})();
