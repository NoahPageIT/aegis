#!/usr/bin/env node
// Aegis - PDF audit report generator.
// Usage: node report.js [results-file] [output-file]
//   node report.js                              → data/results.json → data/aegis-report.html (+ .pdf hint)
//   node report.js data/results.json report.html

const fs   = require('fs');
const path = require('path');

const resultsPath = process.argv[2] || path.join(__dirname, 'data/results.json');
const outPath     = process.argv[3] || path.join(__dirname, 'data/aegis-report.html');

if (!fs.existsSync(resultsPath)) {
  console.error(`  ✗ Results file not found: ${resultsPath}`);
  console.error(`  Run a scan first: node cli.js`);
  process.exit(1);
}

const report = JSON.parse(fs.readFileSync(resultsPath, 'utf-8'));
const { target, scannedAt, score, total, vulnerable, results } = report;

const SEV_COLOR = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e' };
const SEV_BG    = { critical: 'rgba(239,68,68,0.08)', high: 'rgba(249,115,22,0.08)', medium: 'rgba(234,179,8,0.08)', low: 'rgba(34,197,94,0.08)' };

const scoreColor = score >= 90 ? '#22c55e' : score >= 50 ? '#eab308' : '#ef4444';
const grade = score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 50 ? 'C' : score >= 25 ? 'D' : 'F';

const owaspMap = {};
for (const r of results) {
  const key = r.owasp.id;
  if (!owaspMap[key]) owaspMap[key] = { name: r.owasp.name, tests: [], vuln: 0 };
  owaspMap[key].tests.push(r);
  if (r.vulnerable) owaspMap[key].vuln++;
}

function row(r) {
  const col   = SEV_COLOR[r.severity] || '#888';
  const bg    = SEV_BG[r.severity]    || 'transparent';
  const badge = r.vulnerable
    ? `<span style="background:rgba(239,68,68,0.12);color:#ef4444;border:1px solid rgba(239,68,68,0.3);padding:2px 8px;border-radius:4px;font-size:10px;font-weight:700;letter-spacing:.05em">VULNERABLE</span>`
    : `<span style="background:rgba(34,197,94,0.12);color:#22c55e;border:1px solid rgba(34,197,94,0.3);padding:2px 8px;border-radius:4px;font-size:10px;font-weight:700;letter-spacing:.05em">SECURE</span>`;
  return `
  <tr style="border-bottom:1px solid #1a1a2e;background:${r.vulnerable ? bg : 'transparent'}">
    <td style="padding:10px 12px;font-size:11px;font-weight:700;color:${col};white-space:nowrap">${r.owasp.id}</td>
    <td style="padding:10px 12px;font-size:12px;color:#e2e8f0">${r.name}</td>
    <td style="padding:10px 12px;font-size:10px;font-weight:700;color:${col};text-transform:uppercase">${r.severity}</td>
    <td style="padding:10px 12px;text-align:center">${badge}</td>
  </tr>
  ${r.vulnerable ? `
  <tr style="border-bottom:1px solid #1a1a2e;background:#0a0a12">
    <td colspan="4" style="padding:8px 12px 12px 32px">
      <div style="font-size:10px;color:#64748b;margin-bottom:4px;text-transform:uppercase;letter-spacing:.08em">Payload</div>
      <div style="font-size:11px;color:#94a3b8;font-family:monospace;background:#040408;border:1px solid #1a1a2e;border-radius:4px;padding:6px 10px;margin-bottom:8px;white-space:pre-wrap">${esc(r.payload)}</div>
      <div style="font-size:10px;color:#64748b;margin-bottom:4px;text-transform:uppercase;letter-spacing:.08em">Fix</div>
      <div style="font-size:11px;color:#94a3b8;line-height:1.6">${esc(r.remediation)}</div>
    </td>
  </tr>` : ''}`;
}

function esc(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Aegis Security Report - ${esc(target)}</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: #040408; color: #e2e8f0; font-family: 'Segoe UI', system-ui, sans-serif; padding: 40px 48px; max-width: 900px; margin: 0 auto; }
  @media print { body { background: #fff; color: #111; padding: 20px; } }
  h1 { font-size: 22px; font-weight: 800; letter-spacing: -.02em; }
  h2 { font-size: 13px; font-weight: 700; letter-spacing: .12em; text-transform: uppercase; color: #64748b; margin: 32px 0 12px; }
  table { width: 100%; border-collapse: collapse; font-size: 12px; }
  th { text-align: left; padding: 8px 12px; font-size: 10px; font-weight: 700; letter-spacing: .1em; text-transform: uppercase; color: #475569; border-bottom: 1px solid #1a1a2e; }
</style>
</head>
<body>

<div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:32px;padding-bottom:24px;border-bottom:1px solid #1a1a2e">
  <div>
    <div style="font-size:10px;font-weight:700;letter-spacing:.15em;text-transform:uppercase;color:#a855f7;margin-bottom:8px">AEGIS - AI Security Audit</div>
    <h1>Security Report</h1>
    <div style="font-size:12px;color:#64748b;margin-top:6px">Target: <span style="color:#94a3b8">${esc(target)}</span></div>
    <div style="font-size:12px;color:#64748b;margin-top:2px">Scanned: <span style="color:#94a3b8">${new Date(scannedAt).toLocaleString()}</span></div>
  </div>
  <div style="text-align:right">
    <div style="font-size:64px;font-weight:900;line-height:1;color:${scoreColor}">${score}</div>
    <div style="font-size:11px;color:#64748b;margin-top:2px">Security Score / 100</div>
    <div style="font-size:28px;font-weight:800;color:${scoreColor};margin-top:4px">Grade ${grade}</div>
  </div>
</div>

<div style="display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin-bottom:32px">
  <div style="background:#0a0a12;border:1px solid #1a1a2e;border-radius:8px;padding:16px;text-align:center">
    <div style="font-size:28px;font-weight:800;color:#e2e8f0">${total}</div>
    <div style="font-size:10px;color:#64748b;text-transform:uppercase;letter-spacing:.1em;margin-top:4px">Tests Run</div>
  </div>
  <div style="background:#0a0a12;border:1px solid rgba(239,68,68,0.3);border-radius:8px;padding:16px;text-align:center">
    <div style="font-size:28px;font-weight:800;color:#ef4444">${vulnerable}</div>
    <div style="font-size:10px;color:#64748b;text-transform:uppercase;letter-spacing:.1em;margin-top:4px">Vulnerable</div>
  </div>
  <div style="background:#0a0a12;border:1px solid rgba(34,197,94,0.3);border-radius:8px;padding:16px;text-align:center">
    <div style="font-size:28px;font-weight:800;color:#22c55e">${total - vulnerable}</div>
    <div style="font-size:10px;color:#64748b;text-transform:uppercase;letter-spacing:.1em;margin-top:4px">Secure</div>
  </div>
</div>

<h2>OWASP LLM Top 10 Coverage</h2>
<div style="display:grid;grid-template-columns:repeat(5,1fr);gap:8px;margin-bottom:32px">
${Object.entries(owaspMap).sort((a,b)=>a[0].localeCompare(b[0])).map(([id, cat]) => {
  const c = cat.vuln > 0 ? '#ef4444' : '#22c55e';
  const bg = cat.vuln > 0 ? 'rgba(239,68,68,0.06)' : 'rgba(34,197,94,0.06)';
  return `  <div style="background:${bg};border:1px solid ${c}33;border-radius:6px;padding:10px;text-align:center">
    <div style="font-size:11px;font-weight:700;color:${c}">${id}</div>
    <div style="font-size:9px;color:#64748b;margin-top:3px;line-height:1.3">${esc(cat.name)}</div>
    <div style="font-size:10px;color:${c};font-weight:700;margin-top:6px">${cat.vuln}/${cat.tests.length}</div>
  </div>`;
}).join('\n')}
</div>

<h2>Test Results</h2>
<table>
  <thead>
    <tr>
      <th>OWASP</th><th>Test</th><th>Severity</th><th>Result</th>
    </tr>
  </thead>
  <tbody>
    ${results.sort((a,b) => (b.vulnerable ? 1 : 0) - (a.vulnerable ? 1 : 0)).map(row).join('')}
  </tbody>
</table>

<div style="margin-top:48px;padding-top:24px;border-top:1px solid #1a1a2e;display:flex;justify-content:space-between;font-size:10px;color:#475569">
  <span>Generated by Aegis - github.com/NoahPageIT/aegis</span>
  <span>${new Date().toISOString()}</span>
</div>

</body>
</html>`;

fs.writeFileSync(outPath, html);
console.log(`  Report saved: ${outPath}`);
console.log(`  Open in browser to view, or print to PDF (Cmd+P → Save as PDF).`);
