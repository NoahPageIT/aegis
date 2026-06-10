// Aegis — report server (zero dependencies: raw Node http + fs).
// Serves the HUD report dashboard and runs scans on demand.
const http = require('http');
const fs = require('fs');
const path = require('path');
const { vulnerable, hardened } = require('./targets');
const { runScan } = require('./engine');

const PORT = 3002;
const PUBLIC = path.join(__dirname, 'public');
const RESULTS = path.join(__dirname, 'data', 'results.json');
const MIME = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css' };
const json = (res, o) => { res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(o)); };

http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const p = url.pathname;

  if (p === '/api/scan') {
    const which = (url.searchParams.get('target') || 'vulnerable').toLowerCase();
    const report = await runScan(which === 'hardened' ? hardened : vulnerable, `${which} (mock LLM)`);
    fs.mkdirSync(path.dirname(RESULTS), { recursive: true });
    fs.writeFileSync(RESULTS, JSON.stringify(report, null, 2));
    return json(res, report);
  }
  if (p === '/api/results') {
    try { return json(res, JSON.parse(fs.readFileSync(RESULTS, 'utf8'))); }
    catch { return json(res, await runScan(vulnerable, 'vulnerable (mock LLM)')); }
  }

  let file = p === '/' ? 'index.html' : p.replace(/^\/+/, '');
  const full = path.join(PUBLIC, file);
  if (full.startsWith(PUBLIC) && fs.existsSync(full)) {
    res.writeHead(200, { 'Content-Type': MIME[path.extname(full)] || 'text/plain' });
    return fs.createReadStream(full).pipe(res);
  }
  res.writeHead(404); res.end('Not found');
}).listen(PORT, () => console.log(`\n  🛡  Aegis — LLM Security Test Harness → http://localhost:${PORT}\n`));
