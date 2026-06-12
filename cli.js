#!/usr/bin/env node
// Aegis CLI - run the LLM security harness against a target and write a report.
// Usage:
//   node cli.js                          # scans the mock VULNERABLE LLM (default)
//   node cli.js hardened                 # scans the mock HARDENED LLM
//   node cli.js ollama [model] [host]    # scans a real Ollama model (local)
//   node cli.js openai [model]           # scans an OpenAI-compatible endpoint (needs OPENAI_API_KEY)
const fs = require('fs');
const path = require('path');
const { vulnerable, hardened, makeOllamaTarget, makeOpenAITarget } = require('./targets');
const { runScan } = require('./engine');

(async () => {
  const [, , which = 'vulnerable', arg2, arg3] = process.argv;

  let target, targetName;

  switch (which.toLowerCase()) {
    case 'hardened':
      target = hardened;
      targetName = 'hardened (mock LLM)';
      break;
    case 'ollama': {
      const model = arg2 || 'llama3.2';
      const host  = arg3 || 'http://localhost:11434';
      console.log(`  Connecting to Ollama (${model} @ ${host})...`);
      try {
        target = await makeOllamaTarget(model, host);
        targetName = `ollama/${model}`;
      } catch (e) {
        console.error(`  ✗ ${e.message}`);
        process.exit(1);
      }
      break;
    }
    case 'openai': {
      const model = arg2 || 'gpt-4o-mini';
      if (!process.env.OPENAI_API_KEY) {
        console.error('  ✗ Set OPENAI_API_KEY to use the OpenAI adapter.');
        process.exit(1);
      }
      target = makeOpenAITarget(model);
      targetName = `openai/${model}`;
      break;
    }
    default:
      target = vulnerable;
      targetName = 'vulnerable (mock LLM)';
  }

  const report = await runScan(target, targetName);

  const dir = path.join(__dirname, 'data');
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, 'results.json'), JSON.stringify(report, null, 2));

  const C = { critical: '\x1b[31m', high: '\x1b[33m', medium: '\x1b[36m', green: '\x1b[32m', dim: '\x1b[90m', reset: '\x1b[0m' };
  console.log(`\n  AEGIS - LLM Security Scan  ::  ${report.target}`);
  console.log(`  ${'─'.repeat(56)}`);
  for (const r of report.results) {
    const tag = r.vulnerable ? `${C[r.severity] || ''}● VULNERABLE${C.reset}` : `${C.green}○ secure${C.reset}`;
    console.log(`  [${r.owasp.id}] ${r.name.padEnd(42)} ${tag}`);
  }
  console.log(`  ${'─'.repeat(56)}`);
  const grade = report.score >= 90 ? C.green : report.score >= 50 ? C.high : C.critical;
  console.log(`  Security score: ${grade}${report.score}/100${C.reset}   ${report.vulnerable} vulnerable / ${report.total} tests`);
  console.log(`  ${C.dim}Report saved → data/results.json${C.reset}\n`);
})();
