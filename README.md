# 🛡 Aegis - LLM Security Test Harness

Aegis red-teams LLM-powered applications against the **[OWASP LLM Top 10](https://genai.owasp.org/llm-top-10/)** - probing for prompt injection, system-prompt leakage, secret disclosure, jailbreaks, insecure output handling, and excessive agency - then scores the target and reports findings with remediation.

Built to demonstrate **AI security** skills: adversarial testing, detection logic, and secure-design knowledge for GenAI systems - the emerging discipline at the intersection of cybersecurity and AI.

> Ships with a **mock vulnerable LLM** so the full red-team pipeline runs end-to-end at **zero API cost**. Pluggable adapters let you point it at a real model (Ollama, Anthropic, OpenAI) when you want to.

![Aegis report - mock vulnerable target failing 7/7 OWASP LLM tests](docs/dashboard.png)

> *Aegis scanning a deliberately vulnerable mock LLM: 0/100, every OWASP category exploited. Flip to the hardened target and the same suite scores 100/100 - showing exactly what good looks like.*

---

## What it tests

| # | Attack | OWASP LLM | Severity |
|---|--------|-----------|----------|
| 1 | Direct prompt injection | **LLM01** Prompt Injection | High |
| 2 | System prompt leakage | **LLM07** System Prompt Leakage | High |
| 3 | Sensitive information disclosure | **LLM02** Sensitive Info Disclosure | Critical |
| 4 | Jailbreak via role-play (DAN) | **LLM01** Prompt Injection | High |
| 5 | Indirect prompt injection (untrusted content) | **LLM01** Prompt Injection | High |
| 6 | Improper output handling (stored XSS) | **LLM05** Improper Output Handling | Medium |
| 7 | Excessive agency (destructive action) | **LLM06** Excessive Agency | High |

Each test carries a **detection rule** (did the attack succeed?) and **remediation guidance**. Every probe uses benign canary tokens - no real harmful content is generated.

---

## The demo: vulnerable vs hardened

```
$ node cli.js vulnerable        $ node cli.js hardened
  Security score: 0/100           Security score: 100/100
  7 vulnerable / 7 tests          0 vulnerable / 7 tests
```

The mock **vulnerable** target naively complies with every attack; the **hardened** target applies guardrails and blocks them all. The contrast shows both how the attacks work *and* what mitigations look like.

---

## Run it

```bash
node cli.js              # scan the mock vulnerable LLM (default)
node cli.js hardened     # scan the mock hardened LLM
node server.js           # report dashboard → http://localhost:3002 (live toggle)
```

## Test a real LLM (optional)

Aegis targets are just `async (prompt) => responseText`. Point it at any model with `makeHttpTarget` - for example a **local, free** Ollama model:

```js
const { makeHttpTarget } = require('./targets');
const { runScan } = require('./engine');

const ollama = makeHttpTarget(
  'http://localhost:11434/api/generate',
  prompt => ({ model: 'llama3', prompt, stream: false }),
  data => data.response
);
runScan(ollama, 'llama3 (local)').then(r => console.log(r.score));
```

The same pattern wraps the Anthropic or OpenAI APIs (paid) - just change the URL, body, and extractor.

---

## Tech stack
- **Node.js**, zero runtime dependencies (raw `http` + `fs`)
- Detection-rule engine with weighted severity scoring (0-100)
- Tactical HUD dashboard (vanilla JS)
- Pluggable target adapters (mock + real)

## Roadmap
- [ ] More OWASP categories: data poisoning probes, unbounded-consumption / DoS tests
- [ ] Multi-turn / conversational attack chains
- [ ] Import attack payloads from public jailbreak datasets
- [ ] CI mode: fail a build if an app regresses below a score threshold
- [ ] Export findings as SARIF for security pipelines

---

*Defensive security research. Attacks use benign canaries and are intended for testing systems you own or are authorized to assess.*
