// LPE-Sentinel real-browser CDP driver.
//
// Drives a headless Chrome instance over the Chrome DevTools Protocol using
// ONLY Node.js built-ins (global fetch + global WebSocket). No npm packages,
// no puppeteer/playwright, no dependency of any kind is installed or required.
//
// This file is a test helper. It is invoked by tests/test_browser_dashboard.py
// as:  node browser_cdp.mjs   (JSON job supplied on stdin)
//
// Input (stdin JSON):
//   {
//     "cdpPort": 9222,
//     "url":     "http://127.0.0.1:8080/",
//     "readyExpr": "<JS expression that must become truthy>",
//     "readyTimeoutMs": 15000,
//     "steps": [ { "expr": "...", "await": true, "label": "..." } ]
//   }
//
// Output: a single line starting with "RESULT" followed by JSON:
//   { "ok": true, "values": [ ... ] }
//   { "ok": false, "error": "..." }

const RESULT_PREFIX = 'RESULT';

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

async function readStdin() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  return Buffer.concat(chunks).toString('utf8');
}

async function attach(cdpPort) {
  // Prefer an existing page target; otherwise ask Chrome to create one.
  const list = await (await fetch(`http://127.0.0.1:${cdpPort}/json/list`)).json();
  let target = list.find((t) => t.type === 'page');
  if (!target) {
    target = await (
      await fetch(`http://127.0.0.1:${cdpPort}/json/new?about:blank`, { method: 'PUT' })
    ).json();
  }
  if (!target || !target.webSocketDebuggerUrl) {
    throw new Error('No CDP page target with a webSocketDebuggerUrl');
  }

  const ws = new WebSocket(target.webSocketDebuggerUrl);
  let nextId = 0;
  const pending = new Map();
  const consoleErrors = [];

  ws.onmessage = (ev) => {
    const msg = JSON.parse(ev.data);
    if (msg.id && pending.has(msg.id)) {
      const { resolve } = pending.get(msg.id);
      pending.delete(msg.id);
      resolve(msg);
      return;
    }
    if (msg.method === 'Runtime.exceptionThrown') {
      const d = msg.params?.exceptionDetails;
      consoleErrors.push(d?.exception?.description || d?.text || 'exception');
    }
  };

  await new Promise((resolve, reject) => {
    ws.onopen = resolve;
    ws.onerror = () => reject(new Error('CDP WebSocket failed to open'));
  });

  const send = (method, params = {}) => {
    const id = ++nextId;
    ws.send(JSON.stringify({ id, method, params }));
    return new Promise((resolve, reject) => {
      pending.set(id, { resolve, reject });
      setTimeout(() => {
        if (pending.has(id)) {
          pending.delete(id);
          reject(new Error(`CDP timeout for ${method}`));
        }
      }, 30000);
    });
  };

  return { ws, send, consoleErrors };
}

async function main() {
  if (typeof WebSocket !== 'function') {
    throw new Error('global WebSocket unavailable (requires Node.js 22 or newer)');
  }

  const job = JSON.parse(await readStdin());
  const { send, ws, consoleErrors } = await attach(job.cdpPort);

  await send('Runtime.enable');
  await send('Page.enable');

  // Evaluate a step expression and return a JSON-serialisable value.
  async function evaluate(expr, useAwait) {
    const res = await send('Runtime.evaluate', {
      expression: expr,
      awaitPromise: !!useAwait,
      returnByValue: true,
    });
    if (res.result?.exceptionDetails) {
      const d = res.result.exceptionDetails;
      const text = d.exception?.description || d.text || 'evaluation error';
      throw new Error(`Step failed: ${String(text).slice(0, 500)}`);
    }
    return res.result?.result?.value;
  }

  await send('Page.navigate', { url: job.url });

  // Wait for the dashboard to finish its initial load.
  const deadline = Date.now() + (job.readyTimeoutMs || 15000);
  let ready = false;
  while (Date.now() < deadline) {
    await sleep(200);
    try {
      if (await evaluate(job.readyExpr, false)) {
        ready = true;
        break;
      }
    } catch {
      /* page still loading; keep polling */
    }
  }
  if (!ready) throw new Error('Dashboard did not become ready before readyTimeoutMs');

  const values = [];
  for (const step of job.steps || []) {
    values.push(await evaluate(step.expr, step.await));
  }

  ws.close();
  return { ok: true, values, consoleErrors };
}

main()
  .then((r) => {
    process.stdout.write(RESULT_PREFIX + JSON.stringify(r));
    process.exit(0);
  })
  .catch((e) => {
    process.stdout.write(RESULT_PREFIX + JSON.stringify({ ok: false, error: e.message }));
    process.exit(0);
  });