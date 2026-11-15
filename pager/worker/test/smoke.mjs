// End-to-end smoke test: runs the worker under `wrangler dev` with a mock fire
// endpoint and walks every route. Run with `npm test`. Needs no Cloudflare or
// Anthropic credentials.

import { spawn } from "node:child_process";
import { createServer, request as httpRequest } from "node:http";
import { writeFileSync, rmSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import assert from "node:assert/strict";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const WORKER_PORT = 8790;
const MOCK_PORT = 8791;
const DEVICE = "test-device-key";
const SESSION = "test-session-key";
const BASE = `http://127.0.0.1:${WORKER_PORT}`;

// Mock of the fire endpoint. Records requests; answers like the real one.
const fires = [];
let mockStatus = 200;
const mock = createServer((req, res) => {
  let body = "";
  req.on("data", (c) => (body += c));
  req.on("end", () => {
    fires.push({ headers: req.headers, body: JSON.parse(body || "{}") });
    if (mockStatus !== 200) {
      res.writeHead(mockStatus, { "content-type": "application/json", "retry-after": "120" });
      return res.end(JSON.stringify({ type: "error", error: { type: "rate_limit_error", message: "x" } }));
    }
    const n = fires.length;
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({
      type: "routine_fire",
      claude_code_session_id: `session_test${n}`,
      claude_code_session_url: `https://claude.ai/code/session_test${n}`,
    }));
  });
});
await new Promise((r) => mock.listen(MOCK_PORT, "127.0.0.1", r));

writeFileSync(join(root, ".dev.vars"),
  `DEVICE_KEY=${DEVICE}\nSESSION_KEY=${SESSION}\nROUTINE_TOKEN=sk-ant-oat01-test\n`);
rmSync(join(root, ".wrangler", "state"), { recursive: true, force: true });

const dev = spawn("npx", ["wrangler", "dev", "--port", String(WORKER_PORT), "--ip", "127.0.0.1",
  "--var", `FIRE_URL:http://127.0.0.1:${MOCK_PORT}/fire`, "--var", "ROUTINE_ID:trig_test"],
  { cwd: root, stdio: ["ignore", "pipe", "pipe"], env: { ...process.env, NO_PROXY: "127.0.0.1,localhost", no_proxy: "127.0.0.1,localhost" } });
let devLog = "";
dev.stdout.on("data", (d) => (devLog += d));
dev.stderr.on("data", (d) => (devLog += d));

const call = (method, path, { key, body } = {}) =>
  fetch(BASE + path, {
    method,
    headers: { ...(key ? { authorization: `Bearer ${key}` } : {}), "content-type": "application/json" },
    body: body === undefined ? undefined : typeof body === "string" ? body : JSON.stringify(body),
  }).then(async (r) => ({ status: r.status, headers: r.headers, body: await r.json() }));

async function waitReady() {
  for (let i = 0; i < 120; i++) {
    try {
      const r = await fetch(BASE + "/health");
      if (r.ok) return;
    } catch {}
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error("wrangler dev did not start:\n" + devLog);
}

function openWs(key) {
  return new Promise((resolve, reject) => {
    // undici's WebSocket (Node's global) takes a non-standard headers option.
    const ws = new WebSocket(`ws://127.0.0.1:${WORKER_PORT}/ws`, { headers: { authorization: `Bearer ${key}` } });
    const queue = [];
    const waiters = [];
    ws.onmessage = (e) => {
      const m = JSON.parse(e.data);
      const w = waiters.shift();
      w ? w(m) : queue.push(m);
    };
    ws.onerror = (e) => reject(new Error("ws error " + (e.message || "")));
    ws.onopen = () =>
      resolve({
        ws,
        next: () => new Promise((r) => (queue.length ? r(queue.shift()) : waiters.push(r))),
        send: (o) => ws.send(JSON.stringify(o)),
        raw: (s) => ws.send(s),
      });
  });
}

const results = [];
async function check(name, fn) {
  try {
    await fn();
    results.push(["ok", name]);
  } catch (e) {
    results.push(["FAIL", name, e.message]);
  }
}

try {
  await waitReady();

  await check("GET /health 200 without auth", async () => {
    const r = await call("GET", "/health");
    assert.equal(r.status, 200);
    assert.deepEqual(r.body, { ok: true });
  });

  await check("401 without key, 401 with wrong key", async () => {
    assert.equal((await call("GET", "/state")).status, 401);
    assert.equal((await call("GET", "/state", { key: "nope" })).status, 401);
  });

  await check("GET /state initial idle (device)", async () => {
    const r = await call("GET", "/state", { key: DEVICE });
    assert.equal(r.status, 200);
    assert.equal(r.body.state, "idle");
  });

  await check("device cannot POST /state, GET /config, GET /log", async () => {
    assert.equal((await call("POST", "/state", { key: DEVICE, body: { state: "idle" } })).status, 403);
    assert.equal((await call("GET", "/config", { key: DEVICE })).status, 403);
    assert.equal((await call("GET", "/log", { key: DEVICE })).status, 403);
  });

  await check("POST /event rejects bad bodies with 400", async () => {
    assert.equal((await call("POST", "/event", { key: DEVICE, body: "not json" })).status, 400);
    assert.equal((await call("POST", "/event", { key: DEVICE, body: {} })).status, 400);
    assert.equal((await call("POST", "/event", { key: DEVICE, body: { text: "  " } })).status, 400);
    assert.equal((await call("POST", "/event", { key: DEVICE, body: { text: "x".repeat(8001) } })).status, 400);
    assert.equal(fires.length, 0);
  });

  await check("POST /event fires 202 with session id/url and correct upstream request", async () => {
    const r = await call("POST", "/event", { key: DEVICE, body: { text: "hello pager", source: "test" } });
    assert.equal(r.status, 202, JSON.stringify(r.body));
    assert.equal(r.body.fired, true);
    assert.equal(r.body.session_id, "session_test1");
    assert.equal(r.body.session_url, "https://claude.ai/code/session_test1");
    const f = fires.at(-1);
    assert.equal(f.headers.authorization, "Bearer sk-ant-oat01-test");
    assert.equal(f.headers["anthropic-version"], "2023-06-01");
    assert.match(f.body.text, /^\[pager event\]\nsource: test\ntime: .+\n---\nhello pager$/);
  });

  await check("state becomes 'starting' with session_url after a fire", async () => {
    const r = await call("GET", "/state", { key: DEVICE });
    assert.equal(r.body.state, "starting");
    assert.equal(r.body.session_url, "https://claude.ai/code/session_test1");
  });

  await check("duplicate event within window is not fired (200, duplicate)", async () => {
    const n = fires.length;
    const r = await call("POST", "/event", { key: DEVICE, body: { text: "hello pager", source: "test" } });
    assert.equal(r.status, 200);
    assert.deepEqual(r.body, { fired: false, reason: "duplicate" });
    assert.equal(fires.length, n);
  });

  await check("PUT /config validates and applies", async () => {
    assert.equal((await call("PUT", "/config", { key: SESSION, body: { max_fires_per_hour: 99 } })).status, 400);
    assert.equal((await call("PUT", "/config", { key: SESSION, body: { buttons: { D: "x" } } })).status, 400);
    assert.equal((await call("PUT", "/config", { key: SESSION, body: { bogus: 1 } })).status, 400);
    const r = await call("PUT", "/config", { key: SESSION, body: { max_fires_per_hour: 4, buttons: { B: "custom B" } } });
    assert.equal(r.status, 200);
    assert.equal(r.body.max_fires_per_hour, 4);
    assert.equal(r.body.buttons.B, "custom B");
    assert.match(r.body.buttons.A, /check-in/);
  });

  // WebSocket section
  let dev1;
  await check("WS rejects bad key, accepts device key and sends state on connect", async () => {
    // fetch() forbids the upgrade header, so probe the refusal with node:http.
    const badStatus = await new Promise((resolve, reject) => {
      const req = httpRequest(`${BASE}/ws`, {
        headers: { connection: "Upgrade", upgrade: "websocket", "sec-websocket-version": "13",
          "sec-websocket-key": "dGhlIHNhbXBsZSBub25jZQ==", authorization: "Bearer nope" },
      });
      req.on("response", (res) => { res.resume(); resolve(res.statusCode); });
      req.on("upgrade", () => resolve(101));
      req.on("error", reject);
      req.end();
    });
    assert.equal(badStatus, 401);
    dev1 = await openWs(DEVICE);
    const m = await dev1.next();
    assert.equal(m.type, "state");
    assert.equal(m.state, "starting");
  });

  await check("WS press B fires the configured prompt and acks", async () => {
    dev1.send({ type: "press", button: "B", ref: 7 });
    const msgs = [await dev1.next(), await dev1.next()];
    const ack = msgs.find((m) => m.type === "ack");
    const st = msgs.find((m) => m.type === "state");
    assert.ok(ack && ack.fired && ack.ref === 7, JSON.stringify(msgs));
    assert.ok(st && st.state === "starting");
    assert.match(fires.at(-1).body.text, /source: core2-button-B\n.*\n---\ncustom B$/s);
  });

  await check("WS invalid json / unknown type / bad button give errors", async () => {
    dev1.raw("{nope");
    assert.equal((await dev1.next()).type, "error");
    dev1.send({ type: "dance" });
    assert.equal((await dev1.next()).type, "error");
    dev1.send({ type: "press", button: "Z" });
    assert.equal((await dev1.next()).type, "error");
  });

  await check("POST /state validates question shape", async () => {
    const bad = [
      { state: "sleeping" },
      { state: "working", text: "x".repeat(501) },
      { state: "working", question: { id: "q", prompt: "p", options: ["a"] } },
      { state: "waiting", question: { id: "q", prompt: "p", options: [] } },
      { state: "waiting", question: { id: "q", prompt: "p", options: ["a", "b", "c", "d"] } },
      { state: "waiting", question: { id: "", prompt: "p", options: ["a"] } },
    ];
    for (const b of bad) assert.equal((await call("POST", "/state", { key: SESSION, body: b })).status, 400, JSON.stringify(b));
  });

  await check("POST /state with question broadcasts to the device", async () => {
    const r = await call("POST", "/state", {
      key: SESSION,
      body: {
        state: "waiting",
        text: "need a call",
        question: { id: "q1", prompt: "Merge the PR?", options: ["yes", "no"], session_id: "session_asker" },
      },
    });
    assert.equal(r.status, 200);
    const m = await dev1.next();
    assert.equal(m.type, "state");
    assert.equal(m.question.id, "q1");
  });

  await check("WS answer validates id and choice", async () => {
    dev1.send({ type: "answer", id: "q-wrong", choice: "yes" });
    assert.equal((await dev1.next()).type, "error");
    dev1.send({ type: "answer", id: "q1", choice: "maybe" });
    assert.equal((await dev1.next()).type, "error");
  });

  await check("WS answer fires a relay and clears the question", async () => {
    dev1.send({ type: "answer", id: "q1", choice: "yes" });
    const msgs = [await dev1.next(), await dev1.next()];
    const ack = msgs.find((m) => m.type === "ack");
    const st = msgs.find((m) => m.type === "state");
    assert.ok(ack && ack.fired, JSON.stringify(msgs));
    assert.equal(st.question, null);
    const t = fires.at(-1).body.text;
    assert.match(t, /question: Merge the PR\?/);
    assert.match(t, /answer: yes/);
    assert.match(t, /asked by session: session_asker/);
  });

  await check("rate limit: 4/hour -> 5th fire is 429 with retry-after", async () => {
    // Fires so far: event, press B, answer = 3. One more allowed.
    const ok = await call("POST", "/event", { key: SESSION, body: { text: "fourth" } });
    assert.equal(ok.status, 202, JSON.stringify(ok.body));
    const n = fires.length;
    const r = await call("POST", "/event", { key: SESSION, body: { text: "fifth" } });
    assert.equal(r.status, 429);
    assert.equal(r.body.reason, "rate_limited");
    assert.ok(Number(r.headers.get("retry-after")) > 0);
    assert.equal(fires.length, n);
  });

  await check("upstream 429 maps to upstream_rate_limited, not counted", async () => {
    await call("PUT", "/config", { key: SESSION, body: { max_fires_per_hour: 30 } });
    mockStatus = 429;
    const r = await call("POST", "/event", { key: SESSION, body: { text: "upstream busy" } });
    assert.equal(r.status, 429);
    assert.equal(r.body.reason, "upstream_rate_limited");
    assert.equal(r.body.retry_after, 120);
    mockStatus = 200;
    // Not deduped: the same text fires once upstream recovers.
    const again = await call("POST", "/event", { key: SESSION, body: { text: "upstream busy" } });
    assert.equal(again.status, 202);
  });

  await check("GET /log records fires and refusals", async () => {
    const r = await call("GET", "/log", { key: SESSION });
    assert.equal(r.status, 200);
    const reasons = r.body.map((e) => e.reason || "fired");
    for (const want of ["fired", "duplicate", "rate_limited", "upstream_rate_limited"]) {
      assert.ok(reasons.includes(want), `log missing ${want}: ${reasons}`);
    }
  });

  await check("unknown route 404", async () => {
    assert.equal((await call("GET", "/nope", { key: SESSION })).status, 404);
  });

  dev1?.ws.close();
} finally {
  dev.kill("SIGTERM");
  mock.close();
  rmSync(join(root, ".dev.vars"), { force: true });
}

for (const [s, n, e] of results) console.log(`${s.padEnd(4)} ${n}${e ? `\n     ${e}` : ""}`);
const failed = results.filter((r) => r[0] === "FAIL").length;
console.log(`\n${results.length - failed}/${results.length} passed`);
process.exit(failed ? 1 : 0);
