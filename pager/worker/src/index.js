// muninn-pager: the always-on half of the Core2 pager.
//
// Events (a Core2 button, a tap answering a question, an HTTP POST) arrive
// here, pass a rate limit and a dedupe window, and fire a Claude Code
// scheduled task through its API trigger. Sessions report what they are doing
// back to /state, and every connected Core2 gets that state over a WebSocket.
//
// One Durable Object instance ("main") holds all state, so the rate limit,
// the pending question and the socket list are consistent.
//
// Routes                     auth            purpose
//   GET  /health             none            liveness
//   POST /event              device|session  fire the task with {text}
//   GET  /state              device|session  current state
//   POST /state              session         a session reports state / asks a question
//   GET  /config             session         button prompts, rate limit
//   PUT  /config             session         change them
//   GET  /log                session         recent fires and refusals
//   GET  /ws                 device|session  WebSocket for the Core2
//
// Secrets: DEVICE_KEY, SESSION_KEY, ROUTINE_TOKEN. Vars: ROUTINE_ID,
// FIRE_URL (optional; overrides the Anthropic endpoint, for tests).

import { DurableObject } from "cloudflare:workers";

const STATES = ["idle", "starting", "working", "waiting", "done", "error"];
const BUTTONS = ["A", "B", "C"];
const DEFAULT_CONFIG = {
  buttons: {
    A: "Oskar pressed the check-in button on the Core2. Look at what is open (recent sessions, unread notifications, PRs you are watching), decide what most needs attention, and report on the pager.",
    B: "Oskar pressed button B on the Core2. No action is configured for it yet; report that on the pager and stop.",
    C: "Oskar pressed button C on the Core2. No action is configured for it yet; report that on the pager and stop.",
  },
  max_fires_per_hour: 10,
  dedupe_seconds: 600,
};
const HOUR_MS = 3600_000;
const MAX_TEXT = 8000;
const MAX_STATE_TEXT = 500;
const LOG_KEEP = 50;
const ANTHROPIC_FIRE = "https://api.anthropic.com/v1/claude_code/routines";

const json = (body, status = 200, headers = {}) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", ...headers },
  });

// Constant-time comparison of two strings via their SHA-256 digests, so
// neither length nor prefix leaks through timing.
async function safeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || !b) return false;
  const enc = new TextEncoder();
  const [da, db] = await Promise.all([
    crypto.subtle.digest("SHA-256", enc.encode(a)),
    crypto.subtle.digest("SHA-256", enc.encode(b)),
  ]);
  return crypto.subtle.timingSafeEqual(da, db);
}

// Returns "session", "device" or null.
async function whoIs(request, env) {
  const h = request.headers.get("authorization") || "";
  const m = h.match(/^Bearer\s+(.+)$/i);
  if (!m) return null;
  const key = m[1].trim();
  if (await safeEqual(key, env.SESSION_KEY)) return "session";
  if (await safeEqual(key, env.DEVICE_KEY)) return "device";
  return null;
}

async function sha256Hex(s) {
  const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function readJson(request) {
  try {
    return await request.json();
  } catch {
    return undefined;
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === "/health" && request.method === "GET") {
      return json({ ok: true });
    }
    const role = await whoIs(request, env);
    if (!role) return json({ error: "unauthorized" }, 401);
    const stub = env.PAGER.get(env.PAGER.idFromName("main"));
    // The DO trusts this header only because nothing reaches it except
    // through this function.
    const fwd = new Request(request);
    fwd.headers.set("x-pager-role", role);
    return stub.fetch(fwd);
  },
};

export class Pager extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.env = env;
    this.ctx.setWebSocketAutoResponse(new WebSocketRequestResponsePair("ping", "pong"));
  }

  async config() {
    const stored = (await this.ctx.storage.get("config")) || {};
    return {
      ...DEFAULT_CONFIG,
      ...stored,
      buttons: { ...DEFAULT_CONFIG.buttons, ...(stored.buttons || {}) },
    };
  }

  async state() {
    return (
      (await this.ctx.storage.get("state")) || {
        state: "idle",
        text: "",
        session_url: null,
        question: null,
        updated_at: null,
      }
    );
  }

  async setState(patch) {
    const next = { ...(await this.state()), ...patch, updated_at: new Date().toISOString() };
    await this.ctx.storage.put("state", next);
    this.broadcast({ type: "state", ...next });
    return next;
  }

  broadcast(msg) {
    const s = JSON.stringify(msg);
    for (const ws of this.ctx.getWebSockets()) {
      try {
        ws.send(s);
      } catch {
        // A dead socket is cleaned up by webSocketClose/Error.
      }
    }
  }

  async log(entry) {
    const log = (await this.ctx.storage.get("log")) || [];
    log.unshift({ at: new Date().toISOString(), ...entry });
    await this.ctx.storage.put("log", log.slice(0, LOG_KEEP));
  }

  // Rate limit, dedupe, then POST to the task's fire endpoint.
  // Returns {fired, reason?, retry_after?, session_id?, session_url?, status?}.
  async fire(source, text, dedupeKey) {
    const cfg = await this.config();
    const now = Date.now();

    const recent = ((await this.ctx.storage.get("fires")) || []).filter((t) => now - t < HOUR_MS);
    if (recent.length >= cfg.max_fires_per_hour) {
      const retry_after = Math.ceil((recent[0] + HOUR_MS - now) / 1000);
      await this.log({ source, fired: false, reason: "rate_limited" });
      return { fired: false, reason: "rate_limited", retry_after };
    }

    const dkey = dedupeKey || (await sha256Hex(`${source}\n${text}`));
    const seen = (await this.ctx.storage.get("dedupe")) || {};
    for (const [k, t] of Object.entries(seen)) {
      if (now - t > cfg.dedupe_seconds * 1000) delete seen[k];
    }
    if (seen[dkey]) {
      await this.log({ source, fired: false, reason: "duplicate" });
      return { fired: false, reason: "duplicate" };
    }

    if (!this.env.ROUTINE_TOKEN || !(this.env.ROUTINE_ID || this.env.FIRE_URL)) {
      await this.log({ source, fired: false, reason: "not_configured" });
      return { fired: false, reason: "not_configured" };
    }

    // The task's prompt says this block is untrusted event data.
    const body = {
      text: [
        "[pager event]",
        `source: ${source}`,
        `time: ${new Date(now).toISOString()}`,
        "---",
        text,
      ].join("\n"),
    };
    const fireUrl = this.env.FIRE_URL || `${ANTHROPIC_FIRE}/${this.env.ROUTINE_ID}/fire`;
    let res;
    try {
      res = await fetch(fireUrl, {
        method: "POST",
        headers: {
          authorization: `Bearer ${this.env.ROUTINE_TOKEN}`,
          "anthropic-version": "2023-06-01",
          "anthropic-beta": "experimental-cc-routine-2026-04-01",
          "content-type": "application/json",
        },
        body: JSON.stringify(body),
      });
    } catch (e) {
      await this.log({ source, fired: false, reason: "upstream_unreachable" });
      return { fired: false, reason: "upstream_unreachable" };
    }

    if (!res.ok) {
      const retry = res.headers.get("retry-after");
      const detail = (await res.text()).slice(0, 300);
      const reason = res.status === 429 ? "upstream_rate_limited" : "upstream";
      await this.log({ source, fired: false, reason, status: res.status, detail });
      return {
        fired: false,
        reason,
        status: res.status,
        ...(retry && Number.isFinite(Number(retry)) ? { retry_after: Number(retry) } : {}),
      };
    }

    const out = (await res.json().catch(() => null)) || {};
    // Field names per the fire endpoint docs; tolerate either flat or nested.
    const session_id = out.claude_code_session_id || out.session_id || out.session?.id || null;
    const session_url = out.claude_code_session_url || out.session_url || out.session?.url || null;

    recent.push(now);
    seen[dkey] = now;
    await this.ctx.storage.put("fires", recent);
    await this.ctx.storage.put("dedupe", seen);
    await this.log({ source, fired: true, session_id, session_url });
    await this.setState({
      state: "starting",
      text: `${source}: ${text.split("\n")[0].slice(0, 120)}`,
      session_url,
      question: null,
    });
    return { fired: true, session_id, session_url };
  }

  async fetch(request) {
    const url = new URL(request.url);
    const role = request.headers.get("x-pager-role");
    const route = `${request.method} ${url.pathname}`;

    if (url.pathname === "/ws") {
      if (request.headers.get("upgrade")?.toLowerCase() !== "websocket") {
        return json({ error: "expected websocket upgrade" }, 426);
      }
      const { 0: client, 1: server } = new WebSocketPair();
      this.ctx.acceptWebSocket(server, [role]);
      server.send(JSON.stringify({ type: "state", ...(await this.state()) }));
      return new Response(null, { status: 101, webSocket: client });
    }

    switch (route) {
      case "POST /event": {
        const b = await readJson(request);
        if (!b || typeof b.text !== "string" || !b.text.trim() || b.text.length > MAX_TEXT) {
          return json({ error: `body must be {text: string, 1..${MAX_TEXT} chars}` }, 400);
        }
        const source = typeof b.source === "string" && b.source ? b.source.slice(0, 64) : `http-${role}`;
        const r = await this.fire(source, b.text, typeof b.dedupe_key === "string" ? b.dedupe_key : null);
        return json(r, statusFor(r), r.retry_after ? { "retry-after": String(r.retry_after) } : {});
      }

      case "GET /state":
        return json(await this.state());

      case "POST /state": {
        if (role !== "session") return json({ error: "session key required" }, 403);
        const b = await readJson(request);
        const err = validateState(b);
        if (err) return json({ error: err }, 400);
        const patch = { state: b.state };
        if ("text" in b) patch.text = b.text;
        if ("session_url" in b) patch.session_url = b.session_url;
        if ("question" in b) patch.question = b.question;
        // A new state without a question clears any pending one unless the
        // caller is explicitly waiting on it.
        if (!("question" in b) && b.state !== "waiting") patch.question = null;
        return json(await this.setState(patch));
      }

      case "GET /config":
        if (role !== "session") return json({ error: "session key required" }, 403);
        return json(await this.config());

      case "PUT /config": {
        if (role !== "session") return json({ error: "session key required" }, 403);
        const b = await readJson(request);
        const err = validateConfig(b);
        if (err) return json({ error: err }, 400);
        const stored = (await this.ctx.storage.get("config")) || {};
        const next = {
          ...stored,
          ...b,
          buttons: { ...(stored.buttons || {}), ...(b.buttons || {}) },
        };
        await this.ctx.storage.put("config", next);
        return json(await this.config());
      }

      case "GET /log":
        if (role !== "session") return json({ error: "session key required" }, 403);
        return json((await this.ctx.storage.get("log")) || []);
    }
    return json({ error: "not found" }, 404);
  }

  async webSocketMessage(ws, raw) {
    let m;
    try {
      m = JSON.parse(typeof raw === "string" ? raw : new TextDecoder().decode(raw));
    } catch {
      return ws.send(JSON.stringify({ type: "error", error: "invalid json" }));
    }
    const reply = (o) => ws.send(JSON.stringify({ ...o, ref: m.ref ?? null }));

    if (m.type === "press") {
      if (!BUTTONS.includes(m.button)) return reply({ type: "error", error: "button must be A, B or C" });
      const cfg = await this.config();
      const r = await this.fire(`core2-button-${m.button}`, cfg.buttons[m.button], null);
      return reply({ type: "ack", ...r });
    }

    if (m.type === "answer") {
      const st = await this.state();
      const q = st.question;
      if (!q || q.id !== m.id) return reply({ type: "error", error: "no pending question with that id" });
      if (!q.options.includes(m.choice)) return reply({ type: "error", error: "choice is not one of the options" });
      const text = [
        `Oskar answered a question on the Core2.`,
        `question id: ${q.id}`,
        `question: ${q.prompt}`,
        `answer: ${m.choice}`,
        q.session_id ? `asked by session: ${q.session_id}` : "asked by session: unknown",
        "If a session is named, relay the answer to it with send_message and stop; otherwise act on the answer.",
      ].join("\n");
      // The answer is unique per question, so dedupe on the question id.
      const r = await this.fire("core2-answer", text, `answer:${q.id}`);
      return reply({ type: "ack", ...r });
    }

    if (m.type === "get_state") {
      return ws.send(JSON.stringify({ type: "state", ...(await this.state()) }));
    }

    reply({ type: "error", error: "unknown message type" });
  }

  async webSocketClose(ws, code, reason) {
    try {
      ws.close(code, reason);
    } catch {}
  }

  async webSocketError(ws) {
    try {
      ws.close(1011, "error");
    } catch {}
  }
}

function statusFor(r) {
  if (r.fired) return 202;
  if (r.reason === "duplicate") return 200;
  if (r.reason === "rate_limited" || r.reason === "upstream_rate_limited") return 429;
  if (r.reason === "not_configured") return 503;
  return 502;
}

function validateState(b) {
  if (!b || typeof b !== "object") return "body must be a JSON object";
  if (!STATES.includes(b.state)) return `state must be one of ${STATES.join(", ")}`;
  if ("text" in b && (typeof b.text !== "string" || b.text.length > MAX_STATE_TEXT)) {
    return `text must be a string of at most ${MAX_STATE_TEXT} chars`;
  }
  if ("session_url" in b && b.session_url !== null && typeof b.session_url !== "string") {
    return "session_url must be a string or null";
  }
  if ("question" in b && b.question !== null) {
    const q = b.question;
    if (typeof q !== "object") return "question must be an object or null";
    if (typeof q.id !== "string" || !q.id || q.id.length > 64) return "question.id must be a 1..64 char string";
    if (typeof q.prompt !== "string" || !q.prompt || q.prompt.length > 200) return "question.prompt must be a 1..200 char string";
    if (!Array.isArray(q.options) || q.options.length < 1 || q.options.length > 3) {
      return "question.options must hold 1 to 3 strings (buttons A, B, C)";
    }
    if (!q.options.every((o) => typeof o === "string" && o && o.length <= 24)) {
      return "each option must be a 1..24 char string";
    }
    if ("session_id" in q && typeof q.session_id !== "string") return "question.session_id must be a string";
    if (b.state !== "waiting") return "a question needs state 'waiting'";
  }
  return null;
}

function validateConfig(b) {
  if (!b || typeof b !== "object") return "body must be a JSON object";
  for (const k of Object.keys(b)) {
    if (!["buttons", "max_fires_per_hour", "dedupe_seconds"].includes(k)) return `unknown key ${k}`;
  }
  if ("buttons" in b) {
    if (typeof b.buttons !== "object" || b.buttons === null) return "buttons must be an object";
    for (const [k, v] of Object.entries(b.buttons)) {
      if (!BUTTONS.includes(k)) return "buttons keys must be A, B or C";
      if (typeof v !== "string" || !v || v.length > MAX_TEXT) return `button ${k} prompt must be a 1..${MAX_TEXT} char string`;
    }
  }
  if ("max_fires_per_hour" in b) {
    const n = b.max_fires_per_hour;
    if (!Number.isInteger(n) || n < 1 || n > 30) return "max_fires_per_hour must be an integer 1..30";
  }
  if ("dedupe_seconds" in b) {
    const n = b.dedupe_seconds;
    if (!Number.isInteger(n) || n < 0 || n > 86400) return "dedupe_seconds must be an integer 0..86400";
  }
  return null;
}
