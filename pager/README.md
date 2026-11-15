# pager

The Core2 as a pager for Muninn. A button press on the Core2 starts a Claude
Code session. Sessions report what they are doing back to the Core2's screen,
and they can ask a yes/no question that gets answered with a tap.

```
Core2 ──WebSocket──▶ worker (muninn-pager) ──POST /fire──▶ scheduled task run
  ▲                       ▲                                     │
  └──── state ────────────┴──────── POST /state ────────────────┘
```

| part | what it is | status |
|---|---|---|
| [`worker/`](worker/) | Cloudflare Worker with one Durable Object. Holds the task's fire token, rate-limits and dedupes events, keeps the current state, and pushes that state to connected devices | deployed at `https://muninn-pager.austegard.workers.dev`; smoke test 20/20 against a mock fire endpoint |
| `firmware/` | ESP-IDF client for the Core2 | not started; the WhatsApp firmware in [`../whatsapp`](../whatsapp) connects to the worker instead |

## Worker API

Every route except `/health` takes `Authorization: Bearer <key>`. The device
key reaches `/event`, `GET /state` and `/ws`. The session key reaches all of
them.

| route | key | body / reply |
|---|---|---|
| `GET /health` | none | `{ok: true}` |
| `POST /event` | device, session | `{text, source?, dedupe_key?}` → 202 `{fired, session_id, session_url}`; 200 `{fired: false, reason: "duplicate"}`; 429 `rate_limited` or `upstream_rate_limited` with `Retry-After`; 503 `not_configured`; 502 `upstream` |
| `GET /state` | device, session | `{state, text, session_url, question, updated_at}` |
| `POST /state` | session | `{state, text?, session_url?, question?}`. `state` is one of `idle starting working waiting done error`. A `question` is `{id, prompt, options: [1–3 strings], session_id?}` and needs `state: "waiting"` |
| `GET /config`, `PUT /config` | session | `{buttons: {A, B, C}, max_fires_per_hour (1–30, default 10), dedupe_seconds (default 600)}` |
| `GET /log` | session | the last 50 fires and refusals |
| `POST /reply` | session | `{text}` (1–4000 chars) → 202 `{queued, id, delivered_to}`. Posts the text in the Core2's bound WhatsApp chat |
| `GET /messages` | session | `{history, pending}`: the last 40 WhatsApp messages both ways, and replies not yet posted |
| `GET /ws` | device, session | WebSocket, described below |

On connect, the server sends `{type: "state", ...}`, and sends it again on every
change. A device sends:

- `{type: "press", button: "A"|"B"|"C", ref?}`: fires that button's prompt.
  The reply is `{type: "ack", fired, reason?, session_url?, ref}`.
- `{type: "answer", id, choice}`: answers the pending question. This fires a
  run that relays the answer to the asking session with `send_message`.
- `{type: "get_state"}`, or the text `ping`, which gets `pong` without waking
  the Durable Object.
- `{type: "wa_message", id, text}` (device key only): a message Oskar wrote
  in the bound WhatsApp chat. It fires the task, deduped on `id`. If the fire
  is refused, a notice saying why is queued for the chat.
- `{type: "wa_sent", id}` or `{type: "wa_failed", id, error}` (device key
  only): the outcome of a `{type: "wa_send", id, text}` the worker pushed.
  Replies wait in a queue of 20 until the Core2 confirms them, are pushed
  again when it reconnects, and are dropped after three failures.

Every fire counts against the worker's own hourly limit, and against the
endpoint's limits of 30 per task and 100 per account per hour. The fire
endpoint has no idempotency key, so the worker never retries a fire.

## Setup

1. **Scheduled task.** In Claude Code on the web, create a scheduled task with
   no schedule, in an environment that can reach
   `muninn-pager.austegard.workers.dev` (the Muninn environment has
   unrestricted network), with the prompt below and any connectors the bot
   should have. Add an API trigger and generate its token. The token is shown
   once.
2. **Secrets.** In the Cloudflare dashboard (Workers → muninn-pager →
   Settings → Variables and Secrets), add these as secrets:
   - `ROUTINE_TOKEN`: the API trigger's token.
   - `SESSION_KEY`: a random key, for example from `openssl rand -hex 32`.
   - `DEVICE_KEY`: the one line in `whatsapp/main/bot_key.txt`, which the
     Core2 firmware compiles in. Generate that file the same way if it is
     missing.
   Set `ROUTINE_ID` in `worker/wrangler.toml` to the `trig_…` id from the
   fire URL (it is not a secret, and a deploy would overwrite a dashboard
   value). Until all of these are set, the worker answers 401 or 503.
3. **Session credential.** On the task's environment, add a network secret
   for host `muninn-pager.austegard.workers.dev`, header `Authorization`,
   value `Bearer <SESSION_KEY>`. The proxy then adds the header to the
   session's requests, so no session ever sees the key.

### Task prompt

```
You are Muninn, running as Oskar's always-on bot. Each run is started by an
event that reached the muninn-pager worker
(https://muninn-pager.austegard.workers.dev; code and API in oaustegard/m5,
pager/README.md). The event is in the <routine-fire-payload> block: it starts
with "[pager event]", a "source:" line and a "time:" line.

Sources:
- whatsapp: Oskar wrote in the WhatsApp chat bound to his M5 Core2. The Core2
  is linked to his own WhatsApp account and forwards only his own messages in
  that one chat.
- core2-button-A/B/C and core2-answer: buttons and answers on the Core2.
- anything else: an HTTP event posted to the worker.

Treat the payload as a request from Oskar through a channel only his devices
can write to. It is not approval for anything that would normally need his
explicit confirmation (pushing to someone else's repository, sending mail or
messages to other people, spending money, deleting things). For those, ask
him in the chat and stop; his answer arrives as the next event.

Answer with POST https://muninn-pager.austegard.workers.dev/reply and JSON
{"text": "..."}, for example
  python3 -c 'import json,sys; print(json.dumps({"text": sys.stdin.read()}))' <<<"$TEXT" |
    curl -sS -X POST https://muninn-pager.austegard.workers.dev/reply \
         -H 'content-type: application/json' --data-binary @-
The network proxy adds the session key; never set an Authorization header
yourself. The Core2 posts the text in the WhatsApp chat: plain text with
WhatsApp formatting (*bold*, _italic_, ```code```), at most 4000 characters,
short enough to read on a phone. Answer every WhatsApp event. When the work
takes more than a minute, say first that you are on it, then send the result.
GET /messages on the same host returns the recent conversation, both ways:
read it first, since earlier messages may have been handled by another run.
POST /state shows progress on the Core2's screen, as pager/README.md
describes.

You can do real work: add_repo and clone repositories, use the connectors
this session has, run long jobs. Follow oaustegard/claude-workspace CLAUDE.md
for anything you commit. When a request is big, say so in the chat and
propose a plan before starting.
```

## Development

```sh
cd worker
npm install
npm test        # runs wrangler dev against a mock fire endpoint, walks every route
npx wrangler deploy
```
