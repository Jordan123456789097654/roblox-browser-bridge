'use strict';

const http = require('http');
const crypto = require('crypto');
const { URL } = require('url');
const puppeteer = require('puppeteer');
const sharp = require('sharp');

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const CFG = Object.freeze({
  port: Number(process.env.PORT) || 8080,
  bridgeKey: process.env.BRIDGE_KEY || '',

  viewport: { width: 1280, height: 800 },
  out: { w: 480, h: 300 },
  tile: 20,
  maxFps: 8,
  idleFps: 2,
  idleAfterFrames: 16,

  maxSessions: 8,
  maxQueuedOps: 64,
  sessionIdleMs: 120_000,
  inputPerSec: 120,
  maxTypeChars: 256,
  tilesPerChunk: 16,

  // Outbox limits for frames waiting to be picked up by Roblox's /sync polls.
  outboxMaxMessages: 2000,
  outboxMaxBytes: 4 * 1024 * 1024,
  syncMaxBytes: 512 * 1024,

  // Blocked hosts. Every http(s) URL is allowed unless its hostname matches one of these.
  // Loopback, private, and link-local addresses are always blocked (SSRF protection).
  blockedHosts: [
    /(^|\.)localhost$/i,
    /\.(local|internal|lan)$/i,
    /^metadata\.google\.internal$/i,
    /^0\.0\.0\.0$/,
    /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/,
    /^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$/,
    /^192\.168\.\d{1,3}\.\d{1,3}$/,
    /^172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}$/,
    /^169\.254\.\d{1,3}\.\d{1,3}$/,
    /^(::1|f[cd][0-9a-f]{0,2}:|fe80:)/i,
    // Add your own blocked domains here, for example:
    // /(^|\.)badsite\.example$/i,
  ],
});

const TILE_BYTES = CFG.tile * CFG.tile * 4;
const TILES_X = CFG.out.w / CFG.tile;
const TILES_Y = CFG.out.h / CFG.tile;
const TILE_COUNT = TILES_X * TILES_Y;

if (!Number.isInteger(TILES_X) || !Number.isInteger(TILES_Y)) {
  throw new Error('out.w and out.h must be divisible by tile size');
}

const ALLOWED_INPUT = new Set([
  'mdown', 'mmove', 'mup', 'wheel', 'text', 'key', 'back', 'forward', 'reload',
]);
const PLAIN_KEYS = new Set([
  'Backspace', 'Enter', 'Tab', 'Escape', 'Delete', 'Home', 'End',
  'PageUp', 'PageDown', 'ArrowUp', 'ArrowDown', 'ArrowLeft', 'ArrowRight',
]);
const CTRL_KEYS = new Set(['a', 'c', 'v', 'x', 'z', 'y', 'f']);

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const log = (...args) => console.log(new Date().toISOString(), ...args);
const clamp01 = (n) => (typeof n === 'number' && Number.isFinite(n) ? Math.min(1, Math.max(0, n)) : 0);
const clampNum = (n, lo, hi) => (typeof n === 'number' && Number.isFinite(n) ? Math.min(hi, Math.max(lo, n)) : 0);

const LOCAL_SCHEMES = new Set(['data:', 'blob:', 'about:']);

function isBlockedUrl(raw) {
  let u;
  try { u = new URL(raw); } catch { return true; }
  if (LOCAL_SCHEMES.has(u.protocol)) return false;
  if (u.protocol !== 'https:' && u.protocol !== 'http:') return true;
  const host = u.hostname.replace(/^\[|\]$/g, '');
  return CFG.blockedHosts.some((re) => re.test(host));
}

function keyOk(provided) {
  if (!provided || !CFG.bridgeKey) return false;
  const a = Buffer.from(String(provided));
  const b = Buffer.from(CFG.bridgeKey);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

// ---------------------------------------------------------------------------
// Browser
// ---------------------------------------------------------------------------

let browser = null;

function launchBrowser() {
  return puppeteer.launch({
    headless: true,
    defaultViewport: null,
    args: [
      '--no-sandbox',
      '--use-gl=angle',
      '--use-angle=swiftshader',
      '--enable-gpu',
      '--disable-dev-shm-usage',
      '--disable-background-timer-throttling',
      '--disable-renderer-backgrounding',
      '--disable-features=Translate,MediaRouter',
      '--mute-audio',
    ],
  });
}

// ---------------------------------------------------------------------------
// Session model
// ---------------------------------------------------------------------------

class Session {
  constructor(sid, context, page, cdp) {
    this.sid = sid;
    this.context = context;
    this.page = page;
    this.cdp = cdp;
    this.hashes = new Float64Array(TILE_COUNT).fill(-1);
    this.frameId = 0;
    this.idleFrames = 0;
    this.lastSeen = Date.now();
    this.alive = true;
    this.queue = Promise.resolve();
    this.depth = 0;
    this.winStart = 0;
    this.winCount = 0;
    this.loop = null;
  }
}

const sessions = new Map();
const pending = new Map();

function onRequest(req) {
  if (isBlockedUrl(req.url())) req.abort('blockedbyclient').catch(() => {});
  else req.continue().catch(() => {});
}

async function createSession(sid) {
  const context = await browser.createBrowserContext();
  try {
    const page = await context.newPage();
    await page.setViewport(CFG.viewport);
    await page.setRequestInterception(true);
    page.on('request', onRequest);
    page.on('dialog', (d) => d.dismiss().catch(() => {}));
    const cdp = await page.createCDPSession();
    const s = new Session(sid, context, page, cdp);
    sessions.set(sid, s);
    s.loop = runLoop(s);
    return s;
  } catch (err) {
    await context.close().catch(() => {});
    throw err;
  }
}

function getSession(sid) {
  const existing = sessions.get(sid);
  if (existing) {
    existing.lastSeen = Date.now();
    return Promise.resolve(existing);
  }
  if (pending.has(sid)) return pending.get(sid);
  if (sessions.size + pending.size >= CFG.maxSessions) {
    return Promise.reject(new Error('session limit reached'));
  }
  const p = createSession(sid).finally(() => pending.delete(sid));
  pending.set(sid, p);
  return p;
}

async function destroySession(sid) {
  const s = sessions.get(sid);
  if (!s) return;
  s.alive = false;
  sessions.delete(sid);
  await s.context.close().catch(() => {});
}

function sweepIdle() {
  const now = Date.now();
  for (const s of sessions.values()) {
    if (now - s.lastSeen > CFG.sessionIdleMs) destroySession(s.sid);
  }
}

function allowInput(s) {
  const now = Date.now();
  if (now - s.winStart >= 1000) {
    s.winStart = now;
    s.winCount = 0;
  }
  return ++s.winCount <= CFG.inputPerSec;
}

function enqueue(s, fn) {
  if (s.depth >= CFG.maxQueuedOps) return Promise.resolve();
  s.depth++;
  s.queue = s.queue
    .then(fn)
    .catch((err) => { if (s.alive) log('op', s.sid, err.message); })
    .finally(() => { s.depth--; });
  return s.queue;
}

// ---------------------------------------------------------------------------
// Outbox (Roblox collects these via POST /sync)
// ---------------------------------------------------------------------------

let outbox = [];
let outboxBytes = 0;
let lastSyncAt = 0;

function sendToBridge(obj) {
  const line = JSON.stringify(obj);
  if (outbox.length >= CFG.outboxMaxMessages) return false;
  if (outboxBytes + line.length > CFG.outboxMaxBytes) return false;
  outbox.push(line);
  outboxBytes += line.length;
  return true;
}

// Takes as many queued messages as fit under syncMaxBytes. Always takes at least one
// so an oversized message can't block the queue forever.
function drainOutbox() {
  let size = 0;
  let n = 0;
  while (n < outbox.length && size + outbox[n].length <= CFG.syncMaxBytes) {
    size += outbox[n].length;
    n++;
  }
  if (n === 0 && outbox.length) n = 1;
  const taken = outbox.splice(0, n);
  for (const line of taken) outboxBytes -= line.length;
  return taken;
}

function sendStatus(s, extra = {}) {
  if (!s.alive) return Promise.resolve();
  return (async () => {
    let canBack = false;
    let canForward = false;
    try {
      const h = await s.cdp.send('Page.getNavigationHistory');
      canBack = h.currentIndex > 0;
      canForward = h.currentIndex < h.entries.length - 1;
    } catch { /* page may be mid-navigation */ }
    const title = await s.page.title().catch(() => '');
    sendToBridge({
      sid: s.sid,
      t: 'status',
      state: 'ready',
      url: s.page.url(),
      title: String(title).slice(0, 120),
      canBack,
      canForward,
      ...extra,
    });
  })();
}

function navigate(s, raw) {
  if (!/^https?:\/\//i.test(raw) || isBlockedUrl(raw)) {
    return sendStatus(s, { state: 'blocked', reason: 'Blocked URL' });
  }
  return enqueue(s, async () => {
    sendStatus(s, { state: 'loading' });
    try {
      await s.page.goto(raw, { waitUntil: 'domcontentloaded', timeout: 20000 });
    } catch (err) {
      return sendStatus(s, { state: 'error', reason: String(err.message).slice(0, 200) });
    }
    s.idleFrames = 0;
    return sendStatus(s);
  });
}

function toPx(n, max) {
  return Math.round(clamp01(n) * max);
}

function dispatchInput(s, m) {
  const x = toPx(m.x, CFG.viewport.width);
  const y = toPx(m.y, CFG.viewport.height);

  switch (m.t) {
    case 'mdown':
      return enqueue(s, async () => {
        await s.page.mouse.move(x, y);
        await s.page.mouse.down();
      });

    case 'mmove':
      return enqueue(s, () => s.page.mouse.move(x, y));

    case 'mup':
      return enqueue(s, async () => {
        await s.page.mouse.move(x, y);
        await s.page.mouse.up();
      });

    case 'wheel':
      return enqueue(s, async () => {
        await s.page.mouse.move(x, y);
        await s.page.mouse.wheel({
          deltaX: clampNum(m.dx, -4000, 4000),
          deltaY: clampNum(m.dy, -4000, 4000),
        });
      });

    case 'text': {
      const chars = Array.from(String(m.s ?? '')).slice(0, CFG.maxTypeChars);
      return enqueue(s, async () => {
        for (const ch of chars) await s.page.keyboard.sendCharacter(ch);
      });
    }

    case 'key': {
      const key = m.k;
      if (m.ctrl) {
        if (!CTRL_KEYS.has(key)) return;
        return enqueue(s, async () => {
          await s.page.keyboard.down('Control');
          try { await s.page.keyboard.press(key); }
          finally { await s.page.keyboard.up('Control'); }
        });
      }
      if (!PLAIN_KEYS.has(key)) return;
      return enqueue(s, () => s.page.keyboard.press(key));
    }

    case 'back':
      return enqueue(s, async () => {
        await s.page.goBack({ waitUntil: 'domcontentloaded', timeout: 10000 }).catch(() => {});
        await sendStatus(s);
      });

    case 'forward':
      return enqueue(s, async () => {
        await s.page.goForward({ waitUntil: 'domcontentloaded', timeout: 10000 }).catch(() => {});
        await sendStatus(s);
      });

    case 'reload':
      return enqueue(s, async () => {
        await s.page.reload({ waitUntil: 'domcontentloaded', timeout: 20000 }).catch(() => {});
        await sendStatus(s);
      });
  }
}

async function openSession(sid, url) {
  try {
    const s = await getSession(sid);
    if (typeof url === 'string') await navigate(s, url);
  } catch (err) {
    sendToBridge({ sid, t: 'status', state: 'error', reason: err.message });
  }
}

async function onBridgeMessage(msg) {
  if (!msg || typeof msg.sid !== 'string' || typeof msg.t !== 'string') return;

  const sid = msg.sid.slice(0, 32);
  if (msg.t === 'open') return openSession(sid, msg.url);
  if (msg.t === 'close') return destroySession(sid);
  if (!ALLOWED_INPUT.has(msg.t)) return;

  const s = sessions.get(sid);
  if (!s || !allowInput(s)) return;
  s.lastSeen = Date.now();
  s.idleFrames = 0;
  dispatchInput(s, msg);
}

// ---------------------------------------------------------------------------
// Capture, hash-diff, and tile encoding
// ---------------------------------------------------------------------------

async function captureRgba(s) {
  const png = await s.page.screenshot({ type: 'png', optimizeForSpeed: true });
  const { data } = await sharp(png)
    .resize(CFG.out.w, CFG.out.h, { fit: 'fill' })
    .ensureAlpha()
    .raw()
    .toBuffer({ resolveWithObject: true });
  return data;
}

function diffTiles(s, data) {
  const changed = [];
  const rowBytes = CFG.tile * 4;
  for (let idx = 0; idx < TILE_COUNT; idx++) {
    const tx = idx % TILES_X;
    const ty = (idx - tx) / TILES_X;
    let h = 0x811c9dc5;
    for (let row = 0; row < CFG.tile; row++) {
      const off = ((ty * CFG.tile + row) * CFG.out.w + tx * CFG.tile) * 4;
      for (let i = 0; i < rowBytes; i++) {
        h = Math.imul(h ^ data[off + i], 0x01000193);
      }
    }
    h >>>= 0;
    if (h !== s.hashes[idx]) {
      s.hashes[idx] = h;
      changed.push(idx);
    }
  }
  return changed;
}

// Binary chunk layout (little-endian):
//   u8  kind   0 = skip, 1 = more chunks follow, 2 = last chunk of frame
//   u32 frameId
//   u16 count
//   count x { u16 tileIndex, RGBA[TILE_BYTES] }
function emitFrame(s, data, changed) {
  s.frameId = (s.frameId + 1) >>> 0;
  let ok = true;

  if (changed.length === 0) {
    const skip = Buffer.alloc(7);
    skip.writeUInt8(0, 0);
    skip.writeUInt32LE(s.frameId, 1);
    skip.writeUInt16LE(0, 5);
    ok = sendToBridge({ sid: s.sid, t: 'frame', d: skip.toString('base64') });
  } else {
    for (let i = 0; i < changed.length; i += CFG.tilesPerChunk) {
      const group = changed.slice(i, i + CFG.tilesPerChunk);
      const last = i + CFG.tilesPerChunk >= changed.length;
      const buf = Buffer.allocUnsafe(7 + group.length * (2 + TILE_BYTES));
      buf.writeUInt8(last ? 2 : 1, 0);
      buf.writeUInt32LE(s.frameId, 1);
      buf.writeUInt16LE(group.length, 5);

      let off = 7;
      for (const idx of group) {
        buf.writeUInt16LE(idx, off);
        off += 2;
        const tx = idx % TILES_X;
        const ty = (idx - tx) / TILES_X;
        for (let row = 0; row < CFG.tile; row++) {
          const src = ((ty * CFG.tile + row) * CFG.out.w + tx * CFG.tile) * 4;
          data.copy(buf, off, src, src + CFG.tile * 4);
          off += CFG.tile * 4;
        }
      }
      ok = sendToBridge({ sid: s.sid, t: 'frame', d: buf.toString('base64') }) && ok;
    }
  }

  if (!ok) s.hashes.fill(-1);
}

async function runLoop(s) {
  while (s.alive) {
    const started = Date.now();
    try {
      const data = await captureRgba(s);
      const changed = diffTiles(s, data);
      s.idleFrames = changed.length ? 0 : s.idleFrames + 1;
      if (s.alive) emitFrame(s, data, changed);
    } catch (err) {
      if (!s.alive) break;
      log('capture', s.sid, err.message);
      await sleep(250);
    }
    const period = s.idleFrames >= CFG.idleAfterFrames ? 1000 / CFG.idleFps : 1000 / CFG.maxFps;
    await sleep(Math.max(0, period - (Date.now() - started)));
  }
}

// ---------------------------------------------------------------------------
// HTTP server
// ---------------------------------------------------------------------------

const MAX_BODY_BYTES = 256 * 1024;

function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > MAX_BODY_BYTES) {
        reject(Object.assign(new Error('body too large'), { status: 413 }));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

function sendJson(res, status, obj) {
  res.writeHead(status, { 'content-type': 'application/json' });
  res.end(typeof obj === 'string' ? obj : JSON.stringify(obj));
}

const httpServer = http.createServer(async (req, res) => {
  const u = new URL(req.url, 'http://localhost');

  if (req.method === 'GET' && u.pathname === '/health') {
    return sendJson(res, 200, {
      ok: true,
      sessions: sessions.size,
      pendingMessages: outbox.length,
      lastSyncAgoMs: lastSyncAt ? Date.now() - lastSyncAt : null,
    });
  }

  if (req.method === 'POST' && u.pathname === '/sync') {
    if (!keyOk(req.headers['x-bridge-key'])) {
      res.writeHead(401);
      return res.end();
    }
    lastSyncAt = Date.now();

    let body;
    try {
      body = JSON.parse(await readBody(req));
    } catch (err) {
      return sendJson(res, err.status || 400, { error: 'bad request' });
    }

    const inputs = Array.isArray(body?.inputs) ? body.inputs.slice(0,
