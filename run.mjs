// run.mjs — scheduled checker. Targets, tokens and windows all live in the encrypted blob.
// Phases: inbox (every slot) + diff (record check) or sweep (feed scan) per schedule.
// Console prints aggregate counts only; row-level data is written as encrypted snapshots.
import { loadConfig, keyFromEnv, openJson, sealJson } from './lib/crypt.mjs';
import { mkdirSync, writeFileSync, readdirSync, existsSync, unlinkSync } from 'node:fs';

const key = keyFromEnv();
const cfg = loadConfig('config.enc', key);
mkdirSync('snapshots', { recursive: true });

const now = new Date();
const iso = now.toISOString();
const day = iso.slice(0, 10);
const hour = now.getUTCHours();
const stamp = iso.replace(/[-:]/g, '').slice(0, 13);

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const jj = async (r) => { try { return await r.json(); } catch { return null; } };

async function got(url, token, opt) {
  const base = { 'user-agent': cfg.api.ua, accept: 'application/json' };
  let h;
  if (token && typeof token === 'object') h = { ...base, ...token };
  else if (token) { h = { ...base, cookie: token, origin: new URL(cfg.api.b).origin, referer: new URL(cfg.api.b).origin + '/' }; }
  else h = base;
  try {
    return await fetch(url, { ...opt, headers: { ...h, ...(opt && opt.headers) }, signal: AbortSignal.timeout(25000) });
  } catch { return null; }
}

function latestSnap(prefix) {
  try {
    const f = readdirSync('snapshots').filter((x) => x.startsWith(prefix) && x.endsWith('.enc')).sort().reverse()[0];
    if (!f) return null;
    return openJson('snapshots/' + f, key);
  } catch { return null; }
}

function snapName(phase, hit) {
  return `snapshots/${phase}-${stamp}${hit ? '-HIT' : ''}.enc`;
}

function saveSnap(phase, hit, obj) {
  writeFileSync(snapName(phase, hit), sealJson(obj, key));
}

// ---------- phase: diff ----------
async function diffPhase() {
  const t0 = Date.now();
  const nodes = cfg.nodes;
  const bg = new Map(nodes.map((n) => [n.a, n.g | 0]));
  const bb = new Map(nodes.map((n) => [n.a, n.b == null ? null : Number(n.b)]));
  const rows = [];
  let idx = 0;
  const worker = async () => {
    while (idx < nodes.length) {
      const k = idx++;
      const n = nodes[k];
      const tok = n.k ? { authorization: 'Bearer ' + n.k } : n.t;
      const s1 = await got(cfg.api.b + cfg.api.ep.sub, tok);
      const j1 = s1 ? await jj(s1) : null;
      const s2 = await got(cfg.api.b + cfg.api.ep.bal, tok);
      const j2 = s2 ? await jj(s2) : null;
      const s3 = await got(cfg.api.b + cfg.api.ep.grants, tok);
      const j3 = s3 ? await jj(s3) : null;
      const s = (j1 && (j1.subscription || j1)) || {};
      const gl = (j3 && j3.grants) || [];
      rows.push({
        a: n.a,
        st: s.status ?? null,
        dsc: Array.isArray(s.discounts) ? s.discounts.length : null,
        bal: j2 ? (j2.balance_usd ?? null) : null,
        gn: gl.length,
        gu: gl.reduce((a, x) => a + Number(x.amount_usd || 0), 0),
        e: s1 ? (s2 ? (s3 ? 0 : 'g') : 'b') : 's',
      });
      await sleep(120);
    }
  };
  await Promise.all(Array.from({ length: 6 }, worker));

  const prev = latestSnap('diff-');
  const prevDsc = new Map((prev && prev.rows || []).map((r) => [r.a, r.dsc]));
  let ok = 0, grantUp = 0, balUp = 0, dscDropped = 0;
  let sumG = 0, sumB = 0;
  for (const r of rows) {
    if (!r.e) ok++;
    sumG += r.gu || 0; sumB += Number(r.bal || 0);
    if (r.gn > (bg.get(r.a) ?? 0)) grantUp++;
    const b0 = bb.get(r.a);
    if (b0 != null && Number(r.bal || 0) > b0) balUp++;
    const pd = prevDsc.get(r.a);
    if (pd != null && r.dsc != null && r.dsc < pd) dscDropped++;
  }
  const agg = { ts: iso, n: rows.length, ok, grantUp, balUp, dscDropped, sumG: sumG.toFixed(2), sumB: sumB.toFixed(2), ms: Date.now() - t0 };
  const hit = grantUp > 0 || balUp > 0;
  saveSnap('diff', hit, { ts: iso, phase: 'diff', agg, rows });
  console.log(`diff n=${agg.n} ok=${ok} grantUp=${grantUp} balUp=${balUp} dscDropped=${dscDropped} sumG=${agg.sumG} sumB=${agg.sumB} ms=${agg.ms}`);
}

// ---------- phase: inbox ----------
async function inboxPhase() {
  const origin = new URL(cfg.mail.b).origin;
  const r = await got(cfg.mail.b + '/message-list', null, {
    method: 'POST',
    headers: { 'content-type': 'application/json', origin, referer: origin + '/' },
    body: JSON.stringify({ email: cfg.mail.i, limit: 20 }),
  });
  const data = r ? await jj(r) : null;
  const msgs = (data && data.messages) || [];
  if (!r || !r.ok) { console.log(`inbox err=${r ? r.status : 'net'} n=${msgs.length}`); return; }
  const prev = latestSnap('inbox-');
  const seen = new Set((prev && prev.seen) || []);
  const fresh = msgs.filter((m) => !seen.has(m.id));
  const reTerm = new RegExp(cfg.mail.terms, 'i');
  const reCode = new RegExp(cfg.mail.code, 'g');
  const reLink = new RegExp(cfg.mail.links, 'i');
  let hit = 0;
  const hits = [];
  for (const m of fresh) {
    const blob = (m.from || '') + ' ' + (m.subject || '');
    if (!reTerm.test(blob)) continue;
    const r2 = await got(cfg.mail.b + '/message/' + encodeURIComponent(m.id), null, { headers: { origin, referer: origin + '/' } });
    const full = r2 ? await jj(r2) : null;
    const html = String((full && full.content) || '');
    const plain = html.replace(/<style[\s\S]*?<\/style>/gi, ' ').replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ');
    const codes = [...new Set(plain.match(reCode) || [])];
    const links = [...new Set(html.match(/https?:\/\/[^"'\s<>]+/g) || [])].filter((l) => reLink.test(l));
    if (codes.length || links.length) { hit++; hits.push({ id: m.id, subject: m.subject, codes, links: links.slice(0, 8), text: plain.slice(0, 600) }); }
    await sleep(400);
  }
  if (fresh.length || hit) {
    saveSnap('inbox', hit > 0, { ts: iso, phase: 'inbox', seen: msgs.map((m) => m.id), hit: hit, hits });
  }
  console.log(`inbox n=${msgs.length} fresh=${fresh.length} hit=${hit}`);
}

// ---------- phase: sweep ----------
async function sweepPhase() {
  const prev = latestSnap('sweep-');
  const seenCodes = new Set((prev && prev.seen) || []);
  const texts = [];
  let feedsOk = 0;
  for (const f of cfg.feeds) {
    const r = await got(f.u, null, { headers: { 'user-agent': cfg.api.ua } });
    if (!r || !r.ok) continue;
    feedsOk++;
    if (f.t === 'json') { const j = await jj(r); texts.push(JSON.stringify(j)); } else texts.push(await r.text());
    await sleep(600);
  }
  const blob = texts.join(' ');
  const re = new RegExp(cfg.cand, 'g');
  const codes = [...new Set((blob.match(re) || []).map((x) => x.trim()))].filter((c) => !seenCodes.has(c)).slice(0, 40);
  const sacTok = (cfg.nodes.find((n) => n.a === cfg.sac) || {}).t;
  let live = 0, signal = 0, dead = 0, err = 0;
  const results = [];
  for (const code of codes) {
    let best = 'err';
    const detail = [];
    for (const p of cfg.api.plans) {
      const url = cfg.api.b + cfg.api.ep.chk + encodeURIComponent(code) + '?plan_id=' + p + '&quantity=1&amount_usd=25';
      const r = await got(url, sacTok);
      if (!r) { detail.push(0); continue; }
      detail.push(r.status);
      if (r.status === 200) best = 'live';
      else if (r.status === 400 && best !== 'live') {
        const j = await jj(r);
        const code2 = (j && (j.code || j.error || (j.body && j.body.code))) || '';
        best = /invalid|not_found|expired|used/i.test(String(code2)) ? 'dead' : 'signal';
      }
      await sleep(500);
    }
    if (best === 'live') live++;
    else if (best === 'signal') signal++;
    else if (best === 'dead') dead++;
    else err++;
    results.push({ code, st: detail.join('|'), verdict: best });
  }
  const agg = { ts: iso, phase: 'sweep', feedsOk, feeds: cfg.feeds.length, cand: codes.length, live, signal, dead, err };
  const seen = [...new Set([...((prev && prev.seen) || []), ...codes])].slice(-4000);
  saveSnap('sweep', live > 0 || signal > 0, { ts: iso, phase: 'sweep', agg, seen, results });
  console.log(`sweep feeds=${feedsOk}/${cfg.feeds.length} cand=${codes.length} live=${live} signal=${signal} dead=${dead} err=${err}`);
}

// ---------- schedule ----------
function pickPhase() {
  const w = cfg.wins;
  const waveHours = [...(w.hours || []), ...((w.extra && w.extra[day]) || [])];
  if (w.days && w.days.includes(day) && waveHours.includes(hour)) return 'diff';
  if (w.dailyHour != null && hour === w.dailyHour) return 'diff';
  if ((hour - cfg.sweepOffset) % cfg.sweepEvery === 0) return 'sweep';
  return 'inbox';
}

// inbox always runs; big phase per schedule (PHASE env overrides, for tests)
await inboxPhase();
const phase = process.env.PHASE || pickPhase();
console.log(`phase=${phase} day=${day} h=${hour} n=${cfg.nodes.length}`);
if (phase === 'diff') await diffPhase();
else if (phase === 'sweep') await sweepPhase();

// prune: keep the newest 400 snapshots
const all = readdirSync('snapshots').filter((f) => f.endsWith('.enc')).sort();
for (const f of all.slice(0, Math.max(0, all.length - 400))) { try { unlinkSync('snapshots/' + f); } catch {} }
console.log('done');