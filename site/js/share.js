/*
 * share.js — workshop support for a room, a booth, and a table of handouts.
 *
 * Three jobs, none of which the engine knows about:
 *
 *   1. Shareable bench links. A URL that puts everyone in a room on the same
 *      bench — same drill (or free-play scenario), same difficulty band, same
 *      configuration overrides. Because a scenario's seed is deterministic, the
 *      same drill reproduces the same bytes for everyone, so thirty people who
 *      click one link get an identical bench.
 *
 *   2. Printable handouts. Built from the engine's own catalogue, so the paper
 *      on the tables cannot drift from what the app teaches.
 *
 *   3. The service-worker registration helper. Same-origin only, so caching for
 *      offline use never becomes a request that leaves the browser.
 *
 * NOTHING HERE TOUCHES THE NETWORK. The one exception is registerOffline(),
 * which registers a service worker whose fetch handler is same-origin only; it
 * caches assets already being loaded and never originates a request of its own.
 *
 * ---------------------------------------------------------------------------
 * A NOTE ON THE SEED (read this before "fixing" the link format).
 *
 * There is no engine seam to SET a seed. loadDrill(id, band) and
 * loadSandbox(scenarioId) take no seed; createEngine() takes none; Session.seed
 * is read-only and derived internally from the scenario (see ENGINE-API.md §2).
 * The room-sync property does not need one: the seed is DETERMINISTIC per
 * scenario, so loading the same drill reproduces the same seed and the same
 * bytes on every machine (DESIGN.md "Determinism"). The link therefore carries
 * the seed as a STAMP that we verify after loading — never as something we set.
 * A mismatch (only possible if the engine changed its seed derivation) is
 * surfaced honestly rather than papered over.
 *
 * What a link CAN reproduce: the drill or free-play scenario, the band, and any
 * configuration overrides (setConfig is a real seam as of engine API v3).
 * What it CANNOT: an arbitrary instructor-chosen seed to reroll the randomised
 * credential. That needs an engine seam that does not exist; see the final
 * report.
 * ---------------------------------------------------------------------------
 */

/* ================================================================== *
 * 1. Bench links
 * ================================================================== */

/**
 * Read bench parameters from the current URL. Accepts them in the query string
 * (?d=1.3&b=silver) or after the hash (#d=1.3&b=silver), so a link survives
 * being pasted into tools that mangle one or the other.
 *
 * Returns null when there are no bench parameters at all — that is the seedless
 * default, and the caller must fall back to its normal boot.
 */
export function parseShareParams(loc = window.location) {
  const params = new URLSearchParams(loc.search || '');
  // Merge hash params (everything after a leading '#', parsed as a query).
  const hash = (loc.hash || '').replace(/^#/, '');
  if (hash && hash.includes('=')) {
    const hp = new URLSearchParams(hash);
    for (const [k, v] of hp) if (!params.has(k)) params.set(k, v);
  }

  const drill = params.get('d') || params.get('drill');
  const sandbox = params.get('sandbox') || params.get('s0');
  const view = params.get('view');
  if (!drill && !sandbox && !view) return null;

  const band = normaliseBand(params.get('b') || params.get('band'));
  const seed = params.get('seed');
  return {
    view: view || null,                 // 'handouts' boots straight into the print view
    drill: drill || null,
    sandbox: sandbox || null,
    band,
    config: parseConfig(params.get('c')),
    seed: seed != null && seed !== '' ? Number(seed) : null,
  };
}

function normaliseBand(b) {
  return b === 'bronze' || b === 'silver' || b === 'gold' ? b : null;
}

/** "security.secureChannel=off;security.macBytes=2" → [[group, field, value], …] */
function parseConfig(raw) {
  if (!raw) return [];
  const out = [];
  for (const part of raw.split(';')) {
    if (!part) continue;
    const eq = part.indexOf('=');
    if (eq < 0) continue;
    const path = part.slice(0, eq);
    const value = part.slice(eq + 1);
    const dot = path.indexOf('.');
    if (dot < 0) continue;
    out.push([path.slice(0, dot), path.slice(dot + 1), value]);
  }
  return out;
}

/**
 * Collect the configuration overrides the learner has actually made, straight
 * from the engine. A field carries `changed: true` (engine API v3) when it has
 * been moved off the bench's own setting, so this is exactly the set of things
 * a link needs to reproduce — nothing more, so the URL stays short.
 */
export function collectConfigOverrides(engine) {
  const out = [];
  let groups;
  try { groups = engine.configGroups(); } catch { return out; }
  for (const g of groups || []) {
    for (const f of g.fields || []) {
      if (f.changed && !f.fixed) out.push([g.id, f.id, String(f.value)]);
    }
  }
  return out;
}

function encodeConfig(overrides) {
  return overrides.map(([g, f, v]) => `${g}.${f}=${v}`).join(';');
}

/**
 * Build a shareable URL for the engine's current state. Strips any existing
 * query/hash so re-sharing a shared bench does not accumulate parameters.
 */
export function buildShareUrl(engine, loc = window.location) {
  const session = engine.session;
  const params = new URLSearchParams();

  if (session.sandbox) {
    params.set('sandbox', session.scenarioId);
  } else if (session.drillId) {
    params.set('d', session.drillId);
  }
  if (session.band) params.set('b', session.band);

  const overrides = collectConfigOverrides(engine);
  if (overrides.length) params.set('c', encodeConfig(overrides));

  // The seed is a stamp we verify on load, never something we set. Recording it
  // makes the link self-describing and lets a future engine flag a mismatch.
  if (typeof session.seed === 'number') params.set('seed', String(session.seed));

  const base = loc.origin + loc.pathname;
  return `${base}?${params.toString()}`;
}

/**
 * Apply parsed bench parameters to the engine: load the drill or the sandbox,
 * then replay the configuration overrides, then verify the seed stamp.
 *
 * `notify` is an optional (message) => void for surfacing anything the engine
 * refused or a seed that did not match. Returns a small report.
 */
export function applyShareParams(engine, p, notify = () => {}) {
  const report = { loaded: null, band: p.band, applied: [], refused: [], seedMismatch: false };

  if (p.sandbox) {
    engine.loadSandbox(p.sandbox);
    report.loaded = { sandbox: p.sandbox };
  } else if (p.drill) {
    engine.loadDrill(p.drill, p.band || 'bronze');
    report.loaded = { drill: p.drill };
  } else {
    return report; // view-only link (e.g. ?view=handouts); nothing to load
  }

  // loadDrill / loadSandbox clear options (ENGINE-API §3), so overrides are
  // applied after the load, and their order does not matter (determinism).
  for (const [g, f, v] of p.config) {
    let res;
    try { res = engine.setConfig(g, f, v); } catch (err) { res = { ok: false, error: String(err) }; }
    if (res && res.ok === false) {
      report.refused.push([g, f, v, res.error]);
      notify(`Shared bench: could not set ${g}.${f} — ${res.error}`);
    } else {
      report.applied.push([g, f, v]);
    }
  }

  // Verify, never set. Same drill → same seed on every machine; a mismatch can
  // only mean the engine changed its derivation, and the honest thing is to say
  // the bench may differ rather than pretend the link pinned it.
  if (p.seed != null && typeof engine.session.seed === 'number' && engine.session.seed !== p.seed) {
    report.seedMismatch = true;
    notify('Shared bench: this engine produced a different seed than the link recorded. '
      + 'The bench may not exactly match the one it was shared from.');
  }

  return report;
}

/* ================================================================== *
 * 2. Printable handouts
 * ================================================================== */

const PROJECT_URL = 'https://holdthedoorhoid.github.io/open-door-range/';
const ETHICS_LINE =
  'Everything here is simulated: no real credentials, no vendor-specific exploit '
  + 'code, no named products targeted. The weak-key material is already public. The '
  + 'defensive half is first-class — a defender can run the same range to learn what '
  + 'their own bus looks like under each attack.';

/**
 * Build the printable handout DOM from the engine's own catalogue and per-drill
 * detail. One section per module, so the print stylesheet can put each on its
 * own sheet. Content comes from engine.catalog() and engine.getDrill(), the
 * same data the app renders, so a handout cannot drift from the course.
 */
export function renderHandouts(host, engine) {
  const doc = host.ownerDocument;
  const h = (tag, cls, text) => {
    const n = doc.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = text;
    return n;
  };

  host.textContent = '';

  const catalog = engine.catalog();

  const header = h('div', 'handout-doc__head');
  header.append(h('h1', null, 'Open Door Range — course handout'));
  const sub = h('p', 'handout-doc__sub');
  sub.append(
    `A virtual range for physical access control. ${catalog.drillCount} drills across `
      + `${catalog.modules.length} modules. `,
  );
  const link = h('span', 'handout-doc__url', PROJECT_URL);
  sub.append(link);
  header.append(sub);
  header.append(h('p', 'handout-doc__ethics', ETHICS_LINE));
  host.append(header);

  for (const m of catalog.modules) {
    const sec = h('section', 'handout-module');
    const hd = h('div', 'handout-module__hd');
    hd.append(h('span', 'handout-module__num', `Module ${m.number}`));
    hd.append(h('h2', null, m.title));
    sec.append(hd);
    if (m.blurb) sec.append(h('p', 'handout-module__blurb', m.blurb));

    for (const d of m.drills) {
      const drill = safeGetDrill(engine, d.id);
      const card = h('div', 'handout-drill');

      const dhd = h('div', 'handout-drill__hd');
      dhd.append(h('span', 'handout-drill__id', d.id));
      dhd.append(h('span', 'handout-drill__title', d.title));
      const band = h('span', `handout-band handout-band--${d.band}`,
        d.simulated ? d.band : 'reference');
      dhd.append(band);
      card.append(dhd);

      const summary = (drill && drill.summary) || d.summary;
      if (summary) card.append(labelled(h, 'What it is', summary));

      if (drill && drill.objective) card.append(labelled(h, 'Objective', drill.objective));

      if (d.simulated && drill && drill.flagText) {
        card.append(labelled(h, 'Flag — earned by the engine, not a typed answer', drill.flagText));
      } else if (!d.simulated) {
        card.append(labelled(h, 'Reference', 'No flag. This section is prose, on purpose.'));
      }

      if (drill && drill.note) card.append(labelled(h, 'Takeaway', drill.note));

      sec.append(card);
    }
    host.append(sec);
  }

  const foot = h('div', 'handout-doc__foot');
  foot.append(`Open Door Range · ${PROJECT_URL} · runs entirely in your browser, nothing collected.`);
  host.append(foot);
}

function labelled(h, label, body) {
  const wrap = h('div', 'handout-field');
  wrap.append(h('span', 'handout-field__label', label));
  wrap.append(h('span', 'handout-field__body', body));
  return wrap;
}

function safeGetDrill(engine, id) {
  try { return engine.getDrill(id); } catch { return null; }
}

/* ================================================================== *
 * 3. Offline service worker (registration helper)
 * ================================================================== */

/**
 * Register the same-origin service worker so a browser that has loaded the page
 * once keeps working with the network off. Silent no-op where service workers
 * are unavailable (file:// URLs, private windows, unsupported browsers) — the
 * app must run identically without it.
 *
 * The relative path 'sw.js' resolves against the page URL, so the worker's
 * scope is the directory the site is served from — correct on GitHub Pages
 * (/open-door-range/) and on a laptop's local server alike.
 */
export function registerOffline() {
  if (!('serviceWorker' in navigator)) return;
  if (location.protocol !== 'http:' && location.protocol !== 'https:') return; // not file://
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('sw.js').catch(() => { /* offline is a bonus, never required */ });
  });
}
