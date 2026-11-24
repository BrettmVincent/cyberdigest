// Ransomware activity + group profiles. Every fetcher reduces upstream data to COUNTS in memory:
// victim names, post titles, chat text, ransom notes and wallet addresses are never stored or published.
import { createRequire } from 'node:module';
import countries from 'i18n-iso-countries';
import type { CveInfo, GroupRole, Named, RansomGroupProfile, RansomwareData } from '../../../shared/types';
import type { KevVuln } from '../enrich/kev';
import type { DictEntry } from '../extract';
import { fetchJson } from '../fetch';
import { countryName, countryNumeric } from '../geo';
import type { SourceRegistry } from '../sources';
import { fetchIfChanged, githubApi, isDue, markRan, rawUrl, type Upstream } from '../upstream';
import { DAY, errMsg, isoDay } from '../util';
import { groupKey, type GroupResolver } from './aliases';
import { RTM_REPO, RVM_REPO, type RtmRow, type RvmRow } from './matrices';

const require = createRequire(import.meta.url);
countries.registerLocale(require('i18n-iso-countries/langs/en.json'));

export const CAVEAT = 'Leak-site claims: unverified, and they undercount victims who pay. Counts only; no victim data is published.';
const WEEKS = 12;

/** day → key → count (key = group id, ISO country code or sector name). */
type DailyCounts = Record<string, Record<string, number>>;

interface CountsState {
  days: DailyCounts;
  names?: Record<string, string>;
  /** Raw upstream spelling per group id, for outbound links. */
  raw?: Record<string, string>;
}

function bump(days: DailyCounts, day: string, key: string, n = 1): void {
  const d = (days[day] ??= {});
  d[key] = (d[key] ?? 0) + n;
}

function prune(days: DailyCounts, keepFrom: string): void {
  for (const d of Object.keys(days)) if (d < keepFrom) delete days[d];
}

export function sumWindow(days: DailyCounts, from: string, to: string): Record<string, number> {
  const out: Record<string, number> = {};
  for (const [d, m] of Object.entries(days)) {
    if (d < from || d > to) continue;
    for (const [k, n] of Object.entries(m)) out[k] = (out[k] ?? 0) + n;
  }
  return out;
}

export function weekStarts(now: number, n = WEEKS): string[] {
  const d = new Date(now);
  const monday = Date.parse(isoDay(now)) - ((d.getUTCDay() + 6) % 7) * DAY;
  return Array.from({ length: n }, (_, i) => isoDay(monday - (n - 1 - i) * 7 * DAY));
}

/** Weekly series per key aligned with `weeks`, plus the overall total series. */
export function weekly(days: DailyCounts, weeks: string[]): { byKey: Record<string, number[]>; total: number[] } {
  const byKey: Record<string, number[]> = {};
  const total = new Array<number>(weeks.length).fill(0);
  for (const [day, m] of Object.entries(days)) {
    let w = -1;
    for (let i = weeks.length - 1; i >= 0; i--) {
      if (day >= weeks[i]!) {
        w = i;
        break;
      }
    }
    if (w < 0) continue;
    for (const [k, n] of Object.entries(m)) {
      (byKey[k] ??= new Array<number>(weeks.length).fill(0))[w]! += n;
      total[w]! += n;
    }
  }
  return { byKey, total };
}

// ── Fetchers (each gated, each storing counts only) ─────────────────────────

async function ransomlook(u: Upstream, reg: SourceRegistry, resolver: GroupResolver): Promise<CountsState> {
  const file = 'ransomware/ransomlook.json';
  const state = u.store.readJson<CountsState>(file, { days: {} });
  if (!isDue(u, 'ransomlook', 3) && Object.keys(state.days).length) {
    reg.set('ransomlook', { status: 'ok', detail: 'counts cached (refreshed every 3 h)' });
    return state;
  }
  try {
    const { result, json } = await fetchJson<{ posts?: { group_name?: string; discovered?: string }[] }>(`https://www.ransomlook.io/api/posts?days=${WEEKS * 7}`, {
      timeoutMs: 60_000,
      maxBytes: 64 * 1024 * 1024,
    });
    if (!json?.posts) throw new Error(result.error ?? `HTTP ${result.httpStatus}`);
    const days: DailyCounts = {};
    const names: Record<string, string> = {};
    const raw: Record<string, string> = {};
    for (const p of json.posts) {
      // Only the group and the date are read; post_title (the victim) is never touched.
      if (!p.group_name || !p.discovered) continue;
      const g = resolver.resolve(p.group_name);
      names[g.id] = g.name;
      raw[g.id] ??= p.group_name;
      bump(days, p.discovered.slice(0, 10), g.id);
    }
    const next = { days, names, raw };
    u.store.writeJson(file, next);
    markRan(u, 'ransomlook');
    reg.set('ransomlook', { status: 'ok', detail: `${json.posts.length} posts in ${WEEKS} weeks counted across ${Object.keys(names).length} groups`, retrieved: true });
    return next;
  } catch (e) {
    reg.set('ransomlook', { status: Object.keys(state.days).length ? 'stale' : 'error', detail: errMsg(e) });
    return state;
  }
}

interface RlState {
  groups: CountsState;
  countries: DailyCounts;
  sectors: DailyCounts;
}

type RlVictim = Record<string, unknown>;
const str = (v: unknown) => (typeof v === 'string' ? v : '');

/** ransomware.live PRO (free key). Victim records are reduced to counts per group/country/sector/day. */
async function ransomwareLive(u: Upstream, reg: SourceRegistry, resolver: GroupResolver): Promise<RlState | null> {
  const key = process.env.RANSOMWARE_LIVE_KEY;
  const file = 'ransomware/ransomware-live.json';
  const state = u.store.readJson<RlState | null>(file, null);
  if (!key) {
    reg.set('ransomware-live', { status: 'skipped', detail: 'No RANSOMWARE_LIVE_KEY secret (free key at ransomware.live/my)' });
    return null;
  }
  if (state && !isDue(u, 'ransomware-live', 3)) {
    reg.set('ransomware-live', { status: 'ok', detail: 'counts cached (refreshed every 3 h)' });
    return state;
  }
  try {
    const groups: DailyCounts = {};
    const ctry: DailyCounts = {};
    const sect: DailyCounts = {};
    const names: Record<string, string> = {};
    const raw: Record<string, string> = {};
    const from = isoDay(u.now - WEEKS * 7 * DAY);
    const months = new Set<string>();
    for (let t = Date.parse(from); t <= u.now; t += 20 * DAY) months.add(isoDay(t).slice(0, 7));
    months.add(isoDay(u.now).slice(0, 7));
    let n = 0;
    for (const ym of months) {
      const [y, m] = ym.split('-');
      const { result, json } = await fetchJson<RlVictim[] | { victims?: RlVictim[]; data?: RlVictim[] }>(`https://api-pro.ransomware.live/victims/?year=${y}&month=${m}`, {
        headers: { 'X-API-KEY': key },
        timeoutMs: 60_000,
        maxBytes: 128 * 1024 * 1024,
      });
      if (!json) throw new Error(result.httpStatus === 401 || result.httpStatus === 403 ? 'API key rejected' : (result.error ?? `HTTP ${result.httpStatus}`));
      const list = Array.isArray(json) ? json : (json.victims ?? json.data ?? []);
      for (const v of list) {
        const group = str(v.group) || str(v.group_name);
        const date = (str(v.discovered) || str(v.attackdate) || str(v.published)).slice(0, 10);
        if (!group || !/^\d{4}-\d{2}-\d{2}$/.test(date) || date < from) continue;
        const g = resolver.resolve(group);
        names[g.id] = g.name;
        raw[g.id] ??= group.toLowerCase();
        bump(groups, date, g.id);
        const c = str(v.country).toUpperCase();
        if (/^[A-Z]{2}$/.test(c)) bump(ctry, date, c);
        const s = str(v.activity) || str(v.sector);
        if (s && !/^not found$/i.test(s)) bump(sect, date, s);
        n++;
      }
    }
    const next: RlState = { groups: { days: groups, names, raw }, countries: ctry, sectors: sect };
    u.store.writeJson(file, next);
    markRan(u, 'ransomware-live');
    reg.set('ransomware-live', { status: 'ok', detail: `${n} claims in ${WEEKS} weeks reduced to counts`, retrieved: true });
    return next;
  } catch (e) {
    reg.set('ransomware-live', { status: state ? 'stale' : 'error', detail: errMsg(e) });
    return state;
  }
}

/** Sports/IOC-style codes Cyberwatch sometimes uses instead of ISO 3166 alpha-3. */
const IOC_TO_ISO2: Record<string, string> = {
  SLO: 'SI', GER: 'DE', NED: 'NL', SUI: 'CH', POR: 'PT', DEN: 'DK', CRO: 'HR', GRE: 'GR', BUL: 'BG', RSA: 'ZA', UAE: 'AE', KSA: 'SA',
  CHI: 'CL', MAS: 'MY', INA: 'ID', PHI: 'PH', VIE: 'VN', LAT: 'LV', IRI: 'IR', ALG: 'DZ', NGR: 'NG', ANG: 'AO', ZIM: 'ZW', TAN: 'TZ', URU: 'UY', PAR: 'PY',
};

/** Cyberwatch country field → ISO alpha-2 (alpha-3, alpha-2, or IOC code); null when unrecognisable. */
export function cyberwatchCountry(raw: string): string | null {
  const c = raw.trim().toUpperCase();
  if (/^[A-Z]{3}$/.test(c)) return countries.alpha3ToAlpha2(c) ?? IOC_TO_ISO2[c] ?? null;
  if (/^[A-Z]{2}$/.test(c) && countries.isValid(c)) return c;
  return null;
}

/** Cyberwatch (CC BY-NC): publicly reported cyberattacks → counts per country per day. */
async function cyberwatch(u: Upstream, reg: SourceRegistry): Promise<DailyCounts> {
  const file = 'ransomware/cyberwatch.json';
  const state = u.store.readJson<DailyCounts>(file, {});
  if (!isDue(u, 'cyberwatch', 24) && Object.keys(state).length) {
    reg.set('cyberwatch', { status: 'ok', detail: 'counts cached (daily)' });
    return state;
  }
  try {
    const res = await fetchIfChanged(u, rawUrl('Casualtek/Cyberwatch', 'cyberattacks.json'), Object.keys(state).length > 0, { maxBytes: 64 * 1024 * 1024 });
    if (res.result.status === 'error') throw new Error(res.result.error);
    if (!res.changed) {
      markRan(u, 'cyberwatch');
      reg.set('cyberwatch', { status: 'ok', detail: 'unchanged' });
      return state;
    }
    const list = JSON.parse(res.text!) as { date?: string; country?: string }[];
    const days: DailyCounts = {};
    const from = isoDay(u.now - 90 * DAY);
    let unmapped = 0;
    for (const r of list) {
      const date = (r.date ?? '').slice(0, 10);
      if (date < from) continue;
      const iso2 = cyberwatchCountry(r.country ?? '');
      if (iso2) bump(days, date, iso2);
      else unmapped++;
    }
    u.store.writeJson(file, days);
    markRan(u, 'cyberwatch');
    reg.set('cyberwatch', { status: 'ok', detail: `${list.length} reported attacks scanned; per-country counts kept${unmapped ? `; ${unmapped} in 90 days without a recognisable country` : ''}`, retrieved: true });
    return days;
  } catch (e) {
    delete u.http[rawUrl('Casualtek/Cyberwatch', 'cyberattacks.json')];
    reg.set('cyberwatch', { status: Object.keys(state).length ? 'stale' : 'error', detail: errMsg(e) });
    return state;
  }
}

interface PerGroup {
  counts: Record<string, number>;
  folders?: Record<string, string>;
}

/** Ransomchats chat_index.json → negotiation chats per group (no chat content). */
async function ransomchats(u: Upstream, reg: SourceRegistry, resolver: GroupResolver): Promise<PerGroup> {
  const file = 'ransomware/ransomchats.json';
  const state = u.store.readJson<PerGroup>(file, { counts: {} });
  if (!isDue(u, 'ransomchats', 24) && Object.keys(state.counts).length) {
    reg.set('ransomchats', { status: 'ok', detail: 'counts cached (daily)' });
    return state;
  }
  try {
    const { result, json } = await fetchJson<{ groups?: Record<string, { chats?: unknown[] }> }>(rawUrl('Casualtek/Ransomchats', 'chat_index.json'));
    if (!json?.groups) throw new Error(result.error ?? `HTTP ${result.httpStatus}`);
    const counts: Record<string, number> = {};
    const folders: Record<string, string> = {};
    for (const [name, g] of Object.entries(json.groups)) {
      const id = resolver.resolve(name).id;
      counts[id] = (counts[id] ?? 0) + (g.chats?.length ?? 0);
      folders[id] ??= name;
    }
    const next = { counts, folders };
    u.store.writeJson(file, next);
    markRan(u, 'ransomchats');
    reg.set('ransomchats', { status: 'ok', detail: `${Object.values(counts).reduce((a, b) => a + b, 0)} chats across ${Object.keys(counts).length} groups`, retrieved: true });
    return next;
  } catch (e) {
    reg.set('ransomchats', { status: Object.keys(state.counts).length ? 'stale' : 'error', detail: errMsg(e) });
    return state;
  }
}

/** ThreatLabz ransomware_notes → note files per family folder (GitHub tree API; weekly). */
async function threatlabzNotes(u: Upstream, reg: SourceRegistry, resolver: GroupResolver): Promise<PerGroup> {
  const file = 'ransomware/threatlabz-notes.json';
  const state = u.store.readJson<PerGroup>(file, { counts: {} });
  if (!isDue(u, 'threatlabz-notes', 24 * 7) && Object.keys(state.counts).length) {
    reg.set('threatlabz-notes', { status: 'ok', detail: 'counts cached (weekly)' });
    return state;
  }
  const { json, error } = await githubApi<{ tree?: { path: string; type: string }[] }>('/repos/ThreatLabz/ransomware_notes/git/trees/HEAD?recursive=1');
  if (!json?.tree) {
    reg.set('threatlabz-notes', { status: Object.keys(state.counts).length ? 'stale' : 'skipped', detail: `GitHub API: ${error ?? 'no tree'} (needs GITHUB_TOKEN in CI)` });
    return state;
  }
  const counts: Record<string, number> = {};
  const folders: Record<string, string> = {};
  for (const node of json.tree) {
    if (node.type !== 'blob' || !node.path.includes('/')) continue;
    const folder = node.path.split('/')[0]!;
    if (folder.startsWith('.')) continue;
    const id = resolver.resolve(folder).id;
    counts[id] = (counts[id] ?? 0) + 1;
    folders[id] ??= folder;
  }
  const next = { counts, folders };
  u.store.writeJson(file, next);
  markRan(u, 'threatlabz-notes');
  reg.set('threatlabz-notes', { status: 'ok', detail: `${Object.keys(counts).length} families`, retrieved: true });
  return next;
}

type Payments = Record<string, { count: number; usd: number; last: string | null }>;

/** Ransomwhere export → per-family payment totals. Addresses and transactions are not kept. */
async function ransomwhere(u: Upstream, reg: SourceRegistry, resolver: GroupResolver): Promise<Payments> {
  const file = 'ransomware/ransomwhere.json';
  const state = u.store.readJson<Payments>(file, {});
  if (!isDue(u, 'ransomwhere', 24) && Object.keys(state).length) {
    reg.set('ransomwhere', { status: 'ok', detail: 'totals cached (daily)' });
    return state;
  }
  try {
    const { result, json } = await fetchJson<{ result?: { family?: string; transactions?: { time?: number; amountUSD?: number }[] }[] }>('https://api.ransomwhe.re/export', {
      timeoutMs: 120_000,
      maxBytes: 128 * 1024 * 1024,
    });
    if (!json?.result) throw new Error(result.error ?? `HTTP ${result.httpStatus}`);
    const out: Payments = {};
    for (const a of json.result) {
      if (!a.family) continue;
      const id = resolver.resolve(a.family.replace(/\s*\(.*\)\s*$/, '')).id;
      const p = (out[id] ??= { count: 0, usd: 0, last: null });
      for (const t of a.transactions ?? []) {
        p.count++;
        p.usd += t.amountUSD ?? 0;
        const when = t.time ? new Date(t.time * 1000).toISOString().slice(0, 10) : null;
        if (when && (!p.last || when > p.last)) p.last = when;
      }
    }
    for (const p of Object.values(out)) p.usd = Math.round(p.usd);
    u.store.writeJson(file, out);
    markRan(u, 'ransomwhere');
    reg.set('ransomwhere', { status: 'ok', detail: `${json.result.length} addresses summed into ${Object.keys(out).length} families`, retrieved: true });
    return out;
  } catch (e) {
    reg.set('ransomwhere', { status: Object.keys(state).length ? 'stale' : 'error', detail: errMsg(e) });
    return state;
  }
}

// ── Assembly ────────────────────────────────────────────────────────────────

export interface RansomwareInput {
  u: Upstream;
  reg: SourceRegistry;
  resolver: GroupResolver;
  rvm: { rows: RvmRow[]; updated: string | null };
  rtm: { rows: RtmRow[]; updated: string | null };
  mispRansomware: DictEntry[];
  kevIndex: Map<string, KevVuln>;
  flips: Map<string, string>;
  cveInfo: (id: string) => CveInfo | undefined;
}

export async function buildRansomware(inp: RansomwareInput): Promise<{ data: RansomwareData; countries: Record<string, number> }> {
  const { u, reg, resolver } = inp;
  const [rl, live, cw, chats, notes, pay] = await Promise.all([
    ransomlook(u, reg, resolver),
    ransomwareLive(u, reg, resolver),
    cyberwatch(u, reg),
    ransomchats(u, reg, resolver),
    threatlabzNotes(u, reg, resolver),
    ransomwhere(u, reg, resolver),
  ]);
  const now = u.now;
  const weeks = weekStarts(now);
  const today = isoDay(now);
  const d7 = isoDay(now - 6 * DAY);
  const d14 = isoDay(now - 13 * DAY);
  const d30 = isoDay(now - 29 * DAY);
  prune(rl.days, weeks[0]!);

  const rlWeekly = weekly(rl.days, weeks);
  const liveWeekly = live ? weekly(live.groups.days, weeks) : null;
  const rl7 = sumWindow(rl.days, d7, today);
  const rl30 = sumWindow(rl.days, d30, today);
  const live7 = live ? sumWindow(live.groups.days, d7, today) : {};
  const live30 = live ? sumWindow(live.groups.days, d30, today) : {};
  const total = (m: Record<string, number>) => Object.values(m).reduce((a, b) => a + b, 0);
  const totalsFor = (days: DailyCounts) => {
    const last = sumWindow(days, d7, today);
    const prev = sumWindow(days, d14, isoDay(now - 7 * DAY));
    return { last7: total(last), prev7: total(prev), groups7: Object.keys(last).length, groupsPrev7: Object.keys(prev).length };
  };

  // Profiles: union of active groups and groups named by the matrices.
  const profiles = new Map<string, RansomGroupProfile>();
  const profile = (id: string, name: string): RansomGroupProfile => {
    let p = profiles.get(id);
    if (!p) {
      p = { id, name, aliases: [], description: null, weekly: new Array(WEEKS).fill(0), weeklyRl: live ? new Array(WEEKS).fill(0) : null, last7: 0, last30: 0, cves: [], tools: [], notes: 0, chats: 0, payments: null, links: [] };
      profiles.set(id, p);
    }
    return p;
  };
  for (const [id, series] of Object.entries(rlWeekly.byKey)) {
    const p = profile(id, rl.names?.[id] ?? id);
    p.weekly = series;
    p.last7 = rl7[id] ?? 0;
    p.last30 = rl30[id] ?? 0;
  }
  if (live && liveWeekly) {
    for (const [id, series] of Object.entries(liveWeekly.byKey)) {
      const p = profile(id, live.groups.names?.[id] ?? id);
      p.weeklyRl = series;
      if (!rl30[id]) {
        p.last7 = live7[id] ?? 0;
        p.last30 = live30[id] ?? 0;
      }
    }
  }
  for (const row of inp.rvm.rows) {
    for (const g of row.groups) {
      const r = resolver.resolve(g.name);
      const p = profile(r.id, r.name);
      for (const cve of row.cves) {
        if (!p.cves.some((c) => c.id === cve)) p.cves.push({ id: cve, role: g.role, product: row.product, vendor: row.vendor, sources: row.sources.slice(0, 4) });
      }
    }
  }
  for (const row of inp.rtm.rows) {
    for (const g of row.groups) {
      const r = resolver.resolve(g.name);
      const p = profile(r.id, r.name);
      if (!p.tools.some((t) => t.name === row.tool)) p.tools.push({ name: row.tool, category: row.category });
    }
  }

  const mispByKey = new Map<string, DictEntry>();
  for (const e of inp.mispRansomware) for (const k of [e.name, ...e.aliases].map(groupKey)) if (!mispByKey.has(k)) mispByKey.set(k, e);

  for (const p of profiles.values()) {
    p.aliases = resolver.aliases(p.id).filter((a) => groupKey(a) !== groupKey(p.name));
    p.description = mispByKey.get(p.id)?.description ?? p.aliases.map((a) => mispByKey.get(groupKey(a))?.description).find(Boolean) ?? null;
    p.notes = notes.counts[p.id] ?? 0;
    p.chats = chats.counts[p.id] ?? 0;
    p.payments = pay[p.id] ?? null;
    p.cves.sort((a, b) => b.id.localeCompare(a.id, 'en', { numeric: true }));
    const links: { label: string; url: string }[] = [];
    if (rl.raw?.[p.id]) links.push({ label: 'RansomLook', url: `https://www.ransomlook.io/group/${encodeURIComponent(rl.raw[p.id]!)}` });
    links.push({ label: 'Ransomware.live', url: `https://www.ransomware.live/group/${encodeURIComponent(live?.groups.raw?.[p.id] ?? p.id)}` });
    if (notes.folders?.[p.id]) links.push({ label: `Ransom notes (ThreatLabz, ${p.notes})`, url: `https://github.com/ThreatLabz/ransomware_notes/tree/main/${encodeURIComponent(notes.folders[p.id]!)}` });
    if (chats.folders?.[p.id]) links.push({ label: `Negotiation chats (${p.chats})`, url: `https://github.com/Casualtek/Ransomchats/tree/main/${encodeURIComponent(chats.folders[p.id]!)}` });
    if (p.cves.length) links.push({ label: 'Ransomware Vulnerability Matrix', url: `https://github.com/${RVM_REPO}` });
    if (p.tools.length) links.push({ label: 'Ransomware Tool Matrix', url: `https://github.com/${RTM_REPO}` });
    links.push({ label: 'ATT&CK TTP mapping (crocodyli)', url: 'https://github.com/crocodyli/ThreatActors-TTPs' });
    links.push({ label: 'CISA #StopRansomware advisories', url: 'https://www.cisa.gov/stopransomware/official-alerts-statements-cisa' });
    links.push({ label: 'Infostealer lookups (Hudson Rock)', url: 'https://www.hudsonrock.com/threat-intelligence-cybercrime-tools' });
    p.links = links;
  }

  const groups = [...profiles.values()]
    .filter((p) => p.last30 > 0 || p.cves.length > 0 || p.tools.length > 0)
    .sort((a, b) => b.last30 - a.last30 || b.cves.length - a.cves.length || a.name.localeCompare(b.name));

  // Weeks where one group supplies an outsized share (mass-exploitation campaigns distort totals).
  const annotations: RansomwareData['annotations'] = [];
  weeks.forEach((week, i) => {
    const tot = rlWeekly.total[i] ?? 0;
    if (tot < 30) return;
    let best = '';
    let max = 0;
    for (const [id, s] of Object.entries(rlWeekly.byKey)) if ((s[i] ?? 0) > max) [best, max] = [id, s[i]!];
    if (max / tot >= 0.35) annotations.push({ week, group: rl.names?.[best] ?? best, share: Math.round((max / tot) * 100) / 100 });
  });

  // Sectors and countries (30 days): ransomware.live when configured, else Cyberwatch for countries.
  const sectors: Named[] = live
    ? Object.entries(sumWindow(live.sectors, d30, today))
        .sort((a, b) => b[1] - a[1])
        .slice(0, 12)
        .map(([name, count]) => ({ name, count }))
    : [];
  const countryCounts = live ? sumWindow(live.countries, d30, today) : sumWindow(cw, d30, today);
  const countrySource: RansomwareData['countrySource'] = live ? 'ransomware.live' : Object.keys(cw).length ? 'cyberwatch' : null;
  const countryList = Object.entries(countryCounts)
    .sort((a, b) => b[1] - a[1])
    .map(([iso, count]) => ({ iso, name: countryName(iso), numeric: countryNumeric(iso), count }));

  // Hunting: RTM tools used by this month's most active groups.
  const topIds = new Set(groups.filter((g) => g.last30 > 0).slice(0, 10).map((g) => g.id));
  const byCat = new Map<string, Map<string, Set<string>>>();
  for (const row of inp.rtm.rows) {
    const users = row.groups.map((g) => resolver.resolve(g.name)).filter((r) => topIds.has(r.id));
    if (!users.length) continue;
    const cat = byCat.get(row.category) ?? new Map<string, Set<string>>();
    const set = cat.get(row.tool) ?? new Set<string>();
    for (const r of users) set.add(r.name);
    cat.set(row.tool, set);
    byCat.set(row.category, cat);
  }
  const hunting = [...byCat.entries()]
    .map(([category, tools]) => ({
      category,
      tools: [...tools.entries()]
        .sort((a, b) => b[1].size - a[1].size || a[0].localeCompare(b[0]))
        .slice(0, 6)
        .map(([name, g]) => ({ name, groups: [...g] })),
    }))
    .sort((a, b) => (b.tools[0]?.groups.length ?? 0) - (a.tools[0]?.groups.length ?? 0));

  // CVEs exploited by ransomware groups (RVM), with CyberDigest enrichment.
  const rvmMap = new Map<string, { groups: Set<string>; product: string; vendor: string }>();
  for (const row of inp.rvm.rows) {
    for (const cve of row.cves) {
      const e = rvmMap.get(cve) ?? { groups: new Set<string>(), product: row.product, vendor: row.vendor };
      for (const g of row.groups) e.groups.add(resolver.resolve(g.name).name);
      rvmMap.set(cve, e);
    }
  }
  const rvmCves = [...rvmMap.entries()]
    .map(([cve, e]) => {
      const info = inp.cveInfo(cve);
      const k = inp.kevIndex.get(cve);
      const d = info?.detections;
      return {
        cve,
        groups: [...e.groups].sort(),
        product: e.product,
        vendor: e.vendor,
        kev: Boolean(k),
        kevRansomware: k?.knownRansomwareCampaignUse === 'Known',
        epss: info?.epss ?? null,
        epssPct: info?.epssPct ?? null,
        cvss: info?.cvss ?? null,
        detections: d ? (d.nuclei ? 1 : 0) + d.sigma.length + d.et.length + d.yara.length : 0,
      };
    })
    .sort((a, b) => b.cve.localeCompare(a.cve, 'en', { numeric: true }));

  const kevFlips = [...inp.flips.entries()]
    .map(([cve, date]) => {
      const k = inp.kevIndex.get(cve);
      return { cve, date, vendor: k?.vendorProject ?? '', product: k?.product ?? '', name: k?.vulnerabilityName ?? '' };
    })
    .sort((a, b) => b.date.localeCompare(a.date));

  return {
    data: {
      weeks,
      caveat: CAVEAT,
      totals: {
        ransomlook: Object.keys(rl.days).length ? totalsFor(rl.days) : null,
        ransomwareLive: live ? totalsFor(live.groups.days) : null,
      },
      weekly: { ransomlook: Object.keys(rl.days).length ? rlWeekly.total : null, ransomwareLive: liveWeekly ? liveWeekly.total : null },
      annotations,
      sectors,
      countries: countryList,
      countrySource,
      groups,
      kevFlips,
      hunting,
      rvmCves,
      matrixUpdated: { rvm: inp.rvm.updated, rtm: inp.rtm.updated },
    },
    countries: countryCounts,
  };
}

export type { GroupRole };
