// Token search: free text plus field filters, e.g.
//   vendor:fortinet kev:yes since:7d "remote code"   actor:"Volt Typhoon"   p:1,2   tier:A
import type { ActorProfile, CveInfo, Priority, SourceTier, Story } from '../../../shared/types';
import { parseTerm } from './terms';

export interface Query {
  text: string[];
  vendor: string[];
  actor: string[];
  malware: string[];
  cve: string[];
  feed: string[];
  group: string[];
  tier: SourceTier[];
  priority: Priority[];
  kev: boolean | null;
  exploited: boolean | null;
  sinceMs: number | null;
  /** First-reported day (YYYY-MM-DD). */
  date: string | null;
  country: string[];
  origin: string[];
  target: string[];
  /** 'yes' = any ransomware link; otherwise a group name fragment. */
  ransomware: string[];
  gap: boolean | null;
  exploitedBy: string[];
  watched: boolean;
  starred: boolean;
  isNew: boolean;
}

export const QUERY_HELP: [string, string][] = [
  ['vendor:fortinet', 'vendor or product (FortiOS → Fortinet)'],
  ['actor:"volt typhoon"', 'threat actor (aliases resolved)'],
  ['malware:lockbit', 'malware / ransomware family'],
  ['cve:CVE-2026-1234', 'CVE ID (prefix works: cve:2026-12)'],
  ['kev:yes', 'mentions a CISA KEV entry'],
  ['exploited:yes', 'exploitation claimed or confirmed'],
  ['p:1,2', 'priority band(s)'],
  ['tier:A', 'lead source tier (A advisory, B research, C news)'],
  ['since:24h', 'last seen within 6h / 24h / 3d / 7d …'],
  ['feed:cisa', 'source feed id or name'],
  ['country:UA', 'country named in the story (ISO code or name: country:ukraine)'],
  ['origin:RU', 'mentions an actor attributed to this country (code or name)'],
  ['target:DE', 'mentions an actor known to target this country (code or name)'],
  ['date:2026-11-20', 'first reported on this day'],
  ['ransomware:yes', 'CVE linked to ransomware (or ransomware:qilin)'],
  ['exploited-by:enisa', 'CVE listed as exploited by ENISA / Shadowserver / …'],
  ['gap:yes', 'exploited CVE with no public detection rule'],
  ['is:watched / is:starred / is:new', 'your watchlist, starred stories, new since last visit'],
];

function tokenize(q: string): string[] {
  return q.match(/(?:[^\s"]+:)?"[^"]*"|\S+/g) ?? [];
}

function unquote(s: string): string {
  return s.replace(/^"|"$/g, '').trim();
}

export function parseQuery(q: string): Query {
  const out: Query = {
    text: [],
    vendor: [],
    actor: [],
    malware: [],
    cve: [],
    feed: [],
    group: [],
    tier: [],
    priority: [],
    kev: null,
    exploited: null,
    sinceMs: null,
    date: null,
    country: [],
    origin: [],
    target: [],
    ransomware: [],
    gap: null,
    exploitedBy: [],
    watched: false,
    starred: false,
    isNew: false,
  };
  for (const tok of tokenize(q)) {
    const m = /^([a-z][a-z-]*):(.+)$/i.exec(tok);
    if (!m) {
      const t = unquote(tok).toLowerCase();
      if (t) out.text.push(t);
      continue;
    }
    const key = m[1]!.toLowerCase();
    const val = unquote(m[2]!);
    const lower = val.toLowerCase();
    const list = lower.split(',').map((s) => s.trim()).filter(Boolean);
    const yes = ['yes', 'y', 'true', '1'].includes(lower);
    switch (key) {
      case 'vendor':
      case 'v':
      case 'product':
        out.vendor.push(lower);
        break;
      case 'actor':
      case 'a':
        out.actor.push(lower);
        break;
      case 'malware':
      case 'm':
        out.malware.push(lower);
        break;
      case 'cve':
        out.cve.push(lower.replace(/^cve-/, ''));
        break;
      case 'feed':
      case 'src':
      case 'source':
        out.feed.push(lower);
        break;
      case 'group':
        out.group.push(lower);
        break;
      case 'tier':
        out.tier.push(...(list.map((s) => s.toUpperCase()).filter((s) => ['A', 'B', 'C'].includes(s)) as SourceTier[]));
        break;
      case 'p':
      case 'priority':
        out.priority.push(...(list.map(Number).filter((n) => n >= 1 && n <= 4) as Priority[]));
        break;
      case 'kev':
        out.kev = yes;
        break;
      case 'exploited':
        out.exploited = yes;
        break;
      case 'since': {
        const s = /^(\d+)\s*([hdw])$/.exec(lower);
        if (s) out.sinceMs = Number(s[1]) * { h: 3_600_000, d: 86_400_000, w: 604_800_000 }[s[2] as 'h' | 'd' | 'w'];
        break;
      }
      case 'date':
      case 'on':
        if (/^\d{4}-\d{2}-\d{2}$/.test(lower)) out.date = lower;
        break;
      // Country values stay as typed (ISO code or name); matchStory resolves them via ctx.countryIso.
      case 'country':
        out.country.push(lower);
        break;
      case 'origin':
        out.origin.push(lower);
        break;
      case 'target':
        out.target.push(lower);
        break;
      case 'ransomware':
      case 'rw':
        out.ransomware.push(yes ? 'yes' : lower);
        break;
      case 'gap':
        out.gap = yes;
        break;
      case 'exploited-by':
      case 'exploitedby':
        out.exploitedBy.push(lower);
        break;
      case 'is':
        if (lower === 'watched' || lower === 'watch') out.watched = true;
        if (lower === 'starred' || lower === 'star') out.starred = true;
        if (lower === 'new') out.isNew = true;
        break;
      default:
        out.text.push(tok.toLowerCase());
    }
  }
  return out;
}

const anyIncludes = (haystack: string[], needle: string) => haystack.some((h) => h.toLowerCase().includes(needle));

export interface MatchContext {
  now: number;
  cveInfo: Map<string, CveInfo>;
  actors: Map<string, ActorProfile>;
  isWatched: (s: Story) => boolean;
  isStarred: (s: Story) => boolean;
  isNew: (s: Story) => boolean;
  /** Resolve a country name or code ("ukraine", "uk", "UA") to ISO alpha-2. */
  countryIso?: (value: string) => string | null;
}

const COUNTRY_SYNONYMS: Record<string, string> = {
  uk: 'GB', britain: 'GB', 'great britain': 'GB', england: 'GB', usa: 'US', 'u.s.': 'US', 'u.s': 'US', america: 'US', 'united states of america': 'US',
  russia: 'RU', 'south korea': 'KR', 'north korea': 'KP', dprk: 'KP', iran: 'IR', taiwan: 'TW', vietnam: 'VN', syria: 'SY', uae: 'AE', czech: 'CZ', 'czech republic': 'CZ', turkey: 'TR',
};

/** ISO alpha-2 for a typed value: a code ("ua"), a known synonym, or a name resolved by ctx.countryIso. */
export function resolveCountry(value: string, ctx: Pick<MatchContext, 'countryIso'>): string {
  const v = value.trim().toLowerCase();
  if (COUNTRY_SYNONYMS[v]) return COUNTRY_SYNONYMS[v];
  if (/^[a-z]{2}$/.test(v)) return v.toUpperCase();
  return ctx.countryIso?.(v) ?? v.toUpperCase();
}

/** Story actor matches the term by canonical name or any MISP alias. */
function actorMatches(s: Story, term: string, actors: Map<string, ActorProfile>): boolean {
  return s.actors.some((a) => a.toLowerCase().includes(term) || (actors.get(a)?.aliases ?? []).some((x) => x.toLowerCase().includes(term)));
}

export function matchStory(s: Story, q: Query, ctx: MatchContext): boolean {
  if (q.priority.length && !q.priority.includes(s.priority)) return false;
  if (q.tier.length && !q.tier.includes(s.tier)) return false;
  if (q.sinceMs !== null && ctx.now - Date.parse(s.lastSeen) > q.sinceMs) return false;
  if (q.exploited !== null && s.exploited !== q.exploited && !(q.exploited && s.reasons.some((r) => r.code.startsWith('kev') || r.code === 'ssvc-active'))) return false;
  if (q.kev !== null && s.cves.some((c) => ctx.cveInfo.get(c)?.kev) !== q.kev) return false;
  for (const v of q.vendor) if (!anyIncludes(s.vendors, v)) return false;
  for (const a of q.actor) if (!actorMatches(s, a, ctx.actors)) return false;
  for (const m of q.malware) if (!anyIncludes(s.malware, m)) return false;
  for (const c of q.cve) if (!s.cves.some((x) => x.toLowerCase().slice(4).startsWith(c))) return false;
  for (const f of q.feed) if (![s.feedId, s.feed, ...s.sources.flatMap((x) => [x.feedId, x.feed])].some((x) => x.toLowerCase().includes(f))) return false;
  for (const g of q.group) if (!s.group.includes(g)) return false;
  if (q.date && s.date.slice(0, 10) !== q.date) return false;
  for (const v of q.country) {
    const c = resolveCountry(v, ctx);
    if (!(s.countries ?? []).includes(c)) return false;
  }
  for (const v of q.origin) {
    const c = resolveCountry(v, ctx);
    if (!s.actors.some((a) => ctx.actors.get(a)?.country === c)) return false;
  }
  for (const v of q.target) {
    const c = resolveCountry(v, ctx);
    if (!s.actors.some((a) => ctx.actors.get(a)?.targets.some((t) => t.iso === c))) return false;
  }
  if (q.ransomware.length || q.gap !== null || q.exploitedBy.length) {
    const infos = s.cves.map((c) => ctx.cveInfo.get(c)).filter((x): x is CveInfo => Boolean(x));
    for (const r of q.ransomware) {
      const hit =
        r === 'yes'
          ? infos.some((i) => i.ransomware)
          : infos.some((i) => i.ransomware?.groups.some((g) => g.name.toLowerCase().includes(r))) || s.malware.some((m) => m.toLowerCase().includes(r));
      if (!hit) return false;
    }
    if (q.gap !== null && infos.some((i) => i.detectionGap) !== q.gap) return false;
    for (const e of q.exploitedBy) if (!infos.some((i) => i.exploitation?.catalogs.some((c) => c.toLowerCase().includes(e)))) return false;
  }
  if (q.watched && !ctx.isWatched(s)) return false;
  if (q.starred && !ctx.isStarred(s)) return false;
  if (q.isNew && !ctx.isNew(s)) return false;
  if (q.text.length) {
    const hay = [s.title, s.summary, s.feed, ...s.cves, ...s.vendors, ...s.actors, ...s.malware, ...s.sources.map((x) => x.title)].join(' ').toLowerCase();
    for (const t of q.text) if (!hay.includes(t)) return false;
  }
  return true;
}

/** Does a watch/mute term match this story? Entity terms match exactly (case-insensitive); kw matches title text. */
export function termMatches(t: string, s: Story): boolean {
  const p = parseTerm(t);
  if (!p) return false;
  const v = p.value.toLowerCase();
  switch (p.kind) {
    case 'vendor':
      return s.vendors.some((x) => x.toLowerCase() === v);
    case 'actor':
      return s.actors.some((x) => x.toLowerCase() === v);
    case 'malware':
      return s.malware.some((x) => x.toLowerCase() === v);
    case 'cve':
      return s.cves.some((x) => x.toLowerCase() === v);
    case 'kw':
      return `${s.title} ${s.sources.map((x) => x.title).join(' ')}`.toLowerCase().includes(v);
  }
}

/** Quote a value for use in the search box. */
export function q(key: string, value: string): string {
  return /[\s"]/.test(value) ? `${key}:"${value.replace(/"/g, '')}"` : `${key}:${value}`;
}
