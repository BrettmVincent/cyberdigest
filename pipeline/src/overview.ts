// Aggregates for the Overview tab (charts + world map) and actor profiles.
import type { ActorProfile, CountryStat, CveInfo, FeedGroup, Named, Overview, Story } from '../../shared/types';
import type { KevCatalog } from './enrich/kev';
import type { DictEntry } from './extract';
import { countryName, countryNumeric } from './geo';
import { DAY, isoDay } from './util';

const CWE_NAMES: Record<string, string> = {
  'CWE-20': 'Improper input validation', 'CWE-22': 'Path traversal', 'CWE-77': 'Command injection', 'CWE-78': 'OS command injection',
  'CWE-79': 'Cross-site scripting', 'CWE-89': 'SQL injection', 'CWE-94': 'Code injection', 'CWE-119': 'Memory buffer bounds',
  'CWE-120': 'Classic buffer overflow', 'CWE-121': 'Stack buffer overflow', 'CWE-122': 'Heap buffer overflow', 'CWE-125': 'Out-of-bounds read',
  'CWE-190': 'Integer overflow', 'CWE-200': 'Information exposure', 'CWE-269': 'Improper privilege management', 'CWE-276': 'Incorrect default permissions',
  'CWE-284': 'Improper access control', 'CWE-285': 'Improper authorization', 'CWE-287': 'Improper authentication', 'CWE-288': 'Auth bypass via alternate path',
  'CWE-290': 'Auth bypass by spoofing', 'CWE-306': 'Missing authentication', 'CWE-312': 'Cleartext storage', 'CWE-319': 'Cleartext transmission',
  'CWE-326': 'Weak encryption', 'CWE-352': 'Cross-site request forgery', 'CWE-362': 'Race condition', 'CWE-400': 'Resource exhaustion',
  'CWE-416': 'Use after free', 'CWE-427': 'Uncontrolled search path', 'CWE-434': 'Unrestricted file upload', 'CWE-476': 'NULL pointer dereference',
  'CWE-502': 'Unsafe deserialization', 'CWE-601': 'Open redirect', 'CWE-611': 'XML external entity', 'CWE-639': 'Authorization bypass (IDOR)',
  'CWE-668': 'Exposure to wrong sphere', 'CWE-732': 'Incorrect permission assignment', 'CWE-770': 'Unlimited resource allocation',
  'CWE-787': 'Out-of-bounds write', 'CWE-798': 'Hard-coded credentials', 'CWE-843': 'Type confusion', 'CWE-862': 'Missing authorization',
  'CWE-863': 'Incorrect authorization', 'CWE-918': 'Server-side request forgery', 'CWE-1321': 'Prototype pollution',
  'CWE-908': 'Uninitialized resource', 'CWE-822': 'Untrusted pointer dereference', 'CWE-823': 'Out-of-range pointer offset',
  'CWE-824': 'Uninitialized pointer access', 'CWE-191': 'Integer underflow', 'CWE-23': 'Relative path traversal', 'CWE-74': 'Injection', 'CWE-59': 'Link following', 'CWE-367': 'TOCTOU race',
  'CWE-401': 'Memory leak', 'CWE-415': 'Double free', 'CWE-617': 'Reachable assertion', 'CWE-835': 'Infinite loop',
  'CWE-704': 'Incorrect type conversion', 'CWE-1284': 'Improper quantity validation', 'CWE-73': 'External file path control',
  'CWE-116': 'Improper output encoding', 'CWE-209': 'Error message info leak', 'CWE-347': 'Bad signature verification',
  'CWE-379': 'Insecure temp file', 'CWE-532': 'Sensitive data in logs', 'CWE-565': 'Cookie trust', 'CWE-829': 'Untrusted functionality',
};

export interface OverviewInput {
  now: number;
  /** All clusters in the 30-day window, with their first-reported time. */
  allStories: (Story & { start: number })[];
  /** Published stories (14-day window). */
  stories: Story[];
  cveInfo: (id: string) => CveInfo | undefined;
  kev: KevCatalog | null;
  items: { feedGroup: FeedGroup; time: number }[];
  actorDict: Map<string, DictEntry>;
  trendDays: string[];
  /** ISO alpha-2 → ransomware claims / reported attacks (30 days). */
  ransomCountries?: Record<string, number>;
}

const top = <T>(m: Map<string, T>, score: (v: T) => number, n: number) => [...m.entries()].sort((a, b) => score(b[1]) - score(a[1]) || a[0].localeCompare(b[0])).slice(0, n);

export function buildOverview(inp: OverviewInput): Overview {
  const { now, allStories, stories } = inp;
  const today = Date.parse(isoDay(now));
  const days = Array.from({ length: 30 }, (_, i) => isoDay(today - (29 - i) * DAY));
  const dayIdx = new Map(days.map((d, i) => [d, i]));

  // Priority mix per day.
  const priorityByDay = days.map((day) => ({ day, p: [0, 0, 0, 0] as [number, number, number, number] }));
  for (const s of allStories) {
    const i = dayIdx.get(isoDay(s.start));
    if (i === undefined) continue;
    const row = priorityByDay[i]!.p;
    row[s.priority - 1] = (row[s.priority - 1] ?? 0) + 1;
  }

  // KEV additions per ISO week (Monday start), last 26 weeks.
  const monday = (t: number) => {
    const d = new Date(t);
    return Date.parse(isoDay(t)) - ((d.getUTCDay() + 6) % 7) * DAY;
  };
  const thisWeek = monday(now);
  const kevByWeek = Array.from({ length: 26 }, (_, i) => ({ week: isoDay(thisWeek - (25 - i) * 7 * DAY), total: 0, ransomware: 0 }));
  const weekIdx = new Map(kevByWeek.map((w, i) => [w.week, i]));
  for (const v of inp.kev?.vulnerabilities ?? []) {
    const i = weekIdx.get(isoDay(monday(Date.parse(v.dateAdded))));
    if (i === undefined) continue;
    kevByWeek[i]!.total++;
    if (v.knownRansomwareCampaignUse === 'Known') kevByWeek[i]!.ransomware++;
  }

  // What an analyst actually sees: P1–P3 stories in the 14-day window.
  const visible = stories.filter((s) => s.priority <= 3);
  const visibleCves = [...new Set(visible.flatMap((s) => s.cves))].map(inp.cveInfo).filter((c): c is CveInfo => Boolean(c));

  const vendorMap = new Map<string, { stories: number; high: number; kev: number }>();
  for (const s of visible) {
    for (const v of s.vendors) {
      const e = vendorMap.get(v) ?? { stories: 0, high: 0, kev: 0 };
      e.stories++;
      if (s.priority <= 2) e.high++;
      if (s.cves.some((c) => inp.cveInfo(c)?.kev)) e.kev++;
      vendorMap.set(v, e);
    }
  }
  const vendors = top(vendorMap, (v) => v.stories * 10 + v.high, 12).map(([name, v]) => ({ name, ...v }));

  const cweMap = new Map<string, number>();
  for (const c of visibleCves) for (const w of c.cwe ?? []) cweMap.set(w, (cweMap.get(w) ?? 0) + 1);
  const cwes = top(cweMap, (n) => n, 10).map(([id, count]) => ({ id, name: CWE_NAMES[id] ?? id, count }));

  const sev = { Critical: 0, High: 0, Medium: 0, Low: 0, 'Not scored yet': 0 };
  for (const c of visibleCves) {
    const s = c.cvss;
    if (s == null) sev['Not scored yet']++;
    else if (s >= 9) sev.Critical++;
    else if (s >= 7) sev.High++;
    else if (s >= 4) sev.Medium++;
    else sev.Low++;
  }
  const severity = Object.entries(sev).map(([label, count]) => ({ label, count }));

  const bins: [string, (e: number) => boolean][] = [
    ['< 1%', (e) => e < 0.01],
    ['1–10%', (e) => e >= 0.01 && e < 0.1],
    ['10–50%', (e) => e >= 0.1 && e < 0.5],
    ['≥ 50%', (e) => e >= 0.5],
  ];
  const epssBins = [
    ...bins.map(([label, f]) => ({ label, count: visibleCves.filter((c) => c.epss !== null && f(c.epss)).length })),
    { label: 'n/a', count: visibleCves.filter((c) => c.epss === null).length },
  ];

  const groupMap = new Map<FeedGroup, { items: number; stories: number }>();
  const cutoff14 = now - 14 * DAY;
  for (const it of inp.items) {
    if (it.time < cutoff14) continue;
    const g = groupMap.get(it.feedGroup) ?? { items: 0, stories: 0 };
    g.items++;
    groupMap.set(it.feedGroup, g);
  }
  for (const s of visible) {
    const g = groupMap.get(s.group) ?? { items: 0, stories: 0 };
    g.stories++;
    groupMap.set(s.group, g);
  }
  const groups = [...groupMap.entries()].map(([group, v]) => ({ group, ...v })).sort((a, b) => b.items - a.items);

  // Countries: in the news / actor origin / actor targets.
  const cmap = new Map<string, CountryStat>();
  const country = (iso: string): CountryStat => {
    let c = cmap.get(iso);
    if (!c) {
      c = { iso, numeric: countryNumeric(iso), name: countryName(iso), news: 0, origin: 0, targeted: 0, ransom: 0, newsStories: [], originActors: [], targetActors: [] };
      cmap.set(iso, c);
    }
    return c;
  };
  // Geography uses every published story: country mentions mostly come from news coverage (often P4).
  for (const s of stories) {
    for (const iso of s.countries) {
      const c = country(iso);
      c.news++;
      if (c.newsStories.length < 8) c.newsStories.push(s.id);
    }
    const origins = new Set<string>();
    for (const a of s.actors) {
      const iso = inp.actorDict.get(a)?.country;
      if (!iso) continue;
      origins.add(iso);
      const c = country(iso);
      if (!c.originActors.includes(a)) c.originActors.push(a);
    }
    for (const iso of origins) country(iso).origin++;
  }
  const activeActors = new Set(stories.flatMap((s) => s.actors));
  for (const a of activeActors) {
    for (const iso of inp.actorDict.get(a)?.targets ?? []) {
      const c = country(iso);
      c.targeted++;
      c.targetActors.push(a);
    }
  }
  for (const [iso, n] of Object.entries(inp.ransomCountries ?? {})) country(iso).ransom = n;
  const countries = [...cmap.values()].sort((a, b) => b.news - a.news || b.origin - a.origin || b.targeted - a.targeted);

  // Headline tiles: this week vs the week before.
  const inWeek = (t: number, w: 0 | 1) => t <= now - w * 7 * DAY && t > now - (w + 1) * 7 * DAY;
  const pair = (f: (w: 0 | 1) => number): [number, number] => [f(0), f(1)];
  const kevTimes = (inp.kev?.vulnerabilities ?? []).map((v) => Date.parse(v.dateAdded) + DAY / 2);
  const exploitedCves = (w: 0 | 1) =>
    new Set(
      allStories
        .filter((s) => inWeek(s.start, w))
        .flatMap((s) => s.cves)
        .filter((id) => {
          const c = inp.cveInfo(id);
          return c?.kev || c?.ssvc?.exploitation === 'active';
        }),
    ).size;

  return {
    days,
    priorityByDay,
    kevByWeek,
    vendors,
    cwes,
    severity,
    epssBins,
    groups,
    countries,
    tiles: {
      p1: pair((w) => allStories.filter((s) => s.priority === 1 && inWeek(s.start, w)).length),
      kev: pair((w) => kevTimes.filter((t) => inWeek(t, w)).length),
      stories: pair((w) => allStories.filter((s) => s.priority <= 3 && inWeek(s.start, w)).length),
      exploitedCves: pair(exploitedCves),
    },
  };
}

/** Profiles for every actor mentioned in the 30-day window. */
export function buildActors(inp: OverviewInput): ActorProfile[] {
  const dayIdx = new Map(inp.trendDays.map((d, i) => [d, i]));
  const published = new Set(inp.stories.map((s) => s.id));
  const byActor = new Map<string, (Story & { start: number })[]>();
  for (const s of inp.allStories) for (const a of s.actors) byActor.set(a, [...(byActor.get(a) ?? []), s]);

  const profiles: ActorProfile[] = [];
  for (const [name, list] of byActor) {
    const d = inp.actorDict.get(name);
    list.sort((a, b) => b.lastSeen.localeCompare(a.lastSeen));
    const days = new Array<number>(inp.trendDays.length).fill(0);
    for (const s of list) {
      const i = dayIdx.get(isoDay(s.start));
      if (i !== undefined) days[i]!++;
    }
    const count = (pick: (s: Story) => string[]): Named[] => {
      const m = new Map<string, number>();
      for (const s of list) for (const x of pick(s)) m.set(x, (m.get(x) ?? 0) + 1);
      return top(m, (n) => n, 8).map(([n, c]) => ({ name: n, count: c }));
    };
    profiles.push({
      name,
      aliases: (d?.aliases ?? []).filter((a) => a !== name).slice(0, 12),
      country: d?.country ?? null,
      countryName: d?.country ? countryName(d.country) : null,
      countryNumeric: d?.country ? countryNumeric(d.country) : null,
      targets: (d?.targets ?? []).map((iso) => ({ iso, name: countryName(iso), numeric: countryNumeric(iso) })),
      sectors: d?.sectors ?? [],
      motive: d?.motive ?? null,
      description: d?.description ?? null,
      stories: list.filter((s) => published.has(s.id)).map((s) => s.id).slice(0, 40),
      days,
      last7: days.slice(-7).reduce((a, b) => a + b, 0),
      total30: list.length,
      malware: count((s) => s.malware),
      vendors: count((s) => s.vendors),
      cves: [...new Set(list.flatMap((s) => s.cves))].slice(0, 30),
      lastSeen: list[0]!.lastSeen,
    });
  }
  return profiles.sort((a, b) => b.last7 - a.last7 || b.total30 - a.total30 || a.name.localeCompare(b.name));
}
