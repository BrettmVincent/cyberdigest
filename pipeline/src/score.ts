import type { CveInfo, Priority, Reason, SourceTier } from '../../shared/types';
import { CONFIG } from './config';
import { DAY, HOUR } from './util';

export interface ScoreItem {
  feedId: string;
  tier: SourceTier;
  firehose: boolean;
  /** Item from an all-CVE aggregator feed: never corroborates (multi-source, exploitation claims). */
  aggregator?: boolean;
  time: number;
  exploited: boolean;
  cves: string[];
  /** CVEs this item is actually about: named in its headline, or all of them if it names ≤ 3. */
  focalCves: string[];
  hasThreatEntity: boolean;
}

/** Round-ups list dozens of CVEs; only headline CVEs (or a short list) count as the item's subject. */
export function focalCves(cves: string[], titleCves: string[], maxListed = 3): string[] {
  return cves.length <= maxListed ? cves : titleCves;
}

export interface ScoreResult {
  priority: Priority;
  reasons: Reason[];
}

const pctLabel = (p: number) => {
  const n = Math.floor(p * 100);
  const suffix = n % 10 === 1 && n !== 11 ? 'st' : n % 10 === 2 && n !== 12 ? 'nd' : n % 10 === 3 && n !== 13 ? 'rd' : 'th';
  return `${n}${suffix}`;
};

export function epssLabel(epss: number, pct: number): string {
  return `EPSS ${(epss * 100).toFixed(epss < 0.1 ? 1 : 0)}% (${pctLabel(pct)})`;
}

/**
 * Ordered rules — the story takes the highest priority any rule assigns.
 * Every rule that fires contributes a reason so the ranking is explainable.
 */
export function scoreStory(items: ScoreItem[], cveInfo: (id: string) => CveInfo | undefined, now: number, rules = CONFIG.rules): ScoreResult {
  const reasons: Reason[] = [];
  let priority: Priority = 4;
  const raise = (p: Priority) => {
    if (p < priority) priority = p;
  };
  // One chip per rule; when a rule fires for several CVEs, show the one that set the highest priority.
  const chipPriority = new Map<Reason['code'], Priority>();
  const add = (r: Reason, p: Priority) => {
    const prev = chipPriority.get(r.code);
    if (prev === undefined) reasons.push(r);
    else if (p < prev) reasons[reasons.findIndex((x) => x.code === r.code)] = r;
    if (prev === undefined || p < prev) chipPriority.set(r.code, p);
    raise(p);
  };

  const cves = [...new Set(items.flatMap((i) => i.cves))];
  const infos = cves.map(cveInfo).filter((x): x is CveInfo => Boolean(x));
  const focal = new Set(items.flatMap((i) => i.focalCves));
  // CVE rules that would make a story P1 cap at P2 when the CVE is only listed in passing.
  const urgent = (c: CveInfo): Priority => (focal.has(c.id) ? 1 : 2);

  // ── P1: act now ──
  for (const c of infos) {
    if (!c.kev) continue;
    const ageDays = (now - Date.parse(c.kev.dateAdded)) / DAY;
    if (ageDays <= rules.kevNewDays) {
      add({ code: 'kev-new', label: `KEV +${Math.max(0, Math.floor(ageDays))}d`, cve: c.id }, urgent(c));
    }
    const dueIn = (Date.parse(c.kev.dueDate) - now) / DAY;
    if (c.kev.ransomware && dueIn <= rules.kevRansomDueDays && dueIn >= -7) {
      add({ code: 'kev-ransom', label: 'KEV · ransomware', cve: c.id }, urgent(c));
    }
  }
  // SSVC "active" means exploited at some point, so it is only urgent for recent CVEs.
  for (const c of infos) {
    if (c.ssvc?.exploitation !== 'active') continue;
    if (cveAgeDays(c, now) <= rules.ssvcActiveUrgentDays) add({ code: 'ssvc-active', label: 'SSVC: active', cve: c.id }, urgent(c));
    else if (cveAgeDays(c, now) <= 365) add({ code: 'ssvc-active', label: 'SSVC: active', cve: c.id }, 2);
  }
  if (items.some((i) => i.tier === 'A' && i.exploited)) add({ code: 'exploited-advisory', label: 'Exploited (advisory)' }, 1);

  // ── P2: high: ransomware & multi-source exploitation ──
  for (const c of infos) {
    const flipped = c.ransomware?.flippedAt;
    if (flipped && (now - Date.parse(flipped)) / DAY <= rules.kevFlipDays) {
      add({ code: 'kev-ransom-flip', label: 'KEV: newly ransomware-linked', cve: c.id }, 2);
    }
    const groups = c.ransomware?.groups ?? [];
    if (groups.length) {
      const hot = cveAgeDays(c, now) <= 365 && (Boolean(c.kev) || (c.epss ?? 0) >= rules.epssHigh);
      const names = groups.slice(0, 2).map((g) => g.name).join(', ') + (groups.length > 2 ? ` +${groups.length - 2}` : '');
      add({ code: 'ransomware-linked', label: `Ransomware: ${names}`, cve: c.id }, hot ? 2 : 3);
    }
    const ex = c.exploitation;
    if (ex?.notInCisa && cveAgeDays(c, now) <= 365) {
      const strong = ex.catalogs.filter((k) => k !== 'Previdian');
      add({ code: 'exploited-multi', label: `Exploited: ${ex.catalogs.join(' + ')}`, cve: c.id }, strong.length ? 2 : 3);
    }
    if (ex?.honeypot7d && cveAgeDays(c, now) <= 365 * 3) add({ code: 'honeypot', label: 'Honeypot hits (7d)', cve: c.id }, 2);
  }

  // ── P2: high ──
  // Older KEV entries still matter, but a passing mention of e.g. Log4Shell should not outrank fresh news.
  for (const c of infos) {
    if (!c.kev || reasons.some((r) => r.code === 'kev-new' && r.cve === c.id)) continue;
    const recent = now - Date.parse(c.kev.dateAdded) <= rules.kevRecentForHighDays * DAY;
    add({ code: 'kev', label: recent ? 'KEV' : `KEV (${c.kev.dateAdded.slice(0, 4)})`, cve: c.id }, recent ? 2 : 3);
  }
  if (items.some((i) => i.tier !== 'A' && i.exploited && !i.aggregator)) add({ code: 'exploited-claim', label: 'Exploitation reported' }, 2);

  // EPSS-high only for CVEs from the last year: old, well-known CVEs score high forever.
  const byEpss = [...infos].filter((c) => c.epss !== null && cveAgeDays(c, now) <= 365).sort((a, b) => b.epss! - a.epss!);
  const highEpss = byEpss.find((c) => c.epss! >= rules.epssHigh && (c.cvss ?? 0) >= rules.cvssHigh);
  if (highEpss) add({ code: 'epss-high', label: epssLabel(highEpss.epss!, highEpss.epssPct!), cve: highEpss.id }, 2);
  const jump = infos.filter((c) => (c.epssDelta ?? 0) >= rules.epssJump).sort((a, b) => b.epssDelta! - a.epssDelta!)[0];
  if (jump) add({ code: 'epss-jump', label: `EPSS +${(jump.epssDelta! * 100).toFixed(0)} pts`, cve: jump.id }, 2);

  const poc = infos.find(
    (c) => c.poc?.firstSeen && now - Date.parse(c.poc.firstSeen) <= rules.pocNewHours * HOUR && ((c.cvss ?? 0) >= rules.cvssHigh || /critical|high/i.test(c.severity ?? '')),
  );
  if (poc) add({ code: 'poc-new', label: 'New public PoC', cve: poc.id }, 2);

  const independent = items.filter((i) => !i.aggregator);
  const first = Math.min(...independent.map((i) => i.time));
  const early = new Set(independent.filter((i) => i.time - first <= rules.multiSourceWindowHours * HOUR).map((i) => i.feedId));
  if (early.size >= rules.multiSourceCount) add({ code: 'multi-source', label: `${early.size} sources in 24h` }, 2);

  // ── P3: monitor ──
  if (items.some((i) => i.tier === 'A' && !i.firehose)) add({ code: 'advisory', label: 'Advisory' }, 3);
  if (items.some((i) => i.tier === 'B' && (i.cves.length > 0 || i.hasThreatEntity))) add({ code: 'research', label: 'Research' }, 3);

  // Keep only the reasons that explain the final priority band, plus higher ones.
  return { priority, reasons: reasons.filter((r) => reasonPriority(r.code) <= Math.max(priority, 2)) };
}

/** Days since the CVE was published (falls back to KEV date, then the CVE ID year). */
export function cveAgeDays(c: CveInfo, now: number): number {
  const ref = c.published ?? c.kev?.dateAdded;
  if (ref) return (now - Date.parse(ref)) / DAY;
  const year = Number(c.id.slice(4, 8));
  return year >= new Date(now).getUTCFullYear() ? 0 : year === new Date(now).getUTCFullYear() - 1 ? 180 : 9999;
}

function reasonPriority(code: Reason['code']): Priority {
  switch (code) {
    case 'kev-new':
    case 'kev-ransom':
    case 'ssvc-active':
    case 'exploited-advisory':
      return 1;
    case 'advisory':
    case 'research':
      return 3;
    default:
      return 2;
  }
}
