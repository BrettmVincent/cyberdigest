// CIRCL Vulnerability-Lookup: multi-source KEV catalogues, typed sightings (rolling 30-day counts),
// and Rulezet detection-rule counts for hot CVEs. Honours the published API policy:
// ≤20 req/min anonymous, incremental date_from pulls, a User-Agent with a contact URL.
import type { CveInfo } from '../../../shared/types';
import { fetchJson } from '../fetch';
import type { SourceRegistry } from '../sources';
import type { Upstream } from '../upstream';
import { DAY, errMsg, isoDay } from '../util';

const BASE = 'https://vulnerability.circl.lu/api';
const PAGE = 1000;

export const CATALOG_NAMES: Record<string, string> = {
  'cisa-kev': 'CISA',
  'enisa-cnw-kev': 'ENISA',
  shadowserver: 'Shadowserver',
  siberkapan: 'SiberKapan',
  previdian: 'Previdian',
  circl: 'CIRCL',
};

export function catalogName(source: string): string {
  const k = source.toLowerCase();
  return CATALOG_NAMES[k] ?? source.replace(/(^|[-_\s])(\w)/g, (_, s: string, c: string) => `${s ? ' ' : ''}${c.toUpperCase()}`).trim();
}

/** exploited, seen, poc, honeypot-exploited */
type DayCounts = [number, number, number, number];

export interface CirclState {
  kevBackfilled: boolean;
  kevCursor: string | null;
  kev: Record<string, string[]>;
  sightCursorDay: string | null;
  sight: Record<string, Record<string, DayCounts>>;
  rulezet: Record<string, { n: number; at: string }>;
}

const EMPTY: CirclState = { kevBackfilled: false, kevCursor: null, kev: {}, sightCursorDay: null, sight: {}, rulezet: {} };

interface KevEntry {
  vulnerability?: { vulnId?: string };
  status?: { exploited?: boolean };
  evidence?: { source?: string }[];
}
interface Sighting {
  vulnerability?: string;
  type?: string;
  source?: string;
  creation_timestamp?: string;
}
interface Paged<T> {
  metadata?: { count?: number };
  data?: T[];
}

const HONEYPOT_RE = /shadowserver|mirage|honeypot/i;
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export function classifySighting(s: Sighting): { cve: string; day: string; idx: 0 | 1 | 2; honeypot: boolean } | null {
  const cve = (s.vulnerability ?? '').toUpperCase();
  if (!/^CVE-\d{4}-\d{4,7}$/.test(cve) || !s.creation_timestamp) return null;
  const t = (s.type ?? '').toLowerCase();
  const idx = t === 'exploited' ? 0 : t.includes('proof-of-concept') ? 2 : 1;
  return { cve, day: s.creation_timestamp.slice(0, 10), idx, honeypot: idx === 0 && HONEYPOT_RE.test(s.source ?? '') };
}

export class Circl {
  state: CirclState;
  private requests = 0;
  private headers: Record<string, string>;

  constructor(private u: Upstream) {
    this.state = { ...EMPTY, ...u.store.readJson<Partial<CirclState>>('circl.json', {}) };
    const key = process.env.CIRCL_API_KEY;
    this.headers = key ? { 'X-API-KEY': key } : {};
  }

  /** Paced GET: ~18 req/min without a key, ~36 with one. */
  private async get<T>(path: string): Promise<T> {
    if (this.requests++ > 0) await sleep(this.headers['X-API-KEY'] ? 1700 : 3400);
    const { result, json } = await fetchJson<T>(`${BASE}${path}`, { headers: this.headers, timeoutMs: 45_000, maxBytes: 64 * 1024 * 1024 });
    if (!json) throw new Error(`${path.split('?')[0]}: ${result.error ?? `HTTP ${result.httpStatus}`}`);
    return json;
  }

  private async paged<T>(path: string, maxPages: number): Promise<T[]> {
    const out: T[] = [];
    for (let page = 1; page <= maxPages; page++) {
      const sep = path.includes('?') ? '&' : '?';
      const res = await this.get<Paged<T>>(`${path}${sep}per_page=${PAGE}&page=${page}`);
      const data = res.data ?? [];
      out.push(...data);
      if (data.length < PAGE) break;
    }
    return out;
  }

  async updateKev(reg: SourceRegistry): Promise<void> {
    try {
      const since = this.state.kevBackfilled && this.state.kevCursor ? `?date_from=${this.state.kevCursor.slice(0, 10)}` : '';
      const entries = await this.paged<KevEntry>(`/kev/${since}`, since ? 5 : 20);
      for (const e of entries) {
        const cve = e.vulnerability?.vulnId?.toUpperCase();
        if (!cve?.startsWith('CVE-') || e.status?.exploited === false) continue;
        const cats = new Set(this.state.kev[cve] ?? []);
        for (const ev of e.evidence ?? []) if (ev.source) cats.add(catalogName(ev.source));
        if (cats.size) this.state.kev[cve] = [...cats].sort();
      }
      this.state.kevBackfilled = true;
      this.state.kevCursor = new Date(this.u.now - DAY).toISOString();
      reg.set('circl-kev', { status: 'ok', detail: `${Object.keys(this.state.kev).length} exploited CVEs across catalogues (+${entries.length} entries this run)`, retrieved: true });
    } catch (e) {
      reg.set('circl-kev', { status: Object.keys(this.state.kev).length ? 'stale' : 'error', detail: errMsg(e) });
    }
  }

  async updateSightings(reg: SourceRegistry): Promise<void> {
    const today = isoDay(this.u.now);
    const from = this.state.sightCursorDay ?? isoDay(this.u.now - 29 * DAY);
    try {
      // Only exploitation and public-PoC sightings: "seen" mentions are high-volume social posts with little signal.
      const items: Sighting[] = [];
      for (const type of ['exploited', 'published-proof-of-concept']) {
        items.push(...(await this.paged<Sighting>(`/sighting/?date_from=${from}&type=${type}`, this.state.sightCursorDay ? 4 : 12)));
      }
      const fresh: Record<string, Record<string, DayCounts>> = {};
      for (const s of items) {
        const c = classifySighting(s);
        if (!c || c.day < from) continue;
        const day = (fresh[c.day] ??= {});
        const counts = (day[c.cve] ??= [0, 0, 0, 0]);
        counts[c.idx]++;
        if (c.honeypot) counts[3]++;
      }
      // Replace every day ≥ cursor with the fresh tallies (re-fetching yesterday+today avoids double counting).
      for (const d of Object.keys(this.state.sight)) if (d >= from) delete this.state.sight[d];
      Object.assign(this.state.sight, fresh);
      const cutoff = isoDay(this.u.now - 30 * DAY);
      for (const d of Object.keys(this.state.sight)) if (d < cutoff) delete this.state.sight[d];
      this.state.sightCursorDay = isoDay(Date.parse(today) - DAY);
      reg.set('circl-sightings', { status: 'ok', detail: `${items.length} sightings since ${from}; 30-day window kept`, retrieved: true });
    } catch (e) {
      reg.set('circl-sightings', { status: Object.keys(this.state.sight).length ? 'stale' : 'error', detail: errMsg(e) });
    }
  }

  /** Rule counts from Rulezet for up to `max` hot CVEs not checked in the last 7 days. */
  async updateRulezet(hot: string[], reg: SourceRegistry, max = 10): Promise<void> {
    const due = hot.filter((c) => !this.state.rulezet[c] || this.u.now - Date.parse(this.state.rulezet[c]!.at) > 7 * DAY).slice(0, max);
    let ok = 0;
    for (const cve of due) {
      try {
        const res = await this.get<Paged<unknown>>(`/rulezet/search_rules_by_vulnerabilities/${cve}?per_page=1`);
        this.state.rulezet[cve] = { n: res.metadata?.count ?? 0, at: new Date(this.u.now).toISOString() };
        ok++;
      } catch {
        break;
      }
    }
    for (const [c, v] of Object.entries(this.state.rulezet)) if (this.u.now - Date.parse(v.at) > 30 * DAY) delete this.state.rulezet[c];
    reg.set('rulezet', { status: 'ok', detail: `${ok} hot CVEs checked this run; ${Object.keys(this.state.rulezet).length} cached`, retrieved: ok > 0 });
  }

  /** `extra`: catalogue names from other sources (e.g. VulnCheck KEV) merged with CIRCL's. */
  exploitation(cve: string, inCisaKev: boolean, extra: string[] = []): CveInfo['exploitation'] | undefined {
    const catalogs = [...new Set([...(this.state.kev[cve] ?? []), ...extra])].sort();
    let e = 0;
    let p = 0;
    let honeypot7d = false;
    const recent = isoDay(this.u.now - 7 * DAY);
    for (const [day, perCve] of Object.entries(this.state.sight)) {
      const c = perCve[cve];
      if (!c) continue;
      e += c[0];
      p += c[2];
      if (c[3] > 0 && day >= recent) honeypot7d = true;
    }
    if (!catalogs.length && !e && !p) return undefined;
    return { catalogs, notInCisa: catalogs.length > 0 && !inCisaKev && !catalogs.includes('CISA'), exploited30d: e, poc30d: p, honeypot7d };
  }

  rulezetCount(cve: string): number | undefined {
    return this.state.rulezet[cve]?.n;
  }

  save(): void {
    this.u.store.writeJson('circl.json', this.state);
  }
}
