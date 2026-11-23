import { gunzipSync } from 'node:zlib';
import type { EnrichmentHealth, EpssMover } from '../../../shared/types';
import { CONFIG } from '../config';
import { fetchJson, fetchRaw } from '../fetch';
import type { HttpCacheEntry, StateStore } from '../state';
import { errMsg } from '../util';

export interface EpssScore {
  epss: number;
  pct: number;
}

export interface EpssData {
  date: string | null;
  model: string | null;
  scores: Map<string, EpssScore>;
  /** Previous-day score for CVEs that moved (used for 24h delta). */
  prev: Map<string, EpssScore>;
  prevDate: string | null;
  movers: Omit<EpssMover, 'kev' | 'stories'>[];
  modelChange: { from: string; to: string; date: string } | null;
}

interface EpssMeta {
  date: string | null;
  model: string | null;
  prevDate: string | null;
  movers: Omit<EpssMover, 'kev' | 'stories'>[];
  /** Previous scores for CVEs whose score changed materially, keyed by CVE. */
  prev: Record<string, [number, number]>;
  modelChange?: { from: string; to: string; date: string } | null;
}

const CSV_FILE = 'epss/current.csv.gz';
const META_FILE = 'epss/meta.json';

export function parseEpssCsv(gz: Uint8Array): { date: string | null; model: string | null; scores: Map<string, EpssScore> } {
  const text = gunzipSync(gz).toString('utf8');
  const scores = new Map<string, EpssScore>();
  let date: string | null = null;
  let model: string | null = null;
  let start = 0;
  while (start < text.length) {
    let end = text.indexOf('\n', start);
    if (end === -1) end = text.length;
    const line = text.slice(start, end).trim();
    start = end + 1;
    if (!line) continue;
    if (line.startsWith('#')) {
      model = /model_version:([^,]+)/.exec(line)?.[1]?.trim() ?? model;
      date = /score_date:(\d{4}-\d{2}-\d{2})/.exec(line)?.[1] ?? date;
      continue;
    }
    const c1 = line.indexOf(',');
    const c2 = line.indexOf(',', c1 + 1);
    if (c1 < 0 || c2 < 0) continue;
    const cve = line.slice(0, c1);
    if (!cve.startsWith('CVE-')) continue;
    const epss = Number(line.slice(c1 + 1, c2));
    const pct = Number(line.slice(c2 + 1));
    if (Number.isFinite(epss) && Number.isFinite(pct)) scores.set(cve, { epss, pct });
  }
  return { date, model, scores };
}

/** Compare two daily snapshots: big jumps, and CVEs newly crossing the 95th/99th percentile. */
export function computeMovers(prev: Map<string, EpssScore>, cur: Map<string, EpssScore>): { movers: EpssMeta['movers']; prevChanged: EpssMeta['prev'] } {
  const movers: EpssMeta['movers'] = [];
  const prevChanged: EpssMeta['prev'] = {};
  for (const [cve, s] of cur) {
    const p = prev.get(cve);
    const delta = p ? s.epss - p.epss : null;
    if (p && Math.abs(s.epss - p.epss) >= 0.01) prevChanged[cve] = [p.epss, p.pct];
    let kind: EpssMover['kind'] | null = null;
    if (delta !== null && delta >= CONFIG.rules.epssJump) kind = 'jump';
    else if (s.pct >= 0.99 && (!p || p.pct < 0.99)) kind = 'cross-p99';
    else if (s.pct >= 0.95 && (!p || p.pct < 0.95)) kind = 'cross-p95';
    if (kind) movers.push({ cve, epss: s.epss, pct: s.pct, prevEpss: p?.epss ?? null, prevPct: p?.pct ?? null, delta, kind });
  }
  const rank = { jump: 0, 'cross-p99': 1, 'cross-p95': 2 } as const;
  movers.sort((a, b) => rank[a.kind] - rank[b.kind] || (b.delta ?? 0) - (a.delta ?? 0) || b.epss - a.epss);
  return { movers: movers.slice(0, 300), prevChanged };
}

type Snapshot = ReturnType<typeof parseEpssCsv>;

/** Day-over-day comparison. A model change re-scores everything, so movers are paused that day. */
export function diffSnapshots(current: Snapshot, parsed: Snapshot): Pick<EpssMeta, 'movers' | 'prev' | 'modelChange'> {
  if (current.model && parsed.model && current.model !== parsed.model) {
    return { movers: [], prev: {}, modelChange: { from: current.model, to: parsed.model, date: parsed.date ?? '' } };
  }
  const { movers, prevChanged } = computeMovers(current.scores, parsed.scores);
  return { movers, prev: prevChanged, modelChange: null };
}

/**
 * Daily EPSS snapshot. Downloads the full CSV only when it changed; when the score date
 * advances, computes movers against the previous snapshot before replacing it.
 */
export async function updateEpss(store: StateStore, http: Record<string, HttpCacheEntry>): Promise<{ data: EpssData; health: EnrichmentHealth }> {
  const meta = store.readJson<EpssMeta>(META_FILE, { date: null, model: null, prevDate: null, movers: [], prev: {} });
  const cachedGz = store.readBuf(CSV_FILE);
  let current = cachedGz ? safeParse(cachedGz) : null;
  let health: EnrichmentHealth = { name: 'FIRST EPSS', status: 'error', detail: 'not fetched' };

  let lastError = '';
  for (const url of CONFIG.urls.epssCsv) {
    const res = await fetchRaw(url, { ...(cachedGz ? http.epss : {}), accept: 'application/gzip, */*', timeoutMs: 60_000, maxBytes: 64 * 1024 * 1024 });
    if (res.status === 'not-modified' && current) {
      health = { name: 'FIRST EPSS', status: 'ok', detail: `scores ${current.date} (not modified)` };
      lastError = '';
      break;
    }
    if (res.status === 'ok' && res.data) {
      const parsed = safeParse(res.data);
      if (!parsed || parsed.scores.size < 1000) {
        lastError = `${url}: unparseable CSV`;
        continue;
      }
      if (current && parsed.date && current.date && parsed.date !== current.date) {
        Object.assign(meta, diffSnapshots(current, parsed));
        meta.prevDate = current.date;
      }
      meta.date = parsed.date;
      meta.model = parsed.model;
      store.writeBuf(CSV_FILE, res.data);
      store.writeJson(META_FILE, meta);
      http.epss = { etag: res.etag, lastModified: res.lastModified };
      current = parsed;
      health = { name: 'FIRST EPSS', status: 'ok', detail: `scores ${parsed.date}, model ${parsed.model}, ${parsed.scores.size} CVEs` };
      lastError = '';
      break;
    }
    lastError = `${url}: ${res.error ?? res.httpStatus}`;
  }
  if (lastError) {
    health = current
      ? { name: 'FIRST EPSS', status: 'stale', detail: `using cached ${current.date}: ${lastError}` }
      : { name: 'FIRST EPSS', status: 'error', detail: lastError };
  }

  const prev = new Map(Object.entries(meta.prev).map(([k, [epss, pct]]) => [k, { epss, pct }]));
  return {
    data: {
      date: current?.date ?? null,
      model: current?.model ?? null,
      scores: current?.scores ?? new Map(),
      prev,
      prevDate: meta.prevDate,
      movers: meta.movers,
      modelChange: meta.modelChange && meta.modelChange.date === current?.date ? meta.modelChange : null,
    },
    health,
  };
}

function safeParse(gz: Uint8Array): ReturnType<typeof parseEpssCsv> | null {
  try {
    return parseEpssCsv(gz);
  } catch {
    return null;
  }
}

/** Fallback when the CSV is unavailable: query the API for specific CVEs. */
export async function epssApiLookup(cves: string[]): Promise<Map<string, EpssScore>> {
  const out = new Map<string, EpssScore>();
  for (let i = 0; i < cves.length; i += 80) {
    const batch = cves.slice(i, i + 80);
    try {
      const { json } = await fetchJson<{ data?: { cve: string; epss: string; percentile: string }[] }>(
        `${CONFIG.urls.epssApi}?cve=${batch.join(',')}`,
      );
      for (const d of json?.data ?? []) out.set(d.cve, { epss: Number(d.epss), pct: Number(d.percentile) });
    } catch (e) {
      console.warn(`EPSS API batch failed: ${errMsg(e)}`);
    }
  }
  return out;
}
