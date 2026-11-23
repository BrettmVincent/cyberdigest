import type { EnrichmentHealth } from '../../../shared/types';
import { CONFIG } from '../config';
import { fetchJson } from '../fetch';
import { HOUR, pool } from '../util';

export interface CveSummary {
  id: string;
  fetchedAt: string;
  missing?: boolean;
  state?: string;
  published?: string;
  description?: string;
  cvss?: number;
  cvssVersion?: string;
  severity?: string;
  cwe?: string[];
  vendor?: string;
  product?: string;
  ssvc?: { exploitation?: string; automatable?: string; technicalImpact?: string };
}

export interface PocSummary {
  fetchedAt: string;
  count: number;
  firstSeen?: string;
}

type Json = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

export function cvePath(id: string): string | null {
  const m = /^CVE-(\d{4})-(\d{4,7})$/.exec(id);
  if (!m) return null;
  return `${m[1]}/${Math.floor(Number(m[2]) / 1000)}xxx/${id}.json`;
}

const METRIC_ORDER = ['cvssV3_1', 'cvssV4_0', 'cvssV3_0', 'cvssV2_0'] as const;

function pickCvss(metrics: Json[] | undefined): { score: number; version: string; severity?: string } | null {
  for (const key of METRIC_ORDER) {
    for (const m of metrics ?? []) {
      const v = m?.[key];
      if (v && typeof v.baseScore === 'number') {
        return { score: v.baseScore, version: key.replace('cvssV', '').replace('_', '.'), severity: v.baseSeverity };
      }
    }
  }
  return null;
}

/** Reduce a CVE JSON 5.x record to the fields the dashboard uses. */
export function summarizeCveRecord(rec: Json, id: string): CveSummary {
  const meta = rec.cveMetadata ?? {};
  const cna = rec.containers?.cna ?? {};
  const adps: Json[] = rec.containers?.adp ?? [];
  const cisa = adps.find((a) => a?.providerMetadata?.shortName === 'CISA-ADP');
  const cvss = pickCvss(cna.metrics) ?? pickCvss(adps.flatMap((a) => a.metrics ?? []));

  let ssvc: CveSummary['ssvc'];
  for (const m of cisa?.metrics ?? []) {
    if (m?.other?.type === 'ssvc') {
      const opts: Json[] = m.other.content?.options ?? [];
      const get = (k: string) => opts.find((o) => k in o)?.[k] as string | undefined;
      ssvc = { exploitation: get('Exploitation'), automatable: get('Automatable'), technicalImpact: get('Technical Impact') };
    }
  }

  const desc = (cna.descriptions as Json[] | undefined)?.find((d) => String(d.lang ?? '').startsWith('en'))?.value;
  const cwe = [
    ...new Set(
      ((cna.problemTypes as Json[] | undefined) ?? [])
        .flatMap((p) => (p.descriptions as Json[] | undefined) ?? [])
        .map((d) => d.cweId as string | undefined)
        .filter((x): x is string => Boolean(x)),
    ),
  ];
  const affected = (cna.affected as Json[] | undefined)?.[0];
  const clean = (s: unknown) => (typeof s === 'string' && s.trim() && s.toLowerCase() !== 'n/a' ? s.trim() : undefined);

  return {
    id,
    fetchedAt: new Date().toISOString(),
    state: meta.state,
    published: meta.datePublished,
    description: typeof desc === 'string' ? desc.slice(0, 600) : undefined,
    cvss: cvss?.score,
    cvssVersion: cvss?.version,
    severity: cvss?.severity,
    cwe: cwe.length ? cwe : undefined,
    vendor: clean(affected?.vendor),
    product: clean(affected?.product),
    ssvc,
  };
}

function authHeaders(): Record<string, string> {
  const t = process.env.GITHUB_TOKEN;
  return t ? { Authorization: `Bearer ${t}` } : {};
}

function stale(fetchedAt: string | undefined, ttlHours: number): boolean {
  return !fetchedAt || Date.now() - Date.parse(fetchedAt) > ttlHours * HOUR;
}

/** Pick which CVEs to (re)fetch this run: never-seen first (in the caller's priority order), then the stalest. */
function plan<T extends { fetchedAt: string; missing?: boolean }>(ids: string[], cache: Record<string, T>, ttlHours: number, max: number): string[] {
  const fresh = ids.filter((id) => !cache[id]);
  const due = ids
    .filter((id) => cache[id] && stale(cache[id]!.fetchedAt, cache[id]!.missing ? ttlHours / 4 : ttlHours))
    .sort((a, b) => Date.parse(cache[a]!.fetchedAt) - Date.parse(cache[b]!.fetchedAt));
  return [...fresh, ...due].slice(0, max);
}

export async function enrichCves(ids: string[], cache: Record<string, CveSummary>): Promise<EnrichmentHealth> {
  const todo = plan(ids, cache, CONFIG.enrich.cveTtlHours, CONFIG.enrich.maxFetchPerRun);
  let ok = 0;
  let missing = 0;
  let failed = 0;
  await pool(todo, 6, async (id) => {
    const path = cvePath(id);
    if (!path) return;
    const { result, json } = await fetchJson<Json>(`${CONFIG.urls.cvelist}/${path}`, { headers: authHeaders(), timeoutMs: 15_000 });
    if (json) {
      cache[id] = summarizeCveRecord(json, id);
      ok++;
    } else if (result.httpStatus === 404) {
      cache[id] = { id, fetchedAt: new Date().toISOString(), missing: true };
      missing++;
    } else {
      failed++;
    }
  });
  const pending = ids.filter((id) => !cache[id]).length;
  return {
    name: 'CVE records (cvelistV5)',
    status: failed > ok && failed > 5 ? 'error' : 'ok',
    detail: `${ok} fetched, ${missing} not yet published, ${failed} failed, ${pending} queued for later runs`,
  };
}

export async function enrichPoc(ids: string[], cache: Record<string, PocSummary>): Promise<EnrichmentHealth> {
  const todo = plan(ids, cache, CONFIG.enrich.pocTtlHours, CONFIG.enrich.maxFetchPerRun);
  let ok = 0;
  let failed = 0;
  await pool(todo, 6, async (id) => {
    const year = id.slice(4, 8);
    const { result, json } = await fetchJson<{ created_at?: string }[]>(`${CONFIG.urls.poc}/${year}/${id}.json`, { headers: authHeaders(), timeoutMs: 15_000 });
    const now = new Date().toISOString();
    if (Array.isArray(json)) {
      const dates = json.map((r) => r.created_at).filter((d): d is string => Boolean(d)).sort();
      cache[id] = { fetchedAt: now, count: json.length, firstSeen: dates[0] };
      ok++;
    } else if (result.httpStatus === 404) {
      cache[id] = { fetchedAt: now, count: 0 };
      ok++;
    } else {
      failed++;
    }
  });
  return {
    name: 'Public PoC (PoC-in-GitHub)',
    status: failed > ok && failed > 5 ? 'error' : 'ok',
    detail: `${ok} checked, ${failed} failed`,
  };
}
