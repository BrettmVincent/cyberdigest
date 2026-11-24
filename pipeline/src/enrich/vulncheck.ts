// VulnCheck KEV (Community tier, optional free key in VULNCHECK_API_KEY).
// Full index pulled once a day with cursor paging; only CVE membership + VulnCheck's date added are
// kept. Shown as the "VulnCheck KEV" catalogue, which is the attribution VulnCheck requires.
// Without a key the source is skipped cleanly.
import { fetchJson } from '../fetch';
import type { SourceRegistry } from '../sources';
import { isDue, markRan, type Upstream } from '../upstream';
import { errMsg } from '../util';

const BASE = 'https://api.vulncheck.com/v3';
export const VULNCHECK_CATALOG = 'VulnCheck KEV';
const CVE_RE = /^CVE-\d{4}-\d{4,7}$/;
const MAX_PAGES = 200;

interface VcState {
  kev: Record<string, string>;
}

type Json = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

/** One page of /v3/index/vulncheck-kev → [cve, dateAdded] pairs and the next cursor. */
export function parseVulncheckPage(page: Json | undefined): { entries: [string, string][]; next?: string } {
  const entries: [string, string][] = [];
  for (const rec of page?.data ?? []) {
    const added = String(rec?.date_added ?? rec?.cisa_date_added ?? '').slice(0, 10);
    for (const c of rec?.cve ?? []) {
      const cve = String(c).toUpperCase();
      if (CVE_RE.test(cve)) entries.push([cve, added]);
    }
  }
  const next = page?._meta?.next_cursor;
  return { entries, ...(typeof next === 'string' && next ? { next } : {}) };
}

export async function updateVulncheck(u: Upstream, reg: SourceRegistry): Promise<Map<string, string>> {
  const state = u.store.readJson<VcState>('vulncheck.json', { kev: {} });
  const key = process.env.VULNCHECK_API_KEY;
  if (!key) {
    reg.set('vulncheck-kev', { status: 'skipped', detail: 'No VULNCHECK_API_KEY secret (free Community key from vulncheck.com)' });
    return new Map();
  }
  if (!isDue(u, 'vulncheck-kev', 24)) {
    reg.set('vulncheck-kev', { status: 'ok', detail: `${Object.keys(state.kev).length} CVEs (daily refresh)` });
    return new Map(Object.entries(state.kev));
  }
  try {
    const kev: Record<string, string> = {};
    const headers = { Authorization: `Bearer ${key}` };
    let url = `${BASE}/index/vulncheck-kev?limit=100&start_cursor=true`;
    let pages = 0;
    for (;;) {
      const { result, json } = await fetchJson<Json>(url, { headers, timeoutMs: 60_000 });
      if (!json) throw new Error(result.error ?? `HTTP ${result.httpStatus}`);
      const { entries, next } = parseVulncheckPage(json);
      for (const [cve, added] of entries) if (!kev[cve] || (added && added < kev[cve]!)) kev[cve] = added;
      if (!next) break;
      if (++pages >= MAX_PAGES) throw new Error(`stopped after ${MAX_PAGES} pages (index larger than expected)`);
      url = `${BASE}/index/vulncheck-kev?limit=100&cursor=${encodeURIComponent(next)}`;
    }
    if (Object.keys(kev).length === 0) throw new Error('index returned no CVEs');
    state.kev = kev;
    markRan(u, 'vulncheck-kev');
    u.store.writeJson('vulncheck.json', state);
    reg.set('vulncheck-kev', { status: 'ok', detail: `${Object.keys(kev).length} CVEs in VulnCheck KEV`, retrieved: true });
  } catch (e) {
    reg.set('vulncheck-kev', { status: Object.keys(state.kev).length ? 'stale' : 'error', detail: errMsg(e) });
  }
  return new Map(Object.entries(state.kev));
}
