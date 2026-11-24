// ENISA European Vulnerability Database (EUVD): EUVD identifiers for tracked CVEs.
// The full CVE→EUVD mapping dump (~12 MB CSV, refreshed daily at 07:00 UTC) is pulled once a day;
// CVEs that become tracked in between are looked up one by one (paced at 1 request / 6 s, as
// ENISA's API is slow and unauthenticated). EUVD's exploited list (CISA KEV + EU KEV) is not
// re-ingested: CIRCL Vulnerability-Lookup already supplies the same EU KEV catalogue.
import { fetchJson, fetchRaw, decodeText } from '../fetch';
import type { SourceRegistry } from '../sources';
import { isDue, markRan, type Upstream } from '../upstream';
import { DAY, errMsg } from '../util';

const API = 'https://euvdservices.enisa.europa.eu/api';
const EUVD_RE = /^EUVD-\d{4}-\d+$/;
const CVE_RE = /^CVE-\d{4}-\d{4,7}$/;

interface EuvdState {
  map: Record<string, string>;
  /** CVEs with no EUVD record yet, and when we last asked. */
  miss: Record<string, string>;
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** Parse the `euvd_id,cve_id` dump, keeping only the CVEs we track. */
export function parseEuvdMapping(csv: string, want: Set<string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const line of csv.split('\n')) {
    const comma = line.indexOf(',');
    if (comma < 0) continue;
    const euvd = line.slice(0, comma).trim();
    const cve = line.slice(comma + 1).trim().toUpperCase();
    if (want.has(cve) && EUVD_RE.test(euvd)) out[cve] = euvd;
  }
  return out;
}

export async function updateEuvd(u: Upstream, tracked: Set<string>, reg: SourceRegistry, maxLookups = 6): Promise<Map<string, string>> {
  const state = u.store.readJson<EuvdState>('euvd.json', { map: {}, miss: {} });
  let detail = '';
  try {
    if (isDue(u, 'euvd-mapping', 24)) {
      const res = await fetchRaw(`${API}/dump/cve-euvd-mapping`, { accept: 'text/csv', timeoutMs: 180_000, maxBytes: 64 * 1024 * 1024 });
      if (res.status !== 'ok' || !res.data) throw new Error(`mapping dump: ${res.error ?? `HTTP ${res.httpStatus}`}`);
      const fresh = parseEuvdMapping(decodeText(res.data, res.contentType), tracked);
      if (Object.keys(fresh).length === 0 && tracked.size > 50) throw new Error('mapping dump parsed to 0 tracked CVEs (format change?)');
      state.map = fresh;
      state.miss = {};
      markRan(u, 'euvd-mapping');
      detail = `daily mapping dump: ${Object.keys(fresh).length}/${tracked.size} tracked CVEs mapped`;
    } else {
      // Top up CVEs that became tracked since the last dump.
      const due = [...tracked].filter((c) => CVE_RE.test(c) && !state.map[c] && (!state.miss[c] || u.now - Date.parse(state.miss[c]!) > DAY)).slice(0, maxLookups);
      let found = 0;
      for (const [i, cve] of due.entries()) {
        if (i > 0) await sleep(6000);
        const { result, json } = await fetchJson<{ id?: string }>(`${API}/enisaid?id=${encodeURIComponent(cve)}`, { timeoutMs: 30_000 });
        if (json?.id && EUVD_RE.test(json.id)) {
          state.map[cve] = json.id;
          found++;
        } else if (result.httpStatus === 404 || result.httpStatus === 204 || (result.status === 'ok' && !json?.id)) {
          state.miss[cve] = new Date(u.now).toISOString();
        } else break; // API trouble: try again next run.
      }
      detail = `${Object.keys(state.map).length} tracked CVEs mapped; ${found}/${due.length} new looked up this run`;
    }
    for (const c of Object.keys(state.map)) if (!tracked.has(c)) delete state.map[c];
    for (const c of Object.keys(state.miss)) if (!tracked.has(c)) delete state.miss[c];
    reg.set('euvd', { status: 'ok', detail, retrieved: true });
  } catch (e) {
    reg.set('euvd', { status: Object.keys(state.map).length ? 'stale' : 'error', detail: errMsg(e) });
  }
  u.store.writeJson('euvd.json', state);
  return new Map(Object.entries(state.map));
}
