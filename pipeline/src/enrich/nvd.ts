// NIST NVD API 2.0, light use: one lastModified window per run, keeping analysis status,
// CPE-configuration count and an NVD CVSS fallback for tracked CVEs only.
// "This product uses data from the NVD API but is not endorsed or certified by the NVD."
import { fetchJson } from '../fetch';
import type { SourceRegistry } from '../sources';
import type { Upstream } from '../upstream';
import { DAY, errMsg } from '../util';

const API = 'https://services.nvd.nist.gov/rest/json/cves/2.0';

export interface NvdRecord {
  status: string;
  cpes: number;
  cvss?: number;
  at: string;
}

interface NvdState {
  cursor: string | null;
  records: Record<string, NvdRecord>;
}

type Json = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

const fmt = (t: number) => new Date(t).toISOString().replace('Z', '');
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export function summarizeNvd(cve: Json): NvdRecord {
  let cpes = 0;
  for (const conf of cve.configurations ?? []) for (const node of conf.nodes ?? []) cpes += (node.cpeMatch ?? []).length;
  const metrics = cve.metrics ?? {};
  const pick = (list?: Json[]) => (list ?? []).find((m) => m.type === 'Primary')?.cvssData?.baseScore ?? list?.[0]?.cvssData?.baseScore;
  const cvss = pick(metrics.cvssMetricV31) ?? pick(metrics.cvssMetricV40) ?? pick(metrics.cvssMetricV30);
  return { status: String(cve.vulnStatus ?? ''), cpes, ...(typeof cvss === 'number' ? { cvss } : {}), at: new Date().toISOString() };
}

export async function updateNvd(u: Upstream, tracked: Set<string>, reg: SourceRegistry): Promise<Map<string, NvdRecord>> {
  const state = u.store.readJson<NvdState>('nvd.json', { cursor: null, records: {} });
  const key = process.env.NVD_API_KEY;
  const end = u.now;
  // Window: from cursor (or 1 day back) to now, capped at the API's 120-day maximum.
  const start = Math.max(state.cursor ? Date.parse(state.cursor) : end - DAY, end - 119 * DAY);
  let fetched = 0;
  let kept = 0;
  try {
    for (let startIndex = 0, page = 0; page < 4; page++) {
      if (page > 0) await sleep(key ? 700 : 6500);
      const url = `${API}?lastModStartDate=${fmt(start)}&lastModEndDate=${fmt(end)}&resultsPerPage=2000&startIndex=${startIndex}`;
      const { result, json } = await fetchJson<{ totalResults?: number; vulnerabilities?: { cve: Json }[] }>(url, {
        headers: key ? { apiKey: key } : {},
        timeoutMs: 60_000,
        maxBytes: 96 * 1024 * 1024,
      });
      if (!json) throw new Error(result.error ?? `HTTP ${result.httpStatus}`);
      const vulns = json.vulnerabilities ?? [];
      fetched += vulns.length;
      for (const v of vulns) {
        const id = String(v.cve?.id ?? '');
        if (tracked.has(id)) {
          state.records[id] = summarizeNvd(v.cve);
          kept++;
        }
      }
      startIndex += vulns.length;
      if (vulns.length === 0 || startIndex >= (json.totalResults ?? 0)) {
        state.cursor = new Date(end).toISOString();
        break;
      }
    }
    for (const id of Object.keys(state.records)) if (!tracked.has(id)) delete state.records[id];
    reg.set('nvd', { status: 'ok', detail: `${fetched} modified CVEs scanned, ${kept} tracked updated${key ? '' : ' (no API key: slower paging)'}`, retrieved: true });
  } catch (e) {
    reg.set('nvd', { status: Object.keys(state.records).length ? 'stale' : 'error', detail: errMsg(e) });
  }
  u.store.writeJson('nvd.json', state);
  return new Map(Object.entries(state.records));
}
