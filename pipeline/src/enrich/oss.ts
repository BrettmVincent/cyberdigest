// Open-source package data for tracked CVEs:
//  • GitHub Advisory Database (reviewed advisories, CC BY 4.0): GHSA ID, affected packages and the
//    first patched version. Uses GITHUB_TOKEN in Actions; anonymous locally (60 req/h), so the
//    per-run budget is small without a token.
//  • OSV.dev (CC BY 4.0): whether an OSV record exists, GHSA aliases and related advisories
//    (distro / ecosystem advisories). No documented rate limit; called politely, one at a time.
// Closed-source CVEs (appliances, Windows…) simply have no record and are cached as "none".
import { fetchJson } from '../fetch';
import type { SourceRegistry } from '../sources';
import { githubApi, type Upstream } from '../upstream';
import { DAY, errMsg } from '../util';

export interface OssPackage {
  ecosystem: string;
  name: string;
  /** First patched version; absent when no fix is published. */
  fixed?: string;
}

export interface OssRecord {
  at: string;
  ghsa?: string;
  packages: OssPackage[];
  osv: boolean;
  related: number;
}

type Json = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

const MAX_PACKAGES = 6;
const REFRESH = 7 * DAY;

/** Summarise the GitHub `/advisories?cve_id=` response (first reviewed advisory wins). */
export function summarizeGhsa(list: Json[] | undefined): Pick<OssRecord, 'ghsa' | 'packages'> {
  const adv = (list ?? []).find((a) => a && typeof a.ghsa_id === 'string' && a.type !== 'malware');
  if (!adv) return { packages: [] };
  const packages: OssPackage[] = [];
  const seen = new Set<string>();
  for (const v of adv.vulnerabilities ?? []) {
    const ecosystem = String(v?.package?.ecosystem ?? '').trim();
    const name = String(v?.package?.name ?? '').trim();
    if (!ecosystem || !name || seen.has(`${ecosystem}/${name}`)) continue;
    seen.add(`${ecosystem}/${name}`);
    const fp = v.first_patched_version;
    const fixed = typeof fp === 'string' ? fp : typeof fp?.identifier === 'string' ? fp.identifier : undefined;
    packages.push({ ecosystem, name, ...(fixed ? { fixed } : {}) });
    if (packages.length >= MAX_PACKAGES) break;
  }
  return { ghsa: adv.ghsa_id, packages };
}

/** Summarise an OSV `/v1/vulns/{id}` record. */
export function summarizeOsv(rec: Json | undefined): Pick<OssRecord, 'osv' | 'related'> & { ghsaAlias?: string } {
  if (!rec?.id) return { osv: false, related: 0 };
  const ghsaAlias = (rec.aliases ?? []).find((a: unknown) => typeof a === 'string' && a.startsWith('GHSA-')) as string | undefined;
  return { osv: true, related: Array.isArray(rec.related) ? rec.related.length : 0, ...(ghsaAlias ? { ghsaAlias } : {}) };
}

export async function updateOss(u: Upstream, ordered: string[], reg: SourceRegistry): Promise<Map<string, OssRecord>> {
  const state = u.store.readJson<Record<string, OssRecord>>('oss.json', {});
  const tracked = new Set(ordered);
  const budget = process.env.GITHUB_TOKEN ? 40 : 8;
  const due = ordered.filter((c) => !state[c] || u.now - Date.parse(state[c]!.at) > REFRESH).slice(0, budget);
  let done = 0;
  let ghsaErr: string | undefined;
  let osvErr: string | undefined;
  for (const cve of due) {
    const osvRes = await fetchJson<Json>(`https://api.osv.dev/v1/vulns/${encodeURIComponent(cve)}`, { timeoutMs: 20_000 });
    if (!osvRes.json && osvRes.result.httpStatus !== 404) {
      osvErr = osvRes.result.error ?? `HTTP ${osvRes.result.httpStatus}`;
      break;
    }
    const gh = await githubApi<Json[]>(`/advisories?cve_id=${encodeURIComponent(cve)}&per_page=5`);
    if (!gh.json) {
      ghsaErr = gh.error;
      break;
    }
    const osv = summarizeOsv(osvRes.json);
    const g = summarizeGhsa(gh.json);
    const ghsa = g.ghsa ?? osv.ghsaAlias;
    state[cve] = { at: new Date(u.now).toISOString(), ...(ghsa ? { ghsa } : {}), packages: g.packages, osv: osv.osv, related: osv.related };
    done++;
  }
  for (const c of Object.keys(state)) if (!tracked.has(c)) delete state[c];
  const withPkgs = Object.values(state).filter((r) => r.packages.length).length;
  const withOsv = Object.values(state).filter((r) => r.osv).length;
  const tail = `${done}/${due.length} due CVEs checked this run${process.env.GITHUB_TOKEN ? '' : ' (no GITHUB_TOKEN: small budget)'}`;
  reg.set('ghsa', ghsaErr ? { status: withPkgs ? 'stale' : 'error', detail: ghsaErr } : { status: 'ok', detail: `${withPkgs} tracked CVEs with reviewed advisories; ${tail}`, retrieved: done > 0 });
  reg.set('osv', osvErr ? { status: withOsv ? 'stale' : 'error', detail: errMsg(osvErr) } : { status: 'ok', detail: `${withOsv} tracked CVEs with OSV records; ${tail}`, retrieved: done > 0 });
  u.store.writeJson('oss.json', state);
  return new Map(Object.entries(state));
}
