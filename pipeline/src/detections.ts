// Weekly index of public detection content per CVE: Nuclei templates, ET Open (Suricata) rules,
// SigmaHQ rules and YARA Forge rules. Only names, IDs and links are kept, never rule bodies.
import { strFromU8, unzipSync } from 'fflate';
import type { Detections } from '../../shared/types';
import { extractCves } from './extract';
import { fetchRaw, decodeText } from './fetch';
import type { SourceRegistry } from './sources';
import type { Upstream } from './upstream';
import { DAY, errMsg } from './util';

const URLS = {
  nuclei: 'https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/cves.json',
  et: 'https://rules.emergingthreats.net/open/suricata-7.0.3/emerging-all.rules',
  sigma: 'https://github.com/SigmaHQ/sigma/releases/latest/download/sigma_all_rules.zip',
  yara: 'https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-full.zip',
};
const MAX_PER_CVE = 8;

type Entry = Omit<Detections, 'rulezet'>;

export interface DetectionIndex {
  builtAt: string;
  counts: Record<'nuclei' | 'et' | 'sigma' | 'yara', number>;
  cves: Record<string, Entry>;
}

const entry = (idx: Record<string, Entry>, cve: string): Entry => (idx[cve] ??= { sigma: [], et: [], yara: [] });

/** cves.json is newline-delimited JSON: {"ID":"CVE-…","Info":{"Name":…},"file_path":"http/cves/…"} */
export function indexNuclei(text: string, idx: Record<string, Entry>): number {
  let n = 0;
  for (const line of text.split('\n')) {
    if (!line.trim()) continue;
    try {
      const j = JSON.parse(line) as { ID?: string; file_path?: string };
      const cve = j.ID?.toUpperCase();
      if (cve?.startsWith('CVE-') && j.file_path) {
        entry(idx, cve).nuclei = j.file_path;
        n++;
      }
    } catch {
      /* skip malformed line */
    }
  }
  return n;
}

/** ET Open rules: `reference:cve,2009-0696;` (also tolerates `reference:cve,CVE-…`). Disabled (#) rules count too. */
export function indexEt(text: string, idx: Record<string, Entry>): number {
  let n = 0;
  for (const line of text.split('\n')) {
    if (!line.includes('reference:cve,')) continue;
    const sid = Number(/\bsid:\s*(\d+)/.exec(line)?.[1]);
    const msg = /msg:"([^"]*)"/.exec(line)?.[1] ?? '';
    if (!sid) continue;
    for (const m of line.matchAll(/reference:\s*cve,\s*(?:CVE-)?(\d{4}-\d{4,7})/gi)) {
      const e = entry(idx, `CVE-${m[1]}`);
      if (e.et.length < MAX_PER_CVE && !e.et.some((x) => x.sid === sid)) e.et.push({ sid, msg: msg.slice(0, 140) });
      n++;
    }
  }
  return n;
}

/** Sigma YAML: CVEs from `cve.YYYY-NNNN` tags, the title, or the file name. */
export function indexSigmaRule(path: string, yaml: string, idx: Record<string, Entry>): number {
  const title = /^title:\s*(.+)$/m.exec(yaml)?.[1]?.trim().replace(/^['"]|['"]$/g, '') ?? path.split('/').pop()!;
  const fromTags = [...yaml.matchAll(/-\s*cve[.\-_](\d{4})[.\-_](\d{4,7})/gi)].map((m) => `CVE-${m[1]}-${m[2]}`);
  const cves = new Set([...fromTags, ...extractCves(`${title} ${path.replace(/_/g, '-')}`)]);
  for (const cve of cves) {
    const e = entry(idx, cve);
    if (e.sigma.length < MAX_PER_CVE && !e.sigma.some((s) => s.path === path)) e.sigma.push({ title: title.slice(0, 140), path });
  }
  return cves.size;
}

/** YARA: split into rules and map CVE mentions (name, meta, strings) to rule names. */
export function indexYara(text: string, idx: Record<string, Entry>): number {
  let n = 0;
  const chunks = text.split(/\n(?=(?:private\s+|global\s+)*rule\s+\w+)/);
  for (const chunk of chunks) {
    const name = /^(?:private\s+|global\s+)*rule\s+(\w+)/.exec(chunk.trimStart())?.[1];
    if (!name) continue;
    for (const cve of extractCves(chunk.replace(/_/g, '-'))) {
      const e = entry(idx, cve);
      if (e.yara.length < MAX_PER_CVE && !e.yara.includes(name)) {
        e.yara.push(name);
        n++;
      }
    }
  }
  return n;
}

async function download(url: string): Promise<Uint8Array> {
  const r = await fetchRaw(url, { accept: '*/*', timeoutMs: 120_000, maxBytes: 128 * 1024 * 1024 });
  if (r.status !== 'ok' || !r.data) throw new Error(`${url.split('/').pop()}: ${r.error ?? `HTTP ${r.httpStatus}`}`);
  return r.data;
}

export async function buildDetectionIndex(reg: SourceRegistry): Promise<DetectionIndex> {
  const cves: Record<string, Entry> = {};
  const counts = { nuclei: 0, et: 0, sigma: 0, yara: 0 };
  const steps: [keyof typeof counts, string, () => Promise<number>][] = [
    ['nuclei', 'nuclei', async () => indexNuclei(decodeText(await download(URLS.nuclei)), cves)],
    ['et', 'et-open', async () => indexEt(decodeText(await download(URLS.et)), cves)],
    [
      'sigma',
      'sigma',
      async () => {
        const files = unzipSync(await download(URLS.sigma), { filter: (f) => /\.ya?ml$/i.test(f.name) });
        let n = 0;
        for (const [path, bytes] of Object.entries(files)) n += indexSigmaRule(path.replace(/^[^/]*?\/(?=rules)/, ''), strFromU8(bytes), cves);
        return n;
      },
    ],
    [
      'yara',
      'yara-forge',
      async () => {
        const files = unzipSync(await download(URLS.yara), { filter: (f) => /\.yara?$/i.test(f.name) });
        let n = 0;
        for (const bytes of Object.values(files)) n += indexYara(strFromU8(bytes), cves);
        return n;
      },
    ],
  ];
  for (const [key, sourceId, run] of steps) {
    try {
      counts[key] = await run();
      reg.set(sourceId, { status: 'ok', detail: `${counts[key]} CVE references indexed`, retrieved: true });
    } catch (e) {
      reg.set(sourceId, { status: 'error', detail: errMsg(e) });
    }
  }
  return { builtAt: new Date().toISOString(), counts, cves };
}

/** Load the cached index, rebuilding weekly (or when missing). Never fails the run. */
export async function loadDetectionIndex(u: Upstream, reg: SourceRegistry): Promise<DetectionIndex | null> {
  const cached = u.store.readJson<DetectionIndex | null>('detections/index.json', null);
  if (cached && u.now - Date.parse(cached.builtAt) < 7 * DAY) {
    for (const [key, id] of [['nuclei', 'nuclei'], ['et', 'et-open'], ['sigma', 'sigma'], ['yara', 'yara-forge']] as const) {
      reg.set(id, { status: 'ok', detail: `${cached.counts[key]} CVE references (index built ${cached.builtAt.slice(0, 10)}; weekly)` });
    }
    return cached;
  }
  const fresh = await buildDetectionIndex(reg);
  const total = Object.values(fresh.counts).reduce((a, b) => a + b, 0);
  if (total === 0) return cached;
  // Keep the previous data for any source that failed this time.
  if (cached) {
    for (const [cve, e] of Object.entries(cached.cves)) {
      const f = entry(fresh.cves, cve);
      if (!fresh.counts.nuclei && e.nuclei) f.nuclei = e.nuclei;
      if (!fresh.counts.et && e.et.length) f.et = e.et;
      if (!fresh.counts.sigma && e.sigma.length) f.sigma = e.sigma;
      if (!fresh.counts.yara && e.yara.length) f.yara = e.yara;
    }
  }
  u.store.writeJson('detections/index.json', fresh);
  return fresh;
}

export const detectionCount = (d: Detections | undefined) => (d ? (d.nuclei ? 1 : 0) + d.sigma.length + d.et.length + d.yara.length : 0);
