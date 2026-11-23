// Will Thomas (BushidoUK) Ransomware Vulnerability Matrix + Ransomware Tool Matrix (CC BY 4.0).
// Markdown tables → CVE→groups and tool→groups maps. Files are fetched raw with ETag caching;
// a parse only replaces the cached result when it is structurally sound.
import type { GroupRole } from '../../../shared/types';
import type { SourceRegistry } from '../sources';
import { fetchIfChanged, isDue, lastCommitDate, markRan, rawUrl, type Upstream } from '../upstream';
import { errMsg } from '../util';
import { parseRoleMarkers } from './aliases';

export const RVM_REPO = 'BushidoUK/Ransomware-Vulnerability-Matrix';
export const RTM_REPO = 'BushidoUK/Ransomware-Tool-Matrix';
const RVM_FILES = ['Applications', 'Drivers', 'FileTransferServers', 'Linux', 'Microsoft', 'NetworkEdge', 'RMM_Tools', 'Virtualization'];
const RTM_FILES: Record<string, string> = {
  'RMM-Tools': 'RMM tools',
  Exfiltration: 'Exfiltration',
  CredentialTheft: 'Credential theft',
  DefenseEvasion: 'Defence evasion',
  DiscoveryEnum: 'Discovery & enumeration',
  Networking: 'Networking / tunnelling',
  Offsec: 'Offensive security tools',
  LOLBAS: 'Living off the land',
};

export interface RvmRow {
  cves: string[];
  product: string;
  vendor: string;
  category: string;
  groups: { name: string; role: GroupRole }[];
  sources: string[];
}

export interface RtmRow {
  tool: string;
  category: string;
  groups: { name: string; role: GroupRole }[];
}

const CVE_RE = /CVE-\d{4}-\d{4,7}/gi;
const LINK_RE = /\]\((https?:\/\/[^)\s]+)\)/g;

function cells(line: string): string[] {
  return line
    .trim()
    .replace(/^\|/, '')
    .replace(/\|$/, '')
    .split('|')
    .map((c) => c.trim());
}

function splitGroups(cell: string): { name: string; role: GroupRole }[] {
  return cell
    .split(/,|\s\/\s|;/)
    .map((s) => s.trim())
    .filter((s) => s && s !== '-' && !/^n\/?a$/i.test(s))
    .map(parseRoleMarkers)
    .filter((g) => g.name.length > 1);
}

/** Parse one RVM category file. Throws if no table with the expected header is found. */
export function parseRvm(md: string, category: string): RvmRow[] {
  const rows: RvmRow[] = [];
  let vendor = '';
  let cols: { product: number; cve: number; groups: number; sources: number } | null = null;
  let sawHeader = false;
  for (const line of md.split(/\r?\n/)) {
    const h = /^#{2,4}\s+`?([^`]+?)`?\s*$/.exec(line);
    if (h) {
      if (line.startsWith('###')) vendor = h[1]!.trim();
      cols = null;
      continue;
    }
    if (!line.trim().startsWith('|')) {
      cols = null;
      continue;
    }
    const c = cells(line);
    if (c.every((x) => /^:?-+:?$/.test(x))) continue;
    const lower = c.map((x) => x.toLowerCase());
    if (lower.some((x) => x.startsWith('cve')) && lower.some((x) => x.includes('group'))) {
      cols = {
        product: lower.findIndex((x) => x.startsWith('product')),
        cve: lower.findIndex((x) => x.startsWith('cve')),
        groups: lower.findIndex((x) => x.includes('group')),
        sources: lower.findIndex((x) => x.startsWith('source')),
      };
      sawHeader = true;
      continue;
    }
    if (!cols) continue;
    const cves = [...new Set((c[cols.cve] ?? '').match(CVE_RE) ?? [])].map((x) => x.toUpperCase());
    if (cves.length === 0) continue;
    rows.push({
      cves,
      product: cols.product >= 0 ? (c[cols.product] ?? '') : '',
      vendor,
      category,
      groups: splitGroups(c[cols.groups] ?? ''),
      sources: cols.sources >= 0 ? [...(c[cols.sources] ?? '').matchAll(LINK_RE)].map((m) => m[1]!) : [],
    });
  }
  if (!sawHeader) throw new Error(`${category}: no "CVE | Ransomware Group" table found`);
  return rows;
}

/** Parse one RTM tool category file (| Tool Name | Threat Group Usage |). */
export function parseRtm(md: string, category: string): RtmRow[] {
  const rows: RtmRow[] = [];
  let inTable = false;
  let sawHeader = false;
  for (const line of md.split(/\r?\n/)) {
    if (!line.trim().startsWith('|')) {
      inTable = false;
      continue;
    }
    const c = cells(line);
    if (c.every((x) => /^:?-+:?$/.test(x))) continue;
    if (/tool/i.test(c[0] ?? '') && /group/i.test(c[1] ?? '')) {
      inTable = true;
      sawHeader = true;
      continue;
    }
    if (!inTable || c.length < 2) continue;
    const tool = (c[0] ?? '').replace(/\[\.\]/g, '.').replace(/\*\*/g, '').trim();
    if (!tool) continue;
    rows.push({ tool, category, groups: splitGroups(c[1] ?? '') });
  }
  if (!sawHeader) throw new Error(`${category}: no "Tool Name | Threat Group Usage" table found`);
  return rows;
}

interface MatrixCache<T> {
  rows: T[];
  updated: string | null;
}

async function loadMatrix<T>(
  u: Upstream,
  reg: SourceRegistry,
  id: 'rvm' | 'rtm',
  repo: string,
  files: [string, string][],
  parser: (md: string, category: string) => T[],
): Promise<MatrixCache<T>> {
  const cacheFile = `ransomware/${id}.json`;
  const cached = u.store.readJson<MatrixCache<T> | null>(cacheFile, null);
  if (cached && !isDue(u, id, 24)) {
    reg.set(id, { status: 'ok', detail: `${cached.rows.length} rows (cached; checked daily)`, version: cached.updated });
    return cached;
  }
  // Eight small files once a day: always re-read them all, so a partial change never drops rows.
  const rows: T[] = [];
  const problems: string[] = [];
  for (const [file, category] of files) {
    try {
      const res = await fetchIfChanged(u, rawUrl(repo, file), false);
      if (!res.text) throw new Error(res.result.error ?? `HTTP ${res.result.httpStatus}`);
      rows.push(...parser(res.text, category));
    } catch (e) {
      problems.push(`${file}: ${errMsg(e)}`);
    }
  }
  if (problems.length || rows.length === 0) {
    if (cached) {
      reg.set(id, { status: 'stale', detail: `kept last good parse; ${problems.join('; ') || 'empty parse'}`, version: cached.updated });
      return cached;
    }
    reg.set(id, { status: 'error', detail: problems.join('; ') || 'no rows parsed' });
    return { rows: [], updated: null };
  }
  const updated = (await lastCommitDate(repo)) ?? cached?.updated ?? null;
  const result = { rows, updated };
  u.store.writeJson(cacheFile, result);
  markRan(u, id);
  reg.set(id, { status: 'ok', detail: `${rows.length} rows parsed`, version: updated, retrieved: true });
  return result;
}

export function loadRvm(u: Upstream, reg: SourceRegistry): Promise<MatrixCache<RvmRow>> {
  return loadMatrix(u, reg, 'rvm', RVM_REPO, RVM_FILES.map((f) => [`Vulnerabilities/${f}.md`, f.replace(/_/g, ' ')]), parseRvm);
}

export function loadRtm(u: Upstream, reg: SourceRegistry): Promise<MatrixCache<RtmRow>> {
  return loadMatrix(u, reg, 'rtm', RTM_REPO, Object.entries(RTM_FILES).map(([f, label]) => [`Tools/${f}.md`, label]), parseRtm);
}
