import { CONFIG } from './config';
import { jaccard } from './text';
import { DAY, HOUR } from './util';

export interface ClusterInput {
  feedId: string;
  /** Epoch ms used for time-windowing. */
  time: number;
  cves: string[];
  /** CVEs named in the headline itself (a strong same-story signal). */
  titleCves: string[];
  /** Lower-cased vendor/actor/malware names. */
  entities: Set<string>;
  tokens: Set<string>;
}

class UnionFind {
  private parent: number[];
  constructor(n: number) {
    this.parent = Array.from({ length: n }, (_, i) => i);
  }
  find(x: number): number {
    while (this.parent[x] !== x) {
      this.parent[x] = this.parent[this.parent[x]!]!;
      x = this.parent[x]!;
    }
    return x;
  }
  union(a: number, b: number): void {
    const ra = this.find(a);
    const rb = this.find(b);
    if (ra !== rb) this.parent[rb] = ra;
  }
}

/**
 * Group items that describe the same story:
 *  1. items within 7 days of each other that name the same CVE in both headlines, or whose
 *     CVE sets mostly overlap (so round-ups listing many CVEs cannot bridge stories);
 *  2. items from different feeds with similar headlines within the time window — a lower
 *     similarity bar applies when they also share a CVE, vendor, actor or malware name.
 * Returns groups of input indices.
 */
export function clusterItems(items: ClusterInput[], cfg = CONFIG.cluster): number[][] {
  const uf = new UnionFind(items.length);

  // CVE links. A shared CVE alone is not enough: items listing several unrelated CVEs
  // ("CISA Adds Four…", monthly rollups) would bridge separate stories. Link when the
  // CVE appears in both headlines, or when the two CVE sets mostly overlap.
  const cveSets = items.map((it) => new Set(it.cves));
  const byCve = new Map<string, number[]>();
  items.forEach((it, i) => {
    for (const c of it.cves) {
      const list = byCve.get(c);
      if (list) list.push(i);
      else byCve.set(c, [i]);
    }
  });
  for (const [cve, idx] of byCve) {
    if (idx.length < 2) continue;
    idx.sort((a, b) => items[a]!.time - items[b]!.time);
    for (let x = 0; x < idx.length; x++) {
      const i = idx[x]!;
      for (let y = x + 1; y < idx.length; y++) {
        const j = idx[y]!;
        if (items[j]!.time - items[i]!.time > 7 * DAY) break;
        const bothTitles = items[i]!.titleCves.includes(cve) && items[j]!.titleCves.includes(cve);
        if (bothTitles || jaccard(cveSets[i]!, cveSets[j]!) >= cfg.cveSetJaccard) uf.union(i, j);
      }
    }
  }

  const order = items.map((_, i) => i).sort((a, b) => items[a]!.time - items[b]!.time);
  const windowMs = cfg.windowHours * HOUR;
  for (let x = 0; x < order.length; x++) {
    const i = order[x]!;
    const a = items[i]!;
    if (a.tokens.size < 2) continue;
    for (let y = x + 1; y < order.length; y++) {
      const j = order[y]!;
      const b = items[j]!;
      if (b.time - a.time > windowMs) break;
      if (b.tokens.size < 2) continue;
      // Same-feed items reuse title templates ("CISA Adds One Known Exploited…"); only CVEs may join them.
      if (a.feedId === b.feedId) continue;
      const sim = jaccard(a.tokens, b.tokens);
      if (sim >= cfg.titleJaccardAlone && a.tokens.size >= 3 && b.tokens.size >= 3) {
        uf.union(i, j);
        continue;
      }
      if (sim >= cfg.titleJaccardWithEntity && sharesEntity(a, b)) uf.union(i, j);
    }
  }

  const groups = new Map<number, number[]>();
  items.forEach((_, i) => {
    const r = uf.find(i);
    const g = groups.get(r);
    if (g) g.push(i);
    else groups.set(r, [i]);
  });
  return [...groups.values()];
}

function sharesEntity(a: ClusterInput, b: ClusterInput): boolean {
  for (const c of a.cves) if (b.cves.includes(c)) return true;
  for (const e of a.entities) if (b.entities.has(e)) return true;
  return false;
}
