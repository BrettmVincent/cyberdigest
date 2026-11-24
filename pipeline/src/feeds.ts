import { readFileSync } from 'node:fs';
import { parse } from 'yaml';
import type { FeedGroup, SourceTier } from '../../shared/types';
import { CONFIG } from './config';

export interface FeedConfig {
  id: string;
  name: string;
  url: string;
  tier: SourceTier;
  group: FeedGroup;
  enabled: boolean;
  firehose: boolean;
  /** Re-publishes every CVE record (not independent coverage): never counts as a corroborating source. */
  aggregator: boolean;
  /** Keep this feed's items for fewer days than CONFIG.retentionDays (high-volume streams). */
  retainDays?: number;
  /** 'first-seen': ignore the feed's dates (unreliable/backdated) and date items when first seen. */
  dates: 'published' | 'first-seen';
  include?: RegExp;
  exclude?: RegExp;
  marketing: boolean;
  lang?: string;
  headers?: Record<string, string>;
}

const TIERS = new Set(['A', 'B', 'C']);
const GROUPS = new Set(['intel', 'vuln', 'gov', 'psirt', 'news', 'blue']);

export function loadFeeds(path: string = CONFIG.paths.feeds): FeedConfig[] {
  // merge: true enables YAML "<<: *anchor" templates (used for groups of feeds sharing a filter).
  const doc = parse(readFileSync(path, 'utf8'), { merge: true }) as { feeds?: Record<string, unknown>[] };
  if (!doc?.feeds || !Array.isArray(doc.feeds)) throw new Error(`${path}: missing "feeds" list`);
  const seen = new Set<string>();
  return doc.feeds.map((f, i) => {
    const where = `${path} entry #${i + 1}`;
    const id = String(f.id ?? '');
    if (!/^[a-z0-9][a-z0-9-]*$/.test(id)) throw new Error(`${where}: invalid id "${id}"`);
    if (seen.has(id)) throw new Error(`${where}: duplicate id "${id}"`);
    seen.add(id);
    const tier = String(f.tier);
    const group = String(f.group);
    if (!TIERS.has(tier)) throw new Error(`${where} (${id}): tier must be A, B or C`);
    if (!GROUPS.has(group)) throw new Error(`${where} (${id}): unknown group "${group}"`);
    const url = String(f.url ?? '');
    if (!/^https?:\/\//.test(url)) throw new Error(`${where} (${id}): url must be http(s)`);
    const retainDays = f.retainDays === undefined ? undefined : Number(f.retainDays);
    if (retainDays !== undefined && !(retainDays >= 1 && retainDays <= CONFIG.retentionDays)) throw new Error(`${where} (${id}): retainDays must be 1–${CONFIG.retentionDays}`);
    const dates = f.dates === undefined ? 'published' : String(f.dates);
    if (dates !== 'published' && dates !== 'first-seen') throw new Error(`${where} (${id}): dates must be "published" or "first-seen"`);
    return {
      id,
      name: String(f.name ?? id),
      url,
      tier: tier as SourceTier,
      group: group as FeedGroup,
      enabled: f.enabled !== false,
      firehose: f.firehose === true,
      aggregator: f.aggregator === true,
      ...(retainDays !== undefined ? { retainDays } : {}),
      dates,
      include: f.include ? new RegExp(String(f.include), 'i') : undefined,
      exclude: f.exclude ? new RegExp(String(f.exclude), 'i') : undefined,
      marketing: f.marketing === undefined ? tier !== 'A' : f.marketing === true,
      lang: f.lang ? String(f.lang) : undefined,
      headers: f.headers as Record<string, string> | undefined,
    };
  });
}

/** Apply the per-feed include/exclude regexes and the global marketing filter. */
export function keepTitle(feed: FeedConfig, title: string): boolean {
  if (!title) return false;
  if (feed.include && !feed.include.test(title)) return false;
  if (feed.exclude && feed.exclude.test(title)) return false;
  // Marketing filter, unless the headline carries a strong security signal ("Git security vulnerabilities announced").
  if (feed.marketing && CONFIG.marketingExclude.test(title) && !CONFIG.securitySignal.test(title)) return false;
  return true;
}
