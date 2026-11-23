import type { EnrichmentHealth } from '../../../shared/types';
import { CONFIG } from '../config';
import { fetchJson } from '../fetch';
import type { HttpCacheEntry, StateStore } from '../state';

export interface KevVuln {
  cveID: string;
  vendorProject: string;
  product: string;
  vulnerabilityName: string;
  dateAdded: string;
  shortDescription: string;
  requiredAction: string;
  dueDate: string;
  knownRansomwareCampaignUse: string;
  notes?: string;
}

export interface KevCatalog {
  title?: string;
  catalogVersion: string;
  dateReleased: string;
  count: number;
  vulnerabilities: KevVuln[];
}

const FILE = 'kev.json';

/** Refresh the CISA KEV catalog (conditional GET); falls back to the cached copy. */
export async function updateKev(store: StateStore, http: Record<string, HttpCacheEntry>): Promise<{ catalog: KevCatalog | null; health: EnrichmentHealth }> {
  const cached = store.readJson<KevCatalog | null>(FILE, null);
  const cacheEntry = cached ? http.kev : undefined;
  const { result, json } = await fetchJson<KevCatalog>(CONFIG.urls.kev, { ...cacheEntry, maxBytes: 32 * 1024 * 1024 });

  if (result.status === 'ok' && json?.vulnerabilities?.length) {
    store.writeJson(FILE, json);
    http.kev = { etag: result.etag, lastModified: result.lastModified };
    return { catalog: json, health: { name: 'CISA KEV', status: 'ok', detail: `catalog ${json.catalogVersion}, ${json.count} entries` } };
  }
  if (result.status === 'not-modified' && cached) {
    return { catalog: cached, health: { name: 'CISA KEV', status: 'ok', detail: `catalog ${cached.catalogVersion} (not modified)` } };
  }
  const why = result.error ?? 'empty catalog';
  return cached
    ? { catalog: cached, health: { name: 'CISA KEV', status: 'stale', detail: `using cached ${cached.catalogVersion}: ${why}` } }
    : { catalog: null, health: { name: 'CISA KEV', status: 'error', detail: why } };
}

interface FlipState {
  known: string[];
  all: string[];
  events: { cve: string; date: string }[];
}

/**
 * Track CISA silently flipping knownRansomwareCampaignUse from Unknown to Known.
 * Only CVEs already in the catalog on the previous run count (new additions are not flips).
 */
export function trackRansomwareFlips(store: StateStore, catalog: KevCatalog | null, now: number): Map<string, string> {
  if (!catalog) return new Map();
  const prev = store.readJson<FlipState | null>('kev-ransomware.json', null);
  const known = catalog.vulnerabilities.filter((v) => v.knownRansomwareCampaignUse === 'Known').map((v) => v.cveID);
  const events = prev?.events ?? [];
  if (prev) {
    const wasKnown = new Set(prev.known);
    const existed = new Set(prev.all);
    const today = new Date(now).toISOString().slice(0, 10);
    for (const cve of known) if (existed.has(cve) && !wasKnown.has(cve)) events.push({ cve, date: today });
  }
  const cutoff = new Date(now - 60 * 86_400_000).toISOString().slice(0, 10);
  const kept = events.filter((e) => e.date >= cutoff);
  store.writeJson('kev-ransomware.json', { known, all: catalog.vulnerabilities.map((v) => v.cveID), events: kept } satisfies FlipState);
  return new Map(kept.map((e) => [e.cve, e.date]));
}

export function indexKev(catalog: KevCatalog | null): Map<string, KevVuln> {
  return new Map((catalog?.vulnerabilities ?? []).map((v) => [v.cveID.toUpperCase(), v]));
}
