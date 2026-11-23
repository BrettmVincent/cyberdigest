// Helpers shared by the enrichment fetchers: conditional downloads keyed by URL,
// cadence gates, and (token-authenticated) GitHub API calls.
import { decodeText, fetchJson, fetchRaw, type FetchOptions, type FetchResult } from './fetch';
import type { HttpCacheEntry, StateStore } from './state';
import { HOUR } from './util';

export interface Upstream {
  store: StateStore;
  http: Record<string, HttpCacheEntry>;
  gates: Record<string, string>;
  now: number;
}

/** True when `key` last ran more than `hours` ago (or never). Call markRan() after a successful run. */
export function isDue(u: Upstream, key: string, hours: number): boolean {
  const last = u.gates[key];
  return !last || u.now - Date.parse(last) >= hours * HOUR - 5 * 60_000;
}

export function markRan(u: Upstream, key: string): void {
  u.gates[key] = new Date(u.now).toISOString();
}

/**
 * Conditional GET keyed by URL. Returns `changed: false` on 304 (caller reuses its cached parse).
 * When `hasCache` is false the request is unconditional, so a lost parse cache always re-fetches.
 */
export async function fetchIfChanged(
  u: Upstream,
  url: string,
  hasCache: boolean,
  opts: FetchOptions = {},
): Promise<{ changed: boolean; text?: string; data?: Uint8Array; result: FetchResult }> {
  const prev = hasCache ? u.http[url] : undefined;
  const result = await fetchRaw(url, { ...prev, ...opts });
  if (result.status === 'not-modified') return { changed: false, result };
  if (result.status !== 'ok' || !result.data) return { changed: false, result };
  u.http[url] = { etag: result.etag, lastModified: result.lastModified };
  return { changed: true, data: result.data, text: decodeText(result.data, result.contentType), result };
}

function ghHeaders(): Record<string, string> {
  const t = process.env.GITHUB_TOKEN;
  return { Accept: 'application/vnd.github+json', ...(t ? { Authorization: `Bearer ${t}` } : {}) };
}

/** GitHub REST call (authenticated with GITHUB_TOKEN in Actions; 60/h anonymous locally). */
export async function githubApi<T>(path: string): Promise<{ json?: T; error?: string }> {
  const { result, json } = await fetchJson<T>(`https://api.github.com${path}`, { headers: ghHeaders(), accept: 'application/vnd.github+json' });
  return json ? { json } : { error: result.error ?? `HTTP ${result.httpStatus}` };
}

/** Date of the latest commit on the default branch (null if the API is unavailable). */
export async function lastCommitDate(repo: string): Promise<string | null> {
  const { json } = await githubApi<{ commit?: { committer?: { date?: string } } }[]>(`/repos/${repo}/commits?per_page=1`);
  return json?.[0]?.commit?.committer?.date ?? null;
}

export const rawUrl = (repo: string, path: string, ref = 'HEAD') => `https://raw.githubusercontent.com/${repo}/${ref}/${path.split('/').map(encodeURIComponent).join('/')}`;
