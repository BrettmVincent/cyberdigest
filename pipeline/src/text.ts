import { decodeHTML } from 'entities';

const BLOCK_TAGS = /<(script|style|noscript|iframe|object|embed|svg|math|template)\b[\s\S]*?<\/\1\s*>/gi;
const COMMENTS = /<!--[\s\S]*?-->/g;
const TAG = /<\/?[a-z!?][^>]*>/gi;
const LOOKS_LIKE_HTML = /<\/?[a-z!][^>]*>/i;

/**
 * Convert untrusted feed HTML (or double-encoded HTML) to plain text.
 * The output never contains markup: the dashboard renders it as text only.
 */
export function toPlainText(input: unknown): string {
  if (input == null) return '';
  let s = String(input);
  for (let pass = 0; pass < 3; pass++) {
    s = s.replace(COMMENTS, ' ').replace(BLOCK_TAGS, ' ').replace(TAG, ' ');
    const decoded = decodeHTML(s);
    if (decoded === s) break;
    s = decoded;
    if (!LOOKS_LIKE_HTML.test(s)) break;
  }
  // A final strip in case the last decode produced tags, then drop stray angle brackets.
  s = s.replace(TAG, ' ').replace(/[<>]/g, ' ');
  return s
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F​-‍﻿]/g, '')
    .replace(/\s+/g, ' ')
    .trim();
}

export function clamp(s: string, max: number): string {
  if (s.length <= max) return s;
  const cut = s.slice(0, max);
  const lastSpace = cut.lastIndexOf(' ');
  return `${(lastSpace > max * 0.6 ? cut.slice(0, lastSpace) : cut).replace(/[\s,.;:–—-]+$/, '')}…`;
}

const TRACKING_PARAMS = /^(utm_\w+|fbclid|gclid|mc_cid|mc_eid|_hsenc|_hsmi|mkt_tok|ref|source|cmpid|sc_cid)$/i;

/** Returns a canonical http(s) URL or null (rejects javascript:, data:, etc.). */
export function canonicalUrl(raw: unknown, base?: string): string | null {
  if (typeof raw !== 'string' || !raw.trim()) return null;
  let u: URL;
  try {
    u = new URL(raw.trim(), base);
  } catch {
    return null;
  }
  if (u.protocol !== 'https:' && u.protocol !== 'http:') return null;
  if (u.username || u.password) return null;
  u.hash = '';
  u.hostname = u.hostname.toLowerCase();
  for (const key of [...u.searchParams.keys()]) {
    if (TRACKING_PARAMS.test(key)) u.searchParams.delete(key);
  }
  return u.toString();
}

const STOPWORDS = new Set(
  ('a an the and or of for to in on at by with from as is are was were be been it its this that these those via over into after before new how why what who your our their vs about amid than more most can could will would may might has have had not no up out off update updates updated security vulnerability vulnerabilities flaw flaws bug bugs attack attacks hackers hacker ' +
    'january february march april may june july august september october november december jan feb mar apr jun jul aug sep sept oct nov dec monday tuesday wednesday thursday friday week weekly monthly').split(
    ' ',
  ),
);

/** Lower-case content tokens of a headline, for similarity comparisons. */
export function titleTokens(title: string): Set<string> {
  const tokens = title
    .toLowerCase()
    .replace(/[’']s\b/g, '')
    .split(/[^a-z0-9.-]+/)
    .map((t) => t.replace(/^[.-]+|[.-]+$/g, ''))
    .filter((t) => t.length > 1 && !STOPWORDS.has(t) && !/^(19|20)\d\d$/.test(t))
    .map((t) => (t.length > 4 && t.endsWith('s') && !t.endsWith('ss') ? t.slice(0, -1) : t));
  return new Set(tokens);
}

export function jaccard(a: Set<string>, b: Set<string>): number {
  if (a.size === 0 || b.size === 0) return 0;
  let inter = 0;
  const [small, large] = a.size < b.size ? [a, b] : [b, a];
  for (const t of small) if (large.has(t)) inter++;
  return inter / (a.size + b.size - inter);
}
