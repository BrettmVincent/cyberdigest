import { XMLParser } from 'fast-xml-parser';

/** A feed entry as published, before any CyberDigest processing. */
export interface ParsedEntry {
  title: string;
  link: string | null;
  guid: string | null;
  published: string | null;
  /** Raw (possibly HTML) description/summary/content. */
  body: string;
  categories: string[];
}

const ARRAY_TAGS = new Set(['item', 'entry', 'link', 'category']);

const parser = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: '@_',
  textNodeName: '#text',
  removeNSPrefix: true,
  htmlEntities: true,
  processEntities: true,
  parseTagValue: false,
  parseAttributeValue: false,
  trimValues: true,
  isArray: (name) => ARRAY_TAGS.has(name),
});

type Node = Record<string, unknown>;

/** Text content of a parsed node (string, number, {#text}, or array of those). */
export function text(v: unknown): string {
  if (v == null) return '';
  if (typeof v === 'string') return v;
  if (typeof v === 'number' || typeof v === 'boolean') return String(v);
  if (Array.isArray(v)) return v.map(text).filter(Boolean).join(' ');
  if (typeof v === 'object') {
    const n = v as Node;
    if ('#text' in n) return text(n['#text']);
  }
  return '';
}

function parseDate(...candidates: unknown[]): string | null {
  for (const c of candidates) {
    const s = text(c).trim();
    if (!s) continue;
    const t = Date.parse(s);
    if (!Number.isNaN(t)) return new Date(t).toISOString();
  }
  return null;
}

function atomLink(links: unknown): string | null {
  if (!Array.isArray(links)) return text(links) || null;
  let fallback: string | null = null;
  for (const l of links) {
    if (typeof l === 'string') {
      fallback ??= l;
      continue;
    }
    const n = l as Node;
    const href = text(n['@_href']);
    if (!href) continue;
    const rel = text(n['@_rel']) || 'alternate';
    if (rel === 'alternate') return href;
    fallback ??= href;
  }
  return fallback;
}

function categories(v: unknown): string[] {
  if (!Array.isArray(v)) return [];
  return v
    .map((c) => (typeof c === 'object' && c && '@_term' in (c as Node) ? text((c as Node)['@_term']) : text(c)))
    .map((s) => s.trim())
    .filter(Boolean);
}

function rssEntry(it: Node): ParsedEntry {
  const guid = text(it.guid) || null;
  // RSS 2.0: isPermaLink defaults to true when the attribute is absent.
  const isPermaLink = !(typeof it.guid === 'object' && it.guid && text((it.guid as Node)['@_isPermaLink']) === 'false');
  let link = atomLink(it.link);
  if (!link && guid && isPermaLink && /^https?:\/\//.test(guid)) link = guid;
  return {
    title: text(it.title),
    link,
    guid,
    published: parseDate(it.pubDate, it.date, it.published, it.updated, it.issued),
    body: text(it.encoded) || text(it.description) || text(it.summary),
    categories: categories(it.category),
  };
}

function atomEntry(e: Node): ParsedEntry {
  return {
    title: text(e.title),
    link: atomLink(e.link),
    guid: text(e.id) || null,
    published: parseDate(e.published, e.updated, e.issued, e.date),
    body: text(e.summary) || text(e.content),
    categories: categories(e.category),
  };
}

export class NotAFeedError extends Error {}

/** Parse RSS 2.0, RSS 1.0 (RDF) or Atom into entries. Throws NotAFeedError for HTML or unknown XML. */
export function parseFeed(xml: string): ParsedEntry[] {
  const head = xml.slice(0, 1000).trimStart().toLowerCase();
  if (head.startsWith('<!doctype html') || head.startsWith('<html')) {
    throw new NotAFeedError('server returned an HTML page, not a feed');
  }
  const doc = parser.parse(xml) as Node;
  const rss = doc.rss as Node | undefined;
  if (rss) {
    const channel = (Array.isArray(rss.channel) ? rss.channel[0] : rss.channel) as Node | undefined;
    return ((channel?.item as Node[] | undefined) ?? []).map(rssEntry);
  }
  const rdf = doc.RDF as Node | undefined;
  if (rdf) return ((rdf.item as Node[] | undefined) ?? []).map(rssEntry);
  const feed = doc.feed as Node | undefined;
  if (feed) return ((feed.entry as Node[] | undefined) ?? []).map(atomEntry);
  if (doc.html) throw new NotAFeedError('server returned an HTML page, not a feed');
  throw new NotAFeedError('unrecognised document (not RSS, RDF or Atom)');
}
