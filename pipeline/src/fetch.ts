import { CONFIG } from './config';
import { errMsg } from './util';

export interface FetchOptions {
  etag?: string;
  lastModified?: string;
  headers?: Record<string, string>;
  accept?: string;
  timeoutMs?: number;
  maxBytes?: number;
}

export interface FetchResult {
  status: 'ok' | 'not-modified' | 'error';
  httpStatus?: number;
  data?: Uint8Array;
  contentType?: string;
  etag?: string;
  lastModified?: string;
  error?: string;
  ms: number;
  bytes: number;
}

const FEED_ACCEPT =
  'application/rss+xml, application/atom+xml, application/rdf+xml, application/xml;q=0.9, text/xml;q=0.9, */*;q=0.5';

/** Conditional GET with timeout and a hard size cap. Never throws. */
export async function fetchRaw(url: string, opts: FetchOptions = {}): Promise<FetchResult> {
  const started = Date.now();
  const headers: Record<string, string> = {
    'User-Agent': CONFIG.userAgent,
    Accept: opts.accept ?? FEED_ACCEPT,
    'Accept-Encoding': 'gzip, deflate, br',
    ...opts.headers,
  };
  if (opts.etag) headers['If-None-Match'] = opts.etag;
  if (opts.lastModified) headers['If-Modified-Since'] = opts.lastModified;

  try {
    const res = await fetch(url, {
      headers,
      redirect: 'follow',
      signal: AbortSignal.timeout(opts.timeoutMs ?? CONFIG.fetch.timeoutMs),
    });
    const base = {
      httpStatus: res.status,
      etag: res.headers.get('etag') ?? undefined,
      lastModified: res.headers.get('last-modified') ?? undefined,
      contentType: res.headers.get('content-type') ?? undefined,
    };
    if (res.status === 304) {
      return { status: 'not-modified', ...base, ms: Date.now() - started, bytes: 0 };
    }
    if (!res.ok || !res.body) {
      await res.body?.cancel();
      return { status: 'error', ...base, error: `HTTP ${res.status}`, ms: Date.now() - started, bytes: 0 };
    }
    const max = opts.maxBytes ?? CONFIG.fetch.maxBytes;
    const chunks: Uint8Array[] = [];
    let total = 0;
    const reader = res.body.getReader();
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > max) {
        await reader.cancel();
        return { status: 'error', ...base, error: `response larger than ${max} bytes`, ms: Date.now() - started, bytes: total };
      }
      chunks.push(value);
    }
    const data = new Uint8Array(total);
    let off = 0;
    for (const c of chunks) {
      data.set(c, off);
      off += c.byteLength;
    }
    return { status: 'ok', ...base, data, ms: Date.now() - started, bytes: total };
  } catch (e) {
    return { status: 'error', error: errMsg(e), ms: Date.now() - started, bytes: 0 };
  }
}

/** Decode bytes using the HTTP charset, then the XML prolog, then UTF-8. */
export function decodeText(data: Uint8Array, contentType?: string): string {
  let charset = /charset=["']?([\w-]+)/i.exec(contentType ?? '')?.[1];
  if (!charset) {
    const head = new TextDecoder('latin1').decode(data.subarray(0, 300));
    charset = /encoding=["']([\w-]+)["']/i.exec(head)?.[1];
  }
  try {
    return new TextDecoder(charset?.toLowerCase() ?? 'utf-8').decode(data);
  } catch {
    return new TextDecoder('utf-8').decode(data);
  }
}

export async function fetchJson<T>(url: string, opts: FetchOptions = {}): Promise<{ result: FetchResult; json?: T }> {
  const result = await fetchRaw(url, { accept: 'application/json', ...opts });
  if (result.status !== 'ok' || !result.data) return { result };
  try {
    return { result, json: JSON.parse(decodeText(result.data, result.contentType)) as T };
  } catch (e) {
    return { result: { ...result, status: 'error', error: `invalid JSON: ${errMsg(e)}` } };
  }
}
