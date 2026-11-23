import { createHash } from 'node:crypto';

export const HOUR = 3_600_000;
export const DAY = 24 * HOUR;

export function shortHash(s: string, len = 12): string {
  return createHash('sha1').update(s).digest('hex').slice(0, len);
}

/** Run `fn` over `items` with at most `limit` in flight. Results keep input order. */
export async function pool<T, R>(items: readonly T[], limit: number, fn: (item: T, i: number) => Promise<R>): Promise<R[]> {
  const results = new Array<R>(items.length);
  let next = 0;
  async function worker(): Promise<void> {
    while (next < items.length) {
      const i = next++;
      results[i] = await fn(items[i]!, i);
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return results;
}

export function isoDay(d: Date | number | string): string {
  return new Date(d).toISOString().slice(0, 10);
}

export function uniq<T>(xs: Iterable<T>): T[] {
  return [...new Set(xs)];
}

export function errMsg(e: unknown): string {
  if (e instanceof Error) {
    const cause = (e as Error & { cause?: unknown }).cause;
    return cause instanceof Error ? `${e.message}: ${cause.message}` : e.message;
  }
  return String(e);
}
