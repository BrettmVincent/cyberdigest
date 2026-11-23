import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';

/** Small JSON/binary store rooted at the state directory (the `data` branch checkout in CI). */
export class StateStore {
  constructor(readonly dir: string) {
    mkdirSync(dir, { recursive: true });
  }

  path(name: string): string {
    return join(this.dir, name);
  }

  has(name: string): boolean {
    return existsSync(this.path(name));
  }

  readJson<T>(name: string, fallback: T): T {
    const p = this.path(name);
    if (!existsSync(p)) return fallback;
    try {
      return JSON.parse(readFileSync(p, 'utf8')) as T;
    } catch {
      return fallback;
    }
  }

  writeJson(name: string, data: unknown, pretty = false): void {
    this.writeBuf(name, Buffer.from(JSON.stringify(data, null, pretty ? 2 : undefined)));
  }

  readBuf(name: string): Buffer | null {
    const p = this.path(name);
    return existsSync(p) ? readFileSync(p) : null;
  }

  writeBuf(name: string, data: Uint8Array): void {
    const p = this.path(name);
    mkdirSync(dirname(p), { recursive: true });
    const tmp = `${p}.tmp`;
    writeFileSync(tmp, data);
    renameSync(tmp, p);
  }
}

export interface HttpCacheEntry {
  etag?: string;
  lastModified?: string;
}
