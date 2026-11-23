import { existsSync, readFileSync } from 'node:fs';
import { parse } from 'yaml';
import type { GroupRole } from '../../../shared/types';
import type { DictEntry } from '../extract';

/** Lower-case, letters and digits only: "INC Ransom" / "inc ransom" / "incransom" → "incransom". */
export function groupKey(name: string): string {
  return name
    .toLowerCase()
    .normalize('NFKD')
    .replace(/[^a-z0-9]/g, '');
}

/**
 * Strip Ransomware Vulnerability/Tool Matrix role markers:
 * trailing "*" = affiliate, leading "*" = initial access broker, trailing "+" = suspected state-sponsored.
 */
export function parseRoleMarkers(raw: string): { name: string; role: GroupRole } {
  let s = raw.trim();
  let role: GroupRole = 'operator';
  if (s.startsWith('*')) {
    role = 'broker';
    s = s.replace(/^\*+/, '');
  }
  if (s.endsWith('+')) {
    role = 'state';
    s = s.replace(/\++$/, '');
  }
  if (s.endsWith('*')) {
    if (role === 'operator') role = 'affiliate';
    s = s.replace(/\*+$/, '');
  }
  return { name: s.replace(/\[\.\]/g, '.').trim(), role };
}

export interface ResolvedGroup {
  id: string;
  name: string;
}

/** Resolves any spelling of a ransomware group to one canonical id + display name. */
export class GroupResolver {
  private byKey = new Map<string, ResolvedGroup>();
  private aliasesById = new Map<string, Set<string>>();

  constructor(overrides: { name: string; aliases: string[] }[], misp: DictEntry[] = []) {
    for (const o of overrides) this.register(o.name, o.aliases, true);
    for (const e of misp) this.register(e.name, e.aliases, false);
  }

  static fromConfig(path = 'config/ransomware-aliases.yaml', misp: DictEntry[] = []): GroupResolver {
    const doc = existsSync(path) ? (parse(readFileSync(path, 'utf8')) as { groups?: { name: string; aliases?: string[] }[] }) : {};
    return new GroupResolver((doc.groups ?? []).map((g) => ({ name: String(g.name), aliases: (g.aliases ?? []).map(String) })), misp);
  }

  private register(name: string, aliases: string[], authoritative: boolean): void {
    const keys = [name, ...aliases].map(groupKey).filter((k) => k.length >= 2);
    if (keys.length === 0) return;
    // Join an existing group if any key is already known (overrides win over MISP).
    const existing = keys.map((k) => this.byKey.get(k)).find(Boolean);
    if (existing && !authoritative) {
      for (const k of keys) if (!this.byKey.has(k)) this.byKey.set(k, existing);
      return;
    }
    const target = existing ?? { id: groupKey(name), name };
    for (const k of keys) if (authoritative || !this.byKey.has(k)) this.byKey.set(k, target);
    const set = this.aliasesById.get(target.id) ?? new Set<string>();
    for (const a of [name, ...aliases]) if (a !== target.name) set.add(a);
    this.aliasesById.set(target.id, set);
  }

  /** Canonical group for a raw name; unknown names become their own group (display name kept). */
  resolve(raw: string): ResolvedGroup {
    const { name } = parseRoleMarkers(raw);
    const key = groupKey(name);
    const hit = this.byKey.get(key);
    if (hit) return hit;
    const created = { id: key, name };
    if (key) this.byKey.set(key, created);
    return created;
  }

  aliases(id: string): string[] {
    return [...(this.aliasesById.get(id) ?? [])].slice(0, 12);
  }
}
