// Per-browser preferences (watchlist, mutes, starred/hidden stories, theme), kept in localStorage.
// Nothing leaves the browser.

export type Theme = 'dark' | 'light';

/** Watch/mute terms are "kind:value", e.g. "vendor:Fortinet", "actor:APT28", "cve:CVE-2026-1234", "kw:ivanti". */
export type TermKind = 'vendor' | 'actor' | 'malware' | 'cve' | 'kw';

export type View = 'overview' | 'stories' | 'cves' | 'sources' | 'ransomware' | 'actor' | 'group';

export interface Prefs {
  /** Last main view used: the landing view on the next visit. */
  view: View;
  /** true = group duplicate coverage into stories; false = show every article. */
  grouped: boolean;
  watch: string[];
  mute: string[];
  starred: string[];
  hidden: string[];
  theme: Theme;
  lastVisit: string | null;
}

const KEY = 'cyberdigest.prefs.v1';

const systemTheme = (): Theme => (typeof matchMedia === 'function' && matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark');

const DEFAULTS: Prefs = { view: 'overview', grouped: true, watch: [], mute: [], starred: [], hidden: [], theme: systemTheme(), lastVisit: null };

function load(): Prefs {
  try {
    const raw = localStorage.getItem(KEY);
    if (!raw) return { ...DEFAULTS };
    const p = JSON.parse(raw) as Partial<Prefs>;
    const strings = (x: unknown) => (Array.isArray(x) ? x.filter((v): v is string => typeof v === 'string').slice(0, 2000) : []);
    return {
      view: p.view === 'stories' || p.view === 'cves' || p.view === 'sources' || p.view === 'ransomware' ? p.view : 'overview',
      grouped: p.grouped !== false,
      watch: strings(p.watch),
      mute: strings(p.mute),
      starred: strings(p.starred),
      hidden: strings(p.hidden),
      theme: p.theme === 'light' || p.theme === 'dark' ? p.theme : systemTheme(),
      lastVisit: typeof p.lastVisit === 'string' ? p.lastVisit : null,
    };
  } catch {
    return { ...DEFAULTS };
  }
}

export const prefs: Prefs = $state(load());

/** The previous visit time, captured once at startup (drives "new since last visit"). */
export const previousVisit: string | null = prefs.lastVisit;

export function savePrefs(): void {
  try {
    localStorage.setItem(KEY, JSON.stringify(prefs));
  } catch {
    /* storage full or disabled: preferences just won't persist */
  }
}

export function term(kind: TermKind, value: string): string {
  return `${kind}:${value}`;
}

export function parseTerm(t: string): { kind: TermKind; value: string } | null {
  const i = t.indexOf(':');
  if (i < 0) return null;
  const kind = t.slice(0, i) as TermKind;
  if (!['vendor', 'actor', 'malware', 'cve', 'kw'].includes(kind)) return null;
  return { kind, value: t.slice(i + 1) };
}

export function toggleIn(list: string[], value: string): void {
  const i = list.indexOf(value);
  if (i >= 0) list.splice(i, 1);
  else list.push(value);
}

/** Validate and merge an imported prefs JSON file (watch/mute only). */
export function importPrefs(json: string): { added: number } {
  const data = JSON.parse(json) as Partial<Prefs>;
  let added = 0;
  for (const key of ['watch', 'mute'] as const) {
    for (const t of Array.isArray(data[key]) ? data[key] : []) {
      if (typeof t === 'string' && parseTerm(t) && !prefs[key].includes(t)) {
        prefs[key].push(t);
        added++;
      }
    }
  }
  return { added };
}
