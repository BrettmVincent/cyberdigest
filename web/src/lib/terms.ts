// Watch/mute terms ("vendor:Fortinet", "kw:citrix bleed"). Plain module (no runes) so search
// matching can be unit-tested outside Svelte.
export type TermKind = 'vendor' | 'actor' | 'malware' | 'cve' | 'kw';

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
