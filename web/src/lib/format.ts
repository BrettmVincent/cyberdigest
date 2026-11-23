const MIN = 60_000;
const HOUR = 60 * MIN;
const DAY = 24 * HOUR;

/** Compact relative age: "now", "12m", "5h", "3d". */
export function ago(iso: string | undefined, now: number): string {
  if (!iso) return '';
  const d = now - Date.parse(iso);
  if (d < MIN) return 'now';
  if (d < HOUR) return `${Math.floor(d / MIN)}m`;
  if (d < DAY) return `${Math.floor(d / HOUR)}h`;
  return `${Math.floor(d / DAY)}d`;
}

export function fmtDate(iso: string | undefined): string {
  if (!iso) return '';
  return new Date(iso).toLocaleDateString(undefined, { day: 'numeric', month: 'short', year: 'numeric' });
}

export function fmtDateTime(iso: string | undefined): string {
  if (!iso) return '';
  return new Date(iso).toLocaleString(undefined, { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' });
}

export function ordinal(n: number): string {
  const v = n % 100;
  if (v >= 11 && v <= 13) return `${n}th`;
  return `${n}${['th', 'st', 'nd', 'rd'][n % 10] ?? 'th'}`;
}

/** EPSS as a probability with its percentile, e.g. "15.3% (92nd)". Missing scores are "n/a", never 0. */
export function epssText(epss: number | null | undefined, pct: number | null | undefined): string {
  if (epss == null || pct == null) return 'n/a';
  const p = epss * 100;
  return `${p < 10 ? p.toFixed(1) : p.toFixed(0)}% (${ordinal(Math.floor(pct * 100))})`;
}

export function deltaText(delta: number | null | undefined): string {
  if (delta == null) return '';
  const pts = delta * 100;
  if (Math.abs(pts) < 0.05) return '±0';
  return `${pts > 0 ? '+' : '−'}${Math.abs(pts).toFixed(Math.abs(pts) < 10 ? 1 : 0)} pts`;
}

/** Whole days from today until the given date (negative when past). */
export function daysUntil(isoDate: string, now: number): number {
  const today = Date.parse(new Date(now).toISOString().slice(0, 10));
  return Math.round((Date.parse(isoDate.slice(0, 10)) - today) / DAY);
}

/** Only http(s) links are ever rendered as hrefs. */
export function safeHref(url: string | undefined): string | undefined {
  if (!url) return undefined;
  try {
    const u = new URL(url);
    return u.protocol === 'https:' || u.protocol === 'http:' ? u.toString() : undefined;
  } catch {
    return undefined;
  }
}

function csvCell(v: unknown): string {
  let s = v == null ? '' : Array.isArray(v) ? v.join(' ') : String(v);
  // Neutralise spreadsheet formula injection.
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

export function toCsv(rows: Record<string, unknown>[]): string {
  if (rows.length === 0) return '';
  const cols = Object.keys(rows[0]!);
  return [cols.join(','), ...rows.map((r) => cols.map((c) => csvCell(r[c])).join(','))].join('\r\n');
}

export function download(filename: string, content: string, type: string): void {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}
