export interface Toast {
  id: number;
  text: string;
  tone: 'info' | 'alert';
  action?: { label: string; run: () => void };
  timeout: number;
}

let next = 1;
export const toasts: Toast[] = $state([]);

export function toast(text: string, opts: Partial<Omit<Toast, 'id' | 'text'>> = {}): number {
  const t: Toast = { id: next++, text, tone: opts.tone ?? 'info', action: opts.action, timeout: opts.timeout ?? 5000 };
  toasts.push(t);
  if (toasts.length > 4) toasts.splice(0, toasts.length - 4);
  if (t.timeout > 0) setTimeout(() => dismiss(t.id), t.timeout);
  return t.id;
}

export function dismiss(id: number): void {
  const i = toasts.findIndex((t) => t.id === id);
  if (i >= 0) toasts.splice(i, 1);
}
