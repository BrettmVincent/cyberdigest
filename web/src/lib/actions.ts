// Positioning helpers that write through the CSSOM (element.style), which the page's
// Content-Security-Policy allows, unlike inline style="" attributes.

export interface Point {
  x: number;
  y: number;
}

/** Absolutely position an element at (x, y) px within its offset parent. */
export function place(node: HTMLElement, p: Point) {
  const apply = (q: Point) => {
    node.style.left = `${Math.round(q.x)}px`;
    node.style.top = `${Math.round(q.y)}px`;
  };
  apply(p);
  return { update: apply };
}

/** Set an element's width as a percentage. */
export function widthPct(node: HTMLElement, pct: number) {
  const apply = (v: number) => {
    node.style.width = `${Math.max(0, Math.min(100, v))}%`;
  };
  apply(pct);
  return { update: apply };
}

export const reducedMotion = (): boolean => typeof matchMedia === 'function' && matchMedia('(prefers-reduced-motion: reduce)').matches;
