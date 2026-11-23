<script lang="ts" module>
  export interface Series {
    key: string;
    label: string;
    /** CSS class that sets `fill` (keeps colours in the stylesheet). */
    cls: string;
    values: number[];
  }
</script>

<script lang="ts">
  // Vertical (stacked) bar chart: thin bars, 4px rounded data-end on top, 2px surface gaps
  // between stacked segments, recessive grid, hover column + tooltip, optional click-through.
  import { place } from '../../lib/actions';

  interface Props {
    labels: string[];
    series: Series[];
    height?: number;
    tickEvery?: number;
    formatLabel?: (l: string) => string;
    ariaLabel: string;
    onSelect?: (index: number) => void;
    selectHint?: string;
  }
  let { labels, series, height = 190, tickEvery = 7, formatLabel = (l) => l, ariaLabel, onSelect, selectHint }: Props = $props();

  let width = $state(600);
  let hover = $state<number | null>(null);

  const m = { top: 10, right: 6, bottom: 22, left: 30 };
  const totals = $derived(labels.map((_, i) => series.reduce((a, s) => a + (s.values[i] ?? 0), 0)));
  const niceMax = $derived.by(() => {
    const max = Math.max(1, ...totals);
    const pow = 10 ** Math.floor(Math.log10(max));
    const n = max / pow;
    return (n <= 1 ? 1 : n <= 2 ? 2 : n <= 5 ? 5 : 10) * pow;
  });
  const ticks = $derived([0, niceMax / 2, niceMax]);
  const innerW = $derived(Math.max(50, width - m.left - m.right));
  const innerH = $derived(height - m.top - m.bottom);
  const band = $derived(innerW / Math.max(1, labels.length));
  const barW = $derived(Math.max(2, Math.min(18, band * 0.62)));
  const x = (i: number) => m.left + i * band + (band - barW) / 2;
  const y = (v: number) => m.top + innerH - (v / niceMax) * innerH;

  /** Rect with only the top corners rounded (data-end), bottom square on the baseline. */
  function topRounded(x0: number, y0: number, w: number, h: number, r: number): string {
    const rr = Math.min(r, w / 2, h);
    return `M${x0},${y0 + h}V${y0 + rr}Q${x0},${y0} ${x0 + rr},${y0}H${x0 + w - rr}Q${x0 + w},${y0} ${x0 + w},${y0 + rr}V${y0 + h}Z`;
  }

  interface Seg {
    cls: string;
    d: string;
  }
  const bars = $derived(
    labels.map((_, i) => {
      const segs: Seg[] = [];
      let acc = 0;
      const nonZero = series.filter((s) => (s.values[i] ?? 0) > 0);
      nonZero.forEach((s, k) => {
        const v = s.values[i] ?? 0;
        const yTop = y(acc + v);
        const yBottom = y(acc);
        const isTop = k === nonZero.length - 1;
        // 2px surface gap above every segment that has another stacked on it.
        const h = Math.max(0, yBottom - yTop - (isTop ? 0 : 2));
        const top = isTop ? yTop : yTop + 2;
        if (h > 0) segs.push({ cls: s.cls, d: isTop ? topRounded(x(i), top, barW, h, 4) : `M${x(i)},${top}h${barW}v${h}h${-barW}Z` });
        acc += v;
      });
      return segs;
    }),
  );

  const tipX = $derived(hover === null ? 0 : Math.min(Math.max(x(hover) + barW / 2, 70), width - 70));
</script>

<div class="wrap" bind:clientWidth={width}>
  <svg {width} {height} role="img" aria-label={ariaLabel}>
    {#each ticks as t (t)}
      <line class="grid" x1={m.left} x2={width - m.right} y1={y(t)} y2={y(t)} />
      <text class="tick" x={m.left - 6} y={y(t)} dy="0.32em" text-anchor="end">{t}</text>
    {/each}
    <line class="axis" x1={m.left} x2={width - m.right} y1={y(0)} y2={y(0)} />
    {#if hover !== null}
      <rect class="hover-col" x={m.left + hover * band} y={m.top} width={band} height={innerH} />
    {/if}
    {#each bars as segs, i (i)}
      {#each segs as s, k (k)}<path class="seg {s.cls}" d={s.d} />{/each}
    {/each}
    {#each labels as l, i (i)}
      {#if i % tickEvery === (labels.length - 1) % tickEvery}
        <text class="tick" x={x(i) + barW / 2} y={height - 6} text-anchor="middle">{formatLabel(l)}</text>
      {/if}
    {/each}
    {#each labels as _, i (i)}
      <rect
        class="hit"
        class:clickable={!!onSelect}
        x={m.left + i * band}
        y={m.top}
        width={band}
        height={innerH}
        role="presentation"
        onpointerenter={() => (hover = i)}
        onpointerleave={() => (hover = null)}
        onclick={() => onSelect?.(i)}
      />
    {/each}
  </svg>
  {#if hover !== null}
    <div class="tip" use:place={{ x: tipX, y: 0 }} role="status">
      <div class="tip-h">{formatLabel(labels[hover] ?? '')} · <b class="num">{totals[hover]}</b></div>
      {#each [...series].reverse() as s (s.key)}
        <div class="tip-r"><span class="sw {s.cls}"></span>{s.label}<b class="num">{s.values[hover] ?? 0}</b></div>
      {/each}
      {#if onSelect && selectHint}<div class="tip-hint">{selectHint}</div>{/if}
    </div>
  {/if}
</div>

<style>
  .wrap {
    position: relative;
    width: 100%;
  }
  svg {
    display: block;
    overflow: visible;
  }
  .grid {
    stroke: var(--grid);
    stroke-width: 1;
  }
  .axis {
    stroke: var(--axis);
    stroke-width: 1;
  }
  .tick {
    fill: var(--muted);
    font-size: 10.5px;
    font-variant-numeric: tabular-nums;
  }
  .hover-col {
    fill: var(--surface-2);
  }
  .hit {
    fill: transparent;
  }
  .hit.clickable {
    cursor: pointer;
  }
  .tip {
    position: absolute;
    transform: translate(-50%, -100%);
    z-index: 5;
    min-width: 140px;
    padding: 6px 9px;
    border: 1px solid var(--border-strong);
    border-radius: 6px;
    background: var(--surface-2);
    box-shadow: 0 6px 18px rgba(0, 0, 0, 0.3);
    font-size: 11.5px;
    pointer-events: none;
  }
  .tip-h {
    margin-bottom: 3px;
    color: var(--text);
  }
  .tip-r {
    display: flex;
    align-items: center;
    gap: 6px;
    color: var(--text-2);
  }
  .tip-r b {
    margin-left: auto;
    color: var(--text);
  }
  .tip-hint {
    margin-top: 4px;
    color: var(--muted);
    font-size: 10.5px;
  }
  .sw {
    width: 9px;
    height: 9px;
    border-radius: 2px;
    display: inline-block;
  }
  /* Series fills: shared classes used by the bars, tooltip and legend swatches. */
  :global(.f-p1) {
    fill: var(--critical);
    background: var(--critical);
  }
  :global(.f-p2) {
    fill: var(--serious);
    background: var(--serious);
  }
  :global(.f-p3) {
    fill: var(--p3-fill);
    background: var(--p3-fill);
  }
  :global(.f-s1) {
    fill: var(--series-1);
    background: var(--series-1);
  }
  :global(.f-s2) {
    fill: var(--series-2);
    background: var(--series-2);
  }
</style>
