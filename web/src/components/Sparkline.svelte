<script lang="ts">
  // Single-series 30-day sparkline: 2px line, recessive baseline (expected daily rate),
  // per-day hover targets with a tooltip. The row's text carries the numbers, so identity
  // and value never rely on the line alone.
  interface Props {
    values: number[];
    days: string[];
    /** Expected 7-day count from history; drawn as a per-day dashed rule. */
    baseline: number | null;
    label: string;
    width?: number;
    height?: number;
  }
  let { values, days, baseline, label, width = 104, height = 24 }: Props = $props();

  let hover = $state<number | null>(null);

  const pad = 3;
  const max = $derived(Math.max(1, ...values, baseline !== null ? baseline / 7 : 0));
  const step = $derived(values.length > 1 ? (width - pad * 2) / (values.length - 1) : 0);
  const x = (i: number) => pad + i * step;
  const y = (v: number) => height - pad - (v / max) * (height - pad * 2);
  const path = $derived(values.map((v, i) => `${i ? 'L' : 'M'}${x(i).toFixed(1)},${y(v).toFixed(1)}`).join(''));
  const baseY = $derived(baseline !== null ? y(baseline / 7) : null);
  const summary = $derived(
    `${label}: ${values.slice(-7).reduce((a, b) => a + b, 0)} stories in the last 7 days` +
      (baseline !== null ? `, typical ${baseline}` : '') +
      `; peak ${Math.max(...values)} per day.`,
  );
  const fmtDay = (d: string) => new Date(`${d}T00:00:00Z`).toLocaleDateString(undefined, { day: 'numeric', month: 'short', timeZone: 'UTC' });
</script>

<span class="spark" role="img" aria-label={summary}>
  <svg {width} {height} viewBox="0 0 {width} {height}" aria-hidden="true">
    {#if baseY !== null}
      <line class="base" x1={pad} x2={width - pad} y1={baseY} y2={baseY} />
    {/if}
    <path class="line" d={path} />
    {#if hover !== null}
      <line class="cross" x1={x(hover)} x2={x(hover)} y1={pad} y2={height - pad} />
      <circle class="dot" cx={x(hover)} cy={y(values[hover] ?? 0)} r="3" />
    {:else}
      <circle class="dot" cx={x(values.length - 1)} cy={y(values.at(-1) ?? 0)} r="2.5" />
    {/if}
    {#each values as _, i (i)}
      <rect
        class="hit"
        x={x(i) - step / 2}
        y="0"
        width={Math.max(step, 4)}
        {height}
        role="presentation"
        onpointerenter={() => (hover = i)}
        onpointerleave={() => (hover = null)}
      />
    {/each}
  </svg>
  {#if hover !== null}
    <span class="tip" role="status">{fmtDay(days[hover] ?? '')}: <b>{values[hover]}</b></span>
  {/if}
</span>

<style>
  .spark {
    position: relative;
    display: inline-block;
    line-height: 0;
  }
  svg {
    overflow: visible;
    display: block;
  }
  .line {
    fill: none;
    stroke: var(--accent);
    stroke-width: 2;
    stroke-linejoin: round;
    stroke-linecap: round;
  }
  .base {
    stroke: var(--muted);
    stroke-width: 1;
    stroke-dasharray: 2 3;
  }
  .cross {
    stroke: var(--border-strong);
    stroke-width: 1;
  }
  .dot {
    fill: var(--accent);
    stroke: var(--surface);
    stroke-width: 2;
  }
  .hit {
    fill: transparent;
  }
  .tip {
    position: absolute;
    bottom: calc(100% + 4px);
    right: 0;
    z-index: 5;
    padding: 3px 7px;
    border-radius: 4px;
    background: var(--surface-3);
    border: 1px solid var(--border-strong);
    color: var(--text);
    font-size: 11px;
    line-height: 1.4;
    white-space: nowrap;
    pointer-events: none;
  }
</style>
