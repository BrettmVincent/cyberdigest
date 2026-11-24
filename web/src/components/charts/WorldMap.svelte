<script lang="ts" module>
  export type MapMode = 'news' | 'origin' | 'targeted' | 'ransom';
</script>

<script lang="ts">
  // Choropleth world map. Data modes use a single-hue sequential ramp (5 ordinal steps);
  // the profile mode marks one origin + target countries with the two validated categorical hues.
  import type { CountryStat } from '../../../../shared/types';
  import { place, reducedMotion } from '../../lib/actions';
  import { loadWorld, MAP_H, MAP_W, type CountryShape } from '../../lib/world';

  interface Props {
    mode?: MapMode;
    countries?: CountryStat[];
    /** Actor-profile mode: numeric ids for origin and targets. */
    profile?: { origin: string | null; targets: string[] };
    onSelect?: (iso: string) => void;
    ariaLabel: string;
  }
  let { mode = 'news', countries = [], profile, onSelect, ariaLabel }: Props = $props();

  let shapes = $state<CountryShape[]>([]);
  let failed = $state(false);
  let hover = $state<{ shape: CountryShape; x: number; y: number } | null>(null);
  let wrap = $state<HTMLDivElement>();

  $effect(() => {
    loadWorld()
      .then((s) => (shapes = s))
      .catch(() => (failed = true));
  });

  const BREAKS = [1, 2, 4, 8, 16];
  const LEGEND = ['1', '2–3', '4–7', '8–15', '16+'];
  const byNumeric = $derived(new Map(countries.filter((c) => c.numeric).map((c) => [c.numeric!, c])));
  const value = (c: CountryStat | undefined) => (c ? c[mode] : 0);
  const bin = (v: number) => {
    let b = 0;
    for (let i = 0; i < BREAKS.length; i++) if (v >= BREAKS[i]!) b = i + 1;
    return b;
  };
  const targets = $derived(new Set(profile?.targets ?? []));

  function fillClass(s: CountryShape): string {
    if (profile) return s.id === profile.origin ? 'origin' : targets.has(s.id) ? 'target' : 'empty';
    const b = bin(value(byNumeric.get(s.id)));
    return b ? `seq-${b}` : 'empty';
  }

  // Pulsing markers on the three busiest countries (data modes only).
  const hotspots = $derived(
    profile
      ? []
      : shapes
          .map((s) => ({ s, v: value(byNumeric.get(s.id)) }))
          .filter((x) => x.v > 0 && Number.isFinite(x.s.centroid[0]))
          .sort((a, b) => b.v - a.v)
          .slice(0, 3),
  );
  const animate = !reducedMotion();

  function move(e: PointerEvent, shape: CountryShape) {
    const r = wrap!.getBoundingClientRect();
    hover = { shape, x: e.clientX - r.left, y: e.clientY - r.top };
  }

  const hovered = $derived(hover ? byNumeric.get(hover.shape.id) : undefined);
  const modeLabel = {
    news: 'stories naming it',
    origin: 'stories with actors from here',
    targeted: 'active actors that target it',
    ransom: 'ransomware claims / reported attacks (30d)',
  } as const;
</script>

<div class="map" bind:this={wrap}>
  {#if failed}
    <p class="muted">Map unavailable.</p>
  {:else}
    <svg viewBox="0 0 {MAP_W} {MAP_H}" role="img" aria-label={ariaLabel} preserveAspectRatio="xMidYMid meet">
      <g>
        {#each shapes as s (s.id + s.name)}
          {@const c = byNumeric.get(s.id)}
          <path
            d={s.d}
            class="land {fillClass(s)}"
            class:active={hover?.shape === s}
            class:clickable={!!onSelect && !!c && value(c) > 0}
            role="presentation"
            onpointermove={(e) => move(e, s)}
            onpointerleave={() => (hover = null)}
            onclick={() => c && value(c) > 0 && onSelect?.(c.iso)}
          />
        {/each}
      </g>
      {#each hotspots as h (h.s.id)}
        <g class="hot" transform="translate({h.s.centroid[0]},{h.s.centroid[1]})">
          {#if animate}<circle class="pulse" r="10" />{/if}
          <circle class="core" r="3.5" />
        </g>
      {/each}
    </svg>
    {#if hover}
      <div class="tip" use:place={{ x: hover.x, y: hover.y }} role="status">
        <b>{hovered?.name ?? hover.shape.name}</b>
        {#if profile}
          <div class="muted">{hover.shape.id === profile.origin ? 'Suspected origin' : targets.has(hover.shape.id) ? 'Known target' : ''}</div>
        {:else if hovered && value(hovered) > 0}
          <div><b class="num">{value(hovered)}</b> {modeLabel[mode]}</div>
          {#if mode === 'origin' && hovered.originActors.length}<div class="muted">{hovered.originActors.slice(0, 4).join(', ')}</div>{/if}
          {#if mode === 'targeted' && hovered.targetActors.length}<div class="muted">{hovered.targetActors.slice(0, 4).join(', ')}</div>{/if}
          {#if onSelect}<div class="hint">Click to filter stories</div>{/if}
        {:else}
          <div class="muted">No activity</div>
        {/if}
      </div>
    {/if}
  {/if}
  <div class="legend" aria-hidden="true">
    {#if profile}
      <span class="legend-key"><span class="legend-swatch origin"></span>Suspected origin</span>
      <span class="legend-key"><span class="legend-swatch target"></span>Known targets (MISP profile)</span>
    {:else}
      <span class="muted">{modeLabel[mode]}:</span>
      {#each LEGEND as l, i (l)}<span class="legend-key"><span class="legend-swatch seq-{i + 1}"></span>{l}</span>{/each}
      {#if hotspots.length}<span class="legend-key"><span class="legend-dot"></span>top {hotspots.length}</span>{/if}
    {/if}
  </div>
</div>

<style>
  .map {
    position: relative;
  }
  svg {
    display: block;
    width: 100%;
    height: auto;
  }
  .land {
    stroke: var(--map-stroke);
    stroke-width: 0.6;
    transition: fill 250ms ease;
  }
  .land.active {
    stroke: var(--text);
    stroke-width: 1.2;
  }
  .land.clickable {
    cursor: pointer;
  }
  .empty {
    fill: var(--map-empty);
    background: var(--map-empty);
  }
  .seq-1 {
    fill: var(--seq-1);
    background: var(--seq-1);
  }
  .seq-2 {
    fill: var(--seq-2);
    background: var(--seq-2);
  }
  .seq-3 {
    fill: var(--seq-3);
    background: var(--seq-3);
  }
  .seq-4 {
    fill: var(--seq-4);
    background: var(--seq-4);
  }
  .seq-5 {
    fill: var(--seq-5);
    background: var(--seq-5);
  }
  .origin {
    fill: var(--series-2);
    background: var(--series-2);
  }
  .target {
    fill: var(--series-1);
    background: var(--series-1);
  }
  .hot {
    pointer-events: none;
  }
  .core {
    fill: var(--text);
    stroke: var(--surface);
    stroke-width: 1.5;
  }
  .pulse {
    fill: none;
    stroke: var(--text);
    stroke-width: 1.5;
    transform-box: fill-box;
    transform-origin: center;
    animation: pulse 2.4s ease-out infinite;
  }
  @keyframes pulse {
    from {
      transform: scale(0.35);
      opacity: 0.9;
    }
    to {
      transform: scale(1.6);
      opacity: 0;
    }
  }
  .tip {
    position: absolute;
    transform: translate(12px, -50%);
    z-index: 5;
    padding: 6px 9px;
    min-width: 140px;
    max-width: 240px;
    border: 1px solid var(--border-strong);
    border-radius: 6px;
    background: var(--surface-2);
    box-shadow: 0 6px 18px rgba(0, 0, 0, 0.3);
    font-size: 11.5px;
    pointer-events: none;
  }
  .hint {
    margin-top: 3px;
    color: var(--muted);
    font-size: 10.5px;
  }
  .legend-dot {
    display: inline-block;
    width: 7px;
    height: 7px;
    margin-right: 4px;
    border-radius: 50%;
    background: var(--text);
    box-shadow: 0 0 0 1.5px var(--surface);
  }
  .legend {
    display: flex;
    flex-wrap: wrap;
    gap: 10px;
    margin-top: 6px;
    font-size: 11px;
    color: var(--text-2);
  }
</style>
